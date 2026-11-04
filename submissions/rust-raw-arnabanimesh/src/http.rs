//! Minimal HTTP/1.1 plumbing: request-head parsing, chunked request bodies and response framing.

pub const MAX_HEAD: usize = 16 * 1024;
pub const MAX_BODY: usize = 1024 * 1024;

/// Bytes reserved at the front of every response buffer. `frame` writes the status line and
/// headers right-aligned into this gap, so the body is written once and never copied.
pub const HDR_RESERVE: usize = 192;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Other,
}

/// Everything the connection loop needs from a parsed request head. All positions are byte
/// offsets into the receive buffer, so no strings are allocated per request.
pub struct Head {
    pub header_len: usize,
    pub method: Method,
    pub path: (usize, usize),
    pub auth: Option<(usize, usize)>,
    pub content_length: usize,
    pub chunked: bool,
    pub close: bool,
    pub expect_continue: bool,
}

pub enum HeadParse {
    Partial,
    Bad,
    Complete(Head),
}

fn parse_usize(v: &[u8]) -> Option<usize> {
    let v = v.trim_ascii();
    if v.is_empty() || v.len() > 12 {
        return None;
    }
    let mut n = 0usize;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (b - b'0') as usize;
    }
    Some(n)
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

pub fn parse_head(buf: &[u8]) -> HeadParse {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let header_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return HeadParse::Partial,
        Err(_) => return HeadParse::Bad,
    };

    let base = buf.as_ptr() as usize;
    let buf_len = buf.len();
    let range = |s: &[u8]| -> (usize, usize) {
        let start = (s.as_ptr() as usize).wrapping_sub(base);
        if start > buf_len || start + s.len() > buf_len {
            (0, 0)
        } else {
            (start, start + s.len())
        }
    };

    let method = match req.method {
        Some("GET") => Method::Get,
        Some("POST") => Method::Post,
        Some("PUT") => Method::Put,
        Some("DELETE") => Method::Delete,
        Some(_) => Method::Other,
        None => return HeadParse::Bad,
    };
    let path = match req.path {
        Some(p) => range(p.as_bytes()),
        None => return HeadParse::Bad,
    };
    let http10 = req.version == Some(0);

    let mut auth = None;
    let mut content_length = 0usize;
    let mut chunked = false;
    let mut conn_close = false;
    let mut conn_keep = false;
    let mut expect_continue = false;

    for h in req.headers.iter() {
        let name = h.name;
        if name.eq_ignore_ascii_case("authorization") {
            auth = Some(range(h.value));
        } else if name.eq_ignore_ascii_case("content-length") {
            match parse_usize(h.value) {
                Some(n) => content_length = n,
                None => return HeadParse::Bad,
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if contains_ci(h.value, b"chunked") {
                chunked = true;
            }
        } else if name.eq_ignore_ascii_case("connection") {
            if contains_ci(h.value, b"close") {
                conn_close = true;
            }
            if contains_ci(h.value, b"keep-alive") {
                conn_keep = true;
            }
        } else if name.eq_ignore_ascii_case("expect") {
            if contains_ci(h.value, b"100-continue") {
                expect_continue = true;
            }
        }
    }

    let close = if http10 { !conn_keep } else { conn_close };
    HeadParse::Complete(Head {
        header_len,
        method,
        path,
        auth,
        content_length,
        chunked,
        close,
        expect_continue,
    })
}

pub enum Chunked {
    Incomplete,
    Bad,
    /// Body fully decoded; the value is the number of bytes consumed from `data`.
    Done(usize),
}

/// Decodes a `Transfer-Encoding: chunked` request body starting at `data[0]`.
/// The decoded bytes are left in `body`.
pub fn decode_chunked(data: &[u8], body: &mut Vec<u8>) -> Chunked {
    body.clear();
    let mut pos = 0usize;
    loop {
        let line_end = match memchr::memchr(b'\n', &data[pos..]) {
            Some(i) => pos + i,
            None => return Chunked::Incomplete,
        };
        let mut line = &data[pos..line_end];
        if let Some(&b'\r') = line.last() {
            line = &line[..line.len() - 1];
        }
        let size_part = match memchr::memchr(b';', line) {
            Some(i) => &line[..i],
            None => line,
        };
        let size_part = size_part.trim_ascii();
        if size_part.is_empty() || size_part.len() > 8 {
            return Chunked::Bad;
        }
        let mut size = 0usize;
        for &b in size_part {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Chunked::Bad,
            };
            size = size * 16 + d as usize;
        }
        pos = line_end + 1;

        if size == 0 {
            // Optional trailers, terminated by an empty line.
            loop {
                let le = match memchr::memchr(b'\n', &data[pos..]) {
                    Some(i) => pos + i,
                    None => return Chunked::Incomplete,
                };
                let l = &data[pos..le];
                pos = le + 1;
                if l.is_empty() || (l.len() == 1 && l[0] == b'\r') {
                    return Chunked::Done(pos);
                }
            }
        }

        if body.len() + size > MAX_BODY {
            return Chunked::Bad;
        }
        if data.len() < pos + size + 2 {
            return Chunked::Incomplete;
        }
        body.extend_from_slice(&data[pos..pos + size]);
        pos += size;
        if data[pos] != b'\r' || data[pos + 1] != b'\n' {
            return Chunked::Bad;
        }
        pos += 2;
    }
}

fn put(head: &mut [u8; HDR_RESERVE], n: &mut usize, s: &[u8]) {
    head[*n..*n + s.len()].copy_from_slice(s);
    *n += s.len();
}

/// Frames a response whose JSON body already sits at `out[HDR_RESERVE..]`.
/// Writes the status line and headers into the reserved gap and returns the offset from
/// which `out` should be sent. 204 responses carry no body and no Content-Length.
pub fn frame(out: &mut Vec<u8>, status: u16, close: bool) -> usize {
    if status == 204 {
        out.truncate(HDR_RESERVE);
    }
    let body_len = out.len() - HDR_RESERVE;

    let mut head = [0u8; HDR_RESERVE];
    let mut n = 0usize;
    let line: &[u8] = match status {
        200 => b"HTTP/1.1 200 OK\r\n",
        201 => b"HTTP/1.1 201 Created\r\n",
        204 => b"HTTP/1.1 204 No Content\r\n",
        400 => b"HTTP/1.1 400 Bad Request\r\n",
        401 => b"HTTP/1.1 401 Unauthorized\r\n",
        403 => b"HTTP/1.1 403 Forbidden\r\n",
        404 => b"HTTP/1.1 404 Not Found\r\n",
        413 => b"HTTP/1.1 413 Payload Too Large\r\n",
        422 => b"HTTP/1.1 422 Unprocessable Entity\r\n",
        503 => b"HTTP/1.1 503 Service Unavailable\r\n",
        _ => b"HTTP/1.1 500 Internal Server Error\r\n",
    };
    put(&mut head, &mut n, line);
    if status != 204 {
        put(
            &mut head,
            &mut n,
            b"Content-Type: application/json\r\nContent-Length: ",
        );
        let mut ib = itoa::Buffer::new();
        put(&mut head, &mut n, ib.format(body_len).as_bytes());
        put(&mut head, &mut n, b"\r\n");
    }
    if close {
        put(&mut head, &mut n, b"Connection: close\r\n");
    }
    put(&mut head, &mut n, b"\r\n");

    let start = HDR_RESERVE - n;
    out[start..HDR_RESERVE].copy_from_slice(&head[..n]);
    start
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_head_with_auth_and_body_length() {
        let raw = b"POST /api/articles?limit=5 HTTP/1.1\r\nHost: x\r\nauthorization: Token abc.def.ghi\r\nContent-Length: 17\r\n\r\n{\"article\":{...}}";
        match parse_head(raw) {
            HeadParse::Complete(h) => {
                assert_eq!(h.method, Method::Post);
                assert_eq!(&raw[h.path.0..h.path.1], b"/api/articles?limit=5");
                let a = h.auth.unwrap();
                assert_eq!(&raw[a.0..a.1], b"Token abc.def.ghi");
                assert_eq!(h.content_length, 17);
                assert!(!h.close && !h.chunked);
                assert_eq!(&raw[h.header_len..], b"{\"article\":{...}}");
            }
            _ => panic!("expected a complete head"),
        }
    }

    #[test]
    fn partial_and_bad() {
        assert!(matches!(parse_head(b"GET /api/tags HT"), HeadParse::Partial));
        assert!(matches!(parse_head(b"\x00\x01garbage\r\n\r\n"), HeadParse::Bad));
    }

    #[test]
    fn connection_close_and_http10() {
        let r = b"GET /api/tags HTTP/1.1\r\nConnection: close\r\n\r\n";
        match parse_head(r) {
            HeadParse::Complete(h) => assert!(h.close),
            _ => panic!(),
        }
        let r = b"GET /api/tags HTTP/1.0\r\n\r\n";
        match parse_head(r) {
            HeadParse::Complete(h) => assert!(h.close),
            _ => panic!(),
        }
        let r = b"GET /api/tags HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
        match parse_head(r) {
            HeadParse::Complete(h) => assert!(!h.close),
            _ => panic!(),
        }
    }

    #[test]
    fn chunked_roundtrip_and_incremental() {
        let full = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\nNEXT";
        let mut body = Vec::new();
        match decode_chunked(full, &mut body) {
            Chunked::Done(n) => {
                assert_eq!(&body, b"hello world");
                assert_eq!(&full[n..], b"NEXT");
            }
            _ => panic!("expected done"),
        }
        // every strict prefix must report Incomplete, never Bad or Done
        let end = full.len() - 4; // without the pipelined "NEXT"
        for cut in 0..end {
            let mut b = Vec::new();
            assert!(
                matches!(decode_chunked(&full[..cut], &mut b), Chunked::Incomplete),
                "prefix of {cut} bytes"
            );
        }
        assert!(matches!(decode_chunked(b"zz\r\n", &mut Vec::new()), Chunked::Bad));
    }

    #[test]
    fn frames_right_aligned() {
        let mut out = vec![0u8; HDR_RESERVE];
        out.extend_from_slice(b"{\"tags\":[]}");
        let start = frame(&mut out, 200, false);
        let sent = &out[start..];
        assert_eq!(
            sent,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"tags\":[]}".as_slice()
        );

        let mut out = vec![0u8; HDR_RESERVE];
        out.extend_from_slice(b"ignored");
        let start = frame(&mut out, 204, true);
        assert_eq!(
            &out[start..],
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".as_slice()
        );
    }
}