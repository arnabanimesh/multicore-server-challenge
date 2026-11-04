//! Allocation-free JSON output helpers.
//!
//! Responses are written straight into the (pooled) response buffer instead of being
//! built as `serde_json::Value` trees and serialised a second time.

static ESCAPE: [bool; 256] = build_escape_table();

const fn build_escape_table() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 0x20 {
        t[i] = true;
        i += 1;
    }
    t[b'"' as usize] = true;
    t[b'\\' as usize] = true;
    t
}

/// Writes `s` as a quoted, escaped JSON string (same escaping rules as serde_json).
#[inline]
pub fn put_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if !ESCAPE[b as usize] {
            continue;
        }
        if start < i {
            out.extend_from_slice(&bytes[start..i]);
        }
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0x0f) as usize]);
            }
        }
        start = i + 1;
    }
    if start < bytes.len() {
        out.extend_from_slice(&bytes[start..]);
    }
    out.push(b'"');
}

#[inline]
pub fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => put_str(out, v),
        None => out.extend_from_slice(b"null"),
    }
}

#[inline]
pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    let mut b = itoa::Buffer::new();
    out.extend_from_slice(b.format(v).as_bytes());
}

#[inline]
pub fn put_bool(out: &mut Vec<u8>, v: bool) {
    if v {
        out.extend_from_slice(b"true");
    } else {
        out.extend_from_slice(b"false");
    }
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Writes a Postgres `timestamptz` (microseconds since 2000-01-01 UTC) as a quoted
/// RFC 3339 string with exactly three fractional digits. The sub-millisecond part is
/// truncated, never rounded, as SPEC.md requires.
pub fn put_pg_ts(out: &mut Vec<u8>, pg_micros: i64) {
    const PG_EPOCH_TO_UNIX_US: i64 = 946_684_800_000_000;
    let us = pg_micros.saturating_add(PG_EPOCH_TO_UNIX_US);
    let secs = us.div_euclid(1_000_000);
    let ms = (us.rem_euclid(1_000_000) / 1_000) as u32;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let (y, mo, d) = civil_from_days(days);
    let y = y.clamp(0, 9999) as u32;
    let hh = sod / 3600;
    let mi = (sod % 3600) / 60;
    let ss = sod % 60;
    let b: [u8; 26] = [
        b'"',
        b'0' + (y / 1000) as u8,
        b'0' + ((y / 100) % 10) as u8,
        b'0' + ((y / 10) % 10) as u8,
        b'0' + (y % 10) as u8,
        b'-',
        b'0' + (mo / 10) as u8,
        b'0' + (mo % 10) as u8,
        b'-',
        b'0' + (d / 10) as u8,
        b'0' + (d % 10) as u8,
        b'T',
        b'0' + (hh / 10) as u8,
        b'0' + (hh % 10) as u8,
        b':',
        b'0' + (mi / 10) as u8,
        b'0' + (mi % 10) as u8,
        b':',
        b'0' + (ss / 10) as u8,
        b'0' + (ss % 10) as u8,
        b'.',
        b'0' + (ms / 100) as u8,
        b'0' + ((ms / 10) % 10) as u8,
        b'0' + (ms % 10) as u8,
        b'Z',
        b'"',
    ];
    out.extend_from_slice(&b);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(f: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut v = Vec::new();
        f(&mut v);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn escapes_like_serde_json() {
        let input = "a\"b\\c\n\r\t\u{8}\u{c}\u{1}\u{1f}é日😀";
        let mine = s(|o| put_str(o, input));
        let theirs = serde_json::to_string(input).unwrap();
        assert_eq!(mine, theirs);
    }

    #[test]
    fn pg_epoch_formats() {
        // 2000-01-01T00:00:00.000Z is pg microsecond 0
        assert_eq!(s(|o| put_pg_ts(o, 0)), "\"2000-01-01T00:00:00.000Z\"");
        // truncation, not rounding: .999999 must stay .999
        assert_eq!(s(|o| put_pg_ts(o, 999_999)), "\"2000-01-01T00:00:00.999Z\"");
        assert_eq!(s(|o| put_pg_ts(o, -1)), "\"1999-12-31T23:59:59.999Z\"");
        // vectors computed independently with Python's datetime
        assert_eq!(s(|o| put_pg_ts(o, 762_525_296_789_012)), "\"2024-02-29T12:34:56.789Z\"");
        assert_eq!(s(|o| put_pg_ts(o, 846_836_130_123_999)), "\"2026-11-01T08:15:30.123Z\"");
        assert_eq!(s(|o| put_pg_ts(o, -946_684_800_000_001)), "\"1969-12-31T23:59:59.999Z\"");
    }
}