mod auth;
mod db;
mod http;
mod json;

use std::borrow::Cow;
use std::cell::RefCell;
use std::env;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, bounded};
use serde_json::{Map, Value};
use socket2::{Domain, Protocol, Socket, Type};
use tikv_jemallocator::Jemalloc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_postgres::Row;

use crate::auth::{AuthOutcome, JwtAuth};
use crate::db::PgConn;
use crate::http::{Chunked, HDR_RESERVE, HeadParse, MAX_BODY, MAX_HEAD, Method};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const BCRYPT_COST: u32 = 10;
/// Pending bcrypt jobs beyond this are shed with a 503 instead of blocking an I/O thread.
const BCRYPT_QUEUE: usize = 512;
/// Total Postgres connections across all workers (the box allows 100, SPEC says keep <= 95).
const DEFAULT_PG_CONNS: usize = 32;
const MAX_PG_CONNS: usize = 90;

// ---------------------------------------------------------------------------------------------
// bcrypt pool: cost-10 hashing is ~50 ms of CPU, so it never runs on an I/O thread.
// ---------------------------------------------------------------------------------------------

pub enum BcryptJob {
    Hash {
        plaintext: String,
        reply: oneshot::Sender<Option<String>>,
    },
    Verify {
        plaintext: String,
        hash: String,
        reply: oneshot::Sender<bool>,
    },
}

fn lower_priority_for_bcrypt() {
    // Logins are ~0.1% of requests and have a generous latency budget; keep them from
    // competing with the other 99.9% (and with Postgres) for CPU.
    unsafe {
        let param = libc::sched_param { sched_priority: 0 };
        libc::sched_setscheduler(0, libc::SCHED_BATCH, &param);
        libc::setpriority(libc::PRIO_PROCESS as _, 0, 5);
    }
}

fn run_bcrypt_worker(rx: Receiver<BcryptJob>) {
    lower_priority_for_bcrypt();
    while let Ok(job) = rx.recv() {
        match job {
            BcryptJob::Hash { plaintext, reply } => {
                let res = bcrypt::hash(plaintext, BCRYPT_COST).ok();
                let _ = reply.send(res);
            }
            BcryptJob::Verify {
                plaintext,
                hash,
                reply,
            } => {
                let ok = bcrypt::verify(plaintext, &hash).unwrap_or(false);
                let _ = reply.send(ok);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Per-worker state
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct AppConfig {
    bind_addr: SocketAddr,
    db_url: String,
    jwt: JwtAuth,
}

struct WorkerState {
    conns: Vec<PgConn>,
    jwt: JwtAuth,
    bcrypt_tx: Sender<BcryptJob>,
    out_pool: RefCell<Vec<Vec<u8>>>,
}

/// A borrowed Postgres connection; counts itself in/out so `pg()` can pick the least busy one.
struct PgGuard<'a> {
    conn: &'a PgConn,
}

impl<'a> Deref for PgGuard<'a> {
    type Target = PgConn;
    fn deref(&self) -> &PgConn {
        self.conn
    }
}

impl<'a> Drop for PgGuard<'a> {
    fn drop(&mut self) {
        self.conn.inflight.set(self.conn.inflight.get() - 1);
    }
}

impl WorkerState {
    /// Join-the-shortest-queue over this worker's connections. Statements from different
    /// requests still pipeline on one connection, but a slow query no longer delays a request
    /// that could have used an idle connection (round-robin could not avoid that).
    fn pg(&self) -> PgGuard<'_> {
        let mut best = 0usize;
        let mut best_n = u32::MAX;
        for (i, c) in self.conns.iter().enumerate() {
            let n = c.inflight.get();
            if n < best_n {
                best = i;
                best_n = n;
                if n == 0 {
                    break;
                }
            }
        }
        let conn = &self.conns[best];
        conn.inflight.set(conn.inflight.get() + 1);
        PgGuard { conn }
    }

    /// Response buffers come from a per-worker pool, so idle keep-alive connections hold none.
    fn take_out(&self) -> Vec<u8> {
        let mut v = self
            .out_pool
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(16 * 1024));
        v.clear();
        v.resize(HDR_RESERVE, 0);
        v
    }

    fn give_out(&self, v: Vec<u8>) {
        if v.capacity() <= 256 * 1024 {
            let mut pool = self.out_pool.borrow_mut();
            if pool.len() < 256 {
                pool.push(v);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------------------------

fn env_usize(name: &str) -> Option<usize> {
    env::var(name).ok().and_then(|v| v.parse().ok())
}

fn main() -> io::Result<()> {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80);
    let bind_addr: SocketAddr = format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .expect("Invalid HOST:PORT");

    let jwt_secret =
        env::var("JWT_SECRET").unwrap_or_else(|_| "multicore-server-challenge".to_string());
    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://conduit:conduit@127.0.0.1:5432/conduit".to_string());

    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    // The app is a small slice of the box's CPU (Postgres is the big one), so fewer I/O threads
    // means fewer wakeups and more requests handled per wakeup. All three knobs can be
    // overridden from the environment for experiments.
    let io_workers = env_usize("IO_WORKERS").unwrap_or_else(|| (cores / 2).max(2)).max(1);
    let bcrypt_threads = env_usize("BCRYPT_THREADS")
        .unwrap_or_else(|| (cores / 2).max(2))
        .max(1);
    let pg_total = env_usize("PG_CONNS").unwrap_or(DEFAULT_PG_CONNS).min(MAX_PG_CONNS);
    let pg_per_worker = (pg_total / io_workers).max(1);

    let config = AppConfig {
        bind_addr,
        db_url,
        jwt: JwtAuth::new(jwt_secret.as_bytes()),
    };

    let (bcrypt_tx, bcrypt_rx) = bounded::<BcryptJob>(BCRYPT_QUEUE);
    for idx in 0..bcrypt_threads {
        let rx = bcrypt_rx.clone();
        thread::Builder::new()
            .name(format!("bcrypt-{idx}"))
            .spawn(move || run_bcrypt_worker(rx))?;
    }

    let mut handles = Vec::with_capacity(io_workers);
    for worker_id in 0..io_workers {
        let cfg = config.clone();
        let b_tx = bcrypt_tx.clone();
        handles.push(
            thread::Builder::new()
                .name(format!("io-{worker_id}"))
                .spawn(move || {
                    if let Err(e) = run_io_worker(cfg, b_tx, pg_per_worker) {
                        eprintln!("io worker {worker_id} stopped: {e}");
                    }
                })?,
        );
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn create_reuseport_std_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(16384)?;
    Ok(socket.into())
}

async fn connect_with_retry(db_url: &str) -> PgConn {
    let mut attempts = 0u32;
    loop {
        match PgConn::connect_and_prepare(db_url).await {
            Ok(c) => return c,
            Err(e) => {
                attempts += 1;
                if attempts >= 240 {
                    panic!("cannot connect to Postgres at DATABASE_URL: {e}");
                }
                // Startup only: nothing else runs on this thread yet, so blocking is fine.
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

fn run_io_worker(
    config: AppConfig,
    bcrypt_tx: Sender<BcryptJob>,
    pg_conns: usize,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, io_worker_main(config, bcrypt_tx, pg_conns))
}

/// One I/O worker: its own Postgres connections, its own SO_REUSEPORT listener, its own
/// single-threaded runtime. Nothing is shared with the other workers.
async fn io_worker_main(
    config: AppConfig,
    bcrypt_tx: Sender<BcryptJob>,
    pg_conns: usize,
) -> io::Result<()> {
    let mut conns = Vec::with_capacity(pg_conns);
    for _ in 0..pg_conns {
        conns.push(connect_with_retry(&config.db_url).await);
    }

    let state = Rc::new(WorkerState {
        conns,
        jwt: config.jwt,
        bcrypt_tx,
        out_pool: RefCell::new(Vec::new()),
    });

    let std_listener = create_reuseport_std_listener(config.bind_addr)?;
    let listener = TcpListener::from_std(std_listener)?;

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(true);
                let st = Rc::clone(&state);
                tokio::task::spawn_local(async move {
                    handle_connection(stream, st).await;
                });
            }
            // e.g. EMFILE: yield so other tasks still run instead of spinning on accept
            Err(_) => tokio::task::yield_now().await,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Connection loop
// ---------------------------------------------------------------------------------------------

enum BodyLoc {
    Buf(usize, usize),
    Chunk,
}

async fn read_more(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<usize> {
    if buf.capacity() - buf.len() < 1024 {
        buf.reserve(4096);
    }
    stream.read_buf(buf).await
}

/// Reads the rest of the request body. `Err(0)` = just close; `Err(code)` = answer and close.
async fn read_body(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    chunk_body: &mut Vec<u8>,
    head: &http::Head,
) -> Result<(BodyLoc, usize), u16> {
    let start = head.header_len;
    let mut sent_continue = false;

    if head.chunked {
        loop {
            match http::decode_chunked(&buf[start..], chunk_body) {
                Chunked::Done(n) => return Ok((BodyLoc::Chunk, start + n)),
                Chunked::Bad => return Err(400),
                Chunked::Incomplete => {
                    if head.expect_continue && !sent_continue {
                        sent_continue = true;
                        if stream
                            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return Err(0);
                        }
                    }
                    match read_more(stream, buf).await {
                        Ok(0) | Err(_) => return Err(0),
                        Ok(_) => {}
                    }
                }
            }
        }
    }

    if head.content_length > MAX_BODY {
        return Err(413);
    }
    let end = start + head.content_length;
    while buf.len() < end {
        if head.expect_continue && !sent_continue && buf.len() == start {
            sent_continue = true;
            if stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .is_err()
            {
                return Err(0);
            }
        }
        match read_more(stream, buf).await {
            Ok(0) | Err(_) => return Err(0),
            Ok(_) => {}
        }
    }
    Ok((BodyLoc::Buf(start, end), end))
}

async fn send_error_close(stream: &mut TcpStream, status: u16, msg: &str) {
    let mut out: Vec<u8> = vec![0u8; HDR_RESERVE];
    let st = err(&mut out, status, msg);
    let start = http::frame(&mut out, st, true);
    let _ = stream.write_all(&out[start..]).await;
    let _ = stream.shutdown().await;
}

async fn handle_connection(mut stream: TcpStream, state: Rc<WorkerState>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk_body: Vec<u8> = Vec::new();

    loop {
        // ---- request head
        let head = loop {
            match http::parse_head(&buf) {
                HeadParse::Complete(h) => break h,
                HeadParse::Bad => {
                    send_error_close(&mut stream, 400, "bad request").await;
                    return;
                }
                HeadParse::Partial => {
                    if buf.len() > MAX_HEAD {
                        send_error_close(&mut stream, 400, "request head too large").await;
                        return;
                    }
                }
            }
            match read_more(&mut stream, &mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        };

        // ---- request body
        let (loc, consumed) = match read_body(&mut stream, &mut buf, &mut chunk_body, &head).await
        {
            Ok(x) => x,
            Err(0) => return,
            Err(code) => {
                send_error_close(&mut stream, code, "invalid request body").await;
                return;
            }
        };

        // ---- handle
        let mut out = state.take_out();
        let status = {
            let path_full = std::str::from_utf8(&buf[head.path.0..head.path.1]).unwrap_or("/");
            let (path, query) = match path_full.split_once('?') {
                Some((p, q)) => (p, q),
                None => (path_full, ""),
            };
            let auth_hdr: Option<&[u8]> = head.auth.map(|(s, e)| &buf[s..e]);
            let body: &[u8] = match loc {
                BodyLoc::Buf(s, e) => &buf[s..e],
                BodyLoc::Chunk => &chunk_body[..],
            };
            let req = Req {
                method: head.method,
                path,
                query,
                auth_hdr,
                body,
            };
            dispatch(&state, &req, &mut out).await
        };

        let start = http::frame(&mut out, status, head.close);
        let wrote = stream.write_all(&out[start..]).await;
        state.give_out(out);
        if wrote.is_err() {
            return;
        }
        if head.close {
            let _ = stream.shutdown().await;
            return;
        }

        if consumed >= buf.len() {
            buf.clear();
            if buf.capacity() > 64 * 1024 {
                buf = Vec::new();
            }
        } else {
            buf.drain(..consumed);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------------------------

struct Req<'a> {
    method: Method,
    path: &'a str,
    query: &'a str,
    auth_hdr: Option<&'a [u8]>,
    body: &'a [u8],
}

/// Replaces whatever was written to `out` with a RealWorld-style error body.
fn err(out: &mut Vec<u8>, status: u16, msg: &str) -> u16 {
    out.truncate(HDR_RESERVE);
    out.extend_from_slice(b"{\"errors\":{\"body\":[");
    json::put_str(out, msg);
    out.extend_from_slice(b"]}}");
    status
}

/// Integrity-constraint (23xxx) and data-exception (22xxx) errors are the caller's fault
/// (duplicate username, bad value, ...): 422. Anything else is a server problem: 500.
fn db_err(out: &mut Vec<u8>, e: &tokio_postgres::Error) -> u16 {
    let client_fault = match e.code() {
        Some(c) => {
            let code = c.code();
            code.starts_with("23") || code.starts_with("22")
        }
        None => false,
    };
    if client_fault {
        err(out, 422, "invalid request")
    } else {
        err(out, 500, "database error")
    }
}

/// Auth-required endpoints: `Some((user_id, token))`, otherwise answer 401.
fn require_auth<'a>(state: &WorkerState, req: &Req<'a>) -> Option<(i64, &'a str)> {
    match state.jwt.verify_header(req.auth_hdr) {
        (AuthOutcome::Authenticated(id), Some(tok)) => Some((id, tok)),
        _ => None,
    }
}

/// Auth-optional endpoints: viewer id (0 = anonymous), or `None` for a present-but-invalid
/// token (answer 401).
fn optional_auth(state: &WorkerState, req: &Req<'_>) -> Option<i64> {
    match state.jwt.verify_header(req.auth_hdr).0 {
        AuthOutcome::Authenticated(id) => Some(id),
        AuthOutcome::Anonymous => Some(0),
        AuthOutcome::Invalid => None,
    }
}

fn parse_body(body: &[u8]) -> Option<Value> {
    serde_json::from_slice(body).ok()
}

fn non_empty<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

/// Optional string field of an update body: absent or null -> `Ok(None)`; a string -> `Ok(Some)`;
/// anything else (or an empty string when not allowed) -> `Err`.
fn opt_field<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    allow_empty: bool,
) -> Result<Option<&'a str>, ()> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.is_empty() && !allow_empty {
                Err(())
            } else {
                Ok(Some(s.as_str()))
            }
        }
        Some(_) => Err(()),
    }
}

fn decode_segment(raw: &str) -> Option<Cow<'_, str>> {
    urlencoding::decode(raw).ok()
}

/// Query-string values: `+` is a space, `%XX` is a byte.
fn decode_query_value(v: &str) -> Option<Cow<'_, str>> {
    if v.as_bytes().contains(&b'+') {
        let replaced = v.replace('+', " ");
        match urlencoding::decode(&replaced) {
            Ok(c) => Some(Cow::Owned(c.into_owned())),
            Err(_) => None,
        }
    } else {
        urlencoding::decode(v).ok()
    }
}

/// `limit` (default 20, 1..=100) and `offset` (default 0, >= 0); anything else is a 422.
fn parse_limit_offset(query: &str) -> Option<(i64, i64)> {
    let mut limit: i64 = 20;
    let mut offset: i64 = 0;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "limit" {
                let n: i64 = v.parse().ok()?;
                if !(1..=100).contains(&n) {
                    return None;
                }
                limit = n;
            } else if k == "offset" {
                let n: i64 = v.parse().ok()?;
                if n < 0 {
                    return None;
                }
                offset = n;
            }
        }
    }
    Some((limit, offset))
}

struct Filters<'a> {
    tag: Option<Cow<'a, str>>,
    author: Option<Cow<'a, str>>,
    favorited: Option<Cow<'a, str>>,
}

fn parse_filters(query: &str) -> Filters<'_> {
    let mut f = Filters {
        tag: None,
        author: None,
        favorited: None,
    };
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if v.is_empty() {
            continue;
        }
        let slot = match k {
            "tag" => &mut f.tag,
            "author" => &mut f.author,
            "favorited" => &mut f.favorited,
            _ => continue,
        };
        if slot.is_none() {
            if let Some(d) = decode_query_value(v) {
                *slot = Some(d);
            }
        }
    }
    f
}

/// bcrypt only uses the first 72 bytes of a password. The spec wants longer ones refused (422)
/// rather than silently truncated.
const BCRYPT_MAX_PASSWORD_BYTES: usize = 72;

fn hash_error_message(code: u16) -> &'static str {
    if code == 422 {
        "password must be at most 72 bytes"
    } else {
        "could not hash password"
    }
}

async fn bcrypt_hash(state: &WorkerState, plaintext: &str) -> Result<String, u16> {
    if plaintext.len() > BCRYPT_MAX_PASSWORD_BYTES {
        return Err(422);
    }
    let (tx, rx) = oneshot::channel();
    let job = BcryptJob::Hash {
        plaintext: plaintext.to_string(),
        reply: tx,
    };
    if state.bcrypt_tx.try_send(job).is_err() {
        return Err(503);
    }
    match rx.await {
        Ok(Some(h)) => Ok(h),
        Ok(None) => Err(422),
        Err(_) => Err(500),
    }
}

async fn bcrypt_verify(state: &WorkerState, plaintext: &str, hash: String) -> Result<bool, u16> {
    let (tx, rx) = oneshot::channel();
    let job = BcryptJob::Verify {
        plaintext: plaintext.to_string(),
        hash,
        reply: tx,
    };
    if state.bcrypt_tx.try_send(job).is_err() {
        return Err(503);
    }
    match rx.await {
        Ok(ok) => Ok(ok),
        Err(_) => Err(500),
    }
}

fn article_response(out: &mut Vec<u8>, row: &Row, status: u16) -> u16 {
    out.extend_from_slice(b"{\"article\":");
    if db::write_article(out, row, 0, true).is_err() {
        return err(out, 500, "decode error");
    }
    out.push(b'}');
    status
}

fn list_response(out: &mut Vec<u8>, res: Result<Vec<Row>, tokio_postgres::Error>) -> u16 {
    match res {
        Ok(rows) => {
            if db::write_article_list(out, &rows).is_err() {
                return err(out, 500, "decode error");
            }
            200
        }
        Err(e) => db_err(out, &e),
    }
}

// ---------------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------------

async fn dispatch(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let rest = match req.path.strip_prefix("/api/") {
        Some(r) => r,
        None => return err(out, 404, "not found"),
    };
    let (seg, tail) = match rest.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };

    match (req.method, seg, tail) {
        (Method::Get, "tags", None) => h_tags(state, out).await,
        (Method::Post, "users", None) => h_register(state, req, out).await,
        (Method::Post, "users", Some("login")) => h_login(state, req, out).await,
        (Method::Get, "user", None) => h_get_user(state, req, out).await,
        (Method::Put, "user", None) => h_put_user(state, req, out).await,
        (_, "profiles", Some(t)) => h_profiles(state, req, t, out).await,
        (Method::Get, "articles", None) => h_list(state, req, out).await,
        (Method::Post, "articles", None) => h_create_article(state, req, out).await,
        (_, "articles", Some(t)) => h_article_routes(state, req, t, out).await,
        _ => err(out, 404, "not found"),
    }
}

async fn h_article_routes(
    state: &WorkerState,
    req: &Req<'_>,
    tail: &str,
    out: &mut Vec<u8>,
) -> u16 {
    let (first, sub) = match tail.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (tail, None),
    };
    match (req.method, first, sub) {
        (Method::Get, "feed", None) => h_feed(state, req, out).await,
        (Method::Get, _, None) => h_get_article(state, req, first, out).await,
        (Method::Put, _, None) => h_update_article(state, req, first, out).await,
        (Method::Delete, _, None) => h_delete_article(state, req, first, out).await,
        (Method::Post, _, Some("favorite")) => h_favorite(state, req, first, true, out).await,
        (Method::Delete, _, Some("favorite")) => h_favorite(state, req, first, false, out).await,
        (Method::Get, _, Some("comments")) => h_get_comments(state, req, first, out).await,
        (Method::Post, _, Some("comments")) => h_add_comment(state, req, first, out).await,
        (Method::Delete, _, Some(s)) => match s.strip_prefix("comments/") {
            Some(id) => h_delete_comment(state, req, first, id, out).await,
            None => err(out, 404, "not found"),
        },
        _ => err(out, 404, "not found"),
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers: tags and users
// ---------------------------------------------------------------------------------------------

async fn h_tags(state: &WorkerState, out: &mut Vec<u8>) -> u16 {
    let pg = state.pg();
    match pg.client.query_one(&pg.s.tags, &[]).await {
        Ok(row) => {
            if db::write_tags(out, &row).is_err() {
                return err(out, 500, "decode error");
            }
            200
        }
        Err(e) => db_err(out, &e),
    }
}

async fn h_register(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let parsed = match parse_body(req.body) {
        Some(v) => v,
        None => return err(out, 422, "invalid json"),
    };
    let u = match parsed.get("user") {
        Some(u) => u,
        None => return err(out, 422, "missing user"),
    };
    let username = match non_empty(u, "username") {
        Some(s) => s,
        None => return err(out, 422, "invalid username"),
    };
    let email = match non_empty(u, "email") {
        Some(s) => s,
        None => return err(out, 422, "invalid email"),
    };
    let password = match non_empty(u, "password") {
        Some(s) => s,
        None => return err(out, 422, "invalid password"),
    };

    let hash = match bcrypt_hash(state, password).await {
        Ok(h) => h,
        Err(code) => return err(out, code, hash_error_message(code)),
    };

    let pg = state.pg();
    match pg
        .client
        .query_one(&pg.s.register, &[&username, &email, &hash])
        .await
    {
        Ok(row) => {
            let id: i64 = match row.try_get(0) {
                Ok(v) => v,
                Err(_) => return err(out, 500, "decode error"),
            };
            let token = state.jwt.sign(id);
            if db::write_user(out, &row, &token).is_err() {
                return err(out, 500, "decode error");
            }
            201
        }
        Err(e) => db_err(out, &e),
    }
}

async fn h_login(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let parsed = match parse_body(req.body) {
        Some(v) => v,
        None => return err(out, 422, "invalid json"),
    };
    let u = match parsed.get("user") {
        Some(u) => u,
        None => return err(out, 422, "missing user"),
    };
    let email = match non_empty(u, "email") {
        Some(s) => s,
        None => return err(out, 422, "invalid email"),
    };
    let password = match non_empty(u, "password") {
        Some(s) => s,
        None => return err(out, 422, "invalid password"),
    };

    // Release the connection before the (slow) bcrypt verification.
    let res = {
        let pg = state.pg();
        let r = pg.client.query_opt(&pg.s.login, &[&email]).await;
        r
    };
    let row = match res {
        Ok(Some(r)) => r,
        Ok(None) => return err(out, 401, "invalid credentials"),
        Err(e) => return db_err(out, &e),
    };

    let hash: String = match row.try_get::<usize, &str>(5) {
        Ok(h) => h.to_string(),
        Err(_) => return err(out, 500, "decode error"),
    };
    match bcrypt_verify(state, password, hash).await {
        Ok(true) => {}
        Ok(false) => return err(out, 401, "invalid credentials"),
        Err(code) => return err(out, code, "login unavailable"),
    }

    let id: i64 = match row.try_get(0) {
        Ok(v) => v,
        Err(_) => return err(out, 500, "decode error"),
    };
    let token = state.jwt.sign(id);
    if db::write_user(out, &row, &token).is_err() {
        return err(out, 500, "decode error");
    }
    200
}

async fn h_get_user(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let (uid, token) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let pg = state.pg();
    match pg.client.query_opt(&pg.s.get_user, &[&uid]).await {
        Ok(Some(row)) => {
            if db::write_user(out, &row, token).is_err() {
                return err(out, 500, "decode error");
            }
            200
        }
        Ok(None) => err(out, 401, "unauthorized"),
        Err(e) => db_err(out, &e),
    }
}

async fn h_put_user(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let (uid, token) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let parsed = match parse_body(req.body) {
        Some(v) => v,
        None => return err(out, 422, "invalid json"),
    };
    let u = match parsed.get("user").and_then(|v| v.as_object()) {
        Some(u) => u,
        None => return err(out, 422, "missing user"),
    };
    let email = match opt_field(u, "email", false) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid email"),
    };
    let username = match opt_field(u, "username", false) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid username"),
    };
    let password = match opt_field(u, "password", false) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid password"),
    };
    let bio = match opt_field(u, "bio", true) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid bio"),
    };
    let image = match opt_field(u, "image", true) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid image"),
    };

    let pw_hash: Option<String> = match password {
        Some(p) => match bcrypt_hash(state, p).await {
            Ok(h) => Some(h),
            Err(code) => return err(out, code, hash_error_message(code)),
        },
        None => None,
    };

    let pg = state.pg();
    match pg
        .client
        .query_opt(
            &pg.s.update_user,
            &[&uid, &email, &username, &pw_hash, &bio, &image],
        )
        .await
    {
        Ok(Some(row)) => {
            if db::write_user(out, &row, token).is_err() {
                return err(out, 500, "decode error");
            }
            200
        }
        Ok(None) => err(out, 401, "unauthorized"),
        Err(e) => db_err(out, &e),
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers: profiles
// ---------------------------------------------------------------------------------------------

async fn h_profiles(state: &WorkerState, req: &Req<'_>, tail: &str, out: &mut Vec<u8>) -> u16 {
    match tail.split_once('/') {
        None => {
            if req.method != Method::Get {
                return err(out, 404, "not found");
            }
            let viewer = match optional_auth(state, req) {
                Some(v) => v,
                None => return err(out, 401, "unauthorized"),
            };
            let name = match decode_segment(tail) {
                Some(n) => n,
                None => return err(out, 404, "profile not found"),
            };
            let name: &str = &name;
            let pg = state.pg();
            match pg.client.query_opt(&pg.s.profile, &[&viewer, &name]).await {
                Ok(Some(row)) => {
                    if db::write_profile(out, &row).is_err() {
                        return err(out, 500, "decode error");
                    }
                    200
                }
                Ok(None) => err(out, 404, "profile not found"),
                Err(e) => db_err(out, &e),
            }
        }
        Some((raw_name, "follow")) => {
            let follow = match req.method {
                Method::Post => true,
                Method::Delete => false,
                _ => return err(out, 404, "not found"),
            };
            let (uid, _) = match require_auth(state, req) {
                Some(x) => x,
                None => return err(out, 401, "unauthorized"),
            };
            let name = match decode_segment(raw_name) {
                Some(n) => n,
                None => return err(out, 404, "profile not found"),
            };
            let name: &str = &name;
            let pg = state.pg();
            let stmt = if follow { &pg.s.follow } else { &pg.s.unfollow };
            match pg.client.query_opt(stmt, &[&uid, &name]).await {
                Ok(Some(row)) => {
                    if db::write_profile(out, &row).is_err() {
                        return err(out, 500, "decode error");
                    }
                    200
                }
                Ok(None) => err(out, 404, "profile not found"),
                Err(e) => db_err(out, &e),
            }
        }
        Some(_) => err(out, 404, "not found"),
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers: article lists
// ---------------------------------------------------------------------------------------------

async fn h_list(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let viewer = match optional_auth(state, req) {
        Some(v) => v,
        None => return err(out, 401, "unauthorized"),
    };
    let (limit, offset) = match parse_limit_offset(req.query) {
        Some(p) => p,
        None => return err(out, 422, "invalid limit or offset"),
    };
    // If more than one filter is present only the first of tag, author, favorited applies.
    let f = parse_filters(req.query);

    let pg = state.pg();
    let res = if let Some(tag) = f.tag.as_deref() {
        pg.client
            .query(&pg.s.list_tag, &[&viewer, &limit, &offset, &tag])
            .await
    } else if let Some(author) = f.author.as_deref() {
        pg.client
            .query(&pg.s.list_author, &[&viewer, &limit, &offset, &author])
            .await
    } else if let Some(fav) = f.favorited.as_deref() {
        pg.client
            .query(&pg.s.list_fav, &[&viewer, &limit, &offset, &fav])
            .await
    } else {
        pg.client
            .query(&pg.s.list_all, &[&viewer, &limit, &offset])
            .await
    };
    list_response(out, res)
}

async fn h_feed(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let (uid, _) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let (limit, offset) = match parse_limit_offset(req.query) {
        Some(p) => p,
        None => return err(out, 422, "invalid limit or offset"),
    };
    let pg = state.pg();
    let res = pg
        .client
        .query(&pg.s.list_feed, &[&uid, &limit, &offset])
        .await;
    list_response(out, res)
}

// ---------------------------------------------------------------------------------------------
// Handlers: single articles
// ---------------------------------------------------------------------------------------------

async fn h_get_article(
    state: &WorkerState,
    req: &Req<'_>,
    raw_slug: &str,
    out: &mut Vec<u8>,
) -> u16 {
    let viewer = match optional_auth(state, req) {
        Some(v) => v,
        None => return err(out, 401, "unauthorized"),
    };
    let slug = match decode_segment(raw_slug) {
        Some(s) => s,
        None => return err(out, 404, "article not found"),
    };
    let slug: &str = &slug;
    let pg = state.pg();
    match pg
        .client
        .query_opt(&pg.s.article_by_slug, &[&viewer, &slug])
        .await
    {
        Ok(Some(row)) => article_response(out, &row, 200),
        Ok(None) => err(out, 404, "article not found"),
        Err(e) => db_err(out, &e),
    }
}

async fn h_create_article(state: &WorkerState, req: &Req<'_>, out: &mut Vec<u8>) -> u16 {
    let (uid, _) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let parsed = match parse_body(req.body) {
        Some(v) => v,
        None => return err(out, 422, "invalid json"),
    };
    let a = match parsed.get("article") {
        Some(a) if a.is_object() => a,
        _ => return err(out, 422, "missing article"),
    };
    let title = match non_empty(a, "title") {
        Some(s) => s,
        None => return err(out, 422, "invalid title"),
    };
    let description = match non_empty(a, "description") {
        Some(s) => s,
        None => return err(out, 422, "invalid description"),
    };
    let art_body = match non_empty(a, "body") {
        Some(s) => s,
        None => return err(out, 422, "invalid body"),
    };

    let mut tags: Vec<String> = Vec::new();
    match a.get("tagList") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                match item.as_str() {
                    Some(s) if !s.is_empty() => tags.push(s.to_string()),
                    _ => return err(out, 422, "invalid tag"),
                }
            }
        }
        Some(_) => return err(out, 422, "invalid tagList"),
    }

    let slug_prefix = db::slugify(title);
    let pg = state.pg();
    if !tags.is_empty() {
        if let Err(e) = pg.client.execute(&pg.s.upsert_tags, &[&tags]).await {
            return db_err(out, &e);
        }
    }
    match pg
        .client
        .query_one(
            &pg.s.create_article,
            &[&uid, &slug_prefix, &title, &description, &art_body, &tags],
        )
        .await
    {
        Ok(row) => article_response(out, &row, 201),
        Err(e) => db_err(out, &e),
    }
}

async fn h_update_article(
    state: &WorkerState,
    req: &Req<'_>,
    raw_slug: &str,
    out: &mut Vec<u8>,
) -> u16 {
    let (uid, _) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let parsed = match parse_body(req.body) {
        Some(v) => v,
        None => return err(out, 422, "invalid json"),
    };
    let a = match parsed.get("article").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => return err(out, 422, "missing article"),
    };
    let title = match opt_field(a, "title", false) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid title"),
    };
    let description = match opt_field(a, "description", false) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid description"),
    };
    let art_body = match opt_field(a, "body", false) {
        Ok(v) => v,
        Err(()) => return err(out, 422, "invalid body"),
    };
    let slug = match decode_segment(raw_slug) {
        Some(s) => s,
        None => return err(out, 404, "article not found"),
    };
    let slug: &str = &slug;
    // The SQL appends "-<id>" to this prefix, exactly like article creation does.
    let new_prefix: Option<String> = title.map(db::slugify);

    let pg = state.pg();
    let row = match pg
        .client
        .query_opt(
            &pg.s.update_article,
            &[&slug, &uid, &title, &description, &art_body, &new_prefix],
        )
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return err(out, 404, "article not found"),
        Err(e) => return db_err(out, &e),
    };
    let id: i64 = match row.try_get(0) {
        Ok(v) => v,
        Err(_) => return err(out, 500, "decode error"),
    };
    let updated: bool = match row.try_get(2) {
        Ok(v) => v,
        Err(_) => return err(out, 500, "decode error"),
    };
    if !updated {
        return err(out, 403, "forbidden");
    }
    match pg
        .client
        .query_one(&pg.s.article_by_id, &[&uid, &id])
        .await
    {
        Ok(r) => article_response(out, &r, 200),
        Err(e) => db_err(out, &e),
    }
}

async fn h_delete_article(
    state: &WorkerState,
    req: &Req<'_>,
    raw_slug: &str,
    out: &mut Vec<u8>,
) -> u16 {
    let (uid, _) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let slug = match decode_segment(raw_slug) {
        Some(s) => s,
        None => return err(out, 404, "article not found"),
    };
    let slug: &str = &slug;
    let pg = state.pg();
    match pg
        .client
        .query_opt(&pg.s.delete_article, &[&slug, &uid])
        .await
    {
        Ok(Some(row)) => {
            let deleted: bool = match row.try_get(1) {
                Ok(v) => v,
                Err(_) => return err(out, 500, "decode error"),
            };
            if deleted {
                204
            } else {
                err(out, 403, "forbidden")
            }
        }
        Ok(None) => err(out, 404, "article not found"),
        Err(e) => db_err(out, &e),
    }
}

async fn h_favorite(
    state: &WorkerState,
    req: &Req<'_>,
    raw_slug: &str,
    favorite: bool,
    out: &mut Vec<u8>,
) -> u16 {
    let (uid, _) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let slug = match decode_segment(raw_slug) {
        Some(s) => s,
        None => return err(out, 404, "article not found"),
    };
    let slug: &str = &slug;
    let pg = state.pg();
    let stmt = if favorite {
        &pg.s.favorite
    } else {
        &pg.s.unfavorite
    };
    match pg.client.query_opt(stmt, &[&uid, &slug]).await {
        Ok(Some(row)) => article_response(out, &row, 200),
        Ok(None) => err(out, 404, "article not found"),
        Err(e) => db_err(out, &e),
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers: comments
// ---------------------------------------------------------------------------------------------

async fn h_get_comments(
    state: &WorkerState,
    req: &Req<'_>,
    raw_slug: &str,
    out: &mut Vec<u8>,
) -> u16 {
    let viewer = match optional_auth(state, req) {
        Some(v) => v,
        None => return err(out, 401, "unauthorized"),
    };
    let slug = match decode_segment(raw_slug) {
        Some(s) => s,
        None => return err(out, 404, "article not found"),
    };
    let slug: &str = &slug;
    let pg = state.pg();
    match pg.client.query(&pg.s.comments, &[&viewer, &slug]).await {
        Ok(rows) => {
            if rows.is_empty() {
                return err(out, 404, "article not found");
            }
            if db::write_comments(out, &rows).is_err() {
                return err(out, 500, "decode error");
            }
            200
        }
        Err(e) => db_err(out, &e),
    }
}

async fn h_add_comment(
    state: &WorkerState,
    req: &Req<'_>,
    raw_slug: &str,
    out: &mut Vec<u8>,
) -> u16 {
    let (uid, _) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let parsed = match parse_body(req.body) {
        Some(v) => v,
        None => return err(out, 422, "invalid json"),
    };
    let text = match parsed.get("comment").and_then(|c| non_empty(c, "body")) {
        Some(s) => s,
        None => return err(out, 422, "invalid comment body"),
    };
    let slug = match decode_segment(raw_slug) {
        Some(s) => s,
        None => return err(out, 404, "article not found"),
    };
    let slug: &str = &slug;
    let pg = state.pg();
    match pg
        .client
        .query_opt(&pg.s.create_comment, &[&slug, &uid, &text])
        .await
    {
        Ok(Some(row)) => {
            out.extend_from_slice(b"{\"comment\":");
            if db::write_comment(out, &row).is_err() {
                return err(out, 500, "decode error");
            }
            out.push(b'}');
            201
        }
        Ok(None) => err(out, 404, "article not found"),
        Err(e) => db_err(out, &e),
    }
}

async fn h_delete_comment(
    state: &WorkerState,
    req: &Req<'_>,
    raw_slug: &str,
    raw_id: &str,
    out: &mut Vec<u8>,
) -> u16 {
    let (uid, _) = match require_auth(state, req) {
        Some(x) => x,
        None => return err(out, 401, "unauthorized"),
    };
    let comment_id: i64 = match raw_id.parse() {
        Ok(id) if id > 0 => id,
        _ => return err(out, 404, "comment not found"),
    };
    let slug = match decode_segment(raw_slug) {
        Some(s) => s,
        None => return err(out, 404, "comment not found"),
    };
    let slug: &str = &slug;
    let pg = state.pg();
    match pg
        .client
        .query_opt(&pg.s.delete_comment, &[&comment_id, &slug, &uid])
        .await
    {
        Ok(Some(row)) => {
            let deleted: bool = match row.try_get(1) {
                Ok(v) => v,
                Err(_) => return err(out, 500, "decode error"),
            };
            if deleted {
                204
            } else {
                err(out, 403, "forbidden")
            }
        }
        Ok(None) => err(out, 404, "comment not found"),
        Err(e) => db_err(out, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_and_offset() {
        assert_eq!(parse_limit_offset(""), Some((20, 0)));
        assert_eq!(parse_limit_offset("limit=10&offset=30"), Some((10, 30)));
        assert_eq!(parse_limit_offset("tag=x&limit=100"), Some((100, 0)));
        assert_eq!(parse_limit_offset("limit=0"), None);
        assert_eq!(parse_limit_offset("limit=101"), None);
        assert_eq!(parse_limit_offset("limit=abc"), None);
        assert_eq!(parse_limit_offset("offset=-1"), None);
        assert_eq!(parse_limit_offset("limit="), None);
    }

    #[test]
    fn filters_decode_plus_and_percent() {
        let f = parse_filters("tag=machine+learning&author=a%20b&favorited=&limit=5");
        assert_eq!(f.tag.as_deref(), Some("machine learning"));
        assert_eq!(f.author.as_deref(), Some("a b"));
        assert!(f.favorited.is_none());
        // first occurrence wins
        let f = parse_filters("tag=one&tag=two");
        assert_eq!(f.tag.as_deref(), Some("one"));
    }

    #[test]
    fn error_body_shape() {
        let mut out = vec![0u8; HDR_RESERVE];
        out.extend_from_slice(b"partial garbage");
        assert_eq!(err(&mut out, 422, "bad \"x\""), 422);
        assert_eq!(&out[HDR_RESERVE..], br#"{"errors":{"body":["bad \"x\""]}}"#.as_slice());
    }
}