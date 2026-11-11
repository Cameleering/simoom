//! simoom-server with simoom's default features: the campaign routes over HTTP/1.1 and h2c.
//!
//! - `GET /` 13-byte `Hello, World!` (S1), `POST /echo` the request body back (S3),
//!   `GET /64k` and `GET /1m` fixed bodies from memory (S4);
//! - HTTP/1.1 and h2c (prior knowledge) on `--addr`.
//!
//! ```text
//! simoom-default [--addr 0.0.0.0:8080] [--threads N] [--backend epoll|io_uring|auto]
//!     [--mode fixed|builder] [--keepalive-s 120] [--no-watchdog]
//! ```

#![forbid(unsafe_code)]

use simoom::{Backend, Limits, Outcome, Reply, Request, Server, StaticReply};
use std::sync::Arc;
use std::time::Duration;

/// The large bodies are built on first use (K7): built at start-up and touched, they were
/// 1.06 MiB of the server's idle memory, which the campaign then counted against simoom.
fn body(n: usize) -> &'static [u8] {
    static B64K: std::sync::OnceLock<&'static [u8]> = std::sync::OnceLock::new();
    static B1M: std::sync::OnceLock<&'static [u8]> = std::sync::OnceLock::new();
    let cell = if n == 64 * 1024 { &B64K } else { &B1M };
    cell.get_or_init(|| Box::leak(vec![b'x'; n].into_boxed_slice()))
}

fn main() {
    let mut addr = "0.0.0.0:8080".to_string();
    let mut threads = 0usize;
    let mut backend = Backend::Auto;
    let mut mode = "fixed".to_string();
    let mut keepalive = 120u64;
    let mut watchdog = true;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--no-watchdog" => {
                watchdog = false;
                i += 1;
                continue;
            }
            "--addr" => addr = val,
            "--threads" => threads = val.parse().expect("--threads"),
            "--mode" => mode = val,
            "--keepalive-s" => keepalive = val.parse().expect("--keepalive-s"),
            "--backend" => {
                backend = match val.as_str() {
                    "epoll" => Backend::Epoll,
                    "io_uring" | "uring" => Backend::IoUring,
                    _ => Backend::Auto,
                }
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let mut limits = Limits { keep_alive_timeout: Duration::from_secs(keepalive), max_body: 16 << 20, ..Limits::default() };
    if !watchdog {
        limits.inline_budget = None;
    }
    let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let builder = mode == "builder";
    let svc = move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        match req.path() {
            b"/64k" => reply.header("content-type", "application/octet-stream").body_static(body(64 * 1024)),
            b"/1m" => reply.header("content-type", "application/octet-stream").body_static(body(1024 * 1024)),
            b"/echo" => {
                let body = req.body();
                reply.header("content-type", "application/json").body_copy(body)
            }
            _ => {
                if builder {
                    reply.header("content-type", "text/plain").body_static(b"Hello, World!")
                } else {
                    reply.fixed(&hello)
                }
            }
        }
    };
    let server = Server::builder().listen(addr.as_str()).threads(threads).backend(backend).limits(limits).service(svc).start().expect("start");
    eprintln!(
        "simoom-default: {} on {:?}, back end {:?}{}",
        mode,
        server.local_addrs(),
        server.backend(),
        server.fallback_reason().map(|r| format!(" ({r})")).unwrap_or_default()
    );
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
