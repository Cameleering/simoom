//! The simoom side of the benchmark campaign: the same routes every competitor serves.
//!
//! - `GET /` 13-byte `Hello, World!` (S1), `POST /echo` the request body back (S3),
//!   `GET /64k` and `GET /1m` fixed bodies from memory (S4);
//! - HTTP/1.1 and h2c (prior knowledge) on `--addr` (8080), TLS 1.3 with ALPN h2/http1.1 on
//!   `--tls-addr` (8443) and HTTP/3 on `--quic-addr` (8443/udp) when `--cert`/`--key` are given.
//!
//! ```text
//! simoom-server [--addr 0.0.0.0:8080] [--tls-addr 0.0.0.0:8443] [--quic-addr 0.0.0.0:8443]
//!     [--cert cert.pem --key key.pem] [--threads N] [--backend epoll|io_uring|auto]
//!     [--mode fixed|builder] [--keepalive-s 120] [--no-quic] [--no-tls] [--no-watchdog]
//! ```
//!
//! `--mode fixed` answers `/` with a pre-serialized `StaticReply` (the same path as the facade's
//! `bench_server` example); `--mode builder` builds every reply. Large bodies always go out as
//! `body_static` (no copy of the body per request). Runs until killed.

#![forbid(unsafe_code)]

use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Backend, Limits, Outcome, Reply, Request, Server, StaticReply};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let mut addr = "0.0.0.0:8080".to_string();
    let mut tls_addr = "0.0.0.0:8443".to_string();
    let mut quic_addr = "0.0.0.0:8443".to_string();
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut threads = 0usize;
    let mut backend = Backend::Auto;
    let mut mode = "fixed".to_string();
    let mut keepalive = 120u64;
    let mut quic = true;
    let mut tls = true;
    let mut watchdog = true;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--no-quic" => {
                quic = false;
                i += 1;
                continue;
            }
            "--no-watchdog" => {
                watchdog = false;
                i += 1;
                continue;
            }
            "--no-tls" => {
                tls = false;
                quic = false;
                i += 1;
                continue;
            }
            "--addr" => addr = val,
            "--tls-addr" => tls_addr = val,
            "--quic-addr" => quic_addr = val,
            "--cert" => cert = Some(val),
            "--key" => key = Some(val),
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
        // the stall watchdog times handlers by wall clock; on a busy VM a preempted 13-byte
        // handler can look slow and move the service to the offload pool (see the campaign notes)
        limits.inline_budget = None;
    }
    let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let b64k: &'static [u8] = Box::leak(vec![b'x'; 64 * 1024].into_boxed_slice());
    let b1m: &'static [u8] = Box::leak(vec![b'x'; 1024 * 1024].into_boxed_slice());
    let builder = mode == "builder";
    let svc = move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        match req.path() {
            b"/64k" => reply.header("content-type", "application/octet-stream").body_static(b64k),
            b"/1m" => reply.header("content-type", "application/octet-stream").body_static(b1m),
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
    let mut b = Server::builder().listen(addr.as_str()).threads(threads).backend(backend).limits(limits).service(svc);
    if let (true, Some(c), Some(k)) = (tls, &cert, &key) {
        let cp = std::fs::read(c).expect("--cert");
        let kp = std::fs::read(k).expect("--key");
        // One parsed certificate and one set of ticket keys for both listeners (clones share
        // them); the builder sets each listener's ALPN.
        let cfg = ServerConfig::new(CertifiedKey::from_pem(&cp, &kp).expect("certificate and key"));
        if quic {
            b = b.listen_quic(quic_addr.as_str()).quic_tls(cfg.clone());
        }
        b = b.listen_tls(tls_addr.as_str()).tls(cfg);
    }
    let server = b.start().expect("start");
    eprintln!(
        "simoom-server: {} on {:?} quic {:?}, back end {:?}{}",
        mode,
        server.local_addrs(),
        server.quic_addrs(),
        server.backend(),
        server.fallback_reason().map(|r| format!(" ({r})")).unwrap_or_default()
    );
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
