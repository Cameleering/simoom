//! The smallest server: a fixed 13-byte reply, plain and optionally TLS and HTTP/3. The
//! start-up and memory counterpart of `bench/competitors/cameleer-http-min` (docs/STATUS.md,
//! "Start-up and memory against cameleer-http").
//!
//! TLS needs the `tls` feature and HTTP/3 the `http3` feature (`--features full` for both); the
//! default features build the plain-only row.
//!
//! ```text
//! cargo run --release -p simoom --features full --example min_server -- [--addr 127.0.0.1:8080]
//!     [--tls-addr 127.0.0.1:8443 --cert cert.pem --key key.pem] [--quic-addr 127.0.0.1:8443]
//!     [--threads N]
//! ```
//!
//! Prints `ready` on standard output once every listener is bound, then serves until killed.

#![forbid(unsafe_code)]

use simoom::{Outcome, Reply, Request, Server, StaticReply};
use std::io::Write;
use std::sync::Arc;

fn main() {
    let mut addr = "127.0.0.1:8080".to_string();
    let mut tls_addr: Option<String> = None;
    let mut quic_addr: Option<String> = None;
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut threads: Option<usize> = None;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--addr" => addr = val,
            "--tls-addr" => tls_addr = Some(val),
            "--quic-addr" => quic_addr = Some(val),
            "--cert" => cert = Some(val),
            "--key" => key = Some(val),
            "--threads" => threads = Some(val.parse().expect("--threads")),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let mut b = Server::builder().listen(addr.as_str()).service(move |_req: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.fixed(&hello) });
    if let Some(t) = threads {
        b = b.threads(t);
    }
    #[cfg(feature = "tls")]
    if let (Some(c), Some(k)) = (&cert, &key) {
        use simoom::tls::{CertifiedKey, ServerConfig};
        let cfg = ServerConfig::new(CertifiedKey::from_pem(&std::fs::read(c).expect("--cert"), &std::fs::read(k).expect("--key")).expect("certificate and key"));
        #[cfg(feature = "http3")]
        if let Some(q) = &quic_addr {
            b = b.listen_quic(q.as_str()).quic_tls(cfg.clone());
        }
        if let Some(t) = &tls_addr {
            b = b.listen_tls(t.as_str()).tls(cfg);
        }
    }
    #[cfg(not(feature = "tls"))]
    assert!(cert.is_none() && key.is_none() && tls_addr.is_none(), "TLS needs the `tls` feature");
    #[cfg(not(feature = "http3"))]
    assert!(quic_addr.is_none(), "HTTP/3 needs the `http3` feature");
    let _server = b.start().expect("start");
    let mut out = std::io::stdout();
    let _ = writeln!(out, "ready");
    let _ = out.flush();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
