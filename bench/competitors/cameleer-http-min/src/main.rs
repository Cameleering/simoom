//! cameleer-http with a fixed 13-byte reply: the start-up and memory baseline.
//!
//! ```text
//! cameleer-http-min [--addr 127.0.0.1:8080] [--tls-addr 127.0.0.1:8443 --cert cert.pem --key key.pem]
//! ```
//!
//! Prints `ready` on standard output once every listener is bound, then serves until killed.

use cameleer_http::http::{HttpRequest, HttpResponse};
use cameleer_http::server::{HttpServer, ServerConfig};
use std::io::Write;
use std::sync::Arc;

fn main() {
    let mut addr = "127.0.0.1:8080".to_string();
    let mut tls_addr: Option<String> = None;
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--addr" => addr = val,
            "--tls-addr" => tls_addr = Some(val),
            "--cert" => cert = Some(val),
            "--key" => key = Some(val),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let reply = |_req: &mut HttpRequest| -> HttpResponse {
        let mut r = HttpResponse::new(200);
        r.headers.set("Content-Type", "text/plain");
        r.body = b"Hello, World!".to_vec();
        r
    };
    // TLS configuration first, so the plain listener (the one the cold-start probe hits) is
    // bound only once everything is ready, as simoom's `start` does.
    let tls = match (tls_addr, cert, key) {
        (Some(a), Some(c), Some(k)) => {
            let cfg = cameleer_tls::TlsServerConfig::from_pem(&std::fs::read(c).expect("--cert"), &std::fs::read(k).expect("--key")).expect("certificate and key");
            Some((a, ServerConfig { tls: Some(Arc::new(cfg)), ..ServerConfig::default() }))
        }
        _ => None,
    };
    let _tls = tls.map(|(a, sc)| HttpServer::bind(a.as_str(), sc, reply).expect("bind tls"));
    let _plain = HttpServer::bind(addr.as_str(), ServerConfig::default(), reply).expect("bind");
    let mut out = std::io::stdout();
    let _ = writeln!(out, "ready");
    let _ = out.flush();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
