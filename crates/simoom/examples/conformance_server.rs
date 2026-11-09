//! A server for live conformance and desync testing with external tools (`nghttp`, `h2load`,
//! curl, nginx and haproxy in front of it, and the `h2_live` conformance runner).
//!
//! ```text
//! cargo run --release -p simoom --features full --example conformance_server -- \
//!     [--addr 127.0.0.1:8080] [--tls-addr 127.0.0.1:8443] [--out DIR] [--garden]
//! ```
//!
//! `--addr` is a cleartext listener (HTTP/1.1, h2c prior knowledge, `Upgrade: h2c`);
//! `--tls-addr` (feature `tls`) is TLS 1.3 with ALPN h2 / http/1.1 and a certificate for
//! `localhost` and `127.0.0.1` signed by a private CA written to `DIR/ca.pem`.
//!
//! Every request is answered with one line describing what the server parsed, and the same line
//! goes to stdout, so a desync harness can count the requests the server saw and compare their
//! boundaries:
//!
//! ```text
//! REQ <n> <method> <target> len=<body bytes> sha=<fnv-1a of the body, hex>
//! ```
//!
//! `GET /big/<n>` answers with `n` bytes (for flow-control and many-stream tests).
//!
//! `--garden` answers every request with the HTTP Garden's echo format instead (JSON with the
//! base64 of the method, version, target, each header and the body), so the server can be an
//! origin in the Garden's differential tests (<https://github.com/narfindustries/http-garden>).

#![forbid(unsafe_code)]

use simoom::{Outcome, Reply, Request, Server, Version};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &x| (h ^ u64::from(x)).wrapping_mul(0x100_0000_01b3))
}

fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            s.push(if k <= c.len() { A[(n >> (18 - 6 * k)) as usize & 63] as char } else { '=' });
        }
    }
    s
}

/// The HTTP Garden's echo body for a request.
fn garden_json(req: &Request<'_>) -> String {
    let version: &[u8] = match req.version() {
        Version::Http10 => b"1.0",
        Version::Http11 => b"1.1",
        Version::H2 => b"2",
        Version::H3 => b"3",
    };
    let headers: Vec<String> = req.headers().map(|(k, v)| format!("[\"{}\",\"{}\"]", base64(k), base64(v))).collect();
    format!(
        "{{\"method\":\"{}\",\"version\":\"{}\",\"uri\":\"{}\",\"headers\":[{}],\"body\":\"{}\"}}",
        base64(req.method()),
        base64(version),
        base64(req.target()),
        headers.join(","),
        base64(req.body())
    )
}

fn main() {
    let mut addr = "127.0.0.1:8080".to_string();
    let mut tls_addr: Option<String> = None;
    let mut out = std::path::PathBuf::from("conformance-server");
    let mut garden = false;
    let mut v: Vec<String> = std::env::args().skip(1).collect();
    if let Some(p) = v.iter().position(|a| a == "--garden") {
        v.remove(p);
        garden = true;
    }
    let mut i = 0;
    while i + 1 < v.len() {
        let val = v[i + 1].clone();
        match v[i].as_str() {
            "--addr" => addr = val,
            "--tls-addr" => tls_addr = Some(val),
            "--out" => out = val.into(),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let n = Arc::new(AtomicU64::new(0));
    let svc = move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if garden {
            return reply.header("content-type", "application/json").body(garden_json(req));
        }
        let k = n.fetch_add(1, Ordering::Relaxed) + 1;
        let line = format!(
            "REQ {k} {} {} len={} sha={:016x}\n",
            String::from_utf8_lossy(req.method()),
            req.path_str(),
            req.body().len(),
            fnv(req.body())
        );
        {
            let mut o = std::io::stdout().lock();
            let _ = o.write_all(line.as_bytes());
            let _ = o.flush();
        }
        if let Some(sz) = req.path_str().strip_prefix("/big/").and_then(|s| s.parse::<usize>().ok()) {
            return reply.header("content-type", "application/octet-stream").body(vec![b'x'; sz.min(64 << 20)]);
        }
        reply.header("content-type", "text/plain").body(line)
    };
    #[cfg_attr(not(feature = "tls"), allow(unused_mut))]
    let mut b = Server::builder().listen(addr.as_str()).threads(2);
    #[cfg(feature = "tls")]
    if let Some(t) = &tls_addr {
        use simoom::tls::certgen::{self, CertParams};
        use simoom::tls::{CertifiedKey, ServerConfig};
        use simoom_tls::keys::{EcCurve, PrivateKey};
        std::fs::create_dir_all(&out).expect("create --out");
        let ca = certgen::issue(&CertParams::ca("simoom conformance CA"), PrivateKey::generate_ec(EcCurve::P256), None);
        let leaf = certgen::issue(&CertParams::server(&["localhost", "127.0.0.1"]), PrivateKey::generate_ec(EcCurve::P256), Some(&ca));
        std::fs::write(out.join("ca.pem"), &ca.cert_pem).expect("write ca.pem");
        b = b.listen_tls(t.as_str()).tls(ServerConfig::new(CertifiedKey::new(vec![leaf.cert_der.clone(), ca.cert_der.clone()], leaf.key.clone()).expect("key")));
    }
    #[cfg(not(feature = "tls"))]
    if tls_addr.is_some() {
        panic!("--tls-addr needs the `tls` feature");
    }
    let _ = &out;
    let server = b.service(svc).start().expect("start");
    eprintln!("listening on {:?}", server.local_addrs());
    loop {
        std::thread::park();
    }
}
