//! A server for live conformance and desync testing with external tools (`nghttp`, `h2load`,
//! curl, nginx and haproxy in front of it, and the `h2_live` conformance runner).
//!
//! ```text
//! cargo run --release -p simoom --features full --example conformance_server -- \
//!     [--addr 127.0.0.1:8080] [--tls-addr 127.0.0.1:8443] [--out DIR]
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

#![forbid(unsafe_code)]

use simoom::{Outcome, Reply, Request, Server};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &x| (h ^ u64::from(x)).wrapping_mul(0x100_0000_01b3))
}

fn main() {
    let mut addr = "127.0.0.1:8080".to_string();
    let mut tls_addr: Option<String> = None;
    let mut out = std::path::PathBuf::from("conformance-server");
    let v: Vec<String> = std::env::args().skip(1).collect();
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
