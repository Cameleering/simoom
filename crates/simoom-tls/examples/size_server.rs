//! A minimal TLS 1.3 server for size measurements (plan §0): loads a certificate and key from
//! PEM files, reads one client flight from stdin and writes the server flight to stdout. Built
//! with the `dist` profile and compared with `size_empty`, it shows what the server side of
//! simoom-tls adds to a binary for a given feature set:
//!
//! `cargo build -p simoom-tls --profile dist --no-default-features --features rsa,p384,ed25519,chacha20 --example size_server --example size_empty`

use simoom_tls::{ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: size_server CERT.pem KEY.pem < client_flight");
        std::process::exit(2);
    }
    let cert = std::fs::read(&args[1]).expect("certificate");
    let key = std::fs::read(&args[2]).expect("key");
    let cfg = Arc::new(ServerConfig::from_pem(&cert, &key).expect("server config").with_alpn(&[b"h2", b"http/1.1"]));
    let mut conn = ServerConnection::new(cfg);
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("stdin");
    conn.read_tls(&input);
    if let Err(e) = conn.process_new_packets() {
        eprintln!("{e:?}");
    }
    let out = conn.tls_output().to_vec();
    conn.consume_tls_output(out.len());
    std::io::stdout().write_all(&out).expect("stdout");
    let mut buf = [0u8; 1024];
    let n = conn.read_plaintext(&mut buf);
    std::io::stdout().write_all(&buf[..n]).expect("stdout");
}
