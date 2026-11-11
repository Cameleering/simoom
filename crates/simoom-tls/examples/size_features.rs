//! What each optional simoom-tls feature adds to a binary that uses it (report rows of
//! `scripts/size.sh`). A TLS server that, depending on the features compiled in, loads its key
//! material through `SslContextParameters` (`keystore`, `pkcs12`, `jks`), staples an OCSP
//! response and checks client certificates against CRLs (`revocation`), negotiates TLS 1.2
//! (`tls12`), and serves one connection through the blocking adapter (`blocking`). Without
//! those features it is the plain `size_server` path. Built with the `dist` profile:
//!
//! `cargo build -p simoom-tls --profile dist --no-default-features --features rsa,tls12,pkcs12 --example size_features`

use simoom_tls::{ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::sync::Arc;

#[allow(unused_variables, unused_mut)]
fn config(args: &[String]) -> ServerConfig {
    let cert = std::fs::read(&args[1]).expect("certificate");
    let key = std::fs::read(&args[2]).expect("key");
    #[cfg(feature = "keystore")]
    let mut cfg = {
        let p = simoom_tls::params::SslContextParameters::new()
            .key_pair_pem(&String::from_utf8_lossy(&cert), &String::from_utf8_lossy(&key))
            .key_password(args.get(3).map(|s| s.as_str()).unwrap_or(""));
        let p = match args.get(4) {
            // a key store file instead (PKCS#12 / JKS / JCEKS, detected)
            Some(ks) => simoom_tls::params::SslContextParameters::new().key_store(ks, args.get(3).map(|s| s.as_str()).unwrap_or("")),
            None => p,
        };
        p.server_config().expect("server config")
    };
    #[cfg(not(feature = "keystore"))]
    let mut cfg = ServerConfig::from_pem(&cert, &key).expect("server config");
    #[cfg(feature = "revocation")]
    {
        let staple = simoom_tls::revocation::StapleSource::new();
        if let Some(der) = args.get(5).and_then(|p| std::fs::read(p).ok()) {
            staple.set(Some(der));
        }
        cfg.ocsp_staple = Some(staple);
        if let Some(crl) = args.get(6).and_then(|p| std::fs::read(p).ok()) {
            let mut pol = simoom_tls::revocation::RevocationPolicy::new();
            pol.add_crls(&crl).expect("CRL");
            cfg.client_revocation = Some(pol);
        }
    }
    cfg.with_alpn(&[b"h2", b"http/1.1"])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: size_features CERT.pem KEY.pem [PASSWORD [KEYSTORE [OCSP.der [CRL]]]] < client_flight");
        std::process::exit(2);
    }
    let cfg = Arc::new(config(&args));
    #[cfg(feature = "blocking")]
    if std::env::var("SIZE_FEATURES_LISTEN").is_ok() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let (tcp, _) = l.accept().expect("accept");
        let mut s = simoom_tls::blocking::accept(tcp, cfg).expect("handshake");
        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf).expect("read");
        s.write_all(&buf[..n]).expect("write");
        return;
    }
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
