//! A TLS listener for interop probing with external tools (`openssl s_client`, `gnutls-cli`,
//! Python `ssl`, curl). It issues a private CA, a server certificate for `localhost` signed by
//! it, and a client CA with one good client certificate, and writes them as PEM files to
//! `--out` so the tools can verify the server and present a client certificate.
//!
//! ```text
//! cargo run -p simoom --features full --example tls_probe_server -- \
//!     [--addr 127.0.0.1:8443] [--out DIR] [--cert PEM --key PEM] [--client-auth none|optional|required]
//! ```
//!
//! Files written to `--out` (default `tls-probe`): `ca.pem` (trust anchor for the server
//! certificate), `server.pem`, `client-ca.pem`, `client.pem` + `client.key` (accepted),
//! `rogue.pem` + `rogue.key` (a client certificate from an unknown CA). The service answers
//! every request with `ok <version> <path>`. Prints `listening on ADDR` when ready.

#![forbid(unsafe_code)]

#[cfg(feature = "tls")]
fn main() {
    use simoom::tls::certgen::{self, CertParams};
    use simoom::tls::{CertifiedKey, ServerConfig};
    use simoom::{Outcome, Reply, Request, Server};
    use simoom_tls::keys::{EcCurve, PrivateKey};
    use simoom_tls::x509::RootStore;
    use simoom_tls::ClientAuth;

    let mut addr = "127.0.0.1:8443".to_string();
    let mut out = std::path::PathBuf::from("tls-probe");
    let mut cert_pem: Option<String> = None;
    let mut key_pem: Option<String> = None;
    let mut client_auth = "none".to_string();
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i + 1 < v.len() {
        let val = v[i + 1].clone();
        match v[i].as_str() {
            "--addr" => addr = val,
            "--out" => out = val.into(),
            "--cert" => cert_pem = Some(val),
            "--key" => key_pem = Some(val),
            "--client-auth" => client_auth = val,
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    std::fs::create_dir_all(&out).expect("create --out");
    let ca = certgen::issue(&CertParams::ca("simoom probe CA"), PrivateKey::generate_ec(EcCurve::P256), None);
    let leaf = certgen::issue(&CertParams::server(&["localhost", "127.0.0.1"]), PrivateKey::generate_ec(EcCurve::P256), Some(&ca));
    let client_ca = certgen::issue(&CertParams::ca("simoom probe client CA"), PrivateKey::generate_ec(EcCurve::P256), None);
    let client = certgen::issue(&CertParams::client("probe client"), PrivateKey::generate_ec(EcCurve::P256), Some(&client_ca));
    let rogue_ca = certgen::issue(&CertParams::ca("rogue CA"), PrivateKey::generate_ec(EcCurve::P256), None);
    let rogue = certgen::issue(&CertParams::client("rogue client"), PrivateKey::generate_ec(EcCurve::P256), Some(&rogue_ca));
    let w = |name: &str, s: &str| std::fs::write(out.join(name), s).expect("write PEM");
    w("ca.pem", &ca.cert_pem);
    w("server.pem", &leaf.cert_pem);
    w("client-ca.pem", &client_ca.cert_pem);
    w("client.pem", &client.cert_pem);
    w("client.key", &client.key_pem);
    w("rogue.pem", &rogue.cert_pem);
    w("rogue.key", &rogue.key_pem);

    let mut cfg = match (cert_pem, key_pem) {
        (Some(c), Some(k)) => ServerConfig::from_pem(&std::fs::read(c).expect("--cert"), &std::fs::read(k).expect("--key")).expect("PEM server key"),
        _ => ServerConfig::new(CertifiedKey::new(vec![leaf.cert_der.clone(), ca.cert_der.clone()], leaf.key.clone()).expect("key")),
    };
    let mut roots = RootStore::empty();
    roots.add_der(&client_ca.cert_der).expect("client CA");
    cfg.client_auth = match client_auth.as_str() {
        "optional" => ClientAuth::Optional(roots),
        "required" => ClientAuth::Required(roots),
        _ => ClientAuth::None,
    };
    let server = Server::builder()
        .listen_tls(addr.as_str())
        .tls(cfg)
        .threads(2)
        .service(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.body(format!("ok {:?} {}\n", req.version(), req.path_str())) })
        .start()
        .expect("start");
    println!("listening on {}", server.local_addr());
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let s = server.stats();
        eprintln!("tls_errors={} requests={}", s.tls_errors, s.requests);
    }
}

#[cfg(not(feature = "tls"))]
fn main() {
    eprintln!("tls_probe_server needs the `tls` feature");
}
