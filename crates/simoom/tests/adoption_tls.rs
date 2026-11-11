//! The Cameleer adoption items on TLS listeners (docs/BUGS.md U1, U6): the TLS session on the
//! request (version, cipher suite, SNI, ALPN, the verified client certificate chain) and
//! certificate reload without a restart.

#![cfg(feature = "tls-client")]

use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Outcome, Reply, Request, Server, ServerHandle};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::{ClientAuth, ClientConfig, ClientConnection};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

fn issue(name: &str) -> certgen::SelfSigned {
    certgen::issue(&CertParams::server(&[name]), PrivateKey::generate_ec(EcCurve::P256), None)
}

fn server_config(ss: &certgen::SelfSigned) -> ServerConfig {
    ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap())
}

/// Connects, sends one request with `Connection: close`, returns (server leaf DER, response).
fn fetch(addr: std::net::SocketAddr, cfg: Arc<ClientConfig>, alpn_h1: bool) -> (Vec<u8>, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut c = ClientConnection::new(cfg, "localhost").unwrap();
    let mut out = Vec::new();
    let mut tmp = [0u8; 16384];
    let mut pump = |c: &mut ClientConnection, s: &mut TcpStream| -> bool {
        if c.wants_write() {
            out.clear();
            c.write_tls_into(&mut out);
            s.write_all(&out).unwrap();
        }
        let n = s.read(&mut tmp).unwrap_or(0);
        let mut off = 0;
        while off < n {
            off += c.read_tls(&tmp[off..n]);
            c.process_new_packets().expect("tls");
        }
        n > 0
    };
    while c.is_handshaking() {
        assert!(pump(&mut c, &mut s), "handshake");
    }
    let _ = alpn_h1;
    c.write_plaintext(b"GET /info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    loop {
        let more = pump(&mut c, &mut s);
        let p = c.plaintext().to_vec();
        c.consume_plaintext(p.len());
        resp.extend_from_slice(&p);
        if !more || c.peer_has_closed() {
            break;
        }
    }
    (c.peer_certificates()[0].clone(), String::from_utf8_lossy(&resp).into_owned())
}

fn info(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let t = req.tls().expect("a TLS session");
    let owned = req.to_owned_request();
    assert_eq!(owned.tls().map(|t| t.cipher_suite()), Some(t.cipher_suite()));
    let body = format!(
        "{} {:04x} {} {} {} certs={} leaf={}",
        t.version_name(),
        t.version(),
        t.cipher_suite_name(),
        t.server_name().unwrap_or("-"),
        String::from_utf8_lossy(t.alpn().unwrap_or(b"-")),
        t.peer_certificates().len(),
        t.peer_certificates().first().map_or(0, |c| c.len()),
    );
    reply.body(body)
}

#[test]
fn the_tls_session_and_the_client_chain_reach_the_request() {
    let server = issue("localhost");
    let ca = certgen::issue(&CertParams { is_ca: true, ..CertParams::client("test ca") }, PrivateKey::generate_ec(EcCurve::P256), None);
    let client = certgen::issue(&CertParams::client("client one"), PrivateKey::generate_ec(EcCurve::P256), Some(&ca));
    let mut scfg = server_config(&server);
    let mut client_roots = RootStore::empty();
    client_roots.add_der(&ca.cert_der).unwrap();
    scfg.client_auth = ClientAuth::Optional(client_roots);
    let h: ServerHandle = Server::builder().listen_tls("127.0.0.1:0").tls(scfg).threads(1).service(info).start().unwrap();
    let mut roots = RootStore::empty();
    roots.add_der(&server.cert_der).unwrap();
    // with a client certificate
    let mut ccfg = ClientConfig::new(roots.clone()).with_alpn(&[b"http/1.1"]);
    ccfg.client_cert = Some(CertifiedKey::new(vec![client.cert_der.clone(), ca.cert_der.clone()], client.key.clone()).unwrap());
    let (_, r) = fetch(h.local_addr(), Arc::new(ccfg), true);
    let want = format!("TLSv1.3 0304 TLS_AES_128_GCM_SHA256 localhost http/1.1 certs=2 leaf={}", client.cert_der.len());
    assert!(r.ends_with(&want), "{r}");
    // without one
    let (_, r) = fetch(h.local_addr(), Arc::new(ClientConfig::new(roots)), false);
    assert!(r.ends_with("TLSv1.3 0304 TLS_AES_128_GCM_SHA256 localhost - certs=0 leaf=0"), "{r}");
}

#[test]
fn a_new_certificate_applies_to_new_connections() {
    let (one, two) = (issue("localhost"), issue("localhost"));
    let h = Server::builder().listen_tls("127.0.0.1:0").tls(server_config(&one)).threads(1).service(info).start().unwrap();
    let mut roots = RootStore::empty();
    roots.add_der(&one.cert_der).unwrap();
    roots.add_der(&two.cert_der).unwrap();
    let cfg = || {
        let mut c = ClientConfig::new(roots.clone());
        c.sessions = None; // a full handshake each time
        Arc::new(c)
    };
    let (leaf, r) = fetch(h.local_addr(), cfg(), false);
    assert_eq!(leaf, one.cert_der);
    assert!(r.contains("200 OK"), "{r}");
    h.set_tls(server_config(&two)).unwrap();
    let (leaf, r) = fetch(h.local_addr(), cfg(), false);
    assert_eq!(leaf, two.cert_der, "the reloaded certificate");
    assert!(r.contains("200 OK"), "{r}");
    // a server without TLS listeners refuses
    let plain = Server::builder().listen("127.0.0.1:0").threads(1).service(info).start().unwrap();
    assert!(plain.set_tls(server_config(&two)).is_err());
    #[cfg(feature = "http3")]
    assert!(plain.set_quic_tls(server_config(&two)).is_err());
}
