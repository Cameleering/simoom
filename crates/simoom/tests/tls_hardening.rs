//! Hostile TLS clients against a live simoom TLS listener, over loopback with raw bytes: the
//! server must answer each with the right fatal alert, flush it before closing, keep serving
//! other clients, and count the failures.

#![cfg(feature = "tls-client")]

use simoom::tls::certgen::{self, CertParams};
use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Outcome, Reply, Request, Server, ServerHandle};
use simoom_tls::keys::{EcCurve, PrivateKey};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn start() -> ServerHandle {
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let cfg = ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap());
    Server::builder()
        .listen_tls("127.0.0.1:0")
        .tls(cfg)
        .threads(1)
        .service(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.body_static(b"ok") })
        .start()
        .expect("start")
}

fn record(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut r = vec![typ, 3, 1, (body.len() >> 8) as u8, body.len() as u8];
    r.extend_from_slice(body);
    r
}

fn ext(t: u16, data: &[u8]) -> Vec<u8> {
    let mut e = t.to_be_bytes().to_vec();
    e.extend_from_slice(&(data.len() as u16).to_be_bytes());
    e.extend_from_slice(data);
    e
}

/// A ClientHello offering only `versions` in supported_versions (none if empty).
fn client_hello(legacy: u16, versions: &[u16]) -> Vec<u8> {
    let mut b = legacy.to_be_bytes().to_vec();
    b.extend_from_slice(&[7; 32]);
    b.push(0);
    b.extend_from_slice(&[0, 4, 0xc0, 0x2f, 0x00, 0x2f, 1, 0]);
    let mut exts = Vec::new();
    if !versions.is_empty() {
        let mut v = vec![(versions.len() * 2) as u8];
        for x in versions {
            v.extend_from_slice(&x.to_be_bytes());
        }
        exts.extend(ext(43, &v));
    }
    exts.extend(ext(10, &[0, 2, 0, 0x17]));
    exts.extend(ext(13, &[0, 2, 4, 3]));
    b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    b.extend(exts);
    let mut m = vec![1, 0, (b.len() >> 8) as u8, b.len() as u8];
    m.extend(b);
    record(22, &m)
}

/// Sends `bytes` and reads until the server closes; returns what it sent.
fn exchange(h: &ServerHandle, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(h.local_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(bytes).unwrap();
    let mut got = Vec::new();
    let mut tmp = [0u8; 4096];
    let t = Instant::now();
    loop {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&tmp[..n]),
            // a reset after the alert still counts as closed
            Err(e) if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("server did not close: {e} after {:?}", t.elapsed()),
        }
    }
    got
}

fn fatal_alert(got: &[u8]) -> Option<u8> {
    (got.len() >= 7 && got[0] == 21 && got[5] == 2).then(|| got[6])
}

#[test]
fn legacy_hellos_get_protocol_version_and_the_server_keeps_serving() {
    let h = start();
    for (legacy, versions) in [(0x0303u16, &[0x0303u16][..]), (0x0303, &[]), (0x0302, &[]), (0x0301, &[])] {
        let got = exchange(&h, &client_hello(legacy, versions));
        assert_eq!(fatal_alert(&got), Some(70), "legacy {legacy:#x} versions {versions:x?}: {got:x?}");
    }
    // SSLv2-compatible hello: refused with an alert, not a hang
    let mut v2 = vec![0x80, 0x2e, 1, 3, 1, 0, 9, 0, 0, 0, 16];
    v2.extend_from_slice(&[0x00, 0x00, 0x2f, 0x00, 0x00, 0x35, 0x01, 0x00, 0x80]);
    v2.extend_from_slice(&[0x5a; 16]);
    assert_eq!(fatal_alert(&exchange(&h, &v2)), Some(10));
    // a plaintext HTTP request on the TLS port
    assert_eq!(fatal_alert(&exchange(&h, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")), Some(10));
    // an oversized record header
    assert_eq!(fatal_alert(&exchange(&h, &[22, 3, 1, 0x48, 0x01])), Some(22));
    // a 16 MiB handshake message
    assert_eq!(fatal_alert(&exchange(&h, &record(22, &[1, 0xff, 0xff, 0xff]))), Some(50));
    assert!(h.stats().tls_errors >= 8, "tls_errors = {}", h.stats().tls_errors);
    // still serving real clients
    let mut c = simoom_tls::ClientConnection::new(
        std::sync::Arc::new(simoom_tls::ClientConfig::new(simoom_tls::x509::RootStore::empty())),
        "localhost",
    )
    .unwrap();
    let mut s = TcpStream::connect(h.local_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut out = Vec::new();
    c.write_tls_into(&mut out);
    s.write_all(&out).unwrap();
    let mut tmp = [0u8; 8192];
    let n = s.read(&mut tmp).unwrap();
    assert!(n > 0 && tmp[0] == 22, "ServerHello for a TLS 1.3 client");
    h.stop(Duration::from_millis(100));
    h.join();
}

#[test]
fn slow_fragmented_garbage_is_bounded_by_the_head_deadline() {
    // a client that opens TLS and then sends one byte of a record header and stalls must be
    // dropped by the handshake/head deadline, not held forever
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let cfg = ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap());
    let h = Server::builder()
        .listen_tls("127.0.0.1:0")
        .tls(cfg)
        .threads(1)
        .limits(simoom::Limits { head_timeout: Duration::from_millis(300), ..simoom::Limits::default() })
        .service(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.body_static(b"ok") })
        .start()
        .unwrap();
    let mut s = TcpStream::connect(h.local_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(&[22]).unwrap();
    let t = Instant::now();
    let mut tmp = [0u8; 64];
    let _ = s.read(&mut tmp);
    assert!(t.elapsed() < Duration::from_secs(5), "held for {:?}", t.elapsed());
    h.stop(Duration::from_millis(100));
    h.join();
}
