//! End-to-end TLS 1.3 handshakes between simoom's client and server, in memory.

#![cfg(feature = "client")]

mod common;

use common::*;
use simoom_tls::tls::alert;
use simoom_tls::x509::RootStore;
use simoom_tls::{CipherSuite, ClientAuth, ClientConnection, Error, NamedGroup, ServerConnection};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn connect(scfg: Arc<simoom_tls::ServerConfig>, ccfg: Arc<simoom_tls::ClientConfig>, name: &str) -> (ClientConnection, ServerConnection, Result<(), (char, Error)>) {
    let mut c = ClientConnection::new(ccfg, name).unwrap();
    let mut s = ServerConnection::new(scfg);
    let r = pump(&mut c, &mut s);
    if r.is_err() {
        // deliver the alert the failing side queued
        let _ = pump(&mut c, &mut s);
    }
    (c, s, r)
}

#[test]
fn every_suite_group_and_key_type() {
    for kind in [KeyKind::P256, KeyKind::P384, KeyKind::Ed25519, KeyKind::Rsa] {
        let kname = match kind {
            KeyKind::P256 => "p256",
            KeyKind::P384 => "p384",
            KeyKind::Ed25519 => "ed25519",
            KeyKind::Rsa => "rsa",
        };
        let ss = server_cert(kind);
        for suite in CipherSuite::ALL {
            for group in NamedGroup::ALL {
                let mut scfg = simoom_tls::ServerConfig::new(certified(&ss));
                scfg.suites = vec![suite];
                let mut ccfg = simoom_tls::ClientConfig::new(roots_of(&ss));
                ccfg.groups = vec![group];
                ccfg.sessions = None;
                let (mut c, mut s, r) = connect(arc(scfg), arc(ccfg), "localhost");
                r.unwrap_or_else(|e| panic!("{kname} {suite:?} {group:?}: {e:?}"));
                assert!(!c.is_handshaking() && !s.is_handshaking());
                assert_eq!(c.negotiated_cipher_suite(), Some(suite));
                assert_eq!(s.negotiated_group(), Some(group));
                assert_eq!(c.peer_certificates()[0], ss.cert_der);
                assert_eq!(s.server_name(), Some("localhost"));
                assert_eq!(transfer(&mut c, &mut s, b"ping"), b"ping");
                assert_eq!(transfer(&mut s, &mut c, b"pong"), b"pong");
                let ekm_c = c.export_keying_material(b"EXPERIMENTAL test", b"ctx", 32).unwrap();
                assert_eq!(ekm_c, s.export_keying_material(b"EXPERIMENTAL test", b"ctx", 32).unwrap());
            }
        }
    }
}

#[test]
fn alpn_negotiation_and_mismatch() {
    let (scfg, ccfg) = pair(KeyKind::P256);
    let scfg = arc(scfg.with_alpn(&[b"h2", b"http/1.1"]));
    let (c, s, r) = connect(scfg.clone(), arc(ccfg.with_alpn(&[b"http/1.1", b"h2"])), "localhost");
    r.unwrap();
    assert_eq!(c.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(s.alpn_protocol(), Some(&b"h2"[..]));
    let (_, ccfg) = pair(KeyKind::P256);
    let (c, _s, r) = connect(scfg.clone(), arc(ccfg.with_alpn(&[b"spdy/3"])), "localhost");
    let (side, e) = r.unwrap_err();
    assert_eq!((side, e.alert()), ('s', Some(alert::NO_APPLICATION_PROTOCOL)));
    assert_eq!(c.error(), Some(&Error::PeerAlert(alert::NO_APPLICATION_PROTOCOL)));
    // no ALPN from the client: allowed over TCP
    let (_, ccfg) = pair(KeyKind::P256);
    let (c, _, r) = connect(scfg, arc(ccfg), "localhost");
    r.unwrap();
    assert_eq!(c.alpn_protocol(), None);
}

#[test]
fn hello_retry_request() {
    let (mut scfg, mut ccfg) = pair(KeyKind::P256);
    scfg.groups = vec![NamedGroup::Secp256r1];
    ccfg.groups = vec![NamedGroup::X25519, NamedGroup::Secp256r1];
    let (mut c, mut s, r) = connect(arc(scfg), arc(ccfg), "localhost");
    r.unwrap();
    assert_eq!(c.negotiated_group(), Some(NamedGroup::Secp256r1));
    assert_eq!(transfer(&mut c, &mut s, b"after hrr"), b"after hrr");
    // no common group at all
    let (mut scfg, mut ccfg) = pair(KeyKind::P256);
    scfg.groups = vec![NamedGroup::Secp256r1];
    ccfg.groups = vec![NamedGroup::X25519];
    let (_, _, r) = connect(arc(scfg), arc(ccfg), "localhost");
    assert_eq!(r.unwrap_err().1.alert(), Some(alert::HANDSHAKE_FAILURE));
}

#[test]
fn resumption_with_tickets() {
    let (scfg, ccfg) = pair(KeyKind::P256);
    let scfg = arc(scfg.with_alpn(&[b"h2"]));
    let ccfg = arc(ccfg.with_alpn(&[b"h2"]));
    let (mut c, mut s, r) = connect(scfg.clone(), ccfg.clone(), "localhost");
    r.unwrap();
    assert!(!c.is_resumed());
    // tickets arrive with the server's first flight after the client Finished
    assert_eq!(transfer(&mut s, &mut c, b"x"), b"x");
    assert_eq!(ccfg.sessions.as_ref().unwrap().len_for("localhost"), 1);
    let (mut c2, mut s2, r) = connect(scfg.clone(), ccfg.clone(), "localhost");
    r.unwrap();
    assert!(c2.is_resumed() && s2.is_resumed());
    assert_eq!(c2.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(c2.peer_certificates().len(), 0, "no Certificate message on resumption");
    assert_eq!(transfer(&mut c2, &mut s2, b"resumed"), b"resumed");
    // the ticket was used once; the resumed connection issued a new one
    assert_eq!(transfer(&mut s2, &mut c2, b"y"), b"y");
    assert_eq!(ccfg.sessions.as_ref().unwrap().len_for("localhost"), 1);
    // a ticket from another server (different ticket keys) falls back to a full handshake
    let (scfg_other, _) = pair(KeyKind::P256);
    let (c3, _, r) = connect(arc(scfg_other.with_alpn(&[b"h2"])), ccfg.clone(), "localhost");
    r.unwrap();
    assert!(!c3.is_resumed());
}

#[test]
fn ticket_key_rotation_and_expiry() {
    let clock = Arc::new(TestClock(AtomicU64::new(now_ms())));
    let (mut scfg, mut ccfg) = pair(KeyKind::P256);
    scfg.time = clock.clone();
    scfg.ticketer = Some(Arc::new(simoom_tls::Ticketer::new(3600)));
    scfg.ticket_lifetime_secs = 7200;
    ccfg.time = clock.clone();
    let (scfg, ccfg) = (arc(scfg), arc(ccfg));
    let get_ticket = |scfg: &Arc<simoom_tls::ServerConfig>| {
        let (mut c, mut s, r) = connect(scfg.clone(), ccfg.clone(), "localhost");
        r.unwrap();
        transfer(&mut s, &mut c, b"t");
        c.is_resumed()
    };
    assert!(!get_ticket(&scfg));
    // one rotation later the previous key still decrypts
    clock.0.fetch_add(3_600_500, std::sync::atomic::Ordering::Relaxed);
    assert!(get_ticket(&scfg));
    // past the ticket lifetime: full handshake
    clock.0.fetch_add(7_300_000, std::sync::atomic::Ordering::Relaxed);
    assert!(!get_ticket(&scfg));
}

#[test]
fn mutual_tls() {
    let (ca, client) = ca_and_client_cert();
    let mut client_roots = RootStore::empty();
    client_roots.add_der(&ca.cert_der).unwrap();
    let ss = server_cert(KeyKind::P256);
    let mk_server = |auth: ClientAuth| {
        let mut s = simoom_tls::ServerConfig::new(certified(&ss));
        s.client_auth = auth;
        arc(s)
    };
    let mk_client = |with_cert: bool| {
        let mut c = simoom_tls::ClientConfig::new(roots_of(&ss));
        if with_cert {
            c.client_cert = Some(simoom_tls::CertifiedKey::new(vec![client.cert_der.clone(), ca.cert_der.clone()], client.key.clone()).unwrap());
        }
        arc(c)
    };
    // required, with a certificate
    let required = mk_server(ClientAuth::Required(client_roots.clone()));
    let ccfg = mk_client(true);
    let (mut c, mut s, r) = connect(required.clone(), ccfg.clone(), "localhost");
    r.unwrap();
    assert_eq!(s.peer_certificates()[0], client.cert_der);
    assert_eq!(transfer(&mut c, &mut s, b"authenticated"), b"authenticated");
    transfer(&mut s, &mut c, b"t");
    // resumption keeps the client identity
    let (_, s2, r) = connect(required.clone(), ccfg, "localhost");
    r.unwrap();
    assert!(s2.is_resumed());
    assert_eq!(s2.peer_certificates()[0], client.cert_der);
    // required, without a certificate
    let (_, _, r) = connect(required.clone(), mk_client(false), "localhost");
    let (side, e) = r.unwrap_err();
    assert_eq!((side, e.alert()), ('s', Some(alert::CERTIFICATE_REQUIRED)));
    // optional, without a certificate
    let (_, s, r) = connect(mk_server(ClientAuth::Optional(client_roots)), mk_client(false), "localhost");
    r.unwrap();
    assert!(s.peer_certificates().is_empty());
    // required, with a certificate from an unknown CA
    let (_, _, r) = connect(mk_server(ClientAuth::Required(roots_of(&ss))), mk_client(true), "localhost");
    assert_eq!(r.unwrap_err().1.alert(), Some(alert::UNKNOWN_CA));
}

#[test]
fn certificate_validation_failures() {
    let ss = server_cert(KeyKind::P256);
    let scfg = arc(simoom_tls::ServerConfig::new(certified(&ss)));
    // untrusted
    let (_, s, r) = connect(scfg.clone(), arc(simoom_tls::ClientConfig::new(RootStore::empty())), "localhost");
    assert_eq!(r.unwrap_err().1.alert(), Some(alert::UNKNOWN_CA));
    assert_eq!(s.error(), Some(&Error::PeerAlert(alert::UNKNOWN_CA)));
    // wrong name
    let (_, _, r) = connect(scfg.clone(), arc(simoom_tls::ClientConfig::new(roots_of(&ss))), "example.com");
    assert!(matches!(r.unwrap_err(), ('c', Error::Certificate(simoom_tls::x509::CertError::HostnameMismatch { .. }))));
    // IP address SAN
    let (_, _, r) = connect(scfg.clone(), arc(simoom_tls::ClientConfig::new(roots_of(&ss))), "127.0.0.1");
    r.unwrap();
    // expired: the client's clock is two years ahead
    let mut ccfg = simoom_tls::ClientConfig::new(roots_of(&ss));
    ccfg.time = Arc::new(TestClock(AtomicU64::new(now_ms() + 2 * 365 * 86_400_000)));
    let (_, _, r) = connect(scfg, arc(ccfg), "localhost");
    assert_eq!(r.unwrap_err().1.alert(), Some(alert::CERTIFICATE_EXPIRED));
}

#[test]
fn chain_with_intermediate_from_openssl_fixtures() {
    // leaf (P-256) <- intermediate (RSA, RSA-PSS signature) <- root (P-384, ECDSA-SHA384)
    let leaf = include_bytes!("../testdata/leaf.pem");
    let int = include_bytes!("../testdata/int.pem");
    let mut chain_pem = leaf.to_vec();
    chain_pem.extend_from_slice(int);
    let ck = simoom_tls::CertifiedKey::from_pem(&chain_pem, include_bytes!("../testdata/leaf.key")).unwrap();
    let scfg = arc(simoom_tls::ServerConfig::new(ck));
    let mut roots = RootStore::empty();
    roots.add_pem(include_bytes!("../testdata/ca.pem")).unwrap();
    let (c, _, r) = connect(scfg, arc(simoom_tls::ClientConfig::new(roots)), "leaf.camel.test");
    r.unwrap();
    assert_eq!(c.peer_certificates().len(), 2);
}

#[test]
fn sni_selects_certificates() {
    let a = simoom_tls::certgen::issue(&simoom_tls::certgen::CertParams::server(&["a.test"]), simoom_tls::keys::PrivateKey::generate_ed25519(), None);
    let b = simoom_tls::certgen::issue(&simoom_tls::certgen::CertParams::server(&["*.b.test"]), simoom_tls::keys::PrivateKey::generate_ed25519(), None);
    let mut scfg = simoom_tls::ServerConfig::new(certified(&a));
    scfg.add_sni_cert(certified(&b));
    let scfg = arc(scfg);
    let mut roots = roots_of(&a);
    roots.add_der(&b.cert_der).unwrap();
    let ccfg = arc(simoom_tls::ClientConfig::new(roots));
    let (c, s, r) = connect(scfg.clone(), ccfg.clone(), "x.b.test");
    r.unwrap();
    assert_eq!(c.peer_certificates()[0], b.cert_der);
    assert_eq!(s.server_name(), Some("x.b.test"));
    let (c, _, r) = connect(scfg.clone(), ccfg.clone(), "a.test");
    r.unwrap();
    assert_eq!(c.peer_certificates()[0], a.cert_der);
}

#[test]
fn key_update_both_directions() {
    let (scfg, ccfg) = pair(KeyKind::Ed25519);
    let (mut c, mut s, r) = connect(arc(scfg), arc(ccfg), "localhost");
    r.unwrap();
    for i in 0..3 {
        c.send_key_update(true).unwrap();
        assert_eq!(transfer(&mut c, &mut s, format!("after update {i}").as_bytes()), format!("after update {i}").as_bytes());
        // the server answered the request with its own KeyUpdate
        assert_eq!(transfer(&mut s, &mut c, b"reply"), b"reply");
    }
    s.send_key_update(false).unwrap();
    assert_eq!(transfer(&mut s, &mut c, b"one-sided"), b"one-sided");
    assert_eq!(transfer(&mut c, &mut s, b"other way"), b"other way");
}

#[test]
fn bulk_data_fragmentation_and_bytewise_delivery() {
    let (scfg, ccfg) = pair(KeyKind::P256);
    let (scfg, ccfg) = (arc(scfg), arc(ccfg));
    let mut c = ClientConnection::new(ccfg, "localhost").unwrap();
    let mut s = ServerConnection::new(scfg);
    // data written before the handshake completes is sent right after it
    c.write_plaintext(b"early write").unwrap();
    pump_bytewise(&mut c, &mut s).unwrap();
    let mut buf = [0u8; 64];
    let n = s.read_plaintext(&mut buf);
    assert_eq!(&buf[..n], b"early write");
    let big: Vec<u8> = (0..1_000_003u32).map(|i| (i * 31) as u8).collect();
    assert_eq!(transfer(&mut c, &mut s, &big), big);
    assert_eq!(transfer(&mut s, &mut c, &big), big);
    assert_eq!(transfer(&mut c, &mut s, b""), b"");
    // idle connections can drop their buffers and keep working
    assert_eq!(c.release_buffers(), 0);
    assert_eq!(s.release_buffers(), 0);
    assert_eq!(transfer(&mut c, &mut s, b"after release"), b"after release");
}

#[test]
fn close_notify_and_tampering() {
    let (scfg, ccfg) = pair(KeyKind::P256);
    let (mut c, mut s, r) = connect(arc(scfg), arc(ccfg), "localhost");
    r.unwrap();
    c.write_plaintext(b"last words").unwrap();
    c.send_close_notify();
    assert_eq!(c.write_plaintext(b"more"), Err(Error::Closed));
    pump(&mut c, &mut s).unwrap();
    assert!(s.peer_has_closed());
    let mut buf = [0u8; 32];
    let n = s.read_plaintext(&mut buf);
    assert_eq!(&buf[..n], b"last words");
    // tampered record
    let (scfg, ccfg) = pair(KeyKind::P256);
    let (mut c, mut s, r) = connect(arc(scfg), arc(ccfg), "localhost");
    r.unwrap();
    c.write_plaintext(b"secret").unwrap();
    let mut rec = c.tls_output().to_vec();
    let n = rec.len();
    rec[n - 3] ^= 0x40;
    s.read_tls(&rec);
    assert_eq!(s.process_new_packets().unwrap_err().alert(), Some(alert::BAD_RECORD_MAC));
    // the alert goes out encrypted and the client reports it
    let n = c.read_tls(s.tls_output());
    s.consume_tls_output(n);
    assert_eq!(c.process_new_packets().unwrap_err(), Error::PeerAlert(alert::BAD_RECORD_MAC));
    // garbage instead of TLS
    let (scfg, _) = pair(KeyKind::P256);
    let mut s = ServerConnection::new(arc(scfg));
    s.read_tls(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(s.process_new_packets().unwrap_err().alert(), Some(alert::UNEXPECTED_MESSAGE));
}

#[test]
fn export_traffic_secrets_for_ktls() {
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    ccfg.suites = vec![CipherSuite::Aes256GcmSha384];
    let (mut c, mut s, r) = connect(arc(scfg), arc(ccfg), "localhost");
    r.unwrap();
    transfer(&mut s, &mut c, b"ticket flush");
    transfer(&mut c, &mut s, b"data");
    let ce = ClientConnectionExt::take(c);
    let se = ServerConnectionExt::take(s);
    assert_eq!(ce.suite, CipherSuite::Aes256GcmSha384);
    assert_eq!(ce.tx.key, se.rx.key);
    assert_eq!(ce.tx.iv, se.rx.iv);
    assert_eq!(ce.tx.seq, se.rx.seq);
    assert_eq!(ce.rx.secret, se.tx.secret);
    assert_eq!(ce.tx.seq, 1, "one application record after the handshake");
}

struct ClientConnectionExt;
impl ClientConnectionExt {
    fn take(c: ClientConnection) -> simoom_tls::ExportedSecrets {
        let conn: simoom_tls::Connection = unwrap_client(c);
        conn.export_traffic_secrets().unwrap()
    }
}
struct ServerConnectionExt;
impl ServerConnectionExt {
    fn take(s: ServerConnection) -> simoom_tls::ExportedSecrets {
        let conn: simoom_tls::Connection = unwrap_server(s);
        conn.export_traffic_secrets().unwrap()
    }
}

fn unwrap_client(c: ClientConnection) -> simoom_tls::Connection {
    c.into_inner()
}
fn unwrap_server(s: ServerConnection) -> simoom_tls::Connection {
    s.into_inner()
}

