//! Hostile and malformed peers against the TLS 1.3 record layer and handshake: legacy-only
//! ClientHellos, an SSLv2-compatible hello, fragmented and oversized handshake messages, the
//! downgrade sentinels, and client certificates with a bad chain. Floods of empty records,
//! warning alerts and KeyUpdates, renegotiation and early data are unit tests in
//! `src/tls/conn.rs`, which can forge records under the real keys.

#![cfg(feature = "client")]

mod common;

use common::*;
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::tls::alert;
use simoom_tls::x509::RootStore;
use simoom_tls::{ClientAuth, ClientConnection, Error, ServerConnection};
use std::sync::Arc;

fn server() -> ServerConnection {
    let (s, _) = pair(KeyKind::P256);
    ServerConnection::new(Arc::new(s))
}

fn client() -> ClientConnection {
    let (_, c) = pair(KeyKind::P256);
    ClientConnection::new(Arc::new(c), "localhost").unwrap()
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

/// A ClientHello handshake message. `versions` fills supported_versions (none if empty).
fn client_hello(legacy: u16, versions: &[u16]) -> Vec<u8> {
    let mut b = legacy.to_be_bytes().to_vec();
    b.extend_from_slice(&[7; 32]); // random
    b.push(0); // session id
    b.extend_from_slice(&[0, 6, 0x13, 0x01, 0xc0, 0x2f, 0x00, 0x2f]); // suites
    b.extend_from_slice(&[1, 0]); // null compression
    let mut exts = Vec::new();
    if !versions.is_empty() {
        let mut v = vec![(versions.len() * 2) as u8];
        for x in versions {
            v.extend_from_slice(&x.to_be_bytes());
        }
        exts.extend(ext(43, &v));
    }
    exts.extend(ext(10, &[0, 2, 0, 0x1d])); // x25519
    exts.extend(ext(13, &[0, 4, 4, 3, 8, 4])); // ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256
    let mut share = vec![0, 0x1d, 0, 32];
    share.extend_from_slice(&simoom_tls::crypto::x25519::x25519_base(&[9; 32]));
    let mut ks = (share.len() as u16).to_be_bytes().to_vec();
    ks.extend(share);
    exts.extend(ext(51, &ks));
    b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    b.extend(exts);
    let mut m = vec![1, 0, (b.len() >> 8) as u8, b.len() as u8];
    m.extend(b);
    m
}

/// Feeds `data` and returns the error and the plaintext alert written, if any.
fn reject(s: &mut ServerConnection, data: &[u8]) -> (Error, Option<u8>) {
    s.read_tls(data);
    let e = s.process_new_packets().expect_err("must be refused");
    let out = s.tls_output();
    let alert = (out.len() == 7 && out[0] == 21).then(|| out[6]);
    if let Some(a) = alert {
        assert_eq!(out[5], 2, "fatal level");
        assert_eq!(Some(a), e.alert());
    }
    (e, alert)
}

#[test]
fn tls12_only_client_hello_gets_protocol_version() {
    // with the tls12 feature a server refuses TLS 1.2 only when configured TLS 1.3-only
    #[cfg(feature = "tls12")]
    let server = || {
        let (mut s, _) = pair(KeyKind::P256);
        s.min_version = simoom_tls::tls::ProtocolVersion::Tls13;
        ServerConnection::new(Arc::new(s))
    };
    let mut s = server();
    let (_, a) = reject(&mut s, &record(22, &client_hello(0x0303, &[0x0303, 0x0302])));
    assert_eq!(a, Some(alert::PROTOCOL_VERSION));
    // no supported_versions at all means TLS 1.2
    let mut s = server();
    let (_, a) = reject(&mut s, &record(22, &client_hello(0x0303, &[])));
    assert_eq!(a, Some(alert::PROTOCOL_VERSION));
}

#[test]
fn tls11_and_older_client_hellos_get_protocol_version() {
    for legacy in [0x0302, 0x0301, 0x0300] {
        let mut s = server();
        let (_, a) = reject(&mut s, &record(22, &client_hello(legacy, &[])));
        assert_eq!(a, Some(alert::PROTOCOL_VERSION), "legacy_version {legacy:#x}");
    }
    // a 1.3 offer behind an old legacy_version is still refused (RFC 8446 section 4.1.2
    // requires 0x0303 there)
    let mut s = server();
    let (_, a) = reject(&mut s, &record(22, &client_hello(0x0301, &[0x0304])));
    assert_eq!(a, Some(alert::PROTOCOL_VERSION));
}

#[test]
fn sslv2_compatible_hello_is_refused() {
    // SSLv2 CLIENT-HELLO with a 2-byte header (high bit set), offering SSL 3.0/TLS 1.0 suites
    let mut body = vec![1, 3, 1, 0, 9, 0, 0, 0, 16];
    body.extend_from_slice(&[0x00, 0x00, 0x2f, 0x00, 0x00, 0x35, 0x01, 0x00, 0x80]);
    body.extend_from_slice(&[0x5a; 16]);
    let mut hello = vec![0x80 | (body.len() >> 8) as u8, body.len() as u8];
    hello.extend(body);
    let mut s = server();
    let (e, a) = reject(&mut s, &hello);
    assert_eq!(e.alert(), Some(alert::UNEXPECTED_MESSAGE));
    assert_eq!(a, Some(alert::UNEXPECTED_MESSAGE));
    assert!(s.is_handshaking());
}

#[test]
fn handshake_fragmented_into_one_byte_records_completes() {
    let mut c = client();
    let mut s = server();
    let flight = c.tls_output().to_vec();
    c.consume_tls_output(flight.len());
    assert_eq!(flight[0], 22);
    let ch = &flight[5..];
    for b in ch {
        assert_eq!(s.read_tls(&record(22, &[*b])), 6);
        s.process_new_packets().unwrap();
    }
    pump(&mut c, &mut s).unwrap();
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(transfer(&mut c, &mut s, b"after fragments"), b"after fragments");
}

#[test]
fn huge_handshake_message_is_refused_from_its_header() {
    // a ClientHello announcing 16 MiB: refused as soon as the 4-byte header arrives, nothing
    // is buffered for it
    let mut s = server();
    let (e, a) = reject(&mut s, &record(22, &[1, 0xff, 0xff, 0xff]));
    assert_eq!(e.alert(), Some(alert::DECODE_ERROR));
    assert_eq!(a, Some(alert::DECODE_ERROR));
}

#[test]
fn zero_length_and_interleaved_records_before_the_handshake() {
    // an empty handshake record and application data before any key are both fatal
    let mut s = server();
    assert_eq!(reject(&mut s, &record(22, &[])).1, Some(alert::UNEXPECTED_MESSAGE));
    let mut s = server();
    assert_eq!(reject(&mut s, &record(23, b"GET / HTTP/1.1\r\n")).1, Some(alert::UNEXPECTED_MESSAGE));
    // more than the two ChangeCipherSpecs middlebox compatibility allows
    let mut s = server();
    let mut ccs = Vec::new();
    for _ in 0..3 {
        ccs.extend(record(20, &[1]));
    }
    assert_eq!(reject(&mut s, &ccs).1, Some(alert::UNEXPECTED_MESSAGE));
}

/// A TLS 1.2 ServerHello answering `c`'s ClientHello with `random`.
fn tls12_server_hello(c: &mut ClientConnection, random: [u8; 32]) -> Vec<u8> {
    let flight = c.tls_output().to_vec();
    c.consume_tls_output(flight.len());
    // record header 5, handshake header 4, legacy_version 2, random 32, then the session id
    let sid_len = flight[43] as usize;
    let sid = &flight[44..44 + sid_len];
    let mut b = vec![3, 3];
    b.extend_from_slice(&random);
    b.push(sid.len() as u8);
    b.extend_from_slice(sid);
    b.extend_from_slice(&[0xc0, 0x2f, 0, 0, 0]); // ECDHE-RSA-AES128-GCM, null, no extensions
    let mut m = vec![2, 0, (b.len() >> 8) as u8, b.len() as u8];
    m.extend(b);
    record(22, &m)
}

#[test]
fn client_rejects_the_downgrade_sentinels() {
    for last in [1u8, 0] {
        let mut c = client();
        let mut random = [0x42; 32];
        random[24..].copy_from_slice(b"DOWNGRD\0");
        random[31] = last;
        let sh = tls12_server_hello(&mut c, random);
        c.read_tls(&sh);
        assert_eq!(c.process_new_packets().unwrap_err().alert(), Some(alert::ILLEGAL_PARAMETER));
    }
    // a plain TLS 1.2 ServerHello is protocol_version (with the tls12 feature: handshake_failure,
    // since this one lacks the extended master secret the client requires)
    let mut c = client();
    let sh = tls12_server_hello(&mut c, [0x42; 32]);
    c.read_tls(&sh);
    let want = if cfg!(feature = "tls12") { alert::HANDSHAKE_FAILURE } else { alert::PROTOCOL_VERSION };
    assert_eq!(c.process_new_packets().unwrap_err().alert(), Some(want));
}

#[test]
fn server_random_never_carries_a_downgrade_sentinel() {
    for _ in 0..64 {
        let mut c = client();
        let mut s = server();
        let flight = c.tls_output().to_vec();
        c.consume_tls_output(flight.len());
        s.read_tls(&flight);
        s.process_new_packets().unwrap();
        let out = s.tls_output();
        assert_eq!((out[0], out[5]), (22, 2), "ServerHello first");
        assert_ne!(&out[11 + 24..11 + 31], b"DOWNGRD");
    }
}

#[test]
fn client_certificate_with_a_bad_chain_is_refused_with_a_readable_alert() {
    let trusted_ca = certgen::issue(&CertParams::ca("trusted client CA"), PrivateKey::generate_ec(EcCurve::P256), None);
    let other_ca = certgen::issue(&CertParams::ca("other CA"), PrivateKey::generate_ec(EcCurve::P256), None);
    let leaf = certgen::issue(&CertParams::client("client"), PrivateKey::generate_ec(EcCurve::P256), Some(&other_ca));
    let not_a_ca = certgen::issue(&CertParams::client("not a CA"), PrivateKey::generate_ec(EcCurve::P256), Some(&trusted_ca));
    let under_leaf = certgen::issue(&CertParams::client("signed by a leaf"), PrivateKey::generate_ec(EcCurve::P256), Some(&not_a_ca));
    let mut roots = RootStore::empty();
    roots.add_der(&trusted_ca.cert_der).unwrap();
    let ss = server_cert(KeyKind::P256);
    let mut scfg = simoom_tls::ServerConfig::new(certified(&ss));
    scfg.client_auth = ClientAuth::Required(roots);
    let scfg = Arc::new(scfg);
    let cases: [(&str, Vec<Vec<u8>>, &PrivateKey); 3] = [
        // issued by an unknown CA, the trusted CA appended as if it were the issuer
        ("unknown issuer", vec![leaf.cert_der.clone(), trusted_ca.cert_der.clone()], &leaf.key),
        // chained through an end-entity certificate posing as an intermediate
        ("leaf as intermediate", vec![under_leaf.cert_der.clone(), not_a_ca.cert_der.clone()], &under_leaf.key),
        // a chain that does not link at all
        ("unrelated chain", vec![leaf.cert_der.clone(), not_a_ca.cert_der.clone()], &leaf.key),
    ];
    for (name, chain, key) in cases {
        let mut ccfg = simoom_tls::ClientConfig::new(roots_of(&ss));
        ccfg.client_cert = Some(simoom_tls::CertifiedKey::new(chain, key.clone()).unwrap());
        let mut c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        let (side, e) = pump(&mut c, &mut s).unwrap_err();
        assert_eq!(side, 's', "{name}");
        let sent = e.alert().unwrap();
        assert!([alert::UNKNOWN_CA, alert::BAD_CERTIFICATE, alert::CERTIFICATE_UNKNOWN].contains(&sent), "{name}: {e:?}");
        // the client decrypts the alert (it is under the server's application key after the
        // server's Finished) instead of failing with bad_record_mac
        let n = c.read_tls(s.tls_output());
        s.consume_tls_output(n);
        assert_eq!(c.process_new_packets().unwrap_err(), Error::PeerAlert(sent), "{name}");
    }
}
