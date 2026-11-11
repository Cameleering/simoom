//! TLS 1.2 (feature `tls12`) between simoom's own client and server, in memory: every suite and
//! key type, version negotiation, downgrade protection, resumption by ticket and by session ID,
//! client certificates, the extended master secret requirement, refused renegotiation,
//! TLS_FALLBACK_SCSV, the RFC 5705 exporter and hostile peers.

mod common;

use common::*;
use simoom_tls::tls::tls12::Tls12Suite;
use simoom_tls::tls::ProtocolVersion;
use simoom_tls::{alert, ClientAuth, ClientConfig, ClientConnection, Error, NamedGroup, ServerConfig, ServerConnection};
use std::sync::Arc;

fn v12(c: &mut ClientConfig) {
    c.max_version = ProtocolVersion::Tls12;
}

fn connect(scfg: ServerConfig, ccfg: ClientConfig) -> (ClientConnection, ServerConnection) {
    let (scfg, ccfg) = (Arc::new(scfg), Arc::new(ccfg));
    let mut c = ClientConnection::new(ccfg, "localhost").unwrap();
    let mut s = ServerConnection::new(scfg);
    pump(&mut c, &mut s).unwrap_or_else(|(side, e)| panic!("{side}: {e}"));
    assert!(!c.is_handshaking() && !s.is_handshaking());
    (c, s)
}

fn data_both_ways(c: &mut ClientConnection, s: &mut ServerConnection) {
    let big: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
    assert_eq!(transfer(c, s, &big), big);
    assert_eq!(transfer(s, c, b"pong"), b"pong");
}

#[test]
fn every_suite_and_key_type() {
    for (kind, suites) in [
        (KeyKind::P256, [Tls12Suite::EcdheEcdsaAes128GcmSha256, Tls12Suite::EcdheEcdsaAes256GcmSha384, Tls12Suite::EcdheEcdsaChacha20Poly1305]),
        (KeyKind::P384, [Tls12Suite::EcdheEcdsaAes128GcmSha256, Tls12Suite::EcdheEcdsaAes256GcmSha384, Tls12Suite::EcdheEcdsaChacha20Poly1305]),
        (KeyKind::Ed25519, [Tls12Suite::EcdheEcdsaAes128GcmSha256, Tls12Suite::EcdheEcdsaAes256GcmSha384, Tls12Suite::EcdheEcdsaChacha20Poly1305]),
        (KeyKind::Rsa, [Tls12Suite::EcdheRsaAes128GcmSha256, Tls12Suite::EcdheRsaAes256GcmSha384, Tls12Suite::EcdheRsaChacha20Poly1305]),
    ] {
        let k = kind as usize;
        for suite in suites {
            for group in [NamedGroup::X25519, NamedGroup::Secp256r1, NamedGroup::Secp384r1] {
                let kind = [KeyKind::P256, KeyKind::P384, KeyKind::Ed25519, KeyKind::Rsa].into_iter().nth(k).unwrap();
                let (mut scfg, mut ccfg) = pair(kind);
                scfg.groups = vec![group];
                scfg.suites12 = vec![suite];
                v12(&mut ccfg);
                ccfg.groups = vec![group, NamedGroup::Secp256r1];
                if k == 1 {
                    // a P-384 certificate needs the client to list secp384r1 (RFC 8422)
                    ccfg.groups.push(NamedGroup::Secp384r1);
                    ccfg.groups.dedup();
                }
                let (mut c, mut s) = connect(scfg, ccfg);
                assert_eq!(c.protocol_version(), Some(ProtocolVersion::Tls12));
                assert_eq!(s.negotiated_tls12_suite(), Some(suite));
                assert_eq!(c.cipher_suite_name(), Some(suite.name()));
                assert_eq!(c.negotiated_cipher_suite(), None);
                assert_eq!(s.negotiated_group(), Some(group));
                data_both_ways(&mut c, &mut s);
            }
        }
    }
}

#[test]
fn tls13_is_chosen_when_both_sides_support_it() {
    let (scfg, ccfg) = pair(KeyKind::P256);
    let (c, s) = connect(scfg, ccfg);
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::Tls13));
    assert_eq!(s.protocol_version(), Some(ProtocolVersion::Tls13));
    // a TLS 1.2-only server, a client offering both: TLS 1.2
    let (mut scfg, ccfg) = pair(KeyKind::Rsa);
    scfg.max_version = ProtocolVersion::Tls12;
    let (mut c, mut s) = connect(scfg, ccfg);
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::Tls12));
    data_both_ways(&mut c, &mut s);
    // a TLS 1.3-only server refuses a TLS 1.2-only client
    let (mut scfg, mut ccfg) = pair(KeyKind::P256);
    scfg.min_version = ProtocolVersion::Tls13;
    v12(&mut ccfg);
    let mut c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg));
    let e = pump(&mut c, &mut s).unwrap_err();
    assert_eq!(e.1.alert(), Some(alert::PROTOCOL_VERSION));
}

#[test]
fn downgrade_sentinel_is_detected() {
    // a server that supports TLS 1.3 but answers TLS 1.2 (as an attacker stripping
    // supported_versions would make it) marks its random; a TLS 1.3 client refuses it
    let (scfg, ccfg) = pair(KeyKind::P256);
    let mut c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg));
    // strip supported_versions (and key_share) from the ClientHello by building a TLS 1.2-only
    // one with the same client: the server answers TLS 1.2 with the sentinel
    let mut ccfg12 = pair(KeyKind::P256).1;
    v12(&mut ccfg12);
    let mut c12 = ClientConnection::new(Arc::new(ccfg12), "localhost").unwrap();
    let hello12 = c12.tls_output().to_vec();
    s.read_tls(&hello12);
    s.process_new_packets().unwrap();
    // hand the server's TLS 1.2 flight to the client that offered TLS 1.3
    let _ = c.tls_output().to_vec();
    let n = c.tls_output().len();
    c.consume_tls_output(n);
    c.read_tls(s.tls_output());
    let e = c.process_new_packets().unwrap_err();
    assert_eq!(e.alert(), Some(alert::ILLEGAL_PARAMETER), "{e}");
    // the TLS 1.2-only client that sent this ClientHello accepts the same flight
    c12.read_tls(s.tls_output());
    c12.process_new_packets().unwrap();
}

#[test]
fn fallback_scsv_is_refused_when_tls13_is_supported() {
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    v12(&mut ccfg);
    let c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
    let mut hello = c.tls_output().to_vec();
    // append TLS_FALLBACK_SCSV to the cipher suite list: record(5) hs(4) version(2) random(32) sid
    let sid_len = hello[5 + 4 + 2 + 32] as usize;
    let at = 5 + 4 + 2 + 32 + 1 + sid_len;
    let len = u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
    hello.splice(at + 2 + len..at + 2 + len, [0x56, 0x00]);
    let l = u16::from_be_bytes([hello[at], hello[at + 1]]) + 2;
    hello[at..at + 2].copy_from_slice(&l.to_be_bytes());
    let rec = u16::from_be_bytes([hello[3], hello[4]]) + 2;
    hello[3..5].copy_from_slice(&rec.to_be_bytes());
    let hs = (hello[6] as usize) << 16 | (hello[7] as usize) << 8 | hello[8] as usize;
    let hs = hs + 2;
    hello[6..9].copy_from_slice(&[(hs >> 16) as u8, (hs >> 8) as u8, hs as u8]);
    let mut s = ServerConnection::new(Arc::new(scfg));
    s.read_tls(&hello);
    assert_eq!(s.process_new_packets().unwrap_err().alert(), Some(alert::INAPPROPRIATE_FALLBACK));
}

#[test]
fn ticket_and_session_id_resumption() {
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    v12(&mut ccfg);
    let (scfg, ccfg) = (Arc::new(scfg), Arc::new(ccfg));
    // tickets (the client offers the session_ticket extension by default)
    for round in 0..3 {
        let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        pump(&mut c, &mut s).unwrap();
        assert_eq!(c.is_resumed(), round > 0, "round {round}");
        assert_eq!(s.is_resumed(), round > 0);
        assert_eq!(c.protocol_version(), Some(ProtocolVersion::Tls12));
        data_both_ways(&mut c, &mut s);
    }
    // session IDs: a server without tickets
    let (mut scfg, mut ccfg) = pair(KeyKind::Rsa);
    scfg.ticketer = None;
    v12(&mut ccfg);
    let (scfg, ccfg) = (Arc::new(scfg), Arc::new(ccfg));
    for round in 0..3 {
        let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        pump(&mut c, &mut s).unwrap();
        assert_eq!(c.is_resumed(), round > 0, "round {round}");
        data_both_ways(&mut c, &mut s);
    }
    assert_eq!(scfg.session_ids.as_ref().unwrap().len(), 1);
    // neither: no resumption
    let (mut scfg, mut ccfg) = pair(KeyKind::P256);
    scfg.ticketer = None;
    scfg.session_ids = None;
    v12(&mut ccfg);
    let (scfg, ccfg) = (Arc::new(scfg), Arc::new(ccfg));
    for _ in 0..2 {
        let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        pump(&mut c, &mut s).unwrap();
        assert!(!c.is_resumed());
    }
}

#[test]
fn client_certificates() {
    let (ca, client) = ca_and_client_cert();
    for required in [false, true] {
        for present in [false, true] {
            let (mut scfg, mut ccfg) = pair(KeyKind::P256);
            let roots = roots_of(&ca);
            scfg.client_auth = if required { ClientAuth::Required(roots) } else { ClientAuth::Optional(roots) };
            v12(&mut ccfg);
            if present {
                ccfg.client_cert = Some(simoom_tls::CertifiedKey::new(vec![client.cert_der.clone(), ca.cert_der.clone()], client.key.clone()).unwrap());
            }
            let mut c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
            let mut s = ServerConnection::new(Arc::new(scfg));
            let r = pump(&mut c, &mut s);
            if required && !present {
                assert_eq!(r.unwrap_err().1.alert(), Some(alert::HANDSHAKE_FAILURE));
                continue;
            }
            r.unwrap();
            assert_eq!(s.peer_certificates().len(), if present { 2 } else { 0 });
            data_both_ways(&mut c, &mut s);
        }
    }
    // an untrusted client certificate is refused
    let (mut scfg, mut ccfg) = pair(KeyKind::P256);
    scfg.client_auth = ClientAuth::Required(roots_of(&server_cert(KeyKind::Rsa)));
    v12(&mut ccfg);
    ccfg.client_cert = Some(simoom_tls::CertifiedKey::new(vec![client.cert_der.clone()], client.key.clone()).unwrap());
    let mut c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg));
    assert_eq!(pump(&mut c, &mut s).unwrap_err().1.alert(), Some(alert::UNKNOWN_CA));
}

#[test]
fn server_certificate_is_verified() {
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    ccfg.roots = roots_of(&server_cert(KeyKind::Rsa));
    v12(&mut ccfg);
    let mut c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg));
    let e = pump(&mut c, &mut s).unwrap_err();
    assert_eq!(e.0, 'c');
    assert!(matches!(e.1, Error::Certificate(_)), "{}", e.1);
    // the wrong host name
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    v12(&mut ccfg);
    let mut c = ClientConnection::new(Arc::new(ccfg), "other.example").unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg));
    assert!(matches!(pump(&mut c, &mut s).unwrap_err().1, Error::Certificate(_)));
}

#[test]
fn extended_master_secret_is_required() {
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    v12(&mut ccfg);
    let c = ClientConnection::new(Arc::new(ccfg), "localhost").unwrap();
    let mut hello = c.tls_output().to_vec();
    // rename the extended_master_secret extension (0x0017, empty) to an unknown one
    let pos = hello.windows(4).position(|w| w == [0x00, 0x17, 0x00, 0x00]).expect("EMS extension");
    hello[pos + 1] = 0x99;
    let mut s = ServerConnection::new(Arc::new(scfg));
    s.read_tls(&hello);
    let e = s.process_new_packets().unwrap_err();
    assert_eq!(e.alert(), Some(alert::HANDSHAKE_FAILURE));
    assert!(e.to_string().contains("extended master secret"), "{e}");
}

#[test]
fn exporter_matches_on_both_sides() {
    let (scfg, mut ccfg) = pair(KeyKind::Rsa);
    v12(&mut ccfg);
    let (c, s) = connect(scfg, ccfg);
    let a = c.export_keying_material(b"EXPORTER-test", b"ctx", 32).unwrap();
    let b = s.export_keying_material(b"EXPORTER-test", b"ctx", 32).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c.export_keying_material(b"EXPORTER-test", b"", 32).unwrap());
    assert!(c.into_inner().export_traffic_secrets().is_err(), "kernel TLS export is TLS 1.3 only");
}

#[test]
fn key_update_is_tls13_only() {
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    v12(&mut ccfg);
    let (mut c, _s) = connect(scfg, ccfg);
    assert!(matches!(c.send_key_update(false), Err(Error::Config(_))));
}

#[test]
fn bytewise_and_tampered_flights() {
    let (scfg, mut ccfg) = pair(KeyKind::Rsa);
    v12(&mut ccfg);
    let (scfg, ccfg) = (Arc::new(scfg), Arc::new(ccfg));
    let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
    let mut s = ServerConnection::new(scfg.clone());
    pump_bytewise(&mut c, &mut s).unwrap();
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::Tls12));
    // flip one byte anywhere in the server's first flight: the client fails cleanly
    let mut probe_c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
    let mut probe_s = ServerConnection::new(scfg.clone());
    probe_s.read_tls(probe_c.tls_output());
    probe_s.process_new_packets().unwrap();
    let flight_len = probe_s.tls_output().len();
    let n = probe_c.tls_output().len();
    probe_c.consume_tls_output(n);
    for i in (0..flight_len).step_by(97) {
        let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        s.read_tls(c.tls_output());
        let n = c.tls_output().len();
        c.consume_tls_output(n);
        s.process_new_packets().unwrap();
        let mut flight = s.tls_output().to_vec();
        if i >= flight.len() {
            break;
        }
        flight[i] ^= 0x41;
        c.read_tls(&flight);
        // either a clean error now or later in the handshake, never a panic or success with
        // different keys
        let r = c.process_new_packets();
        if r.is_ok() {
            let n = s.tls_output().len();
            s.consume_tls_output(n);
            let _ = pump(&mut c, &mut s);
            assert!(c.is_handshaking() || s.is_handshaking() || c.error().is_some() || s.error().is_some() || flight_len == 0);
        }
    }
}

#[test]
fn quic_stays_tls13_only() {
    // a QUIC client never offers TLS 1.2, even when configured to allow it
    let (_, mut ccfg) = pair(KeyKind::P256);
    ccfg.alpn = vec![b"h3".to_vec()];
    let mut q = simoom_tls::quic::QuicConnection::new_client(Arc::new(ccfg), "localhost", vec![1, 2, 3]).unwrap();
    let mut hello = Vec::new();
    q.write_handshake(&mut hello);
    // no TLS 1.2 suite (0xc0xx / 0xccxx) and no EMS extension in the QUIC ClientHello
    assert!(!hello.windows(2).any(|w| w == [0xc0, 0x2b] || w == [0xcc, 0xa8]));
    assert!(!hello.windows(4).any(|w| w == [0x00, 0x17, 0x00, 0x00]));
}
