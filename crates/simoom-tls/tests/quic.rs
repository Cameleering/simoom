//! The QUIC TLS interface: RFC 9001 Appendix A and RFC 9369 vectors, and in-memory handshakes.

#![cfg(feature = "client")]

mod common;

use common::*;
use simoom_tls::quic::{self, DirectionalKeys, KeyChange, Keys, Level, QuicConnection, Secrets, VERSION_1, VERSION_2};
use simoom_tls::util::{hex, unhex};
use simoom_tls::{CipherSuite, NamedGroup};
use std::sync::Arc;

/// Protects a packet: AEAD over the payload, then header protection.
fn protect(k: &DirectionalKeys, header: &[u8], pn_len: usize, pn: u64, payload: &[u8]) -> Vec<u8> {
    let mut body = payload.to_vec();
    let mut tag = [0u8; 16];
    k.packet.seal_in_place(pn, header, &mut body, &mut tag);
    body.extend_from_slice(&tag);
    let pn_off = header.len() - pn_len;
    let sample = &body[4 - pn_len..20 - pn_len];
    let mask = k.header.mask(sample);
    let mut h = header.to_vec();
    h[0] ^= mask[0] & if h[0] & 0x80 != 0 { 0x0f } else { 0x1f };
    for i in 0..pn_len {
        h[pn_off + i] ^= mask[1 + i];
    }
    h.extend_from_slice(&body);
    h
}

/// Removes header protection and decrypts; `pn_off` is the packet number offset.
fn unprotect(k: &DirectionalKeys, packet: &[u8], pn_off: usize) -> (Vec<u8>, Vec<u8>) {
    let mut p = packet.to_vec();
    let mask = k.header.mask(&p[pn_off + 4..pn_off + 20]);
    p[0] ^= mask[0] & if p[0] & 0x80 != 0 { 0x0f } else { 0x1f };
    let pn_len = (p[0] & 3) as usize + 1;
    let mut pn = 0u64;
    for i in 0..pn_len {
        p[pn_off + i] ^= mask[1 + i];
        pn = pn << 8 | p[pn_off + i] as u64;
    }
    let header = p[..pn_off + pn_len].to_vec();
    let mut body = p[pn_off + pn_len..].to_vec();
    let pt = k.packet.open_in_place(pn, &header, &mut body).unwrap().to_vec();
    (header, pt)
}

const DCID: &str = "8394c8f03e515708";
const SERVER_PAYLOAD: &str = "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304";

#[test]
fn rfc9001_a1_initial_secrets() {
    let (c, s) = quic::initial_secrets(VERSION_1, &unhex(DCID));
    assert_eq!(hex(&c), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    assert_eq!(hex(&s), "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    let (c, s) = quic::initial_secrets(VERSION_2, &unhex(DCID));
    assert_eq!(hex(&c), "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b");
    assert_eq!(hex(&s), "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1");
}

#[test]
fn rfc9001_a2_client_initial() {
    let crypto = unhex("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff");
    let mut payload = crypto.clone();
    payload.resize(1162, 0);
    let header = unhex("c300000001088394c8f03e5157080000449e00000002");
    let client = quic::initial_keys(VERSION_1, &unhex(DCID), false);
    let sample: [u8; 16] = unhex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
    assert_eq!(hex(&client.local.header.mask(&sample)), "437b9aec36");
    let pkt = protect(&client.local, &header, 4, 2, &payload);
    assert_eq!(pkt.len(), 1200);
    assert_eq!(hex(&pkt[..40]), "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8ba");
    assert_eq!(hex(&pkt[1168..]), "8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934");
    // the server opens it with its remote keys
    let server = quic::initial_keys(VERSION_1, &unhex(DCID), true);
    let (h, pt) = unprotect(&server.remote, &pkt, 18);
    assert_eq!(h, header);
    assert_eq!(pt, payload);
}

#[test]
fn rfc9001_a3_server_initial() {
    let header = unhex("c1000000010008f067a5502a4262b50040750001");
    let keys = quic::initial_keys(VERSION_1, &unhex(DCID), true);
    let pkt = protect(&keys.local, &header, 2, 1, &unhex(SERVER_PAYLOAD));
    assert_eq!(
        hex(&pkt),
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee"
    );
}

#[test]
fn rfc9001_a4_retry_and_rfc9369_retry() {
    let tag = quic::retry_integrity_tag(VERSION_1, &unhex(DCID), &unhex("ff000000010008f067a5502a4262b5746f6b656e"));
    assert_eq!(hex(&tag), "04a265ba2eff4d829058fb3f0f2496ba");
    let tag = quic::retry_integrity_tag(VERSION_2, &unhex(DCID), &unhex("cf6b3343cf0008f067a5502a4262b5746f6b656e"));
    assert_eq!(hex(&tag), "c8646ce8bfe33952d955543665dcc7b6");
}

#[test]
fn rfc9001_a5_chacha20_short_header_and_key_update() {
    let secret = unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let k = DirectionalKeys::new(CipherSuite::Chacha20Poly1305Sha256, VERSION_1, &secret);
    let pkt = protect(&k, &unhex("4200bff4"), 3, 654360564, &[0x01]);
    assert_eq!(hex(&pkt), "4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    assert_eq!(k.packet.confidentiality_limit(), 1 << 62);
    assert_eq!(k.packet.integrity_limit(), 1 << 36);
    // "quic ku" gives 1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9
    let ku = unhex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");
    let expect = DirectionalKeys::new(CipherSuite::Chacha20Poly1305Sha256, VERSION_1, &ku);
    let mut s = Secrets::new(CipherSuite::Chacha20Poly1305Sha256, VERSION_1, true, secret.clone(), secret);
    let (local, remote) = s.next_packet_keys();
    for key in [&local, &remote] {
        let (mut a, mut b) = (vec![7u8; 33], vec![7u8; 33]);
        let (mut ta, mut tb) = ([0u8; 16], [0u8; 16]);
        key.seal_in_place(9, b"hdr", &mut a, &mut ta);
        expect.packet.seal_in_place(9, b"hdr", &mut b, &mut tb);
        assert_eq!((a, ta), (b, tb));
    }
}

#[test]
fn rfc9369_v2_server_initial() {
    let header = unhex("d16b3343cf0008f067a5502a4262b50040750001");
    let keys = quic::initial_keys(VERSION_2, &unhex(DCID), true);
    let pkt = protect(&keys.local, &header, 2, 1, &unhex(SERVER_PAYLOAD));
    assert_eq!(
        hex(&pkt),
        "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca84bed8521e2e140"
    );
    assert_eq!(keys.local.packet.confidentiality_limit(), 1 << 23);
}

/// Per-side results of driving a QUIC handshake.
#[derive(Default)]
struct Side {
    hs: Option<Keys>,
    one_rtt: Option<(Keys, Secrets)>,
}

/// Runs `write_handshake` and delivers its output to `to`. Returns false if nothing happened.
fn step(from: &mut QuicConnection, side: &mut Side, to: &mut QuicConnection) -> Result<bool, simoom_tls::Error> {
    let mut progressed = false;
    loop {
        let level = from.write_level();
        let mut out = Vec::new();
        let change = from.write_handshake(&mut out);
        if !out.is_empty() {
            to.read_handshake(level, &out)?;
            progressed = true;
        }
        match change {
            Some(KeyChange::Handshake { keys }) => side.hs = Some(keys),
            Some(KeyChange::OneRtt { keys, next }) => side.one_rtt = Some((keys, next)),
            None if out.is_empty() => return Ok(progressed),
            None => {}
        }
        progressed = true;
    }
}

fn drive(c: &mut QuicConnection, s: &mut QuicConnection) -> Result<(Side, Side), simoom_tls::Error> {
    let (mut cs, mut ss) = (Side::default(), Side::default());
    for _ in 0..20 {
        let a = step(c, &mut cs, s)?;
        let b = step(s, &mut ss, c)?;
        if !a && !b {
            break;
        }
    }
    Ok((cs, ss))
}

fn keys_match(a: &Keys, b: &Keys) {
    let mut d = b"stream frame".to_vec();
    let mut tag = [0u8; 16];
    a.local.packet.seal_in_place(5, b"short header", &mut d, &mut tag);
    d.extend_from_slice(&tag);
    assert_eq!(b.remote.packet.open_in_place(5, b"short header", &mut d).unwrap(), b"stream frame");
    let sample = [0x42u8; 16];
    assert_eq!(a.local.header.mask(&sample), b.remote.header.mask(&sample));
}

fn quic_configs() -> (Arc<simoom_tls::ServerConfig>, Arc<simoom_tls::ClientConfig>) {
    let (s, c) = pair(KeyKind::P256);
    (arc(s.with_alpn(&[b"h3"])), arc(c.with_alpn(&[b"h3"])))
}

#[test]
fn quic_handshake_v1_v2_and_resumption() {
    let (scfg, ccfg) = quic_configs();
    for version in [VERSION_1, VERSION_2] {
        let mut s = QuicConnection::new_server(scfg.clone(), b"server-params".to_vec());
        let mut c = QuicConnection::new_client(ccfg.clone(), "localhost", b"client-params".to_vec()).unwrap();
        s.set_version(version);
        c.set_version(version);
        assert_eq!(c.write_level(), Level::Initial);
        let (cs, ss) = drive(&mut c, &mut s).unwrap();
        assert!(!c.is_handshaking() && !s.is_handshaking());
        assert_eq!(c.alpn_protocol(), Some(&b"h3"[..]));
        assert_eq!(s.peer_transport_params(), Some(&b"client-params"[..]));
        assert_eq!(c.peer_transport_params(), Some(&b"server-params"[..]));
        keys_match(cs.hs.as_ref().unwrap(), ss.hs.as_ref().unwrap());
        keys_match(ss.hs.as_ref().unwrap(), cs.hs.as_ref().unwrap());
        let (ck, mut cn) = cs.one_rtt.unwrap();
        let (sk, mut sn) = ss.one_rtt.unwrap();
        keys_match(&ck, &sk);
        keys_match(&sk, &ck);
        // key update: both sides derive the same next generation
        let (cl, cr) = cn.next_packet_keys();
        let (sl, sr) = sn.next_packet_keys();
        let mut d = b"x".to_vec();
        let mut t = [0u8; 16];
        cl.seal_in_place(1, b"h", &mut d, &mut t);
        d.extend_from_slice(&t);
        assert!(sr.open_in_place(1, b"h", &mut d).is_ok());
        let mut d = b"y".to_vec();
        sl.seal_in_place(2, b"h", &mut d, &mut t);
        d.extend_from_slice(&t);
        assert!(cr.open_in_place(2, b"h", &mut d).is_ok());
        assert_eq!(c.write_level(), Level::OneRtt);
    }
    // the NewSessionTicket (1-RTT CRYPTO data) enables resumption
    let mut s = QuicConnection::new_server(scfg.clone(), b"tp".to_vec());
    let mut c = QuicConnection::new_client(ccfg.clone(), "localhost", b"tp".to_vec()).unwrap();
    drive(&mut c, &mut s).unwrap();
    assert_eq!(ccfg.sessions.as_ref().unwrap().len_for("localhost"), 1);
    let mut s = QuicConnection::new_server(scfg, b"tp".to_vec());
    let mut c = QuicConnection::new_client(ccfg, "localhost", b"tp".to_vec()).unwrap();
    let (cs, ss) = drive(&mut c, &mut s).unwrap();
    assert!(c.is_resumed() && s.is_resumed());
    keys_match(&cs.one_rtt.unwrap().0, &ss.one_rtt.unwrap().0);
}

#[test]
fn quic_hello_retry_request() {
    let (s, mut c) = pair(KeyKind::Ed25519);
    let mut s = s.with_alpn(&[b"h3"]);
    s.groups = vec![NamedGroup::Secp256r1];
    c.groups = vec![NamedGroup::X25519, NamedGroup::Secp256r1];
    let c = c.with_alpn(&[b"h3"]);
    let mut s = QuicConnection::new_server(arc(s), vec![1]);
    let mut c = QuicConnection::new_client(arc(c), "localhost", vec![2]).unwrap();
    let (cs, ss) = drive(&mut c, &mut s).unwrap();
    keys_match(&cs.one_rtt.unwrap().0, &ss.one_rtt.unwrap().0);
}

#[test]
fn quic_errors_map_to_crypto_error_codes() {
    // no common ALPN: no_application_protocol (0x100 + 120)
    let (s, c) = pair(KeyKind::P256);
    let mut s = QuicConnection::new_server(arc(s.with_alpn(&[b"h3"])), vec![]);
    let mut c = QuicConnection::new_client(arc(c.with_alpn(&[b"hq-interop"])), "localhost", vec![]).unwrap();
    assert!(drive(&mut c, &mut s).is_err());
    assert_eq!(s.tls_alert(), Some(0x178));
    // a client configuration without ALPN cannot start a QUIC handshake
    let (_, c) = pair(KeyKind::P256);
    assert!(QuicConnection::new_client(arc(c), "localhost", vec![]).is_err());
    // KeyUpdate is refused (unexpected_message, 0x10a)
    let (scfg, ccfg) = quic_configs();
    let mut s = QuicConnection::new_server(scfg, vec![]);
    let mut c = QuicConnection::new_client(ccfg, "localhost", vec![]).unwrap();
    drive(&mut c, &mut s).unwrap();
    assert!(c.read_handshake(Level::OneRtt, &[24, 0, 0, 1, 0]).is_err());
    assert_eq!(c.tls_alert(), Some(0x10a));
    // data at the wrong level
    let (scfg, _) = quic_configs();
    let mut s = QuicConnection::new_server(scfg, vec![]);
    assert!(s.read_handshake(Level::Handshake, &[1, 0, 0, 0]).is_err());
    assert_eq!(s.tls_alert(), Some(0x10a));
}
