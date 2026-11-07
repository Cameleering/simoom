//! The transport with real TLS 1.3 (simoom-tls): RFC 9001 Appendix A vectors through this
//! crate's packet code, and full handshakes over the simulated network.

mod common;
use common::{echo_on, pattern};
use simoom_quic::crypto::CryptoProvider;
use simoom_quic::sim::{Link, Pair};
use simoom_quic::tls::TlsProvider;
use simoom_quic::{packet, Config, ConnectionError, Event, VERSION_1, VERSION_2};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::{CertifiedKey, ClientConfig, ServerConfig};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cert() -> &'static certgen::SelfSigned {
    static C: OnceLock<certgen::SelfSigned> = OnceLock::new();
    C.get_or_init(|| certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None))
}

fn server_provider() -> Arc<TlsProvider> {
    let ss = cert();
    let ck = CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap();
    Arc::new(TlsProvider::server(Arc::new(ServerConfig::new(ck).with_alpn(&[b"h3"]))))
}

fn client_provider(trust: bool) -> Arc<TlsProvider> {
    let mut roots = RootStore::empty();
    if trust {
        roots.add_der(&cert().cert_der).unwrap();
    }
    Arc::new(TlsProvider::client(Arc::new(ClientConfig::new(roots).with_alpn(&[b"h3"]))))
}

fn configs(f: impl Fn(&mut Config)) -> (Arc<Config>, Arc<Config>) {
    let mut c = Config::new(client_provider(true));
    let mut s = Config::new(server_provider());
    f(&mut c);
    f(&mut s);
    (Arc::new(c), Arc::new(s))
}

const DCID: &str = "8394c8f03e515708";

#[test]
fn rfc9001_a3_server_initial_through_packet_code() {
    // Seal and header-protect the RFC 9001 A.3 server Initial with this crate's code path.
    let p = server_provider();
    let keys = p.initial_keys(VERSION_1, &unhex(DCID), true);
    let payload = unhex("02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304");
    let mut buf = Vec::new();
    let (len_at, pn_at) = packet::put_long_header(&mut buf, VERSION_1, packet::PacketType::Initial, &[], &unhex("f067a5502a4262b5"), Some(&[]), 1, 2);
    simoom_quic::coding::put_varint_fixed(&mut buf[len_at..], (2 + payload.len() + 16) as u64, 2);
    let hdr_end = buf.len();
    buf.extend_from_slice(&payload);
    let end = buf.len();
    buf.resize(end + 16, 0);
    {
        let (head, rest) = buf.split_at_mut(hdr_end);
        let (body, tag) = rest.split_at_mut(end - hdr_end);
        keys.local.packet.seal(1, head, body, tag);
    }
    packet::protect(&mut buf, 0, pn_at, 2, &*keys.local.header);
    assert_eq!(
        hex(&buf),
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee"
    );
    // And the client removes protection with this crate's code.
    let client = client_provider(true).initial_keys(VERSION_1, &unhex(DCID), false);
    let h = packet::parse_header(&buf, 0, 8).unwrap();
    let (tpn, pn_len) = packet::unprotect(&mut buf, 0, h.pn_offset, h.end, &*client.remote.header).unwrap();
    assert_eq!((tpn, pn_len), (1, 2));
    let hdr_end = h.pn_offset + pn_len;
    let (head, rest) = buf[..h.end].split_at_mut(hdr_end);
    let n = client.remote.packet.open(1, head, rest).unwrap();
    assert_eq!(&rest[..n], &payload[..]);
}

#[test]
fn rfc9001_a4_retry_tag_through_packet_code() {
    let p = server_provider();
    let mut out = Vec::new();
    // Retry from A.4: random bits 0xf, empty DCID, SCID f067a5502a4262b5, token "token".
    packet::retry(&mut out, &*p, VERSION_1, 0x0f, &unhex(DCID), &[], &unhex("f067a5502a4262b5"), b"token");
    assert_eq!(hex(&out), "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
}

#[test]
fn real_tls_handshake_and_transfer() {
    for version in [VERSION_1, VERSION_2] {
        let (c, s) = configs(|c| c.versions = vec![version]);
        let mut p = Pair::new(c, s, Link::default(), 1);
        let (ch, sh) = common::handshake(&mut p);
        assert_eq!(p.client.conn(ch).unwrap().alpn(), Some(&b"h3"[..]));
        assert_eq!(p.server.conn(sh).unwrap().version(), version);
        echo_on(&mut p, ch, sh, 500_000, Duration::from_secs(60));
    }
}

#[test]
fn real_tls_under_loss_with_retry_and_key_updates() {
    let (c, s) = configs(|c| {
        c.retry = true;
        c.transport.key_update_interval = Some(200);
    });
    let link = Link { loss_ppm: 50_000, reorder_ppm: 50_000, reorder_delay: Duration::from_millis(20), ..Link::default() };
    let mut p = Pair::new(c, s, link, 2);
    let (ch, sh) = common::handshake(&mut p);
    echo_on(&mut p, ch, sh, 1_000_000, Duration::from_secs(300));
    assert!(p.client.conn(ch).unwrap().stats().key_updates > 2);
    assert!(p.server.conn(sh).unwrap().stats().key_updates > 2);
}

#[test]
fn untrusted_certificate_fails_with_crypto_error() {
    let mut c = Config::new(client_provider(false));
    c.transport.max_idle_timeout = Duration::from_secs(5);
    let s = Config::new(server_provider());
    let mut p = Pair::new(Arc::new(c), Arc::new(s), Link::default(), 3);
    let h = p.connect();
    let mut err = None;
    p.run_until(Duration::from_secs(30), |p| {
        while let Some(e) = p.client.poll_event(h) {
            if let Event::Closed(e) = e {
                err = Some(e);
            }
        }
        err.is_some()
    });
    match err {
        Some(ConnectionError::Transport(e)) => assert!(e.code > 0x100 && e.code < 0x200, "{e:?}"),
        other => panic!("expected a CRYPTO_ERROR, got {other:?}"),
    }
    let _ = pattern(1, 1);
}
