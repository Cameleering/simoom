//! The TLS interface for QUIC (RFC 9001), with QUIC version 2 key labels (RFC 9369).
//!
//! [`QuicConnection`] runs the same handshake engine as the record layer, but exchanges raw
//! handshake messages tagged with their encryption [`Level`] (carried in CRYPTO frames) and
//! hands out packet and header-protection keys as they become available.
//!
//! Driving it:
//! 1. Feed CRYPTO frame data with [`QuicConnection::read_handshake`].
//! 2. Call [`QuicConnection::write_handshake`] until it returns `None` and writes nothing. The
//!    bytes it appends belong to the level reported by [`QuicConnection::write_level`] *before*
//!    the call; a returned [`KeyChange`] applies to the bytes of later calls.
//! 3. On an error, close the connection with [`QuicConnection::tls_alert`]
//!    (QUIC CRYPTO_ERROR, 0x100 + the TLS alert).
//!
//! 0-RTT is not offered or accepted. KeyUpdate messages are refused (QUIC updates keys with
//! [`Secrets::next_packet_keys`] instead).

use crate::crypto::aes::Aes;
#[cfg(feature = "chacha20")]
use crate::crypto::chacha::chacha20_block;
use crate::crypto::gcm::AesGcm;
use crate::crypto::sha2::HashAlg;
#[cfg(feature = "client")]
use crate::tls::client::ClientHs;
#[cfg(feature = "client")]
use crate::tls::config::ClientConfig;
use crate::tls::config::ServerConfig;
use crate::tls::engine::{Engine, Event, HsReader};
use crate::tls::keyschedule::{expand_label, expand_label_vec};
use crate::tls::record::{nonce, Aead};
use crate::tls::server::ServerHs;
use crate::tls::{alert, AeadAlg, CipherSuite, Error, Result};
use std::sync::Arc;

pub use crate::tls::Level;

/// QUIC version 1 (RFC 9000).
pub const VERSION_1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369).
pub const VERSION_2: u32 = 0x6b33_43cf;

struct Labels {
    key: &'static [u8],
    iv: &'static [u8],
    hp: &'static [u8],
    ku: &'static [u8],
}

fn labels(version: u32) -> Labels {
    if version == VERSION_2 {
        Labels { key: b"quicv2 key", iv: b"quicv2 iv", hp: b"quicv2 hp", ku: b"quicv2 ku" }
    } else {
        Labels { key: b"quic key", iv: b"quic iv", hp: b"quic hp", ku: b"quic ku" }
    }
}

/// AEAD packet protection for one direction (RFC 9001 section 5.3).
#[derive(Clone)]
pub struct PacketKey {
    aead: Aead,
    iv: [u8; 12],
    alg: AeadAlg,
}

impl std::fmt::Debug for PacketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PacketKey({:?})", self.alg)
    }
}

impl PacketKey {
    fn new(suite: CipherSuite, version: u32, secret: &[u8]) -> PacketKey {
        let l = labels(version);
        let h = suite.hash();
        let key = expand_label_vec(h, secret, l.key, &[], suite.aead().key_len());
        let mut iv = [0u8; 12];
        expand_label(h, secret, l.iv, &[], &mut iv);
        PacketKey { aead: Aead::new(suite.aead(), &key), iv, alg: suite.aead() }
    }

    /// Encrypts `payload` in place; `header` is the unprotected header (the AAD).
    pub fn seal_in_place(&self, pn: u64, header: &[u8], payload: &mut [u8], tag_out: &mut [u8; 16]) {
        *tag_out = self.aead.seal(&nonce(&self.iv, pn), header, payload);
    }

    /// Decrypts `payload_with_tag` in place and returns the plaintext part.
    pub fn open_in_place<'a>(&self, pn: u64, header: &[u8], payload_with_tag: &'a mut [u8]) -> Result<&'a mut [u8]> {
        if payload_with_tag.len() < 16 {
            return Err(Error::proto(alert::BAD_RECORD_MAC, "packet too short"));
        }
        let n = payload_with_tag.len() - 16;
        let (ct, tag) = payload_with_tag.split_at_mut(n);
        if !self.aead.open(&nonce(&self.iv, pn), header, ct, tag) {
            return Err(Error::proto(alert::BAD_RECORD_MAC, "packet authentication failed"));
        }
        Ok(ct)
    }

    pub fn tag_len(&self) -> usize {
        16
    }

    /// Packets that may be encrypted under this key (RFC 9001 section 6.6).
    pub fn confidentiality_limit(&self) -> u64 {
        match self.alg {
            #[cfg(feature = "chacha20")]
            AeadAlg::Chacha20Poly1305 => 1 << 62,
            _ => 1 << 23,
        }
    }

    /// Forged packets tolerated before the connection must close (RFC 9001 section 6.6).
    pub fn integrity_limit(&self) -> u64 {
        match self.alg {
            #[cfg(feature = "chacha20")]
            AeadAlg::Chacha20Poly1305 => 1 << 36,
            _ => 1 << 52,
        }
    }
}

/// Header protection (RFC 9001 section 5.4): AES-ECB or ChaCha20.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // one per connection or key; boxing would add an indirection on the hot path
pub enum HeaderProtectionKey {
    Aes(Aes),
    #[cfg(feature = "chacha20")]
    ChaCha([u8; 32]),
}

impl std::fmt::Debug for HeaderProtectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HeaderProtectionKey::Aes(_) => "HeaderProtectionKey(AES)",
            #[cfg(feature = "chacha20")]
            HeaderProtectionKey::ChaCha(_) => "HeaderProtectionKey(ChaCha20)",
        })
    }
}

impl HeaderProtectionKey {
    fn new(suite: CipherSuite, version: u32, secret: &[u8]) -> HeaderProtectionKey {
        let key = expand_label_vec(suite.hash(), secret, labels(version).hp, &[], suite.aead().key_len());
        match suite.aead() {
            #[cfg(feature = "chacha20")]
            AeadAlg::Chacha20Poly1305 => HeaderProtectionKey::ChaCha(key.try_into().unwrap()),
            _ => HeaderProtectionKey::Aes(Aes::new(&key)),
        }
    }

    /// The 5-byte mask for a 16-byte `sample` of the protected payload.
    pub fn mask(&self, sample: &[u8]) -> [u8; 5] {
        assert!(sample.len() >= 16, "header protection sample must be 16 bytes");
        let mut out = [0u8; 5];
        match self {
            HeaderProtectionKey::Aes(a) => {
                let mut b: [u8; 16] = sample[..16].try_into().unwrap();
                a.encrypt_block(&mut b);
                out.copy_from_slice(&b[..5]);
            }
            #[cfg(feature = "chacha20")]
            HeaderProtectionKey::ChaCha(k) => {
                let counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
                let block = chacha20_block(k, counter, sample[4..16].try_into().unwrap());
                out.copy_from_slice(&block[..5]);
            }
        }
        out
    }
}

/// Packet and header protection for one direction.
#[derive(Clone, Debug)]
pub struct DirectionalKeys {
    pub packet: PacketKey,
    pub header: HeaderProtectionKey,
}

impl DirectionalKeys {
    /// Packet and header protection keys derived from a traffic secret.
    pub fn new(suite: CipherSuite, version: u32, secret: &[u8]) -> DirectionalKeys {
        DirectionalKeys { packet: PacketKey::new(suite, version, secret), header: HeaderProtectionKey::new(suite, version, secret) }
    }
}

/// Keys for sending (`local`) and receiving (`remote`).
#[derive(Clone, Debug)]
pub struct Keys {
    pub local: DirectionalKeys,
    pub remote: DirectionalKeys,
}

impl Keys {
    fn new(suite: CipherSuite, version: u32, is_client: bool, client: &[u8], server: &[u8]) -> Keys {
        let (l, r) = if is_client { (client, server) } else { (server, client) };
        Keys { local: DirectionalKeys::new(suite, version, l), remote: DirectionalKeys::new(suite, version, r) }
    }
}

fn initial_salt(version: u32) -> &'static [u8; 20] {
    if version == VERSION_2 {
        &[0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9]
    } else {
        &[0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]
    }
}

/// The client's and server's Initial secrets for a destination connection ID.
pub fn initial_secrets(version: u32, dcid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let h = HashAlg::Sha256;
    let initial = h.hkdf_extract(initial_salt(version), dcid);
    (expand_label_vec(h, &initial, b"client in", &[], 32), expand_label_vec(h, &initial, b"server in", &[], 32))
}

/// Initial packet protection keys (AES-128-GCM, RFC 9001 section 5.2; RFC 9369 for v2).
pub fn initial_keys(version: u32, dcid: &[u8], is_server: bool) -> Keys {
    let (c, s) = initial_secrets(version, dcid);
    Keys::new(CipherSuite::Aes128GcmSha256, version, !is_server, &c, &s)
}

/// The Retry Integrity Tag (RFC 9001 section 5.8, RFC 9369 section 3.3.3) over
/// `retry_without_tag` (the Retry packet up to the tag) for the original destination CID.
pub fn retry_integrity_tag(version: u32, original_dcid: &[u8], retry_without_tag: &[u8]) -> [u8; 16] {
    let (key, nonce): ([u8; 16], [u8; 12]) = if version == VERSION_2 {
        (
            [0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92],
            [0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a],
        )
    } else {
        (
            [0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e],
            [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb],
        )
    };
    let mut aad = Vec::with_capacity(1 + original_dcid.len() + retry_without_tag.len());
    aad.push(original_dcid.len() as u8);
    aad.extend_from_slice(original_dcid);
    aad.extend_from_slice(retry_without_tag);
    AesGcm::new(&key).seal(&nonce, &aad, &mut [])
}

/// The 1-RTT secrets, for key updates.
pub struct Secrets {
    suite: CipherSuite,
    version: u32,
    is_client: bool,
    client: Vec<u8>,
    server: Vec<u8>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secrets({:?})", self.suite)
    }
}

impl Secrets {
    /// Key-update state from the current 1-RTT traffic secrets.
    pub fn new(suite: CipherSuite, version: u32, is_client: bool, client: Vec<u8>, server: Vec<u8>) -> Secrets {
        Secrets { suite, version, is_client, client, server }
    }

    /// Advances both secrets with the key-update label and returns the next generation of
    /// packet keys as (local, remote). Header protection keys never change.
    pub fn next_packet_keys(&mut self) -> (PacketKey, PacketKey) {
        let h = self.suite.hash();
        let ku = labels(self.version).ku;
        self.client = expand_label_vec(h, &self.client, ku, &[], h.output_len());
        self.server = expand_label_vec(h, &self.server, ku, &[], h.output_len());
        let c = PacketKey::new(self.suite, self.version, &self.client);
        let s = PacketKey::new(self.suite, self.version, &self.server);
        if self.is_client {
            (c, s)
        } else {
            (s, c)
        }
    }
}

/// New keys from the handshake.
pub enum KeyChange {
    /// Handshake packet keys.
    Handshake { keys: Keys },
    /// 1-RTT packet keys and the secrets for later key updates.
    OneRtt { keys: Keys, next: Secrets },
}

impl std::fmt::Debug for KeyChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyChange::Handshake { .. } => "KeyChange::Handshake",
            KeyChange::OneRtt { .. } => "KeyChange::OneRtt",
        })
    }
}

/// A TLS 1.3 handshake for a QUIC connection.
pub struct QuicConnection {
    engine: Engine,
    hs: HsReader,
    write_level: Level,
    version: u32,
    alert: Option<u8>,
    error: Option<Error>,
}

impl std::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnection").field("client", &self.engine.is_client()).field("handshaking", &self.is_handshaking()).finish()
    }
}

impl QuicConnection {
    /// A server; `transport_params` is our encoded transport_parameters extension body.
    pub fn new_server(cfg: Arc<ServerConfig>, transport_params: Vec<u8>) -> QuicConnection {
        QuicConnection::from_engine(Engine::Server(Box::new(ServerHs::new(cfg, Some(transport_params)))))
    }

    /// A client; the ClientHello is ready for the first `write_handshake`. The configuration
    /// must have ALPN protocols.
    #[cfg(feature = "client")]
    pub fn new_client(cfg: Arc<ClientConfig>, server_name: &str, transport_params: Vec<u8>) -> Result<QuicConnection> {
        Ok(QuicConnection::from_engine(Engine::Client(Box::new(ClientHs::new(cfg, server_name, Some(transport_params))?))))
    }

    fn from_engine(engine: Engine) -> QuicConnection {
        QuicConnection { engine, hs: HsReader::new(), write_level: Level::Initial, version: VERSION_1, alert: None, error: None }
    }

    /// Selects the QUIC version whose key labels are used (default [`VERSION_1`]); set it
    /// before the first key change.
    pub fn set_version(&mut self, version: u32) {
        self.version = version;
    }

    /// Feeds CRYPTO frame data received at `level`, in order.
    pub fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<()> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let r = self.read_inner(level, data);
        if let Err(e) = &r {
            self.alert = e.alert();
            self.error = Some(e.clone());
        }
        r
    }

    fn read_inner(&mut self, level: Level, data: &[u8]) -> Result<()> {
        if level != self.engine.shared().expect_level {
            return Err(Error::unexpected("CRYPTO data at this encryption level"));
        }
        self.hs.push(level, data)?;
        let max = self.engine.shared().max_message;
        while let Some((lvl, msg)) = self.hs.next(max)? {
            if msg[0] == crate::tls::hs::KEY_UPDATE {
                return Err(Error::unexpected("KeyUpdate in QUIC"));
            }
            self.engine.handle(lvl, &msg)?;
            if self.engine.shared().expect_level != lvl && !self.hs.is_empty() {
                return Err(Error::unexpected("handshake data across a key change"));
            }
        }
        Ok(())
    }

    /// The level of the bytes the next [`write_handshake`](Self::write_handshake) appends.
    pub fn write_level(&self) -> Level {
        self.write_level
    }

    /// Appends handshake bytes to send at [`write_level`](Self::write_level); returns a key
    /// change when one is due, after which the write level has advanced.
    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        let is_client = self.engine.is_client();
        let version = self.version;
        while let Some(ev) = self.engine.shared_mut().events.pop_front() {
            match ev {
                Event::Msg(_, m) => out.extend_from_slice(&m),
                Event::Ccs => {}
                Event::Secrets { level, client, server } => {
                    let suite = self.engine.shared().suite.expect("suite");
                    let keys = Keys::new(suite, version, is_client, &client, &server);
                    self.write_level = level;
                    return Some(match level {
                        Level::OneRtt => KeyChange::OneRtt { keys, next: Secrets { suite, version, is_client, client, server } },
                        _ => KeyChange::Handshake { keys },
                    });
                }
            }
        }
        None
    }

    pub fn is_handshaking(&self) -> bool {
        !self.engine.shared().done
    }

    /// The peer's transport_parameters extension body.
    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.engine.shared().peer_tp.as_deref()
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.engine.shared().alpn.as_deref()
    }

    pub fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        self.engine.shared().suite
    }

    pub fn server_name(&self) -> Option<&str> {
        self.engine.shared().sni.as_deref()
    }

    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.engine.shared().peer_certs
    }

    pub fn is_resumed(&self) -> bool {
        self.engine.shared().resumed
    }

    /// The QUIC CRYPTO_ERROR code (0x100 + TLS alert) after a handshake failure.
    pub fn tls_alert(&self) -> Option<u64> {
        self.alert.map(|a| 0x100 + a as u64)
    }
}
