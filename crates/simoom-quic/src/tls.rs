//! The production [`CryptoProvider`]: TLS 1.3 from `simoom_tls::quic` (RFC 9001), with
//! AES-GCM or ChaCha20-Poly1305 packet protection, the Retry integrity tag, HMAC-SHA256 for
//! tokens and the TLS crate's DRBG for randomness.

use crate::crypto::{
    CryptoError, CryptoProvider, CryptoSession, DirectionalKeys, HeaderKey, KeyChange, Keys, Level, NextSecrets, PacketKey,
};
use crate::error::TransportError;
use simoom_tls::crypto::{rng, sha2::HashAlg};
use simoom_tls::quic as tq;
use simoom_tls::{ClientConfig, ServerConfig};
use std::sync::Arc;

struct Pk(tq::PacketKey);

impl PacketKey for Pk {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8], tag: &mut [u8]) {
        let t: &mut [u8; 16] = tag.try_into().expect("16-byte tag");
        self.0.seal_in_place(pn, header, payload, t);
    }
    fn open(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize, ()> {
        self.0.open_in_place(pn, header, payload_and_tag).map(|p| p.len()).map_err(|_| ())
    }
    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }
    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }
    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

struct Hk(tq::HeaderProtectionKey);

impl HeaderKey for Hk {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        self.0.mask(sample)
    }
}

struct Ns(tq::Secrets);

impl NextSecrets for Ns {
    fn next_packet_keys(&mut self) -> (Box<dyn PacketKey>, Box<dyn PacketKey>) {
        let (l, r) = self.0.next_packet_keys();
        (Box::new(Pk(l)), Box::new(Pk(r)))
    }
}

fn dir(k: tq::DirectionalKeys) -> DirectionalKeys {
    DirectionalKeys { packet: Box::new(Pk(k.packet)), header: Box::new(Hk(k.header)) }
}

fn keys(k: tq::Keys) -> Keys {
    Keys { local: dir(k.local), remote: dir(k.remote) }
}

fn level(l: Level) -> simoom_tls::Level {
    match l {
        Level::Initial => simoom_tls::Level::Initial,
        Level::Handshake => simoom_tls::Level::Handshake,
        Level::OneRtt => simoom_tls::Level::OneRtt,
    }
}

struct Session(tq::QuicConnection);

impl CryptoSession for Session {
    fn read_handshake(&mut self, l: Level, data: &[u8]) -> Result<(), CryptoError> {
        self.0.read_handshake(level(l), data).map_err(|e| CryptoError {
            alert: e.alert().unwrap_or(simoom_tls::alert::INTERNAL_ERROR),
            reason: "TLS handshake failed",
        })
    }
    fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        Some(match self.0.write_handshake(out)? {
            tq::KeyChange::Handshake { keys: k } => KeyChange::Handshake { keys: keys(k) },
            tq::KeyChange::OneRtt { keys: k, next } => KeyChange::OneRtt { keys: keys(k), next: Box::new(Ns(next)) },
        })
    }
    fn peer_transport_params(&self) -> Option<&[u8]> {
        self.0.peer_transport_params()
    }
    fn alpn_protocol(&self) -> Option<&[u8]> {
        self.0.alpn_protocol()
    }
    fn is_handshaking(&self) -> bool {
        self.0.is_handshaking()
    }
    fn set_version(&mut self, version: u32) {
        self.0.set_version(version);
    }
}

/// TLS-backed crypto for an endpoint. A server needs `server`, a client `client`; the
/// configurations must list ALPN protocols (`h3` for HTTP/3).
pub struct TlsProvider {
    pub server: Option<Arc<ServerConfig>>,
    pub client: Option<Arc<ClientConfig>>,
}

impl TlsProvider {
    pub fn server(cfg: Arc<ServerConfig>) -> Self {
        TlsProvider { server: Some(cfg), client: None }
    }
    pub fn client(cfg: Arc<ClientConfig>) -> Self {
        TlsProvider { server: None, client: Some(cfg) }
    }
}

impl CryptoProvider for TlsProvider {
    fn initial_keys(&self, version: u32, dcid: &[u8], is_server: bool) -> Keys {
        keys(tq::initial_keys(version, dcid, is_server))
    }
    fn retry_tag(&self, version: u32, pseudo: &[u8]) -> [u8; 16] {
        let n = pseudo[0] as usize;
        tq::retry_integrity_tag(version, &pseudo[1..1 + n], &pseudo[1 + n..])
    }
    fn hmac(&self, key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
        let out = HashAlg::Sha256.hmac(key, parts);
        out[..32].try_into().unwrap()
    }
    fn fill_random(&self, buf: &mut [u8]) {
        rng::fill(buf);
    }
    fn server_session(&self, version: u32, tp: Vec<u8>) -> Result<Box<dyn CryptoSession>, TransportError> {
        let cfg = self.server.clone().ok_or(TransportError::new(crate::error::INTERNAL_ERROR, "no TLS server configuration"))?;
        let mut c = tq::QuicConnection::new_server(cfg, tp);
        c.set_version(version);
        Ok(Box::new(Session(c)))
    }
    fn client_session(&self, version: u32, name: &str, tp: Vec<u8>) -> Result<Box<dyn CryptoSession>, TransportError> {
        let cfg = self.client.clone().ok_or(TransportError::new(crate::error::INTERNAL_ERROR, "no TLS client configuration"))?;
        let mut c = tq::QuicConnection::new_client(cfg, name, tp)
            .map_err(|_| TransportError::new(crate::error::INTERNAL_ERROR, "TLS client configuration rejected"))?;
        c.set_version(version);
        Ok(Box::new(Session(c)))
    }
}
