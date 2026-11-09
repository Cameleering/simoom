//! The crypto boundary between the transport and TLS (RFC 9001).
//!
//! The transport never touches TLS internals: it hands handshake bytes to a [`CryptoSession`]
//! per encryption level, receives key changes from it, and protects packets with the
//! [`PacketKey`] and [`HeaderKey`] objects it is given. [`CryptoProvider`] supplies the
//! endpoint-wide pieces (Initial keys, the Retry integrity tag, HMAC for tokens, randomness).
//!
//! [`null`] is a deterministic stand-in used by the tests and the benchmark; the real
//! implementation lives on top of `simoom_tls::quic`.

use crate::error::TransportError;

/// Encryption level (RFC 9001 §4). 0-RTT is not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Initial = 0,
    Handshake = 1,
    OneRtt = 2,
}

impl Level {
    pub const ALL: [Level; 3] = [Level::Initial, Level::Handshake, Level::OneRtt];
}

/// AEAD packet protection for one direction.
pub trait PacketKey: Send {
    /// Encrypts `payload` in place and writes the tag (`tag_len()` bytes) to `tag`.
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8], tag: &mut [u8]);
    /// Decrypts `payload_and_tag` in place; returns the plaintext length.
    fn open(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize, ()>;
    fn tag_len(&self) -> usize;
    /// Packets that may be sealed before a key update is required (RFC 9001 §6.6).
    fn confidentiality_limit(&self) -> u64;
    /// Failed decryptions tolerated before the connection must close (RFC 9001 §6.6).
    fn integrity_limit(&self) -> u64;
}

/// Header protection for one direction (RFC 9001 §5.4).
pub trait HeaderKey: Send {
    /// The five-byte mask for a 16-byte `sample`.
    fn mask(&self, sample: &[u8]) -> [u8; 5];
}

/// Packet and header keys for one direction.
pub struct DirectionalKeys {
    pub packet: Box<dyn PacketKey>,
    pub header: Box<dyn HeaderKey>,
}

/// Keys for both directions of one level.
pub struct Keys {
    pub local: DirectionalKeys,
    pub remote: DirectionalKeys,
}

/// Secrets that derive the next 1-RTT packet keys on a key update (RFC 9001 §6).
pub trait NextSecrets: Send {
    /// Returns (local, remote) packet keys for the next key phase and advances.
    fn next_packet_keys(&mut self) -> (Box<dyn PacketKey>, Box<dyn PacketKey>);
}

/// A change of write level reported by [`CryptoSession::write_handshake`].
pub enum KeyChange {
    Handshake { keys: Keys },
    OneRtt { keys: Keys, next: Box<dyn NextSecrets> },
}

/// A TLS alert raised by the handshake; sent as `CRYPTO_ERROR` (0x100 + alert).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoError {
    pub alert: u8,
    pub reason: &'static str,
}

impl From<CryptoError> for TransportError {
    fn from(e: CryptoError) -> Self {
        TransportError::new(crate::error::CRYPTO_ERROR + e.alert as u64, e.reason)
    }
}

/// One side of a TLS 1.3 handshake carried in CRYPTO frames.
pub trait CryptoSession: Send {
    /// Handshake bytes received at `level`, in order.
    fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<(), CryptoError>;
    /// Appends handshake bytes for the current write level. When it returns a key change,
    /// later bytes belong to the next level.
    fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange>;
    /// The peer's encoded transport parameters, once received.
    fn peer_transport_params(&self) -> Option<&[u8]>;
    /// The negotiated ALPN protocol.
    fn alpn_protocol(&self) -> Option<&[u8]>;
    fn is_handshaking(&self) -> bool;
    /// Client: the connection continues in another QUIC version (compatible version
    /// negotiation, RFC 9368) before any Handshake keys exist; later keys use its labels.
    fn set_version(&mut self, _version: u32) {}
}

/// Endpoint-wide crypto services.
pub trait CryptoProvider: Send + Sync {
    /// Initial keys derived from the client's first destination connection ID.
    fn initial_keys(&self, version: u32, dcid: &[u8], is_server: bool) -> Keys;
    /// The Retry integrity tag over the Retry pseudo-packet (RFC 9001 §5.8).
    fn retry_tag(&self, version: u32, pseudo_packet: &[u8]) -> [u8; 16];
    /// HMAC-SHA256 over the concatenation of `parts`.
    fn hmac(&self, key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32];
    /// Cryptographically secure random bytes.
    fn fill_random(&self, buf: &mut [u8]);
    /// Starts a server handshake for QUIC `version` that will send `transport_params`.
    fn server_session(&self, version: u32, transport_params: Vec<u8>) -> Result<Box<dyn CryptoSession>, TransportError>;
    /// Starts a client handshake to `server_name` that will send `transport_params`.
    fn client_session(
        &self,
        version: u32,
        server_name: &str,
        transport_params: Vec<u8>,
    ) -> Result<Box<dyn CryptoSession>, TransportError>;
}

/// Constant-time equality for tokens and tags.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/// A deterministic, NOT secure crypto provider for tests and benchmarks.
///
/// Packets are not encrypted; a 16-byte keyed checksum stands in for the AEAD tag, so
/// corruption, wrong keys and wrong packet numbers are still detected. The handshake is a
/// TLS-shaped exchange (ClientHello, ServerHello, EncryptedExtensions + Finished, Finished)
/// that carries ALPN and transport parameters and changes keys at the same points as TLS 1.3.
pub mod null {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[inline]
    fn mix(mut x: u64) -> u64 {
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94d049bb133111eb);
        x ^ (x >> 31)
    }

    fn hash(seed: u64, parts: &[&[u8]]) -> u64 {
        let mut h = mix(seed ^ 0x9e3779b97f4a7c15);
        for p in parts {
            let mut chunks = p.chunks_exact(8);
            for c in &mut chunks {
                let w = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
                h = (h ^ w).wrapping_mul(0x100000001b3).rotate_left(29);
            }
            for &b in chunks.remainder() {
                h = (h ^ b as u64).wrapping_mul(0x100000001b3);
            }
            h = mix(h ^ p.len() as u64);
        }
        h
    }

    struct NullPacketKey(u64, bool);

    impl PacketKey for NullPacketKey {
        fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8], tag: &mut [u8]) {
            let a = hash(self.0 ^ pn, &[header, payload]);
            tag[..8].copy_from_slice(&a.to_le_bytes());
            tag[8..16].copy_from_slice(&mix(a ^ self.0).to_le_bytes());
        }
        fn open(&self, pn: u64, header: &[u8], payload_and_tag: &mut [u8]) -> Result<usize, ()> {
            if payload_and_tag.len() < 16 {
                return Err(());
            }
            let n = payload_and_tag.len() - 16;
            let mut tag = [0u8; 16];
            self.seal(pn, header, &mut payload_and_tag[..n], &mut tag);
            if self.1 || ct_eq(&tag, &payload_and_tag[n..]) {
                Ok(n)
            } else {
                Err(())
            }
        }
        fn tag_len(&self) -> usize {
            16
        }
        fn confidentiality_limit(&self) -> u64 {
            1 << 23
        }
        fn integrity_limit(&self) -> u64 {
            1 << 36
        }
    }

    struct NullHeaderKey(u64);

    impl HeaderKey for NullHeaderKey {
        fn mask(&self, sample: &[u8]) -> [u8; 5] {
            let h = hash(self.0, &[sample]).to_le_bytes();
            [h[0], h[1], h[2], h[3], h[4]]
        }
    }

    fn dir(seed: u64, lax: bool) -> DirectionalKeys {
        DirectionalKeys { packet: Box::new(NullPacketKey(seed, lax)), header: Box::new(NullHeaderKey(mix(seed))) }
    }

    /// Keys for a level: `c2s`/`s2c` seeds, oriented for the role.
    fn keys(c2s: u64, s2c: u64, is_server: bool, lax: bool) -> Keys {
        if is_server {
            Keys { local: dir(s2c, lax), remote: dir(c2s, lax) }
        } else {
            Keys { local: dir(c2s, lax), remote: dir(s2c, lax) }
        }
    }

    struct NullSecrets {
        local: u64,
        remote: u64,
        lax: bool,
    }

    impl NextSecrets for NullSecrets {
        fn next_packet_keys(&mut self) -> (Box<dyn PacketKey>, Box<dyn PacketKey>) {
            self.local = mix(self.local ^ 0x6b75);
            self.remote = mix(self.remote ^ 0x6b75);
            (Box::new(NullPacketKey(self.local, self.lax)), Box::new(NullPacketKey(self.remote, self.lax)))
        }
    }

    const CLIENT_HELLO: u8 = 1;
    const SERVER_HELLO: u8 = 2;
    const ENCRYPTED_EXTENSIONS: u8 = 8;
    const CERTIFICATE: u8 = 11;
    const FINISHED: u8 = 20;
    /// Alert codes used by the mock.
    pub const ALERT_UNEXPECTED: u8 = 10;
    pub const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

    fn put_msg(out: &mut Vec<u8>, ty: u8, body: &[u8]) {
        out.push(ty);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
    }

    fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
    }

    fn get_blob<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], CryptoError> {
        let bad = CryptoError { alert: 50, reason: "mock: bad message" };
        if b.len() < 2 {
            return Err(bad);
        }
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        if b.len() < 2 + n {
            return Err(bad);
        }
        let v = &b[2..2 + n];
        *b = &b[2 + n..];
        Ok(v)
    }

    #[derive(PartialEq, Clone, Copy, Debug)]
    enum State {
        Start,
        SentHello,
        GotServerHello,
        HandshakeKeysGiven,
        GotServerFinished,
        Done,
        // Server states.
        WaitHello,
        GotHello,
        SentServerHello,
        SentFinished,
    }

    /// Mock TLS session.
    pub struct NullSession {
        is_server: bool,
        state: State,
        tp: Vec<u8>,
        peer_tp: Option<Vec<u8>>,
        alpn_offer: Vec<Vec<u8>>,
        alpn: Option<Vec<u8>>,
        buf: [Vec<u8>; 3],
        seed: u64,
        hello_padding: usize,
        lax: bool,
    }

    impl NullSession {
        fn take_msg(&mut self, level: Level) -> Option<(u8, Vec<u8>)> {
            let b = &mut self.buf[level as usize];
            if b.len() < 4 {
                return None;
            }
            let n = u32::from_be_bytes([0, b[1], b[2], b[3]]) as usize;
            if b.len() < 4 + n {
                return None;
            }
            let ty = b[0];
            let body = b[4..4 + n].to_vec();
            b.drain(..4 + n);
            Some((ty, body))
        }
    }

    impl CryptoSession for NullSession {
        fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<(), CryptoError> {
            let unexpected = CryptoError { alert: ALERT_UNEXPECTED, reason: "mock: unexpected message" };
            if level == Level::OneRtt {
                return Err(unexpected);
            }
            self.buf[level as usize].extend_from_slice(data);
            if self.buf[level as usize].len() > 1 << 20 {
                return Err(unexpected);
            }
            while let Some((ty, body)) = self.take_msg(level) {
                match (self.is_server, self.state, level, ty) {
                    (true, State::WaitHello, Level::Initial, CLIENT_HELLO) => {
                        let mut b = &body[..];
                        let alpns = get_blob(&mut b)?;
                        let tp = get_blob(&mut b)?;
                        self.peer_tp = Some(tp.to_vec());
                        let mut a = alpns;
                        while !a.is_empty() {
                            let p = get_blob(&mut a)?;
                            if self.alpn.is_none() && self.alpn_offer.iter().any(|o| o == p) {
                                self.alpn = Some(p.to_vec());
                            }
                        }
                        if self.alpn.is_none() && !self.alpn_offer.is_empty() {
                            return Err(CryptoError {
                                alert: ALERT_NO_APPLICATION_PROTOCOL,
                                reason: "mock: no common ALPN",
                            });
                        }
                        self.seed = hash(0x5eed, &[&body]);
                        self.state = State::GotHello;
                    }
                    (false, State::SentHello, Level::Initial, SERVER_HELLO) => {
                        let mut b = &body[..];
                        let alpn = get_blob(&mut b)?;
                        let seed = get_blob(&mut b)?;
                        if seed.len() != 8 {
                            return Err(unexpected);
                        }
                        self.seed = u64::from_le_bytes(seed.try_into().unwrap());
                        if !alpn.is_empty() {
                            self.alpn = Some(alpn.to_vec());
                        }
                        self.state = State::GotServerHello;
                    }
                    (false, State::HandshakeKeysGiven, Level::Handshake, CERTIFICATE) => {}
                    (false, State::HandshakeKeysGiven, Level::Handshake, ENCRYPTED_EXTENSIONS) => {
                        self.peer_tp = Some(body);
                    }
                    (false, State::HandshakeKeysGiven, Level::Handshake, FINISHED) if self.peer_tp.is_some() => {
                        self.state = State::GotServerFinished;
                    }
                    (true, State::SentFinished, Level::Handshake, FINISHED) => {
                        self.state = State::Done;
                    }
                    _ => return Err(unexpected),
                }
            }
            Ok(())
        }

        fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
            let s = self.seed;
            let lax = self.lax;
            let hs = || keys(mix(s ^ 1), mix(s ^ 2), self.is_server, lax);
            let one = || keys(mix(s ^ 3), mix(s ^ 4), self.is_server, lax);
            let secrets = || {
                let (c, sv) = (mix(s ^ 3), mix(s ^ 4));
                let (local, remote) = if self.is_server { (sv, c) } else { (c, sv) };
                Box::new(NullSecrets { local, remote, lax }) as Box<dyn NextSecrets>
            };
            match self.state {
                State::Start => {
                    let mut body = Vec::new();
                    let mut alpns = Vec::new();
                    for a in &self.alpn_offer {
                        put_blob(&mut alpns, a);
                    }
                    put_blob(&mut body, &alpns);
                    put_blob(&mut body, &self.tp);
                    body.resize(body.len() + self.hello_padding, 0);
                    put_msg(out, CLIENT_HELLO, &body);
                    self.state = State::SentHello;
                    None
                }
                State::GotServerHello => {
                    self.state = State::HandshakeKeysGiven;
                    Some(KeyChange::Handshake { keys: hs() })
                }
                State::GotServerFinished => {
                    put_msg(out, FINISHED, &[]);
                    self.state = State::Done;
                    Some(KeyChange::OneRtt { keys: one(), next: secrets() })
                }
                State::GotHello => {
                    let mut body = Vec::new();
                    put_blob(&mut body, self.alpn.as_deref().unwrap_or(&[]));
                    put_blob(&mut body, &s.to_le_bytes());
                    put_msg(out, SERVER_HELLO, &body);
                    self.state = State::SentServerHello;
                    Some(KeyChange::Handshake { keys: hs() })
                }
                State::SentServerHello => {
                    put_msg(out, ENCRYPTED_EXTENSIONS, &self.tp);
                    if self.hello_padding > 0 {
                        put_msg(out, CERTIFICATE, &vec![0x55; self.hello_padding]);
                    }
                    put_msg(out, FINISHED, &[]);
                    self.state = State::SentFinished;
                    Some(KeyChange::OneRtt { keys: one(), next: secrets() })
                }
                _ => None,
            }
        }

        fn peer_transport_params(&self) -> Option<&[u8]> {
            self.peer_tp.as_deref()
        }
        fn alpn_protocol(&self) -> Option<&[u8]> {
            self.alpn.as_deref()
        }
        fn is_handshaking(&self) -> bool {
            self.state != State::Done
        }
    }

    /// The null provider. `alpn` lists the protocols offered (client) or accepted (server).
    pub struct NullProvider {
        rng: AtomicU64,
        pub alpn: Vec<Vec<u8>>,
        /// Extra bytes in the ClientHello, to exercise multi-packet CRYPTO data.
        pub hello_padding: usize,
        /// Size of a mock Certificate message in the server's flight.
        pub server_flight: usize,
        /// Accept any packet tag, so mutated packets reach frame processing (fuzzing).
        pub accept_any_tag: bool,
    }

    impl NullProvider {
        pub fn new(seed: u64) -> Self {
            NullProvider { rng: AtomicU64::new(seed | 1), alpn: vec![b"h3".to_vec()], hello_padding: 0, server_flight: 0, accept_any_tag: false }
        }
    }

    impl CryptoProvider for NullProvider {
        fn initial_keys(&self, version: u32, dcid: &[u8], is_server: bool) -> Keys {
            let s = hash(version as u64, &[dcid]);
            keys(mix(s ^ 0xc), mix(s ^ 0x5), is_server, self.accept_any_tag)
        }
        fn retry_tag(&self, version: u32, pseudo_packet: &[u8]) -> [u8; 16] {
            let a = hash(0x7e7 ^ version as u64, &[pseudo_packet]);
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&a.to_le_bytes());
            t[8..].copy_from_slice(&mix(a).to_le_bytes());
            t
        }
        fn hmac(&self, key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
            let k = hash(0, &[key]);
            let mut out = [0u8; 32];
            let mut h = hash(k, parts);
            for c in out.chunks_mut(8) {
                c.copy_from_slice(&h.to_le_bytes());
                h = mix(h ^ k);
            }
            out
        }
        fn fill_random(&self, buf: &mut [u8]) {
            for c in buf.chunks_mut(8) {
                let v = mix(self.rng.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed));
                c.copy_from_slice(&v.to_le_bytes()[..c.len()]);
            }
        }
        fn server_session(&self, _version: u32, tp: Vec<u8>) -> Result<Box<dyn CryptoSession>, TransportError> {
            Ok(Box::new(NullSession {
                is_server: true,
                state: State::WaitHello,
                tp,
                peer_tp: None,
                alpn_offer: self.alpn.clone(),
                alpn: None,
                buf: Default::default(),
                seed: 0,
                hello_padding: self.server_flight,
                lax: self.accept_any_tag,
            }))
        }
        fn client_session(&self, _version: u32, _name: &str, tp: Vec<u8>) -> Result<Box<dyn CryptoSession>, TransportError> {
            Ok(Box::new(NullSession {
                is_server: false,
                state: State::Start,
                tp,
                peer_tp: None,
                alpn_offer: self.alpn.clone(),
                alpn: None,
                buf: Default::default(),
                seed: 0,
                hello_padding: self.hello_padding,
                lax: self.accept_any_tag,
            }))
        }
    }
}
