//! The sans-io handshake engine interface shared by the server and client state machines.
//!
//! An engine consumes complete handshake messages tagged with their encryption level and
//! queues [`Event`]s: messages to send at a level, middlebox-compatibility ChangeCipherSpec
//! records, and traffic secrets as they become known. The record layer (`conn`) and the QUIC
//! interface (`quic`) both drive engines through this interface; neither the engine nor its
//! callers ever touch a socket or a clock.

#[cfg(feature = "client")]
use super::client::ClientHs;
use super::server::ServerHs;
use super::{alert, CipherSuite, Error, Level, NamedGroup, Result};
use crate::crypto::sha2::{HashAlg, Hasher, Output};
use std::collections::VecDeque;

/// Output of the handshake engine, in order.
pub(crate) enum Event {
    /// A handshake message to send at this level.
    Msg(Level, Vec<u8>),
    /// A middlebox-compatibility ChangeCipherSpec record (record layer only).
    Ccs,
    /// Both traffic secrets of a level.
    Secrets { level: Level, client: Vec<u8>, server: Vec<u8> },
    /// TLS 1.2: send ChangeCipherSpec, then protect everything after it with this cipher.
    #[cfg(feature = "tls12")]
    ChangeCipher12(super::record::RecordCipher),
}

/// State visible to the connection: negotiated parameters and the event queue.
pub(crate) struct Shared {
    pub events: VecDeque<Event>,
    /// The level of the next handshake message we expect from the peer.
    pub expect_level: Level,
    pub done: bool,
    pub suite: Option<CipherSuite>,
    pub group: Option<NamedGroup>,
    pub alpn: Option<Vec<u8>>,
    pub sni: Option<String>,
    pub peer_certs: Vec<Vec<u8>>,
    pub resumed: bool,
    /// QUIC: our transport parameters (None for TLS over records).
    pub quic_tp: Option<Vec<u8>>,
    pub peer_tp: Option<Vec<u8>>,
    pub exporter_master: Option<Vec<u8>>,
    pub max_message: usize,
    /// Server: the first ClientHello offered 0-RTT, which is always rejected, so early data
    /// records must be skipped (RFC 8446 section 4.2.10).
    pub early_data_offered: bool,
    /// TLS 1.2 negotiated: the suite.
    #[cfg(feature = "tls12")]
    pub tls12: Option<super::tls12::Tls12Suite>,
    /// TLS 1.2: the read cipher to install when the peer's ChangeCipherSpec arrives.
    #[cfg(feature = "tls12")]
    pub pending_read12: Option<super::record::RecordCipher>,
    /// TLS 1.2: the keying material exporter state.
    #[cfg(feature = "tls12")]
    pub exporter12: Option<super::tls12::Exporter12>,
    /// The OCSP response the server stapled (client side, feature `revocation`).
    #[cfg(feature = "revocation")]
    pub ocsp_response: Option<Vec<u8>>,
}

impl Shared {
    pub fn new(quic_tp: Option<Vec<u8>>, max_message: usize) -> Shared {
        Shared {
            events: VecDeque::new(),
            expect_level: Level::Initial,
            done: false,
            suite: None,
            group: None,
            alpn: None,
            sni: None,
            peer_certs: Vec::new(),
            resumed: false,
            quic_tp,
            peer_tp: None,
            exporter_master: None,
            max_message,
            early_data_offered: false,
            #[cfg(feature = "tls12")]
            tls12: None,
            #[cfg(feature = "tls12")]
            pending_read12: None,
            #[cfg(feature = "tls12")]
            exporter12: None,
            #[cfg(feature = "revocation")]
            ocsp_response: None,
        }
    }
    /// Whether TLS 1.2 was negotiated.
    #[inline]
    pub fn is_tls12(&self) -> bool {
        #[cfg(feature = "tls12")]
        return self.tls12.is_some();
        #[cfg(not(feature = "tls12"))]
        false
    }
    pub fn is_quic(&self) -> bool {
        self.quic_tp.is_some()
    }
    pub fn send(&mut self, level: Level, msg: Vec<u8>) {
        self.events.push_back(Event::Msg(level, msg));
    }
}

#[allow(clippy::large_enum_variant)] // one per connection or key; boxing would add an indirection on the hot path
pub(crate) enum Engine {
    Server(Box<ServerHs>),
    #[cfg(feature = "client")]
    Client(Box<ClientHs>),
}

impl Engine {
    /// Handles one complete handshake message (header included) received at `level`.
    pub fn handle(&mut self, level: Level, msg: &[u8]) -> Result<()> {
        if level != self.shared().expect_level {
            return Err(Error::unexpected("handshake message at this encryption level"));
        }
        match self {
            Engine::Server(s) => s.handle(msg),
            #[cfg(feature = "client")]
            Engine::Client(c) => c.handle(msg),
        }
    }
    pub fn shared(&self) -> &Shared {
        match self {
            Engine::Server(s) => &s.sh,
            #[cfg(feature = "client")]
            Engine::Client(c) => &c.sh,
        }
    }
    pub fn shared_mut(&mut self) -> &mut Shared {
        match self {
            Engine::Server(s) => &mut s.sh,
            #[cfg(feature = "client")]
            Engine::Client(c) => &mut c.sh,
        }
    }
    pub fn is_client(&self) -> bool {
        #[cfg(feature = "client")]
        return matches!(self, Engine::Client(_));
        #[cfg(not(feature = "client"))]
        false
    }
}

/// Reassembles handshake messages from fragments; fragments of one message never span a key
/// change.
pub(crate) struct HsReader {
    buf: Vec<u8>,
    level: Level,
}

impl HsReader {
    pub fn new() -> HsReader {
        HsReader { buf: Vec::new(), level: Level::Initial }
    }

    pub fn push(&mut self, level: Level, data: &[u8]) -> Result<()> {
        if !self.buf.is_empty() && level != self.level {
            return Err(Error::unexpected("key change inside a handshake message"));
        }
        self.level = level;
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// The next complete message, if buffered.
    pub fn next(&mut self, max: usize) -> Result<Option<(Level, Vec<u8>)>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = (self.buf[1] as usize) << 16 | (self.buf[2] as usize) << 8 | self.buf[3] as usize;
        if len > max {
            return Err(Error::proto(alert::DECODE_ERROR, "handshake message too large"));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let rest = self.buf.split_off(4 + len);
        let msg = std::mem::replace(&mut self.buf, rest);
        Ok(Some((self.level, msg)))
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// The handshake transcript: buffered until the hash is known, then hashed incrementally.
#[derive(Clone)]
pub(crate) enum Transcript {
    Buffer(Vec<u8>),
    Hash(Hasher),
}

impl Transcript {
    pub fn add(&mut self, m: &[u8]) {
        match self {
            Transcript::Buffer(b) => b.extend_from_slice(m),
            Transcript::Hash(h) => h.update(m),
        }
    }
    pub fn start(&mut self, alg: HashAlg) {
        if let Transcript::Buffer(b) = self {
            let mut h = Hasher::new(alg);
            h.update(b);
            *self = Transcript::Hash(h);
        }
    }
    pub fn hash(&self) -> Output {
        match self {
            Transcript::Hash(h) => h.current(),
            Transcript::Buffer(_) => unreachable!("transcript hash before the suite is known"),
        }
    }
    /// The hash of the transcript followed by `extra`, without changing the transcript.
    pub fn hash_with(&self, extra: &[u8]) -> Output {
        match self {
            Transcript::Hash(h) => {
                let mut h = h.clone();
                h.update(extra);
                h.finish()
            }
            Transcript::Buffer(_) => unreachable!("transcript hash before the suite is known"),
        }
    }
}

/// Parses a TLS 1.3 Certificate message body: (context, certificate DERs).
pub(crate) fn parse_certificate(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    parse_certificate_status(body).map(|(c, l, _)| (c, l))
}

/// Like [`parse_certificate`], also returning the OCSP response in the leaf's status_request
/// extension (RFC 8446 section 4.4.2.1), if any.
pub(crate) fn parse_certificate_status(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>, Option<Vec<u8>>)> {
    use super::codec::Reader;
    let mut r = Reader::new(body, "Certificate");
    let ctx = r.vec8()?.to_vec();
    let list = r.vec24()?;
    r.finish()?;
    let mut lr = Reader::new(list, "Certificate");
    let mut certs = Vec::new();
    let mut staple = None;
    while !lr.is_empty() {
        let c = lr.vec24()?;
        if c.is_empty() {
            return Err(Error::decode("Certificate"));
        }
        let exts = lr.vec16()?;
        if certs.is_empty() && !exts.is_empty() {
            for (t, d) in super::codec::parse_extensions(exts)? {
                if t == 5 {
                    staple = Some(parse_certificate_status_body(d)?);
                }
            }
        }
        certs.push(c.to_vec());
        if certs.len() > 16 {
            return Err(Error::proto(alert::BAD_CERTIFICATE, "certificate chain too long"));
        }
    }
    Ok((ctx, certs, staple))
}

/// A CertificateStatus body (RFC 6066 section 8): status_type ocsp(1), then the response.
pub(crate) fn parse_certificate_status_body(d: &[u8]) -> Result<Vec<u8>> {
    use super::codec::Reader;
    let mut r = Reader::new(d, "CertificateStatus");
    if r.u8()? != 1 {
        return Err(Error::proto(alert::BAD_CERTIFICATE_STATUS_RESPONSE, "unsupported certificate status type"));
    }
    let resp = r.vec24()?;
    r.finish()?;
    if resp.is_empty() {
        return Err(Error::decode("CertificateStatus"));
    }
    Ok(resp.to_vec())
}

/// Encodes a Certificate message body; `staple` is an OCSP response carried in the leaf's
/// status_request extension (RFC 8446 section 4.4.2.1).
pub(crate) fn certificate_body(ctx: &[u8], chain: &[Vec<u8>], staple: Option<&[u8]>) -> Vec<u8> {
    use super::codec::{put_u16, put_vec24, put_vec8};
    let mut list = Vec::new();
    for (i, c) in chain.iter().enumerate() {
        put_vec24(&mut list, c);
        // only revocation builds staple: the others leave the code out
        #[cfg(not(feature = "revocation"))]
        let _ = (i, staple);
        #[cfg(not(feature = "revocation"))]
        put_u16(&mut list, 0);
        #[cfg(feature = "revocation")]
        match staple.filter(|_| i == 0) {
            Some(resp) => {
                let mut status = vec![1u8];
                put_vec24(&mut status, resp);
                let mut e = Vec::new();
                put_u16(&mut e, 5);
                super::codec::put_vec16(&mut e, &status);
                super::codec::put_vec16(&mut list, &e);
            }
            None => put_u16(&mut list, 0),
        }
    }
    let mut body = Vec::with_capacity(4 + list.len());
    put_vec8(&mut body, ctx);
    put_vec24(&mut body, &list);
    body
}
