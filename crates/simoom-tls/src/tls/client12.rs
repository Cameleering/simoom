//! The TLS 1.2 client handshake state machine (feature `tls12`), entered from the TLS 1.3
//! client when the server answers with a TLS 1.2 ServerHello. Ported from Cameleer's blocking
//! `cameleer-tls/src/tls/client.rs` `client12` to the sans-io engine interface.

use super::codec::{self, find_ext, handshake_msg, put_u16, put_vec16, put_vec8, Reader};
use super::config::ClientConfig;
use super::engine::{Event, Shared};
use super::record::RecordCipher;
use super::tls12::{
    certificate_body12, choose_scheme12, ciphers, finished, master_secret, parse_certificate12, public_key_auth, sign12, verify12,
    ClientSession12, Exporter12, Tls12Suite,
};
use super::{alert, ext, hs, Error, KeyShare, Level, NamedGroup, PeerCheck, Result};
#[cfg(feature = "rsa")]
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::util::ct_eq;
use std::sync::Arc;

enum State {
    Certificate,
    /// After the Certificate: CertificateStatus (when acknowledged) or ServerKeyExchange.
    StatusOrKeyExchange(Vec<Vec<u8>>),
    KeyExchange(Vec<Vec<u8>>),
    RequestOrDone(PublicKey, NamedGroup, Vec<u8>),
    Done(PublicKey, NamedGroup, Vec<u8>, Option<(Vec<u8>, Vec<u16>)>),
    Ticket,
    Finished,
    Established,
}

pub(crate) struct Client12 {
    cfg: Arc<ClientConfig>,
    state: State,
    server_name: String,
    transcript: Vec<u8>,
    suite: Tls12Suite,
    client_random: [u8; 32],
    server_random: [u8; 32],
    master: Vec<u8>,
    /// Abbreviated handshake: our write cipher, sent after the server's Finished.
    write: Option<RecordCipher>,
    /// The server's write cipher, handed to the connection once its CCS may arrive.
    read: Option<RecordCipher>,
    session_id: Vec<u8>,
    ticket_expected: bool,
    status_expected: bool,
    staple: Option<Vec<u8>>,
    new_ticket: Option<(u32, Vec<u8>)>,
    resumed: Option<ClientSession12>,
}

impl Drop for Client12 {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.master);
    }
}

/// What the TLS 1.3 client hands over with a TLS 1.2 ServerHello.
pub(crate) struct Hello12<'a> {
    pub cfg: Arc<ClientConfig>,
    pub server_name: &'a str,
    pub client_random: [u8; 32],
    pub offered_session_id: &'a [u8],
    pub session: Option<ClientSession12>,
    pub client_hello: &'a [u8],
    pub requested_status: bool,
}

impl Client12 {
    pub fn start(sh: &mut Shared, hello: Hello12, msg: &[u8]) -> Result<Client12> {
        let illegal = |m: &'static str| Error::proto(alert::ILLEGAL_PARAMETER, m);
        let cfg = hello.cfg;
        let mut r = Reader::new(&msg[4..], "ServerHello");
        let _version = r.u16()?;
        let server_random: [u8; 32] = r.take(32)?.try_into().unwrap();
        let sid = r.vec8()?.to_vec();
        let suite_id = r.u16()?;
        let compression = r.u8()?;
        let exts = if r.is_empty() { Vec::new() } else { codec::parse_extensions(r.vec16()?)? };
        r.finish()?;
        let suite = Tls12Suite::from_id(suite_id).filter(|s| cfg.suites12.contains(s)).ok_or_else(|| illegal("server chose a cipher suite we did not offer"))?;
        if compression != 0 {
            return Err(illegal("compression is not supported"));
        }
        for (t, _) in &exts {
            if [ext::KEY_SHARE, ext::PRE_SHARED_KEY, ext::SUPPORTED_VERSIONS, ext::EARLY_DATA, ext::COOKIE].contains(t) {
                return Err(Error::proto(alert::UNSUPPORTED_EXTENSION, "TLS 1.3 extension in a TLS 1.2 ServerHello"));
            }
        }
        if find_ext(&exts, ext::EXTENDED_MASTER_SECRET).is_none() {
            return Err(Error::proto(alert::HANDSHAKE_FAILURE, "the server does not support the extended master secret (RFC 7627)"));
        }
        if let Some(ri) = find_ext(&exts, ext::RENEGOTIATION_INFO) {
            if ri != [0] {
                return Err(Error::proto(alert::HANDSHAKE_FAILURE, "bad renegotiation_info"));
            }
        }
        let ticket_expected = match find_ext(&exts, ext::SESSION_TICKET) {
            Some([]) if cfg.sessions.is_some() => true,
            Some(_) => return Err(Error::proto(alert::UNSUPPORTED_EXTENSION, "unexpected session_ticket extension")),
            None => false,
        };
        let status_expected = match find_ext(&exts, ext::STATUS_REQUEST) {
            Some([]) if hello.requested_status => true,
            Some(_) => return Err(Error::proto(alert::UNSUPPORTED_EXTENSION, "unexpected status_request extension")),
            None => false,
        };
        sh.alpn = match find_ext(&exts, ext::ALPN) {
            Some(d) => {
                let list = codec::parse_alpn_list(d)?;
                if list.len() != 1 || !cfg.alpn.iter().any(|p| p.as_slice() == list[0]) {
                    return Err(illegal("server selected an ALPN protocol we did not offer"));
                }
                Some(list[0].to_vec())
            }
            None => None,
        };
        if find_ext(&exts, ext::SERVER_NAME).is_some() {
            sh.sni = Some(hello.server_name.to_string());
        }
        sh.tls12 = Some(suite);
        let mut transcript = hello.client_hello.to_vec();
        transcript.extend_from_slice(msg);
        let mut c = Client12 {
            cfg,
            state: State::Certificate,
            server_name: hello.server_name.to_string(),
            transcript,
            suite,
            client_random: hello.client_random,
            server_random,
            master: Vec::new(),
            write: None,
            read: None,
            session_id: sid.clone(),
            ticket_expected,
            status_expected,
            staple: None,
            new_ticket: None,
            resumed: None,
        };
        // abbreviated handshake: the server echoed the session ID we offered for a cached session
        if let Some(s) = hello.session.filter(|_| !sid.is_empty() && sid == hello.offered_session_id) {
            if s.suite != suite {
                return Err(illegal("resumed session with a different cipher suite"));
            }
            if s.alpn.is_some() && sh.alpn.is_some() && s.alpn != sh.alpn {
                return Err(illegal("ALPN changed on resumption"));
            }
            let (cw, sw) = ciphers(suite, &s.master, &c.client_random, &c.server_random);
            c.master = s.master.clone();
            c.write = Some(cw);
            sh.resumed = true;
            sh.peer_certs = s.peer_certs.clone();
            if ticket_expected {
                c.read = Some(sw);
                c.state = State::Ticket;
            } else {
                sh.pending_read12 = Some(sw);
                c.state = State::Finished;
            }
            c.resumed = Some(s);
        }
        Ok(c)
    }

    pub fn handle(&mut self, sh: &mut Shared, msg: &[u8]) -> Result<()> {
        let typ = msg[0];
        let body = &msg[4..];
        let state = std::mem::replace(&mut self.state, State::Established);
        match (state, typ) {
            (State::Certificate, hs::CERTIFICATE) => {
                let certs = parse_certificate12(body)?;
                if certs.is_empty() {
                    return Err(Error::proto(alert::DECODE_ERROR, "server sent no certificate"));
                }
                self.transcript.extend_from_slice(msg);
                self.state = if self.status_expected { State::StatusOrKeyExchange(certs) } else { State::KeyExchange(certs) };
                Ok(())
            }
            (State::StatusOrKeyExchange(certs), hs::CERTIFICATE_STATUS) => {
                self.staple = Some(super::engine::parse_certificate_status_body(body)?);
                self.transcript.extend_from_slice(msg);
                self.state = State::KeyExchange(certs);
                Ok(())
            }
            (State::StatusOrKeyExchange(certs) | State::KeyExchange(certs), hs::SERVER_KEY_EXCHANGE) => self.server_key_exchange(sh, msg, body, certs),
            (State::RequestOrDone(key, group, point), hs::CERTIFICATE_REQUEST) => {
                let mut r = Reader::new(body, "CertificateRequest");
                let types = r.vec8()?.to_vec();
                let algs_raw = r.vec16()?;
                let _cas = r.vec16()?;
                r.finish()?;
                if algs_raw.is_empty() || algs_raw.len() % 2 != 0 {
                    return Err(Error::decode("CertificateRequest"));
                }
                let algs = algs_raw.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                self.transcript.extend_from_slice(msg);
                self.state = State::Done(key, group, point, Some((types, algs)));
                Ok(())
            }
            (State::RequestOrDone(key, group, point), hs::SERVER_HELLO_DONE) => self.server_hello_done(sh, msg, body, key, group, point, None),
            (State::Done(key, group, point, req), hs::SERVER_HELLO_DONE) => self.server_hello_done(sh, msg, body, key, group, point, req),
            (State::Ticket, hs::NEW_SESSION_TICKET) => {
                let mut r = Reader::new(body, "NewSessionTicket");
                let hint = r.u32()?;
                let ticket = r.vec16()?.to_vec();
                r.finish()?;
                self.transcript.extend_from_slice(msg);
                if !ticket.is_empty() {
                    let lifetime = if hint == 0 { self.cfg_default_lifetime() } else { hint.min(604_800) };
                    self.new_ticket = Some((lifetime, ticket));
                }
                sh.pending_read12 = self.read.take();
                self.state = State::Finished;
                Ok(())
            }
            (State::Finished, hs::FINISHED) => self.server_finished(sh, msg, body),
            _ => Err(Error::unexpected(&format!("TLS 1.2 handshake message {typ}"))),
        }
    }

    fn cfg_default_lifetime(&self) -> u32 {
        // RFC 5077: a zero hint leaves the lifetime to the client
        86_400
    }

    fn server_key_exchange(&mut self, _sh: &mut Shared, msg: &[u8], body: &[u8], certs: Vec<Vec<u8>>) -> Result<()> {
        let now = (self.cfg.time.unix_millis() / 1000) as i64;
        let host = if self.server_name.is_empty() { None } else { Some(self.server_name.as_str()) };
        let check = PeerCheck {
            roots: &self.cfg.roots,
            now,
            eku: crate::x509::OID_EKU_SERVER_AUTH,
            #[cfg(feature = "revocation")]
            revocation: self.cfg.revocation.as_ref(),
            #[cfg(feature = "revocation")]
            staple: self.staple.as_deref(),
        };
        let key = check.verify(&certs, host)?;
        if public_key_auth(&key) != self.suite.auth() {
            return Err(Error::proto(alert::UNSUPPORTED_CERTIFICATE, "certificate key does not match the cipher suite"));
        }
        _sh.peer_certs = certs;
        #[cfg(feature = "revocation")]
        {
            _sh.ocsp_response = self.staple.take();
        }
        let mut r = Reader::new(body, "ServerKeyExchange");
        if r.u8()? != 3 {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "only named curves are supported"));
        }
        let gid = r.u16()?;
        let point = r.vec8()?.to_vec();
        let params_len = 4 + point.len();
        let scheme = r.u16()?;
        let sig = r.vec16()?;
        r.finish()?;
        let group = NamedGroup::from_id(gid)
            .filter(|g| self.cfg.groups.contains(g))
            .ok_or_else(|| Error::proto(alert::ILLEGAL_PARAMETER, "server chose a group we did not offer"))?;
        let mut signed = Vec::with_capacity(64 + params_len);
        signed.extend_from_slice(&self.client_random);
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&body[..params_len]);
        verify12(&key, scheme, &signed, sig)?;
        self.transcript.extend_from_slice(msg);
        self.state = State::RequestOrDone(key, group, point);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn server_hello_done(
        &mut self,
        sh: &mut Shared,
        msg: &[u8],
        body: &[u8],
        _server_key: PublicKey,
        group: NamedGroup,
        point: Vec<u8>,
        request: Option<(Vec<u8>, Vec<u16>)>,
    ) -> Result<()> {
        if !body.is_empty() {
            return Err(Error::decode("ServerHelloDone"));
        }
        self.transcript.extend_from_slice(msg);
        let mut client_cv = None;
        if let Some((types, algs)) = &request {
            let chosen = self.cfg.client_cert.as_ref().and_then(|ck| {
                let t = match &ck.key {
                    #[cfg(feature = "rsa")]
                    PrivateKey::Rsa(_) => 1u8,
                    _ => 64,
                };
                if !types.contains(&t) {
                    return None;
                }
                choose_scheme12(&ck.key, algs).map(|s| (ck, s))
            });
            let chain: &[Vec<u8>] = chosen.map(|(ck, _)| ck.chain.as_slice()).unwrap_or(&[]);
            let m = handshake_msg(hs::CERTIFICATE, &certificate_body12(chain));
            self.transcript.extend_from_slice(&m);
            sh.send(Level::Initial, m);
            client_cv = chosen;
        }
        let share = KeyShare::generate(group);
        let mut pms = share.agree(&point)?;
        sh.group = Some(group);
        let mut cke = Vec::with_capacity(1 + share.public.len());
        put_vec8(&mut cke, &share.public);
        let m = handshake_msg(hs::CLIENT_KEY_EXCHANGE, &cke);
        self.transcript.extend_from_slice(&m);
        sh.send(Level::Initial, m);
        let h = self.suite.hash();
        let session_hash = h.hash(&self.transcript);
        if let Some((ck, scheme)) = client_cv {
            let sig = sign12(&ck.key, scheme, &self.transcript)?;
            let mut b = Vec::with_capacity(4 + sig.len());
            put_u16(&mut b, scheme);
            put_vec16(&mut b, &sig);
            let m = handshake_msg(hs::CERTIFICATE_VERIFY, &b);
            self.transcript.extend_from_slice(&m);
            sh.send(Level::Initial, m);
        }
        self.master = master_secret(h, &pms, &session_hash);
        crate::util::zeroize(&mut pms);
        let (cw, sw) = ciphers(self.suite, &self.master, &self.client_random, &self.server_random);
        sh.events.push_back(Event::ChangeCipher12(cw));
        let fin = handshake_msg(hs::FINISHED, &finished(h, &self.master, true, &h.hash(&self.transcript)));
        self.transcript.extend_from_slice(&fin);
        sh.send(Level::OneRtt, fin);
        if self.ticket_expected {
            self.read = Some(sw);
            self.state = State::Ticket;
        } else {
            sh.pending_read12 = Some(sw);
            self.state = State::Finished;
        }
        Ok(())
    }

    fn server_finished(&mut self, sh: &mut Shared, msg: &[u8], body: &[u8]) -> Result<()> {
        if sh.pending_read12.is_some() {
            return Err(Error::unexpected("Finished before ChangeCipherSpec"));
        }
        let h = self.suite.hash();
        let expected = finished(h, &self.master, false, &h.hash(&self.transcript));
        if !ct_eq(&expected, body) {
            return Err(Error::proto(alert::DECRYPT_ERROR, "server Finished verification failed"));
        }
        self.transcript.extend_from_slice(msg);
        if self.resumed.is_some() {
            let cw = self.write.take().ok_or_else(|| Error::proto(alert::INTERNAL_ERROR, "missing write cipher"))?;
            sh.events.push_back(Event::ChangeCipher12(cw));
            let fin = handshake_msg(hs::FINISHED, &finished(h, &self.master, true, &h.hash(&self.transcript)));
            sh.send(Level::OneRtt, fin);
        }
        if let Some(cache) = &self.cfg.sessions {
            let now = self.cfg.time.unix_millis();
            let mut s = match self.resumed.take() {
                Some(s) => s,
                None => ClientSession12 {
                    suite: self.suite,
                    master: self.master.clone(),
                    ticket: Vec::new(),
                    session_id: self.session_id.clone(),
                    received_ms: now,
                    lifetime_secs: self.cfg_default_lifetime(),
                    alpn: sh.alpn.clone(),
                    peer_certs: sh.peer_certs.clone(),
                },
            };
            if let Some((lifetime, ticket)) = self.new_ticket.take() {
                s.ticket = ticket;
                s.received_ms = now;
                s.lifetime_secs = lifetime;
            }
            if !s.ticket.is_empty() || !s.session_id.is_empty() {
                cache.put12(&self.server_name, s);
            }
        }
        let mut randoms = self.client_random.to_vec();
        randoms.extend_from_slice(&self.server_random);
        sh.exporter12 = Some(Exporter12 { hash: h, master: self.master.clone(), randoms });
        sh.done = true;
        self.state = State::Established;
        self.transcript = Vec::new();
        Ok(())
    }
}

/// The TLS 1.2 extensions of a ClientHello that offers TLS 1.2.
pub(crate) fn hello_extensions12(exts: &mut Vec<(u16, Vec<u8>)>, ticket: Option<&[u8]>) {
    exts.push((ext::EC_POINT_FORMATS, vec![1, 0]));
    exts.push((ext::EXTENDED_MASTER_SECRET, Vec::new()));
    exts.push((ext::RENEGOTIATION_INFO, vec![0]));
    if let Some(t) = ticket {
        exts.push((ext::SESSION_TICKET, t.to_vec()));
    }
}
