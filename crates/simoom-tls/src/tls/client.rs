//! The TLS 1.3 client handshake state machine.

use super::codec::{self, find_ext, handshake_msg, parse_extensions, put_u16, put_vec16, put_vec8, Reader};
use super::config::{ClientConfig, StoredSession};
use super::engine::{certificate_body, parse_certificate, Event, Shared, Transcript};
use super::keyschedule::{finished_mac, message_hash, psk_binder, ticket_psk, Schedule};
use super::{alert, choose_scheme, cv_content, ext, hs, sign_message, sigscheme, verify_message, CipherSuite, Error, KeyShare, Level, NamedGroup, Result};
use crate::crypto::rng;
use crate::keys::PublicKey;
use crate::util::ct_eq;
use crate::x509::{self, Certificate};
use std::sync::Arc;

#[cfg(test)]
thread_local! {
    /// Test hook: offer early_data (without sending any) to exercise the server's skipping.
    pub(crate) static TEST_OFFER_EARLY_DATA: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

enum State {
    ServerHello,
    EncryptedExtensions,
    CertOrRequest,
    Certificate,
    CertificateVerify(PublicKey),
    Finished,
    Done,
}

pub(crate) struct ClientHs {
    cfg: Arc<ClientConfig>,
    pub sh: Shared,
    state: State,
    server_name: String,
    random: [u8; 32],
    session_id: Vec<u8>,
    shares: Vec<KeyShare>,
    transcript: Transcript,
    /// The ClientHello as sent (needed to rebuild it after a HelloRetryRequest).
    offered_psk: Option<StoredSession>,
    sched: Option<Schedule>,
    retried: bool,
    /// Signature schemes from a CertificateRequest, when one arrived.
    cert_request: Option<(Vec<u8>, Vec<u16>)>,
    resumption_master: Option<Vec<u8>>,
}

impl ClientHs {
    pub fn new(cfg: Arc<ClientConfig>, server_name: &str, quic_tp: Option<Vec<u8>>) -> Result<ClientHs> {
        if cfg.groups.is_empty() || cfg.suites.is_empty() {
            return Err(Error::Config("no groups or cipher suites configured".into()));
        }
        if quic_tp.is_some() && cfg.alpn.is_empty() {
            return Err(Error::Config("QUIC requires ALPN".into()));
        }
        let max = cfg.max_handshake_message;
        let is_quic = quic_tp.is_some();
        let now = cfg.time.unix_millis();
        let offered_psk = cfg.sessions.as_ref().and_then(|s| s.take(server_name, now)).filter(|s| cfg.suites.iter().any(|x| x.hash() == s.suite.hash()));
        let mut c = ClientHs {
            sh: Shared::new(quic_tp, max),
            state: State::ServerHello,
            server_name: server_name.trim_end_matches('.').to_ascii_lowercase(),
            random: rng::array(),
            session_id: if is_quic { Vec::new() } else { rng::bytes(32) },
            shares: vec![KeyShare::generate(cfg.groups[0])],
            transcript: Transcript::Buffer(Vec::new()),
            offered_psk,
            sched: None,
            retried: false,
            cert_request: None,
            resumption_master: None,
            cfg,
        };
        let ch = c.client_hello(None);
        c.transcript.add(&ch);
        c.sh.send(Level::Initial, ch);
        Ok(c)
    }

    /// Builds a ClientHello; `cookie` echoes a HelloRetryRequest cookie.
    fn client_hello(&self, cookie: Option<&[u8]>) -> Vec<u8> {
        let cfg = &self.cfg;
        let mut body = Vec::with_capacity(512);
        put_u16(&mut body, 0x0303);
        body.extend_from_slice(&self.random);
        put_vec8(&mut body, &self.session_id);
        let suites: Vec<u16> = cfg.suites.iter().map(|s| s.id()).collect();
        body.extend(codec::u16_list(&suites));
        put_vec8(&mut body, &[0]);
        let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
        if cfg.enable_sni && self.server_name.parse::<std::net::IpAddr>().is_err() && !self.server_name.is_empty() {
            let mut list = vec![0u8];
            put_vec16(&mut list, self.server_name.as_bytes());
            let mut d = Vec::new();
            put_vec16(&mut d, &list);
            exts.push((ext::SERVER_NAME, d));
        }
        exts.push((ext::SUPPORTED_VERSIONS, vec![2, 3, 4]));
        exts.push((ext::SUPPORTED_GROUPS, codec::u16_list(&cfg.groups.iter().map(|g| g.id()).collect::<Vec<_>>())));
        exts.push((ext::SIGNATURE_ALGORITHMS, codec::u16_list(&sigscheme::SUPPORTED)));
        let mut ks = Vec::new();
        for s in &self.shares {
            put_u16(&mut ks, s.group.id());
            put_vec16(&mut ks, &s.public);
        }
        let mut ksd = Vec::new();
        put_vec16(&mut ksd, &ks);
        exts.push((ext::KEY_SHARE, ksd));
        if !cfg.alpn.is_empty() {
            exts.push((ext::ALPN, codec::alpn_list(&cfg.alpn)));
        }
        if let Some(c) = cookie {
            let mut d = Vec::new();
            put_vec16(&mut d, c);
            exts.push((ext::COOKIE, d));
        }
        if let Some(tp) = &self.sh.quic_tp {
            exts.push((ext::QUIC_TRANSPORT_PARAMETERS, tp.clone()));
        }
        #[cfg(test)]
        if TEST_OFFER_EARLY_DATA.with(|f| f.get()) {
            exts.push((ext::EARLY_DATA, Vec::new()));
        }
        if cfg.sessions.is_some() || self.offered_psk.is_some() {
            exts.push((ext::PSK_KEY_EXCHANGE_MODES, vec![1, 1]));
        }
        let now = cfg.time.unix_millis();
        let binder_len = self.offered_psk.as_ref().map(|s| s.suite.hash().output_len());
        if let Some(s) = &self.offered_psk {
            // identity with obfuscated age, then a zeroed binder filled in below
            let age = (now.saturating_sub(s.received_ms) as u32).wrapping_add(s.age_add);
            let mut ids = Vec::new();
            put_vec16(&mut ids, &s.ticket);
            ids.extend_from_slice(&age.to_be_bytes());
            let mut d = Vec::new();
            put_vec16(&mut d, &ids);
            let bl = binder_len.unwrap();
            put_u16(&mut d, (bl + 1) as u16);
            d.push(bl as u8);
            d.extend(std::iter::repeat_n(0, bl));
            exts.push((ext::PRE_SHARED_KEY, d));
        }
        body.extend(codec::extensions(&exts));
        let mut msg = handshake_msg(hs::CLIENT_HELLO, &body);
        if let (Some(s), Some(bl)) = (&self.offered_psk, binder_len) {
            let h = s.suite.hash();
            let cut = msg.len() - (bl + 3);
            let th = match &self.transcript {
                Transcript::Buffer(prefix) => {
                    let mut t = prefix.clone();
                    t.extend_from_slice(&msg[..cut]);
                    h.hash(&t)
                }
                t @ Transcript::Hash(_) => t.hash_with(&msg[..cut]),
            };
            let binder = psk_binder(h, &s.psk, &th);
            let n = msg.len();
            msg[n - bl..].copy_from_slice(&binder);
        }
        msg
    }

    pub fn handle(&mut self, msg: &[u8]) -> Result<()> {
        let typ = msg[0];
        let body = &msg[4..];
        match (&self.state, typ) {
            (State::ServerHello, hs::SERVER_HELLO) => self.server_hello(msg, body),
            (State::EncryptedExtensions, hs::ENCRYPTED_EXTENSIONS) => self.encrypted_extensions(msg, body),
            (State::CertOrRequest, hs::CERTIFICATE_REQUEST) => self.certificate_request(msg, body),
            (State::CertOrRequest | State::Certificate, hs::CERTIFICATE) => self.certificate(msg, body),
            (State::CertificateVerify(_), hs::CERTIFICATE_VERIFY) => self.certificate_verify(msg, body),
            (State::Finished, hs::FINISHED) => self.finished(msg, body),
            (State::Done, hs::NEW_SESSION_TICKET) => self.new_session_ticket(body),
            _ => Err(Error::unexpected(&format!("handshake message {typ}"))),
        }
    }

    fn server_hello(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "ServerHello");
        let version = r.u16()?;
        let random = r.take(32)?;
        let sid = r.vec8()?;
        let suite_id = r.u16()?;
        let compression = r.u8()?;
        let exts = parse_extensions(r.vec16()?)?;
        r.finish()?;
        let selected_version = find_ext(&exts, ext::SUPPORTED_VERSIONS);
        if version != 0x0303 || selected_version != Some(&[3, 4][..]) {
            return Err(Error::proto(alert::PROTOCOL_VERSION, "server did not select TLS 1.3"));
        }
        if sid != self.session_id.as_slice() || compression != 0 {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "bad ServerHello session id or compression"));
        }
        let suite = CipherSuite::from_id(suite_id)
            .filter(|s| self.cfg.suites.contains(s))
            .ok_or_else(|| Error::proto(alert::ILLEGAL_PARAMETER, "server chose a cipher suite we did not offer"))?;
        if let Some(s) = self.sh.suite {
            if s != suite {
                return Err(Error::proto(alert::ILLEGAL_PARAMETER, "cipher suite changed after HelloRetryRequest"));
            }
        }
        let h = suite.hash();
        if random == super::HRR_RANDOM {
            return self.hello_retry(msg, suite, &exts);
        }
        for (t, _) in &exts {
            if ![ext::SUPPORTED_VERSIONS, ext::KEY_SHARE, ext::PRE_SHARED_KEY].contains(t) {
                return Err(Error::proto(alert::UNSUPPORTED_EXTENSION, "unexpected extension in ServerHello"));
            }
        }
        let ks = find_ext(&exts, ext::KEY_SHARE).ok_or_else(|| Error::proto(alert::MISSING_EXTENSION, "missing key_share"))?;
        let mut kr = Reader::new(ks, "key_share");
        let group = kr.u16()?;
        let peer = kr.vec16()?;
        kr.finish()?;
        let share = self.shares.iter().find(|s| s.group.id() == group).ok_or_else(|| Error::proto(alert::ILLEGAL_PARAMETER, "server chose a key share we did not send"))?;
        let shared = share.agree(peer)?;
        let psk = match find_ext(&exts, ext::PRE_SHARED_KEY) {
            Some(d) => {
                if d != [0, 0] || self.offered_psk.is_none() {
                    return Err(Error::proto(alert::ILLEGAL_PARAMETER, "server selected an unknown PSK"));
                }
                let s = self.offered_psk.as_ref().unwrap();
                if s.suite.hash() != h {
                    return Err(Error::proto(alert::ILLEGAL_PARAMETER, "PSK hash does not match the cipher suite"));
                }
                self.sh.resumed = true;
                self.sh.alpn = s.alpn.clone();
                Some(s.psk.clone())
            }
            None => None,
        };
        self.transcript.start(h);
        self.transcript.add(msg);
        let sched = Schedule::new(h, psk.as_deref(), &shared, &self.transcript.hash());
        self.sh.events.push_back(Event::Secrets { level: Level::Handshake, client: sched.client_hs.clone(), server: sched.server_hs.clone() });
        self.sched = Some(sched);
        self.sh.suite = Some(suite);
        self.sh.group = NamedGroup::from_id(group);
        self.sh.expect_level = Level::Handshake;
        self.shares.clear();
        self.state = State::EncryptedExtensions;
        Ok(())
    }

    fn hello_retry(&mut self, msg: &[u8], suite: CipherSuite, exts: &[(u16, &[u8])]) -> Result<()> {
        if self.retried {
            return Err(Error::proto(alert::UNEXPECTED_MESSAGE, "second HelloRetryRequest"));
        }
        self.retried = true;
        let group = match find_ext(exts, ext::KEY_SHARE) {
            Some(d) if d.len() == 2 => u16::from_be_bytes([d[0], d[1]]),
            _ => return Err(Error::proto(alert::ILLEGAL_PARAMETER, "HelloRetryRequest without a group")),
        };
        let group = NamedGroup::from_id(group)
            .filter(|g| self.cfg.groups.contains(g) && !self.shares.iter().any(|s| s.group == *g))
            .ok_or_else(|| Error::proto(alert::ILLEGAL_PARAMETER, "HelloRetryRequest names an unusable group"))?;
        let cookie = match find_ext(exts, ext::COOKIE) {
            Some(d) => {
                let mut r = Reader::new(d, "cookie");
                let c = r.vec16()?.to_vec();
                r.finish()?;
                Some(c)
            }
            None => None,
        };
        let h = suite.hash();
        if self.offered_psk.as_ref().is_some_and(|s| s.suite.hash() != h) {
            self.offered_psk = None;
        }
        let Transcript::Buffer(ch1) = &self.transcript else { unreachable!() };
        let mut t = Transcript::Buffer(Vec::new());
        t.start(h);
        t.add(&message_hash(h, ch1));
        t.add(msg);
        self.transcript = t;
        self.sh.suite = Some(suite);
        self.shares = vec![KeyShare::generate(group)];
        let ch2 = self.client_hello(cookie.as_deref());
        self.transcript.add(&ch2);
        if !self.session_id.is_empty() {
            self.sh.events.push_back(Event::Ccs);
        }
        self.sh.send(Level::Initial, ch2);
        Ok(())
    }

    fn encrypted_extensions(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "EncryptedExtensions");
        let exts = parse_extensions(r.vec16()?)?;
        r.finish()?;
        for (t, _) in &exts {
            if [ext::KEY_SHARE, ext::PRE_SHARED_KEY, ext::SUPPORTED_VERSIONS, ext::SIGNATURE_ALGORITHMS].contains(t) {
                return Err(Error::proto(alert::ILLEGAL_PARAMETER, "forbidden extension in EncryptedExtensions"));
            }
        }
        match find_ext(&exts, ext::ALPN) {
            Some(d) => {
                let list = codec::parse_alpn_list(d)?;
                if list.len() != 1 || !self.cfg.alpn.iter().any(|p| p.as_slice() == list[0]) {
                    return Err(Error::proto(alert::ILLEGAL_PARAMETER, "server selected an ALPN protocol we did not offer"));
                }
                if self.sh.resumed && self.sh.alpn.as_deref().is_some_and(|a| a != list[0]) {
                    return Err(Error::proto(alert::ILLEGAL_PARAMETER, "ALPN changed on resumption"));
                }
                self.sh.alpn = Some(list[0].to_vec());
            }
            None => {
                if self.sh.is_quic() {
                    return Err(Error::proto(alert::NO_APPLICATION_PROTOCOL, "QUIC server did not select ALPN"));
                }
                self.sh.alpn = None;
            }
        }
        if self.sh.is_quic() {
            let tp = find_ext(&exts, ext::QUIC_TRANSPORT_PARAMETERS).ok_or_else(|| Error::proto(alert::MISSING_EXTENSION, "missing QUIC transport parameters"))?;
            self.sh.peer_tp = Some(tp.to_vec());
        }
        if find_ext(&exts, ext::SERVER_NAME).is_some() {
            self.sh.sni = Some(self.server_name.clone());
        }
        self.transcript.add(msg);
        self.state = if self.sh.resumed { State::Finished } else { State::CertOrRequest };
        Ok(())
    }

    fn certificate_request(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "CertificateRequest");
        let ctx = r.vec8()?.to_vec();
        let exts = parse_extensions(r.vec16()?)?;
        r.finish()?;
        let algs = match find_ext(&exts, ext::SIGNATURE_ALGORITHMS) {
            Some(d) => codec::parse_u16_list(d, "signature_algorithms")?,
            None => return Err(Error::proto(alert::MISSING_EXTENSION, "CertificateRequest without signature_algorithms")),
        };
        self.cert_request = Some((ctx, algs));
        self.transcript.add(msg);
        self.state = State::Certificate;
        Ok(())
    }

    fn certificate(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let (ctx, certs) = parse_certificate(body)?;
        if !ctx.is_empty() {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "server certificate with a request context"));
        }
        if certs.is_empty() {
            return Err(Error::proto(alert::DECODE_ERROR, "server sent no certificate"));
        }
        let now = (self.cfg.time.unix_millis() / 1000) as i64;
        let host = if self.server_name.is_empty() { None } else { Some(self.server_name.as_str()) };
        x509::verify_chain(&certs, host, &self.cfg.roots, now, x509::OID_EKU_SERVER_AUTH)?;
        let leaf = Certificate::from_der(&certs[0]).map_err(|e| Error::proto(alert::BAD_CERTIFICATE, e.to_string()))?;
        let key = leaf.public_key.ok_or_else(|| Error::proto(alert::UNSUPPORTED_CERTIFICATE, "unsupported server key"))?;
        self.sh.peer_certs = certs;
        self.transcript.add(msg);
        self.state = State::CertificateVerify(key);
        Ok(())
    }

    fn certificate_verify(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "CertificateVerify");
        let scheme = r.u16()?;
        let sig = r.vec16()?;
        r.finish()?;
        let State::CertificateVerify(key) = &self.state else { unreachable!() };
        verify_message(key, scheme, &cv_content(true, &self.transcript.hash()), sig)?;
        self.transcript.add(msg);
        self.state = State::Finished;
        Ok(())
    }

    fn finished(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let sched = self.sched.take().expect("schedule");
        let h = sched.h;
        let expected = finished_mac(h, &sched.server_hs, &self.transcript.hash());
        if !ct_eq(&expected, body) {
            return Err(Error::proto(alert::DECRYPT_ERROR, "server Finished verification failed"));
        }
        self.transcript.add(msg);
        let th = self.transcript.hash();
        let (c_ap, s_ap) = sched.app_secrets(&th);
        self.sh.exporter_master = Some(sched.exporter_master(&th));
        if let Some((ctx, algs)) = self.cert_request.take() {
            let mut out = Vec::new();
            match &self.cfg.client_cert {
                Some(cert) => match choose_scheme(&cert.key, &algs) {
                    Some(scheme) => {
                        let m = handshake_msg(hs::CERTIFICATE, &certificate_body(&ctx, &cert.chain));
                        self.transcript.add(&m);
                        out.push(m);
                        let sig = sign_message(&cert.key, scheme, &cv_content(false, &self.transcript.hash()))?;
                        let mut b = Vec::new();
                        put_u16(&mut b, scheme);
                        put_vec16(&mut b, &sig);
                        let m = handshake_msg(hs::CERTIFICATE_VERIFY, &b);
                        self.transcript.add(&m);
                        out.push(m);
                    }
                    None => {
                        let m = handshake_msg(hs::CERTIFICATE, &certificate_body(&ctx, &[]));
                        self.transcript.add(&m);
                        out.push(m);
                    }
                },
                None => {
                    let m = handshake_msg(hs::CERTIFICATE, &certificate_body(&ctx, &[]));
                    self.transcript.add(&m);
                    out.push(m);
                }
            }
            for m in out {
                self.sh.send(Level::Handshake, m);
            }
        }
        let fin = handshake_msg(hs::FINISHED, &finished_mac(h, &sched.client_hs, &self.transcript.hash()));
        self.transcript.add(&fin);
        self.sh.send(Level::Handshake, fin);
        self.sh.events.push_back(Event::Secrets { level: Level::OneRtt, client: c_ap, server: s_ap });
        self.resumption_master = Some(sched.resumption_master(&self.transcript.hash()));
        self.sh.expect_level = Level::OneRtt;
        self.sh.done = true;
        self.state = State::Done;
        Ok(())
    }

    fn new_session_ticket(&mut self, body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "NewSessionTicket");
        let lifetime = r.u32()?;
        let age_add = r.u32()?;
        let nonce = r.vec8()?;
        let ticket = r.vec16()?;
        let _exts = parse_extensions(r.vec16()?)?;
        r.finish()?;
        if ticket.is_empty() {
            return Err(Error::decode("NewSessionTicket"));
        }
        if lifetime > 604_800 {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "ticket lifetime above 7 days"));
        }
        if let (Some(cache), Some(rm), Some(suite)) = (self.cfg.sessions.as_ref(), self.resumption_master.as_ref(), self.sh.suite) {
            if lifetime > 0 {
                cache.put(
                    &self.server_name,
                    StoredSession {
                        suite,
                        psk: ticket_psk(suite.hash(), rm, nonce),
                        ticket: ticket.to_vec(),
                        age_add,
                        received_ms: self.cfg.time.unix_millis(),
                        lifetime_secs: lifetime,
                        alpn: self.sh.alpn.clone(),
                    },
                );
            }
        }
        Ok(())
    }
}
