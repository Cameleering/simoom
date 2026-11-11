//! The TLS 1.3 server handshake state machine.

use super::codec::{self, find_ext, handshake_msg, parse_extensions, parse_u16_list, put_u16, put_vec16, put_vec8, Reader};
use super::config::{CertifiedKey, ClientAuth, ServerConfig};
use super::engine::{certificate_body, parse_certificate, Event, Shared, Transcript};
use super::keyschedule::{finished_mac, message_hash, psk_binder, ticket_psk, Schedule};
use super::{alert, choose_scheme, cv_content, ext, hs, sign_message, sigscheme, verify_message, CipherSuite, Error, KeyShare, Level, NamedGroup, Result};
use crate::crypto::rng;
use crate::keys::PublicKey;
use crate::util::ct_eq;
use crate::x509::{self, RootStore};
use std::sync::Arc;

pub(crate) struct ClientHello<'a> {
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub suites: Vec<u16>,
    pub compression: &'a [u8],
    pub exts: Vec<(u16, &'a [u8])>,
}

impl<'a> ClientHello<'a> {
    fn parse(body: &'a [u8]) -> Result<ClientHello<'a>> {
        let mut r = Reader::new(body, "ClientHello");
        let legacy_version = r.u16()?;
        let random = r.take(32)?;
        let session_id = r.vec8()?;
        let suites_raw = r.vec16()?;
        let compression = r.vec8()?;
        let exts = if r.is_empty() { Vec::new() } else { parse_extensions(r.vec16()?)? };
        r.finish()?;
        if session_id.len() > 32 || suites_raw.is_empty() || suites_raw.len() % 2 != 0 || compression.is_empty() {
            return Err(Error::decode("ClientHello"));
        }
        if legacy_version < 0x0303 {
            return Err(Error::proto(alert::PROTOCOL_VERSION, "client does not support TLS 1.3"));
        }
        let suites = suites_raw.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        Ok(ClientHello { random, session_id, suites, compression, exts })
    }

    pub fn ext(&self, t: u16) -> Option<&'a [u8]> {
        find_ext(&self.exts, t)
    }

    fn offers_tls13(&self) -> Result<bool> {
        let Some(d) = self.ext(ext::SUPPORTED_VERSIONS) else { return Ok(false) };
        let mut r = Reader::new(d, "supported_versions");
        let list = r.vec8()?;
        r.finish()?;
        if list.is_empty() || list.len() % 2 != 0 {
            return Err(Error::decode("supported_versions"));
        }
        Ok(list.chunks(2).any(|c| c == [3, 4]))
    }

    pub fn sni(&self) -> Result<Option<String>> {
        let Some(d) = self.ext(ext::SERVER_NAME) else { return Ok(None) };
        let mut r = Reader::new(d, "server_name");
        let list = r.vec16()?;
        r.finish()?;
        let mut lr = Reader::new(list, "server_name");
        let mut out = None;
        while !lr.is_empty() {
            let typ = lr.u8()?;
            let name = lr.vec16()?;
            if typ == 0 && out.is_none() {
                let s = std::str::from_utf8(name).map_err(|_| Error::decode("server_name"))?;
                if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_') {
                    return Err(Error::proto(alert::ILLEGAL_PARAMETER, "invalid server name"));
                }
                out = Some(s.trim_end_matches('.').to_ascii_lowercase());
            }
        }
        Ok(out)
    }

    fn key_shares(&self) -> Result<Vec<(u16, &'a [u8])>> {
        let Some(d) = self.ext(ext::KEY_SHARE) else { return Ok(Vec::new()) };
        let mut r = Reader::new(d, "key_share");
        let list = r.vec16()?;
        r.finish()?;
        let mut lr = Reader::new(list, "key_share");
        let mut out: Vec<(u16, &[u8])> = Vec::new();
        while !lr.is_empty() {
            let g = lr.u16()?;
            let k = lr.vec16()?;
            if k.is_empty() || out.iter().any(|(x, _)| *x == g) {
                return Err(Error::proto(alert::ILLEGAL_PARAMETER, "bad key_share"));
            }
            out.push((g, k));
        }
        Ok(out)
    }

    /// (identities with obfuscated ages, binders, length of the binders block).
    #[allow(clippy::type_complexity)]
    fn psk(&self) -> Result<Option<(Vec<(&'a [u8], u32)>, Vec<&'a [u8]>, usize)>> {
        let Some(d) = self.ext(ext::PRE_SHARED_KEY) else { return Ok(None) };
        if self.exts.last().map(|e| e.0) != Some(ext::PRE_SHARED_KEY) {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "pre_shared_key is not the last extension"));
        }
        let mut r = Reader::new(d, "pre_shared_key");
        let ids = r.vec16()?;
        let binders = r.vec16()?;
        r.finish()?;
        let mut ir = Reader::new(ids, "pre_shared_key");
        let mut identities = Vec::new();
        while !ir.is_empty() {
            let id = ir.vec16()?;
            identities.push((id, ir.u32()?));
        }
        let mut br = Reader::new(binders, "pre_shared_key");
        let mut bl = Vec::new();
        while !br.is_empty() {
            bl.push(br.vec8()?);
        }
        if identities.is_empty() || identities.len() != bl.len() {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "pre_shared_key identities and binders do not match"));
        }
        Ok(Some((identities, bl, 2 + binders.len())))
    }

    fn psk_dhe_allowed(&self) -> bool {
        self.ext(ext::PSK_KEY_EXCHANGE_MODES).is_some_and(|d| d.len() >= 2 && d[0] as usize == d.len() - 1 && d[1..].contains(&1))
    }
}

/// Session state carried in a ticket.
struct TicketState {
    suite: CipherSuite,
    created_ms: u64,
    age_add: u32,
    psk: Vec<u8>,
    alpn: Vec<u8>,
    sni: Vec<u8>,
    peer_certs: Vec<Vec<u8>>,
}

impl TicketState {
    fn encode(&self) -> Vec<u8> {
        let mut o = vec![1u8];
        put_u16(&mut o, self.suite.id());
        o.extend_from_slice(&self.created_ms.to_be_bytes());
        o.extend_from_slice(&self.age_add.to_be_bytes());
        put_vec8(&mut o, &self.psk);
        put_vec8(&mut o, &self.alpn);
        put_vec8(&mut o, &self.sni);
        o.push(self.peer_certs.len() as u8);
        for c in &self.peer_certs {
            codec::put_vec24(&mut o, c);
        }
        o
    }

    fn decode(b: &[u8]) -> Option<TicketState> {
        let mut r = Reader::new(b, "ticket");
        if r.u8().ok()? != 1 {
            return None;
        }
        let suite = CipherSuite::from_id(r.u16().ok()?)?;
        let created_ms = u64::from_be_bytes(r.take(8).ok()?.try_into().ok()?);
        let age_add = r.u32().ok()?;
        let psk = r.vec8().ok()?.to_vec();
        let alpn = r.vec8().ok()?.to_vec();
        let sni = r.vec8().ok()?.to_vec();
        let n = r.u8().ok()?;
        let mut peer_certs = Vec::new();
        for _ in 0..n {
            peer_certs.push(r.vec24().ok()?.to_vec());
        }
        r.finish().ok()?;
        Some(TicketState { suite, created_ms, age_add, psk, alpn, sni, peer_certs })
    }
}

enum State {
    ClientHello,
    Certificate,
    CertificateVerify(PublicKey),
    Finished,
    Done,
}

pub(crate) struct ServerHs {
    cfg: Arc<ServerConfig>,
    pub sh: Shared,
    state: State,
    transcript: Transcript,
    sched: Option<Schedule>,
    suite: Option<CipherSuite>,
    /// After a HelloRetryRequest: the requested group and the first ClientHello's random and
    /// session id.
    hrr: Option<(NamedGroup, [u8; 32], Vec<u8>)>,
    ccs_sent: bool,
    /// The TLS 1.2 state machine, once the ClientHello chose TLS 1.2.
    #[cfg(feature = "tls12")]
    t12: Option<Box<super::server12::Server12>>,
}

impl ServerHs {
    pub fn new(cfg: Arc<ServerConfig>, quic_tp: Option<Vec<u8>>) -> ServerHs {
        let max = cfg.max_handshake_message;
        ServerHs {
            cfg,
            sh: Shared::new(quic_tp, max),
            state: State::ClientHello,
            transcript: Transcript::Buffer(Vec::new()),
            sched: None,
            suite: None,
            hrr: None,
            ccs_sent: false,
            #[cfg(feature = "tls12")]
            t12: None,
        }
    }

    pub fn handle(&mut self, msg: &[u8]) -> Result<()> {
        #[cfg(feature = "tls12")]
        if let Some(t) = self.t12.as_mut() {
            return t.handle(&mut self.sh, msg);
        }
        let typ = msg[0];
        let body = &msg[4..];
        match (&self.state, typ) {
            (State::ClientHello, hs::CLIENT_HELLO) => self.client_hello(msg),
            (State::Certificate, hs::CERTIFICATE) => self.client_certificate(msg, body),
            (State::CertificateVerify(_), hs::CERTIFICATE_VERIFY) => self.client_cert_verify(msg, body),
            (State::Finished, hs::FINISHED) => self.client_finished(msg, body),
            (State::Done, hs::END_OF_EARLY_DATA) | (_, _) => Err(Error::unexpected(&format!("handshake message {typ}"))),
        }
    }

    fn client_hello(&mut self, msg: &[u8]) -> Result<()> {
        let cfg = self.cfg.clone();
        let ch = ClientHello::parse(&msg[4..])?;
        #[cfg(feature = "tls12")]
        {
            use super::ProtocolVersion;
            let max13 = cfg.max_version >= ProtocolVersion::Tls13;
            if (!max13 || !ch.offers_tls13()?) && self.hrr.is_none() && !self.sh.is_quic() && cfg.min_version <= ProtocolVersion::Tls12 {
                // RFC 7507: a client retrying with a lower version than it supports
                if max13 && ch.suites.contains(&super::tls12::FALLBACK_SCSV) {
                    return Err(Error::proto(alert::INAPPROPRIATE_FALLBACK, "TLS_FALLBACK_SCSV while TLS 1.3 is supported"));
                }
                self.sh.early_data_offered = false;
                self.t12 = Some(Box::new(super::server12::Server12::start(cfg, &mut self.sh, msg, &ch)?));
                return Ok(());
            }
            if !max13 {
                return Err(Error::proto(alert::PROTOCOL_VERSION, "TLS 1.3 is disabled and TLS 1.2 is not possible here"));
            }
        }
        if !ch.offers_tls13()? {
            return Err(Error::proto(alert::PROTOCOL_VERSION, "client does not offer TLS 1.3"));
        }
        if ch.compression != [0] {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "TLS 1.3 requires null compression only"));
        }
        if self.sh.is_quic() && !ch.session_id.is_empty() {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "QUIC ClientHello with a legacy session id"));
        }
        if ch.ext(ext::EARLY_DATA).is_some() {
            if self.hrr.is_some() {
                return Err(Error::proto(alert::ILLEGAL_PARAMETER, "early_data after HelloRetryRequest"));
            }
            self.sh.early_data_offered = !self.sh.is_quic();
        }
        let shares = ch.key_shares()?;
        let suite = match (&self.hrr, self.suite) {
            (Some((group, random, sid)), Some(suite)) => {
                if ch.random != random || ch.session_id != sid.as_slice() || !ch.suites.contains(&suite.id()) {
                    return Err(Error::proto(alert::ILLEGAL_PARAMETER, "second ClientHello differs from the first"));
                }
                if shares.len() != 1 || shares[0].0 != group.id() {
                    return Err(Error::proto(alert::ILLEGAL_PARAMETER, "second ClientHello has the wrong key share"));
                }
                suite
            }
            _ => {
                let suite = cfg
                    .suites
                    .iter()
                    .copied()
                    .find(|s| ch.suites.contains(&s.id()))
                    .ok_or_else(|| Error::proto(alert::HANDSHAKE_FAILURE, "no common cipher suite"))?;
                self.suite = Some(suite);
                self.sh.sni = ch.sni()?;
                suite
            }
        };
        let h = suite.hash();
        let groups = match ch.ext(ext::SUPPORTED_GROUPS) {
            Some(d) => parse_u16_list(d, "supported_groups")?,
            None => return Err(Error::proto(alert::MISSING_EXTENSION, "missing supported_groups")),
        };
        let chosen = cfg.groups.iter().copied().find_map(|g| shares.iter().find(|(id, _)| *id == g.id()).map(|(_, k)| (g, *k)));
        let Some((group, peer_key)) = chosen else {
            if self.hrr.is_some() {
                return Err(Error::proto(alert::ILLEGAL_PARAMETER, "no usable key share after HelloRetryRequest"));
            }
            let group = cfg
                .groups
                .iter()
                .copied()
                .find(|g| groups.contains(&g.id()))
                .ok_or_else(|| Error::proto(alert::HANDSHAKE_FAILURE, "no common key exchange group"))?;
            return self.hello_retry(msg, &ch, suite, group);
        };

        if self.hrr.is_none() {
            self.transcript = Transcript::Buffer(Vec::new());
            self.transcript.start(h);
        }
        if self.sh.is_quic() {
            let tp = ch.ext(ext::QUIC_TRANSPORT_PARAMETERS).ok_or_else(|| Error::proto(alert::MISSING_EXTENSION, "missing QUIC transport parameters"))?;
            self.sh.peer_tp = Some(tp.to_vec());
        }
        self.sh.alpn = self.select_alpn(&ch)?;

        // Resumption (psk_dhe_ke only); the binder covers the ClientHello up to the binders.
        let now = cfg.time.unix_millis();
        let mut resumed: Option<(TicketState, u16)> = None;
        if let (Some(ticketer), Some((ids, binders, binders_len))) = (cfg.ticketer.as_ref(), ch.psk()?) {
            if ch.psk_dhe_allowed() {
                for (i, (id, _age)) in ids.iter().enumerate().take(4) {
                    let Some(st) = ticketer.open(now, id).and_then(|p| TicketState::decode(&p)) else { continue };
                    let age = now.saturating_sub(st.created_ms);
                    let sni_ok = st.sni == self.sh.sni.as_deref().unwrap_or("").as_bytes();
                    let auth_ok = !matches!(cfg.client_auth, ClientAuth::Required(_)) || !st.peer_certs.is_empty();
                    if st.suite.hash() != h || age > cfg.ticket_lifetime_secs as u64 * 1000 || !sni_ok || !auth_ok {
                        continue;
                    }
                    let expected = psk_binder(h, &st.psk, &self.transcript.hash_with(&msg[..msg.len() - binders_len]));
                    if !ct_eq(&expected, binders[i]) {
                        return Err(Error::proto(alert::DECRYPT_ERROR, "PSK binder verification failed"));
                    }
                    resumed = Some((st, i as u16));
                    break;
                }
            }
        }
        self.transcript.add(msg);

        let cert = if resumed.is_none() {
            let cert = cfg.resolve(self.sh.sni.as_deref()).ok_or_else(|| Error::proto(alert::UNRECOGNIZED_NAME, "no certificate for the requested server name"))?;
            let sig_algs = match ch.ext(ext::SIGNATURE_ALGORITHMS) {
                Some(d) => parse_u16_list(d, "signature_algorithms")?,
                None => return Err(Error::proto(alert::MISSING_EXTENSION, "missing signature_algorithms")),
            };
            let scheme = choose_scheme(&cert.key, &sig_algs).ok_or_else(|| Error::proto(alert::HANDSHAKE_FAILURE, "no common signature scheme"))?;
            Some((cert, scheme))
        } else {
            None
        };

        let share = KeyShare::generate(group);
        let shared = share.agree(peer_key)?;

        // ServerHello
        let mut body = Vec::with_capacity(128);
        put_u16(&mut body, 0x0303);
        body.extend_from_slice(&rng::array::<32>());
        put_vec8(&mut body, ch.session_id);
        put_u16(&mut body, suite.id());
        body.push(0);
        let mut ks = Vec::with_capacity(4 + share.public.len());
        put_u16(&mut ks, group.id());
        put_vec16(&mut ks, &share.public);
        let mut exts = vec![(ext::SUPPORTED_VERSIONS, vec![3, 4]), (ext::KEY_SHARE, ks)];
        if let Some((_, idx)) = &resumed {
            exts.push((ext::PRE_SHARED_KEY, idx.to_be_bytes().to_vec()));
        }
        body.extend(codec::extensions(&exts));
        let sh_msg = handshake_msg(hs::SERVER_HELLO, &body);
        self.transcript.add(&sh_msg);
        self.sh.send(Level::Initial, sh_msg);
        if !ch.session_id.is_empty() && !self.ccs_sent && !self.sh.is_quic() {
            self.sh.events.push_back(Event::Ccs);
            self.ccs_sent = true;
        }
        let sched = Schedule::new(h, resumed.as_ref().map(|(s, _)| s.psk.as_slice()), &shared, &self.transcript.hash());
        self.sh.events.push_back(Event::Secrets { level: Level::Handshake, client: sched.client_hs.clone(), server: sched.server_hs.clone() });
        self.sh.expect_level = Level::Handshake;
        self.sh.suite = Some(suite);
        self.sh.group = Some(group);

        // EncryptedExtensions
        let mut ee = Vec::new();
        if let Some(p) = &self.sh.alpn {
            ee.push((ext::ALPN, codec::alpn_list(std::slice::from_ref(p))));
        }
        if self.sh.sni.is_some() && resumed.is_none() {
            ee.push((ext::SERVER_NAME, Vec::new()));
        }
        if let Some(tp) = &self.sh.quic_tp {
            ee.push((ext::QUIC_TRANSPORT_PARAMETERS, tp.clone()));
        }
        self.send_hs(handshake_msg(hs::ENCRYPTED_EXTENSIONS, &codec::extensions(&ee)));

        let request_cert = resumed.is_none() && !matches!(cfg.client_auth, ClientAuth::None);
        if let Some((cert, scheme)) = cert {
            if request_cert {
                let mut cr = vec![(ext::SIGNATURE_ALGORITHMS, codec::u16_list(&sigscheme::SUPPORTED))];
                if let Some(names) = ca_names(&cfg.client_auth) {
                    cr.push((ext::CERTIFICATE_AUTHORITIES, names));
                }
                let mut body = vec![0u8];
                body.extend(codec::extensions(&cr));
                self.send_hs(handshake_msg(hs::CERTIFICATE_REQUEST, &body));
            }
            #[cfg(feature = "revocation")]
            let staple = cfg.ocsp_staple.as_ref().and_then(|s| s.get()).filter(|_| ch.ext(ext::STATUS_REQUEST).is_some_and(|d| d.first() == Some(&1)));
            #[cfg(not(feature = "revocation"))]
            let staple: Option<Arc<Vec<u8>>> = None;
            self.send_certificate(&cert, scheme, staple.as_deref().map(|v| v.as_slice()))?;
        }
        let fin = finished_mac(h, &sched.server_hs, &self.transcript.hash());
        self.send_hs(handshake_msg(hs::FINISHED, &fin));
        let th = self.transcript.hash();
        let (c_ap, s_ap) = sched.app_secrets(&th);
        self.sh.exporter_master = Some(sched.exporter_master(&th));
        self.sh.events.push_back(Event::Secrets { level: Level::OneRtt, client: c_ap, server: s_ap });
        if let Some((st, _)) = resumed {
            self.sh.resumed = true;
            self.sh.peer_certs = st.peer_certs;
        }
        self.sched = Some(sched);
        self.state = if request_cert { State::Certificate } else { State::Finished };
        Ok(())
    }

    fn hello_retry(&mut self, msg: &[u8], ch: &ClientHello, suite: CipherSuite, group: NamedGroup) -> Result<()> {
        let h = suite.hash();
        let mut body = Vec::new();
        put_u16(&mut body, 0x0303);
        body.extend_from_slice(&super::HRR_RANDOM);
        put_vec8(&mut body, ch.session_id);
        put_u16(&mut body, suite.id());
        body.push(0);
        body.extend(codec::extensions(&[(ext::SUPPORTED_VERSIONS, vec![3, 4]), (ext::KEY_SHARE, group.id().to_be_bytes().to_vec())]));
        let hrr = handshake_msg(hs::SERVER_HELLO, &body);
        let mut t = Transcript::Buffer(Vec::new());
        t.start(h);
        t.add(&message_hash(h, msg));
        t.add(&hrr);
        self.transcript = t;
        self.sh.send(Level::Initial, hrr);
        if !ch.session_id.is_empty() && !self.sh.is_quic() {
            self.sh.events.push_back(Event::Ccs);
            self.ccs_sent = true;
        }
        self.hrr = Some((group, ch.random.try_into().unwrap(), ch.session_id.to_vec()));
        Ok(())
    }

    fn select_alpn(&self, ch: &ClientHello) -> Result<Option<Vec<u8>>> {
        let offered = match ch.ext(ext::ALPN) {
            Some(d) => codec::parse_alpn_list(d)?,
            None if self.sh.is_quic() => return Err(Error::proto(alert::NO_APPLICATION_PROTOCOL, "QUIC requires ALPN")),
            None => return Ok(None),
        };
        if self.cfg.alpn.is_empty() {
            return if self.sh.is_quic() { Err(Error::proto(alert::NO_APPLICATION_PROTOCOL, "no ALPN configured")) } else { Ok(None) };
        }
        match self.cfg.alpn.iter().find(|p| offered.contains(&p.as_slice())) {
            Some(p) => Ok(Some(p.clone())),
            None => Err(Error::proto(alert::NO_APPLICATION_PROTOCOL, "no common ALPN protocol")),
        }
    }

    fn send_hs(&mut self, m: Vec<u8>) {
        self.transcript.add(&m);
        self.sh.send(Level::Handshake, m);
    }

    fn send_certificate(&mut self, cert: &CertifiedKey, scheme: u16, staple: Option<&[u8]>) -> Result<()> {
        self.send_hs(handshake_msg(hs::CERTIFICATE, &certificate_body(&[], &cert.chain, staple)));
        let sig = sign_message(&cert.key, scheme, &cv_content(true, &self.transcript.hash()))?;
        let mut body = Vec::with_capacity(4 + sig.len());
        put_u16(&mut body, scheme);
        put_vec16(&mut body, &sig);
        self.send_hs(handshake_msg(hs::CERTIFICATE_VERIFY, &body));
        Ok(())
    }

    fn client_certificate(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let (ctx, certs) = parse_certificate(body)?;
        if !ctx.is_empty() {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "bad certificate_request_context"));
        }
        self.transcript.add(msg);
        let roots = match &self.cfg.client_auth {
            ClientAuth::Required(r) | ClientAuth::Optional(r) => r,
            ClientAuth::None => unreachable!(),
        };
        if certs.is_empty() {
            if matches!(self.cfg.client_auth, ClientAuth::Required(_)) {
                return Err(Error::proto(alert::CERTIFICATE_REQUIRED, "client certificate required"));
            }
            self.state = State::Finished;
            return Ok(());
        }
        let check = super::PeerCheck {
            roots,
            now: (self.cfg.time.unix_millis() / 1000) as i64,
            eku: x509::OID_EKU_CLIENT_AUTH,
            #[cfg(feature = "revocation")]
            revocation: self.cfg.client_revocation.as_ref(),
            #[cfg(feature = "revocation")]
            staple: None,
        };
        let key = check.verify(&certs, None)?;
        self.sh.peer_certs = certs;
        self.state = State::CertificateVerify(key);
        Ok(())
    }

    fn client_cert_verify(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "CertificateVerify");
        let scheme = r.u16()?;
        let sig = r.vec16()?;
        r.finish()?;
        let State::CertificateVerify(key) = &self.state else { unreachable!() };
        verify_message(key, scheme, &cv_content(false, &self.transcript.hash()), sig)?;
        self.transcript.add(msg);
        self.state = State::Finished;
        Ok(())
    }

    fn client_finished(&mut self, msg: &[u8], body: &[u8]) -> Result<()> {
        let sched = self.sched.as_ref().expect("schedule");
        let expected = finished_mac(sched.h, &sched.client_hs, &self.transcript.hash());
        if !ct_eq(&expected, body) {
            return Err(Error::proto(alert::DECRYPT_ERROR, "client Finished verification failed"));
        }
        self.transcript.add(msg);
        self.sh.expect_level = Level::OneRtt;
        self.sh.done = true;
        self.state = State::Done;
        if let Some(ticketer) = self.cfg.ticketer.clone() {
            let h = sched.h;
            let res_master = sched.resumption_master(&self.transcript.hash());
            let now = self.cfg.time.unix_millis();
            for n in 0..self.cfg.ticket_count {
                let nonce = [n];
                let age_add = u32::from_be_bytes(rng::array());
                let st = TicketState {
                    suite: self.sh.suite.expect("suite"),
                    created_ms: now,
                    age_add,
                    psk: ticket_psk(h, &res_master, &nonce),
                    alpn: self.sh.alpn.clone().unwrap_or_default(),
                    sni: self.sh.sni.clone().unwrap_or_default().into_bytes(),
                    peer_certs: self.sh.peer_certs.clone(),
                };
                let ticket = ticketer.seal(now, &st.encode());
                let mut b = Vec::with_capacity(16 + ticket.len());
                b.extend_from_slice(&self.cfg.ticket_lifetime_secs.to_be_bytes());
                b.extend_from_slice(&age_add.to_be_bytes());
                put_vec8(&mut b, &nonce);
                put_vec16(&mut b, &ticket);
                put_u16(&mut b, 0);
                self.sh.send(Level::OneRtt, handshake_msg(hs::NEW_SESSION_TICKET, &b));
            }
        }
        self.sched = None;
        Ok(())
    }
}

/// The DistinguishedName list of the client trust anchors (omitted when large).
pub(crate) fn ca_names(auth: &ClientAuth) -> Option<Vec<u8>> {
    let roots: &RootStore = match auth {
        ClientAuth::Optional(r) | ClientAuth::Required(r) => r,
        ClientAuth::None => return None,
    };
    let mut body = Vec::new();
    for c in roots.certificates() {
        put_vec16(&mut body, &c.subject_raw);
    }
    if body.is_empty() || body.len() > 8 * 1024 {
        return None;
    }
    let mut out = Vec::new();
    put_vec16(&mut out, &body);
    Some(out)
}
