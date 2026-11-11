//! The TLS 1.2 server handshake state machine (feature `tls12`), entered from the TLS 1.3
//! server when the ClientHello does not offer TLS 1.3 (or the configuration caps the version).
//! Ported from Cameleer's blocking `cameleer-tls/src/tls/server.rs` `server12` to the sans-io
//! engine interface.

use super::codec::{self, handshake_msg, parse_u16_list, put_u16, put_vec16, put_vec8, Reader};
use super::config::{ClientAuth, ServerConfig};
use super::engine::{Event, Shared};
use super::record::RecordCipher;
use super::server::{ca_names, ClientHello};
use super::tls12::{
    certificate_body12, choose_scheme12, ciphers, finished, key_auth, master_secret, parse_certificate12, verify12, Exporter12, Session12State,
    Tls12Suite, DOWNGRADE_TLS12, EMPTY_RENEGOTIATION_INFO_SCSV,
};
use super::{alert, ext, hs, sigscheme, Error, KeyShare, Level, NamedGroup, PeerCheck, ProtocolVersion, Result};
use crate::crypto::rng;
use crate::keys::{PrivateKey, PublicKey};
use crate::util::ct_eq;
use std::sync::Arc;

enum State {
    Certificate,
    ClientKeyExchange,
    CertificateVerify(PublicKey),
    Finished,
    Done,
}

pub(crate) struct Server12 {
    cfg: Arc<ServerConfig>,
    state: State,
    /// The raw handshake messages (TLS 1.2 CertificateVerify signs them, not their hash).
    transcript: Vec<u8>,
    suite: Tls12Suite,
    client_random: [u8; 32],
    server_random: [u8; 32],
    share: Option<KeyShare>,
    master: Vec<u8>,
    /// Our write cipher, installed with our ChangeCipherSpec.
    write: Option<RecordCipher>,
    /// The client's write cipher, handed to the connection once the client may send its CCS.
    read: Option<RecordCipher>,
    session_id: Vec<u8>,
    issue_ticket: bool,
    resumed: bool,
    /// The client certificate's key, between Certificate and ClientKeyExchange.
    pending_client_key: Option<PublicKey>,
}

impl Drop for Server12 {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.master);
    }
}

fn select_alpn(cfg: &ServerConfig, ch: &ClientHello) -> Result<Option<Vec<u8>>> {
    let Some(d) = ch.ext(ext::ALPN) else { return Ok(None) };
    let offered = codec::parse_alpn_list(d)?;
    if cfg.alpn.is_empty() {
        return Ok(None);
    }
    match cfg.alpn.iter().find(|p| offered.contains(&p.as_slice())) {
        Some(p) => Ok(Some(p.clone())),
        None => Err(Error::proto(alert::NO_APPLICATION_PROTOCOL, "no common ALPN protocol")),
    }
}

impl Server12 {
    /// Handles the ClientHello (`msg`, header included) and queues the server's first flight.
    pub fn start(cfg: Arc<ServerConfig>, sh: &mut Shared, msg: &[u8], ch: &ClientHello) -> Result<Server12> {
        if !ch.compression.contains(&0) {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, "null compression not offered"));
        }
        if ch.ext(ext::EXTENDED_MASTER_SECRET).is_none() {
            return Err(Error::proto(alert::HANDSHAKE_FAILURE, "the extended master secret (RFC 7627) is required"));
        }
        let reneg = match ch.ext(ext::RENEGOTIATION_INFO) {
            Some(d) if d != [0] => return Err(Error::proto(alert::HANDSHAKE_FAILURE, "bad renegotiation_info")),
            Some(_) => true,
            None => ch.suites.contains(&EMPTY_RENEGOTIATION_INFO_SCSV),
        };
        sh.sni = ch.sni()?;
        sh.alpn = select_alpn(&cfg, ch)?;
        let now = cfg.time.unix_millis();
        let client_random: [u8; 32] = ch.random.try_into().map_err(|_| Error::decode("ClientHello"))?;
        let mut server_random = rng::array::<32>();
        if cfg.max_version >= ProtocolVersion::Tls13 {
            server_random[24..].copy_from_slice(&DOWNGRADE_TLS12);
        }
        let ch_ticket = ch.ext(ext::SESSION_TICKET);

        // resumption: a ticket (RFC 5077) or a cached session ID
        let resumed = {
            let from_ticket = match (ch_ticket, cfg.ticketer.as_ref()) {
                (Some(t), Some(tk)) if !t.is_empty() => tk.open(now, t).and_then(|p| Session12State::decode(&p)),
                _ => None,
            };
            let from_id = || match (&cfg.session_ids, ch.session_id.is_empty()) {
                (Some(c), false) => c.get(ch.session_id).and_then(|p| Session12State::decode(&p)),
                _ => None,
            };
            from_ticket.or_else(from_id).filter(|st| {
                now.saturating_sub(st.created_ms) <= cfg.ticket_lifetime_secs as u64 * 1000
                    && ch.suites.contains(&st.suite.id())
                    && cfg.suites12.contains(&st.suite)
                    && st.sni == sh.sni.as_deref().unwrap_or("").as_bytes()
                    && !(matches!(cfg.client_auth, ClientAuth::Required(_)) && st.peer_certs.is_empty())
            })
        };

        let mut base_exts: Vec<(u16, Vec<u8>)> = Vec::new();
        if reneg {
            base_exts.push((ext::RENEGOTIATION_INFO, vec![0]));
        }
        base_exts.push((ext::EXTENDED_MASTER_SECRET, Vec::new()));
        if let Some(p) = &sh.alpn {
            base_exts.push((ext::ALPN, codec::alpn_list(std::slice::from_ref(p))));
        }

        let mut transcript = msg.to_vec();
        if let Some(st) = resumed {
            // abbreviated handshake: ServerHello, ChangeCipherSpec, Finished
            let suite = st.suite;
            let h = suite.hash();
            let mut body = Vec::with_capacity(128);
            put_u16(&mut body, 0x0303);
            body.extend_from_slice(&server_random);
            put_vec8(&mut body, ch.session_id);
            put_u16(&mut body, suite.id());
            body.push(0);
            body.extend(codec::extensions(&base_exts));
            let sh_msg = handshake_msg(hs::SERVER_HELLO, &body);
            transcript.extend_from_slice(&sh_msg);
            sh.send(Level::Initial, sh_msg);
            let (cw, sw) = ciphers(suite, &st.master, &client_random, &server_random);
            sh.events.push_back(Event::ChangeCipher12(sw));
            let fin = handshake_msg(hs::FINISHED, &finished(h, &st.master, false, &h.hash(&transcript)));
            transcript.extend_from_slice(&fin);
            sh.send(Level::OneRtt, fin);
            sh.pending_read12 = Some(cw);
            sh.tls12 = Some(suite);
            sh.resumed = true;
            sh.peer_certs = st.peer_certs.clone();
            return Ok(Server12 {
                cfg,
                state: State::Finished,
                transcript,
                suite,
                client_random,
                server_random,
                share: None,
                master: st.master.clone(),
                write: None,
                read: None,
                session_id: Vec::new(),
                issue_ticket: false,
                resumed: true,
                pending_client_key: None,
            });
        }

        // full handshake
        let cert = cfg.resolve(sh.sni.as_deref()).ok_or_else(|| Error::proto(alert::UNRECOGNIZED_NAME, "no certificate for the requested server name"))?;
        let kind = key_auth(&cert.key);
        let suite = cfg
            .suites12
            .iter()
            .copied()
            .find(|s| s.auth() == kind && ch.suites.contains(&s.id()))
            .ok_or_else(|| Error::proto(alert::HANDSHAKE_FAILURE, "no common TLS 1.2 cipher suite"))?;
        let sig_algs = match ch.ext(ext::SIGNATURE_ALGORITHMS) {
            Some(d) => parse_u16_list(d, "signature_algorithms")?,
            None => return Err(Error::proto(alert::HANDSHAKE_FAILURE, "client did not send signature_algorithms (SHA-1 only)")),
        };
        let scheme = choose_scheme12(&cert.key, &sig_algs).ok_or_else(|| Error::proto(alert::HANDSHAKE_FAILURE, "no common signature scheme"))?;
        let client_groups = match ch.ext(ext::SUPPORTED_GROUPS) {
            Some(d) => parse_u16_list(d, "supported_groups")?,
            None => vec![NamedGroup::Secp256r1.id()],
        };
        // RFC 8422 section 5.1: an ECDSA certificate's curve must be one the client supports
        let needed: Option<u16> = match &cert.key {
            PrivateKey::Ec { curve: crate::keys::EcCurve::P256, .. } => Some(0x0017),
            #[cfg(feature = "p384")]
            PrivateKey::Ec { curve: crate::keys::EcCurve::P384, .. } => Some(0x0018),
            #[allow(unreachable_patterns)]
            _ => None,
        };
        if needed.is_some_and(|n| !client_groups.contains(&n)) {
            return Err(Error::proto(alert::HANDSHAKE_FAILURE, "client does not support the certificate's curve"));
        }
        let group = cfg
            .groups
            .iter()
            .copied()
            .find(|g| client_groups.contains(&g.id()))
            .ok_or_else(|| Error::proto(alert::HANDSHAKE_FAILURE, "no common key exchange group"))?;
        if let Some(pf) = ch.ext(ext::EC_POINT_FORMATS) {
            let mut r = Reader::new(pf, "ec_point_formats");
            if !r.vec8()?.contains(&0) {
                return Err(Error::proto(alert::ILLEGAL_PARAMETER, "client does not support uncompressed points"));
            }
        }

        let issue_ticket = cfg.ticketer.is_some() && ch_ticket.is_some();
        let session_id = if !issue_ticket && cfg.session_ids.is_some() { rng::bytes(32) } else { Vec::new() };
        let mut exts = base_exts;
        if issue_ticket {
            exts.push((ext::SESSION_TICKET, Vec::new()));
        }
        exts.push((ext::EC_POINT_FORMATS, vec![1, 0]));
        #[cfg(feature = "revocation")]
        let staple = cfg
            .ocsp_staple
            .as_ref()
            .and_then(|s| s.get())
            .filter(|_| ch.ext(ext::STATUS_REQUEST).is_some_and(|d| d.first() == Some(&1)));
        #[cfg(feature = "revocation")]
        if staple.is_some() {
            exts.push((ext::STATUS_REQUEST, Vec::new()));
        }
        let mut body = Vec::with_capacity(128);
        put_u16(&mut body, 0x0303);
        body.extend_from_slice(&server_random);
        put_vec8(&mut body, &session_id);
        put_u16(&mut body, suite.id());
        body.push(0);
        body.extend(codec::extensions(&exts));
        let mut send = |sh: &mut Shared, m: Vec<u8>| {
            transcript.extend_from_slice(&m);
            sh.send(Level::Initial, m);
        };
        send(sh, handshake_msg(hs::SERVER_HELLO, &body));
        send(sh, handshake_msg(hs::CERTIFICATE, &certificate_body12(&cert.chain)));
        #[cfg(feature = "revocation")]
        if let Some(resp) = staple {
            let mut b = vec![1u8];
            codec::put_vec24(&mut b, &resp);
            send(sh, handshake_msg(hs::CERTIFICATE_STATUS, &b));
        }
        let share = KeyShare::generate(group);
        let mut params = vec![3u8];
        put_u16(&mut params, group.id());
        put_vec8(&mut params, &share.public);
        let mut signed = Vec::with_capacity(64 + params.len());
        signed.extend_from_slice(&client_random);
        signed.extend_from_slice(&server_random);
        signed.extend_from_slice(&params);
        let sig = super::tls12::sign12(&cert.key, scheme, &signed)?;
        let mut ske = params;
        put_u16(&mut ske, scheme);
        put_vec16(&mut ske, &sig);
        send(sh, handshake_msg(hs::SERVER_KEY_EXCHANGE, &ske));
        let request_cert = !matches!(cfg.client_auth, ClientAuth::None);
        if request_cert {
            let mut b = Vec::new();
            put_vec8(&mut b, &[1, 64]); // rsa_sign, ecdsa_sign
            b.extend(codec::u16_list(sigscheme::SUPPORTED));
            match ca_names(&cfg.client_auth) {
                Some(names) => b.extend(names),
                None => put_u16(&mut b, 0),
            }
            send(sh, handshake_msg(hs::CERTIFICATE_REQUEST, &b));
        }
        send(sh, handshake_msg(hs::SERVER_HELLO_DONE, &[]));
        sh.tls12 = Some(suite);
        sh.group = Some(group);
        Ok(Server12 {
            cfg,
            state: if request_cert { State::Certificate } else { State::ClientKeyExchange },
            transcript,
            suite,
            client_random,
            server_random,
            share: Some(share),
            master: Vec::new(),
            write: None,
            read: None,
            session_id,
            issue_ticket,
            resumed: false,
            pending_client_key: None,
        })
    }

    pub fn handle(&mut self, sh: &mut Shared, msg: &[u8]) -> Result<()> {
        let typ = msg[0];
        let body = &msg[4..];
        match (&self.state, typ) {
            (State::Certificate, hs::CERTIFICATE) => self.client_certificate(sh, msg, body),
            (State::ClientKeyExchange, hs::CLIENT_KEY_EXCHANGE) => self.client_key_exchange(sh, msg, body),
            (State::CertificateVerify(_), hs::CERTIFICATE_VERIFY) => self.client_cert_verify(sh, msg, body),
            (State::Finished, hs::FINISHED) => self.client_finished(sh, msg, body),
            _ => Err(Error::unexpected(&format!("TLS 1.2 handshake message {typ}"))),
        }
    }

    fn client_certificate(&mut self, sh: &mut Shared, msg: &[u8], body: &[u8]) -> Result<()> {
        let certs = parse_certificate12(body)?;
        self.transcript.extend_from_slice(msg);
        let roots = match &self.cfg.client_auth {
            ClientAuth::Required(r) | ClientAuth::Optional(r) => r,
            ClientAuth::None => return Err(Error::unexpected("Certificate")),
        };
        if certs.is_empty() {
            if matches!(self.cfg.client_auth, ClientAuth::Required(_)) {
                return Err(Error::proto(alert::HANDSHAKE_FAILURE, "client certificate required"));
            }
            self.state = State::ClientKeyExchange;
            return Ok(());
        }
        let check = PeerCheck {
            roots,
            now: (self.cfg.time.unix_millis() / 1000) as i64,
            eku: crate::x509::OID_EKU_CLIENT_AUTH,
            #[cfg(feature = "revocation")]
            revocation: self.cfg.client_revocation.as_ref(),
            #[cfg(feature = "revocation")]
            staple: None,
        };
        let key = check.verify(&certs, None)?;
        sh.peer_certs = certs;
        self.state = State::ClientKeyExchange;
        // the key checks CertificateVerify, which follows ClientKeyExchange
        self.pending_client_key = Some(key);
        Ok(())
    }

    fn client_key_exchange(&mut self, sh: &mut Shared, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "ClientKeyExchange");
        let point = r.vec8()?;
        r.finish()?;
        let share = self.share.take().ok_or_else(|| Error::unexpected("ClientKeyExchange"))?;
        let mut pms = share.agree(point)?;
        self.transcript.extend_from_slice(msg);
        let h = self.suite.hash();
        let session_hash = h.hash(&self.transcript);
        self.master = master_secret(h, &pms, &session_hash);
        crate::util::zeroize(&mut pms);
        let (cw, sw) = ciphers(self.suite, &self.master, &self.client_random, &self.server_random);
        self.write = Some(sw);
        match self.pending_client_key.take() {
            Some(key) => {
                self.read = Some(cw);
                self.state = State::CertificateVerify(key);
            }
            None => {
                sh.pending_read12 = Some(cw);
                self.state = State::Finished;
            }
        }
        Ok(())
    }

    fn client_cert_verify(&mut self, sh: &mut Shared, msg: &[u8], body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body, "CertificateVerify");
        let scheme = r.u16()?;
        let sig = r.vec16()?;
        r.finish()?;
        let State::CertificateVerify(key) = &self.state else { unreachable!() };
        verify12(key, scheme, &self.transcript, sig)?;
        self.transcript.extend_from_slice(msg);
        sh.pending_read12 = self.read.take();
        self.state = State::Finished;
        Ok(())
    }

    fn client_finished(&mut self, sh: &mut Shared, msg: &[u8], body: &[u8]) -> Result<()> {
        if sh.pending_read12.is_some() {
            return Err(Error::unexpected("Finished before ChangeCipherSpec"));
        }
        let h = self.suite.hash();
        let expected = finished(h, &self.master, true, &h.hash(&self.transcript));
        if !ct_eq(&expected, body) {
            return Err(Error::proto(alert::DECRYPT_ERROR, "client Finished verification failed"));
        }
        self.transcript.extend_from_slice(msg);
        if !self.resumed {
            let now = self.cfg.time.unix_millis();
            let st = Session12State {
                suite: self.suite,
                master: self.master.clone(),
                created_ms: now,
                alpn: sh.alpn.clone().unwrap_or_default(),
                sni: sh.sni.clone().unwrap_or_default().into_bytes(),
                peer_certs: sh.peer_certs.clone(),
            };
            if self.issue_ticket {
                if let Some(tk) = &self.cfg.ticketer {
                    let ticket = tk.seal(now, &st.encode());
                    let mut b = Vec::with_capacity(6 + ticket.len());
                    b.extend_from_slice(&self.cfg.ticket_lifetime_secs.to_be_bytes());
                    put_vec16(&mut b, &ticket);
                    let m = handshake_msg(hs::NEW_SESSION_TICKET, &b);
                    self.transcript.extend_from_slice(&m);
                    sh.send(Level::Initial, m);
                }
            } else if let (Some(c), false) = (&self.cfg.session_ids, self.session_id.is_empty()) {
                c.put(&self.session_id, st.encode());
            }
            let sw = self.write.take().ok_or_else(|| Error::proto(alert::INTERNAL_ERROR, "missing write cipher"))?;
            sh.events.push_back(Event::ChangeCipher12(sw));
            let fin = handshake_msg(hs::FINISHED, &finished(h, &self.master, false, &h.hash(&self.transcript)));
            self.transcript.extend_from_slice(&fin);
            sh.send(Level::OneRtt, fin);
        }
        let mut randoms = self.client_random.to_vec();
        randoms.extend_from_slice(&self.server_random);
        sh.exporter12 = Some(Exporter12 { hash: h, master: self.master.clone(), randoms });
        sh.done = true;
        self.state = State::Done;
        self.transcript = Vec::new();
        Ok(())
    }
}
