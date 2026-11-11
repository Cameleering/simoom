//! TLS 1.2 (RFC 5246) pieces shared by the client and server state machines (feature `tls12`):
//! the cipher suites, the PRF and key derivation, extended master secret (RFC 7627), handshake
//! signatures, session state for tickets (RFC 5077) and session IDs, and the server's session
//! ID cache.
//!
//! What is offered: ECDHE (X25519, P-256 and, when configured, P-384) with AES-128/256-GCM
//! (RFC 5289) and ChaCha20-Poly1305 (RFC 7905), with ECDSA, Ed25519 (RFC 8422) or RSA
//! certificates. No CBC, RC4, static RSA, DHE or export suites: Cameleer's TLS 1.2 offers the
//! same six suites. The extended master secret is required; renegotiation is refused (the
//! `renegotiation_info` extension is answered so peers know the connection is safe, and a
//! HelloRequest or a second ClientHello gets a `no_renegotiation` warning). A server that also
//! speaks TLS 1.3 puts the RFC 8446 downgrade sentinel in its random, and a client that offered
//! TLS 1.3 refuses a TLS 1.2 ServerHello carrying it. `TLS_FALLBACK_SCSV` (RFC 7507) is honoured.

use super::codec::{put_u16, put_vec16, put_vec8, Reader};
use super::record::RecordCipher;
use super::{alert, sigscheme, AeadAlg, Error, Result};
use crate::crypto::sha2::HashAlg;
use crate::keys::{EcCurve, PrivateKey, PublicKey};
use std::collections::VecDeque;
use std::sync::Mutex;

/// The RFC 8446 section 4.1.3 downgrade sentinel for TLS 1.2.
pub(crate) const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";
/// TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746).
pub(crate) const EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
/// TLS_FALLBACK_SCSV (RFC 7507).
pub(crate) const FALLBACK_SCSV: u16 = 0x5600;

/// The certificate type a TLS 1.2 suite authenticates with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth12 {
    /// ECDSA or Ed25519 certificates (`ECDHE_ECDSA` suites).
    Ecdsa,
    /// RSA certificates (`ECDHE_RSA` suites).
    Rsa,
}

/// TLS 1.2 cipher suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls12Suite {
    EcdheEcdsaAes128GcmSha256,
    EcdheEcdsaAes256GcmSha384,
    EcdheRsaAes128GcmSha256,
    EcdheRsaAes256GcmSha384,
    #[cfg(feature = "chacha20")]
    EcdheEcdsaChacha20Poly1305,
    #[cfg(feature = "chacha20")]
    EcdheRsaChacha20Poly1305,
}

impl Tls12Suite {
    /// Every suite, in the default preference (Cameleer's order).
    pub const ALL: &'static [Tls12Suite] = &[
        Tls12Suite::EcdheEcdsaAes128GcmSha256,
        Tls12Suite::EcdheRsaAes128GcmSha256,
        Tls12Suite::EcdheEcdsaAes256GcmSha384,
        Tls12Suite::EcdheRsaAes256GcmSha384,
        #[cfg(feature = "chacha20")]
        Tls12Suite::EcdheEcdsaChacha20Poly1305,
        #[cfg(feature = "chacha20")]
        Tls12Suite::EcdheRsaChacha20Poly1305,
    ];

    pub fn id(self) -> u16 {
        match self {
            Tls12Suite::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            Tls12Suite::EcdheEcdsaAes256GcmSha384 => 0xc02c,
            Tls12Suite::EcdheRsaAes128GcmSha256 => 0xc02f,
            Tls12Suite::EcdheRsaAes256GcmSha384 => 0xc030,
            #[cfg(feature = "chacha20")]
            Tls12Suite::EcdheRsaChacha20Poly1305 => 0xcca8,
            #[cfg(feature = "chacha20")]
            Tls12Suite::EcdheEcdsaChacha20Poly1305 => 0xcca9,
        }
    }

    pub fn from_id(id: u16) -> Option<Tls12Suite> {
        Tls12Suite::ALL.iter().copied().find(|s| s.id() == id)
    }

    /// The IANA name, such as `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    pub fn name(self) -> &'static str {
        match self {
            Tls12Suite::EcdheEcdsaAes128GcmSha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            Tls12Suite::EcdheEcdsaAes256GcmSha384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            Tls12Suite::EcdheRsaAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            Tls12Suite::EcdheRsaAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            #[cfg(feature = "chacha20")]
            Tls12Suite::EcdheEcdsaChacha20Poly1305 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            #[cfg(feature = "chacha20")]
            Tls12Suite::EcdheRsaChacha20Poly1305 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        }
    }

    /// The suite with this IANA name (or its OpenSSL spelling, such as `ECDHE-RSA-AES128-GCM-SHA256`).
    pub fn from_name(name: &str) -> Option<Tls12Suite> {
        let n = name.trim();
        Tls12Suite::ALL.iter().copied().find(|s| s.name().eq_ignore_ascii_case(n) || s.openssl_name().eq_ignore_ascii_case(n))
    }

    /// The OpenSSL name.
    pub fn openssl_name(self) -> &'static str {
        match self {
            Tls12Suite::EcdheEcdsaAes128GcmSha256 => "ECDHE-ECDSA-AES128-GCM-SHA256",
            Tls12Suite::EcdheEcdsaAes256GcmSha384 => "ECDHE-ECDSA-AES256-GCM-SHA384",
            Tls12Suite::EcdheRsaAes128GcmSha256 => "ECDHE-RSA-AES128-GCM-SHA256",
            Tls12Suite::EcdheRsaAes256GcmSha384 => "ECDHE-RSA-AES256-GCM-SHA384",
            #[cfg(feature = "chacha20")]
            Tls12Suite::EcdheEcdsaChacha20Poly1305 => "ECDHE-ECDSA-CHACHA20-POLY1305",
            #[cfg(feature = "chacha20")]
            Tls12Suite::EcdheRsaChacha20Poly1305 => "ECDHE-RSA-CHACHA20-POLY1305",
        }
    }

    pub fn hash(self) -> HashAlg {
        match self {
            Tls12Suite::EcdheEcdsaAes256GcmSha384 | Tls12Suite::EcdheRsaAes256GcmSha384 => HashAlg::Sha384,
            _ => HashAlg::Sha256,
        }
    }

    pub fn aead(self) -> AeadAlg {
        match self {
            Tls12Suite::EcdheEcdsaAes128GcmSha256 | Tls12Suite::EcdheRsaAes128GcmSha256 => AeadAlg::Aes128Gcm,
            Tls12Suite::EcdheEcdsaAes256GcmSha384 | Tls12Suite::EcdheRsaAes256GcmSha384 => AeadAlg::Aes256Gcm,
            #[cfg(feature = "chacha20")]
            _ => AeadAlg::Chacha20Poly1305,
        }
    }

    pub fn auth(self) -> Auth12 {
        match self {
            Tls12Suite::EcdheEcdsaAes128GcmSha256 | Tls12Suite::EcdheEcdsaAes256GcmSha384 => Auth12::Ecdsa,
            #[cfg(feature = "chacha20")]
            Tls12Suite::EcdheEcdsaChacha20Poly1305 => Auth12::Ecdsa,
            _ => Auth12::Rsa,
        }
    }

    /// The default preference: AES-GCM first with hardware AES, ChaCha20-Poly1305 first without.
    pub fn default_order() -> Vec<Tls12Suite> {
        #[cfg(feature = "chacha20")]
        if !(simoom_sys::arch::has_aes() && simoom_sys::arch::has_clmul()) {
            let mut v: Vec<Tls12Suite> = Tls12Suite::ALL.iter().copied().filter(|s| s.aead() == AeadAlg::Chacha20Poly1305).collect();
            v.extend(Tls12Suite::ALL.iter().copied().filter(|s| s.aead() != AeadAlg::Chacha20Poly1305));
            return v;
        }
        Tls12Suite::ALL.to_vec()
    }

    fn iv_len(self) -> usize {
        match self.aead() {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => 4,
            #[cfg(feature = "chacha20")]
            AeadAlg::Chacha20Poly1305 => 12,
        }
    }
}

/// The certificate type a private key authenticates as.
pub(crate) fn key_auth(key: &PrivateKey) -> Auth12 {
    match key {
        #[cfg(feature = "rsa")]
        PrivateKey::Rsa(_) => Auth12::Rsa,
        _ => Auth12::Ecdsa,
    }
}

#[cfg(feature = "client")]
pub(crate) fn public_key_auth(key: &PublicKey) -> Auth12 {
    match key {
        #[cfg(feature = "rsa")]
        PublicKey::Rsa(_) => Auth12::Rsa,
        _ => Auth12::Ecdsa,
    }
}

/// The TLS 1.2 PRF (RFC 5246 section 5): P_hash(secret, label || seed).
pub(crate) fn prf(h: HashAlg, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + h.output_len());
    let mut a = h.hmac(secret, &[label, seed]);
    while out.len() < len {
        out.extend_from_slice(&h.hmac(secret, &[&a, label, seed]));
        a = h.hmac(secret, &[&a]);
    }
    out.truncate(len);
    out
}

/// The extended master secret (RFC 7627 section 4).
pub(crate) fn master_secret(h: HashAlg, pms: &[u8], session_hash: &[u8]) -> Vec<u8> {
    prf(h, pms, b"extended master secret", session_hash, 48)
}

/// (client write, server write) record ciphers from the key block (RFC 5246 section 6.3).
pub(crate) fn ciphers(suite: Tls12Suite, master: &[u8], client_random: &[u8], server_random: &[u8]) -> (RecordCipher, RecordCipher) {
    let kl = suite.aead().key_len();
    let il = suite.iv_len();
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);
    let mut kb = prf(suite.hash(), master, b"key expansion", &seed, 2 * kl + 2 * il);
    let (ck, rest) = kb.split_at(kl);
    let (sk, rest) = rest.split_at(kl);
    let (civ, siv) = rest.split_at(il);
    let out = (RecordCipher::tls12(suite.aead(), ck, civ), RecordCipher::tls12(suite.aead(), sk, siv));
    crate::util::zeroize(&mut kb);
    out
}

/// Finished verify_data (RFC 5246 section 7.4.9).
pub(crate) fn finished(h: HashAlg, master: &[u8], client: bool, transcript_hash: &[u8]) -> Vec<u8> {
    prf(h, master, if client { b"client finished" } else { b"server finished" }, transcript_hash, 12)
}

/// The keying material exporter (RFC 5705).
pub(crate) fn export(h: HashAlg, master: &[u8], randoms: &[u8], label: &[u8], context: Option<&[u8]>, len: usize) -> Vec<u8> {
    let mut seed = randoms.to_vec();
    if let Some(c) = context {
        put_vec16(&mut seed, c);
    }
    prf(h, master, label, &seed, len)
}

/// What the connection needs after a TLS 1.2 handshake.
#[derive(Clone)]
pub(crate) struct Exporter12 {
    pub hash: HashAlg,
    pub master: Vec<u8>,
    /// client_random || server_random.
    pub randoms: Vec<u8>,
}

impl Drop for Exporter12 {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.master);
    }
}

fn scheme_hash12(scheme: u16) -> Option<HashAlg> {
    use sigscheme::*;
    match scheme {
        RSA_PKCS1_SHA256 | ECDSA_SECP256R1_SHA256 | RSA_PSS_RSAE_SHA256 => Some(HashAlg::Sha256),
        RSA_PKCS1_SHA384 | ECDSA_SECP384R1_SHA384 | RSA_PSS_RSAE_SHA384 => Some(HashAlg::Sha384),
        RSA_PKCS1_SHA512 | RSA_PSS_RSAE_SHA512 => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// The signature scheme for `key` among the peer's (TLS 1.2: PKCS#1 v1.5 allowed for RSA,
/// ECDSA hashes not bound to the curve, but the curve's own hash preferred).
pub(crate) fn choose_scheme12(key: &PrivateKey, offered: &[u16]) -> Option<u16> {
    use sigscheme::*;
    let candidates: &[u16] = match key {
        PrivateKey::Ec { curve: EcCurve::P256, .. } => &[ECDSA_SECP256R1_SHA256, ECDSA_SECP384R1_SHA384],
        #[cfg(feature = "p384")]
        PrivateKey::Ec { curve: EcCurve::P384, .. } => &[ECDSA_SECP384R1_SHA384, ECDSA_SECP256R1_SHA256],
        #[cfg(feature = "ed25519")]
        PrivateKey::Ed25519 { .. } => &[ED25519],
        #[cfg(feature = "rsa")]
        PrivateKey::Rsa(_) => &[RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512],
    };
    candidates.iter().copied().find(|c| offered.contains(c))
}

/// Signs `message` for a ServerKeyExchange or CertificateVerify.
pub(crate) fn sign12(key: &PrivateKey, scheme: u16, message: &[u8]) -> Result<Vec<u8>> {
    let fail = || Error::proto(alert::INTERNAL_ERROR, "signing failed");
    #[cfg(feature = "ed25519")]
    if let PrivateKey::Ed25519 { seed, public } = key {
        return Ok(crate::crypto::ed25519::sign_with_public(seed, public, message).to_vec());
    }
    let h = scheme_hash12(scheme).ok_or_else(fail)?;
    let digest = h.hash(message);
    match key {
        PrivateKey::Ec { curve, d, .. } => curve.sign(d, &digest, h).map(|(r, s)| crate::keys::ecdsa_sig_to_der(&r, &s)).ok_or_else(fail),
        #[cfg(feature = "rsa")]
        PrivateKey::Rsa(k) => {
            use sigscheme::*;
            if matches!(scheme, RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PKCS1_SHA512) {
                k.sign_pkcs1(h, &digest).ok_or_else(fail)
            } else {
                k.sign_pss(h, &digest).ok_or_else(fail)
            }
        }
        #[cfg(feature = "ed25519")]
        PrivateKey::Ed25519 { .. } => Err(fail()),
    }
}

/// Verifies a TLS 1.2 handshake signature.
pub(crate) fn verify12(key: &PublicKey, scheme: u16, message: &[u8], sig: &[u8]) -> Result<()> {
    use sigscheme::*;
    let fail = || Error::proto(alert::DECRYPT_ERROR, "handshake signature verification failed");
    let mismatch = || Error::proto(alert::ILLEGAL_PARAMETER, "signature scheme does not match the key");
    if !SUPPORTED.contains(&scheme) {
        return Err(Error::proto(alert::ILLEGAL_PARAMETER, format!("unsupported signature scheme {scheme:#06x}")));
    }
    let ok = match (key, scheme) {
        #[cfg(feature = "ed25519")]
        (PublicKey::Ed25519(k), ED25519) => crate::crypto::ed25519::verify(k, message, sig),
        (PublicKey::Ec { curve, point }, ECDSA_SECP256R1_SHA256 | ECDSA_SECP384R1_SHA384) => {
            let h = scheme_hash12(scheme).unwrap();
            match crate::keys::ecdsa_sig_from_der(sig) {
                Some((r, s)) => curve.verify(point, &h.hash(message), &r, &s),
                None => false,
            }
        }
        #[cfg(feature = "rsa")]
        (PublicKey::Rsa(k), RSA_PSS_RSAE_SHA256 | RSA_PSS_RSAE_SHA384 | RSA_PSS_RSAE_SHA512) => {
            let h = scheme_hash12(scheme).unwrap();
            k.verify_pss(h, &h.hash(message), sig, Some(h.output_len()))
        }
        #[cfg(feature = "rsa")]
        (PublicKey::Rsa(k), RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PKCS1_SHA512) => {
            let h = scheme_hash12(scheme).unwrap();
            k.verify_pkcs1(h, &h.hash(message), sig)
        }
        _ => return Err(mismatch()),
    };
    if ok {
        Ok(())
    } else {
        Err(fail())
    }
}

/// A TLS 1.2 Certificate message body (no per-entry extensions, unlike TLS 1.3).
pub(crate) fn certificate_body12(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for c in chain {
        super::codec::put_vec24(&mut list, c);
    }
    let mut body = Vec::with_capacity(3 + list.len());
    super::codec::put_vec24(&mut body, &list);
    body
}

pub(crate) fn parse_certificate12(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut r = Reader::new(body, "Certificate");
    let list = r.vec24()?;
    r.finish()?;
    let mut lr = Reader::new(list, "Certificate");
    let mut certs = Vec::new();
    while !lr.is_empty() {
        let c = lr.vec24()?;
        if c.is_empty() {
            return Err(Error::decode("Certificate"));
        }
        certs.push(c.to_vec());
        if certs.len() > 16 {
            return Err(Error::proto(alert::BAD_CERTIFICATE, "certificate chain too long"));
        }
    }
    Ok(certs)
}

/// Session state for a TLS 1.2 ticket or session ID entry (version byte 2, so a TLS 1.3
/// server never accepts one as a PSK and vice versa).
pub(crate) struct Session12State {
    pub suite: Tls12Suite,
    pub master: Vec<u8>,
    pub created_ms: u64,
    pub alpn: Vec<u8>,
    pub sni: Vec<u8>,
    pub peer_certs: Vec<Vec<u8>>,
}

impl Drop for Session12State {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.master);
    }
}

impl Session12State {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![2u8];
        put_u16(&mut o, self.suite.id());
        put_vec8(&mut o, &self.master);
        o.extend_from_slice(&self.created_ms.to_be_bytes());
        put_vec8(&mut o, &self.alpn);
        put_vec8(&mut o, &self.sni);
        o.push(self.peer_certs.len() as u8);
        for c in &self.peer_certs {
            super::codec::put_vec24(&mut o, c);
        }
        o
    }

    pub fn decode(b: &[u8]) -> Option<Session12State> {
        let mut r = Reader::new(b, "session");
        if r.u8().ok()? != 2 {
            return None;
        }
        let suite = Tls12Suite::from_id(r.u16().ok()?)?;
        let master = r.vec8().ok()?.to_vec();
        if master.len() != 48 {
            return None;
        }
        let created_ms = u64::from_be_bytes(r.take(8).ok()?.try_into().ok()?);
        let alpn = r.vec8().ok()?.to_vec();
        let sni = r.vec8().ok()?.to_vec();
        let n = r.u8().ok()?;
        let mut peer_certs = Vec::new();
        for _ in 0..n {
            peer_certs.push(r.vec24().ok()?.to_vec());
        }
        r.finish().ok()?;
        Some(Session12State { suite, master, created_ms, alpn, sni, peer_certs })
    }
}

/// The server's TLS 1.2 session ID cache, for clients that do not support tickets. Bounded;
/// the oldest entry goes first. Entries expire with `ServerConfig::ticket_lifetime_secs`.
///
/// The sessions are a vector sorted by ID (binary search) next to the IDs in insertion order:
/// a `HashMap` cost about 2.5 KB more code, and an insertion moves at most `max` entries (48 KB
/// at the default 1,024), next to a full handshake that costs far more.
pub struct SessionIdCache {
    inner: Mutex<(Vec<(Vec<u8>, Vec<u8>)>, VecDeque<Vec<u8>>)>,
    max: usize,
}

impl std::fmt::Debug for SessionIdCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionIdCache({} sessions)", self.len())
    }
}

impl SessionIdCache {
    pub fn new(max: usize) -> SessionIdCache {
        SessionIdCache { inner: Mutex::new((Vec::new(), VecDeque::new())), max: max.max(1) }
    }

    pub(crate) fn put(&self, id: &[u8], state: Vec<u8>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (map, order) = &mut *g;
        match map.binary_search_by(|(k, _)| k[..].cmp(id)) {
            Ok(i) => map[i].1 = state,
            Err(_) => {
                while map.len() >= self.max {
                    let Some(old) = order.pop_front() else { break };
                    if let Ok(i) = map.binary_search_by(|(k, _)| k.cmp(&old)) {
                        map.remove(i);
                    }
                }
                // the eviction may have moved the insertion point
                let i = map.binary_search_by(|(k, _)| k[..].cmp(id)).unwrap_or_else(|i| i);
                map.insert(i, (id.to_vec(), state));
                order.push_back(id.to_vec());
            }
        }
    }

    pub(crate) fn get(&self, id: &[u8]) -> Option<Vec<u8>> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let i = g.0.binary_search_by(|(k, _)| k[..].cmp(id)).ok()?;
        Some(g.0[i].1.clone())
    }

    /// Number of cached sessions.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.0.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A TLS 1.2 session remembered by a client.
#[cfg(feature = "client")]
#[derive(Clone, Debug)]
pub(crate) struct ClientSession12 {
    pub suite: Tls12Suite,
    pub master: Vec<u8>,
    /// The ticket (empty for session-ID resumption).
    pub ticket: Vec<u8>,
    pub session_id: Vec<u8>,
    pub received_ms: u64,
    pub lifetime_secs: u32,
    pub alpn: Option<Vec<u8>>,
    pub peer_certs: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn prf_sha256_vector() {
        // the widely used TLS 1.2 PRF test vector (SHA-256), from the IETF TLS mailing list
        let secret = unhex("9bbe436ba940f017b17652849a71db35");
        let seed = unhex("a0ba9f936cda311827a6f796ffd5198c");
        let out = prf(HashAlg::Sha256, &secret, b"test label", &seed, 100);
        assert_eq!(
            hex(&out),
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
        );
    }

    #[test]
    fn prf_sha384_vector() {
        let secret = unhex("b80b733d6ceefcdc71566ea48e5567df");
        let seed = unhex("cd665cf6a8447dd6ff8b27555edb7465");
        let out = prf(HashAlg::Sha384, &secret, b"test label", &seed, 148);
        assert_eq!(
            hex(&out),
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f"
        );
    }

    #[test]
    fn suites_round_trip() {
        for s in Tls12Suite::ALL {
            assert_eq!(Tls12Suite::from_id(s.id()), Some(*s));
            assert_eq!(Tls12Suite::from_name(s.name()), Some(*s));
            assert_eq!(Tls12Suite::from_name(s.openssl_name()), Some(*s));
        }
        assert_eq!(Tls12Suite::from_id(0x002f), None, "no CBC suites");
    }

    #[test]
    fn session_state_round_trip_and_cache_bound() {
        let st = Session12State {
            suite: Tls12Suite::EcdheRsaAes256GcmSha384,
            master: vec![7; 48],
            created_ms: 99,
            alpn: b"h2".to_vec(),
            sni: b"x".to_vec(),
            peer_certs: vec![vec![1, 2, 3]],
        };
        let e = st.encode();
        let d = Session12State::decode(&e).unwrap();
        assert_eq!((d.suite, d.created_ms, &d.alpn[..], d.peer_certs.len()), (st.suite, 99, &b"h2"[..], 1));
        assert!(Session12State::decode(&e[..e.len() - 1]).is_none());
        let c = SessionIdCache::new(2);
        c.put(b"a", vec![1]);
        c.put(b"b", vec![2]);
        c.put(b"c", vec![3]);
        assert_eq!(c.len(), 2);
        assert!(c.get(b"a").is_none() && c.get(b"c").is_some());
        c.put(b"c", vec![4]); // replaced, not added
        assert_eq!((c.len(), c.get(b"c")), (2, Some(vec![4])));
        assert_eq!(c.get(b"b"), Some(vec![2]));
        let c = SessionIdCache::new(100);
        for i in (0..300u32).rev() {
            c.put(&i.to_be_bytes(), i.to_le_bytes().to_vec());
        }
        assert_eq!(c.len(), 100);
        for i in 0..300u32 {
            assert_eq!(c.get(&i.to_be_bytes()), (i < 100).then(|| i.to_le_bytes().to_vec()), "{i}");
        }
    }
}
