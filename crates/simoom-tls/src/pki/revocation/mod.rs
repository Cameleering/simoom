//! Certificate revocation: CRLs (RFC 5280 section 5), OCSP (RFC 6960, with the RFC 8954
//! nonce) and the server-side stapling holder (feature `revocation`).
//!
//! Everything here is sans-io: time is passed in, and the only network access goes through a
//! caller-supplied [`RevocationFetcher`]. [`check_path`] is the one entry point the TLS code
//! calls after [`x509::verify_chain_path`](crate::x509::verify_chain_path) has validated the
//! path:
//!
//! 1. a stapled OCSP response for the leaf ([`OcspMode`]);
//! 2. CRLs ([`CrlMode`]): the ones in the policy, then (through the fetcher) the CRL
//!    distribution points of each certificate, with a small cache keyed by URL;
//! 3. optionally ([`RevocationPolicy::ocsp_online`]) an OCSP request to each certificate's
//!    AIA responder through the fetcher.
//!
//! A revoked certificate always fails with [`CertError::Revoked`]. When a status is required
//! but none can be obtained the check fails with [`CertError::RevocationUnknown`].
//!
//! Not supported: delta CRLs, indirect CRLs (the `certificateIssuer` entry extension or the
//! `indirectCRL` flag), CRLs partitioned by reason (`onlySomeReasons`), attribute certificate
//! CRLs, `nameRelativeToCRLIssuer` distribution points, signed OCSP requests (they are parsed,
//! the signature is ignored), and revocation checking of a delegated OCSP responder's own
//! certificate (RFC 6960 `id-pkix-ocsp-nocheck` behaviour is assumed).
//!
//! (**Moves to ksar-pki.** Ported from Cameleer's `cameleer-tls/src/ocsp.rs`, the CRL code
//! of its `x509.rs` and `tls/config.rs` `OcspMode`.)
//!

pub mod crl;
pub mod ocsp;
pub mod testing;

use crate::asn1::{self, Der, DerError, DerResult, TAG_BOOLEAN};
use crate::x509::{CertError, Certificate, Name};
use crl::{Crl, CrlLimits, RevokedEntry};
use ocsp::{CertStatus, OcspResponse};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

/// Allowed clock skew (seconds) for thisUpdate / nextUpdate checks of CRLs and OCSP responses.
pub const CLOCK_SKEW_SECS: i64 = 300;
/// Default maximum age (seconds) of a CRL or OCSP response that carries no nextUpdate.
pub const DEFAULT_MAX_AGE_SECS: i64 = 7 * 86400;
/// At most this many extensions are parsed in one extension list.
pub(crate) const MAX_EXTENSIONS: usize = 64;

// ------------------------------------------------------------------ shared DER helpers

pub(crate) fn derr<T>(msg: impl Into<String>) -> DerResult<T> {
    Err(DerError(msg.into().into()))
}

/// One parsed extension.
pub(crate) struct Ext<'a> {
    pub oid: String,
    pub critical: bool,
    pub value: &'a [u8],
}

/// Parses `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension` (the reader is positioned on
/// the SEQUENCE). Rejects duplicates and more than [`MAX_EXTENSIONS`] entries.
pub(crate) fn parse_extensions<'a>(r: &mut Der<'a>) -> DerResult<Vec<Ext<'a>>> {
    let mut list = r.sequence()?;
    let mut out: Vec<Ext<'a>> = Vec::new();
    while !list.is_empty() {
        if out.len() >= MAX_EXTENSIONS {
            return derr("too many extensions");
        }
        let mut e = list.sequence()?;
        let oid = e.oid()?;
        let critical = match e.optional(TAG_BOOLEAN)? {
            Some(b) => b.value.first().copied().unwrap_or(0) != 0,
            None => false,
        };
        let value = e.octet_string()?;
        if !e.is_empty() {
            return derr("trailing data in extension");
        }
        if out.iter().any(|x| x.oid == oid) {
            return derr(format!("duplicate extension {oid}"));
        }
        out.push(Ext { oid, critical, value });
    }
    Ok(out)
}

/// Parses a Name (as `x509` does) for display.
pub(crate) fn parse_name(tlv: &asn1::Tlv) -> DerResult<Name> {
    let mut name = Name::default();
    let mut r = tlv.reader();
    while !r.is_empty() {
        let set = r.expect(asn1::TAG_SET)?;
        let mut sr = set.reader();
        while !sr.is_empty() {
            let mut atv = sr.sequence()?;
            let oid = atv.oid()?;
            let v = atv.read()?;
            let s = asn1::decode_string(&v).unwrap_or_else(|| crate::util::hex(v.value));
            name.attributes.push((oid, s));
            if name.attributes.len() > 64 {
                return derr("name has too many attributes");
            }
        }
    }
    Ok(name)
}

/// An Extension encoding.
pub(crate) fn ext_der(oid: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![asn1::oid(oid)];
    if critical {
        parts.push(asn1::tlv(TAG_BOOLEAN, &[0xff]));
    }
    parts.push(asn1::octet_string(value));
    asn1::seq(&parts)
}

/// GeneralizedTime (OCSP requires it for every time field; CRLs use it from 2050 on).
pub(crate) fn gtime(unix: i64) -> Vec<u8> {
    let days = unix.div_euclid(86400);
    let secs = unix.rem_euclid(86400);
    let (y, m, d) = asn1::civil_from_days(days);
    let s = format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", y, m, d, secs / 3600, secs / 60 % 60, secs % 60);
    asn1::tlv(asn1::TAG_GENERALIZED_TIME, s.as_bytes())
}

/// Parses `CRLReason ::= ENUMERATED` (0..=10, 7 unused).
pub(crate) fn parse_reason(tlv: &asn1::Tlv) -> DerResult<u8> {
    if tlv.tag != 0x0a || tlv.value.len() != 1 || tlv.value[0] > 10 || tlv.value[0] == 7 {
        return derr("bad CRLReason");
    }
    Ok(tlv.value[0])
}

/// The RFC 5280 name of a CRLReason code.
pub fn reason_name(code: u8) -> &'static str {
    match code {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unknown",
    }
}

// ------------------------------------------------------------------ policy

/// OCSP stapling on the client (the TLS `status_request` extension).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OcspMode {
    /// Do not request a stapled response and ignore one that arrives (default).
    #[default]
    Off,
    /// Request one and validate it when the server staples: a revoked status or an invalid
    /// response fails the handshake, a missing one does not.
    Request,
    /// Request one and fail the handshake without a valid "good" response for the leaf.
    Require,
}

/// CRL (and online OCSP) checking of every non-anchor certificate in the path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CrlMode {
    /// No CRL checks (default).
    #[default]
    Off,
    /// Check each certificate against a CRL when one is available (in the policy, or fetched
    /// from the certificate's CRL distribution points through the fetcher); certificates
    /// without a usable CRL are accepted.
    IfAvailable,
    /// Every non-anchor certificate in the path needs a definitive status: a valid, fresh CRL
    /// from its issuer that covers it, or a valid "good" OCSP response (stapled for the leaf,
    /// or online when [`RevocationPolicy::ocsp_online`] is set). Otherwise the check fails with
    /// [`CertError::RevocationUnknown`], unless [`RevocationPolicy::soft_fail`] is set.
    Require,
}

/// The caller-supplied I/O hook for revocation data. Implementations do the HTTP (or LDAP)
/// requests; they should apply their own timeouts and size limits and return `None` on any
/// failure.
pub trait RevocationFetcher: Send + Sync {
    /// GETs a CRL (DER or PEM) from a CRL distribution point URL.
    fn fetch_crl(&self, url: &str) -> Option<Vec<u8>>;
    /// POSTs a DER OCSPRequest (`application/ocsp-request`) to a responder URL and returns the
    /// DER OCSPResponse.
    fn ocsp(&self, url: &str, request_der: &[u8]) -> Option<Vec<u8>>;
}

type CacheMap = HashMap<String, (Arc<Crl>, i64)>;

/// A small cache of fetched, verified CRLs keyed by URL. An entry expires at the CRL's
/// nextUpdate (or thisUpdate plus the policy's maximum age when it has none).
pub struct CrlCache {
    entries: Mutex<CacheMap>,
    max_entries: usize,
}

impl fmt::Debug for CrlCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CrlCache({} entries)", self.len())
    }
}

impl Default for CrlCache {
    fn default() -> Self {
        CrlCache::new(64)
    }
}

impl CrlCache {
    /// A cache holding at most `max_entries` CRLs.
    pub fn new(max_entries: usize) -> CrlCache {
        CrlCache { entries: Mutex::new(HashMap::new()), max_entries: max_entries.max(1) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheMap> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cached CRL for `url` when it has not expired at `now`.
    pub fn get(&self, url: &str, now: i64) -> Option<Arc<Crl>> {
        let mut m = self.lock();
        match m.get(url) {
            Some((crl, expires)) if now <= *expires => Some(crl.clone()),
            Some(_) => {
                m.remove(url);
                None
            }
            None => None,
        }
    }

    /// Stores a CRL (call only with CRLs that verified). Expired CRLs are not stored.
    pub fn insert(&self, url: &str, crl: Arc<Crl>, now: i64, max_age_secs: i64) {
        let expires = crl.next_update.unwrap_or(crl.this_update.saturating_add(max_age_secs));
        if expires < now {
            return;
        }
        let mut m = self.lock();
        if !m.contains_key(url) && m.len() >= self.max_entries {
            m.retain(|_, (_, e)| *e >= now);
            if m.len() >= self.max_entries {
                if let Some(k) = m.iter().min_by_key(|(_, (_, e))| *e).map(|(k, _)| k.clone()) {
                    m.remove(&k);
                }
            }
        }
        m.insert(url.to_string(), (crl, expires));
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.lock().clear();
    }
}

/// What [`check_path`] checks and where it gets revocation data.
///
/// `soft_fail`: when a status is required (`CrlMode::Require`) but none can be obtained (no
/// CRL, a fetch failed, an online responder was unreachable, answered "unknown", or sent
/// something that does not verify), accept the certificate instead of failing. A revoked
/// status is never softened, and neither are the stapling rules of [`OcspMode`] (an invalid
/// staple, or a missing one under `Require`, still fails).
#[derive(Clone)]
pub struct RevocationPolicy {
    /// CRLs supplied by the application (any issuer; each is used for the certificates it
    /// covers and whose issuer signed it).
    pub crls: Vec<Arc<Crl>>,
    pub check_crls: CrlMode,
    /// Client-side stapling.
    pub ocsp: OcspMode,
    /// Ask each certificate's AIA OCSP responder through the fetcher when no CRL or staple
    /// gave a status.
    pub ocsp_online: bool,
    /// See the type documentation.
    pub soft_fail: bool,
    /// When set, an online OCSP response must echo the request nonce; otherwise a nonce is
    /// sent and only checked when the responder includes one (most public responders do not).
    pub require_ocsp_nonce: bool,
    /// Maximum age of a CRL or OCSP response without nextUpdate.
    pub max_age_secs: i64,
    /// Size and entry limits for fetched CRLs.
    pub crl_limits: CrlLimits,
    pub fetcher: Option<Arc<dyn RevocationFetcher>>,
    /// Shared by clones of the policy.
    pub cache: Arc<CrlCache>,
}

impl fmt::Debug for RevocationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationPolicy")
            .field("crls", &self.crls.len())
            .field("check_crls", &self.check_crls)
            .field("ocsp", &self.ocsp)
            .field("ocsp_online", &self.ocsp_online)
            .field("soft_fail", &self.soft_fail)
            .field("require_ocsp_nonce", &self.require_ocsp_nonce)
            .field("max_age_secs", &self.max_age_secs)
            .field("crl_limits", &self.crl_limits)
            .field("fetcher", &self.fetcher.is_some())
            .field("cache", &self.cache)
            .finish()
    }
}

impl Default for RevocationPolicy {
    fn default() -> Self {
        RevocationPolicy {
            crls: Vec::new(),
            check_crls: CrlMode::Off,
            ocsp: OcspMode::Off,
            ocsp_online: false,
            soft_fail: false,
            require_ocsp_nonce: false,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            crl_limits: CrlLimits::default(),
            fetcher: None,
            cache: Arc::new(CrlCache::default()),
        }
    }
}

impl RevocationPolicy {
    /// Nothing checked.
    pub fn new() -> RevocationPolicy {
        RevocationPolicy::default()
    }

    /// Whether this policy checks nothing at all.
    pub fn is_off(&self) -> bool {
        self.check_crls == CrlMode::Off && self.ocsp == OcspMode::Off && !self.ocsp_online
    }

    pub fn with_crls(mut self, crls: impl IntoIterator<Item = Crl>) -> Self {
        self.crls.extend(crls.into_iter().map(Arc::new));
        self
    }

    /// Adds every CRL in PEM text (or one DER CRL).
    pub fn add_crls(&mut self, data: &[u8]) -> Result<usize, String> {
        let crls = Crl::parse_all(data)?;
        let n = crls.len();
        self.crls.extend(crls.into_iter().map(Arc::new));
        Ok(n)
    }

    pub fn with_crl_mode(mut self, mode: CrlMode) -> Self {
        self.check_crls = mode;
        self
    }

    pub fn with_ocsp(mut self, mode: OcspMode) -> Self {
        self.ocsp = mode;
        self
    }

    pub fn with_ocsp_online(mut self, on: bool) -> Self {
        self.ocsp_online = on;
        self
    }

    pub fn with_soft_fail(mut self, on: bool) -> Self {
        self.soft_fail = on;
        self
    }

    pub fn with_fetcher(mut self, fetcher: Arc<dyn RevocationFetcher>) -> Self {
        self.fetcher = Some(fetcher);
        self
    }
}

// ------------------------------------------------------------------ the check

fn revoked(c: &Certificate, reason: Option<u8>) -> CertError {
    CertError::Revoked { subject: c.subject.to_string(), reason }
}

fn unknown(c: &Certificate, why: impl Into<String>) -> CertError {
    CertError::RevocationUnknown { subject: c.subject.to_string(), why: why.into() }
}

/// Checks the revocation status of a validated path (leaf first, trust anchor last, as
/// returned by [`x509::verify_chain_path`](crate::x509::verify_chain_path)). The anchor is
/// not checked; a path of one certificate (a pinned leaf) has nothing to check.
///
/// `stapled_ocsp` is the DER OCSPResponse the server stapled for the leaf, if any.
pub fn check_path(path: &[Certificate], policy: &RevocationPolicy, now: i64, stapled_ocsp: Option<&[u8]>) -> Result<(), CertError> {
    if path.len() < 2 || policy.is_off() {
        return Ok(());
    }
    let leaf = &path[0];
    let mut leaf_good = false;
    match (policy.ocsp, stapled_ocsp) {
        (OcspMode::Off, _) | (OcspMode::Request, None) => {}
        (OcspMode::Require, None) => return Err(unknown(leaf, "the server did not staple an OCSP response")),
        (mode, Some(der)) => {
            let status = OcspResponse::parse(der)
                .and_then(|r| r.validate(leaf, &path[1], now, None, policy.max_age_secs))
                .map_err(|e| unknown(leaf, format!("invalid stapled OCSP response: {e}")))?;
            match status {
                CertStatus::Good => leaf_good = true,
                CertStatus::Revoked { reason, .. } => return Err(revoked(leaf, reason)),
                CertStatus::Unknown if mode == OcspMode::Require => {
                    return Err(unknown(leaf, "the stapled OCSP response reports an unknown status"))
                }
                CertStatus::Unknown => {}
            }
        }
    }
    if policy.check_crls == CrlMode::Off && !policy.ocsp_online {
        return Ok(());
    }
    for i in 0..path.len() - 1 {
        let (cert, issuer) = (&path[i], &path[i + 1]);
        let mut covered = i == 0 && leaf_good;
        let mut why: Vec<String> = Vec::new();
        if policy.check_crls != CrlMode::Off {
            match crl_status(cert, issuer, policy, now, &mut why) {
                CrlStatus::Revoked(e) => return Err(revoked(cert, e.reason)),
                CrlStatus::NotRevoked => covered = true,
                CrlStatus::NoCrl => {}
            }
        }
        if !covered && policy.ocsp_online {
            match online_ocsp(cert, issuer, policy, now) {
                Ok(CertStatus::Good) => covered = true,
                Ok(CertStatus::Revoked { reason, .. }) => return Err(revoked(cert, reason)),
                Ok(CertStatus::Unknown) => why.push("the OCSP responder reports an unknown status".into()),
                Err(e) => why.push(e),
            }
        }
        if !covered && policy.check_crls == CrlMode::Require && !policy.soft_fail {
            if why.is_empty() {
                why.push("no CRL or OCSP status available".into());
            }
            return Err(unknown(cert, why.join("; ")));
        }
    }
    Ok(())
}

enum CrlStatus {
    Revoked(RevokedEntry),
    NotRevoked,
    NoCrl,
}

/// The verdict of one verified CRL: a signed listing proves revocation even when the CRL is
/// stale (revocation is permanent), except a certificateHold, which only counts while fresh.
fn crl_verdict(crl: &Crl, cert: &Certificate, now: i64, max_age: i64) -> Option<CrlStatus> {
    let fresh = crl.is_fresh(now, max_age);
    if let Some(e) = crl.is_revoked(&cert.serial) {
        if e.reason != Some(6) || fresh {
            return Some(CrlStatus::Revoked(e));
        }
    }
    if fresh {
        Some(CrlStatus::NotRevoked)
    } else {
        None
    }
}

/// The CRL verdict for `cert`: configured CRLs first, then (when none is valid and fresh) the
/// certificate's distribution points through the cache and the fetcher.
fn crl_status(cert: &Certificate, issuer: &Certificate, policy: &RevocationPolicy, now: i64, why: &mut Vec<String>) -> CrlStatus {
    let mut not_revoked = false;
    for crl in &policy.crls {
        if !crl.covers(cert) || !crl.verify_signature(issuer) {
            continue;
        }
        match crl_verdict(crl, cert, now, policy.max_age_secs) {
            Some(CrlStatus::Revoked(e)) => return CrlStatus::Revoked(e),
            Some(_) => not_revoked = true,
            None => why.push(format!("the CRL of '{}' is not current", crl.issuer)),
        }
    }
    if not_revoked {
        return CrlStatus::NotRevoked;
    }
    if cert.crl_distribution_points.is_empty() {
        why.push("no current CRL, and the certificate names no CRL distribution point".into());
        return CrlStatus::NoCrl;
    }
    for url in &cert.crl_distribution_points {
        let crl = match policy.cache.get(url, now) {
            Some(c) => c,
            None => {
                let Some(fetcher) = &policy.fetcher else {
                    why.push("no current CRL, and no fetcher to download one".into());
                    return CrlStatus::NoCrl;
                };
                let Some(bytes) = fetcher.fetch_crl(url) else {
                    why.push(format!("could not fetch the CRL at {url}"));
                    continue;
                };
                let parsed = if bytes.len() > policy.crl_limits.max_size {
                    Err(format!("larger than {} bytes", policy.crl_limits.max_size))
                } else if bytes.starts_with(b"-----") {
                    Crl::parse_all(&bytes).and_then(|v| v.into_iter().next().ok_or_else(|| "no CRL".to_string()))
                } else {
                    Crl::from_der_with_limits(&bytes, &policy.crl_limits)
                };
                match parsed {
                    Ok(c) if c.covers(cert) && c.verify_signature(issuer) => {
                        let c = Arc::new(c);
                        policy.cache.insert(url, c.clone(), now, policy.max_age_secs);
                        c
                    }
                    Ok(_) => {
                        why.push(format!("the CRL at {url} is not signed by the issuer or does not cover the certificate"));
                        continue;
                    }
                    Err(e) => {
                        why.push(format!("the CRL at {url}: {e}"));
                        continue;
                    }
                }
            }
        };
        match crl_verdict(&crl, cert, now, policy.max_age_secs) {
            Some(v) => return v,
            None => why.push(format!("the CRL at {url} is not current")),
        }
    }
    CrlStatus::NoCrl
}

/// Asks the certificate's AIA OCSP responders through the fetcher.
fn online_ocsp(cert: &Certificate, issuer: &Certificate, policy: &RevocationPolicy, now: i64) -> Result<CertStatus, String> {
    let Some(fetcher) = &policy.fetcher else {
        return Err("no fetcher for online OCSP".into());
    };
    if cert.ocsp_urls.is_empty() {
        return Err("the certificate names no OCSP responder".into());
    }
    let nonce = crate::crypto::rng::bytes(16);
    let request = ocsp::build_request(cert, issuer, Some(&nonce));
    let mut errors = Vec::new();
    for url in &cert.ocsp_urls {
        let Some(der) = fetcher.ocsp(url, &request) else {
            errors.push(format!("no response from the OCSP responder at {url}"));
            continue;
        };
        let checked = OcspResponse::parse(&der).and_then(|r| {
            let expected = if policy.require_ocsp_nonce { Some(&nonce[..]) } else { None };
            let status = r.validate(cert, issuer, now, expected, policy.max_age_secs)?;
            match &r.nonce {
                Some(n) if n[..] != nonce[..] => Err("OCSP nonce mismatch".to_string()),
                _ => Ok(status),
            }
        });
        match checked {
            Ok(CertStatus::Unknown) => errors.push(format!("the OCSP responder at {url} reports an unknown status")),
            Ok(s) => return Ok(s),
            Err(e) => errors.push(format!("OCSP responder at {url}: {e}")),
        }
    }
    Err(errors.join("; "))
}

// ------------------------------------------------------------------ server stapling

/// The OCSP response a server staples, shared between the refresher and the handshakes.
/// Cloning is cheap (the clones share the slot). The caller refreshes it, for example with
/// [`StapleSource::set_checked`] after fetching a new response before the old one expires.
#[derive(Clone, Default)]
pub struct StapleSource {
    inner: Arc<RwLock<Option<Arc<Vec<u8>>>>>,
}

impl fmt::Debug for StapleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StapleSource({})", if self.get().is_some() { "set" } else { "empty" })
    }
}

impl StapleSource {
    pub fn new() -> StapleSource {
        StapleSource::default()
    }

    /// Replaces (or with `None` clears) the stapled response without checking it.
    pub fn set(&self, der: Option<Vec<u8>>) {
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = der.map(Arc::new);
    }

    /// The current response.
    pub fn get(&self) -> Option<Arc<Vec<u8>>> {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Validates `der` for `cert` (issued by `issuer`) at `now` and stores it when it is valid
    /// and reports "good" or "revoked" (a revoked server should staple its revocation). An
    /// invalid response or an "unknown" status is refused and the previous one kept.
    pub fn set_checked(&self, der: Vec<u8>, cert: &Certificate, issuer: &Certificate, now: i64) -> Result<CertStatus, String> {
        let status = OcspResponse::parse(&der)?.validate(cert, issuer, now, None, DEFAULT_MAX_AGE_SECS)?;
        if status == CertStatus::Unknown {
            return Err("the OCSP response reports an unknown status".into());
        }
        self.set(Some(der));
        Ok(status)
    }
}

#[cfg(test)]
mod tests;
