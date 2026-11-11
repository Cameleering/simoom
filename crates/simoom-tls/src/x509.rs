//! X.509 v3 certificate parsing (RFC 5280 subset), trust store and chain
//! validation with hostname matching (RFC 6125).

use crate::asn1::{self, Der, DerError, DerResult, TAG_BOOLEAN, TAG_INTEGER, TAG_SEQUENCE};
use crate::keys::{PublicKey, SignatureAlgorithm};
use crate::pem;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
pub const KU_KEY_CERT_SIGN: u16 = 1 << 5;

const OID_SAN: &str = "2.5.29.17";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";
#[cfg(feature = "revocation")]
const OID_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
#[cfg(feature = "revocation")]
const OID_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
#[cfg(feature = "revocation")]
const OID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
#[cfg(feature = "revocation")]
const OID_AD_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
/// At most this many URIs are kept per extension (CRL distribution points, OCSP, caIssuers).
#[cfg(feature = "revocation")]
const MAX_URIS_PER_EXTENSION: usize = 16;
pub const OID_EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const OID_EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const OID_EKU_ANY: &str = "2.5.29.37.0";
const OID_CN: &str = "2.5.4.3";

/// A distinguished name as an ordered list of (attribute OID, value).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Name {
    pub attributes: Vec<(String, String)>,
}

impl Name {
    pub fn common_name(&self) -> Option<&str> {
        self.attributes.iter().find(|(o, _)| o == OID_CN).map(|(_, v)| v.as_str())
    }

    /// The name with the most specific attribute first (`CN=x, O=y, C=z`), as Java's
    /// `X500Principal.toString()` renders it.
    pub fn to_dn_string(&self) -> String {
        let reversed = Name { attributes: self.attributes.iter().rev().cloned().collect() };
        reversed.to_string()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .attributes
            .iter()
            .map(|(o, v)| {
                let k = match o.as_str() {
                    "2.5.4.3" => "CN",
                    "2.5.4.6" => "C",
                    "2.5.4.7" => "L",
                    "2.5.4.8" => "ST",
                    "2.5.4.10" => "O",
                    "2.5.4.11" => "OU",
                    other => other,
                };
                format!("{k}={v}")
            })
            .collect();
        write!(f, "{}", parts.join(", "))
    }
}

fn parse_name(tlv: &asn1::Tlv) -> DerResult<Name> {
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
        }
    }
    Ok(name)
}

/// A parsed X.509 certificate.
#[derive(Clone, Debug)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub tbs: Vec<u8>,
    pub version: u8,
    pub serial: Vec<u8>,
    pub issuer: Name,
    pub subject: Name,
    pub issuer_raw: Vec<u8>,
    pub subject_raw: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub spki: Vec<u8>,
    /// None when the key algorithm is unsupported (the certificate can still be
    /// parsed, e.g. as an unused root).
    pub public_key: Option<PublicKey>,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub has_san: bool,
    /// Some(is_ca) when basicConstraints is present.
    pub basic_constraints_ca: Option<bool>,
    pub path_len: Option<u64>,
    pub key_usage: Option<u16>,
    pub ext_key_usage: Option<Vec<String>>,
    pub unknown_critical_extensions: Vec<String>,
    /// URIs from the CRL distribution points extension (fullName entries only).
    pub crl_distribution_points: Vec<String>,
    /// OCSP responder URIs from the authority information access extension.
    pub ocsp_urls: Vec<String>,
    /// caIssuers URIs from the authority information access extension.
    pub ca_issuers_urls: Vec<String>,
}

impl Certificate {
    pub fn from_der(der: &[u8]) -> DerResult<Certificate> {
        let mut outer = Der::new(der);
        let cert = outer.expect(TAG_SEQUENCE)?;
        if !outer.is_empty() {
            return Err(DerError("trailing data after certificate".into()));
        }
        let mut c = cert.reader();
        let tbs_tlv = c.expect(TAG_SEQUENCE)?;
        let mut sig_alg_r = c.sequence()?;
        let signature_algorithm = SignatureAlgorithm::parse(&mut sig_alg_r)?;
        let signature = c.bit_string()?.to_vec();

        let mut t = tbs_tlv.reader();
        let mut version = 1u8;
        if let Some(v) = t.optional(0xa0)? {
            version = v.reader().small_uint()? as u8 + 1;
        }
        let serial = t.expect(TAG_INTEGER)?.value.to_vec();
        let mut inner_alg = t.sequence()?;
        let inner_sig = SignatureAlgorithm::parse(&mut inner_alg)?;
        if inner_sig != signature_algorithm {
            return Err(DerError("signature algorithm mismatch".into()));
        }
        let issuer_tlv = t.expect(TAG_SEQUENCE)?;
        let mut validity = t.sequence()?;
        let nb = validity.read()?;
        let na = validity.read()?;
        let not_before = asn1::parse_time(&nb)?;
        let not_after = asn1::parse_time(&na)?;
        let subject_tlv = t.expect(TAG_SEQUENCE)?;
        let spki_tlv = t.expect(TAG_SEQUENCE)?;
        let public_key = PublicKey::from_spki(spki_tlv.raw).ok();

        let mut cert = Certificate {
            der: der.to_vec(),
            tbs: tbs_tlv.raw.to_vec(),
            version,
            serial,
            issuer: parse_name(&issuer_tlv)?,
            subject: parse_name(&subject_tlv)?,
            issuer_raw: issuer_tlv.raw.to_vec(),
            subject_raw: subject_tlv.raw.to_vec(),
            not_before,
            not_after,
            spki: spki_tlv.raw.to_vec(),
            public_key,
            signature_algorithm,
            signature,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            has_san: false,
            basic_constraints_ca: None,
            path_len: None,
            key_usage: None,
            ext_key_usage: None,
            unknown_critical_extensions: Vec::new(),
            crl_distribution_points: Vec::new(),
            ocsp_urls: Vec::new(),
            ca_issuers_urls: Vec::new(),
        };
        // optional issuerUniqueID [1], subjectUniqueID [2]
        let _ = t.optional(0x81)?;
        let _ = t.optional(0x82)?;
        if let Some(exts) = t.optional(0xa3)? {
            let mut list = exts.reader().sequence()?;
            while !list.is_empty() {
                let mut e = list.sequence()?;
                let oid = e.oid()?;
                let critical = match e.optional(TAG_BOOLEAN)? {
                    Some(b) => b.value.first().copied().unwrap_or(0) != 0,
                    None => false,
                };
                let value = e.octet_string()?;
                cert.parse_extension(&oid, critical, value)?;
            }
        }
        Ok(cert)
    }

    fn parse_extension(&mut self, oid: &str, critical: bool, value: &[u8]) -> DerResult<()> {
        let mut r = Der::new(value);
        match oid {
            OID_SAN => {
                self.has_san = true;
                let mut names = r.sequence()?;
                while !names.is_empty() {
                    let gn = names.read()?;
                    match gn.tag {
                        0x82 => self.dns_names.push(String::from_utf8_lossy(gn.value).to_ascii_lowercase()),
                        0x87 => match gn.value.len() {
                            4 => self.ip_addresses.push(IpAddr::from(<[u8; 4]>::try_from(gn.value).unwrap())),
                            16 => self.ip_addresses.push(IpAddr::from(<[u8; 16]>::try_from(gn.value).unwrap())),
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
            OID_BASIC_CONSTRAINTS => {
                let mut bc = r.sequence()?;
                let mut ca = false;
                if let Some(b) = bc.optional(TAG_BOOLEAN)? {
                    ca = b.value.first().copied().unwrap_or(0) != 0;
                }
                if bc.peek_tag() == Some(TAG_INTEGER) {
                    self.path_len = Some(bc.small_uint()?);
                }
                self.basic_constraints_ca = Some(ca);
            }
            OID_KEY_USAGE => {
                let bs = r.expect(asn1::TAG_BIT_STRING)?.value;
                let mut ku = 0u16;
                for (i, byte) in bs.iter().skip(1).take(2).enumerate() {
                    for bit in 0..8 {
                        if byte & (0x80 >> bit) != 0 {
                            ku |= 1 << (8 * i + bit);
                        }
                    }
                }
                self.key_usage = Some(ku);
            }
            OID_EXT_KEY_USAGE => {
                let mut s = r.sequence()?;
                let mut v = Vec::new();
                while !s.is_empty() {
                    v.push(s.oid()?);
                }
                self.ext_key_usage = Some(v);
            }
            // Parsed leniently: a malformed non-critical locator never rejects a certificate.
            // Only revocation checking reads them, so other builds leave them unparsed.
            #[cfg(feature = "revocation")]
            OID_CRL_DISTRIBUTION_POINTS => {
                if parse_crl_distribution_points(value, &mut self.crl_distribution_points).is_err() && critical {
                    return Err(DerError("malformed CRL distribution points".into()));
                }
            }
            #[cfg(feature = "revocation")]
            OID_AUTHORITY_INFO_ACCESS => {
                if parse_authority_info_access(value, &mut self.ocsp_urls, &mut self.ca_issuers_urls).is_err() && critical {
                    return Err(DerError("malformed authority information access".into()));
                }
            }
            _ => {
                if critical {
                    self.unknown_critical_extensions.push(oid.to_string());
                }
            }
        }
        Ok(())
    }

    /// Parses every CERTIFICATE block in PEM text.
    pub fn from_pem_all(data: &[u8]) -> Result<Vec<Certificate>, String> {
        let mut out = Vec::new();
        for b in pem::parse_pem(data)? {
            if b.label == "CERTIFICATE" || b.label == "TRUSTED CERTIFICATE" {
                out.push(Certificate::from_der(&b.der).map_err(|e| e.to_string())?);
            }
        }
        Ok(out)
    }

    pub fn is_self_issued(&self) -> bool {
        self.issuer_raw == self.subject_raw
    }

    /// Verifies this certificate's signature with `issuer_key`.
    pub fn verify_signed_by(&self, issuer_key: &PublicKey) -> bool {
        self.signature_algorithm.verify(issuer_key, &self.tbs, &self.signature)
    }

    /// RFC 6125 style hostname / IP check against SAN (CN only when no SAN extension exists).
    pub fn matches_hostname(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let host_ip = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().ok();
        if let Some(ip) = host_ip {
            return self.ip_addresses.contains(&ip);
        }
        if self.has_san {
            return self.dns_names.iter().any(|p| dns_name_matches(p, &host));
        }
        match self.subject.common_name() {
            Some(cn) => dns_name_matches(&cn.to_ascii_lowercase(), &host),
            None => false,
        }
    }
}

#[cfg(feature = "revocation")]
fn push_uri(out: &mut Vec<String>, gn: &asn1::Tlv) {
    // uniformResourceIdentifier [6] IA5String
    if gn.tag == 0x86 && out.len() < MAX_URIS_PER_EXTENSION && gn.value.is_ascii() {
        out.push(String::from_utf8_lossy(gn.value).into_owned());
    }
}

#[cfg(feature = "revocation")]
/// CRLDistributionPoints ::= SEQUENCE OF DistributionPoint (RFC 5280 section 4.2.1.13).
fn parse_crl_distribution_points(value: &[u8], out: &mut Vec<String>) -> DerResult<()> {
    let mut dps = Der::new(value).sequence()?;
    while !dps.is_empty() {
        let mut dp = dps.sequence()?;
        if let Some(name) = dp.optional(0xa0)? {
            let mut n = name.reader();
            // fullName [0] GeneralNames; nameRelativeToCRLIssuer [1] is skipped
            if let Some(full) = n.optional(0xa0)? {
                let mut gns = full.reader();
                while !gns.is_empty() {
                    push_uri(out, &gns.read()?);
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "revocation")]
/// AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription (RFC 5280 section 4.2.2.1).
fn parse_authority_info_access(value: &[u8], ocsp: &mut Vec<String>, ca_issuers: &mut Vec<String>) -> DerResult<()> {
    let mut list = Der::new(value).sequence()?;
    while !list.is_empty() {
        let mut ad = list.sequence()?;
        let method = ad.oid()?;
        let location = ad.read()?;
        match method.as_str() {
            OID_AD_OCSP => push_uri(ocsp, &location),
            OID_AD_CA_ISSUERS => push_uri(ca_issuers, &location),
            _ => {}
        }
    }
    Ok(())
}

/// Matches a (lowercase) certificate DNS pattern against a (lowercase) host name.
/// A wildcard is only allowed as the complete left-most label and matches exactly
/// one non-empty label; at least two labels must follow it.
pub fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.split('.').filter(|l| !l.is_empty()).count() < 2 || suffix.contains('*') {
            return false;
        }
        match host.split_once('.') {
            Some((first, rest)) => !first.is_empty() && rest == suffix,
            None => false,
        }
    } else {
        !pattern.contains('*') && pattern == host
    }
}

/// Certificate validation failures.
#[derive(Clone, PartialEq, Eq)]
pub enum CertError {
    NoCertificates,
    Parse(String),
    Expired { subject: String },
    NotYetValid { subject: String },
    HostnameMismatch { host: String, names: Vec<String> },
    UnknownIssuer { subject: String, issuer: String },
    BadSignature { subject: String },
    NotCa { subject: String },
    UsageNotAllowed { subject: String },
    PathTooLong,
    UnsupportedCriticalExtension { subject: String, oid: String },
    /// The certificate is revoked (CRL or OCSP); `reason` is the CRLReason code when given.
    Revoked { subject: String, reason: Option<u8> },
    /// Revocation checking was required but no valid status could be obtained.
    RevocationUnknown { subject: String, why: String },
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertError::NoCertificates => write!(f, "peer sent no certificates"),
            CertError::Parse(e) => write!(f, "certificate parse error: {e}"),
            CertError::Expired { subject } => write!(f, "certificate expired: {subject}"),
            CertError::NotYetValid { subject } => write!(f, "certificate not yet valid: {subject}"),
            CertError::HostnameMismatch { host, names } => {
                write!(f, "certificate is not valid for '{host}' (valid for: {})", names.join(", "))
            }
            CertError::UnknownIssuer { subject, issuer } => {
                write!(f, "unable to find trusted issuer '{issuer}' for '{subject}'")
            }
            CertError::BadSignature { subject } => write!(f, "invalid certificate signature on '{subject}'"),
            CertError::NotCa { subject } => write!(f, "issuer certificate '{subject}' is not a CA"),
            CertError::UsageNotAllowed { subject } => write!(f, "key usage not permitted for '{subject}'"),
            CertError::PathTooLong => write!(f, "certificate path too long"),
            CertError::UnsupportedCriticalExtension { subject, oid } => {
                write!(f, "unsupported critical extension {oid} in '{subject}'")
            }
            CertError::Revoked { subject, reason: Some(r) } => write!(f, "certificate revoked (reason {r}): {subject}"),
            CertError::Revoked { subject, reason: None } => write!(f, "certificate revoked: {subject}"),
            CertError::RevocationUnknown { subject, why } => write!(f, "revocation status unknown for '{subject}': {why}"),
        }
    }
}

/// Debug output is the Display text (smaller than a derived implementation).
impl fmt::Debug for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for CertError {}

/// A set of trust anchors.
#[derive(Clone, Default)]
pub struct RootStore {
    roots: Vec<Arc<Certificate>>,
}

impl fmt::Debug for RootStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootStore({} roots)", self.roots.len())
    }
}

/// Candidate locations of the system CA bundle.
pub const SYSTEM_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
];

impl RootStore {
    pub fn empty() -> RootStore {
        RootStore::default()
    }

    /// The system trust store (`SSL_CERT_FILE`, else the first existing bundle in
    /// [`SYSTEM_BUNDLE_PATHS`], else the Windows `ROOT` certificate store; macOS is covered by
    /// `/etc/ssl/cert.pem`); loaded once per process. Certificates that fail to parse are
    /// skipped.
    pub fn system() -> RootStore {
        static SYSTEM: OnceLock<RootStore> = OnceLock::new();
        SYSTEM
            .get_or_init(|| {
                let mut store = RootStore::empty();
                let mut paths: Vec<String> = Vec::new();
                if let Ok(p) = std::env::var("SSL_CERT_FILE") {
                    paths.push(p);
                }
                paths.extend(SYSTEM_BUNDLE_PATHS.iter().map(|s| s.to_string()));
                for p in paths {
                    if let Ok(data) = std::fs::read(&p) {
                        store.add_pem_lenient(&data);
                        if !store.is_empty() {
                            break;
                        }
                    }
                }
                // Windows keeps its roots in the system certificate store, not in a file.
                if store.is_empty() {
                    for der in simoom_sys::certstore::system_roots() {
                        if let Ok(c) = Certificate::from_der(&der) {
                            store.roots.push(Arc::new(c));
                        }
                    }
                }
                store
            })
            .clone()
    }

    fn add_pem_lenient(&mut self, data: &[u8]) -> usize {
        let mut n = 0;
        if let Ok(blocks) = pem::parse_pem(data) {
            for b in blocks.into_iter().filter(|b| b.label == "CERTIFICATE") {
                if let Ok(c) = Certificate::from_der(&b.der) {
                    self.roots.push(Arc::new(c));
                    n += 1;
                }
            }
        }
        n
    }

    /// Adds every certificate in PEM text; fails if any block is malformed or none found.
    pub fn add_pem(&mut self, data: &[u8]) -> Result<usize, String> {
        let certs = Certificate::from_pem_all(data)?;
        if certs.is_empty() {
            return Err("no CERTIFICATE blocks found".into());
        }
        let n = certs.len();
        self.roots.extend(certs.into_iter().map(Arc::new));
        Ok(n)
    }

    pub fn add_pem_file(&mut self, path: impl AsRef<std::path::Path>) -> Result<usize, String> {
        let data = std::fs::read(path.as_ref()).map_err(|e| format!("{}: {e}", path.as_ref().display()))?;
        self.add_pem(&data)
    }

    pub fn add_der(&mut self, der: &[u8]) -> Result<(), String> {
        self.roots.push(Arc::new(Certificate::from_der(der).map_err(|e| e.to_string())?));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn extend(&mut self, other: &RootStore) {
        self.roots.extend(other.roots.iter().cloned());
    }

    /// The trust anchors.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.roots.iter().map(|c| c.as_ref())
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

const MAX_PATH_DEPTH: usize = 8;

fn check_time(c: &Certificate, now: i64) -> Result<(), CertError> {
    if now < c.not_before {
        return Err(CertError::NotYetValid { subject: c.subject.to_string() });
    }
    if now > c.not_after {
        return Err(CertError::Expired { subject: c.subject.to_string() });
    }
    Ok(())
}

fn check_critical(c: &Certificate) -> Result<(), CertError> {
    // name constraints / policy extensions are tolerated but not enforced (documented limitation);
    // anything else unknown and critical is rejected.
    const TOLERATED: &[&str] = &["2.5.29.30", "2.5.29.32", "2.5.29.36", "2.5.29.54"];
    for oid in &c.unknown_critical_extensions {
        if !TOLERATED.contains(&oid.as_str()) {
            return Err(CertError::UnsupportedCriticalExtension { subject: c.subject.to_string(), oid: oid.clone() });
        }
    }
    Ok(())
}

/// Validates a peer certificate chain (leaf first, DER) against `roots` at time `now` (Unix
/// seconds).
///
/// Checks: signatures along the path to a trust anchor, validity periods of the leaf and
/// intermediates, CA flag / keyCertSign / pathLenConstraint on issuers, leaf keyUsage
/// (digitalSignature) and extendedKeyUsage (`required_eku`), and the hostname (when given).
pub fn verify_chain(
    chain: &[Vec<u8>],
    hostname: Option<&str>,
    roots: &RootStore,
    now: i64,
    required_eku: &str,
) -> Result<Certificate, CertError> {
    let (mut certs, _, _) = verify_core(chain, hostname, roots, now, required_eku)?;
    Ok(certs.swap_remove(0))
}

/// Like [`verify_chain`], but returns the validated path: the leaf first, then each issuer,
/// ending with the trust anchor. A pinned leaf that is itself a trust anchor gives a path of
/// one certificate.
pub fn verify_chain_path(
    chain: &[Vec<u8>],
    hostname: Option<&str>,
    roots: &RootStore,
    now: i64,
    required_eku: &str,
) -> Result<Vec<Certificate>, CertError> {
    let (mut certs, path, anchor) = verify_core(chain, hostname, roots, now, required_eku)?;
    let Some(anchor) = anchor else {
        // a pinned leaf
        return Ok(vec![certs.swap_remove(0)]);
    };
    let mut slots: Vec<Option<Certificate>> = certs.into_iter().map(Some).collect();
    let mut out: Vec<Certificate> = path.iter().filter_map(|&i| slots[i].take()).collect();
    out.push(Certificate::clone(&anchor));
    Ok(out)
}

/// Validates the chain: (the parsed certificates, the indices of the path through them, the
/// trust anchor; None when the leaf is itself a trust anchor).
#[allow(clippy::type_complexity)]
fn verify_core(
    chain: &[Vec<u8>],
    hostname: Option<&str>,
    roots: &RootStore,
    now: i64,
    required_eku: &str,
) -> Result<(Vec<Certificate>, Vec<usize>, Option<Arc<Certificate>>), CertError> {
    if chain.is_empty() {
        return Err(CertError::NoCertificates);
    }
    if chain.len() > MAX_PATH_DEPTH + 2 {
        return Err(CertError::PathTooLong);
    }
    let certs: Vec<Certificate> = chain
        .iter()
        .map(|d| Certificate::from_der(d).map_err(|e| CertError::Parse(e.to_string())))
        .collect::<Result<_, _>>()?;
    let leaf = &certs[0];
    check_time(leaf, now)?;
    check_critical(leaf)?;
    if let Some(ku) = leaf.key_usage {
        if ku & KU_DIGITAL_SIGNATURE == 0 {
            return Err(CertError::UsageNotAllowed { subject: leaf.subject.to_string() });
        }
    }
    if let Some(eku) = &leaf.ext_key_usage {
        if !eku.iter().any(|o| o == required_eku || o == OID_EKU_ANY) {
            return Err(CertError::UsageNotAllowed { subject: leaf.subject.to_string() });
        }
    }
    if let Some(host) = hostname {
        if !leaf.matches_hostname(host) {
            let mut names = leaf.dns_names.clone();
            names.extend(leaf.ip_addresses.iter().map(|i| i.to_string()));
            if names.is_empty() {
                names.extend(leaf.subject.common_name().map(str::to_string));
            }
            return Err(CertError::HostnameMismatch { host: host.to_string(), names });
        }
    }
    // a leaf that is itself a trust anchor (pinned self-signed certificate)
    if roots.roots.iter().any(|r| r.der == leaf.der) {
        return Ok((certs, vec![0], None));
    }
    let mut used = vec![false; certs.len()];
    used[0] = true;
    let mut path = vec![0usize];
    let anchor = build_path(&certs, 0, roots, now, &mut used, 0, &mut path)?;
    Ok((certs, path, Some(anchor)))
}

fn build_path(
    certs: &[Certificate],
    idx: usize,
    roots: &RootStore,
    now: i64,
    used: &mut Vec<bool>,
    depth: usize,
    path: &mut Vec<usize>,
) -> Result<Arc<Certificate>, CertError> {
    if depth > MAX_PATH_DEPTH {
        return Err(CertError::PathTooLong);
    }
    let cert = &certs[idx];
    let mut last_err = CertError::UnknownIssuer { subject: cert.subject.to_string(), issuer: cert.issuer.to_string() };
    // trust anchors first
    for root in roots.roots.iter().filter(|r| r.subject_raw == cert.issuer_raw) {
        if let Some(pk) = &root.public_key {
            if cert.verify_signed_by(pk) {
                return Ok(root.clone());
            }
            last_err = CertError::BadSignature { subject: cert.subject.to_string() };
        }
    }
    // then intermediates supplied by the peer
    for j in 0..certs.len() {
        if used[j] || certs[j].subject_raw != cert.issuer_raw {
            continue;
        }
        let issuer = &certs[j];
        if issuer.basic_constraints_ca != Some(true) {
            last_err = CertError::NotCa { subject: issuer.subject.to_string() };
            continue;
        }
        if let Some(ku) = issuer.key_usage {
            if ku & KU_KEY_CERT_SIGN == 0 {
                last_err = CertError::UsageNotAllowed { subject: issuer.subject.to_string() };
                continue;
            }
        }
        if let Some(pl) = issuer.path_len {
            // number of intermediate CA certificates below this issuer (depth counts them)
            if (depth as u64) > pl {
                last_err = CertError::PathTooLong;
                continue;
            }
        }
        if let Err(e) = check_time(issuer, now).and_then(|_| check_critical(issuer)) {
            last_err = e;
            continue;
        }
        let pk = match &issuer.public_key {
            Some(pk) => pk,
            None => continue,
        };
        if !cert.verify_signed_by(pk) {
            last_err = CertError::BadSignature { subject: cert.subject.to_string() };
            continue;
        }
        used[j] = true;
        path.push(j);
        match build_path(certs, j, roots, now, used, depth + 1, path) {
            Ok(anchor) => return Ok(anchor),
            Err(e) => last_err = e,
        }
        path.pop();
        used[j] = false;
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    // some fixtures are used only by the tests that need every key type
    #![cfg_attr(not(all(feature = "rsa", feature = "p384", feature = "ed25519")), allow(dead_code))]
    use super::*;

    fn der_of(pem_text: &str) -> Vec<u8> {
        pem::parse_pem(pem_text.as_bytes()).unwrap().remove(0).der
    }

    const CA: &str = include_str!("../testdata/ca.pem");
    const INT: &str = include_str!("../testdata/int.pem");
    const LEAF: &str = include_str!("../testdata/leaf.pem");
    const RSA_SELF: &str = include_str!("../testdata/rsa_selfsigned.pem");

    #[test]
    #[cfg(all(feature = "rsa", feature = "p384", feature = "ed25519"))] // the test chain uses RSA and P-384
    fn parse_openssl_chain() {
        let leaf = Certificate::from_der(&der_of(LEAF)).unwrap();
        assert_eq!(leaf.version, 3);
        assert_eq!(leaf.subject.common_name(), Some("leaf.camel.test"));
        assert_eq!(leaf.issuer.common_name(), Some("Camel Test Intermediate"));
        assert_eq!(leaf.dns_names, vec!["leaf.camel.test", "*.apps.camel.test"]);
        assert_eq!(leaf.ip_addresses, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(leaf.basic_constraints_ca, Some(false));
        assert_eq!(leaf.key_usage, Some(KU_DIGITAL_SIGNATURE));
        assert_eq!(leaf.ext_key_usage, Some(vec![OID_EKU_SERVER_AUTH.to_string()]));
        assert!(matches!(leaf.signature_algorithm, SignatureAlgorithm::RsaPss { salt_len: 32, .. }));
        assert!(leaf.not_after > 4_102_444_800); // GeneralizedTime beyond 2100
        let int = Certificate::from_der(&der_of(INT)).unwrap();
        assert_eq!(int.basic_constraints_ca, Some(true));
        assert_eq!(int.path_len, Some(0));
        assert!(matches!(int.signature_algorithm, SignatureAlgorithm::Ecdsa(_)));
        let ca = Certificate::from_der(&der_of(CA)).unwrap();
        assert!(ca.is_self_issued());
        assert!(ca.verify_signed_by(ca.public_key.as_ref().unwrap()));
        assert!(int.verify_signed_by(ca.public_key.as_ref().unwrap()));
        assert!(leaf.verify_signed_by(int.public_key.as_ref().unwrap()));
        assert!(!leaf.verify_signed_by(ca.public_key.as_ref().unwrap()));
        let rsa = Certificate::from_der(&der_of(RSA_SELF)).unwrap();
        assert!(rsa.verify_signed_by(rsa.public_key.as_ref().unwrap()));
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "p384", feature = "ed25519"))] // the test chain uses RSA and P-384
    fn chain_validation() {
        let mut roots = RootStore::empty();
        roots.add_pem(CA.as_bytes()).unwrap();
        let chain = vec![der_of(LEAF), der_of(INT)];
        let now = now_unix();
        assert!(verify_chain(&chain, Some("leaf.camel.test"), &roots, now, OID_EKU_SERVER_AUTH).is_ok());
        assert!(verify_chain(&chain, Some("x.apps.camel.test"), &roots, now, OID_EKU_SERVER_AUTH).is_ok());
        assert!(verify_chain(&chain, Some("127.0.0.1"), &roots, now, OID_EKU_SERVER_AUTH).is_ok());
        assert!(matches!(
            verify_chain(&chain, Some("a.b.apps.camel.test"), &roots, now, OID_EKU_SERVER_AUTH),
            Err(CertError::HostnameMismatch { .. })
        ));
        assert!(matches!(
            verify_chain(&chain, Some("other.test"), &roots, now, OID_EKU_SERVER_AUTH),
            Err(CertError::HostnameMismatch { .. })
        ));
        // missing intermediate
        assert!(matches!(
            verify_chain(&chain[..1], Some("leaf.camel.test"), &roots, now, OID_EKU_SERVER_AUTH),
            Err(CertError::UnknownIssuer { .. })
        ));
        // expired / not yet valid
        assert!(matches!(
            verify_chain(&chain, None, &roots, 48_000_000_000, OID_EKU_SERVER_AUTH),
            Err(CertError::Expired { .. })
        ));
        assert!(matches!(verify_chain(&chain, None, &roots, 1_000_000_000, OID_EKU_SERVER_AUTH), Err(CertError::NotYetValid { .. })));
        // wrong EKU
        assert!(matches!(verify_chain(&chain, None, &roots, now, OID_EKU_CLIENT_AUTH), Err(CertError::UsageNotAllowed { .. })));
        // untrusted
        assert!(verify_chain(&chain, None, &RootStore::empty(), now, OID_EKU_SERVER_AUTH).is_err());
        // pinned self-signed leaf
        let mut pinned = RootStore::empty();
        pinned.add_pem(RSA_SELF.as_bytes()).unwrap();
        assert!(verify_chain(&[der_of(RSA_SELF)], Some("rsa.test"), &pinned, now, OID_EKU_SERVER_AUTH).is_ok());
        assert!(verify_chain(&[der_of(RSA_SELF)], Some("foo.wild.test"), &pinned, now, OID_EKU_SERVER_AUTH).is_ok());
        // tampered signature
        let mut bad = der_of(LEAF);
        let n = bad.len();
        bad[n - 5] ^= 1;
        assert!(matches!(
            verify_chain(&[bad, der_of(INT)], None, &roots, now, OID_EKU_SERVER_AUTH),
            Err(CertError::BadSignature { .. })
        ));
    }

    #[test]
    fn wildcard_rules() {
        assert!(dns_name_matches("*.example.com", "www.example.com"));
        assert!(!dns_name_matches("*.example.com", "example.com"));
        assert!(!dns_name_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_name_matches("*.com", "example.com"));
        assert!(!dns_name_matches("w*.example.com", "www.example.com"));
        assert!(dns_name_matches("example.com", "example.com"));
    }

    #[test]
    fn system_bundle_parses() {
        let store = RootStore::system();
        if std::path::Path::new("/etc/ssl/certs/ca-certificates.crt").exists() {
            assert!(store.len() > 10, "only {} roots parsed", store.len());
            // every root with a supported key verifies its own self-signature when self-issued
            // (spot-check a handful; some legacy roots use SHA-1)
            let mut checked = 0;
            for r in store.roots.iter().filter(|r| r.is_self_issued()).take(20) {
                if let Some(pk) = &r.public_key {
                    if !matches!(r.signature_algorithm, SignatureAlgorithm::Unknown(_)) {
                        assert!(r.verify_signed_by(pk), "root {} self-signature", r.subject);
                        checked += 1;
                    }
                }
            }
            assert!(checked > 5);
        }
    }
}
