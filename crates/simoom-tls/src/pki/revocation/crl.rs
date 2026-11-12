//! Certificate revocation lists (RFC 5280 section 5): parsing with bounded sizes, signature
//! and scope checks, lookup, and building (for tests and for CAs that issue their own).
//!
//! (**Moves to ksar-pki**; from Cameleer `cameleer-tls/src/x509.rs` `Crl`.)

use super::{derr, ext_der, parse_extensions, parse_name, parse_reason};
use crate::asn1::{self, Der, DerResult, TAG_INTEGER, TAG_SEQUENCE};
use crate::keys::{PrivateKey, SignatureAlgorithm};
use crate::pem;
use crate::x509::{Certificate, Name};

/// keyUsage cRLSign, in the bit layout of [`Certificate::key_usage`].
pub const KU_CRL_SIGN: u16 = 1 << 6;

const OID_CRL_NUMBER: &str = "2.5.29.20";
const OID_DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const OID_ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
const OID_AUTHORITY_KEY_ID: &str = "2.5.29.35";
const OID_ISSUER_ALT_NAME: &str = "2.5.29.18";
const OID_FRESHEST_CRL: &str = "2.5.29.46";
const OID_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
const OID_REASON_CODE: &str = "2.5.29.21";
const OID_INVALIDITY_DATE: &str = "2.5.29.24";
const OID_CERTIFICATE_ISSUER: &str = "2.5.29.29";

/// Bounds applied while parsing a CRL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrlLimits {
    /// Largest accepted encoding, in bytes (default 32 MiB).
    pub max_size: usize,
    /// Most revoked entries accepted (default 1,000,000).
    pub max_entries: usize,
}

impl Default for CrlLimits {
    fn default() -> Self {
        CrlLimits { max_size: 32 << 20, max_entries: 1_000_000 }
    }
}

/// One revoked certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedEntry {
    /// The serial number as INTEGER contents (as in [`Certificate::serial`]).
    pub serial: Vec<u8>,
    pub revocation_time: i64,
    /// The CRLReason code ([`reason_name`](super::reason_name)), when present.
    pub reason: Option<u8>,
    pub invalidity_date: Option<i64>,
}

/// The supported part of the issuingDistributionPoint extension (RFC 5280 section 5.2.5).
/// The CRL covers only certificates whose CRL distribution points name one of `full_names`
/// (when not empty), and only end-entity or only CA certificates when the flags say so.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuingDistributionPoint {
    /// URIs of the fullName distribution point name.
    pub full_names: Vec<String>,
    pub only_user_certs: bool,
    pub only_ca_certs: bool,
}

/// A parsed certificate revocation list.
#[derive(Clone, Debug)]
pub struct Crl {
    pub der: Vec<u8>,
    pub tbs: Vec<u8>,
    /// 1 or 2.
    pub version: u8,
    pub issuer: Name,
    /// The DER issuer Name (compared byte for byte with the certificates' issuer).
    pub issuer_raw: Vec<u8>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    /// cRLNumber (INTEGER contents).
    pub crl_number: Option<Vec<u8>>,
    pub authority_key_id: Option<Vec<u8>>,
    pub issuing_distribution_point: Option<IssuingDistributionPoint>,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
    /// Sorted by serial.
    revoked: Vec<RevokedEntry>,
}

fn parse_idp(value: &[u8]) -> DerResult<IssuingDistributionPoint> {
    let mut outer = Der::new(value);
    let mut s = outer.sequence()?;
    if !outer.is_empty() {
        return derr("trailing data in issuingDistributionPoint");
    }
    let mut idp = IssuingDistributionPoint::default();
    let flag = |t: &asn1::Tlv| -> DerResult<bool> {
        match t.value {
            [0xff] => Ok(true),
            [0x00] => Ok(false),
            _ => derr("bad BOOLEAN"),
        }
    };
    while !s.is_empty() {
        let t = s.read()?;
        match t.tag {
            0xa0 => {
                let mut n = t.reader();
                let name = n.read()?;
                if name.tag != 0xa0 {
                    return derr("issuingDistributionPoint nameRelativeToCRLIssuer is not supported");
                }
                let mut gns = name.reader();
                while !gns.is_empty() {
                    let gn = gns.read()?;
                    if gn.tag == 0x86 && idp.full_names.len() < 16 && gn.value.is_ascii() {
                        idp.full_names.push(String::from_utf8_lossy(gn.value).into_owned());
                    }
                }
                if idp.full_names.is_empty() {
                    return derr("issuingDistributionPoint names no URI");
                }
            }
            0x81 => idp.only_user_certs = flag(&t)?,
            0x82 => idp.only_ca_certs = flag(&t)?,
            0x83 => return derr("CRLs partitioned by reason (onlySomeReasons) are not supported"),
            0x84 => {
                if flag(&t)? {
                    return derr("indirect CRLs are not supported");
                }
            }
            0x85 => {
                if flag(&t)? {
                    return derr("attribute certificate CRLs are not supported");
                }
            }
            _ => return derr("bad issuingDistributionPoint"),
        }
    }
    if idp.only_user_certs && idp.only_ca_certs {
        return derr("issuingDistributionPoint sets both onlyContainsUserCerts and onlyContainsCACerts");
    }
    Ok(idp)
}

fn parse_entry(e: asn1::Tlv) -> DerResult<RevokedEntry> {
    let mut r = e.reader();
    let serial = r.expect(TAG_INTEGER)?.value;
    if serial.is_empty() || serial.len() > 64 {
        return derr("bad serial number");
    }
    let revocation_time = asn1::parse_time(&r.read()?)?;
    let mut entry = RevokedEntry { serial: serial.to_vec(), revocation_time, reason: None, invalidity_date: None };
    if r.peek_tag() == Some(TAG_SEQUENCE) {
        for ext in parse_extensions(&mut r)? {
            let mut v = Der::new(ext.value);
            match ext.oid.as_str() {
                OID_REASON_CODE => entry.reason = Some(parse_reason(&v.read()?)?),
                OID_INVALIDITY_DATE => entry.invalidity_date = Some(asn1::parse_time(&v.read()?)?),
                OID_CERTIFICATE_ISSUER => return derr("indirect CRLs (certificateIssuer) are not supported"),
                other if ext.critical => return derr(format!("unsupported critical CRL entry extension {other}")),
                _ => {}
            }
        }
    }
    if !r.is_empty() {
        return derr("trailing data in CRL entry");
    }
    Ok(entry)
}

impl Crl {
    /// Parses a DER CRL with the default [`CrlLimits`].
    pub fn from_der(der: &[u8]) -> Result<Crl, String> {
        Crl::from_der_with_limits(der, &CrlLimits::default())
    }

    /// Parses a DER CRL. Rejects delta CRLs, indirect CRLs, unknown critical extensions
    /// (CRL and entry) and anything above `limits`.
    pub fn from_der_with_limits(der: &[u8], limits: &CrlLimits) -> Result<Crl, String> {
        if der.len() > limits.max_size {
            return Err(format!("CRL of {} bytes exceeds the limit of {}", der.len(), limits.max_size));
        }
        Crl::parse(der, limits).map_err(|e| format!("invalid CRL: {}", e.0))
    }

    fn parse(der: &[u8], limits: &CrlLimits) -> DerResult<Crl> {
        let mut outer = Der::new(der);
        let crl = outer.expect(TAG_SEQUENCE)?;
        if !outer.is_empty() {
            return derr("trailing data after CRL");
        }
        let mut c = crl.reader();
        let tbs_tlv = c.expect(TAG_SEQUENCE)?;
        let signature_algorithm = SignatureAlgorithm::parse(&mut c.sequence()?)?;
        let signature = c.bit_string()?.to_vec();
        if !c.is_empty() {
            return derr("trailing data in CRL");
        }
        let mut t = tbs_tlv.reader();
        let mut version = 1u8;
        if t.peek_tag() == Some(TAG_INTEGER) {
            if t.small_uint()? != 1 {
                return derr("unsupported CRL version");
            }
            version = 2;
        }
        if SignatureAlgorithm::parse(&mut t.sequence()?)? != signature_algorithm {
            return derr("signature algorithm mismatch");
        }
        let issuer_tlv = t.expect(TAG_SEQUENCE)?;
        let this_update = asn1::parse_time(&t.read()?)?;
        let mut next_update = None;
        if matches!(t.peek_tag(), Some(asn1::TAG_UTC_TIME) | Some(asn1::TAG_GENERALIZED_TIME)) {
            next_update = Some(asn1::parse_time(&t.read()?)?);
        }
        let mut revoked = Vec::new();
        if t.peek_tag() == Some(TAG_SEQUENCE) {
            let mut list = t.sequence()?;
            while !list.is_empty() {
                if revoked.len() >= limits.max_entries {
                    return derr(format!("more than {} revoked entries", limits.max_entries));
                }
                revoked.push(parse_entry(list.expect(TAG_SEQUENCE)?)?);
            }
        }
        let mut crl = Crl {
            der: der.to_vec(),
            tbs: tbs_tlv.raw.to_vec(),
            version,
            issuer: parse_name(&issuer_tlv)?,
            issuer_raw: issuer_tlv.raw.to_vec(),
            this_update,
            next_update,
            crl_number: None,
            authority_key_id: None,
            issuing_distribution_point: None,
            signature_algorithm,
            signature,
            revoked: Vec::new(),
        };
        if let Some(exts) = t.optional(0xa0)? {
            let mut er = exts.reader();
            for ext in parse_extensions(&mut er)? {
                let mut v = Der::new(ext.value);
                match ext.oid.as_str() {
                    OID_CRL_NUMBER => {
                        let n = v.uint()?;
                        if n.len() > 20 {
                            return derr("cRLNumber longer than 20 octets");
                        }
                        crl.crl_number = Some(n.to_vec());
                    }
                    OID_AUTHORITY_KEY_ID => {
                        let mut s = v.sequence()?;
                        if let Some(k) = s.optional(0x80)? {
                            crl.authority_key_id = Some(k.value.to_vec());
                        }
                    }
                    OID_DELTA_CRL_INDICATOR => return derr("delta CRLs are not supported"),
                    OID_ISSUING_DISTRIBUTION_POINT => crl.issuing_distribution_point = Some(parse_idp(ext.value)?),
                    OID_ISSUER_ALT_NAME | OID_FRESHEST_CRL | OID_AUTHORITY_INFO_ACCESS if !ext.critical => {}
                    other if ext.critical => return derr(format!("unsupported critical CRL extension {other}")),
                    _ => {}
                }
            }
            if !er.is_empty() {
                return derr("trailing data in CRL extensions");
            }
        }
        if !t.is_empty() {
            return derr("trailing data in TBSCertList");
        }
        revoked.sort_by(|a, b| a.serial.cmp(&b.serial));
        crl.revoked = revoked;
        Ok(crl)
    }

    /// Parses every `X509 CRL` block of PEM text, or a single DER CRL.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Crl>, String> {
        if data.windows(10).any(|w| w == b"-----BEGIN") {
            let mut out = Vec::new();
            for b in pem::parse_pem(data)? {
                if b.label == "X509 CRL" {
                    out.push(Crl::from_der(&b.der)?);
                }
            }
            if out.is_empty() {
                return Err("no X509 CRL blocks found".into());
            }
            Ok(out)
        } else {
            Ok(vec![Crl::from_der(data)?])
        }
    }

    /// The revoked entries, sorted by serial.
    pub fn revoked(&self) -> &[RevokedEntry] {
        &self.revoked
    }

    /// Whether `issuer` signed this CRL: same subject name as the CRL issuer, cRLSign in its
    /// keyUsage when it has the extension, and a valid signature.
    pub fn verify_signature(&self, issuer: &Certificate) -> bool {
        if issuer.subject_raw != self.issuer_raw {
            return false;
        }
        if let Some(ku) = issuer.key_usage {
            if ku & KU_CRL_SIGN == 0 {
                return false;
            }
        }
        match &issuer.public_key {
            Some(k) => self.signature_algorithm.verify(k, &self.tbs, &self.signature),
            None => false,
        }
    }

    /// The entry for `serial` (INTEGER contents) when it is listed. An entry with the
    /// removeFromCRL reason (only meaningful in delta CRLs) does not count.
    pub fn is_revoked(&self, serial: &[u8]) -> Option<RevokedEntry> {
        let i = self.revoked.binary_search_by(|e| e.serial.as_slice().cmp(serial)).ok()?;
        let e = &self.revoked[i];
        if e.reason == Some(8) {
            return None;
        }
        Some(e.clone())
    }

    /// Whether this CRL's scope includes `cert`: the same issuer name, and the
    /// issuingDistributionPoint restrictions (distribution point name, user / CA only).
    pub fn covers(&self, cert: &Certificate) -> bool {
        if cert.issuer_raw != self.issuer_raw {
            return false;
        }
        if let Some(idp) = &self.issuing_distribution_point {
            let is_ca = cert.basic_constraints_ca == Some(true);
            if (idp.only_user_certs && is_ca) || (idp.only_ca_certs && !is_ca) {
                return false;
            }
            if !idp.full_names.is_empty() && !cert.crl_distribution_points.iter().any(|u| idp.full_names.contains(u)) {
                return false;
            }
        }
        true
    }

    /// Whether the CRL is current at `now`: thisUpdate not in the future and nextUpdate not in
    /// the past (both with [`CLOCK_SKEW_SECS`](super::CLOCK_SKEW_SECS)); a CRL without
    /// nextUpdate must be at most `max_age_secs` old.
    pub fn is_fresh(&self, now: i64, max_age_secs: i64) -> bool {
        let skew = super::CLOCK_SKEW_SECS;
        if self.this_update > now.saturating_add(skew) {
            return false;
        }
        match self.next_update {
            Some(n) => n >= now.saturating_sub(skew),
            None => self.this_update >= now.saturating_sub(max_age_secs),
        }
    }
}

/// Builds and signs CRLs (version 2).
#[derive(Clone, Debug, Default)]
pub struct CrlBuilder {
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub entries: Vec<RevokedEntry>,
    pub crl_number: Option<u64>,
    pub issuing_distribution_point: Option<IssuingDistributionPoint>,
    /// Extra CRL extensions as (OID, critical, DER value).
    pub extra_extensions: Vec<(String, bool, Vec<u8>)>,
}

impl CrlBuilder {
    pub fn new(this_update: i64, next_update: Option<i64>) -> CrlBuilder {
        CrlBuilder { this_update, next_update, ..CrlBuilder::default() }
    }

    /// Adds an entry for `serial` (INTEGER contents, e.g. [`Certificate::serial`]).
    pub fn revoke(mut self, serial: &[u8], time: i64, reason: Option<u8>) -> CrlBuilder {
        self.entries.push(RevokedEntry { serial: serial.to_vec(), revocation_time: time, reason, invalidity_date: None });
        self
    }

    pub fn crl_number(mut self, n: u64) -> CrlBuilder {
        self.crl_number = Some(n);
        self
    }

    pub fn extension(mut self, oid: &str, critical: bool, value: Vec<u8>) -> CrlBuilder {
        self.extra_extensions.push((oid.to_string(), critical, value));
        self
    }

    /// The DER CRL, issued by `issuer` and signed with its key `key`.
    pub fn sign(&self, issuer: &Certificate, key: &PrivateKey) -> Vec<u8> {
        let sig_alg = crate::certgen::sig_alg_for(key);
        let mut parts = vec![asn1::uint(&[1]), sig_alg.clone(), issuer.subject_raw.clone(), asn1::time(self.this_update)];
        if let Some(n) = self.next_update {
            parts.push(asn1::time(n));
        }
        if !self.entries.is_empty() {
            let mut list = Vec::new();
            for e in &self.entries {
                let mut entry = vec![asn1::tlv(TAG_INTEGER, &e.serial), asn1::time(e.revocation_time)];
                let mut exts = Vec::new();
                if let Some(r) = e.reason {
                    exts.push(ext_der(OID_REASON_CODE, false, &asn1::tlv(0x0a, &[r])));
                }
                if let Some(d) = e.invalidity_date {
                    exts.push(ext_der(OID_INVALIDITY_DATE, false, &super::gtime(d)));
                }
                if !exts.is_empty() {
                    entry.push(asn1::seq(&exts));
                }
                list.push(asn1::seq(&entry));
            }
            parts.push(asn1::seq(&list));
        }
        let mut exts = Vec::new();
        if let Some(n) = self.crl_number {
            exts.push(ext_der(OID_CRL_NUMBER, false, &asn1::uint(&n.to_be_bytes())));
        }
        if let Some(idp) = &self.issuing_distribution_point {
            let mut fields = Vec::new();
            if !idp.full_names.is_empty() {
                let names: Vec<Vec<u8>> = idp.full_names.iter().map(|u| asn1::tlv(0x86, u.as_bytes())).collect();
                fields.push(asn1::explicit(0, &asn1::explicit(0, &names.concat())));
            }
            if idp.only_user_certs {
                fields.push(asn1::tlv(0x81, &[0xff]));
            }
            if idp.only_ca_certs {
                fields.push(asn1::tlv(0x82, &[0xff]));
            }
            exts.push(ext_der(OID_ISSUING_DISTRIBUTION_POINT, true, &asn1::seq(&fields)));
        }
        for (oid, critical, value) in &self.extra_extensions {
            exts.push(ext_der(oid, *critical, value));
        }
        if !exts.is_empty() {
            parts.push(asn1::explicit(0, &asn1::seq(&exts)));
        }
        let tbs = asn1::seq(&parts);
        let sig = crate::certgen::sign_with(key, &tbs);
        asn1::seq(&[tbs, sig_alg, asn1::bit_string(&sig)])
    }
}
