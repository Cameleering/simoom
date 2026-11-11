//! OCSP (RFC 6960): requests with the RFC 8954 nonce, response parsing, validation against a
//! certificate and its issuer, and a responder-side builder (tests, and servers that make
//! their own staples).
//!
//! (**Moves to saltire-pki**; from Cameleer `cameleer-tls/src/ocsp.rs`.)

use super::{derr, ext_der, gtime, parse_extensions, parse_reason, CLOCK_SKEW_SECS};
use crate::asn1::{self, Der, DerResult, TAG_INTEGER, TAG_SEQUENCE};
use crate::crypto::md::Md;
use crate::keys::{PrivateKey, SignatureAlgorithm};
use crate::x509::Certificate;

/// id-pkix-ocsp-basic.
pub const OID_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
/// id-pkix-ocsp-nonce.
pub const OID_OCSP_NONCE: &str = "1.3.6.1.5.5.7.48.1.2";
/// id-kp-OCSPSigning.
pub const OID_EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
/// Largest accepted OCSP response or request, in bytes.
pub const MAX_OCSP_SIZE: usize = 1 << 20;
/// Most SingleResponses (or Requests) accepted in one message.
pub const MAX_SINGLE_RESPONSES: usize = 1024;
/// Most certificates accepted in a response's `certs` field.
pub const MAX_RESPONSE_CERTS: usize = 16;
/// Longest accepted nonce (RFC 8954 allows 1 to 32 octets; some responders send more).
pub const MAX_NONCE_LEN: usize = 128;

/// The status of one certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertStatus {
    Good,
    Revoked { time: i64, reason: Option<u8> },
    Unknown,
}

/// OCSPResponseStatus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

impl ResponseStatus {
    fn from_code(c: u8) -> Option<ResponseStatus> {
        Some(match c {
            0 => ResponseStatus::Successful,
            1 => ResponseStatus::MalformedRequest,
            2 => ResponseStatus::InternalError,
            3 => ResponseStatus::TryLater,
            5 => ResponseStatus::SigRequired,
            6 => ResponseStatus::Unauthorized,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ResponseStatus::Successful => "successful",
            ResponseStatus::MalformedRequest => "malformedRequest",
            ResponseStatus::InternalError => "internalError",
            ResponseStatus::TryLater => "tryLater",
            ResponseStatus::SigRequired => "sigRequired",
            ResponseStatus::Unauthorized => "unauthorized",
        }
    }
}

/// The hash of the issuer's public key: the BIT STRING contents of its SPKI.
fn key_hash(md: Md, spki: &[u8]) -> Vec<u8> {
    let bits = (|| -> DerResult<Vec<u8>> {
        let mut s = Der::new(spki).sequence()?;
        s.expect(TAG_SEQUENCE)?;
        Ok(s.bit_string()?.to_vec())
    })()
    .unwrap_or_default();
    md.hash(&bits)
}

/// A CertID: which certificate a request or response is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertId {
    pub hash: Md,
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    /// INTEGER contents (as in [`Certificate::serial`]).
    pub serial: Vec<u8>,
}

impl CertId {
    /// The SHA-1 CertID of `cert` issued by `issuer` (what responders expect by default).
    pub fn new(cert: &Certificate, issuer: &Certificate) -> CertId {
        CertId::with_hash(cert, issuer, Md::Sha1)
    }

    pub fn with_hash(cert: &Certificate, issuer: &Certificate, md: Md) -> CertId {
        CertId::for_issuer(issuer, &cert.serial, md)
    }

    /// The CertID of serial `serial` (INTEGER contents) under `issuer`.
    pub fn for_issuer(issuer: &Certificate, serial: &[u8], md: Md) -> CertId {
        CertId { hash: md, issuer_name_hash: md.hash(&issuer.subject_raw), issuer_key_hash: key_hash(md, &issuer.spki), serial: serial.to_vec() }
    }

    /// Whether this CertID names `cert` issued by `issuer` (with this CertID's hash).
    pub fn matches(&self, cert: &Certificate, issuer: &Certificate) -> bool {
        self.serial == cert.serial && cert.issuer_raw == issuer.subject_raw && *self == CertId::with_hash(cert, issuer, self.hash)
    }

    pub fn to_der(&self) -> Vec<u8> {
        asn1::seq(&[
            asn1::seq(&[asn1::oid(self.hash.oid()), asn1::tlv(asn1::TAG_NULL, &[])]),
            asn1::octet_string(&self.issuer_name_hash),
            asn1::octet_string(&self.issuer_key_hash),
            asn1::tlv(TAG_INTEGER, &self.serial),
        ])
    }

    fn parse(r: &mut Der) -> DerResult<CertId> {
        let mut c = r.sequence()?;
        let mut alg = c.sequence()?;
        let hash = Md::from_oid(&alg.oid()?).ok_or(asn1::DerError("unsupported CertID hash".into()))?;
        let issuer_name_hash = c.octet_string()?.to_vec();
        let issuer_key_hash = c.octet_string()?.to_vec();
        let serial = c.expect(TAG_INTEGER)?.value;
        if serial.is_empty() || serial.len() > 64 || issuer_name_hash.len() != hash.output_len() || issuer_key_hash.len() != hash.output_len() {
            return derr("bad CertID");
        }
        if !c.is_empty() {
            return derr("trailing data in CertID");
        }
        Ok(CertId { hash, issuer_name_hash, issuer_key_hash, serial: serial.to_vec() })
    }
}

/// The nonce from a nonce extension value: RFC 8954 wraps it in an OCTET STRING; some old
/// responders put the raw bytes there.
fn parse_nonce(value: &[u8]) -> DerResult<Vec<u8>> {
    let mut r = Der::new(value);
    let n = match r.read() {
        Ok(t) if t.tag == asn1::TAG_OCTET_STRING && r.is_empty() => t.value,
        _ => value,
    };
    if n.is_empty() || n.len() > MAX_NONCE_LEN {
        return derr("bad nonce length");
    }
    Ok(n.to_vec())
}

fn nonce_extensions(nonce: &[u8]) -> Vec<u8> {
    asn1::seq(&[ext_der(OID_OCSP_NONCE, false, &asn1::octet_string(nonce))])
}

/// A DER OCSPRequest for `cert` issued by `issuer` (SHA-1 CertID), with a nonce extension
/// when `nonce` is given. Unsigned.
pub fn build_request(cert: &Certificate, issuer: &Certificate, nonce: Option<&[u8]>) -> Vec<u8> {
    build_request_for(&[CertId::new(cert, issuer)], nonce)
}

/// A DER OCSPRequest for several CertIDs.
pub fn build_request_for(ids: &[CertId], nonce: Option<&[u8]>) -> Vec<u8> {
    let list: Vec<Vec<u8>> = ids.iter().map(|id| asn1::seq(&[id.to_der()])).collect();
    let mut tbs = vec![asn1::seq(&list)];
    if let Some(n) = nonce {
        tbs.push(asn1::explicit(2, &nonce_extensions(n)));
    }
    asn1::seq(&[asn1::seq(&tbs)])
}

/// A parsed OCSPRequest (the responder side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspRequest {
    pub cert_ids: Vec<CertId>,
    pub nonce: Option<Vec<u8>>,
}

impl OcspRequest {
    pub fn parse(der: &[u8]) -> Result<OcspRequest, String> {
        if der.len() > MAX_OCSP_SIZE {
            return Err("OCSP request too large".into());
        }
        OcspRequest::parse_inner(der).map_err(|e| format!("malformed OCSP request: {}", e.0))
    }

    fn parse_inner(der: &[u8]) -> DerResult<OcspRequest> {
        let mut outer = Der::new(der);
        let mut req = outer.sequence()?;
        if !outer.is_empty() {
            return derr("trailing data after OCSP request");
        }
        let mut tbs = req.sequence()?;
        let _ = req.optional(0xa0)?; // optionalSignature: not checked
        if !req.is_empty() {
            return derr("trailing data in OCSP request");
        }
        if let Some(v) = tbs.optional(0xa0)? {
            if v.reader().small_uint()? != 0 {
                return derr("unsupported OCSP request version");
            }
        }
        let _ = tbs.optional(0xa1)?; // requestorName
        let mut list = tbs.sequence()?;
        let mut cert_ids = Vec::new();
        while !list.is_empty() {
            if cert_ids.len() >= MAX_SINGLE_RESPONSES {
                return derr("too many requests");
            }
            let mut one = list.sequence()?;
            cert_ids.push(CertId::parse(&mut one)?);
            if let Some(e) = one.optional(0xa0)? {
                for ext in parse_extensions(&mut e.reader())? {
                    if ext.critical {
                        return derr(format!("unsupported critical request extension {}", ext.oid));
                    }
                }
            }
        }
        if cert_ids.is_empty() {
            return derr("empty request list");
        }
        let mut nonce = None;
        if let Some(e) = tbs.optional(0xa2)? {
            for ext in parse_extensions(&mut e.reader())? {
                match ext.oid.as_str() {
                    OID_OCSP_NONCE => nonce = Some(parse_nonce(ext.value)?),
                    other if ext.critical => return derr(format!("unsupported critical request extension {other}")),
                    _ => {}
                }
            }
        }
        if !tbs.is_empty() {
            return derr("trailing data in TBSRequest");
        }
        Ok(OcspRequest { cert_ids, nonce })
    }
}

/// How the response names its signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponderId {
    /// The DER Name.
    ByName(Vec<u8>),
    /// SHA-1 of the responder's public key (BIT STRING contents of its SPKI).
    ByKey(Vec<u8>),
}

/// One SingleResponse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub status: CertStatus,
    pub this_update: i64,
    pub next_update: Option<i64>,
}

/// A parsed successful basic OCSP response.
#[derive(Clone, Debug)]
pub struct OcspResponse {
    pub der: Vec<u8>,
    pub responder_id: ResponderId,
    pub produced_at: i64,
    pub responses: Vec<SingleResponse>,
    /// Certificates the responder included (a delegated responder's certificate).
    pub certs: Vec<Vec<u8>>,
    /// The nonce from the response extensions.
    pub nonce: Option<Vec<u8>>,
    pub tbs: Vec<u8>,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

fn parse_single(r: &mut Der) -> DerResult<SingleResponse> {
    let mut s = r.sequence()?;
    let cert_id = CertId::parse(&mut s)?;
    let st = s.read()?;
    let status = match st.tag {
        0x80 if st.value.is_empty() => CertStatus::Good,
        0xa1 => {
            let mut ri = st.reader();
            let time = asn1::parse_time(&ri.expect(asn1::TAG_GENERALIZED_TIME)?)?;
            let reason = match ri.optional(0xa0)? {
                Some(t) => {
                    let mut tr = t.reader();
                    Some(parse_reason(&tr.read()?)?)
                }
                None => None,
            };
            if !ri.is_empty() {
                return derr("trailing data in RevokedInfo");
            }
            CertStatus::Revoked { time, reason }
        }
        0x82 if st.value.is_empty() => CertStatus::Unknown,
        _ => return derr("bad certStatus"),
    };
    let this_update = asn1::parse_time(&s.expect(asn1::TAG_GENERALIZED_TIME)?)?;
    let next_update = match s.optional(0xa0)? {
        Some(t) => Some(asn1::parse_time(&t.reader().expect(asn1::TAG_GENERALIZED_TIME)?)?),
        None => None,
    };
    if let Some(e) = s.optional(0xa1)? {
        for ext in parse_extensions(&mut e.reader())? {
            if ext.critical {
                return derr(format!("unsupported critical singleResponse extension {}", ext.oid));
            }
        }
    }
    if !s.is_empty() {
        return derr("trailing data in SingleResponse");
    }
    Ok(SingleResponse { cert_id, status, this_update, next_update })
}

/// The responseStatus of a DER OCSPResponse.
pub fn response_status(der: &[u8]) -> Result<ResponseStatus, String> {
    let r = (|| -> DerResult<u8> {
        let mut top = Der::new(der).sequence()?;
        let st = top.expect(0x0a)?;
        if st.value.len() != 1 {
            return derr("bad responseStatus");
        }
        Ok(st.value[0])
    })();
    let code = r.map_err(|e| format!("malformed OCSP response: {}", e.0))?;
    ResponseStatus::from_code(code).ok_or_else(|| format!("unknown OCSP response status {code}"))
}

impl OcspResponse {
    /// Parses a DER OCSPResponse. A responseStatus other than successful is an error that
    /// names it, as is a response type other than id-pkix-ocsp-basic.
    pub fn parse(der: &[u8]) -> Result<OcspResponse, String> {
        if der.len() > MAX_OCSP_SIZE {
            return Err("OCSP response too large".into());
        }
        let status = response_status(der)?;
        if status != ResponseStatus::Successful {
            return Err(format!("OCSP responder status {} ({})", status as u8, status.name()));
        }
        OcspResponse::parse_inner(der).map_err(|e| format!("malformed OCSP response: {}", e.0))
    }

    fn parse_inner(der: &[u8]) -> DerResult<OcspResponse> {
        let mut outer = Der::new(der);
        let mut top = outer.sequence()?;
        if !outer.is_empty() {
            return derr("trailing data after OCSP response");
        }
        top.expect(0x0a)?;
        let rb = top.expect(0xa0)?;
        if !top.is_empty() {
            return derr("trailing data in OCSPResponse");
        }
        let mut rb = rb.reader().sequence()?;
        if rb.oid()? != OID_OCSP_BASIC {
            return derr("unsupported OCSP response type");
        }
        let basic = rb.octet_string()?;
        let mut bo = Der::new(basic);
        let mut b = bo.sequence()?;
        if !bo.is_empty() {
            return derr("trailing data after BasicOCSPResponse");
        }
        let tbs_tlv = b.expect(TAG_SEQUENCE)?;
        let signature_algorithm = SignatureAlgorithm::parse(&mut b.sequence()?)?;
        let signature = b.bit_string()?.to_vec();
        let mut certs = Vec::new();
        if let Some(c) = b.optional(0xa0)? {
            let mut list = c.reader().sequence()?;
            while !list.is_empty() {
                if certs.len() >= MAX_RESPONSE_CERTS {
                    return derr("too many certificates in OCSP response");
                }
                certs.push(list.expect(TAG_SEQUENCE)?.raw.to_vec());
            }
        }
        if !b.is_empty() {
            return derr("trailing data in BasicOCSPResponse");
        }
        let mut tbs = tbs_tlv.reader();
        if let Some(v) = tbs.optional(0xa0)? {
            if v.reader().small_uint()? != 0 {
                return derr("unsupported OCSP response version");
            }
        }
        let rid = tbs.read()?;
        let responder_id = match rid.tag {
            0xa1 => ResponderId::ByName(rid.reader().expect(TAG_SEQUENCE)?.raw.to_vec()),
            0xa2 => ResponderId::ByKey(rid.reader().octet_string()?.to_vec()),
            _ => return derr("bad responderID"),
        };
        let produced_at = asn1::parse_time(&tbs.expect(asn1::TAG_GENERALIZED_TIME)?)?;
        let mut list = tbs.sequence()?;
        let mut responses = Vec::new();
        while !list.is_empty() {
            if responses.len() >= MAX_SINGLE_RESPONSES {
                return derr("too many single responses");
            }
            responses.push(parse_single(&mut list)?);
        }
        let mut nonce = None;
        if let Some(e) = tbs.optional(0xa1)? {
            for ext in parse_extensions(&mut e.reader())? {
                match ext.oid.as_str() {
                    OID_OCSP_NONCE => nonce = Some(parse_nonce(ext.value)?),
                    other if ext.critical => return derr(format!("unsupported critical response extension {other}")),
                    _ => {}
                }
            }
        }
        if !tbs.is_empty() {
            return derr("trailing data in ResponseData");
        }
        Ok(OcspResponse { der: der.to_vec(), responder_id, produced_at, responses, certs, nonce, tbs: tbs_tlv.raw.to_vec(), signature_algorithm, signature })
    }

    /// The SingleResponse for `cert` issued by `issuer` (CertID match with any supported hash).
    pub fn find(&self, cert: &Certificate, issuer: &Certificate) -> Option<&SingleResponse> {
        self.responses.iter().find(|s| s.cert_id.matches(cert, issuer))
    }

    fn signed_by(&self, cert: &Certificate) -> bool {
        cert.public_key.as_ref().is_some_and(|k| self.signature_algorithm.verify(k, &self.tbs, &self.signature))
    }

    /// Validates the response for `cert` (issued by `issuer`) at `now` and returns its status.
    ///
    /// Checks: the signature is by the issuer itself, or by a delegated responder certificate
    /// included in the response that the issuer signed directly, that carries the OCSPSigning
    /// EKU (anyExtendedKeyUsage does not count), allows digitalSignature when it has keyUsage,
    /// has no unsupported critical extension and is valid at `now`; a SingleResponse matches
    /// the CertID; producedAt and thisUpdate are not in the future, nextUpdate is not in the
    /// past (with [`CLOCK_SKEW_SECS`]), and without nextUpdate thisUpdate is at most
    /// `max_age_secs` old; the nonce equals `expected_nonce` when one is given.
    pub fn validate(&self, cert: &Certificate, issuer: &Certificate, now: i64, expected_nonce: Option<&[u8]>, max_age_secs: i64) -> Result<CertStatus, String> {
        if cert.issuer_raw != issuer.subject_raw {
            return Err("the issuer certificate does not match the certificate's issuer".into());
        }
        let issuer_key = issuer.public_key.as_ref().ok_or("unsupported issuer key")?;
        if !self.signed_by(issuer) {
            let authorized = self.certs.iter().filter_map(|d| Certificate::from_der(d).ok()).any(|r| {
                r.issuer_raw == issuer.subject_raw
                    && r.verify_signed_by(issuer_key)
                    && r.ext_key_usage.as_ref().is_some_and(|e| e.iter().any(|o| o == OID_EKU_OCSP_SIGNING))
                    && r.key_usage.is_none_or(|ku| ku & crate::x509::KU_DIGITAL_SIGNATURE != 0)
                    && r.unknown_critical_extensions.is_empty()
                    && now >= r.not_before
                    && now <= r.not_after
                    && self.signed_by(&r)
            });
            if !authorized {
                return Err("the OCSP response is not signed by the issuer or an authorized responder".into());
            }
        }
        let single = self.find(cert, issuer).ok_or("the OCSP response does not cover the certificate")?;
        let skew = CLOCK_SKEW_SECS;
        if self.produced_at > now.saturating_add(skew) || single.this_update > now.saturating_add(skew) {
            return Err("the OCSP response is not yet valid".into());
        }
        match single.next_update {
            Some(n) if n < now.saturating_sub(skew) => return Err("the OCSP response has expired (nextUpdate is in the past)".into()),
            None if single.this_update < now.saturating_sub(max_age_secs) => {
                return Err("the OCSP response has no nextUpdate and is too old".into())
            }
            _ => {}
        }
        if let Some(expected) = expected_nonce {
            match &self.nonce {
                Some(n) if n[..] == expected[..] => {}
                Some(_) => return Err("OCSP nonce mismatch".into()),
                None => return Err("the OCSP response has no nonce".into()),
            }
        }
        Ok(single.status.clone())
    }
}

/// A basic OCSP response signed by `signer` with `signer_key` (the issuer itself, or a
/// delegated responder whose certificate is passed in `include_certs`). The responder ID is
/// the SHA-1 key hash of `signer`. Every time field is GeneralizedTime.
pub fn build_response(
    responses: &[SingleResponse],
    signer: &Certificate,
    signer_key: &PrivateKey,
    include_certs: &[Vec<u8>],
    produced_at: i64,
    nonce: Option<&[u8]>,
) -> Vec<u8> {
    let mut singles = Vec::new();
    for s in responses {
        let status = match &s.status {
            CertStatus::Good => vec![0x80, 0],
            CertStatus::Revoked { time, reason } => {
                let mut inner = gtime(*time);
                if let Some(r) = reason {
                    inner.extend(asn1::explicit(0, &asn1::tlv(0x0a, &[*r])));
                }
                asn1::tlv(0xa1, &inner)
            }
            CertStatus::Unknown => vec![0x82, 0],
        };
        let mut single = vec![s.cert_id.to_der(), status, gtime(s.this_update)];
        if let Some(n) = s.next_update {
            single.push(asn1::explicit(0, &gtime(n)));
        }
        singles.push(asn1::seq(&single));
    }
    let mut tbs = vec![asn1::explicit(2, &asn1::octet_string(&key_hash(Md::Sha1, &signer.spki))), gtime(produced_at), asn1::seq(&singles)];
    if let Some(n) = nonce {
        tbs.push(asn1::explicit(1, &nonce_extensions(n)));
    }
    let tbs = asn1::seq(&tbs);
    let sig = crate::certgen::sign_with(signer_key, &tbs);
    let mut basic = vec![tbs, crate::certgen::sig_alg_for(signer_key), asn1::bit_string(&sig)];
    if !include_certs.is_empty() {
        basic.push(asn1::explicit(0, &asn1::seq(include_certs)));
    }
    let basic = asn1::seq(&basic);
    asn1::seq(&[asn1::tlv(0x0a, &[0]), asn1::explicit(0, &asn1::seq(&[asn1::oid(OID_OCSP_BASIC), asn1::octet_string(&basic)]))])
}

/// A response for one certificate signed by its issuer: the common stapling case.
pub fn build_simple_response(cert: &Certificate, issuer: &Certificate, issuer_key: &PrivateKey, status: CertStatus, this_update: i64, next_update: Option<i64>) -> Vec<u8> {
    let single = SingleResponse { cert_id: CertId::new(cert, issuer), status, this_update, next_update };
    build_response(&[single], issuer, issuer_key, &[], this_update, None)
}

/// An unsuccessful OCSPResponse (no responseBytes). `Successful` is not meaningful here.
pub fn build_error_response(status: ResponseStatus) -> Vec<u8> {
    asn1::seq(&[asn1::tlv(0x0a, &[status as u8])])
}
