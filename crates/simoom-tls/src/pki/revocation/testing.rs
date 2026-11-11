//! Helpers for tests and development: certificates with CRL distribution points, AIA OCSP
//! URLs and the OCSPSigning EKU, a ready-made PKI, and an in-memory [`RevocationFetcher`].
//! Times are passed in; nothing here reads the clock.

use super::crl::CrlBuilder;
use super::ocsp::{build_response, CertId, CertStatus, OcspRequest, SingleResponse};
use super::{ext_der, RevocationFetcher};
use crate::asn1;
use crate::certgen::{sig_alg_for, sign_with, SelfSigned};
use crate::crypto::rng;
use crate::keys::{EcCurve, PrivateKey};
use crate::pem;
use crate::x509::{self, Certificate};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

pub use super::ocsp::OID_EKU_OCSP_SIGNING;

/// What [`issue`] puts into a certificate.
#[derive(Clone, Debug)]
pub struct TestCert {
    pub common_name: String,
    /// SAN entries (DNS names or IP addresses).
    pub sans: Vec<String>,
    pub is_ca: bool,
    /// Extended key usage OIDs (empty = no extension).
    pub ext_key_usage: Vec<String>,
    /// keyUsage BIT STRING contents including the unused-bits octet (None = the default:
    /// keyCertSign and cRLSign for CAs, digitalSignature otherwise).
    pub key_usage: Option<Vec<u8>>,
    pub crl_urls: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    /// Serial number (big-endian, positive); random when None.
    pub serial: Option<Vec<u8>>,
}

impl TestCert {
    fn base(cn: &str, now: i64) -> TestCert {
        TestCert {
            common_name: cn.to_string(),
            sans: Vec::new(),
            is_ca: false,
            ext_key_usage: Vec::new(),
            key_usage: None,
            crl_urls: Vec::new(),
            ocsp_urls: Vec::new(),
            not_before: now - 86400,
            not_after: now + 365 * 86400,
            serial: None,
        }
    }

    pub fn ca(cn: &str, now: i64) -> TestCert {
        TestCert { is_ca: true, ..TestCert::base(cn, now) }
    }

    /// A TLS server certificate for `name`.
    pub fn server(name: &str, now: i64) -> TestCert {
        TestCert { sans: vec![name.to_string()], ext_key_usage: vec![x509::OID_EKU_SERVER_AUTH.to_string()], ..TestCert::base(name, now) }
    }

    /// A delegated OCSP responder certificate (OCSPSigning EKU, digitalSignature).
    pub fn ocsp_responder(cn: &str, now: i64) -> TestCert {
        TestCert { ext_key_usage: vec![OID_EKU_OCSP_SIGNING.to_string()], ..TestCert::base(cn, now) }
    }
}

fn name_der(cn: &str) -> Vec<u8> {
    asn1::seq(&[asn1::set(&[asn1::seq(&[asn1::oid("2.5.4.3"), asn1::tlv(asn1::TAG_UTF8_STRING, cn.as_bytes())])])])
}

/// A fresh P-256 key.
pub fn ec_key() -> PrivateKey {
    PrivateKey::generate_ec(EcCurve::P256)
}

/// Issues a certificate for `key` signed by `issuer` (self-signed when `None`).
pub fn issue(p: &TestCert, key: PrivateKey, issuer: Option<&SelfSigned>) -> SelfSigned {
    let serial = p.serial.clone().unwrap_or_else(|| {
        let mut s = rng::bytes(16);
        s[0] &= 0x7f;
        s[0] |= 0x01;
        s
    });
    let (issuer_name, signer) = match issuer {
        Some(i) => (Certificate::from_der(&i.cert_der).expect("issuer certificate").subject_raw, &i.key),
        None => (name_der(&p.common_name), &key),
    };
    let sig_alg = sig_alg_for(signer);
    let mut exts = Vec::new();
    if !p.sans.is_empty() {
        let gns: Vec<Vec<u8>> = p
            .sans
            .iter()
            .map(|n| match n.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => asn1::tlv(0x87, &v4.octets()),
                Ok(IpAddr::V6(v6)) => asn1::tlv(0x87, &v6.octets()),
                Err(_) => asn1::tlv(0x82, n.as_bytes()),
            })
            .collect();
        exts.push(ext_der("2.5.29.17", false, &asn1::seq(&gns)));
    }
    if p.is_ca {
        exts.push(ext_der("2.5.29.19", true, &asn1::seq(&[asn1::tlv(asn1::TAG_BOOLEAN, &[0xff])])));
    } else {
        exts.push(ext_der("2.5.29.19", true, &asn1::seq(&[])));
    }
    let ku = p.key_usage.clone().unwrap_or_else(|| if p.is_ca { vec![0x01, 0x06] } else { vec![0x07, 0x80] });
    exts.push(ext_der("2.5.29.15", true, &asn1::tlv(asn1::TAG_BIT_STRING, &ku)));
    if !p.ext_key_usage.is_empty() {
        exts.push(ext_der("2.5.29.37", false, &asn1::seq(&p.ext_key_usage.iter().map(|o| asn1::oid(o)).collect::<Vec<_>>())));
    }
    if !p.crl_urls.is_empty() {
        let names: Vec<Vec<u8>> = p.crl_urls.iter().map(|u| asn1::tlv(0x86, u.as_bytes())).collect();
        let dp = asn1::seq(&[asn1::explicit(0, &asn1::explicit(0, &names.concat()))]);
        exts.push(ext_der("2.5.29.31", false, &asn1::seq(&[dp])));
    }
    if !p.ocsp_urls.is_empty() {
        let ads: Vec<Vec<u8>> = p.ocsp_urls.iter().map(|u| asn1::seq(&[asn1::oid("1.3.6.1.5.5.7.48.1"), asn1::tlv(0x86, u.as_bytes())])).collect();
        exts.push(ext_der("1.3.6.1.5.5.7.1.1", false, &asn1::seq(&ads)));
    }
    let tbs = asn1::seq(&[
        asn1::explicit(0, &asn1::uint(&[2])),
        asn1::tlv(asn1::TAG_INTEGER, &asn1_serial(&serial)),
        sig_alg.clone(),
        issuer_name,
        asn1::seq(&[asn1::time(p.not_before), asn1::time(p.not_after)]),
        name_der(&p.common_name),
        key.public_key().to_spki(),
        asn1::explicit(3, &asn1::seq(&exts)),
    ]);
    let sig = sign_with(signer, &tbs);
    let cert_der = asn1::seq(&[tbs, sig_alg, asn1::bit_string(&sig)]);
    let key_der = key.to_pkcs8();
    SelfSigned { cert_pem: pem::encode_pem("CERTIFICATE", &cert_der), key_pem: pem::encode_pem("PRIVATE KEY", &key_der), cert_der, key_der, key }
}

/// INTEGER contents for a positive serial given as big-endian bytes.
fn asn1_serial(s: &[u8]) -> Vec<u8> {
    let mut b = s;
    while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
        b = &b[1..];
    }
    let mut out = Vec::new();
    if b.first().is_some_and(|x| x & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(b);
    out
}

/// A CA, an intermediate, a leaf (`leaf.test`) and a delegated OCSP responder for the leaf
/// (issued by the intermediate), with parsed certificates.
#[derive(Clone, Debug)]
pub struct TestPki {
    pub now: i64,
    pub ca: SelfSigned,
    pub intermediate: SelfSigned,
    pub leaf: SelfSigned,
    pub responder: SelfSigned,
    pub ca_cert: Certificate,
    pub int_cert: Certificate,
    pub leaf_cert: Certificate,
    pub responder_cert: Certificate,
}

/// CRL distribution point of the CA (covers the intermediate).
pub const CA_CRL_URL: &str = "http://crl.test/ca.crl";
/// CRL distribution point of the intermediate (covers the leaf).
pub const INT_CRL_URL: &str = "http://crl.test/int.crl";
/// OCSP responder for certificates issued by the CA.
pub const CA_OCSP_URL: &str = "http://ocsp.test/ca";
/// OCSP responder for certificates issued by the intermediate.
pub const INT_OCSP_URL: &str = "http://ocsp.test/int";

impl TestPki {
    pub fn new(now: i64) -> TestPki {
        let ca = issue(&TestCert::ca("Revocation Test CA", now), ec_key(), None);
        let mut int = TestCert::ca("Revocation Test Intermediate", now);
        int.crl_urls = vec![CA_CRL_URL.into()];
        int.ocsp_urls = vec![CA_OCSP_URL.into()];
        let intermediate = issue(&int, ec_key(), Some(&ca));
        let mut leaf = TestCert::server("leaf.test", now);
        leaf.crl_urls = vec![INT_CRL_URL.into()];
        leaf.ocsp_urls = vec![INT_OCSP_URL.into()];
        let leaf = issue(&leaf, ec_key(), Some(&intermediate));
        let responder = issue(&TestCert::ocsp_responder("Revocation Test OCSP", now), ec_key(), Some(&intermediate));
        let p = |s: &SelfSigned| Certificate::from_der(&s.cert_der).expect("certificate");
        TestPki {
            now,
            ca_cert: p(&ca),
            int_cert: p(&intermediate),
            leaf_cert: p(&leaf),
            responder_cert: p(&responder),
            ca,
            intermediate,
            leaf,
            responder,
        }
    }

    /// The validated path leaf → intermediate → CA.
    pub fn path(&self) -> Vec<Certificate> {
        vec![self.leaf_cert.clone(), self.int_cert.clone(), self.ca_cert.clone()]
    }

    /// The CA's CRL (covers the intermediate), revoking `revoked` serials.
    pub fn ca_crl(&self, revoked: &[&[u8]]) -> Vec<u8> {
        let mut b = CrlBuilder::new(self.now - 3600, Some(self.now + 86400)).crl_number(1);
        for s in revoked {
            b = b.revoke(s, self.now - 600, Some(1));
        }
        b.sign(&self.ca_cert, &self.ca.key)
    }

    /// The intermediate's CRL (covers the leaf), revoking `revoked` serials.
    pub fn int_crl(&self, revoked: &[&[u8]]) -> Vec<u8> {
        let mut b = CrlBuilder::new(self.now - 3600, Some(self.now + 86400)).crl_number(1);
        for s in revoked {
            b = b.revoke(s, self.now - 600, Some(1));
        }
        b.sign(&self.int_cert, &self.intermediate.key)
    }

    /// An OCSP response for the leaf signed by the intermediate.
    pub fn leaf_ocsp(&self, status: CertStatus) -> Vec<u8> {
        let single = SingleResponse { cert_id: CertId::new(&self.leaf_cert, &self.int_cert), status, this_update: self.now - 60, next_update: Some(self.now + 3600) };
        build_response(&[single], &self.int_cert, &self.intermediate.key, &[], self.now - 60, None)
    }
}

/// An in-memory [`RevocationFetcher`]: CRLs by URL, and OCSP responders by URL that answer
/// with a fixed status per serial (signed by the given key), echoing the request nonce.
#[derive(Default)]
pub struct MapFetcher {
    pub crls: Mutex<HashMap<String, Vec<u8>>>,
    /// URL → (signer certificate, signer key, issuer certificate, status per serial, time).
    #[allow(clippy::type_complexity)]
    pub responders: Mutex<HashMap<String, (Certificate, PrivateKey, Certificate, HashMap<Vec<u8>, CertStatus>, i64)>>,
    /// URLs requested so far.
    pub log: Mutex<Vec<String>>,
}

impl std::fmt::Debug for MapFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MapFetcher")
    }
}

impl MapFetcher {
    pub fn new() -> MapFetcher {
        MapFetcher::default()
    }

    pub fn with_crl(self, url: &str, der: Vec<u8>) -> MapFetcher {
        self.crls.lock().unwrap().insert(url.to_string(), der);
        self
    }

    /// An OCSP responder at `url` signing with (`signer`, `key`) for certificates of `issuer`.
    pub fn with_responder(self, url: &str, signer: &Certificate, key: &PrivateKey, issuer: &Certificate, statuses: &[(&[u8], CertStatus)], now: i64) -> MapFetcher {
        let map = statuses.iter().map(|(s, st)| (s.to_vec(), st.clone())).collect();
        self.responders.lock().unwrap().insert(url.to_string(), (signer.clone(), key.clone(), issuer.clone(), map, now));
        self
    }

    pub fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl RevocationFetcher for MapFetcher {
    fn fetch_crl(&self, url: &str) -> Option<Vec<u8>> {
        self.log.lock().unwrap().push(url.to_string());
        self.crls.lock().unwrap().get(url).cloned()
    }

    fn ocsp(&self, url: &str, request_der: &[u8]) -> Option<Vec<u8>> {
        self.log.lock().unwrap().push(url.to_string());
        let req = OcspRequest::parse(request_der).ok()?;
        let responders = self.responders.lock().unwrap();
        let (signer, key, issuer, statuses, now) = responders.get(url)?;
        let include = if signer.der == issuer.der { Vec::new() } else { vec![signer.der.clone()] };
        let singles: Vec<SingleResponse> = req
            .cert_ids
            .iter()
            .map(|id| {
                let ours = CertId::for_issuer(issuer, &id.serial, id.hash);
                let status = if ours == *id { statuses.get(&id.serial).cloned().unwrap_or(CertStatus::Unknown) } else { CertStatus::Unknown };
                SingleResponse { cert_id: id.clone(), status, this_update: *now - 60, next_update: Some(*now + 3600) }
            })
            .collect();
        Some(build_response(&singles, signer, key, &include, *now - 60, req.nonce.as_deref()))
    }
}
