//! Revocation against OpenSSL-made fixtures (`testdata/revocation`, see its README) and a
//! PKI generated with the crate's own certificate builder.

use simoom_tls::revocation::crl::Crl;
use simoom_tls::revocation::ocsp::{self, CertId, CertStatus, OcspRequest, OcspResponse, ResponderId};
use simoom_tls::revocation::testing::{MapFetcher, TestPki, INT_CRL_URL, INT_OCSP_URL};
use simoom_tls::revocation::{check_path, CrlMode, OcspMode, RevocationFetcher, RevocationPolicy, StapleSource, DEFAULT_MAX_AGE_SECS};
use simoom_tls::x509::{self, CertError, Certificate, RootStore};
use std::sync::Arc;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("../testdata/revocation/", $name)).as_slice()
    };
}

fn pem_cert(data: &[u8]) -> Certificate {
    Certificate::from_pem_all(data).unwrap().remove(0)
}

struct Fx {
    ca: Certificate,
    good: Certificate,
    revoked: Certificate,
    unknown: Certificate,
    /// A time at which every fixture is current (just after the responses were made).
    now: i64,
}

fn fx() -> Fx {
    let now = OcspResponse::parse(fixture!("resp-good-issuer.der")).unwrap().produced_at + 60;
    Fx {
        ca: pem_cert(fixture!("ca.pem")),
        good: pem_cert(fixture!("leaf-good.pem")),
        revoked: pem_cert(fixture!("leaf-revoked.pem")),
        unknown: pem_cert(fixture!("leaf-unknown.pem")),
        now,
    }
}

const CRL_URL: &str = "http://crl.revocation.test/ca.crl";

#[test]
fn openssl_certificate_locators() {
    let f = fx();
    assert_eq!(f.good.serial, vec![0x10, 0x01]);
    assert_eq!(f.good.crl_distribution_points, vec![CRL_URL.to_string()]);
    assert_eq!(f.good.ocsp_urls, vec!["http://ocsp.revocation.test/".to_string()]);
    assert_eq!(f.good.ca_issuers_urls, vec!["http://ca.revocation.test/ca.der".to_string()]);
    assert!(f.ca.ocsp_urls.is_empty());
}

#[test]
fn openssl_crls() {
    let f = fx();
    let der = Crl::from_der(fixture!("crl-sha256.der")).unwrap();
    let pem = Crl::parse_all(fixture!("crl-sha256.pem")).unwrap().remove(0);
    assert_eq!(der.der, pem.der);
    for crl in [&der, &pem] {
        assert_eq!(crl.version, 2);
        assert!(crl.verify_signature(&f.ca));
        assert!(crl.covers(&f.good) && crl.covers(&f.revoked));
        assert!(crl.is_fresh(f.now, DEFAULT_MAX_AGE_SECS));
        assert!(crl.authority_key_id.as_ref().is_some_and(|k| k.len() == 20));
        assert!(crl.crl_number.is_some());
        assert_eq!(crl.revoked().len(), 1);
        let e = crl.is_revoked(&f.revoked.serial).unwrap();
        assert_eq!(e.reason, Some(1));
        assert_eq!(e.revocation_time, 1_767_225_600); // 2026-01-01
        assert!(crl.is_revoked(&f.good.serial).is_none());
        // expired and not yet valid
        assert!(!crl.is_fresh(crl.next_update.unwrap() + 86400, DEFAULT_MAX_AGE_SECS));
        assert!(!crl.is_fresh(crl.this_update - 86400, DEFAULT_MAX_AGE_SECS));
    }
    // the CA's CRL is not signed by the RSA CA, and the RSA CA's CRL does not cover these leaves
    let rsa_ca = pem_cert(fixture!("rsa-ca.pem"));
    assert!(!der.verify_signature(&rsa_ca));
    let rsa = Crl::from_der(fixture!("crl-rsa-sha1.der")).unwrap();
    assert!(rsa.verify_signature(&rsa_ca), "sha1WithRSAEncryption");
    assert!(!rsa.verify_signature(&f.ca));
    assert!(!rsa.covers(&f.revoked));
    let ec1 = Crl::from_der(fixture!("crl-ecdsa-sha1.der")).unwrap();
    assert!(ec1.verify_signature(&f.ca), "ecdsa-with-SHA1");
    assert!(ec1.is_revoked(&f.revoked.serial).is_some());
    // a flipped bit in the signed part
    let mut bad = fixture!("crl-sha256.der").to_vec();
    bad[60] ^= 1;
    assert!(Crl::from_der(&bad).map(|c| !c.verify_signature(&f.ca)).unwrap_or(true));
}

#[test]
fn openssl_ocsp_requests() {
    let f = fx();
    let req = OcspRequest::parse(fixture!("req-good.der")).unwrap();
    assert_eq!(req.cert_ids, vec![CertId::new(&f.good, &f.ca)]);
    assert!(req.nonce.as_ref().is_some_and(|n| !n.is_empty()));
    assert_eq!(OcspRequest::parse(fixture!("req-good-nononce.der")).unwrap().nonce, None);
    // our request is byte-identical to OpenSSL's
    assert_eq!(ocsp::build_request(&f.good, &f.ca, None), fixture!("req-good-nononce.der"));
    let nonce = req.nonce.unwrap();
    assert_eq!(ocsp::build_request(&f.good, &f.ca, Some(&nonce)), fixture!("req-good.der"));
}

#[test]
fn openssl_ocsp_responses() {
    let f = fx();
    let v = |resp: &[u8], cert: &Certificate| OcspResponse::parse(resp).unwrap().validate(cert, &f.ca, f.now, None, DEFAULT_MAX_AGE_SECS);
    assert_eq!(v(fixture!("resp-good-issuer.der"), &f.good), Ok(CertStatus::Good));
    assert_eq!(v(fixture!("resp-revoked-issuer.der"), &f.revoked), Ok(CertStatus::Revoked { time: 1_767_225_600, reason: Some(1) }));
    assert_eq!(v(fixture!("resp-unknown-issuer.der"), &f.unknown), Ok(CertStatus::Unknown));
    assert_eq!(v(fixture!("resp-good-delegated.der"), &f.good), Ok(CertStatus::Good));
    assert_eq!(v(fixture!("resp-good-nononce.der"), &f.good), Ok(CertStatus::Good));
    assert!(matches!(v(fixture!("resp-revoked-delegated.der"), &f.revoked), Ok(CertStatus::Revoked { reason: Some(1), .. })));
    // a responder without the OCSPSigning EKU
    let e = v(fixture!("resp-good-noeku.der"), &f.good).unwrap_err();
    assert!(e.contains("authorized responder"), "{e}");
    // CertID mismatch
    assert!(v(fixture!("resp-good-issuer.der"), &f.revoked).unwrap_err().contains("does not cover"));
    // responder ID by name, certificates included for the delegated one
    let r = OcspResponse::parse(fixture!("resp-good-delegated.der")).unwrap();
    assert!(matches!(r.responder_id, ResponderId::ByName(_)));
    assert_eq!(r.certs.len(), 1);
    // the nonce is echoed
    let req_nonce = OcspRequest::parse(fixture!("req-good.der")).unwrap().nonce.unwrap();
    let r = OcspResponse::parse(fixture!("resp-good-issuer.der")).unwrap();
    assert_eq!(r.nonce.as_deref(), Some(req_nonce.as_slice()));
    assert!(r.validate(&f.good, &f.ca, f.now, Some(&req_nonce), DEFAULT_MAX_AGE_SECS).is_ok());
    assert!(r.validate(&f.good, &f.ca, f.now, Some(b"another nonce"), DEFAULT_MAX_AGE_SECS).unwrap_err().contains("nonce"));
    // expired and not yet valid
    let next = r.responses[0].next_update.unwrap();
    assert!(r.validate(&f.good, &f.ca, next + 86400, None, DEFAULT_MAX_AGE_SECS).unwrap_err().contains("expired"));
    assert!(r.validate(&f.good, &f.ca, r.produced_at - 86400, None, DEFAULT_MAX_AGE_SECS).unwrap_err().contains("not yet valid"));
}

#[test]
fn openssl_check_path() {
    let f = fx();
    let path = |leaf: &Certificate| vec![leaf.clone(), f.ca.clone()];
    // the leaves verify against the CA
    let mut roots = RootStore::empty();
    roots.add_pem(fixture!("ca.pem")).unwrap();
    let p = x509::verify_chain_path(std::slice::from_ref(&f.good.der), Some("leaf.revocation.test"), &roots, f.now, x509::OID_EKU_SERVER_AUTH).unwrap();
    assert_eq!(p.len(), 2);
    // stapled OCSP
    let req = RevocationPolicy::new().with_ocsp(OcspMode::Require);
    assert!(check_path(&path(&f.good), &req, f.now, Some(fixture!("resp-good-issuer.der"))).is_ok());
    assert!(check_path(&path(&f.good), &req, f.now, Some(fixture!("resp-good-delegated.der"))).is_ok());
    assert!(matches!(check_path(&path(&f.revoked), &req, f.now, Some(fixture!("resp-revoked-issuer.der"))), Err(CertError::Revoked { reason: Some(1), .. })));
    assert!(matches!(check_path(&path(&f.unknown), &req, f.now, Some(fixture!("resp-unknown-issuer.der"))), Err(CertError::RevocationUnknown { .. })));
    assert!(matches!(check_path(&path(&f.good), &req, f.now, Some(fixture!("resp-good-noeku.der"))), Err(CertError::RevocationUnknown { .. })));
    assert!(matches!(check_path(&path(&f.good), &req, f.now, None), Err(CertError::RevocationUnknown { .. })));
    // configured CRL
    let crl = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_crls(Crl::parse_all(fixture!("crl-sha256.pem")).unwrap());
    assert!(check_path(&path(&f.good), &crl, f.now, None).is_ok());
    assert!(matches!(check_path(&path(&f.revoked), &crl, f.now, None), Err(CertError::Revoked { reason: Some(1), .. })));
    // a SHA-1 signed CRL works the same way
    let crl1 = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_crls(vec![Crl::from_der(fixture!("crl-ecdsa-sha1.der")).unwrap()]);
    assert!(matches!(check_path(&path(&f.revoked), &crl1, f.now, None), Err(CertError::Revoked { .. })));
    // fetched through the leaf's CRL distribution point
    let fetcher = Arc::new(MapFetcher::new().with_crl(CRL_URL, fixture!("crl-sha256.der").to_vec()));
    let fetched = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_fetcher(fetcher.clone());
    assert!(check_path(&path(&f.good), &fetched, f.now, None).is_ok());
    assert!(matches!(check_path(&path(&f.revoked), &fetched, f.now, None), Err(CertError::Revoked { .. })));
    assert_eq!(fetcher.requests(), vec![CRL_URL.to_string()], "the second check used the cache");
}

/// Serves one canned OCSP response for every request.
struct Canned(&'static [u8]);
impl RevocationFetcher for Canned {
    fn fetch_crl(&self, _: &str) -> Option<Vec<u8>> {
        None
    }
    fn ocsp(&self, url: &str, request: &[u8]) -> Option<Vec<u8>> {
        assert_eq!(url, "http://ocsp.revocation.test/");
        OcspRequest::parse(request).ok()?;
        Some(self.0.to_vec())
    }
}

#[test]
fn openssl_online_ocsp() {
    let f = fx();
    let path = vec![f.good.clone(), f.ca.clone()];
    let pol = |r: &'static [u8]| RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_ocsp_online(true).with_fetcher(Arc::new(Canned(r)));
    // a response without a nonce is accepted (most responders do not echo one) ...
    assert!(check_path(&path, &pol(fixture!("resp-good-nononce.der")), f.now, None).is_ok());
    // ... unless the policy requires the nonce
    let mut strict = pol(fixture!("resp-good-nononce.der"));
    strict.require_ocsp_nonce = true;
    assert!(matches!(check_path(&path, &strict, f.now, None), Err(CertError::RevocationUnknown { .. })));
    // a replayed response carrying another request's nonce is refused
    let e = check_path(&path, &pol(fixture!("resp-good-issuer.der")), f.now, None).unwrap_err();
    assert!(e.to_string().contains("nonce mismatch"), "{e}");
    // an unsuccessful responder status counts as unavailable
    let e = check_path(&path, &pol(&[0x30, 0x03, 0x0a, 0x01, 0x03]), f.now, None).unwrap_err();
    assert!(e.to_string().contains("tryLater"), "{e}");
    assert!(check_path(&path, &pol(&[0x30, 0x03, 0x0a, 0x01, 0x03]).with_soft_fail(true), f.now, None).is_ok());
}

#[test]
fn generated_pki_end_to_end() {
    let now = 1_800_000_000;
    let p = TestPki::new(now);
    let mut roots = RootStore::empty();
    roots.add_der(&p.ca.cert_der).unwrap();
    let path = x509::verify_chain_path(&[p.leaf.cert_der.clone(), p.intermediate.cert_der.clone()], Some("leaf.test"), &roots, now, x509::OID_EKU_SERVER_AUTH).unwrap();
    // the server keeps a fresh staple; the client requires it and CRLs for the rest
    let staple = StapleSource::new();
    staple.set_checked(p.leaf_ocsp(CertStatus::Good), &p.leaf_cert, &p.int_cert, now).unwrap();
    let pol = RevocationPolicy::new()
        .with_ocsp(OcspMode::Require)
        .with_crl_mode(CrlMode::Require)
        .with_fetcher(Arc::new(MapFetcher::new().with_crl("http://crl.test/ca.crl", p.ca_crl(&[]))));
    let s = staple.get().unwrap();
    assert!(check_path(&path, &pol, now, Some(&s)).is_ok());
    // the intermediate gets revoked: a new CRL (new cache, as after its nextUpdate)
    let pol = RevocationPolicy::new()
        .with_crl_mode(CrlMode::Require)
        .with_ocsp_online(true)
        .with_fetcher(Arc::new(
            MapFetcher::new()
                .with_crl("http://crl.test/ca.crl", p.ca_crl(&[&p.int_cert.serial]))
                .with_crl(INT_CRL_URL, p.int_crl(&[]))
                .with_responder(INT_OCSP_URL, &p.responder_cert, &p.responder.key, &p.int_cert, &[], now),
        ));
    assert!(matches!(check_path(&path, &pol, now, None), Err(CertError::Revoked { subject, .. }) if subject.contains("Intermediate")));
}
