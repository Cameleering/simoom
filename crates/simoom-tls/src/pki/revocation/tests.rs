use super::crl::{Crl, CrlBuilder, CrlLimits, IssuingDistributionPoint};
use super::ocsp::{self, build_request, build_response, build_simple_response, CertId, CertStatus, OcspRequest, OcspResponse, ResponseStatus, SingleResponse};
use super::testing::{issue, ec_key, MapFetcher, TestCert, TestPki, INT_CRL_URL, INT_OCSP_URL, CA_CRL_URL, CA_OCSP_URL};
use super::*;
use crate::crypto::md::Md;
use crate::x509::{self, CertError, RootStore};

const NOW: i64 = 1_800_000_000;

fn pki() -> TestPki {
    TestPki::new(NOW)
}

// ------------------------------------------------------------------ x509 additions

#[test]
fn certificate_locators_are_parsed() {
    let p = pki();
    assert_eq!(p.leaf_cert.crl_distribution_points, vec![INT_CRL_URL.to_string()]);
    assert_eq!(p.leaf_cert.ocsp_urls, vec![INT_OCSP_URL.to_string()]);
    assert!(p.leaf_cert.ca_issuers_urls.is_empty());
    assert_eq!(p.int_cert.crl_distribution_points, vec![CA_CRL_URL.to_string()]);
    assert_eq!(p.int_cert.ocsp_urls, vec![CA_OCSP_URL.to_string()]);
    assert!(p.ca_cert.crl_distribution_points.is_empty());
}

#[test]
fn verify_chain_path_returns_leaf_to_anchor() {
    let p = pki();
    let mut roots = RootStore::empty();
    roots.add_der(&p.ca.cert_der).unwrap();
    let chain = vec![p.leaf.cert_der.clone(), p.intermediate.cert_der.clone()];
    let path = x509::verify_chain_path(&chain, Some("leaf.test"), &roots, NOW, x509::OID_EKU_SERVER_AUTH).unwrap();
    let ders: Vec<&[u8]> = path.iter().map(|c| c.der.as_slice()).collect();
    assert_eq!(ders, vec![&p.leaf.cert_der[..], &p.intermediate.cert_der[..], &p.ca.cert_der[..]]);
    // the old entry point is unchanged
    let leaf = x509::verify_chain(&chain, Some("leaf.test"), &roots, NOW, x509::OID_EKU_SERVER_AUTH).unwrap();
    assert_eq!(leaf.der, p.leaf.cert_der);
    // a pinned leaf is its own anchor
    let mut pinned = RootStore::empty();
    pinned.add_der(&p.leaf.cert_der).unwrap();
    let path = x509::verify_chain_path(&chain[..1], None, &pinned, NOW, x509::OID_EKU_SERVER_AUTH).unwrap();
    assert_eq!(path.len(), 1);
    // shuffled extra certificates are not part of the path
    let chain = vec![p.leaf.cert_der.clone(), p.responder.cert_der.clone(), p.intermediate.cert_der.clone()];
    assert_eq!(x509::verify_chain_path(&chain, None, &roots, NOW, x509::OID_EKU_SERVER_AUTH).unwrap().len(), 3);
}

#[test]
fn cert_error_display() {
    let e = CertError::Revoked { subject: "CN=x".into(), reason: Some(1) };
    assert_eq!(e.to_string(), "certificate revoked (reason 1): CN=x");
    let e = CertError::RevocationUnknown { subject: "CN=x".into(), why: "no CRL".into() };
    assert!(e.to_string().contains("no CRL"));
}

// ------------------------------------------------------------------ CRLs

#[test]
fn crl_build_parse_lookup() {
    let p = pki();
    let der = CrlBuilder::new(NOW - 10, Some(NOW + 100))
        .crl_number(7)
        .revoke(&p.leaf_cert.serial, NOW - 5, Some(1))
        .revoke(&[0x05], NOW - 5, None)
        .revoke(&[0x06], NOW - 5, Some(8))
        .sign(&p.int_cert, &p.intermediate.key);
    let crl = Crl::from_der(&der).unwrap();
    assert_eq!(crl.version, 2);
    assert_eq!(crl.crl_number, Some(vec![7]));
    assert_eq!(crl.this_update, NOW - 10);
    assert_eq!(crl.next_update, Some(NOW + 100));
    assert_eq!(crl.revoked().len(), 3);
    assert_eq!(crl.issuer.common_name(), Some("Revocation Test Intermediate"));
    let e = crl.is_revoked(&p.leaf_cert.serial).unwrap();
    assert_eq!((e.reason, e.revocation_time), (Some(1), NOW - 5));
    assert!(crl.is_revoked(&[0x05]).is_some());
    assert!(crl.is_revoked(&[0x06]).is_none(), "removeFromCRL does not count");
    assert!(crl.is_revoked(&[0x07]).is_none());
    assert!(crl.verify_signature(&p.int_cert));
    assert!(!crl.verify_signature(&p.ca_cert), "wrong issuer");
    assert!(crl.covers(&p.leaf_cert));
    assert!(!crl.covers(&p.int_cert));
    assert!(crl.is_fresh(NOW, DEFAULT_MAX_AGE_SECS));
    assert!(!crl.is_fresh(NOW + 100 + CLOCK_SKEW_SECS + 1, DEFAULT_MAX_AGE_SECS), "expired");
    assert!(!crl.is_fresh(NOW - 10 - CLOCK_SKEW_SECS - 1, DEFAULT_MAX_AGE_SECS), "not yet valid");
    // without nextUpdate: the maximum age applies
    let crl = Crl::from_der(&CrlBuilder::new(NOW - 1000, None).sign(&p.int_cert, &p.intermediate.key)).unwrap();
    assert!(crl.is_fresh(NOW, 2000));
    assert!(!crl.is_fresh(NOW, 500));
    // PEM
    let pem_text = crate::pem::encode_pem("X509 CRL", &der) + &crate::pem::encode_pem("X509 CRL", &der);
    assert_eq!(Crl::parse_all(pem_text.as_bytes()).unwrap().len(), 2);
    assert_eq!(Crl::parse_all(&der).unwrap().len(), 1);
    assert!(Crl::parse_all(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err());
}

#[test]
fn crl_signature_checks() {
    let p = pki();
    let der = p.int_crl(&[]);
    let mut bad = der.clone();
    let n = bad.len();
    bad[n - 3] ^= 1;
    assert!(!Crl::from_der(&bad).map(|c| c.verify_signature(&p.int_cert)).unwrap_or(false));
    // signed by a stranger that has the same name
    let mut tc = TestCert::ca("Revocation Test Intermediate", NOW);
    tc.serial = Some(vec![9]);
    let stranger = issue(&tc, ec_key(), None);
    let sc = x509::Certificate::from_der(&stranger.cert_der).unwrap();
    let forged = CrlBuilder::new(NOW - 10, Some(NOW + 100)).sign(&sc, &stranger.key);
    let crl = Crl::from_der(&forged).unwrap();
    assert!(crl.covers(&p.leaf_cert), "same issuer name");
    assert!(!crl.verify_signature(&p.int_cert));
    // an issuer whose keyUsage lacks cRLSign may not sign CRLs
    let mut tc = TestCert::ca("No CRL Sign", NOW);
    tc.key_usage = Some(vec![0x02, 0x04]); // keyCertSign only
    let nocrl = issue(&tc, ec_key(), None);
    let nc = x509::Certificate::from_der(&nocrl.cert_der).unwrap();
    let crl = Crl::from_der(&CrlBuilder::new(NOW, Some(NOW + 10)).sign(&nc, &nocrl.key)).unwrap();
    assert!(!crl.verify_signature(&nc));
}

#[test]
fn crl_extensions_that_are_refused() {
    let p = pki();
    let sign = |b: CrlBuilder| b.sign(&p.int_cert, &p.intermediate.key);
    let base = || CrlBuilder::new(NOW - 10, Some(NOW + 100));
    // unknown critical extension
    let e = Crl::from_der(&sign(base().extension("1.2.3.4", true, asn1::tlv(asn1::TAG_NULL, &[])))).unwrap_err();
    assert!(e.contains("unsupported critical CRL extension 1.2.3.4"), "{e}");
    // unknown non-critical is fine
    assert!(Crl::from_der(&sign(base().extension("1.2.3.4", false, asn1::tlv(asn1::TAG_NULL, &[])))).is_ok());
    // delta CRL
    let e = Crl::from_der(&sign(base().extension("2.5.29.27", true, asn1::uint(&[1])))).unwrap_err();
    assert!(e.contains("delta"), "{e}");
    // indirect CRL flag in the IDP
    let idp = asn1::seq(&[asn1::tlv(0x84, &[0xff])]);
    assert!(Crl::from_der(&sign(base().extension("2.5.29.28", true, idp))).unwrap_err().contains("indirect"));
    // onlySomeReasons
    let idp = asn1::seq(&[asn1::tlv(0x83, &[0x07, 0x80])]);
    assert!(Crl::from_der(&sign(base().extension("2.5.29.28", true, idp))).unwrap_err().contains("onlySomeReasons"));
    // duplicate extension
    let e = Crl::from_der(&sign(base().crl_number(1).extension("2.5.29.20", false, asn1::uint(&[2])))).unwrap_err();
    assert!(e.contains("duplicate"), "{e}");
    // certificateIssuer entry extension (indirect CRL)
    let tbs = asn1::seq(&[
        asn1::uint(&[1]),
        crate::certgen::sig_alg_for(&p.intermediate.key),
        p.int_cert.subject_raw.clone(),
        asn1::time(NOW),
        asn1::seq(&[asn1::seq(&[asn1::uint(&[5]), asn1::time(NOW), asn1::seq(&[ext_der("2.5.29.29", true, &asn1::seq(&[]))])])]),
    ]);
    let sig = crate::certgen::sign_with(&p.intermediate.key, &tbs);
    let der = asn1::seq(&[tbs, crate::certgen::sig_alg_for(&p.intermediate.key), asn1::bit_string(&sig)]);
    assert!(Crl::from_der(&der).unwrap_err().contains("certificateIssuer"));
}

#[test]
fn crl_issuing_distribution_point_scope() {
    let p = pki();
    let mut b = CrlBuilder::new(NOW - 10, Some(NOW + 100));
    b.issuing_distribution_point = Some(IssuingDistributionPoint { full_names: vec![INT_CRL_URL.into()], only_user_certs: true, only_ca_certs: false });
    let crl = Crl::from_der(&b.sign(&p.int_cert, &p.intermediate.key)).unwrap();
    assert_eq!(crl.issuing_distribution_point.as_ref().unwrap().full_names, vec![INT_CRL_URL.to_string()]);
    assert!(crl.covers(&p.leaf_cert));
    // another distribution point
    b.issuing_distribution_point = Some(IssuingDistributionPoint { full_names: vec!["http://crl.test/other.crl".into()], ..Default::default() });
    let crl = Crl::from_der(&b.sign(&p.int_cert, &p.intermediate.key)).unwrap();
    assert!(!crl.covers(&p.leaf_cert));
    // CA certificates only
    b.issuing_distribution_point = Some(IssuingDistributionPoint { full_names: vec![], only_user_certs: false, only_ca_certs: true });
    let crl = Crl::from_der(&b.sign(&p.int_cert, &p.intermediate.key)).unwrap();
    assert!(!crl.covers(&p.leaf_cert));
    let ca_crl = Crl::from_der(&{
        let mut b = CrlBuilder::new(NOW - 10, Some(NOW + 100));
        b.issuing_distribution_point = Some(IssuingDistributionPoint { full_names: vec![], only_user_certs: false, only_ca_certs: true });
        b.sign(&p.ca_cert, &p.ca.key)
    })
    .unwrap();
    assert!(ca_crl.covers(&p.int_cert));
}

#[test]
fn crl_limits() {
    let p = pki();
    let mut b = CrlBuilder::new(NOW - 10, Some(NOW + 100));
    for i in 0..50u32 {
        b = b.revoke(&(i + 1).to_be_bytes(), NOW - 5, None);
    }
    let der = b.sign(&p.int_cert, &p.intermediate.key);
    assert!(Crl::from_der_with_limits(&der, &CrlLimits { max_size: 1 << 20, max_entries: 50 }).is_ok());
    assert!(Crl::from_der_with_limits(&der, &CrlLimits { max_size: 1 << 20, max_entries: 49 }).unwrap_err().contains("more than 49"));
    assert!(Crl::from_der_with_limits(&der, &CrlLimits { max_size: der.len() - 1, max_entries: 100 }).unwrap_err().contains("exceeds"));
}

#[test]
fn crl_hostile_inputs() {
    // claimed lengths far beyond the input, deep nesting, empty and truncated encodings
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x30],
        vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
        vec![0x30, 0x83, 0x10, 0x00, 0x00, 0x30, 0x00],
        [vec![0x30, 0x80], vec![0; 10]].concat(),
        std::iter::repeat_n([0x30u8, 0x02], 1000).flatten().collect(),
        asn1::seq(&[asn1::seq(&[asn1::uint(&[1]), asn1::seq(&[asn1::oid("1.2.840.10045.4.3.2")]), asn1::seq(&[]), asn1::time(0), asn1::seq(&[asn1::seq(&[])])])]),
    ];
    for i in &inputs {
        assert!(Crl::from_der(i).is_err());
    }
    // a huge revoked list of tiny entries is cut off by the entry limit
    let entry = asn1::seq(&[asn1::uint(&[1]), asn1::time(0)]);
    let list = asn1::seq(&vec![entry; 2000]);
    let tbs = asn1::seq(&[asn1::uint(&[1]), asn1::seq(&[asn1::oid("1.2.840.10045.4.3.2")]), asn1::seq(&[]), asn1::time(0), list]);
    let der = asn1::seq(&[tbs, asn1::seq(&[asn1::oid("1.2.840.10045.4.3.2")]), asn1::bit_string(&[0])]);
    assert!(Crl::from_der_with_limits(&der, &CrlLimits { max_size: 1 << 20, max_entries: 1000 }).unwrap_err().contains("more than 1000"));
    assert!(Crl::from_der(&der).is_ok(), "parses with the default limit (signature not checked yet)");
}

// ------------------------------------------------------------------ OCSP

#[test]
fn ocsp_request_roundtrip() {
    let p = pki();
    let req = build_request(&p.leaf_cert, &p.int_cert, Some(b"0123456789abcdef"));
    let parsed = OcspRequest::parse(&req).unwrap();
    assert_eq!(parsed.cert_ids, vec![CertId::new(&p.leaf_cert, &p.int_cert)]);
    assert_eq!(parsed.nonce.as_deref(), Some(&b"0123456789abcdef"[..]));
    assert!(parsed.cert_ids[0].matches(&p.leaf_cert, &p.int_cert));
    assert!(!parsed.cert_ids[0].matches(&p.int_cert, &p.ca_cert));
    let req = build_request(&p.leaf_cert, &p.int_cert, None);
    assert_eq!(OcspRequest::parse(&req).unwrap().nonce, None);
    let id256 = CertId::with_hash(&p.leaf_cert, &p.int_cert, Md::Sha256);
    assert_eq!(id256.issuer_name_hash.len(), 32);
    assert!(id256.matches(&p.leaf_cert, &p.int_cert));
}

#[test]
fn ocsp_issuer_signed() {
    let p = pki();
    let good = p.leaf_ocsp(CertStatus::Good);
    let r = OcspResponse::parse(&good).unwrap();
    assert!(matches!(r.responder_id, ocsp::ResponderId::ByKey(ref k) if k.len() == 20));
    assert_eq!(r.validate(&p.leaf_cert, &p.int_cert, NOW, None, DEFAULT_MAX_AGE_SECS), Ok(CertStatus::Good));
    // expired and not yet valid
    assert!(r.validate(&p.leaf_cert, &p.int_cert, NOW + 3600 + CLOCK_SKEW_SECS + 1, None, DEFAULT_MAX_AGE_SECS).unwrap_err().contains("expired"));
    assert!(r.validate(&p.leaf_cert, &p.int_cert, NOW - 60 - CLOCK_SKEW_SECS - 1, None, DEFAULT_MAX_AGE_SECS).unwrap_err().contains("not yet valid"));
    // CertID mismatch: another certificate, or the wrong issuer
    let other = issue(&TestCert::server("other.test", NOW), ec_key(), Some(&p.intermediate));
    let oc = x509::Certificate::from_der(&other.cert_der).unwrap();
    assert!(r.validate(&oc, &p.int_cert, NOW, None, DEFAULT_MAX_AGE_SECS).unwrap_err().contains("does not cover"));
    assert!(r.validate(&p.leaf_cert, &p.ca_cert, NOW, None, DEFAULT_MAX_AGE_SECS).is_err());
    // revoked and unknown
    let rv = OcspResponse::parse(&p.leaf_ocsp(CertStatus::Revoked { time: NOW - 100, reason: Some(4) })).unwrap();
    assert_eq!(rv.validate(&p.leaf_cert, &p.int_cert, NOW, None, DEFAULT_MAX_AGE_SECS), Ok(CertStatus::Revoked { time: NOW - 100, reason: Some(4) }));
    let un = OcspResponse::parse(&p.leaf_ocsp(CertStatus::Unknown)).unwrap();
    assert_eq!(un.validate(&p.leaf_cert, &p.int_cert, NOW, None, DEFAULT_MAX_AGE_SECS), Ok(CertStatus::Unknown));
    // no nextUpdate: max age
    let nn = build_simple_response(&p.leaf_cert, &p.int_cert, &p.intermediate.key, CertStatus::Good, NOW - 1000, None);
    let nn = OcspResponse::parse(&nn).unwrap();
    assert!(nn.validate(&p.leaf_cert, &p.int_cert, NOW, None, 2000).is_ok());
    assert!(nn.validate(&p.leaf_cert, &p.int_cert, NOW, None, 500).unwrap_err().contains("too old"));
    // tampered signature
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 3] ^= 1;
    assert!(OcspResponse::parse(&bad).unwrap().validate(&p.leaf_cert, &p.int_cert, NOW, None, DEFAULT_MAX_AGE_SECS).is_err());
}

#[test]
fn ocsp_wrong_signer_and_delegation() {
    let p = pki();
    let single = |status| SingleResponse { cert_id: CertId::new(&p.leaf_cert, &p.int_cert), status, this_update: NOW - 60, next_update: Some(NOW + 3600) };
    let check = |der: &[u8]| OcspResponse::parse(der).unwrap().validate(&p.leaf_cert, &p.int_cert, NOW, None, DEFAULT_MAX_AGE_SECS);
    // signed by a stranger
    let stranger = issue(&TestCert::ca("Stranger", NOW), ec_key(), None);
    let sc = x509::Certificate::from_der(&stranger.cert_der).unwrap();
    assert!(check(&build_response(&[single(CertStatus::Good)], &sc, &stranger.key, std::slice::from_ref(&stranger.cert_der), NOW, None)).is_err());
    // signed by the CA (the issuer's issuer)
    assert!(check(&build_response(&[single(CertStatus::Good)], &p.ca_cert, &p.ca.key, &[], NOW, None)).is_err());
    // a delegated responder with OCSPSigning, included
    let ok = build_response(&[single(CertStatus::Good)], &p.responder_cert, &p.responder.key, std::slice::from_ref(&p.responder.cert_der), NOW, None);
    assert_eq!(check(&ok), Ok(CertStatus::Good));
    // ... but not included in the response
    assert!(check(&build_response(&[single(CertStatus::Good)], &p.responder_cert, &p.responder.key, &[], NOW, None)).is_err());
    // a delegated responder without the EKU
    let mut tc = TestCert::ocsp_responder("No EKU", NOW);
    tc.ext_key_usage = vec![x509::OID_EKU_SERVER_AUTH.into()];
    let noeku = issue(&tc, ec_key(), Some(&p.intermediate));
    let nc = x509::Certificate::from_der(&noeku.cert_der).unwrap();
    let e = check(&build_response(&[single(CertStatus::Good)], &nc, &noeku.key, std::slice::from_ref(&noeku.cert_der), NOW, None)).unwrap_err();
    assert!(e.contains("authorized responder"), "{e}");
    // anyExtendedKeyUsage does not authorize
    tc.ext_key_usage = vec!["2.5.29.37.0".into()];
    let anyeku = issue(&tc, ec_key(), Some(&p.intermediate));
    let ac = x509::Certificate::from_der(&anyeku.cert_der).unwrap();
    assert!(check(&build_response(&[single(CertStatus::Good)], &ac, &anyeku.key, std::slice::from_ref(&anyeku.cert_der), NOW, None)).is_err());
    // an expired delegated responder
    let mut tc = TestCert::ocsp_responder("Expired", NOW);
    tc.not_after = NOW - 10;
    let exp = issue(&tc, ec_key(), Some(&p.intermediate));
    let ec = x509::Certificate::from_der(&exp.cert_der).unwrap();
    assert!(check(&build_response(&[single(CertStatus::Good)], &ec, &exp.key, std::slice::from_ref(&exp.cert_der), NOW, None)).is_err());
    // a responder with OCSPSigning issued by another CA
    let other_resp = issue(&TestCert::ocsp_responder("Other", NOW), ec_key(), Some(&p.ca));
    let orc = x509::Certificate::from_der(&other_resp.cert_der).unwrap();
    assert!(check(&build_response(&[single(CertStatus::Good)], &orc, &other_resp.key, std::slice::from_ref(&other_resp.cert_der), NOW, None)).is_err());
}

#[test]
fn ocsp_nonce() {
    let p = pki();
    let single = SingleResponse { cert_id: CertId::new(&p.leaf_cert, &p.int_cert), status: CertStatus::Good, this_update: NOW - 60, next_update: Some(NOW + 3600) };
    let der = build_response(std::slice::from_ref(&single), &p.int_cert, &p.intermediate.key, &[], NOW, Some(b"nonce-1"));
    let r = OcspResponse::parse(&der).unwrap();
    assert_eq!(r.nonce.as_deref(), Some(&b"nonce-1"[..]));
    assert!(r.validate(&p.leaf_cert, &p.int_cert, NOW, Some(b"nonce-1"), DEFAULT_MAX_AGE_SECS).is_ok());
    assert!(r.validate(&p.leaf_cert, &p.int_cert, NOW, Some(b"nonce-2"), DEFAULT_MAX_AGE_SECS).unwrap_err().contains("nonce"));
    let without = OcspResponse::parse(&build_response(&[single], &p.int_cert, &p.intermediate.key, &[], NOW, None)).unwrap();
    assert!(without.validate(&p.leaf_cert, &p.int_cert, NOW, Some(b"nonce-1"), DEFAULT_MAX_AGE_SECS).unwrap_err().contains("no nonce"));
}

#[test]
fn ocsp_error_statuses_and_critical_extensions() {
    let e = OcspResponse::parse(&ocsp::build_error_response(ResponseStatus::TryLater)).unwrap_err();
    assert!(e.contains("tryLater"), "{e}");
    assert_eq!(ocsp::response_status(&ocsp::build_error_response(ResponseStatus::Unauthorized)), Ok(ResponseStatus::Unauthorized));
    assert!(OcspResponse::parse(&asn1::seq(&[asn1::tlv(0x0a, &[4])])).is_err());
    // an unknown critical response extension
    let p = pki();
    let single = asn1::seq(&[CertId::new(&p.leaf_cert, &p.int_cert).to_der(), vec![0x80, 0], gtime(NOW)]);
    let tbs = asn1::seq(&[
        asn1::explicit(2, &asn1::octet_string(&[0; 20])),
        gtime(NOW),
        asn1::seq(&[single]),
        asn1::explicit(1, &asn1::seq(&[ext_der("1.2.3.4", true, &[5, 0])])),
    ]);
    let sig = crate::certgen::sign_with(&p.intermediate.key, &tbs);
    let basic = asn1::seq(&[tbs, crate::certgen::sig_alg_for(&p.intermediate.key), asn1::bit_string(&sig)]);
    let der = asn1::seq(&[asn1::tlv(0x0a, &[0]), asn1::explicit(0, &asn1::seq(&[asn1::oid(ocsp::OID_OCSP_BASIC), asn1::octet_string(&basic)]))]);
    assert!(OcspResponse::parse(&der).unwrap_err().contains("1.2.3.4"));
    // too large
    assert!(OcspResponse::parse(&vec![0x30; ocsp::MAX_OCSP_SIZE + 1]).unwrap_err().contains("too large"));
}

// ------------------------------------------------------------------ check_path

#[test]
fn check_path_off_and_trivial() {
    let p = pki();
    assert!(check_path(&p.path(), &RevocationPolicy::new(), NOW, None).is_ok());
    let strict = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_ocsp(OcspMode::Require);
    assert!(check_path(&p.path()[2..], &strict, NOW, None).is_ok(), "an anchor alone is not checked");
}

#[test]
fn check_path_configured_crls() {
    let p = pki();
    let crls = |r: &[&[u8]]| vec![Crl::from_der(&p.int_crl(r)).unwrap(), Crl::from_der(&p.ca_crl(&[])).unwrap()];
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_crls(crls(&[]));
    assert!(check_path(&p.path(), &pol, NOW, None).is_ok());
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::IfAvailable).with_crls(crls(&[&p.leaf_cert.serial]));
    assert_eq!(check_path(&p.path(), &pol, NOW, None), Err(CertError::Revoked { subject: p.leaf_cert.subject.to_string(), reason: Some(1) }));
    // the intermediate revoked by the CA
    let pol = RevocationPolicy::new()
        .with_crl_mode(CrlMode::IfAvailable)
        .with_crls(vec![Crl::from_der(&p.ca_crl(&[&p.int_cert.serial])).unwrap()]);
    assert!(matches!(check_path(&p.path(), &pol, NOW, None), Err(CertError::Revoked { subject, .. }) if subject.contains("Intermediate")));
    // Require: the CA's CRL is missing, so the intermediate has no status
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_crls(vec![Crl::from_der(&p.int_crl(&[])).unwrap()]);
    assert!(matches!(check_path(&p.path(), &pol, NOW, None), Err(CertError::RevocationUnknown { subject, .. }) if subject.contains("Intermediate")));
    // ... soft fail accepts that, IfAvailable too
    assert!(check_path(&p.path(), &pol.clone().with_soft_fail(true), NOW, None).is_ok());
    assert!(check_path(&p.path(), &pol.clone().with_crl_mode(CrlMode::IfAvailable), NOW, None).is_ok());
    // expired CRLs do not count as a status, but still prove a revocation
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_crls(crls(&[]));
    assert!(matches!(check_path(&p.path(), &pol, NOW + 2 * 86400, None), Err(CertError::RevocationUnknown { .. })));
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_crls(crls(&[&p.leaf_cert.serial]));
    assert!(matches!(check_path(&p.path(), &pol, NOW + 2 * 86400, None), Err(CertError::Revoked { .. })));
    // a not yet valid CRL
    let future = CrlBuilder::new(NOW + 3600, Some(NOW + 7200)).sign(&p.int_cert, &p.intermediate.key);
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_crls(vec![Crl::from_der(&future).unwrap(), Crl::from_der(&p.ca_crl(&[])).unwrap()]);
    assert!(matches!(check_path(&p.path(), &pol, NOW, None), Err(CertError::RevocationUnknown { .. })));
    // a CRL signed by the wrong key is ignored, even when it lists the leaf
    let stranger = issue(&TestCert::ca("Revocation Test Intermediate", NOW), ec_key(), None);
    let sc = x509::Certificate::from_der(&stranger.cert_der).unwrap();
    let forged = CrlBuilder::new(NOW - 10, Some(NOW + 100)).revoke(&p.leaf_cert.serial, NOW, None).sign(&sc, &stranger.key);
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::IfAvailable).with_crls(vec![Crl::from_der(&forged).unwrap()]);
    assert!(check_path(&p.path(), &pol, NOW, None).is_ok());
    assert!(matches!(check_path(&p.path(), &pol.with_crl_mode(CrlMode::Require), NOW, None), Err(CertError::RevocationUnknown { .. })));
}

#[test]
fn check_path_stapled_ocsp() {
    let p = pki();
    let good = p.leaf_ocsp(CertStatus::Good);
    let revoked = p.leaf_ocsp(CertStatus::Revoked { time: NOW - 10, reason: Some(1) });
    let unknown_st = p.leaf_ocsp(CertStatus::Unknown);
    let req = RevocationPolicy::new().with_ocsp(OcspMode::Require);
    let opt = RevocationPolicy::new().with_ocsp(OcspMode::Request);
    assert!(check_path(&p.path(), &req, NOW, Some(&good)).is_ok());
    assert!(matches!(check_path(&p.path(), &req, NOW, None), Err(CertError::RevocationUnknown { .. })));
    assert!(matches!(check_path(&p.path(), &req, NOW, Some(&unknown_st)), Err(CertError::RevocationUnknown { .. })));
    assert!(matches!(check_path(&p.path(), &req, NOW, Some(&revoked)), Err(CertError::Revoked { reason: Some(1), .. })));
    assert!(check_path(&p.path(), &opt, NOW, None).is_ok());
    assert!(check_path(&p.path(), &opt, NOW, Some(&unknown_st)).is_ok());
    assert!(matches!(check_path(&p.path(), &opt, NOW, Some(&revoked)), Err(CertError::Revoked { .. })));
    // an invalid staple fails even in Request mode; garbage too
    assert!(matches!(check_path(&p.path(), &opt, NOW + 86400, Some(&good)), Err(CertError::RevocationUnknown { .. })));
    assert!(matches!(check_path(&p.path(), &opt, NOW, Some(b"garbage")), Err(CertError::RevocationUnknown { .. })));
    // Off ignores a staple
    assert!(check_path(&p.path(), &RevocationPolicy::new(), NOW, Some(&revoked)).is_ok());
    // a good staple covers the leaf under CrlMode::Require; the intermediate still needs a CRL
    let pol = RevocationPolicy::new().with_ocsp(OcspMode::Request).with_crl_mode(CrlMode::Require).with_crls(vec![Crl::from_der(&p.ca_crl(&[])).unwrap()]);
    assert!(check_path(&p.path(), &pol, NOW, Some(&good)).is_ok());
    assert!(matches!(check_path(&p.path(), &pol, NOW, None), Err(CertError::RevocationUnknown { subject, .. }) if subject.contains("leaf")));
}

#[test]
fn check_path_fetched_crls_and_cache() {
    let p = pki();
    let fetcher = Arc::new(MapFetcher::new().with_crl(INT_CRL_URL, p.int_crl(&[])).with_crl(CA_CRL_URL, crate::pem::encode_pem("X509 CRL", &p.ca_crl(&[])).into_bytes()));
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_fetcher(fetcher.clone());
    assert!(check_path(&p.path(), &pol, NOW, None).is_ok());
    assert_eq!(fetcher.requests(), vec![INT_CRL_URL.to_string(), CA_CRL_URL.to_string()]);
    assert_eq!(pol.cache.len(), 2);
    // the second check is served from the cache (shared by clones)
    assert!(check_path(&p.path(), &pol.clone(), NOW + 60, None).is_ok());
    assert_eq!(fetcher.requests().len(), 2);
    // after nextUpdate the cache entry expires and the stale CRL is fetched again (and refused)
    assert!(matches!(check_path(&p.path(), &pol, NOW + 2 * 86400, None), Err(CertError::RevocationUnknown { .. })));
    assert_eq!(fetcher.requests().len(), 3);
    // a revoked leaf in the fetched CRL
    let fetcher = Arc::new(MapFetcher::new().with_crl(INT_CRL_URL, p.int_crl(&[&p.leaf_cert.serial])));
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::IfAvailable).with_fetcher(fetcher);
    assert!(matches!(check_path(&p.path(), &pol, NOW, None), Err(CertError::Revoked { .. })));
    // nothing to fetch: Require fails, IfAvailable passes, soft fail passes
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_fetcher(Arc::new(MapFetcher::new()));
    let e = check_path(&p.path(), &pol, NOW, None).unwrap_err();
    assert!(matches!(&e, CertError::RevocationUnknown { why, .. } if why.contains("could not fetch")), "{e}");
    assert!(check_path(&p.path(), &pol.clone().with_crl_mode(CrlMode::IfAvailable), NOW, None).is_ok());
    assert!(check_path(&p.path(), &pol.with_soft_fail(true), NOW, None).is_ok());
    // no fetcher at all
    assert!(matches!(check_path(&p.path(), &RevocationPolicy::new().with_crl_mode(CrlMode::Require), NOW, None), Err(CertError::RevocationUnknown { .. })));
    // a fetched CRL above the size limit, and garbage
    let mut pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_fetcher(Arc::new(MapFetcher::new().with_crl(INT_CRL_URL, p.int_crl(&[])).with_crl(CA_CRL_URL, b"junk".to_vec())));
    pol.crl_limits.max_size = 100;
    let e = check_path(&p.path(), &pol, NOW, None).unwrap_err();
    assert!(e.to_string().contains("larger than 100"), "{e}");
    pol.crl_limits.max_size = 1 << 20;
    let e = check_path(&p.path(), &pol, NOW, None).unwrap_err();
    assert!(matches!(&e, CertError::RevocationUnknown { subject, .. } if subject.contains("Intermediate")), "{e}");
}

#[test]
fn check_path_online_ocsp() {
    let p = pki();
    let fetcher = Arc::new(
        MapFetcher::new()
            .with_responder(INT_OCSP_URL, &p.responder_cert, &p.responder.key, &p.int_cert, &[(&p.leaf_cert.serial, CertStatus::Good)], NOW)
            .with_responder(CA_OCSP_URL, &p.ca_cert, &p.ca.key, &p.ca_cert, &[(&p.int_cert.serial, CertStatus::Good)], NOW),
    );
    let pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_ocsp_online(true).with_fetcher(fetcher.clone());
    assert!(check_path(&p.path(), &pol, NOW, None).is_ok());
    // CRL first (none fetched), then OCSP, for each certificate
    assert_eq!(fetcher.requests(), vec![INT_CRL_URL, INT_OCSP_URL, CA_CRL_URL, CA_OCSP_URL]);
    let mut strict = pol.clone();
    strict.require_ocsp_nonce = true;
    assert!(check_path(&p.path(), &strict, NOW, None).is_ok(), "the test responder echoes the nonce");
    // revoked online
    let fetcher = Arc::new(MapFetcher::new().with_responder(
        INT_OCSP_URL,
        &p.int_cert,
        &p.intermediate.key,
        &p.int_cert,
        &[(&p.leaf_cert.serial, CertStatus::Revoked { time: NOW - 5, reason: Some(3) })],
        NOW,
    ));
    let pol = RevocationPolicy::new().with_ocsp_online(true).with_fetcher(fetcher);
    assert!(matches!(check_path(&p.path(), &pol, NOW, None), Err(CertError::Revoked { reason: Some(3), .. })));
    // a responder that does not know the certificate: fine unless required
    let fetcher = Arc::new(MapFetcher::new().with_responder(INT_OCSP_URL, &p.int_cert, &p.intermediate.key, &p.int_cert, &[], NOW));
    let pol = RevocationPolicy::new().with_ocsp_online(true).with_fetcher(fetcher);
    assert!(check_path(&p.path(), &pol, NOW, None).is_ok());
    let e = check_path(&p.path(), &pol.with_crl_mode(CrlMode::Require), NOW, None).unwrap_err();
    assert!(e.to_string().contains("unknown status"), "{e}");
}

/// A responder that replays a response with a different nonce.
struct WrongNonce(Vec<u8>);
impl RevocationFetcher for WrongNonce {
    fn fetch_crl(&self, _: &str) -> Option<Vec<u8>> {
        None
    }
    fn ocsp(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

#[test]
fn check_path_online_ocsp_nonce_mismatch() {
    let p = pki();
    let single = SingleResponse { cert_id: CertId::new(&p.leaf_cert, &p.int_cert), status: CertStatus::Good, this_update: NOW - 60, next_update: Some(NOW + 3600) };
    let replay = build_response(&[single], &p.int_cert, &p.intermediate.key, &[], NOW - 60, Some(b"an old nonce"));
    let mut pol = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_ocsp_online(true).with_fetcher(Arc::new(WrongNonce(replay)));
    pol.crls.push(Arc::new(Crl::from_der(&p.ca_crl(&[])).unwrap()));
    let e = check_path(&p.path(), &pol, NOW, None).unwrap_err();
    assert!(e.to_string().contains("nonce mismatch"), "{e}");
}

#[test]
fn crl_cache_bounds() {
    let p = pki();
    let cache = CrlCache::new(2);
    let crl = |next| Arc::new(Crl::from_der(&CrlBuilder::new(NOW - 10, next).sign(&p.int_cert, &p.intermediate.key)).unwrap());
    cache.insert("a", crl(Some(NOW + 10)), NOW, 100);
    cache.insert("b", crl(Some(NOW + 1000)), NOW, 100);
    cache.insert("c", crl(Some(NOW + 500)), NOW, 100);
    assert_eq!(cache.len(), 2);
    assert!(cache.get("a", NOW).is_none(), "the entry expiring soonest was evicted");
    assert!(cache.get("b", NOW).is_some());
    assert!(cache.get("c", NOW + 501).is_none(), "expired");
    cache.insert("d", crl(Some(NOW - 1)), NOW, 100);
    assert!(cache.get("d", NOW).is_none(), "an expired CRL is not stored");
    cache.insert("e", crl(None), NOW, 100);
    assert!(cache.get("e", NOW + 80).is_some());
    assert!(cache.get("e", NOW + 95).is_none());
    cache.clear();
    assert!(cache.is_empty());
}

#[test]
fn staple_source() {
    let p = pki();
    let src = StapleSource::new();
    assert!(src.get().is_none());
    let clone = src.clone();
    assert_eq!(src.set_checked(p.leaf_ocsp(CertStatus::Good), &p.leaf_cert, &p.int_cert, NOW), Ok(CertStatus::Good));
    assert!(clone.get().is_some(), "clones share the slot");
    let before = clone.get().unwrap();
    // refused: unknown status, expired, wrong certificate
    assert!(src.set_checked(p.leaf_ocsp(CertStatus::Unknown), &p.leaf_cert, &p.int_cert, NOW).is_err());
    assert!(src.set_checked(p.leaf_ocsp(CertStatus::Good), &p.leaf_cert, &p.int_cert, NOW + 86400).is_err());
    assert!(src.set_checked(p.leaf_ocsp(CertStatus::Good), &p.int_cert, &p.ca_cert, NOW).is_err());
    assert_eq!(clone.get().unwrap(), before, "the previous response is kept");
    src.set(None);
    assert!(clone.get().is_none());
    assert!(format!("{src:?}").contains("empty"));
}

#[test]
fn policy_debug_and_add_crls() {
    let p = pki();
    let mut pol = RevocationPolicy::new();
    let pem_text = crate::pem::encode_pem("X509 CRL", &p.int_crl(&[]));
    assert_eq!(pol.add_crls(pem_text.as_bytes()), Ok(1));
    assert!(pol.add_crls(b"junk").is_err());
    let d = format!("{pol:?}");
    assert!(d.contains("crls: 1") && d.contains("fetcher: false"), "{d}");
    assert_eq!(reason_name(1), "keyCompromise");
}
