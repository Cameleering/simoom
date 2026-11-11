//! Public / private key types and parsing: SubjectPublicKeyInfo, PKCS#8,
//! SEC1 (`EC PRIVATE KEY`) and PKCS#1 (`RSA PRIVATE KEY`).

use crate::asn1::{self, Der, DerError, DerResult, TAG_OID, TAG_SEQUENCE};
#[cfg(feature = "p384")]
use crate::crypto::ec::p384;
use crate::crypto::p256;
#[cfg(feature = "rsa")]
use crate::crypto::rsa::{RsaPrivateKey, RsaPublicKey};
use crate::crypto::sha2::HashAlg;
use crate::pem;

/// A supported NIST curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    #[cfg(feature = "p384")]
    P384,
}

impl EcCurve {
    /// Scalar and coordinate size in bytes.
    pub fn byte_len(self) -> usize {
        match self {
            EcCurve::P256 => 32,
            #[cfg(feature = "p384")]
            EcCurve::P384 => 48,
        }
    }
    /// The hash paired with this curve in TLS 1.3 signature schemes.
    pub fn hash(self) -> HashAlg {
        match self {
            EcCurve::P256 => HashAlg::Sha256,
            #[cfg(feature = "p384")]
            EcCurve::P384 => HashAlg::Sha384,
        }
    }
    pub fn generate_private(self) -> Vec<u8> {
        match self {
            EcCurve::P256 => p256::generate_private().to_vec(),
            #[cfg(feature = "p384")]
            EcCurve::P384 => p384::generate_private(),
        }
    }
    pub fn public_key(self, private: &[u8]) -> Option<Vec<u8>> {
        match self {
            EcCurve::P256 => p256::public_key(private).map(|p| p.to_vec()),
            #[cfg(feature = "p384")]
            EcCurve::P384 => p384::public_key(private),
        }
    }
    /// [`EcCurve::public_key`] for a key being loaded: P-256 skips building its base-point
    /// table (start-up time and memory), which the first signature builds instead.
    pub fn public_key_for_load(self, private: &[u8]) -> Option<Vec<u8>> {
        match self {
            EcCurve::P256 => p256::public_key_untabled(private).map(|p| p.to_vec()),
            #[cfg(feature = "p384")]
            EcCurve::P384 => p384::public_key(private),
        }
    }
    /// ECDSA over a digest; (r, s) big-endian, curve-sized.
    pub fn sign(self, private: &[u8], digest: &[u8], hash: HashAlg) -> Option<(Vec<u8>, Vec<u8>)> {
        match self {
            EcCurve::P256 => p256::sign(private, digest, hash).map(|(r, s)| (r.to_vec(), s.to_vec())),
            #[cfg(feature = "p384")]
            EcCurve::P384 => p384::sign(private, digest, hash),
        }
    }
    pub fn verify(self, public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
        match self {
            EcCurve::P256 => p256::verify(public, digest, r, s),
            #[cfg(feature = "p384")]
            EcCurve::P384 => p384::verify(public, digest, r, s),
        }
    }
    pub fn validate_point(self, public: &[u8]) -> bool {
        match self {
            EcCurve::P256 => p256::validate_point(public),
            #[cfg(feature = "p384")]
            EcCurve::P384 => p384::validate_point(public),
        }
    }
}

pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_P256: &str = "1.2.840.10045.3.1.7";
pub const OID_P384: &str = "1.3.132.0.34";
pub const OID_ED25519: &str = "1.3.101.112";

fn derr<T>(m: &'static str) -> DerResult<T> {
    Err(DerError(m.into()))
}

pub fn curve_from_oid(oid: &str) -> Option<EcCurve> {
    match oid {
        OID_P256 => Some(EcCurve::P256),
        #[cfg(feature = "p384")]
        OID_P384 => Some(EcCurve::P384),
        _ => None,
    }
}

pub fn curve_oid(c: EcCurve) -> &'static str {
    match c {
        EcCurve::P256 => OID_P256,
        #[cfg(feature = "p384")]
        EcCurve::P384 => OID_P384,
    }
}

/// A public key usable for signature verification.
#[derive(Clone, Debug)]
pub enum PublicKey {
    Ec { curve: EcCurve, point: Vec<u8> },
    #[cfg(feature = "rsa")]
    Rsa(RsaPublicKey),
    #[cfg(feature = "ed25519")]
    Ed25519([u8; 32]),
}

impl PublicKey {
    /// Parses a DER SubjectPublicKeyInfo.
    pub fn from_spki(spki: &[u8]) -> DerResult<PublicKey> {
        let mut outer = Der::new(spki);
        let mut s = outer.sequence()?;
        let mut alg = s.sequence()?;
        let oid = alg.oid()?;
        let key = s.bit_string()?;
        match oid.as_str() {
            #[cfg(feature = "rsa")]
            OID_RSA_ENCRYPTION | OID_RSASSA_PSS => {
                let mut k = Der::new(key).sequence()?;
                let n = k.uint()?;
                let e = k.uint()?;
                RsaPublicKey::new(n, e).map(PublicKey::Rsa).ok_or(DerError("unsupported RSA key".into()))
            }
            OID_EC_PUBLIC_KEY => {
                let params = alg.read()?;
                if params.tag != TAG_OID {
                    return derr("explicit EC parameters not supported");
                }
                let curve = curve_from_oid(&asn1::decode_oid(params.value)?).ok_or(DerError("unsupported curve".into()))?;
                if !curve.validate_point(key) {
                    return derr("invalid EC point");
                }
                Ok(PublicKey::Ec { curve, point: key.to_vec() })
            }
            #[cfg(feature = "ed25519")]
            OID_ED25519 => {
                let k: [u8; 32] = key.try_into().map_err(|_| DerError("bad Ed25519 public key length".into()))?;
                Ok(PublicKey::Ed25519(k))
            }
            _ => derr("unsupported public key algorithm"),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            PublicKey::Ec { curve, .. } => format!("ECDSA {:?}", curve),
            #[cfg(feature = "rsa")]
            PublicKey::Rsa(r) => format!("RSA {}", r.modulus_bits()),
            #[cfg(feature = "ed25519")]
            PublicKey::Ed25519(_) => "Ed25519".to_string(),
        }
    }

    /// Encodes the key as a DER SubjectPublicKeyInfo.
    pub fn to_spki(&self) -> Vec<u8> {
        match self {
            PublicKey::Ec { curve, point } => {
                asn1::seq(&[asn1::seq(&[asn1::oid(OID_EC_PUBLIC_KEY), asn1::oid(curve_oid(*curve))]), asn1::bit_string(point)])
            }
            #[cfg(feature = "rsa")]
            PublicKey::Rsa(r) => {
                let (n, e) = r.components();
                let key = asn1::seq(&[asn1::uint(&n), asn1::uint(&e)]);
                asn1::seq(&[asn1::seq(&[asn1::oid(OID_RSA_ENCRYPTION), asn1::tlv(asn1::TAG_NULL, &[])]), asn1::bit_string(&key)])
            }
            #[cfg(feature = "ed25519")]
            PublicKey::Ed25519(k) => asn1::seq(&[asn1::seq(&[asn1::oid(OID_ED25519)]), asn1::bit_string(k)]),
        }
    }

    /// Whether two keys are the same.
    pub fn same_as(&self, other: &PublicKey) -> bool {
        self.to_spki() == other.to_spki()
    }
}

/// A private signing key (server certificates).
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)] // one per connection or key; boxing would add an indirection on the hot path
pub enum PrivateKey {
    Ec { curve: EcCurve, d: Vec<u8>, public: Vec<u8> },
    #[cfg(feature = "rsa")]
    Rsa(RsaPrivateKey),
    #[cfg(feature = "ed25519")]
    Ed25519 { seed: [u8; 32], public: [u8; 32] },
}

impl PrivateKey {
    /// Parses the first private key found in PEM text (PKCS#8, SEC1 or PKCS#1). Encrypted
    /// keys are not supported.
    pub fn from_pem(data: &[u8]) -> Result<PrivateKey, String> {
        let blocks = pem::parse_pem(data)?;
        for b in blocks {
            let r = match b.label.as_str() {
                "PRIVATE KEY" => PrivateKey::from_pkcs8(&b.der),
                "EC PRIVATE KEY" => PrivateKey::from_sec1(&b.der, None),
                #[cfg(feature = "rsa")]
                "RSA PRIVATE KEY" => PrivateKey::from_pkcs1(&b.der),
                "ENCRYPTED PRIVATE KEY" => return Err("encrypted private keys are not supported".into()),
                _ => continue,
            };
            return r.map_err(|e| e.to_string());
        }
        Err("no private key found in PEM input".into())
    }

    /// Parses DER in any supported format (tries PKCS#8, then SEC1, then PKCS#1).
    pub fn from_der(der: &[u8]) -> Result<PrivateKey, String> {
        let r = PrivateKey::from_pkcs8(der).or_else(|_| PrivateKey::from_sec1(der, None));
        #[cfg(feature = "rsa")]
        let r = r.or_else(|_| PrivateKey::from_pkcs1(der));
        r.map_err(|e| format!("unrecognised private key: {e}"))
    }

    pub fn from_pkcs8(der: &[u8]) -> DerResult<PrivateKey> {
        let mut s = Der::new(der).sequence()?;
        let version = s.small_uint()?;
        if version > 1 {
            return derr("unsupported PKCS#8 version");
        }
        let mut alg = s.sequence()?;
        let oid = alg.oid()?;
        let key = s.octet_string()?;
        match oid.as_str() {
            #[cfg(feature = "rsa")]
            OID_RSA_ENCRYPTION => PrivateKey::from_pkcs1(key),
            OID_EC_PUBLIC_KEY => {
                let p = alg.expect(TAG_OID)?;
                let curve = curve_from_oid(&asn1::decode_oid(p.value)?).ok_or(DerError("unsupported curve".into()))?;
                PrivateKey::from_sec1(key, Some(curve))
            }
            #[cfg(feature = "ed25519")]
            OID_ED25519 => {
                let seed = Der::new(key).octet_string()?;
                let seed: [u8; 32] = seed.try_into().map_err(|_| DerError("bad Ed25519 private key length".into()))?;
                Ok(PrivateKey::ed25519_from_seed(seed))
            }
            _ => derr("unsupported private key algorithm"),
        }
    }

    #[cfg(feature = "ed25519")]
    /// An Ed25519 key from its 32-byte seed.
    pub fn ed25519_from_seed(seed: [u8; 32]) -> PrivateKey {
        PrivateKey::Ed25519 { seed, public: crate::crypto::ed25519::public_key(&seed) }
    }

    #[cfg(feature = "ed25519")]
    /// A fresh random Ed25519 key.
    pub fn generate_ed25519() -> PrivateKey {
        PrivateKey::ed25519_from_seed(crate::crypto::rng::array::<32>())
    }

    /// A fresh random ECDSA key.
    pub fn generate_ec(curve: EcCurve) -> PrivateKey {
        let d = curve.generate_private();
        let public = curve.public_key(&d).expect("valid scalar");
        PrivateKey::Ec { curve, d, public }
    }

    pub fn from_sec1(der: &[u8], curve: Option<EcCurve>) -> DerResult<PrivateKey> {
        let mut s = Der::new(der).sequence()?;
        if s.small_uint()? != 1 {
            return derr("unsupported SEC1 version");
        }
        let d = s.octet_string()?;
        let mut curve = curve;
        if let Some(params) = s.optional(0xa0)? {
            let c = curve_from_oid(&params.reader().oid()?).ok_or(DerError("unsupported curve".into()))?;
            if curve.is_some() && curve != Some(c) {
                return derr("curve mismatch");
            }
            curve = Some(c);
        }
        let curve = curve.ok_or(DerError("EC key without curve".into()))?;
        let mut dv = d.to_vec();
        while dv.len() < curve.byte_len() {
            dv.insert(0, 0);
        }
        if dv.len() != curve.byte_len() {
            return derr("bad EC private key length");
        }
        let public = curve.public_key_for_load(&dv).ok_or(DerError("invalid EC private scalar".into()))?;
        Ok(PrivateKey::Ec { curve, d: dv, public })
    }

    #[cfg(feature = "rsa")]
    pub fn from_pkcs1(der: &[u8]) -> DerResult<PrivateKey> {
        let mut s = Der::new(der).sequence()?;
        if s.small_uint()? != 0 {
            return derr("multi-prime RSA keys not supported");
        }
        let n = s.uint()?;
        let e = s.uint()?;
        let d = s.uint()?;
        let mut k = RsaPrivateKey::new(n, e, d).ok_or(DerError("invalid RSA private key".into()))?;
        if let (Ok(p), Ok(q), Ok(dp), Ok(dq), Ok(qinv)) = (s.uint(), s.uint(), s.uint(), s.uint(), s.uint()) {
            k.set_crt(p, q, dp, dq, qinv);
        }
        k.pkcs1 = Some(der.to_vec());
        Ok(PrivateKey::Rsa(k))
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ec { curve, public, .. } => PublicKey::Ec { curve: *curve, point: public.clone() },
            #[cfg(feature = "rsa")]
            PrivateKey::Rsa(r) => PublicKey::Rsa(r.public.clone()),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519 { public, .. } => PublicKey::Ed25519(*public),
        }
    }

    /// Encodes the key as PKCS#8 DER (RSA keys need their original PKCS#1 encoding).
    pub fn to_pkcs8(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "rsa")]
            PrivateKey::Rsa(r) => {
                let pkcs1 = r.pkcs1_der().unwrap_or_default();
                asn1::seq(&[
                    asn1::uint(&[0]),
                    asn1::seq(&[asn1::oid(OID_RSA_ENCRYPTION), asn1::tlv(asn1::TAG_NULL, &[])]),
                    asn1::octet_string(pkcs1),
                ])
            }
            _ => self.to_pkcs8_der().expect("EC / Ed25519 key"),
        }
    }

    /// Encodes an EC or Ed25519 key as PKCS#8 DER (used by the self-signed generator).
    pub fn to_pkcs8_der(&self) -> Option<Vec<u8>> {
        match self {
            PrivateKey::Ec { curve, d, public } => {
                let sec1 = asn1::seq(&[asn1::uint(&[1]), asn1::octet_string(d), asn1::explicit(1, &asn1::bit_string(public))]);
                Some(asn1::seq(&[
                    asn1::uint(&[0]),
                    asn1::seq(&[asn1::oid(OID_EC_PUBLIC_KEY), asn1::oid(curve_oid(*curve))]),
                    asn1::octet_string(&sec1),
                ]))
            }
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519 { seed, .. } => Some(asn1::seq(&[
                asn1::uint(&[0]),
                asn1::seq(&[asn1::oid(OID_ED25519)]),
                asn1::octet_string(&asn1::octet_string(seed)),
            ])),
            #[cfg(feature = "rsa")]
            PrivateKey::Rsa(_) => None,
        }
    }
}

/// Encodes an ECDSA (r, s) pair as a DER `Ecdsa-Sig-Value`.
pub fn ecdsa_sig_to_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    asn1::seq(&[asn1::uint(r), asn1::uint(s)])
}

/// Decodes a DER `Ecdsa-Sig-Value` into (r, s).
pub fn ecdsa_sig_from_der(sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut outer = Der::new(sig);
    let mut s = outer.sequence().ok()?;
    if !outer.is_empty() {
        return None;
    }
    let r = s.uint().ok()?.to_vec();
    let sv = s.uint().ok()?.to_vec();
    if !s.is_empty() {
        return None;
    }
    Some((r, sv))
}

/// Signature algorithm identifiers as they appear in certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaPkcs1(HashAlg),
    RsaPss { hash: HashAlg, salt_len: usize },
    Ecdsa(HashAlg),
    Ed25519,
    /// sha1WithRSAEncryption: legacy certificates, CRLs and OCSP responses (feature `sha1`).
    #[cfg(feature = "sha1")]
    RsaPkcs1Sha1,
    /// ecdsa-with-SHA1 (feature `sha1`).
    #[cfg(feature = "sha1")]
    EcdsaSha1,
    Unknown(String),
}

fn hash_from_oid(oid: &str) -> Option<HashAlg> {
    match oid {
        "2.16.840.1.101.3.4.2.1" => Some(HashAlg::Sha256),
        "2.16.840.1.101.3.4.2.2" => Some(HashAlg::Sha384),
        "2.16.840.1.101.3.4.2.3" => Some(HashAlg::Sha512),
        _ => None,
    }
}

impl SignatureAlgorithm {
    /// Parses an AlgorithmIdentifier (the reader is positioned inside the SEQUENCE).
    pub fn parse(alg: &mut Der) -> DerResult<SignatureAlgorithm> {
        let oid = alg.oid()?;
        Ok(match oid.as_str() {
            "1.2.840.113549.1.1.11" => SignatureAlgorithm::RsaPkcs1(HashAlg::Sha256),
            "1.2.840.113549.1.1.12" => SignatureAlgorithm::RsaPkcs1(HashAlg::Sha384),
            "1.2.840.113549.1.1.13" => SignatureAlgorithm::RsaPkcs1(HashAlg::Sha512),
            "1.2.840.10045.4.3.2" => SignatureAlgorithm::Ecdsa(HashAlg::Sha256),
            "1.2.840.10045.4.3.3" => SignatureAlgorithm::Ecdsa(HashAlg::Sha384),
            "1.2.840.10045.4.3.4" => SignatureAlgorithm::Ecdsa(HashAlg::Sha512),
            #[cfg(feature = "sha1")]
            "1.2.840.113549.1.1.5" => SignatureAlgorithm::RsaPkcs1Sha1,
            #[cfg(feature = "sha1")]
            "1.2.840.10045.4.1" => SignatureAlgorithm::EcdsaSha1,
            #[cfg(feature = "ed25519")]
            OID_ED25519 => SignatureAlgorithm::Ed25519,
            OID_RSASSA_PSS => {
                // The defaults (SHA-1, salt 20) are not supported: parameters must be explicit.
                let mut hash = None;
                let mut mgf_hash = None;
                let mut salt_len = 20usize;
                if let Some(params) = alg.optional(TAG_SEQUENCE)? {
                    let mut p = params.reader();
                    while !p.is_empty() {
                        let t = p.read()?;
                        let mut inner = t.reader();
                        match t.tag {
                            0xa0 => {
                                let mut a = inner.sequence()?;
                                hash = Some(hash_from_oid(&a.oid()?).ok_or(DerError("unsupported PSS hash".into()))?);
                            }
                            0xa1 => {
                                let mut a = inner.sequence()?;
                                if a.oid()? != "1.2.840.113549.1.1.8" {
                                    return derr("unsupported PSS mask generation function");
                                }
                                let mut h = a.sequence()?;
                                mgf_hash = Some(hash_from_oid(&h.oid()?).ok_or(DerError("unsupported MGF hash".into()))?);
                            }
                            0xa2 => salt_len = inner.small_uint()? as usize,
                            0xa3 => {
                                if inner.small_uint()? != 1 {
                                    return derr("unsupported PSS trailer");
                                }
                            }
                            _ => return derr("unexpected PSS parameter"),
                        }
                    }
                }
                match (hash, mgf_hash) {
                    (Some(hash), Some(m)) if hash == m => SignatureAlgorithm::RsaPss { hash, salt_len },
                    _ => return derr("RSA-PSS parameters not supported (SHA-1 or differing MGF hash)"),
                }
            }
            other => SignatureAlgorithm::Unknown(other.to_string()),
        })
    }

    /// Verifies `sig` over `message` with `key`.
    pub fn verify(&self, key: &PublicKey, message: &[u8], sig: &[u8]) -> bool {
        match (self, key) {
            #[cfg(feature = "rsa")]
            (SignatureAlgorithm::RsaPkcs1(h), PublicKey::Rsa(k)) => k.verify_pkcs1(*h, &h.hash(message), sig),
            #[cfg(feature = "rsa")]
            (SignatureAlgorithm::RsaPss { hash, salt_len }, PublicKey::Rsa(k)) => {
                k.verify_pss(*hash, &hash.hash(message), sig, Some(*salt_len))
            }
            (SignatureAlgorithm::Ecdsa(h), PublicKey::Ec { curve, point }) => match ecdsa_sig_from_der(sig) {
                Some((r, s)) => curve.verify(point, &h.hash(message), &r, &s),
                None => false,
            },
            #[cfg(feature = "ed25519")]
            (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(k)) => crate::crypto::ed25519::verify(k, message, sig),
            #[cfg(all(feature = "sha1", feature = "rsa"))]
            (SignatureAlgorithm::RsaPkcs1Sha1, PublicKey::Rsa(k)) => k.verify_pkcs1_sha1(&crate::crypto::sha1::Sha1::digest(message), sig),
            #[cfg(feature = "sha1")]
            (SignatureAlgorithm::EcdsaSha1, PublicKey::Ec { curve, point }) => match ecdsa_sig_from_der(sig) {
                Some((r, s)) => curve.verify(point, &crate::crypto::sha1::Sha1::digest(message), &r, &s),
                None => false,
            },
            _ => false,
        }
    }
}

#[cfg(all(test, feature = "rsa", feature = "p384", feature = "ed25519"))]
mod tests {
    use super::*;

    const RSA_PKCS8: &str = include_str!("../testdata/rsa2048.pkcs8.pem");
    const RSA_PKCS1: &str = include_str!("../testdata/rsa2048.pkcs1.pem");
    const EC_SEC1: &str = include_str!("../testdata/ec256.sec1.pem");
    const EC_PKCS8: &str = include_str!("../testdata/ec256.pkcs8.pem");
    const EC384_SEC1: &str = include_str!("../testdata/ec384.sec1.pem");
    const MSG: &[u8] = include_bytes!("../testdata/msg.txt");
    const SIG_PKCS1: &[u8] = include_bytes!("../testdata/rsa_pkcs1_sha256.sig");
    const SIG_PSS: &[u8] = include_bytes!("../testdata/rsa_pss_sha384.sig");

    #[test]
    fn parse_all_key_formats() {
        let a = PrivateKey::from_pem(RSA_PKCS8.as_bytes()).unwrap();
        let b = PrivateKey::from_pem(RSA_PKCS1.as_bytes()).unwrap();
        assert!(matches!(a, PrivateKey::Rsa(_)));
        assert!(matches!(b, PrivateKey::Rsa(_)));
        let c = PrivateKey::from_pem(EC_SEC1.as_bytes()).unwrap();
        let d = PrivateKey::from_pem(EC_PKCS8.as_bytes()).unwrap();
        match (&c, &d) {
            (PrivateKey::Ec { d: d1, public: p1, .. }, PrivateKey::Ec { d: d2, public: p2, .. }) => {
                assert_eq!(d1, d2);
                assert_eq!(p1, p2);
            }
            _ => panic!("expected EC keys"),
        }
        let e = PrivateKey::from_pem(EC384_SEC1.as_bytes()).unwrap();
        assert!(matches!(e, PrivateKey::Ec { curve: EcCurve::P384, .. }));
        // PKCS#8 export re-parses
        let der = c.to_pkcs8_der().unwrap();
        assert!(matches!(PrivateKey::from_der(&der).unwrap(), PrivateKey::Ec { .. }));
    }

    #[test]
    fn rsa_against_openssl_vectors() {
        let key = match PrivateKey::from_pem(RSA_PKCS8.as_bytes()).unwrap() {
            #[cfg(feature = "rsa")]
            PrivateKey::Rsa(r) => r,
            _ => unreachable!(),
        };
        let h256 = HashAlg::Sha256.hash(MSG);
        // PKCS#1 v1.5 is deterministic: our signature must equal OpenSSL's byte for byte.
        assert!(key.public.verify_pkcs1(HashAlg::Sha256, &h256, SIG_PKCS1));
        assert_eq!(key.sign_pkcs1(HashAlg::Sha256, &h256).unwrap(), SIG_PKCS1);
        let mut bad = SIG_PKCS1.to_vec();
        bad[10] ^= 1;
        assert!(!key.public.verify_pkcs1(HashAlg::Sha256, &h256, &bad));
        // PSS signature made by OpenSSL (SHA-384, salt 48)
        let h384 = HashAlg::Sha384.hash(MSG);
        assert!(key.public.verify_pss(HashAlg::Sha384, &h384, SIG_PSS, Some(48)));
        assert!(!key.public.verify_pss(HashAlg::Sha384, &h384, SIG_PSS, Some(32)));
        assert!(!key.public.verify_pss(HashAlg::Sha384, &HashAlg::Sha384.hash(b"x"), SIG_PSS, None));
        // our PSS signatures verify
        let s = key.sign_pss(HashAlg::Sha256, &h256).unwrap();
        assert!(key.public.verify_pss(HashAlg::Sha256, &h256, &s, Some(32)));
    }

    #[test]
    fn rsa_crt_and_blinding_match_plain_exponentiation() {
        let key = match PrivateKey::from_pem(RSA_PKCS1.as_bytes()).unwrap() {
            #[cfg(feature = "rsa")]
            PrivateKey::Rsa(r) => r,
            _ => unreachable!(),
        };
        assert!(key.has_crt());
        let (n, e) = key.public.components();
        // the same key without CRT parameters: d from the PKCS#1 structure
        let der = key.pkcs1_der().unwrap().to_vec();
        let mut sq = Der::new(&der).sequence().unwrap();
        sq.small_uint().unwrap();
        sq.uint().unwrap();
        sq.uint().unwrap();
        let d = sq.uint().unwrap().to_vec();
        let plain = RsaPrivateKey::new(&n, &e, &d).unwrap();
        assert!(!plain.has_crt());
        let h256 = HashAlg::Sha256.hash(MSG);
        for _ in 0..3 {
            // blinding factors change between calls; results must not
            assert_eq!(key.sign_pkcs1(HashAlg::Sha256, &h256).unwrap(), SIG_PKCS1);
            assert_eq!(plain.sign_pkcs1(HashAlg::Sha256, &h256).unwrap(), SIG_PKCS1);
        }
        // inconsistent CRT parameters are refused
        let mut k2 = plain.clone();
        assert!(!k2.set_crt(&[7], &[11], &[1], &[1], &[1]));
        assert!(!k2.has_crt());
    }

    #[test]
    fn ecdsa_der_roundtrip() {
        let sig = ecdsa_sig_to_der(&[0x80, 1], &[0, 0, 5]);
        assert_eq!(ecdsa_sig_from_der(&sig).unwrap(), (vec![0x80, 1], vec![5]));
    }
}
