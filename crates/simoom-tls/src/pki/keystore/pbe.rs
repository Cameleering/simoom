//! Password-based encryption used by key stores: PBES2 (PBKDF2 + AES-CBC or 3DES-CBC,
//! RFC 8018) and the PKCS#12 PBE schemes (RFC 7292 appendix C:
//! `pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbeWithSHAAnd2-KeyTripleDES-CBC`,
//! `pbeWithSHAAnd128BitRC2-CBC`, `pbeWithSHAAnd40BitRC2-CBC`), plus PKCS#8
//! `EncryptedPrivateKeyInfo`.
//!
//! Writing always uses PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC (the OpenSSL 3 and
//! Java 17+ default); the PKCS#12 PBE schemes are read, and written only by the explicit
//! legacy PKCS#12 profile. Iteration counts read from a file are capped at
//! [`MAX_ITERATIONS`] so a hostile file cannot make a load run for hours.
//!
//! (**Moves to ksar-pki**; from Cameleer `cameleer-tls/src/pbe.rs`.)

use crate::crypto::legacy::{cbc_decrypt, cbc_encrypt, Aes, Rc2, TripleDes};
use crate::asn1::{self, Der, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE};
use crate::crypto::md::{bmp_password, Md, PKCS12_IV, PKCS12_KEY};
use crate::crypto::rng;
use crate::util::zeroize;

pub const OID_PBES2: &str = "1.2.840.113549.1.5.13";
pub const OID_PBKDF2: &str = "1.2.840.113549.1.5.12";
pub const OID_PBE_SHA_3DES: &str = "1.2.840.113549.1.12.1.3";
pub const OID_PBE_SHA_2DES: &str = "1.2.840.113549.1.12.1.4";
pub const OID_PBE_SHA_RC2_128: &str = "1.2.840.113549.1.12.1.5";
pub const OID_PBE_SHA_RC2_40: &str = "1.2.840.113549.1.12.1.6";
pub const OID_HMAC_SHA1: &str = "1.2.840.113549.2.7";
pub const OID_HMAC_SHA256: &str = "1.2.840.113549.2.9";
pub const OID_HMAC_SHA384: &str = "1.2.840.113549.2.10";
pub const OID_HMAC_SHA512: &str = "1.2.840.113549.2.11";
pub const OID_AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
pub const OID_AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
pub const OID_AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
pub const OID_DES_EDE3_CBC: &str = "1.2.840.113549.3.7";

/// Upper bound on KDF iteration counts accepted from a file (denial-of-service guard).
pub const MAX_ITERATIONS: u64 = 10_000_000;

/// Iterations used when writing (PBES2 and the PKCS#12 MAC), as OpenSSL 3 does.
pub const DEFAULT_ITERATIONS: u32 = 2048;

fn e<T: std::fmt::Display>(x: T) -> String {
    x.to_string()
}

/// The PBKDF2 PRF for an HMAC OID.
pub fn prf_hash(oid: &str) -> Option<Md> {
    match oid {
        OID_HMAC_SHA1 => Some(Md::Sha1),
        OID_HMAC_SHA256 => Some(Md::Sha256),
        OID_HMAC_SHA384 => Some(Md::Sha384),
        OID_HMAC_SHA512 => Some(Md::Sha512),
        _ => None,
    }
}

/// Checks an iteration count read from a file.
pub fn check_iterations(n: u64) -> Result<u32, String> {
    if n == 0 || n > MAX_ITERATIONS {
        return Err(format!("unsupported iteration count {n} (allowed: 1 to {MAX_ITERATIONS})"));
    }
    Ok(n as u32)
}

fn iterations(d: &mut Der) -> Result<u32, String> {
    check_iterations(d.small_uint().map_err(e)?)
}

fn wrong() -> String {
    "decryption failed (wrong password?)".to_string()
}

/// Decrypts `data` encrypted with the algorithm described by the DER AlgorithmIdentifier
/// `alg` (its complete SEQUENCE encoding).
pub fn decrypt(alg: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut outer = Der::new(alg);
    let mut a = outer.sequence().map_err(e)?;
    let oid = a.oid().map_err(e)?;
    match oid.as_str() {
        OID_PBES2 => {
            let mut p = a.sequence().map_err(e)?;
            let mut kdf = p.sequence().map_err(e)?;
            let kdf_oid = kdf.oid().map_err(e)?;
            if kdf_oid != OID_PBKDF2 {
                return Err(format!("unsupported PBES2 key derivation function {kdf_oid}"));
            }
            let mut kp = kdf.sequence().map_err(e)?;
            let salt = kp.octet_string().map_err(e)?;
            let iter = iterations(&mut kp)?;
            let mut key_len = None;
            if kp.peek_tag() == Some(TAG_INTEGER) {
                key_len = Some(kp.small_uint().map_err(e)?);
            }
            let mut prf = Md::Sha1;
            if kp.peek_tag() == Some(TAG_SEQUENCE) {
                let mut pa = kp.sequence().map_err(e)?;
                let po = pa.oid().map_err(e)?;
                prf = prf_hash(&po).ok_or_else(|| format!("unsupported PBKDF2 PRF {po}"))?;
            }
            let mut enc = p.sequence().map_err(e)?;
            let enc_oid = enc.oid().map_err(e)?;
            let iv = enc.octet_string().map_err(e)?;
            let klen = match enc_oid.as_str() {
                OID_AES128_CBC => 16,
                OID_AES192_CBC => 24,
                OID_AES256_CBC => 32,
                OID_DES_EDE3_CBC => 24,
                other => return Err(format!("unsupported PBES2 encryption scheme {other}")),
            };
            if key_len.is_some_and(|k| k != klen as u64) {
                return Err("PBES2 key length mismatch".into());
            }
            let mut key = prf.pbkdf2(password.as_bytes(), salt, iter, klen);
            let r = if enc_oid == OID_DES_EDE3_CBC {
                cbc_decrypt(&TripleDes::new(&key), iv, data)
            } else {
                cbc_decrypt(&Aes::new(&key), iv, data)
            };
            zeroize(&mut key);
            r.ok_or_else(wrong)
        }
        OID_PBE_SHA_3DES | OID_PBE_SHA_2DES | OID_PBE_SHA_RC2_128 | OID_PBE_SHA_RC2_40 => {
            let mut p = a.sequence().map_err(e)?;
            let salt = p.octet_string().map_err(e)?;
            let iter = iterations(&mut p)?;
            let mut pw = bmp_password(password);
            let h = Md::Sha1;
            let klen = match oid.as_str() {
                OID_PBE_SHA_3DES => 24,
                OID_PBE_SHA_2DES | OID_PBE_SHA_RC2_128 => 16,
                _ => 5,
            };
            let mut key = h.pkcs12_kdf(&pw, salt, PKCS12_KEY, iter, klen);
            let iv = h.pkcs12_kdf(&pw, salt, PKCS12_IV, iter, 8);
            zeroize(&mut pw);
            let r = match oid.as_str() {
                OID_PBE_SHA_3DES | OID_PBE_SHA_2DES => cbc_decrypt(&TripleDes::new(&key), &iv, data),
                _ => cbc_decrypt(&Rc2::new(&key, klen * 8), &iv, data),
            };
            zeroize(&mut key);
            r.ok_or_else(wrong)
        }
        other => Err(format!("unsupported encryption algorithm {other}")),
    }
}

/// Encrypts with PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC); returns
/// (AlgorithmIdentifier DER, ciphertext).
pub fn encrypt_pbes2(data: &[u8], password: &str, iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let salt = rng::bytes(16);
    let iv = rng::bytes(16);
    let mut key = Md::Sha256.pbkdf2(password.as_bytes(), &salt, iterations.max(1), 32);
    let ct = cbc_encrypt(&Aes::new(&key), &iv, data);
    zeroize(&mut key);
    let alg = asn1::seq(&[
        asn1::oid(OID_PBES2),
        asn1::seq(&[
            asn1::seq(&[
                asn1::oid(OID_PBKDF2),
                asn1::seq(&[
                    asn1::octet_string(&salt),
                    asn1::uint(&iterations.max(1).to_be_bytes()),
                    asn1::seq(&[asn1::oid(OID_HMAC_SHA256), asn1::tlv(asn1::TAG_NULL, &[])]),
                ]),
            ]),
            asn1::seq(&[asn1::oid(OID_AES256_CBC), asn1::octet_string(&iv)]),
        ]),
    ]);
    (alg, ct)
}

/// Encrypts with a PKCS#12 PBE scheme (`OID_PBE_SHA_3DES` or `OID_PBE_SHA_RC2_40`); only the
/// explicit legacy PKCS#12 profile writes these, for consumers that cannot read PBES2.
pub fn encrypt_pkcs12_legacy(oid: &str, data: &[u8], password: &str, iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let iterations = iterations.max(1);
    let salt = rng::bytes(8);
    let mut pw = bmp_password(password);
    let three_des = oid == OID_PBE_SHA_3DES;
    let klen = if three_des { 24 } else { 5 };
    let mut key = Md::Sha1.pkcs12_kdf(&pw, &salt, PKCS12_KEY, iterations, klen);
    let iv = Md::Sha1.pkcs12_kdf(&pw, &salt, PKCS12_IV, iterations, 8);
    zeroize(&mut pw);
    let ct = if three_des { cbc_encrypt(&TripleDes::new(&key), &iv, data) } else { cbc_encrypt(&Rc2::new(&key, 40), &iv, data) };
    zeroize(&mut key);
    let oid = if three_des { OID_PBE_SHA_3DES } else { OID_PBE_SHA_RC2_40 };
    let alg = asn1::seq(&[asn1::oid(oid), asn1::seq(&[asn1::octet_string(&salt), asn1::uint(&iterations.to_be_bytes())])]);
    (alg, ct)
}

/// Decrypts a PKCS#8 `EncryptedPrivateKeyInfo`, returning the inner PrivateKeyInfo DER.
pub fn decrypt_encrypted_private_key_info(der: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut outer = Der::new(der);
    let mut s = outer.sequence().map_err(e)?;
    let alg = s.expect(TAG_SEQUENCE).map_err(e)?;
    let data = s.expect(TAG_OCTET_STRING).map_err(e)?;
    decrypt(alg.raw, data.value, password)
}

/// Builds a PKCS#8 `EncryptedPrivateKeyInfo` (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC).
pub fn encrypt_private_key_info(pkcs8: &[u8], password: &str) -> Vec<u8> {
    let (alg, ct) = encrypt_pbes2(pkcs8, password, DEFAULT_ITERATIONS);
    asn1::seq(&[alg, asn1::octet_string(&ct)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbes2_and_legacy_round_trips() {
        let data = b"some private key bytes, longer than one block".to_vec();
        let (alg, ct) = encrypt_pbes2(&data, "secret", 100);
        assert_eq!(decrypt(&alg, &ct, "secret").unwrap(), data);
        // a wrong password fails the padding check or yields different bytes, never `data`
        assert!(decrypt(&alg, &ct, "wrong").map(|p| p != data).unwrap_or(true));
        for oid in [OID_PBE_SHA_3DES, OID_PBE_SHA_RC2_40] {
            let (alg, ct) = encrypt_pkcs12_legacy(oid, &data, "pässword", 7);
            assert_eq!(decrypt(&alg, &ct, "pässword").unwrap(), data);
        }
        let epki = encrypt_private_key_info(&data, "pw");
        assert_eq!(decrypt_encrypted_private_key_info(&epki, "pw").unwrap(), data);
    }

    #[test]
    fn iteration_counts_are_bounded() {
        assert!(check_iterations(0).is_err());
        assert!(check_iterations(MAX_ITERATIONS + 1).is_err());
        assert_eq!(check_iterations(MAX_ITERATIONS).unwrap(), MAX_ITERATIONS as u32);
        // a PBES2 header asking for 2^31 iterations is refused before any work is done
        let alg = asn1::seq(&[
            asn1::oid(OID_PBES2),
            asn1::seq(&[
                asn1::seq(&[asn1::oid(OID_PBKDF2), asn1::seq(&[asn1::octet_string(&[1; 8]), asn1::uint(&0x8000_0000u32.to_be_bytes())])]),
                asn1::seq(&[asn1::oid(OID_AES256_CBC), asn1::octet_string(&[0; 16])]),
            ]),
        ]);
        let t = std::time::Instant::now();
        let err = decrypt(&alg, &[0; 16], "pw").unwrap_err();
        assert!(err.contains("iteration"), "{err}");
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        let alg = asn1::seq(&[asn1::oid(OID_PBE_SHA_3DES), asn1::seq(&[asn1::octet_string(&[1; 8]), asn1::uint(&u64::MAX.to_be_bytes())])]);
        assert!(decrypt(&alg, &[0; 8], "pw").unwrap_err().contains("iteration"));
    }

    #[test]
    fn unsupported_and_malformed_parameters() {
        assert!(decrypt(&asn1::seq(&[asn1::oid("1.2.3.4")]), &[0; 16], "pw").unwrap_err().contains("unsupported"));
        assert!(decrypt(&[0x30, 0x80], &[0; 16], "pw").is_err());
        // key length that contradicts the cipher
        let alg = asn1::seq(&[
            asn1::oid(OID_PBES2),
            asn1::seq(&[
                asn1::seq(&[asn1::oid(OID_PBKDF2), asn1::seq(&[asn1::octet_string(&[1; 8]), asn1::uint(&[1]), asn1::uint(&[16])])]),
                asn1::seq(&[asn1::oid(OID_AES256_CBC), asn1::octet_string(&[0; 16])]),
            ]),
        ]);
        assert!(decrypt(&alg, &[0; 16], "pw").unwrap_err().contains("length"));
        // a short IV is a decryption failure, not a panic
        let alg = asn1::seq(&[
            asn1::oid(OID_PBES2),
            asn1::seq(&[
                asn1::seq(&[asn1::oid(OID_PBKDF2), asn1::seq(&[asn1::octet_string(&[1; 8]), asn1::uint(&[1])])]),
                asn1::seq(&[asn1::oid(OID_AES128_CBC), asn1::octet_string(&[0; 3])]),
            ]),
        ]);
        assert!(decrypt(&alg, &[0; 16], "pw").is_err());
    }
}
