//! A message digest chosen at run time, SHA-1 included, with HMAC, PBKDF2 (RFC 8018) and the
//! PKCS#12 KDF (RFC 7292 appendix B.2). The TLS handshake uses [`HashAlg`] (SHA-2 only); this
//! type serves the formats that still name SHA-1: key stores, CRLs, OCSP and old certificates.
//!
//! (**Moves to ksar**; HMAC/PBKDF2/PKCS#12 KDF from Cameleer `cameleer-tls/src/crypto/{hash,kdf}.rs`.)

use super::sha1::Sha1;
use super::sha2::HashAlg;

/// A digest algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Md {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// A running hash of an [`Md`].
#[derive(Clone)]
pub enum MdHasher {
    Sha1(Sha1),
    Sha2(super::sha2::Hasher),
}

impl MdHasher {
    pub fn new(md: Md) -> MdHasher {
        match md.sha2() {
            None => MdHasher::Sha1(Sha1::new()),
            Some(h) => MdHasher::Sha2(super::sha2::Hasher::new(h)),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        match self {
            MdHasher::Sha1(h) => h.update(data),
            MdHasher::Sha2(h) => h.update(data),
        }
    }
    pub fn finish(self) -> Vec<u8> {
        match self {
            MdHasher::Sha1(h) => h.finish().to_vec(),
            MdHasher::Sha2(h) => h.finish().to_vec(),
        }
    }
}

impl From<HashAlg> for Md {
    fn from(h: HashAlg) -> Md {
        match h {
            HashAlg::Sha256 => Md::Sha256,
            HashAlg::Sha384 => Md::Sha384,
            HashAlg::Sha512 => Md::Sha512,
        }
    }
}

impl Md {
    /// The SHA-2 equivalent (None for SHA-1).
    pub fn sha2(self) -> Option<HashAlg> {
        match self {
            Md::Sha1 => None,
            Md::Sha256 => Some(HashAlg::Sha256),
            Md::Sha384 => Some(HashAlg::Sha384),
            Md::Sha512 => Some(HashAlg::Sha512),
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Md::Sha1 => 20,
            Md::Sha256 => 32,
            Md::Sha384 => 48,
            Md::Sha512 => 64,
        }
    }

    pub fn block_len(self) -> usize {
        match self {
            Md::Sha1 | Md::Sha256 => 64,
            _ => 128,
        }
    }

    /// The digest from its AlgorithmIdentifier OID (also accepts the HMAC OIDs of RFC 8018).
    pub fn from_oid(oid: &str) -> Option<Md> {
        Some(match oid {
            "1.3.14.3.2.26" | "1.2.840.113549.2.7" => Md::Sha1,
            "2.16.840.1.101.3.4.2.1" | "1.2.840.113549.2.9" => Md::Sha256,
            "2.16.840.1.101.3.4.2.2" | "1.2.840.113549.2.10" => Md::Sha384,
            "2.16.840.1.101.3.4.2.3" | "1.2.840.113549.2.11" => Md::Sha512,
            _ => return None,
        })
    }

    /// The digest OID (as used in OCSP CertIDs and PKCS#12 MacData).
    pub fn oid(self) -> &'static str {
        match self {
            Md::Sha1 => "1.3.14.3.2.26",
            Md::Sha256 => "2.16.840.1.101.3.4.2.1",
            Md::Sha384 => "2.16.840.1.101.3.4.2.2",
            Md::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    /// The HMAC OID (RFC 8018 PBKDF2 PRFs).
    pub fn hmac_oid(self) -> &'static str {
        match self {
            Md::Sha1 => "1.2.840.113549.2.7",
            Md::Sha256 => "1.2.840.113549.2.9",
            Md::Sha384 => "1.2.840.113549.2.10",
            Md::Sha512 => "1.2.840.113549.2.11",
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut h = MdHasher::new(self);
        h.update(data);
        h.finish()
    }

    /// HMAC over the concatenation of `parts`.
    pub fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        if let Some(h) = self.sha2() {
            return h.hmac(key, parts).to_vec();
        }
        let bl = self.block_len();
        let mut k = [0u8; 128];
        if key.len() > bl {
            let d = self.hash(key);
            k[..d.len()].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut pad = [0u8; 128];
        for (p, b) in pad[..bl].iter_mut().zip(&k[..bl]) {
            *p = b ^ 0x36;
        }
        let mut inner = MdHasher::new(self);
        inner.update(&pad[..bl]);
        for p in parts {
            inner.update(p);
        }
        let ih = inner.finish();
        for (p, b) in pad[..bl].iter_mut().zip(&k[..bl]) {
            *p = b ^ 0x5c;
        }
        let mut outer = MdHasher::new(self);
        outer.update(&pad[..bl]);
        outer.update(&ih);
        crate::util::zeroize(&mut k);
        crate::util::zeroize(&mut pad);
        outer.finish()
    }

    /// PBKDF2 with HMAC-`self` (RFC 8018 section 5.2).
    pub fn pbkdf2(self, password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut block = 1u32;
        while out.len() < len {
            let mut u = self.hmac(password, &[salt, &block.to_be_bytes()]);
            let mut t = u.clone();
            for _ in 1..iterations {
                u = self.hmac(password, &[&u]);
                for (a, b) in t.iter_mut().zip(&u) {
                    *a ^= b;
                }
            }
            let take = (len - out.len()).min(t.len());
            out.extend_from_slice(&t[..take]);
            block += 1;
        }
        out
    }

    /// The PKCS#12 KDF (RFC 7292 appendix B.2); `password` is already BMP encoded
    /// ([`bmp_password`]) and `id` is [`PKCS12_KEY`], [`PKCS12_IV`] or [`PKCS12_MAC`].
    pub fn pkcs12_kdf(self, password: &[u8], salt: &[u8], id: u8, iterations: u32, len: usize) -> Vec<u8> {
        let v = self.block_len();
        let u = self.output_len();
        let fill = |src: &[u8]| -> Vec<u8> {
            if src.is_empty() {
                return Vec::new();
            }
            let n = v * src.len().div_ceil(v);
            (0..n).map(|i| src[i % src.len()]).collect()
        };
        let mut i_buf = fill(salt);
        i_buf.extend(fill(password));
        let mut out = Vec::with_capacity(len);
        loop {
            let mut h = MdHasher::new(self);
            h.update(&vec![id; v]);
            h.update(&i_buf);
            let mut a = h.finish();
            for _ in 1..iterations {
                a = self.hash(&a);
            }
            let take = (len - out.len()).min(u);
            out.extend_from_slice(&a[..take]);
            if out.len() >= len {
                return out;
            }
            let b: Vec<u8> = (0..v).map(|i| a[i % u]).collect();
            for chunk in i_buf.chunks_mut(v) {
                // chunk = (chunk + b + 1) mod 2^(8v)
                let mut carry = 1u16;
                for k in (0..v).rev() {
                    let s = chunk[k] as u16 + b[k] as u16 + carry;
                    chunk[k] = s as u8;
                    carry = s >> 8;
                }
            }
        }
    }
}

/// PKCS#12 KDF purpose identifiers.
pub const PKCS12_KEY: u8 = 1;
pub const PKCS12_IV: u8 = 2;
pub const PKCS12_MAC: u8 = 3;

/// The password as a PKCS#12 BMPString: UTF-16BE with a terminating NUL (empty for an empty
/// password, as OpenSSL and Java write it).
pub fn bmp_password(password: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in password.encode_utf16() {
        out.extend_from_slice(&u.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn hmac_sha1_rfc2202() {
        assert_eq!(hex(&Md::Sha1.hmac(&[0x0b; 20], &[b"Hi There"])), "b617318655057264e28bc0b6fb378c8ef146be00");
        assert_eq!(hex(&Md::Sha1.hmac(b"Jefe", &[b"what do ya want ", b"for nothing?"])), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        // a key longer than the block is hashed first
        assert_eq!(
            hex(&Md::Sha1.hmac(&[0xaa; 80], &[b"Test Using Larger Than Block-Size Key - Hash Key First"])),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
        // SHA-2 delegates to HashAlg
        assert_eq!(hex(&Md::Sha256.hmac(b"Jefe", &[b"what do ya want for nothing?"])), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn pbkdf2_rfc6070_and_sha256() {
        assert_eq!(hex(&Md::Sha1.pbkdf2(b"password", b"salt", 1, 20)), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
        assert_eq!(hex(&Md::Sha1.pbkdf2(b"password", b"salt", 2, 20)), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
        assert_eq!(hex(&Md::Sha1.pbkdf2(b"password", b"salt", 4096, 20)), "4b007901b765489abead49d926f721d065a429c1");
        assert_eq!(
            hex(&Md::Sha1.pbkdf2(b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25)),
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
        );
        assert_eq!(hex(&Md::Sha256.pbkdf2(b"password", b"salt", 2, 32)), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    }

    #[test]
    fn pkcs12_kdf_vectors() {
        // BouncyCastle / OpenSSL PKCS#12 KDF vectors ("smeg", salt 0A58CF64530D823F)
        let pw = bmp_password("smeg");
        let salt = unhex("0A58CF64530D823F");
        assert_eq!(hex(&Md::Sha1.pkcs12_kdf(&pw, &salt, PKCS12_KEY, 1, 24)), "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3");
        assert_eq!(hex(&Md::Sha1.pkcs12_kdf(&pw, &salt, PKCS12_IV, 1, 8)), "79993dfe048d3b76");
        // "queeg", salt 1682C0FC5B3F7EC5, 1000 iterations
        let pw = bmp_password("queeg");
        let salt = unhex("1682C0FC5B3F7EC5");
        assert_eq!(hex(&Md::Sha1.pkcs12_kdf(&pw, &salt, PKCS12_KEY, 1000, 24)), "483dd6e919d7de2e8e648ba8f862f3fbfbdc2bcb2c02957f");
        assert_eq!(hex(&Md::Sha1.pkcs12_kdf(&pw, &salt, PKCS12_IV, 1000, 8)), "9d461d1b00355c50");
        assert_eq!(hex(&bmp_password("ab")), "0061006200 00".replace(' ', ""));
    }
}
