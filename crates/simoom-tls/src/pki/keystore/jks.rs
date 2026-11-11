//! Java key stores: Sun JKS (`FEEDFEED`) and JCEKS (`CECECECE`), read and write.
//!
//! Integrity: SHA-1 over the password (UTF-16BE), the string "Mighty Aphrodite" and the store
//! content, checked in constant time before any entry is parsed. Private keys are protected
//! with the JKS key protector (OID 1.3.6.1.4.1.42.2.17.1.1: a SHA-1 keystream XOR with a SHA-1
//! check value) or, in JCEKS, `PBEWithMD5AndTripleDES` (OID 1.3.6.1.4.1.42.2.19.1). JCEKS
//! secret-key entries (serialized Java objects) are not supported.
//!
//! Both formats are weak by today's standards (no or MD5-based key stretching); prefer
//! PKCS#12 for new stores. They are here so existing Java stores keep working.
//!
//! (**Moves to saltire-pki**; from Cameleer `cameleer-tls/src/keystore/jks.rs`.)

use crate::crypto::legacy::{cbc_decrypt, cbc_encrypt, Md5, TripleDes};
use super::{KeyStore, KeyStoreEntry, JCEKS_MAGIC, JKS_MAGIC, MAX_ENTRIES};
use crate::asn1::{self, Der, TAG_OCTET_STRING, TAG_SEQUENCE};
use crate::crypto::rng;
use crate::crypto::sha1::Sha1;
use crate::keys::PrivateKey;
use crate::util::{ct_eq, zeroize};

const OID_JKS_KEY_PROTECTOR: &str = "1.3.6.1.4.1.42.2.17.1.1";
const OID_PBE_MD5_3DES: &str = "1.3.6.1.4.1.42.2.19.1";
/// Longest certificate chain accepted in one key entry.
const MAX_CHAIN: usize = 64;
/// JCEKS `PBEWithMD5AndTripleDES` iterations when writing (the JDK's
/// `jdk.jceks.iterationCount` default).
pub const JCEKS_WRITE_ITERATIONS: u32 = 200_000;

struct Reader<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        match self.p.checked_add(n) {
            Some(end) if end <= self.d.len() => {
                let s = &self.d[self.p..end];
                self.p = end;
                Ok(s)
            }
            _ => Err("JKS: truncated key store".into()),
        }
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn utf(&mut self) -> Result<String, String> {
        let n = self.u16()? as usize;
        let b = self.take(n)?;
        Ok(decode_modified_utf8(b))
    }
    fn bytes32(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// Java "modified UTF-8" (NUL as C0 80, supplementary characters as surrogate pairs).
fn decode_modified_utf8(b: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as u32;
        if c < 0x80 {
            units.push(c as u16);
            i += 1;
        } else if c & 0xe0 == 0xc0 && i + 1 < b.len() {
            units.push((((c & 0x1f) << 6) | (b[i + 1] as u32 & 0x3f)) as u16);
            i += 2;
        } else if i + 2 < b.len() {
            units.push((((c & 0x0f) << 12) | ((b[i + 1] as u32 & 0x3f) << 6) | (b[i + 2] as u32 & 0x3f)) as u16);
            i += 3;
        } else {
            break;
        }
    }
    String::from_utf16_lossy(&units)
}

fn encode_modified_utf8(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in s.encode_utf16() {
        match u {
            1..=0x7f => out.push(u as u8),
            0 | 0x80..=0x7ff => {
                out.push(0xc0 | (u >> 6) as u8);
                out.push(0x80 | (u & 0x3f) as u8);
            }
            _ => {
                out.push(0xe0 | (u >> 12) as u8);
                out.push(0x80 | ((u >> 6) & 0x3f) as u8);
                out.push(0x80 | (u & 0x3f) as u8);
            }
        }
    }
    out
}

fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

fn integrity_digest(password: &str, content: &[u8]) -> [u8; 20] {
    let mut pw = utf16be(password);
    let mut h = Sha1::new();
    h.update(&pw);
    h.update(b"Mighty Aphrodite");
    h.update(content);
    zeroize(&mut pw);
    h.finish()
}

fn jks_keystream_xor(pw: &[u8], salt: &[u8], data: &[u8]) -> Vec<u8> {
    let mut digest = [0u8; 20];
    digest.copy_from_slice(&salt[..20]);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(20) {
        let mut h = Sha1::new();
        h.update(pw);
        h.update(&digest);
        digest = h.finish();
        out.extend(chunk.iter().zip(&digest).map(|(a, b)| a ^ b));
    }
    zeroize(&mut digest);
    out
}

/// Sun's proprietary JKS key protector.
fn jks_unprotect(enc: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if enc.len() < 40 {
        return Err("JKS: protected key too short".into());
    }
    let mut pw = utf16be(password);
    let (salt, rest) = enc.split_at(20);
    let (data, check) = rest.split_at(rest.len() - 20);
    let mut plain = jks_keystream_xor(&pw, salt, data);
    let mut h = Sha1::new();
    h.update(&pw);
    h.update(&plain);
    zeroize(&mut pw);
    if !ct_eq(&h.finish(), check) {
        zeroize(&mut plain);
        return Err("JKS: cannot recover key (wrong key password)".into());
    }
    Ok(plain)
}

fn jks_protect(plain: &[u8], password: &str) -> Vec<u8> {
    let mut pw = utf16be(password);
    let salt = rng::bytes(20);
    let mut out = salt.clone();
    out.extend(jks_keystream_xor(&pw, &salt, plain));
    let mut h = Sha1::new();
    h.update(&pw);
    h.update(plain);
    out.extend(h.finish());
    zeroize(&mut pw);
    out
}

/// The JCEKS `PBEWithMD5AndTripleDES` key and IV (com.sun.crypto.provider.PBES1Core):
/// 32 bytes = two 16-byte MD5 chains over each salt half and the password (one byte per
/// character, high bits dropped).
fn jceks_derive(salt: &[u8; 8], iterations: u32, password: &str) -> [u8; 32] {
    let mut pw: Vec<u8> = password.chars().map(|c| (c as u32 & 0x7f) as u8).collect();
    let mut s = *salt;
    if s[..4] == s[4..] {
        // The JDK "inverts" the first half when both halves are equal, with a long-standing
        // index bug (`salt[3-1]` for `salt[3-i]`) that it keeps for compatibility.
        for i in 0..2 {
            let tmp = s[i];
            s[i] = s[3 - i];
            s[2] = tmp;
        }
    }
    let mut out = [0u8; 32];
    for (half, dst) in s.chunks(4).zip(out.chunks_mut(16)) {
        let mut to_hash = [0u8; 16];
        let mut first = true;
        for _ in 0..iterations {
            let mut h = Md5::new();
            h.update(if first { half } else { &to_hash });
            h.update(&pw);
            to_hash = h.finish();
            first = false;
        }
        dst.copy_from_slice(&to_hash);
        zeroize(&mut to_hash);
    }
    zeroize(&mut pw);
    out
}

fn jceks_unprotect(params: &[u8], enc: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut p = Der::new(params).sequence().map_err(|e| e.to_string())?;
    let salt = p.octet_string().map_err(|e| e.to_string())?;
    let salt: &[u8; 8] = salt.try_into().map_err(|_| "JCEKS: bad PBE salt".to_string())?;
    let iter = super::pbe::check_iterations(p.small_uint().map_err(|e| e.to_string())?).map_err(|e| format!("JCEKS: {e}"))?;
    let mut derived = jceks_derive(salt, iter, password);
    let r = cbc_decrypt(&TripleDes::new(&derived[..24]), &derived[24..], enc);
    zeroize(&mut derived);
    r.ok_or_else(|| "JCEKS: cannot recover key (wrong key password)".to_string())
}

fn jceks_protect(plain: &[u8], password: &str) -> Vec<u8> {
    let salt: [u8; 8] = loop {
        let s = rng::array::<8>();
        if s[..4] != s[4..] {
            break s;
        }
    };
    let mut derived = jceks_derive(&salt, JCEKS_WRITE_ITERATIONS, password);
    let ct = cbc_encrypt(&TripleDes::new(&derived[..24]), &derived[24..], plain);
    zeroize(&mut derived);
    let params = asn1::seq(&[asn1::octet_string(&salt), asn1::uint(&JCEKS_WRITE_ITERATIONS.to_be_bytes())]);
    asn1::seq(&[asn1::seq(&[asn1::oid(OID_PBE_MD5_3DES), params]), asn1::octet_string(&ct)])
}

fn unprotect_key(der: &[u8], password: &str) -> Result<PrivateKey, String> {
    let mut s = Der::new(der).sequence().map_err(|e| format!("JKS: {e}"))?;
    let alg_tlv = s.expect(TAG_SEQUENCE).map_err(|e| format!("JKS: {e}"))?;
    let mut alg = alg_tlv.reader();
    let oid = alg.oid().map_err(|e| format!("JKS: {e}"))?;
    let enc = s.expect(TAG_OCTET_STRING).map_err(|e| format!("JKS: {e}"))?.value;
    let mut plain = match oid.as_str() {
        OID_JKS_KEY_PROTECTOR => jks_unprotect(enc, password)?,
        OID_PBE_MD5_3DES => {
            let params = alg.expect(TAG_SEQUENCE).map_err(|e| format!("JCEKS: {e}"))?;
            jceks_unprotect(params.raw, enc, password)?
        }
        // keytool -importkeystore can carry PKCS#12-style protection into JCEKS
        _ => super::pbe::decrypt(alg_tlv.raw, enc, password).map_err(|e| format!("JKS: key protection {oid}: {e}"))?,
    };
    let key = PrivateKey::from_pkcs8(&plain).map_err(|e| format!("JKS: private key: {e}"));
    zeroize(&mut plain);
    key
}

/// Parses a JKS or JCEKS store. Without `store_password` the integrity check is skipped (as
/// Java does for trust stores loaded without a password); `key_password` defaults to the
/// store password.
pub fn parse(data: &[u8], store_password: Option<&str>, key_password: Option<&str>) -> Result<KeyStore, String> {
    if data.len() < 32 {
        return Err("JKS: file too short".into());
    }
    let (content, digest) = data.split_at(data.len() - 20);
    if let Some(pw) = store_password {
        if !ct_eq(&integrity_digest(pw, content), digest) {
            return Err("Keystore was tampered with, or password was incorrect".into());
        }
    }
    let mut r = Reader { d: content, p: 0 };
    let magic = r.u32()?;
    let jceks = magic == JCEKS_MAGIC;
    if magic != JKS_MAGIC && !jceks {
        return Err("JKS: bad magic".into());
    }
    let version = r.u32()?;
    if version != 1 && version != 2 {
        return Err(format!("JKS: unsupported version {version}"));
    }
    let count = r.u32()? as usize;
    if count > MAX_ENTRIES {
        return Err(format!("JKS: too many entries ({count}, at most {MAX_ENTRIES})"));
    }
    let mut ks = KeyStore::new();
    let read_cert = |r: &mut Reader| -> Result<Vec<u8>, String> {
        if version == 2 {
            let typ = r.utf()?;
            if typ != "X.509" {
                return Err(format!("JKS: unsupported certificate type {typ}"));
            }
        }
        Ok(r.bytes32()?.to_vec())
    };
    for _ in 0..count {
        let tag = r.u32()?;
        let alias = r.utf()?;
        let _timestamp = r.take(8)?;
        match tag {
            1 => {
                let protected = r.bytes32()?;
                let n = r.u32()? as usize;
                if n > MAX_CHAIN {
                    return Err("JKS: certificate chain too long".into());
                }
                let mut chain = Vec::with_capacity(n);
                for _ in 0..n {
                    chain.push(read_cert(&mut r)?);
                }
                let kp = key_password.or(store_password).ok_or_else(|| format!("JKS: a key password is needed for entry '{alias}'"))?;
                let key = unprotect_key(protected, kp)?;
                ks.entries.push(KeyStoreEntry::Key { alias, key, chain });
            }
            2 => {
                let der = read_cert(&mut r)?;
                ks.entries.push(KeyStoreEntry::Cert { alias, der });
            }
            3 => return Err(format!("JCEKS: secret key entry '{alias}' is not supported")),
            other => return Err(format!("JKS: unknown entry tag {other}")),
        }
    }
    if r.p != content.len() {
        return Err("JKS: trailing data after the last entry".into());
    }
    Ok(ks)
}

/// Writes a JKS store (keys protected with the JKS key protector).
pub fn write(ks: &KeyStore, store_password: &str, key_password: &str) -> Vec<u8> {
    write_as(ks, store_password, key_password, false)
}

/// Writes a JCEKS store (keys protected with `PBEWithMD5AndTripleDES`,
/// [`JCEKS_WRITE_ITERATIONS`] iterations).
pub fn write_jceks(ks: &KeyStore, store_password: &str, key_password: &str) -> Vec<u8> {
    write_as(ks, store_password, key_password, true)
}

fn write_as(ks: &KeyStore, store_password: &str, key_password: &str, jceks: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(if jceks { JCEKS_MAGIC } else { JKS_MAGIC }).to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(ks.entries.len() as u32).to_be_bytes());
    let now_ms = (crate::x509::now_unix().max(0) as u64) * 1000;
    let put_utf = |out: &mut Vec<u8>, s: &str| {
        let mut b = encode_modified_utf8(s);
        b.truncate(u16::MAX as usize);
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(&b);
    };
    let put_cert = |out: &mut Vec<u8>, der: &[u8]| {
        put_utf(out, "X.509");
        out.extend_from_slice(&(der.len() as u32).to_be_bytes());
        out.extend_from_slice(der);
    };
    for e in &ks.entries {
        match e {
            KeyStoreEntry::Key { alias, key, chain } => {
                out.extend_from_slice(&1u32.to_be_bytes());
                put_utf(&mut out, alias);
                out.extend_from_slice(&now_ms.to_be_bytes());
                let mut pkcs8 = key.to_pkcs8();
                let epki = if jceks {
                    jceks_protect(&pkcs8, key_password)
                } else {
                    let protected = jks_protect(&pkcs8, key_password);
                    asn1::seq(&[asn1::seq(&[asn1::oid(OID_JKS_KEY_PROTECTOR), asn1::tlv(asn1::TAG_NULL, &[])]), asn1::octet_string(&protected)])
                };
                zeroize(&mut pkcs8);
                out.extend_from_slice(&(epki.len() as u32).to_be_bytes());
                out.extend_from_slice(&epki);
                out.extend_from_slice(&(chain.len() as u32).to_be_bytes());
                for c in chain {
                    put_cert(&mut out, c);
                }
            }
            KeyStoreEntry::Cert { alias, der } => {
                out.extend_from_slice(&2u32.to_be_bytes());
                put_utf(&mut out, alias);
                out.extend_from_slice(&now_ms.to_be_bytes());
                put_cert(&mut out, der);
            }
        }
    }
    let d = integrity_digest(store_password, &out);
    out.extend(d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_utf8_round_trips() {
        for s in ["server", "", "naïve", "\u{0}nul", "日本", "emoji \u{1F600}"] {
            assert_eq!(decode_modified_utf8(&encode_modified_utf8(s)), s);
        }
        assert_eq!(encode_modified_utf8("\u{0}"), vec![0xc0, 0x80]);
    }

    #[test]
    fn jks_protector_round_trip_and_wrong_password() {
        let data = b"0123456789012345678901234567890123456789-tail".to_vec();
        let p = jks_protect(&data, "pw");
        assert_eq!(jks_unprotect(&p, "pw").unwrap(), data);
        assert!(jks_unprotect(&p, "px").is_err());
        assert!(jks_unprotect(&p[..39], "pw").is_err());
    }

    #[test]
    fn jceks_salt_quirk() {
        // equal halves: the JDK turns [a b c d] into [d a b d] (see jceks_derive)
        let a = jceks_derive(&[1, 2, 3, 4, 1, 2, 3, 4], 1, "pw");
        let mut h = Md5::new();
        h.update(&[4, 1, 2, 4]);
        h.update(b"pw");
        assert_eq!(a[..16], h.finish());
        let b = jceks_derive(&[1, 2, 3, 4, 5, 6, 7, 8], 2, "pw");
        let mut h = Md5::new();
        h.update(&[1, 2, 3, 4]);
        h.update(b"pw");
        let x = h.finish();
        let mut h = Md5::new();
        h.update(&x);
        h.update(b"pw");
        assert_eq!(b[..16], h.finish());
    }

    #[test]
    fn hostile_counts_are_refused() {
        let mut body = Vec::new();
        body.extend_from_slice(&JKS_MAGIC.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        body.extend_from_slice(&[0; 16]);
        let d = integrity_digest("pw", &body);
        body.extend(d);
        assert!(parse(&body, Some("pw"), None).unwrap_err().contains("too many"));
        // a huge length field is a truncation error, not an allocation
        let mut body = Vec::new();
        body.extend_from_slice(&JKS_MAGIC.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes()); // trusted cert
        body.extend_from_slice(&[0, 1, b'a']);
        body.extend_from_slice(&[0; 8]);
        body.extend_from_slice(&[0, 5]);
        body.extend_from_slice(b"X.509");
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        body.extend_from_slice(&[0; 20]);
        assert!(parse(&body, None, None).unwrap_err().contains("truncated"));
    }
}
