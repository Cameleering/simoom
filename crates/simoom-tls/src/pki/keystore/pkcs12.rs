//! PKCS#12 (RFC 7292) reader and writer.
//!
//! Reading supports password integrity (MacData with HMAC-SHA1/SHA-256/SHA-384/SHA-512 and
//! the PKCS#12 KDF, checked in constant time before anything inside is used), `data` and
//! `encryptedData` safe contents (PBES2 with PBKDF2-HMAC-SHA* and AES-CBC/3DES, legacy
//! `pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbeWithSHAAnd2-KeyTripleDES-CBC`,
//! `pbeWithSHAAnd128BitRC2-CBC`, `pbeWithSHAAnd40BitRC2-CBC`), key bags, shrouded key bags,
//! certificate bags and nested safe-contents bags. Public-key integrity and privacy modes
//! (signedData / envelopedData), SHA-224 and SHA-512/t MACs and BER indefinite lengths are
//! not supported.
//!
//! Writing uses [`Pkcs12Profile::Modern`] by default: PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC
//! for keys and certificates and an HMAC-SHA256 MAC, as OpenSSL 3 and Java 17+ write it.
//!
//! (**Moves to ksar-pki**; from Cameleer `cameleer-tls/src/keystore/pkcs12.rs`.)

use super::pbe;
use super::{KeyStore, KeyStoreEntry, MAX_ENTRIES};
use crate::asn1::{self, Der, Tlv, TAG_OCTET_STRING, TAG_SEQUENCE, TAG_SET};
use crate::crypto::md::{bmp_password, Md, PKCS12_MAC};
use crate::crypto::rng;
use crate::keys::PrivateKey;
use crate::util::{ct_eq, zeroize};
use crate::x509::Certificate;

const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
const OID_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.1";
const OID_SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const OID_CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const OID_SAFE_CONTENTS_BAG: &str = "1.2.840.113549.1.12.10.1.6";
const OID_X509_CERT: &str = "1.2.840.113549.1.9.22.1";
const OID_FRIENDLY_NAME: &str = "1.2.840.113549.1.9.20";
const OID_LOCAL_KEY_ID: &str = "1.2.840.113549.1.9.21";
/// Java's "trusted for any usage" attribute marking trusted certificate entries.
const OID_ORACLE_TRUSTED: &str = "2.16.840.1.113894.746875.1.1";
const OID_ANY_EKU: &str = "2.5.29.37.0";
const OID_SHA224: &str = "2.16.840.1.101.3.4.2.4";
const OID_SHA1: &str = "1.3.14.3.2.26";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
/// Nesting limit for safe-contents bags.
const MAX_DEPTH: usize = 4;

fn e<T: std::fmt::Display>(x: T) -> String {
    format!("PKCS#12: {x}")
}

#[derive(Default)]
struct Attrs {
    name: Option<String>,
    key_id: Option<Vec<u8>>,
    trusted: bool,
}

fn parse_attrs(d: &mut Der) -> Result<Attrs, String> {
    let mut a = Attrs::default();
    if let Some(set) = d.optional(TAG_SET).map_err(e)? {
        let mut r = set.reader();
        while !r.is_empty() {
            let mut attr = r.sequence().map_err(e)?;
            let oid = attr.oid().map_err(e)?;
            let values = attr.expect(TAG_SET).map_err(e)?;
            let mut vr = values.reader();
            match oid.as_str() {
                OID_FRIENDLY_NAME => {
                    if let Ok(v) = vr.read() {
                        a.name = asn1::decode_string(&v);
                    }
                }
                OID_LOCAL_KEY_ID => a.key_id = vr.octet_string().ok().map(|v| v.to_vec()),
                OID_ORACLE_TRUSTED => a.trusted = true,
                _ => {}
            }
        }
    }
    Ok(a)
}

/// The content of a primitive or (one level) constructed OCTET STRING with tag
/// `primitive` / `primitive | 0x20`.
fn octets_tagged(t: &Tlv, primitive: u8) -> Result<Vec<u8>, String> {
    if t.tag == primitive {
        Ok(t.value.to_vec())
    } else if t.tag == primitive | 0x20 {
        let mut out = Vec::new();
        let mut r = t.reader();
        while !r.is_empty() {
            out.extend_from_slice(r.octet_string().map_err(e)?);
        }
        Ok(out)
    } else {
        Err(e(format!("expected OCTET STRING, found tag {:#04x}", t.tag)))
    }
}

/// An OCTET STRING that may be constructed (BER).
fn octets(t: &Tlv) -> Result<Vec<u8>, String> {
    octets_tagged(t, TAG_OCTET_STRING)
}

fn mac_hash(oid: &str) -> Result<Md, String> {
    match oid {
        OID_SHA1 => Ok(Md::Sha1),
        OID_SHA256 => Ok(Md::Sha256),
        OID_SHA384 => Ok(Md::Sha384),
        OID_SHA512 => Ok(Md::Sha512),
        OID_SHA224 => Err(e("SHA-224 MAC not supported")),
        other => Err(e(format!("unsupported MAC algorithm {other}"))),
    }
}

struct Collected {
    keys: Vec<(Attrs, PrivateKey)>,
    certs: Vec<(Attrs, Vec<u8>)>,
}

impl Collected {
    fn check_size(&self) -> Result<(), String> {
        if self.keys.len() + self.certs.len() > MAX_ENTRIES {
            return Err(e(format!("more than {MAX_ENTRIES} entries")));
        }
        Ok(())
    }
}

fn parse_safe_contents(data: &[u8], key_password: &str, out: &mut Collected, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(e("safe contents nested too deeply"));
    }
    let mut outer = Der::new(data);
    let mut bags = outer.sequence().map_err(e)?;
    while !bags.is_empty() {
        out.check_size()?;
        let mut bag = bags.sequence().map_err(e)?;
        let oid = bag.oid().map_err(e)?;
        let value = bag.expect(0xa0).map_err(e)?;
        let attrs = parse_attrs(&mut bag)?;
        let mut v = value.reader();
        match oid.as_str() {
            OID_KEY_BAG => {
                let der = v.expect(TAG_SEQUENCE).map_err(e)?;
                out.keys.push((attrs, PrivateKey::from_pkcs8(der.raw).map_err(e)?));
            }
            OID_SHROUDED_KEY_BAG => {
                let der = v.expect(TAG_SEQUENCE).map_err(e)?;
                let mut plain = pbe::decrypt_encrypted_private_key_info(der.raw, key_password)
                    .map_err(|x| e(format!("cannot decrypt private key: {x}")))?;
                let key = PrivateKey::from_pkcs8(&plain).map_err(|x| e(format!("private key (wrong key password?): {x}")));
                zeroize(&mut plain);
                out.keys.push((attrs, key?));
            }
            OID_CERT_BAG => {
                let mut cb = v.sequence().map_err(e)?;
                let cert_type = cb.oid().map_err(e)?;
                let cv = cb.expect(0xa0).map_err(e)?;
                if cert_type == OID_X509_CERT {
                    let t = cv.reader().read().map_err(e)?;
                    out.certs.push((attrs, octets(&t)?));
                }
            }
            OID_SAFE_CONTENTS_BAG => {
                let inner = v.expect(TAG_SEQUENCE).map_err(e)?;
                parse_safe_contents(inner.raw, key_password, out, depth + 1)?;
            }
            _ => {} // CRL, secret and unknown bags are ignored
        }
    }
    Ok(())
}

/// Verifies the MacData of a PFX over `auth_data` in constant time.
fn verify_mac(mac_data: &mut Der, auth_data: &[u8], password: &str) -> Result<(), String> {
    let mut digest_info = mac_data.sequence().map_err(e)?;
    let mut alg = digest_info.sequence().map_err(e)?;
    let h = mac_hash(&alg.oid().map_err(e)?)?;
    let expected = digest_info.octet_string().map_err(e)?;
    let salt = mac_data.octet_string().map_err(e)?;
    let iter = if mac_data.is_empty() { 1 } else { pbe::check_iterations(mac_data.small_uint().map_err(e)?).map_err(e)? };
    let mut pw = bmp_password(password);
    let mut key = h.pkcs12_kdf(&pw, salt, PKCS12_MAC, iter, h.output_len());
    let mut ok = ct_eq(&h.hmac(&key, &[auth_data]), expected);
    zeroize(&mut key);
    zeroize(&mut pw);
    if !ok && password.is_empty() {
        // some tools derive the MAC key of an empty password from zero-length input
        let mut key = h.pkcs12_kdf(&[], salt, PKCS12_MAC, iter, h.output_len());
        ok = ct_eq(&h.hmac(&key, &[auth_data]), expected);
        zeroize(&mut key);
    }
    if ok {
        Ok(())
    } else {
        Err("PKCS#12 MAC verification failed: keystore password was incorrect".into())
    }
}

/// Parses a PKCS#12 file. `password` is the integrity and privacy password; `key_password`
/// (default: `password`) decrypts shrouded key bags. A file without MacData is accepted
/// unverified, as OpenSSL and Java do (`-nomac` files).
pub fn parse(data: &[u8], password: &str, key_password: Option<&str>) -> Result<KeyStore, String> {
    let mut outer = Der::new(data);
    let mut pfx = outer.sequence().map_err(|x| e(format!("not a PKCS#12 / key store file ({x})")))?;
    if !outer.is_empty() {
        return Err(e("trailing data after the PFX"));
    }
    if pfx.small_uint().map_err(e)? != 3 {
        return Err(e("unsupported PFX version"));
    }
    let mut auth_safe = pfx.sequence().map_err(e)?;
    let ct = auth_safe.oid().map_err(e)?;
    if ct != OID_DATA {
        return Err(e(format!("unsupported integrity mode (content type {ct}); only password integrity is supported")));
    }
    let content = auth_safe.expect(0xa0).map_err(e)?;
    let auth_data = octets(&content.reader().read().map_err(e)?)?;
    if !pfx.is_empty() {
        let mut mac_data = pfx.sequence().map_err(e)?;
        verify_mac(&mut mac_data, &auth_data, password)?;
    }
    let key_password = key_password.unwrap_or(password);
    let mut col = Collected { keys: Vec::new(), certs: Vec::new() };
    let mut seq = Der::new(&auth_data);
    let mut infos = seq.sequence().map_err(e)?;
    while !infos.is_empty() {
        let mut ci = infos.sequence().map_err(e)?;
        let ct = ci.oid().map_err(e)?;
        let content = ci.expect(0xa0).map_err(e)?;
        match ct.as_str() {
            OID_DATA => {
                let sc = octets(&content.reader().read().map_err(e)?)?;
                parse_safe_contents(&sc, key_password, &mut col, 0)?;
            }
            OID_ENCRYPTED_DATA => {
                let mut ed = content.reader().sequence().map_err(e)?;
                let _version = ed.small_uint().map_err(e)?;
                let mut eci = ed.sequence().map_err(e)?;
                let _ct = eci.oid().map_err(e)?;
                let alg = eci.expect(TAG_SEQUENCE).map_err(e)?;
                let enc = eci.read().map_err(e)?;
                // [0] IMPLICIT OCTET STRING, primitive or constructed
                let ciphertext = octets_tagged(&enc, 0x80)?;
                let plain = pbe::decrypt(alg.raw, &ciphertext, password).map_err(|x| e(format!("cannot decrypt safe contents: {x}")))?;
                parse_safe_contents(&plain, key_password, &mut col, 0)?;
            }
            other => return Err(e(format!("unsupported safe contents type {other}"))),
        }
    }
    col.check_size()?;
    Ok(assemble(col))
}

fn assemble(col: Collected) -> KeyStore {
    let mut ks = KeyStore::new();
    let mut used = vec![false; col.certs.len()];
    let cert_ders: Vec<Vec<u8>> = col.certs.iter().map(|(_, d)| d.clone()).collect();
    for (i, (attrs, key)) in col.keys.into_iter().enumerate() {
        // the leaf by localKeyId, else by public key
        let pk = key.public_key();
        let leaf = attrs.key_id.as_ref().and_then(|id| col.certs.iter().position(|(a, _)| a.key_id.as_ref() == Some(id))).or_else(|| {
            col.certs.iter().position(|(_, d)| Certificate::from_der(d).ok().and_then(|c| c.public_key).is_some_and(|k| k.same_as(&pk)))
        });
        let mut chain = Vec::new();
        if let Some(l) = leaf {
            used[l] = true;
            let mut ordered = vec![cert_ders[l].clone()];
            ordered.extend(cert_ders.iter().enumerate().filter(|(j, _)| *j != l).map(|(_, d)| d.clone()));
            chain = super::order_chain(&key, &ordered);
            // certificates that complete the chain belong to the key entry
            for c in chain.iter().skip(1) {
                if let Some(j) = cert_ders.iter().position(|d| d == c) {
                    if col.certs[j].0.key_id.is_none() && !col.certs[j].0.trusted {
                        used[j] = true;
                    }
                }
            }
        }
        let alias = attrs.name.clone().or_else(|| leaf.and_then(|l| col.certs[l].0.name.clone())).unwrap_or_else(|| format!("{}", i + 1));
        ks.entries.push(KeyStoreEntry::Key { alias, key, chain });
    }
    // Certificates completing a key's chain (OpenSSL -certfile / -chain) belong to that entry,
    // as in Java; the remaining ones are trusted-certificate entries.
    for (j, (attrs, der)) in col.certs.into_iter().enumerate() {
        if (used[j] || attrs.key_id.is_some()) && !attrs.trusted {
            continue;
        }
        let alias = attrs.name.unwrap_or_else(|| format!("cert{j}"));
        ks.entries.push(KeyStoreEntry::Cert { alias, der });
    }
    ks
}

/// Encryption profile used by [`write`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pkcs12Profile {
    /// PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC, HMAC-SHA256 MAC (OpenSSL 3, Java 17+).
    Modern,
    /// pbeWithSHAAnd3-KeyTripleDES-CBC keys, pbeWithSHAAnd40BitRC2-CBC certificates,
    /// HMAC-SHA1 MAC (OpenSSL 1.x / older Java defaults). Only for consumers that cannot read
    /// the modern profile.
    Legacy,
}

fn attr(oid: &str, value: Vec<u8>) -> Vec<u8> {
    asn1::seq(&[asn1::oid(oid), asn1::set(&[value])])
}

fn bmp(s: &str) -> Vec<u8> {
    let v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    asn1::tlv(asn1::TAG_BMP_STRING, &v)
}

fn bag(oid: &str, value: Vec<u8>, attrs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut parts = vec![asn1::oid(oid), asn1::explicit(0, &value)];
    if !attrs.is_empty() {
        parts.push(asn1::set(&attrs));
    }
    asn1::seq(&parts)
}

fn cert_bag(der: &[u8], attrs: Vec<Vec<u8>>) -> Vec<u8> {
    bag(OID_CERT_BAG, asn1::seq(&[asn1::oid(OID_X509_CERT), asn1::explicit(0, &asn1::octet_string(der))]), attrs)
}

/// Serialises a key store as PKCS#12 protected by `password` (also the key password).
pub fn write(ks: &KeyStore, password: &str, profile: Pkcs12Profile) -> Vec<u8> {
    let iterations = pbe::DEFAULT_ITERATIONS;
    let mut key_bags = Vec::new();
    let mut cert_bags = Vec::new();
    for (i, entry) in ks.entries.iter().enumerate() {
        match entry {
            KeyStoreEntry::Key { alias, key, chain } => {
                let mut id = rng::bytes(4);
                id.extend_from_slice(&(i as u32).to_be_bytes());
                let attrs = vec![attr(OID_FRIENDLY_NAME, bmp(alias)), attr(OID_LOCAL_KEY_ID, asn1::octet_string(&id))];
                let mut pkcs8 = key.to_pkcs8();
                let (alg, ct) = match profile {
                    Pkcs12Profile::Modern => pbe::encrypt_pbes2(&pkcs8, password, iterations),
                    Pkcs12Profile::Legacy => pbe::encrypt_pkcs12_legacy(pbe::OID_PBE_SHA_3DES, &pkcs8, password, iterations),
                };
                zeroize(&mut pkcs8);
                key_bags.push(bag(OID_SHROUDED_KEY_BAG, asn1::seq(&[alg, asn1::octet_string(&ct)]), attrs.clone()));
                for (j, c) in chain.iter().enumerate() {
                    cert_bags.push(cert_bag(c, if j == 0 { attrs.clone() } else { Vec::new() }));
                }
            }
            KeyStoreEntry::Cert { alias, der } => {
                let trusted = attr(OID_ORACLE_TRUSTED, asn1::oid(OID_ANY_EKU));
                cert_bags.push(cert_bag(der, vec![attr(OID_FRIENDLY_NAME, bmp(alias)), trusted]));
            }
        }
    }
    let data_ci = |content: &[u8]| asn1::seq(&[asn1::oid(OID_DATA), asn1::explicit(0, &asn1::octet_string(content))]);
    let mut infos = Vec::new();
    if !cert_bags.is_empty() {
        let sc = asn1::seq(&cert_bags);
        let (alg, ct) = match profile {
            Pkcs12Profile::Modern => pbe::encrypt_pbes2(&sc, password, iterations),
            Pkcs12Profile::Legacy => pbe::encrypt_pkcs12_legacy(pbe::OID_PBE_SHA_RC2_40, &sc, password, iterations),
        };
        let eci = asn1::seq(&[asn1::oid(OID_DATA), alg, asn1::tlv(0x80, &ct)]);
        infos.push(asn1::seq(&[asn1::oid(OID_ENCRYPTED_DATA), asn1::explicit(0, &asn1::seq(&[asn1::uint(&[0]), eci]))]));
    }
    if !key_bags.is_empty() {
        infos.push(data_ci(&asn1::seq(&key_bags)));
    }
    let auth_safe = asn1::seq(&infos);
    let h = match profile {
        Pkcs12Profile::Modern => Md::Sha256,
        Pkcs12Profile::Legacy => Md::Sha1,
    };
    let salt = rng::bytes(16);
    let mut pw = bmp_password(password);
    let mut mac_key = h.pkcs12_kdf(&pw, &salt, PKCS12_MAC, iterations, h.output_len());
    let mac = h.hmac(&mac_key, &[&auth_safe]);
    zeroize(&mut mac_key);
    zeroize(&mut pw);
    let mac_data = asn1::seq(&[
        asn1::seq(&[asn1::seq(&[asn1::oid(h.oid()), asn1::tlv(asn1::TAG_NULL, &[])]), asn1::octet_string(&mac)]),
        asn1::octet_string(&salt),
        asn1::uint(&iterations.to_be_bytes()),
    ]);
    asn1::seq(&[asn1::uint(&[3]), data_ci(&auth_safe), mac_data])
}
