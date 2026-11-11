//! A std-only mutation fuzzer for the key store parsers: PKCS#12 (whole files, and the inner
//! safe contents behind a valid MAC so mutations get past the integrity check), JKS and JCEKS
//! (parsed without a store password, so the integrity digest does not stop them), encrypted
//! PKCS#8 (DER and PEM) and PEM bundles. The invariant is "no panic, no hang": every input
//! must load or fail with an error.
//!
//! Seeds use iteration counts of 1 (re-encoded where a fixture has more), so that a mutated
//! count stays small and the run stays fast; the hard cap on counts read from a file is
//! tested in `tests/keystores.rs`. Scale with `SIMOOM_FUZZ_ITERS=<multiplier>` and pick a
//! seed with `SIMOOM_FUZZ_SEED=<u64>`.

use simoom_tls::asn1::{self, Der, TAG_OCTET_STRING, TAG_SEQUENCE};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::crypto::md::{bmp_password, Md, PKCS12_MAC};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::keystore::{self, pbe, pkcs12, KeyStore, KeyStoreFormat};
use std::path::PathBuf;

/// xorshift64* generator.
pub struct Rng(pub u64);

impl Rng {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const INTERESTING: [u16; 10] = [0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x4000, 0xffff];

/// One to four stacked mutations of `input` (bit flips, byte and 16-bit boundary writes,
/// insertions, deletions, duplication, truncation, splicing from `others`).
pub fn mutate(rng: &mut Rng, input: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    let mut d = input.to_vec();
    for _ in 0..1 + rng.below(4) {
        let n = d.len();
        match rng.below(9) {
            0 if n > 0 => {
                let i = rng.below(n);
                d[i] ^= 1 << rng.below(8);
            }
            1 if n > 0 => {
                let i = rng.below(n);
                d[i] = rng.next() as u8;
            }
            2 if n > 1 => {
                let i = rng.below(n - 1);
                let v = INTERESTING[rng.below(INTERESTING.len())].to_be_bytes();
                d[i..i + 2].copy_from_slice(&v);
            }
            3 => {
                let i = rng.below(n + 1);
                for _ in 0..1 + rng.below(16) {
                    d.insert(i, rng.next() as u8);
                }
            }
            4 if n > 0 => {
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(32));
                d.drain(i..i + k);
            }
            5 if n > 0 => {
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(64));
                let chunk = d[i..i + k].to_vec();
                let j = rng.below(n + 1);
                d.splice(j..j, chunk);
            }
            6 if n > 0 => d.truncate(rng.below(n)),
            7 if !others.is_empty() => {
                let o = &others[rng.below(others.len())];
                if !o.is_empty() {
                    let i = rng.below(o.len());
                    let k = 1 + rng.below((o.len() - i).min(64));
                    let j = rng.below(n + 1);
                    d.splice(j..j, o[i..i + k].iter().copied());
                }
            }
            _ if n > 0 => {
                let i = rng.below(n);
                d[i] = d[i].wrapping_add(1 + rng.below(3) as u8);
            }
            _ => {}
        }
        d.truncate(1 << 16);
    }
    d
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)).unwrap()
}

const PW: &str = "pw";

/// A PFX around `auth_safe` with a valid HMAC-SHA256 MAC (1 iteration).
fn pfx_with_mac(auth_safe: &[u8]) -> Vec<u8> {
    let salt = [7u8; 8];
    let key = Md::Sha256.pkcs12_kdf(&bmp_password(PW), &salt, PKCS12_MAC, 1, 32);
    let mac = Md::Sha256.hmac(&key, &[auth_safe]);
    asn1::seq(&[
        asn1::uint(&[3]),
        asn1::seq(&[asn1::oid("1.2.840.113549.1.7.1"), asn1::explicit(0, &asn1::octet_string(auth_safe))]),
        asn1::seq(&[
            asn1::seq(&[asn1::seq(&[asn1::oid(Md::Sha256.oid()), asn1::tlv(asn1::TAG_NULL, &[])]), asn1::octet_string(&mac)]),
            asn1::octet_string(&salt),
            asn1::uint(&[1]),
        ]),
    ])
}

/// An authenticated-safe with every bag kind, encrypted parts using 1 iteration.
fn auth_safe_seed(key: &PrivateKey, cert: &[u8]) -> Vec<u8> {
    let attrs = asn1::set(&[
        asn1::seq(&[asn1::oid("1.2.840.113549.1.9.20"), asn1::set(&[asn1::tlv(asn1::TAG_BMP_STRING, &[0, b's'])])]),
        asn1::seq(&[asn1::oid("1.2.840.113549.1.9.21"), asn1::set(&[asn1::octet_string(&[1, 2, 3, 4])])]),
    ]);
    let cert_bag = asn1::seq(&[
        asn1::oid("1.2.840.113549.1.12.10.1.3"),
        asn1::explicit(0, &asn1::seq(&[asn1::oid("1.2.840.113549.1.9.22.1"), asn1::explicit(0, &asn1::octet_string(cert))])),
        attrs.clone(),
    ]);
    let (alg, ct) = pbe::encrypt_pbes2(&key.to_pkcs8(), PW, 1);
    let shrouded = asn1::seq(&[asn1::oid("1.2.840.113549.1.12.10.1.2"), asn1::explicit(0, &asn1::seq(&[alg, asn1::octet_string(&ct)])), attrs]);
    let (alg3, ct3) = pbe::encrypt_pkcs12_legacy(pbe::OID_PBE_SHA_3DES, &key.to_pkcs8(), PW, 1);
    let shrouded3 = asn1::seq(&[asn1::oid("1.2.840.113549.1.12.10.1.2"), asn1::explicit(0, &asn1::seq(&[alg3, asn1::octet_string(&ct3)]))]);
    let plain_key = asn1::seq(&[asn1::oid("1.2.840.113549.1.12.10.1.1"), asn1::explicit(0, &key.to_pkcs8())]);
    let nested = asn1::seq(&[asn1::oid("1.2.840.113549.1.12.10.1.6"), asn1::explicit(0, &asn1::seq(std::slice::from_ref(&cert_bag)))]);
    let data_ci = |c: &[u8]| asn1::seq(&[asn1::oid("1.2.840.113549.1.7.1"), asn1::explicit(0, &asn1::octet_string(c))]);
    let enc_ci = |alg: Vec<u8>, ct: Vec<u8>| {
        let eci = asn1::seq(&[asn1::oid("1.2.840.113549.1.7.1"), alg, asn1::tlv(0x80, &ct)]);
        asn1::seq(&[asn1::oid("1.2.840.113549.1.7.6"), asn1::explicit(0, &asn1::seq(&[asn1::uint(&[0]), eci]))])
    };
    let certs = asn1::seq(std::slice::from_ref(&cert_bag));
    let (a1, c1) = pbe::encrypt_pbes2(&certs, PW, 1);
    let (a2, c2) = pbe::encrypt_pkcs12_legacy(pbe::OID_PBE_SHA_RC2_40, &certs, PW, 1);
    asn1::seq(&[enc_ci(a1, c1), enc_ci(a2, c2), data_ci(&asn1::seq(&[shrouded, shrouded3, plain_key, nested]))])
}

/// Rewrites every key entry's protection parameters in a JKS/JCEKS store with `f` and fixes
/// the lengths (the integrity digest is left stale: the fuzzer parses without a store password).
fn rewrite_jks_keys(store: &[u8], f: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let content = &store[..store.len() - 20];
    let mut out = content[..12].to_vec();
    let version = u32::from_be_bytes(content[4..8].try_into().unwrap());
    let count = u32::from_be_bytes(content[8..12].try_into().unwrap());
    let mut p = 12;
    let take = |p: &mut usize, n: usize| -> std::ops::Range<usize> {
        *p += n;
        *p - n..*p
    };
    let u32_at = |p: usize| u32::from_be_bytes(content[p..p + 4].try_into().unwrap()) as usize;
    let u16_at = |p: usize| u16::from_be_bytes(content[p..p + 2].try_into().unwrap()) as usize;
    let copy_cert = |p: &mut usize, out: &mut Vec<u8>| {
        if version == 2 {
            let n = u16_at(*p);
            out.extend_from_slice(&content[take(p, 2 + n)]);
        }
        let n = u32_at(*p);
        out.extend_from_slice(&content[take(p, 4 + n)]);
    };
    for _ in 0..count {
        let tag = u32_at(p);
        out.extend_from_slice(&content[take(&mut p, 4)]);
        let n = u16_at(p);
        out.extend_from_slice(&content[take(&mut p, 2 + n + 8)]);
        if tag == 1 {
            let n = u32_at(p);
            let r = take(&mut p, 4 + n);
            let protected = f(&content[r.start + 4..r.end]);
            out.extend_from_slice(&(protected.len() as u32).to_be_bytes());
            out.extend_from_slice(&protected);
            let chain = u32_at(p);
            out.extend_from_slice(&content[take(&mut p, 4)]);
            for _ in 0..chain {
                copy_cert(&mut p, &mut out);
            }
        } else {
            copy_cert(&mut p, &mut out);
        }
    }
    out.extend_from_slice(&[0; 20]);
    out
}

/// JCEKS key protection with the iteration count set to 1.
fn jceks_one_iteration(epki: &[u8]) -> Vec<u8> {
    let mut s = Der::new(epki).sequence().unwrap();
    let mut alg = s.sequence().unwrap();
    let oid = alg.oid().unwrap();
    let enc = s.expect(TAG_OCTET_STRING).unwrap().value;
    if oid != "1.3.6.1.4.1.42.2.19.1" {
        return epki.to_vec();
    }
    let mut params = alg.expect(TAG_SEQUENCE).unwrap().reader();
    let salt = params.octet_string().unwrap();
    asn1::seq(&[asn1::seq(&[asn1::oid(&oid), asn1::seq(&[asn1::octet_string(salt), asn1::uint(&[1])])]), asn1::octet_string(enc)])
}

/// Seeds for the key store targets.
pub struct Corpus {
    /// Complete PKCS#12 files (fixtures and our writer).
    pub pfx: Vec<Vec<u8>>,
    /// Authenticated-safe contents, wrapped in a valid MAC after mutation.
    pub auth_safe: Vec<Vec<u8>>,
    /// JKS and JCEKS stores (iteration counts 1).
    pub jks: Vec<Vec<u8>>,
    /// EncryptedPrivateKeyInfo DER (iteration counts 1).
    pub epki: Vec<Vec<u8>>,
    /// PEM text: bundles and keys.
    pub pem: Vec<Vec<u8>>,
}

pub fn corpus() -> Corpus {
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let ks = KeyStore::from_key_entry("k", ss.key.clone(), vec![ss.cert_der.clone()]).add_cert("t", ss.cert_der.clone());
    let pfx = vec![read("keystores/openssl_modern.p12"), read("keystores/openssl_trust.p12"), read("keystores/openssl3_plain_nomac.p12"), ks.to_pkcs12(PW)];
    let auth_safe = vec![auth_safe_seed(&ss.key, &ss.cert_der)];
    let jks = vec![
        rewrite_jks_keys(&read("keystores/keytool.jceks"), jceks_one_iteration),
        read("keystores/keytool.jks"),
        read("keystores/keytool_trust.jks"),
        rewrite_jks_keys(&ks.to_jceks(PW, PW), jceks_one_iteration),
        ks.to_jks(PW, PW),
    ];
    let pkcs8 = ss.key.to_pkcs8();
    let epki = vec![
        pbe::encrypt_pbes2(&pkcs8, PW, 1),
        pbe::encrypt_pkcs12_legacy(pbe::OID_PBE_SHA_3DES, &pkcs8, PW, 1),
        pbe::encrypt_pkcs12_legacy(pbe::OID_PBE_SHA_RC2_40, &pkcs8, PW, 1),
    ]
    .into_iter()
    .map(|(alg, ct)| asn1::seq(&[alg, asn1::octet_string(&ct)]))
    .collect::<Vec<_>>();
    let enc_pem = simoom_tls::pem::encode_pem("ENCRYPTED PRIVATE KEY", &epki[0]);
    let pem = vec![
        format!("{}{}", ss.cert_pem, ss.key_pem).into_bytes(),
        format!("{}{}", ss.cert_pem, enc_pem).into_bytes(),
        read("leaf.key"),
        read("rsa2048.pkcs1.pem"),
    ];
    Corpus { pfx, auth_safe, jks, epki, pem }
}

/// Runs `iters` mutated inputs through every key store parser; any panic fails the test.
pub fn keystores(rng: &mut Rng, corpus: &Corpus, iters: usize) {
    let all: Vec<Vec<u8>> = [&corpus.pfx, &corpus.auth_safe, &corpus.jks, &corpus.epki, &corpus.pem].into_iter().flatten().cloned().collect();
    // the seeds themselves parse (sanity check of the harness)
    assert!(pkcs12::parse(&pfx_with_mac(&corpus.auth_safe[0]), PW, None).is_ok());
    assert!(keystore::jks::parse(&corpus.jks[1], None, Some("keypass")).is_ok());
    assert!(pbe::decrypt_encrypted_private_key_info(&corpus.epki[0], PW).is_ok());
    for i in 0..iters {
        match i % 5 {
            0 => {
                let seed = &corpus.pfx[rng.below(corpus.pfx.len())];
                let m = mutate(rng, seed, &all);
                let _ = KeyStore::load_as(&m, KeyStoreFormat::Pkcs12, Some("changeit"), None);
                let _ = KeyStore::load(&m, Some(PW), None);
            }
            1 => {
                let seed = &corpus.auth_safe[rng.below(corpus.auth_safe.len())];
                let m = mutate(rng, seed, &all);
                let _ = pkcs12::parse(&pfx_with_mac(&m), PW, None);
                let _ = pkcs12::parse(&pfx_with_mac(&m), PW, Some("other"));
            }
            2 => {
                let seed = &corpus.jks[rng.below(corpus.jks.len())];
                let m = mutate(rng, seed, &all);
                let kp = if rng.below(2) == 0 { "keypass" } else { PW };
                let _ = keystore::jks::parse(&m, None, Some(kp));
                let _ = KeyStore::load(&m, Some(PW), Some(kp));
            }
            3 => {
                let seed = &corpus.epki[rng.below(corpus.epki.len())];
                let m = mutate(rng, seed, &all);
                let _ = pbe::decrypt_encrypted_private_key_info(&m, PW);
                let pem = simoom_tls::pem::encode_pem("ENCRYPTED PRIVATE KEY", &m);
                let _ = keystore::private_key_from_pem(pem.as_bytes(), Some(PW));
            }
            _ => {
                let seed = &corpus.pem[rng.below(corpus.pem.len())];
                let m = mutate(rng, seed, &all);
                let _ = KeyStore::load(&m, None, Some(PW));
                let _ = keystore::private_key_from_pem(&m, Some(PW));
            }
        }
    }
}

fn iters(base: usize) -> usize {
    let k: usize = std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    base * k
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_1234_abcd_0042)
}

#[test]
fn fuzz_key_store_parsers() {
    let c = corpus();
    let t = std::time::Instant::now();
    keystores(&mut Rng(seed()), &c, iters(3000));
    eprintln!("key store fuzz: {} inputs in {:?}", iters(3000), t.elapsed());
}
