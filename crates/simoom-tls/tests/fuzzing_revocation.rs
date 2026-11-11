//! A std-only mutation fuzzer for the CRL and OCSP parsers and validators (modelled on
//! `tests/fuzzing/mod.rs`): seeds are OpenSSL fixtures and generated CRLs and responses;
//! mutations are bit flips, byte overwrites, DER length rewrites with boundary values,
//! insertions, deletions, splicing and truncation. The invariant is "no panic"; every result
//! must be an `Ok` or an `Err`. Scale with `SIMOOM_FUZZ_ITERS=<multiplier>` and pick a seed
//! with `SIMOOM_FUZZ_SEED`.

use simoom_tls::revocation::crl::{Crl, CrlBuilder, CrlLimits};
use simoom_tls::revocation::ocsp::{self, CertStatus, OcspRequest, OcspResponse};
use simoom_tls::revocation::testing::{MapFetcher, TestPki};
use simoom_tls::revocation::{check_path, CrlMode, OcspMode, RevocationFetcher, RevocationPolicy};
use std::sync::Arc;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const LENGTHS: [&[u8]; 10] = [&[0x00], &[0x7f], &[0x80], &[0x81, 0xff], &[0x82, 0xff, 0xff], &[0x83, 0x10, 0, 0], &[0x84, 0xff, 0xff, 0xff, 0xff], &[0x85, 1, 0, 0, 0, 0], &[0x81, 0x00], &[0x01]];
const TAGS: [u8; 12] = [0x02, 0x03, 0x04, 0x05, 0x06, 0x0a, 0x17, 0x18, 0x30, 0x31, 0xa0, 0x80];

fn mutate(rng: &mut Rng, input: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
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
                // rewrite a length octet (after any byte) with a boundary encoding
                let i = 1 + rng.below(n - 1);
                let l = LENGTHS[rng.below(LENGTHS.len())];
                d.splice(i..i + 1, l.iter().copied());
            }
            3 if n > 0 => {
                let i = rng.below(n);
                d[i] = TAGS[rng.below(TAGS.len())];
            }
            4 => {
                let i = rng.below(n + 1);
                for _ in 0..1 + rng.below(16) {
                    d.insert(i, rng.next() as u8);
                }
            }
            5 if n > 0 => {
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(32));
                d.drain(i..i + k);
            }
            6 if !others.is_empty() => {
                let o = &others[rng.below(others.len())];
                if !o.is_empty() {
                    let i = rng.below(o.len());
                    let k = 1 + rng.below((o.len() - i).min(128));
                    let j = rng.below(n + 1);
                    d.splice(j..j, o[i..i + k].iter().copied());
                }
            }
            7 if n > 0 => d.truncate(rng.below(n)),
            _ if n > 0 => {
                // duplicate a chunk (repeated elements)
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(64));
                let chunk = d[i..i + k].to_vec();
                d.splice(i..i, chunk);
            }
            _ => {}
        }
        if d.len() > 1 << 16 {
            d.truncate(1 << 16);
        }
    }
    d
}

fn iters(base: usize) -> usize {
    base * std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_4e70_cafe_0001)
}

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("../testdata/revocation/", $name)).to_vec()
    };
}

const NOW: i64 = 1_800_000_000;

struct Seeds {
    pki: TestPki,
    crls: Vec<Vec<u8>>,
    requests: Vec<Vec<u8>>,
    responses: Vec<Vec<u8>>,
}

fn seeds() -> Seeds {
    let pki = TestPki::new(NOW);
    let mut b = CrlBuilder::new(NOW - 10, Some(NOW + 100)).crl_number(3);
    for i in 0..20u16 {
        b = b.revoke(&(0x100 + i).to_be_bytes(), NOW - 5, Some((i % 7) as u8));
    }
    b = b.revoke(&pki.leaf_cert.serial, NOW - 5, Some(1));
    let crls = vec![fixture!("crl-sha256.der"), fixture!("crl-ecdsa-sha1.der"), fixture!("crl-rsa-sha1.der"), b.sign(&pki.int_cert, &pki.intermediate.key), pki.ca_crl(&[])];
    let requests = vec![fixture!("req-good.der"), fixture!("req-good-nononce.der"), ocsp::build_request(&pki.leaf_cert, &pki.int_cert, Some(b"nonce"))];
    let responses = vec![
        fixture!("resp-good-issuer.der"),
        fixture!("resp-revoked-delegated.der"),
        fixture!("resp-unknown-issuer.der"),
        fixture!("resp-good-noeku.der"),
        pki.leaf_ocsp(CertStatus::Good),
        pki.leaf_ocsp(CertStatus::Revoked { time: NOW - 10, reason: Some(4) }),
    ];
    Seeds { pki, crls, requests, responses }
}

#[test]
fn fuzz_crl_parser() {
    let s = seeds();
    let mut rng = Rng(seed());
    let limits = CrlLimits { max_size: 1 << 20, max_entries: 1000 };
    for i in 0..iters(4000) {
        let seed_crl = &s.crls[i % s.crls.len()];
        let d = mutate(&mut rng, seed_crl, &s.crls);
        if let Ok(crl) = Crl::from_der_with_limits(&d, &limits) {
            let _ = crl.verify_signature(&s.pki.int_cert);
            let _ = crl.covers(&s.pki.leaf_cert);
            let _ = crl.is_fresh(NOW, 86400);
            let _ = crl.is_revoked(&s.pki.leaf_cert.serial);
            assert!(crl.revoked().len() <= 1000);
        }
        let _ = Crl::parse_all(&d);
    }
}

#[test]
fn fuzz_ocsp_parsers() {
    let s = seeds();
    let mut rng = Rng(seed() ^ 1);
    for i in 0..iters(4000) {
        let d = mutate(&mut rng, &s.requests[i % s.requests.len()], &s.requests);
        if let Ok(r) = OcspRequest::parse(&d) {
            assert!(!r.cert_ids.is_empty());
        }
        let d = mutate(&mut rng, &s.responses[i % s.responses.len()], &s.responses);
        let _ = ocsp::response_status(&d);
        if let Ok(r) = OcspResponse::parse(&d) {
            let _ = r.validate(&s.pki.leaf_cert, &s.pki.int_cert, NOW, Some(b"nonce"), 86400);
            let _ = r.validate(&s.pki.leaf_cert, &s.pki.int_cert, NOW, None, 86400);
        }
    }
}

/// Serves mutated CRLs and OCSP responses to `check_path`.
struct Mutant {
    crl: Vec<u8>,
    resp: Vec<u8>,
}
impl RevocationFetcher for Mutant {
    fn fetch_crl(&self, _: &str) -> Option<Vec<u8>> {
        Some(self.crl.clone())
    }
    fn ocsp(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> {
        Some(self.resp.clone())
    }
}

#[test]
fn fuzz_check_path() {
    let s = seeds();
    let path = s.pki.path();
    let mut rng = Rng(seed() ^ 2);
    let base = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_ocsp(OcspMode::Request).with_ocsp_online(true);
    for i in 0..iters(800) {
        let crl = mutate(&mut rng, &s.crls[3 + i % 2], &s.crls);
        let resp = mutate(&mut rng, &s.responses[4 + i % 2], &s.responses);
        let staple = mutate(&mut rng, &s.responses[4], &s.responses);
        let pol = base.clone().with_fetcher(Arc::new(Mutant { crl, resp }));
        pol.cache.clear();
        let _ = check_path(&path, &pol, NOW, Some(&staple));
    }
    // and the unmutated seeds still pass
    let ok = RevocationPolicy::new().with_crl_mode(CrlMode::Require).with_fetcher(Arc::new(
        MapFetcher::new().with_crl("http://crl.test/int.crl", s.pki.int_crl(&[])).with_crl("http://crl.test/ca.crl", s.pki.ca_crl(&[])),
    ));
    assert!(check_path(&path, &ok, NOW, None).is_ok());
}
