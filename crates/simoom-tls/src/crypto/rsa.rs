//! RSA signatures: PKCS#1 v1.5 and RSASSA-PSS (RFC 8017) verify and sign.
//!
//! Private-key operations use a fixed square-and-multiply-always Montgomery
//! exponentiation over the full exponent width, with base blinding (the input is
//! multiplied by `r^e` and the result by `r^-1` for a random `r`, the pair being
//! squared after every use) and the Chinese Remainder Theorem when the key carries its
//! CRT parameters (PKCS#1 keys); every result is verified with the public exponent before
//! it is released (fault attacks on CRT). Not hardened against cache or power analysis
//! beyond that.

use std::sync::{Arc, Mutex};

use super::bigint::{adc, bit_len, from_be_bytes, lt, mac, mod_sub, reduce_be, sbb, to_be_bytes, MontCtx};
use super::sha2::HashAlg;
use super::rng;
use crate::util::ct_eq;

#[derive(Clone)]
pub struct RsaPublicKey {
    ctx: MontCtx,
    e: Vec<u64>,
    /// Modulus size in bytes.
    k: usize,
    mod_bits: usize,
}

#[derive(Clone)]
pub struct RsaPrivateKey {
    pub public: RsaPublicKey,
    d: Vec<u64>,
    /// The original PKCS#1 encoding (with CRT parameters), when parsed from one.
    pub(crate) pkcs1: Option<Vec<u8>>,
    crt: Option<Crt>,
    blinding: Arc<Mutex<Option<Blinding>>>,
}

/// CRT parameters: Montgomery contexts for p and q, d mod (p-1), d mod (q-1), q^-1 mod p.
#[derive(Clone)]
struct Crt {
    p: MontCtx,
    q: MontCtx,
    dp: Vec<u64>,
    dq: Vec<u64>,
    qinv: Vec<u64>,
}

/// Base blinding pair: `vi = r^e mod n`, `vf = r^-1 mod n`.
struct Blinding {
    vi: Vec<u64>,
    vf: Vec<u64>,
}

/// a * b mod m (plain representations).
fn mod_mul(ctx: &MontCtx, a: &[u64], b: &[u64]) -> Vec<u64> {
    ctx.mul(&ctx.to_mont(a), b)
}

/// Full product a * b.
fn mul_full(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut r = vec![0u64; a.len() + b.len()];
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0;
        for (j, &y) in b.iter().enumerate() {
            let (lo, hi) = mac(r[i + j], x, y, carry);
            r[i + j] = lo;
            carry = hi;
        }
        r[i + b.len()] = carry;
    }
    r
}

fn add_assign(r: &mut [u64], b: &[u64]) {
    let mut carry = 0;
    for i in 0..r.len() {
        let (v, c) = adc(r[i], *b.get(i).unwrap_or(&0), carry);
        r[i] = v;
        carry = c;
    }
}

fn trim_to(mut v: Vec<u64>, n: usize) -> Option<Vec<u64>> {
    if v[n.min(v.len())..].iter().any(|x| *x != 0) {
        return None;
    }
    v.resize(n, 0);
    Some(v)
}

impl std::fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPublicKey({} bits)", self.mod_bits)
    }
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPrivateKey({} bits)", self.public.mod_bits)
    }
}

fn digest_info_prefix(h: HashAlg) -> &'static [u8] {
    match h {
        HashAlg::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        HashAlg::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        HashAlg::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.output_len());
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash.hash(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

impl RsaPublicKey {
    /// Builds a key from big-endian modulus and exponent.
    pub fn new(n: &[u8], e: &[u8]) -> Option<RsaPublicKey> {
        let n = {
            let mut i = 0;
            while i < n.len() && n[i] == 0 {
                i += 1;
            }
            &n[i..]
        };
        if n.len() < 64 || n.len() > 1024 || n[n.len() - 1] & 1 == 0 {
            return None; // < 512 bits or > 8192 bits or even
        }
        let limbs = n.len().div_ceil(8);
        let nl = from_be_bytes(n, limbs)?;
        let el = from_be_bytes(e, limbs)?;
        if el.iter().all(|x| *x == 0) || !lt(&el, &nl) {
            return None;
        }
        let mod_bits = bit_len(&nl);
        Some(RsaPublicKey { ctx: MontCtx::new(nl), e: el, k: mod_bits.div_ceil(8), mod_bits })
    }

    pub fn modulus_bits(&self) -> usize {
        self.mod_bits
    }

    /// Big-endian (modulus, public exponent).
    pub fn components(&self) -> (Vec<u8>, Vec<u8>) {
        let n = to_be_bytes(&self.ctx.m, self.k);
        let mut e = to_be_bytes(&self.e, self.k);
        while e.len() > 1 && e[0] == 0 {
            e.remove(0);
        }
        (n, e)
    }

    pub fn size(&self) -> usize {
        self.k
    }

    fn encrypt_raw(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.k {
            return None;
        }
        let s = from_be_bytes(sig, self.ctx.n())?;
        if !lt(&s, &self.ctx.m) {
            return None;
        }
        let m = self.ctx.pow(&s, &self.e, false);
        Some(to_be_bytes(&m, self.k))
    }

    /// RSASSA-PKCS1-v1_5 verification over a digest.
    pub fn verify_pkcs1(&self, hash: HashAlg, digest: &[u8], sig: &[u8]) -> bool {
        let em = match self.encrypt_raw(sig) {
            Some(e) => e,
            None => return false,
        };
        match pkcs1_encode(hash, digest, self.k) {
            Some(expect) => ct_eq(&em, &expect),
            None => false,
        }
    }

    /// RSASSA-PSS verification over a digest with MGF1 using the same hash.
    /// `salt_len` = None accepts any salt length.
    pub fn verify_pss(&self, hash: HashAlg, digest: &[u8], sig: &[u8], salt_len: Option<usize>) -> bool {
        let em_full = match self.encrypt_raw(sig) {
            Some(e) => e,
            None => return false,
        };
        let em_bits = self.mod_bits - 1;
        let em_len = em_bits.div_ceil(8);
        let em = if em_len < self.k {
            if em_full[0] != 0 {
                return false;
            }
            &em_full[1..]
        } else {
            &em_full[..]
        };
        let hlen = hash.output_len();
        if digest.len() != hlen || em_len < hlen + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let masked_db = &em[..em_len - hlen - 1];
        let h = &em[em_len - hlen - 1..em_len - 1];
        let top_bits = 8 * em_len - em_bits;
        let top_mask: u8 = if top_bits == 0 { 0 } else { 0xffu8 << (8 - top_bits) };
        if masked_db[0] & top_mask != 0 {
            return false;
        }
        let db_mask = mgf1(hash, h, masked_db.len());
        let mut db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
        db[0] &= !top_mask;
        let pos = match db.iter().position(|b| *b != 0) {
            Some(p) => p,
            None => return false,
        };
        if db[pos] != 1 {
            return false;
        }
        let salt = &db[pos + 1..];
        if let Some(sl) = salt_len {
            if salt.len() != sl {
                return false;
            }
        }
        let mut mp = vec![0u8; 8];
        mp.extend_from_slice(digest);
        mp.extend_from_slice(salt);
        ct_eq(&hash.hash(&mp), h)
    }
}

fn pkcs1_encode(hash: HashAlg, digest: &[u8], k: usize) -> Option<Vec<u8>> {
    let prefix = digest_info_prefix(hash);
    let t_len = prefix.len() + digest.len();
    if digest.len() != hash.output_len() || k < t_len + 11 {
        return None;
    }
    let mut em = vec![0x00, 0x01];
    em.resize(k - t_len - 1, 0xff);
    em.push(0);
    em.extend_from_slice(prefix);
    em.extend_from_slice(digest);
    Some(em)
}

impl RsaPrivateKey {
    /// Builds a private key from big-endian n, e, d.
    pub fn new(n: &[u8], e: &[u8], d: &[u8]) -> Option<RsaPrivateKey> {
        let public = RsaPublicKey::new(n, e)?;
        let d = from_be_bytes(d, public.ctx.n())?;
        if !lt(&d, &public.ctx.m) {
            return None;
        }
        Some(RsaPrivateKey { public, d, pkcs1: None, crt: None, blinding: Arc::new(Mutex::new(None)) })
    }

    /// Adds the CRT parameters (big-endian p, q, d mod (p-1), d mod (q-1), q^-1 mod p);
    /// returns false (and keeps the plain exponentiation) when they do not match the key.
    pub fn set_crt(&mut self, p: &[u8], q: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8]) -> bool {
        let strip = |b: &[u8]| -> Vec<u8> { b.iter().copied().skip_while(|x| *x == 0).collect() };
        let (p, q) = (strip(p), strip(q));
        if p.is_empty() || q.is_empty() || p.last().unwrap() & 1 == 0 || q.last().unwrap() & 1 == 0 {
            return false;
        }
        let limbs = |b: &[u8]| b.len().div_ceil(8).max(1);
        let (Some(pl), Some(ql)) = (from_be_bytes(&p, limbs(&p)), from_be_bytes(&q, limbs(&q))) else { return false };
        // p * q must be n
        match trim_to(mul_full(&pl, &ql), self.public.ctx.n()) {
            Some(n) if n == self.public.ctx.m => {}
            _ => return false,
        }
        let (Some(dp), Some(dq), Some(qinv)) = (from_be_bytes(&strip(dp), pl.len()), from_be_bytes(&strip(dq), ql.len()), from_be_bytes(&strip(qinv), pl.len())) else { return false };
        self.crt = Some(Crt { p: MontCtx::new(pl), q: MontCtx::new(ql), dp, dq, qinv });
        true
    }

    /// Whether private operations use the CRT.
    pub fn has_crt(&self) -> bool {
        self.crt.is_some()
    }

    /// c^d mod n with the CRT.
    fn crt_pow(&self, crt: &Crt, c: &[u64]) -> Option<Vec<u64>> {
        let m1 = crt.p.pow(&crt.p.reduce(c), &crt.dp, true);
        let m2 = crt.q.pow(&crt.q.reduce(c), &crt.dq, true);
        let m2p = crt.p.reduce(&m2);
        let mut diff = vec![0u64; crt.p.n()];
        mod_sub(&mut diff, &m1, &m2p, &crt.p.m);
        let h = mod_mul(&crt.p, &crt.qinv, &diff);
        let mut s = mul_full(&h, &crt.q.m);
        add_assign(&mut s, &m2);
        trim_to(s, self.public.ctx.n())
    }

    /// The blinding pair for this operation (created on first use, then squared).
    fn next_blinding(&self) -> Option<(Vec<u64>, Vec<u64>)> {
        let ctx = &self.public.ctx;
        let mut g = self.blinding.lock().unwrap();
        if g.is_none() {
            // r^-1 = r^(e*d - 2) mod n, as r^(e*d - 1) = 1 for r coprime to n
            if self.public.e.iter().skip(1).any(|x| *x != 0) {
                return None;
            }
            let e = self.public.e[0];
            let mut ed = vec![0u64; self.d.len() + 1];
            let mut carry = 0;
            for (i, &x) in self.d.iter().enumerate() {
                let (lo, hi) = mac(0, x, e, carry);
                ed[i] = lo;
                carry = hi;
            }
            ed[self.d.len()] = carry;
            let mut borrow = 0;
            for (i, limb) in ed.iter_mut().enumerate() {
                let (v, b) = sbb(*limb, if i == 0 { 2 } else { 0 }, borrow);
                *limb = v;
                borrow = b;
            }
            let r = loop {
                let r = reduce_be(&rng::bytes(self.public.k + 8), &ctx.m);
                if bit_len(&r) > 64 {
                    break r;
                }
            };
            let vi = ctx.pow(&r, &self.public.e, false);
            let vf = ctx.pow(&r, &ed, true);
            if mod_mul(ctx, &vi, &ctx.pow(&vf, &self.public.e, false)).iter().enumerate().any(|(i, x)| *x != (i == 0) as u64) {
                return None; // r not coprime to n (practically impossible)
            }
            *g = Some(Blinding { vi, vf });
        }
        let b = g.as_mut().unwrap();
        let out = (b.vi.clone(), b.vf.clone());
        b.vi = mod_mul(ctx, &b.vi, &b.vi);
        b.vf = mod_mul(ctx, &b.vf, &b.vf);
        Some(out)
    }

    /// The PKCS#1 `RSAPrivateKey` encoding this key was parsed from (keys built with
    /// [`RsaPrivateKey::new`] lack the CRT parameters and have none).
    pub fn pkcs1_der(&self) -> Option<&[u8]> {
        self.pkcs1.as_deref()
    }

    fn decrypt_raw(&self, em: &[u8]) -> Option<Vec<u8>> {
        let m = from_be_bytes(em, self.public.ctx.n())?;
        if !lt(&m, &self.public.ctx.m) {
            return None;
        }
        let ctx = &self.public.ctx;
        let blinding = self.next_blinding();
        let mb = match &blinding {
            Some((vi, _)) => mod_mul(ctx, &m, vi),
            None => m.clone(),
        };
        let sb = match &self.crt {
            Some(crt) => self.crt_pow(crt, &mb)?,
            None => ctx.pow(&mb, &self.d, true),
        };
        let s = match &blinding {
            Some((_, vf)) => mod_mul(ctx, &sb, vf),
            None => sb,
        };
        let sig = to_be_bytes(&s, self.public.k);
        // guard against faults: verify before releasing
        if self.public.encrypt_raw(&sig)? != to_be_bytes(&m, self.public.k) {
            return None;
        }
        Some(sig)
    }

    pub fn sign_pkcs1(&self, hash: HashAlg, digest: &[u8]) -> Option<Vec<u8>> {
        let em = pkcs1_encode(hash, digest, self.public.k)?;
        self.decrypt_raw(&em)
    }

    /// RSASSA-PSS signature with salt length = hash length (as TLS 1.3 requires).
    pub fn sign_pss(&self, hash: HashAlg, digest: &[u8]) -> Option<Vec<u8>> {
        let salt = rng::bytes(hash.output_len());
        self.sign_pss_with_salt(hash, digest, &salt)
    }

    pub fn sign_pss_with_salt(&self, hash: HashAlg, digest: &[u8], salt: &[u8]) -> Option<Vec<u8>> {
        let hlen = hash.output_len();
        let em_bits = self.public.mod_bits - 1;
        let em_len = em_bits.div_ceil(8);
        if digest.len() != hlen || em_len < hlen + salt.len() + 2 {
            return None;
        }
        let mut mp = vec![0u8; 8];
        mp.extend_from_slice(digest);
        mp.extend_from_slice(salt);
        let h = hash.hash(&mp).to_vec();
        let db_len = em_len - hlen - 1;
        let mut db = vec![0u8; db_len - salt.len() - 1];
        db.push(1);
        db.extend_from_slice(salt);
        let mask = mgf1(hash, &h, db_len);
        let mut em: Vec<u8> = db.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();
        let top_bits = 8 * em_len - em_bits;
        if top_bits > 0 {
            em[0] &= 0xff >> top_bits;
        }
        em.extend_from_slice(&h);
        em.push(0xbc);
        let mut full = vec![0u8; self.public.k - em_len];
        full.extend(em);
        self.decrypt_raw(&full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhex;

    // Arbitrary 1024-bit odd value (structure checks only; signature vectors
    // against OpenSSL live in keys.rs tests).
    const N: &str = "c7f6a2d7ec1d1a1ac3cd29b2a6a04e5e3e4b2aca69f2c3c4e94f3dbfc40b2c7c\
2b0b0f13c69c43c4a18c0bfa6e7bc5ff10a36eb4b55cb43e3098ce3a85c3e1d1\
6f4f80bd2a9c1d13ba88da2bc4bf1ad3b6d15d5d71d6f9c6c55c0a1f33f01a1e\
ab38f19c0e7c70e9c6c2fb7e43cd7d5e2c91b88dbdc7aa2a4b9cb7df5dc33d81";

    #[test]
    fn rejects_bad_keys() {
        assert!(RsaPublicKey::new(&unhex("0f"), &[3]).is_none());
        let mut even = unhex(N);
        let last = even.len() - 1;
        even[last] &= 0xfe;
        assert!(RsaPublicKey::new(&even, &[1, 0, 1]).is_none());
    }
}
