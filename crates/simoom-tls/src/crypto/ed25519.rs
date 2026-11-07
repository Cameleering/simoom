//! Ed25519 signatures (RFC 8032, PureEdDSA).
//!
//! Points use extended coordinates. Fixed-base multiplication uses signed radix-16 digits and a
//! 32 x 8 table of affine multiples of B (30 KB, built on first use) read with masked
//! selection, so signing and key generation are constant time. Verification multiplies the
//! public key with a 4-bit window. Scalars are reduced modulo L bit-serially without branches.

use super::f25519::Fe;
use super::sha2::Sha512;
use std::sync::OnceLock;

/// A point in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub t: Fe,
}

/// An affine point as (y + x, y - x, 2d xy).
#[derive(Clone, Copy)]
struct Niels {
    ypx: Fe,
    ymx: Fe,
    xy2d: Fe,
}

const NIELS_IDENTITY: Niels = Niels { ypx: Fe::ONE, ymx: Fe::ONE, xy2d: Fe::ZERO };

struct Consts {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
    base: Point,
}

fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| {
        let d = Fe::from_u64(121665).neg().mul(Fe::from_u64(121666).invert());
        // sqrt(-1) = 2^((p-1)/4)
        let sqrt_m1 = Fe::from_u64(2).pow2k(253).mul(Fe::from_u64(32).invert());
        let mut enc = [0x66u8; 32];
        enc[0] = 0x58;
        let mut c = Consts { d, d2: d.add(d), sqrt_m1, base: Point::IDENTITY };
        c.base = Point::decode_with(&enc, &c).expect("Ed25519 base point");
        c
    })
}

impl Point {
    pub const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };

    fn decode_with(b: &[u8; 32], c: &Consts) -> Option<Point> {
        let x0 = b[31] >> 7;
        let y = Fe::from_bytes(b);
        let mut yb = *b;
        yb[31] &= 0x7f;
        if y.to_bytes() != yb {
            return None; // non-canonical y
        }
        let yy = y.square();
        let u = yy.sub(Fe::ONE);
        let v = c.d.mul(yy).add(Fe::ONE);
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v7).pow22523());
        let vxx = v.mul(x.square());
        if vxx.ct_eq(u) {
        } else if vxx.ct_eq(u.neg()) {
            x = x.mul(c.sqrt_m1);
        } else {
            return None;
        }
        if x.is_zero() && x0 == 1 {
            return None;
        }
        if x.is_negative() != x0 {
            x = x.neg();
        }
        Some(Point { x, y, z: Fe::ONE, t: x.mul(y) })
    }

    fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(zi);
        let y = self.y.mul(zi);
        let mut out = y.to_bytes();
        out[31] |= x.is_negative() << 7;
        out
    }

    /// Unified addition (RFC 8032 section 5.1.4).
    fn add(&self, q: &Point) -> Point {
        let a = self.y.sub(self.x).mul(q.y.sub(q.x));
        let b = self.y.add(self.x).mul(q.y.add(q.x));
        let c = self.t.mul(consts().d2).mul(q.t);
        let d = self.z.add(self.z).mul(q.z);
        let (e, f, g, h) = (b.sub(a), d.sub(c), d.add(c), b.add(a));
        Point { x: e.mul(f), y: g.mul(h), t: e.mul(h), z: f.mul(g) }
    }

    fn add_niels(&self, q: &Niels) -> Point {
        let a = self.y.sub(self.x).mul(q.ymx);
        let b = self.y.add(self.x).mul(q.ypx);
        let c = self.t.mul(q.xy2d);
        let d = self.z.add(self.z);
        let (e, f, g, h) = (b.sub(a), d.sub(c), d.add(c), b.add(a));
        Point { x: e.mul(f), y: g.mul(h), t: e.mul(h), z: f.mul(g) }
    }

    /// Doubling for a = -1 (dbl-2008-hwcd).
    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(self.z.square());
        let e = self.x.add(self.y).square().sub(a).sub(b);
        let g = b.sub(a);
        let f = g.sub(c);
        let h = a.add(b).neg();
        Point { x: e.mul(f), y: g.mul(h), t: e.mul(h), z: f.mul(g) }
    }

    fn neg(&self) -> Point {
        Point { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    fn select(&self, o: &Point, flag: u64) -> Point {
        Point { x: self.x.select(o.x, flag), y: self.y.select(o.y, flag), z: self.z.select(o.z, flag), t: self.t.select(o.t, flag) }
    }

    /// k * self, 4-bit fixed window (used for verification).
    fn mul(&self, k: &[u8; 32]) -> Point {
        let mut tbl = [Point::IDENTITY; 16];
        tbl[1] = *self;
        for i in 2..16 {
            tbl[i] = tbl[i - 1].add(self);
        }
        let mut r = Point::IDENTITY;
        for i in (0..64).rev() {
            r = r.double().double().double().double();
            let n = ((k[i / 2] >> (4 * (i % 2))) & 15) as u64;
            let mut s = Point::IDENTITY;
            for (j, t) in tbl.iter().enumerate() {
                s = s.select(t, eq(n, j as u64));
            }
            r = r.add(&s);
        }
        r
    }
}

/// 1 if a == b, else 0 (selects mask it with `ct_mask`).
#[inline(always)]
fn eq(a: u64, b: u64) -> u64 {
    crate::util::ct_eq_mask(a, b) & 1
}

/// Table entry [i][j-1] = j * 256^i * B.
fn base_table() -> &'static [[Niels; 8]] {
    static T: OnceLock<Vec<[Niels; 8]>> = OnceLock::new();
    T.get_or_init(|| {
        let c = consts();
        let mut proj = Vec::with_capacity(256);
        let mut base = c.base;
        for _ in 0..32 {
            let mut acc = base;
            proj.push(acc);
            for _ in 2..=8 {
                acc = acc.add(&base);
                proj.push(acc);
            }
            for _ in 0..8 {
                base = base.double();
            }
        }
        // batch inversion of Z
        let mut prefix = Vec::with_capacity(proj.len());
        let mut acc = Fe::ONE;
        for p in &proj {
            prefix.push(acc);
            acc = acc.mul(p.z);
        }
        let mut inv = acc.invert();
        let mut out = vec![NIELS_IDENTITY; proj.len()];
        for i in (0..proj.len()).rev() {
            let zi = inv.mul(prefix[i]);
            inv = inv.mul(proj[i].z);
            let (x, y) = (proj[i].x.mul(zi), proj[i].y.mul(zi));
            out[i] = Niels { ypx: y.add(x), ymx: y.sub(x), xy2d: x.mul(y).mul(c.d2) };
        }
        out.chunks(8).map(|ch| ch.try_into().unwrap()).collect()
    })
}

/// Selects e * entry (e in -8..=8) from one table row, in constant time.
fn select_niels(row: &[Niels; 8], e: i8) -> Niels {
    let neg = ((e as u8) >> 7) as u64;
    // |e| without a branch
    let m = (e as i64 >> 63) as u64;
    let abs = ((e as i64 as u64) ^ m).wrapping_sub(m);
    let mut r = NIELS_IDENTITY;
    for (j, n) in row.iter().enumerate() {
        let f = eq(abs, j as u64 + 1);
        r = Niels { ypx: r.ypx.select(n.ypx, f), ymx: r.ymx.select(n.ymx, f), xy2d: r.xy2d.select(n.xy2d, f) };
    }
    // -P swaps y+x and y-x and negates 2dxy
    let (ypx, ymx) = (r.ymx.select(r.ypx, 1 - neg), r.ypx.select(r.ymx, 1 - neg));
    Niels { ypx, ymx, xy2d: r.xy2d.select(r.xy2d.neg(), neg) }
}

/// k * B for a little-endian scalar k < 2^255.
pub(crate) fn mul_base(k: &[u8; 32]) -> Point {
    let mut e = [0i8; 64];
    for i in 0..32 {
        e[2 * i] = (k[i] & 15) as i8;
        e[2 * i + 1] = (k[i] >> 4) as i8;
    }
    let mut carry = 0i8;
    for v in e.iter_mut().take(63) {
        *v += carry;
        carry = (*v + 8) >> 4;
        *v -= carry << 4;
    }
    e[63] += carry;
    let tbl = base_table();
    let mut r = Point::IDENTITY;
    for i in (1..64).step_by(2) {
        r = r.add_niels(&select_niels(&tbl[i / 2], e[i]));
    }
    r = r.double().double().double().double();
    for i in (0..64).step_by(2) {
        r = r.add_niels(&select_niels(&tbl[i / 2], e[i]));
    }
    r
}

// ---- scalars mod L

const L: [u64; 4] = [0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000];

/// A little-endian integer of any length, reduced mod L (constant time in the value).
fn reduce_mod_l(bytes: &[u8]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for i in (0..bytes.len() * 8).rev() {
        let mut carry = ((bytes[i / 8] >> (i % 8)) & 1) as u64;
        for limb in r.iter_mut() {
            let nc = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = nc;
        }
        let mut t = [0u64; 4];
        let mut borrow = 0u64;
        for j in 0..4 {
            let (d1, b1) = r[j].overflowing_sub(L[j]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            t[j] = d2;
            borrow = (b1 | b2) as u64;
        }
        let mask = crate::util::ct_mask(1 ^ borrow);
        for j in 0..4 {
            r[j] = (t[j] & mask) | (r[j] & !mask);
        }
    }
    let mut out = [0u8; 32];
    for (j, limb) in r.iter().enumerate() {
        out[8 * j..8 * j + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// (a * b + c) mod L.
fn mul_add_mod_l(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let limbs = |x: &[u8; 32]| -> [u64; 4] { core::array::from_fn(|j| u64::from_le_bytes(x[8 * j..8 * j + 8].try_into().unwrap())) };
    let (al, bl, cl) = (limbs(a), limbs(b), limbs(c));
    let mut p = [0u64; 9];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = al[i] as u128 * bl[j] as u128 + p[i + j] as u128 + carry;
            p[i + j] = t as u64;
            carry = t >> 64;
        }
        p[i + 4] = carry as u64;
    }
    let mut carry = 0u128;
    for (j, v) in p.iter_mut().enumerate() {
        let t = *v as u128 + if j < 4 { cl[j] as u128 } else { 0 } + carry;
        *v = t as u64;
        carry = t >> 64;
    }
    let mut bytes = [0u8; 72];
    for (j, limb) in p.iter().enumerate() {
        bytes[8 * j..8 * j + 8].copy_from_slice(&limb.to_le_bytes());
    }
    reduce_mod_l(&bytes)
}

fn is_canonical_scalar(s: &[u8; 32]) -> bool {
    let mut lb = [0u8; 32];
    for (j, limb) in L.iter().enumerate() {
        lb[8 * j..8 * j + 8].copy_from_slice(&limb.to_le_bytes());
    }
    for i in (0..32).rev() {
        if s[i] != lb[i] {
            return s[i] < lb[i];
        }
    }
    false
}

fn expand(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let h = Sha512::digest(seed);
    let a = super::x25519::clamp(h[..32].try_into().unwrap());
    (a, h[32..].try_into().unwrap())
}

/// The public key for a 32-byte private seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    mul_base(&expand(seed).0).encode()
}

/// Signs `msg`.
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    sign_with_public(seed, &public_key(seed), msg)
}

/// Signs `msg` with a key whose public key is already known (saves a fixed-base
/// multiplication and an inversion); `public` must be `public_key(seed)`.
pub fn sign_with_public(seed: &[u8; 32], public: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let (a, prefix) = expand(seed);
    let mut h = Sha512::new();
    h.update(&prefix);
    h.update(msg);
    let r = reduce_mod_l(&h.finish());
    let rp = mul_base(&r).encode();
    let mut h = Sha512::new();
    h.update(&rp);
    h.update(public);
    h.update(msg);
    let k = reduce_mod_l(&h.finish());
    let s = mul_add_mod_l(&k, &a, &r);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rp);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Verifies a signature with the cofactorless equation `[S]B = R + [k]A`.
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), true) = (<[u8; 32]>::try_from(public), sig.len() == 64) else { return false };
    let Some(a) = Point::decode_with(&pk, consts()) else { return false };
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if !is_canonical_scalar(&s) {
        return false;
    }
    let mut h = Sha512::new();
    h.update(&sig[..32]);
    h.update(public);
    h.update(msg);
    let k = reduce_mod_l(&h.finish());
    let check = mul_base(&s).add(&a.neg().mul(&k));
    crate::util::ct_eq(&check.encode(), &sig[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    const VECTORS: &[(&str, &str, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];

    #[test]
    fn rfc8032_vectors() {
        for (sk, pk, msg, sig) in VECTORS {
            let seed: [u8; 32] = unhex(sk).try_into().unwrap();
            assert_eq!(hex(&public_key(&seed)), *pk);
            let m = unhex(msg);
            let s = sign(&seed, &m);
            assert_eq!(hex(&s), *sig);
            assert!(verify(&unhex(pk), &m, &s));
            let mut bad = s;
            bad[10] ^= 1;
            assert!(!verify(&unhex(pk), &m, &bad));
            assert!(!verify(&unhex(pk), b"other", &s));
        }
    }

    #[test]
    fn group_law_consistency() {
        let b = consts().base;
        assert_eq!(b.double().encode(), b.add(&b).encode());
        let mut k = [0u8; 32];
        k[0] = 5;
        let five = b.double().double().add(&b);
        assert_eq!(mul_base(&k).encode(), five.encode());
        assert_eq!(b.mul(&k).encode(), five.encode());
        let k = super::super::rng::array::<32>();
        let k = super::super::x25519::clamp(&k);
        assert_eq!(mul_base(&k).encode(), b.mul(&k).encode());
    }

    #[test]
    fn rejects_non_canonical_s_and_bad_points() {
        let seed: [u8; 32] = unhex(VECTORS[0].0).try_into().unwrap();
        let pk = public_key(&seed);
        let mut s = sign(&seed, b"x");
        let mut carry = 0u16;
        for (j, limb) in L.iter().enumerate() {
            for (i, lb) in limb.to_le_bytes().iter().enumerate() {
                let v = s[32 + 8 * j + i] as u16 + *lb as u16 + carry;
                s[32 + 8 * j + i] = v as u8;
                carry = v >> 8;
            }
        }
        assert!(!verify(&pk, b"x", &s));
        assert!(!verify(&[0xffu8; 32], b"x", &sign(&seed, b"x")));
        let mut lb = Vec::new();
        for limb in L {
            lb.extend_from_slice(&limb.to_le_bytes());
        }
        assert_eq!(reduce_mod_l(&lb), [0u8; 32]);
    }
}
