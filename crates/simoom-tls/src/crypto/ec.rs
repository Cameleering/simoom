//! Generic NIST curve code (short Weierstrass, a = -3), used for P-384 ECDSA. P-256 has its
//! own faster implementation in `p256`.
//!
//! Field and scalar arithmetic use Montgomery multiplication with branch-free
//! reductions; point arithmetic uses the complete projective addition formulas
//! of Renes-Costello-Batina (2015, algorithm 4) so there are no special cases.
//! Scalar multiplication is a fixed-length double-and-add-always ladder with
//! constant-time selection. ECDSA nonces are derived deterministically
//! (RFC 6979).

use super::bigint::{mod_add, mod_sub, mont_m0inv, mont_mul, mont_r2, sbb, select};
use super::sha2::HashAlg;
use std::sync::OnceLock;

#[derive(Clone)]
struct Field<const N: usize> {
    m: [u64; N],
    m0inv: u64,
    r2: [u64; N],
    one: [u64; N],
}

impl<const N: usize> Field<N> {
    fn new(m: [u64; N]) -> Self {
        let m0inv = mont_m0inv(m[0]);
        let r2v = mont_r2(&m);
        let mut r2 = [0u64; N];
        r2.copy_from_slice(&r2v);
        let mut f = Field { m, m0inv, r2, one: [0; N] };
        let mut one = [0u64; N];
        one[0] = 1;
        f.one = f.to_mont(&one);
        f
    }
    fn mul(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut r = [0u64; N];
        let mut t = [0u64; 10];
        mont_mul(&mut r, a, b, &self.m, self.m0inv, &mut t[..N + 2]);
        r
    }
    fn sqr(&self, a: &[u64; N]) -> [u64; N] {
        self.mul(a, a)
    }
    fn add(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut r = [0u64; N];
        mod_add(&mut r, a, b, &self.m);
        r
    }
    fn sub(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut r = [0u64; N];
        mod_sub(&mut r, a, b, &self.m);
        r
    }
    fn to_mont(&self, a: &[u64; N]) -> [u64; N] {
        self.mul(a, &self.r2)
    }
    fn from_mont(&self, a: &[u64; N]) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        self.mul(a, &one)
    }
    /// a^(m-2) (Fermat inversion, constant-time: fixed exponent).
    fn inv(&self, a: &[u64; N]) -> [u64; N] {
        let mut e = self.m;
        let (v, mut borrow) = sbb(e[0], 2, 0);
        e[0] = v;
        for limb in e.iter_mut().skip(1) {
            let (v, b) = sbb(*limb, 0, borrow);
            *limb = v;
            borrow = b;
        }
        let mut acc = self.one;
        for i in (0..64 * N).rev() {
            acc = self.sqr(&acc);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                acc = self.mul(&acc, a);
            }
        }
        acc
    }
    /// Reduces a value < 2m to [0, m).
    fn reduce_once(&self, a: &[u64; N]) -> [u64; N] {
        let mut d = [0u64; N];
        let mut borrow = 0;
        for i in 0..N {
            let (v, b) = sbb(a[i], self.m[i], borrow);
            d[i] = v;
            borrow = b;
        }
        let mut r = [0u64; N];
        select(&mut r, borrow ^ 1, &d, a);
        r
    }
}

fn is_zero<const N: usize>(a: &[u64; N]) -> bool {
    a.iter().fold(0, |acc, x| acc | x) == 0
}

fn lt<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    super::bigint::lt(a, b)
}

fn from_be<const N: usize>(bytes: &[u8]) -> [u64; N] {
    let mut out = [0u64; N];
    for (i, b) in bytes.iter().rev().enumerate() {
        if i / 8 < N {
            out[i / 8] |= (*b as u64) << (8 * (i % 8));
        }
    }
    out
}

fn to_be<const N: usize>(a: &[u64; N]) -> Vec<u8> {
    super::bigint::to_be_bytes(a, 8 * N)
}

struct Curve<const N: usize> {
    fp: Field<N>,
    fq: Field<N>,
    b: [u64; N], // montgomery
    g: Point<N>,
    n: [u64; N],
}

#[derive(Clone, Copy)]
struct Point<const N: usize> {
    x: [u64; N],
    y: [u64; N],
    z: [u64; N],
}

impl<const N: usize> Curve<N> {
    fn new(p: &str, n: &str, b: &str, gx: &str, gy: &str) -> Self {
        let pb = crate::util::unhex(p);
        let fp = Field::new(from_be(&pb));
        let nn = from_be(&crate::util::unhex(n));
        let fq = Field::new(nn);
        let bm = fp.to_mont(&from_be(&crate::util::unhex(b)));
        let g = Point { x: fp.to_mont(&from_be(&crate::util::unhex(gx))), y: fp.to_mont(&from_be(&crate::util::unhex(gy))), z: fp.one };
        Curve { fp, fq, b: bm, g, n: nn }
    }

    fn infinity(&self) -> Point<N> {
        Point { x: [0; N], y: self.fp.one, z: [0; N] }
    }

    /// Complete addition (RCB 2015, algorithm 4, a = -3).
    fn add(&self, p: &Point<N>, q: &Point<N>) -> Point<N> {
        let f = &self.fp;
        let mut t0 = f.mul(&p.x, &q.x);
        let mut t1 = f.mul(&p.y, &q.y);
        let mut t2 = f.mul(&p.z, &q.z);
        let mut t3 = f.add(&p.x, &p.y);
        let mut t4 = f.add(&q.x, &q.y);
        t3 = f.mul(&t3, &t4);
        t4 = f.add(&t0, &t1);
        t3 = f.sub(&t3, &t4);
        t4 = f.add(&p.y, &p.z);
        let mut x3 = f.add(&q.y, &q.z);
        t4 = f.mul(&t4, &x3);
        x3 = f.add(&t1, &t2);
        t4 = f.sub(&t4, &x3);
        x3 = f.add(&p.x, &p.z);
        let mut y3 = f.add(&q.x, &q.z);
        x3 = f.mul(&x3, &y3);
        y3 = f.add(&t0, &t2);
        y3 = f.sub(&x3, &y3);
        let mut z3 = f.mul(&self.b, &t2);
        x3 = f.sub(&y3, &z3);
        z3 = f.add(&x3, &x3);
        x3 = f.add(&x3, &z3);
        z3 = f.sub(&t1, &x3);
        x3 = f.add(&t1, &x3);
        y3 = f.mul(&self.b, &y3);
        t1 = f.add(&t2, &t2);
        t2 = f.add(&t1, &t2);
        y3 = f.sub(&y3, &t2);
        y3 = f.sub(&y3, &t0);
        t1 = f.add(&y3, &y3);
        y3 = f.add(&t1, &y3);
        t1 = f.add(&t0, &t0);
        t0 = f.add(&t1, &t0);
        t0 = f.sub(&t0, &t2);
        t1 = f.mul(&t4, &y3);
        t2 = f.mul(&t0, &y3);
        y3 = f.mul(&x3, &z3);
        y3 = f.add(&y3, &t2);
        x3 = f.mul(&t3, &x3);
        x3 = f.sub(&x3, &t1);
        z3 = f.mul(&t4, &z3);
        t1 = f.mul(&t3, &t0);
        z3 = f.add(&z3, &t1);
        Point { x: x3, y: y3, z: z3 }
    }

    fn select_point(flag: u64, a: &Point<N>, b: &Point<N>) -> Point<N> {
        let mut r = *b;
        select(&mut r.x, flag, &a.x, &b.x);
        select(&mut r.y, flag, &a.y, &b.y);
        select(&mut r.z, flag, &a.z, &b.z);
        r
    }

    /// k * P with a fixed sequence of operations (k is a plain integer < 2^(64N)).
    fn mul(&self, p: &Point<N>, k: &[u64; N]) -> Point<N> {
        let mut r = self.infinity();
        for i in (0..64 * N).rev() {
            r = self.add(&r, &r);
            let t = self.add(&r, p);
            let bit = (k[i / 64] >> (i % 64)) & 1;
            r = Self::select_point(bit, &t, &r);
        }
        r
    }

    /// Returns affine (x, y) as plain integers, or None for infinity.
    fn to_affine(&self, p: &Point<N>) -> Option<([u64; N], [u64; N])> {
        if is_zero(&p.z) {
            return None;
        }
        let zi = self.fp.inv(&p.z);
        let x = self.fp.from_mont(&self.fp.mul(&p.x, &zi));
        let y = self.fp.from_mont(&self.fp.mul(&p.y, &zi));
        Some((x, y))
    }

    fn decode_point(&self, data: &[u8]) -> Option<Point<N>> {
        let len = 8 * N;
        if data.len() != 1 + 2 * len || data[0] != 4 {
            return None;
        }
        let x: [u64; N] = from_be(&data[1..1 + len]);
        let y: [u64; N] = from_be(&data[1 + len..]);
        if !lt(&x, &self.fp.m) || !lt(&y, &self.fp.m) {
            return None;
        }
        let f = &self.fp;
        let xm = f.to_mont(&x);
        let ym = f.to_mont(&y);
        // y^2 == x^3 - 3x + b
        let lhs = f.sqr(&ym);
        let x3 = f.mul(&f.sqr(&xm), &xm);
        let three_x = f.add(&f.add(&xm, &xm), &xm);
        let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
        if lhs != rhs {
            return None;
        }
        Some(Point { x: xm, y: ym, z: f.one })
    }

    fn encode_point(&self, x: &[u64; N], y: &[u64; N]) -> Vec<u8> {
        let mut out = vec![4u8];
        out.extend(to_be(x));
        out.extend(to_be(y));
        out
    }

    fn scalar_valid(&self, k: &[u64; N]) -> bool {
        !is_zero(k) && lt(k, &self.n)
    }

    fn public_key(&self, d: &[u8]) -> Option<Vec<u8>> {
        if d.len() > 8 * N {
            return None;
        }
        let k: [u64; N] = from_be(d);
        if !self.scalar_valid(&k) {
            return None;
        }
        let (x, y) = self.to_affine(&self.mul(&self.g, &k))?;
        Some(self.encode_point(&x, &y))
    }

    fn ecdh(&self, d: &[u8], peer: &[u8]) -> Option<Vec<u8>> {
        let q = self.decode_point(peer)?;
        let k: [u64; N] = from_be(d);
        if !self.scalar_valid(&k) {
            return None;
        }
        let (x, _) = self.to_affine(&self.mul(&q, &k))?;
        Some(to_be(&x))
    }

    /// bits2int(h) mod n (the curve order is a whole number of bytes for P-256/P-384).
    fn hash_to_scalar(&self, h: &[u8]) -> [u64; N] {
        let len = 8 * N;
        let take = &h[..h.len().min(len)];
        let e: [u64; N] = from_be(take);
        self.fq.reduce_once(&e)
    }

    fn rfc6979_k(&self, d: &[u64; N], h: &[u8], hash: HashAlg, extra: u32) -> [u64; N] {
        let rlen = 8 * N;
        let hlen = hash.output_len();
        let x = to_be(d);
        let h1 = to_be(&self.hash_to_scalar(h));
        let mut v = vec![1u8; hlen];
        let mut k = vec![0u8; hlen];
        k = hash.hmac(&k, &[&v, &[0], &x, &h1]).to_vec();
        v = hash.hmac(&k, &[&v]).to_vec();
        k = hash.hmac(&k, &[&v, &[1], &x, &h1]).to_vec();
        v = hash.hmac(&k, &[&v]).to_vec();
        let mut attempt = 0u32;
        loop {
            let mut t = Vec::new();
            while t.len() < rlen {
                v = hash.hmac(&k, &[&v]).to_vec();
                t.extend_from_slice(&v);
            }
            let cand: [u64; N] = from_be(&t[..rlen]);
            if self.scalar_valid(&cand) {
                if attempt == extra {
                    return cand;
                }
                attempt += 1;
            }
            k = hash.hmac(&k, &[&v, &[0]]).to_vec();
            v = hash.hmac(&k, &[&v]).to_vec();
        }
    }

    fn sign(&self, d_bytes: &[u8], h: &[u8], hash: HashAlg) -> Option<(Vec<u8>, Vec<u8>)> {
        let d: [u64; N] = from_be(d_bytes);
        if !self.scalar_valid(&d) {
            return None;
        }
        let q = &self.fq;
        let e = self.hash_to_scalar(h);
        let mut extra = 0;
        loop {
            let k = self.rfc6979_k(&d, h, hash, extra);
            extra += 1;
            let (x, _) = match self.to_affine(&self.mul(&self.g, &k)) {
                Some(p) => p,
                None => continue,
            };
            let r = q.reduce_once(&x);
            if is_zero(&r) {
                continue;
            }
            let km = q.to_mont(&k);
            let kinv = q.inv(&km);
            let rm = q.to_mont(&r);
            let dm = q.to_mont(&d);
            let em = q.to_mont(&e);
            let s = q.from_mont(&q.mul(&kinv, &q.add(&em, &q.mul(&rm, &dm))));
            if is_zero(&s) {
                continue;
            }
            return Some((to_be(&r), to_be(&s)));
        }
    }

    fn verify(&self, pubkey: &[u8], h: &[u8], r: &[u8], s: &[u8]) -> bool {
        if r.len() > 8 * N + 1 || s.len() > 8 * N + 1 {
            return false;
        }
        let strip = |b: &[u8]| -> Option<Vec<u8>> {
            let mut b = b;
            while b.len() > 8 * N && b[0] == 0 {
                b = &b[1..];
            }
            if b.len() > 8 * N {
                None
            } else {
                Some(b.to_vec())
            }
        };
        let (r, s) = match (strip(r), strip(s)) {
            (Some(r), Some(s)) => (r, s),
            _ => return false,
        };
        let r: [u64; N] = from_be(&r);
        let s: [u64; N] = from_be(&s);
        if !self.scalar_valid(&r) || !self.scalar_valid(&s) {
            return false;
        }
        let qpt = match self.decode_point(pubkey) {
            Some(p) => p,
            None => return false,
        };
        let q = &self.fq;
        let e = self.hash_to_scalar(h);
        let w = q.inv(&q.to_mont(&s));
        let u1 = q.from_mont(&q.mul(&q.to_mont(&e), &w));
        let u2 = q.from_mont(&q.mul(&q.to_mont(&r), &w));
        let p = self.add(&self.mul(&self.g, &u1), &self.mul(&qpt, &u2));
        match self.to_affine(&p) {
            None => false,
            Some((x, _)) => q.reduce_once(&x) == r,
        }
    }

    fn random_scalar(&self) -> Vec<u8> {
        loop {
            let mut b = vec![0u8; 8 * N];
            super::rng::fill(&mut b);
            let k: [u64; N] = from_be(&b);
            if self.scalar_valid(&k) {
                return b;
            }
        }
    }
}

fn p384() -> &'static Curve<6> {
    static C: OnceLock<Curve<6>> = OnceLock::new();
    C.get_or_init(|| {
        Curve::new(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        )
    })
}

/// P-384 operations (certificate and handshake signatures; not offered as a key-exchange group).
pub mod p384 {
    use super::*;

    /// Generates a random private scalar.
    pub fn generate_private() -> Vec<u8> {
        p384().random_scalar()
    }
    /// Uncompressed public point for a private scalar.
    pub fn public_key(private: &[u8]) -> Option<Vec<u8>> {
        p384().public_key(private)
    }
    /// ECDH: the x-coordinate of private * peer (validates the peer point).
    pub fn ecdh(private: &[u8], peer: &[u8]) -> Option<Vec<u8>> {
        p384().ecdh(private, peer)
    }
    /// ECDSA over a digest; (r, s) as 48-byte big-endian values.
    pub fn sign(private: &[u8], digest: &[u8], hash: HashAlg) -> Option<(Vec<u8>, Vec<u8>)> {
        p384().sign(private, digest, hash)
    }
    /// ECDSA verification over a digest.
    pub fn verify(public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
        p384().verify(public, digest, r, s)
    }
    /// Checks that `public` is a valid uncompressed point.
    pub fn validate_point(public: &[u8]) -> bool {
        p384().decode_point(public).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::p384;
    use crate::crypto::sha2::HashAlg;
    use crate::util::{hex, unhex};

    #[test]
    fn p384_ecdsa_rfc6979() {
        let x = unhex("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5");
        let pk = p384::public_key(&x).unwrap();
        assert_eq!(hex(&pk[1..49]), "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13");
        let h = HashAlg::Sha384.hash(b"sample");
        let (r, s) = p384::sign(&x, &h, HashAlg::Sha384).unwrap();
        assert_eq!(hex(&r), "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46");
        assert_eq!(hex(&s), "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8");
        assert!(p384::verify(&pk, &h, &r, &s));
        assert!(!p384::verify(&pk, &HashAlg::Sha384.hash(b"x"), &r, &s));
    }

    #[test]
    fn p384_ecdh_cavp() {
        let qcavs = "04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a";
        let d = unhex("3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1");
        let z = p384::ecdh(&d, &unhex(qcavs)).unwrap();
        assert_eq!(hex(&z), "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1");
    }
}
