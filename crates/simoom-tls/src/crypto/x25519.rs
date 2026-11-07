//! X25519 (RFC 7748). Shared secrets use the constant-time Montgomery ladder; public keys use
//! the Ed25519 fixed-base table (constant time) and the birational map u = (1 + y) / (1 - y),
//! which is several times faster than the ladder.

use super::f25519::Fe;

/// Clamps a private scalar.
pub fn clamp(k: &[u8; 32]) -> [u8; 32] {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// X25519(scalar, u).
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let k = clamp(scalar);
    #[cfg(target_arch = "x86_64")]
    if simoom_sys::arch::has_mulx() {
        return ladder64(&k, u);
    }
    ladder51(&k, u)
}

/// The Montgomery ladder on five 51-bit limbs (portable).
fn ladder51(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = kt;
        // Additions and subtractions are left uncarried (every multiplication input stays
        // below 2^54). Without the x86-64 kernels this is the main ladder, so its field
        // operations are inlined; on x86-64 it is the fallback for CPUs without MULX and
        // calls them, to save size.
        #[cfg(not(target_arch = "x86_64"))]
        let (mul, sqr) = (Fe::mul_inline, Fe::square_inline);
        #[cfg(target_arch = "x86_64")]
        let (mul, sqr) = (Fe::mul, Fe::square);
        let a = x2.add_nc(z2);
        let aa = sqr(a);
        let b = x2.sub_nc(z2);
        let bb = sqr(b);
        let e = aa.sub_nc(bb);
        let c = x3.add_nc(z3);
        let d = x3.sub_nc(z3);
        let da = mul(d, a);
        let cb = mul(c, b);
        x3 = sqr(da.add_nc(cb));
        z3 = mul(x1, sqr(da.sub_nc(cb)));
        x2 = mul(aa, bb);
        z2 = mul(e, bb.add_nc(e.mul_small(121666)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    x2.mul(z2.invert()).to_bytes()
}

type L4 = [u64; 4];

/// The Montgomery ladder on four 64-bit limbs with the MULX kernels of `simoom_sys::arch`
/// (values below 2^256, congruent mod p, fully reduced only at the end). Same steps and
/// constant-time swaps as [`ladder51`].
#[cfg(target_arch = "x86_64")]
fn ladder64(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    use simoom_sys::arch::{fe25519_add as add, fe25519_mul121666, fe25519_sub as sub};
    // `ladder64` runs only when the kernels are available, so the fallbacks are never taken
    let mul = |a: &L4, b: &L4| simoom_sys::arch::fe25519_mul(a, b).unwrap_or_default();
    let sqr = |a: &L4| simoom_sys::arch::fe25519_sqr(a).unwrap_or_default();
    let mut x1: L4 = core::array::from_fn(|i| u64::from_le_bytes(u[8 * i..8 * i + 8].try_into().unwrap()));
    x1[3] &= u64::MAX >> 1;
    let (mut x2, mut z2, mut x3, mut z3): (L4, L4, L4, L4) = ([1, 0, 0, 0], [0; 4], x1, [1, 0, 0, 0]);
    let mut swap = 0u64;
    let cswap = |a: &mut L4, b: &mut L4, flag: u64| {
        let m = crate::util::ct_mask(flag);
        for i in 0..4 {
            let t = m & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
        }
    };
    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);
        swap = kt;
        let a = add(&x2, &z2);
        let aa = sqr(&a);
        let b = sub(&x2, &z2);
        let bb = sqr(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = sqr(&add(&da, &cb));
        z3 = mul(&x1, &sqr(&sub(&da, &cb)));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&bb, &fe25519_mul121666(&e).unwrap_or_default()));
    }
    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);
    let zi = super::modinv::invert(&canonical(&z2), &super::f25519::P_INV);
    let r = canonical(&mul(&x2, &zi));
    let mut out = [0u8; 32];
    for (i, l) in r.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&l.to_le_bytes());
    }
    out
}

/// The canonical residue mod 2^255 - 19 of a value below 2^256, in constant time.
#[cfg(target_arch = "x86_64")]
fn canonical(v: &L4) -> L4 {
    // fold bit 255 (2^255 = 19): the result is below 2^255 + 19
    let mut r = *v;
    let mut c = (r[3] >> 63) * 19;
    r[3] &= u64::MAX >> 1;
    for l in r.iter_mut() {
        let (s, o) = l.overflowing_add(c);
        *l = s;
        c = o as u64;
    }
    // subtract p if r + 19 reaches 2^255
    let mut t = r;
    let mut c = 19u64;
    for l in t.iter_mut() {
        let (s, o) = l.overflowing_add(c);
        *l = s;
        c = o as u64;
    }
    let m = crate::util::ct_mask(t[3] >> 63);
    t[3] &= u64::MAX >> 1;
    core::array::from_fn(|i| (t[i] & m) | (r[i] & !m))
}

/// The u-coordinate 9.
pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// X25519(scalar, 9): the public key. With the `ed25519` feature this uses the Ed25519
/// fixed-base table (constant time) and the birational map, about twice as fast as the ladder.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    #[cfg(feature = "ed25519")]
    {
        let k = clamp(scalar);
        let p = super::ed25519::mul_base(&k);
        // u = (Z + Y) / (Z - Y)
        p.z.add(p.y).mul(p.z.sub(p.y).invert()).to_bytes()
    }
    #[cfg(not(feature = "ed25519"))]
    x25519(scalar, &BASEPOINT)
}

/// The shared secret, or None if it is all zeros (a low-order peer key, RFC 7748 section 6.1).
pub fn agree(private: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
    let s = x25519(private, peer);
    if crate::util::ct_eq(&s, &[0u8; 32]) {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    fn b32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn rfc7748_vectors() {
        let out = x25519(
            &b32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            &b32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        );
        assert_eq!(hex(&out), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let out = x25519(
            &b32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            &b32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
        );
        assert_eq!(hex(&out), "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }

    #[test]
    fn rfc7748_iterated_1000() {
        let (mut k, mut u) = (BASEPOINT, BASEPOINT);
        for i in 1..=1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(hex(&k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
            }
        }
        assert_eq!(hex(&k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    }

    #[test]
    fn rfc7748_dh_and_fast_base() {
        let a = b32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = b32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let apub = x25519_base(&a);
        assert_eq!(hex(&apub), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bpub = x25519_base(&b);
        assert_eq!(hex(&bpub), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let s = agree(&a, &bpub).unwrap();
        assert_eq!(hex(&s), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(Some(s), agree(&b, &apub));
        for _ in 0..20 {
            let k = super::super::rng::array::<32>();
            assert_eq!(x25519_base(&k), x25519(&k, &BASEPOINT));
            // both ladders agree, for random and non-canonical u (u >= p, top bit set)
            let mut u = super::super::rng::array::<32>();
            assert_eq!(x25519(&k, &u), ladder51(&clamp(&k), &u));
            u[31] |= 0x80;
            assert_eq!(x25519(&k, &u), ladder51(&clamp(&k), &u));
        }
        assert!(agree(&a, &[0u8; 32]).is_none());
    }

    #[test]
    fn low_order_points_give_no_shared_secret() {
        // the points of order 1, 2, 4 and 8 and their non-canonical encodings (u + p), with
        // and without the ignored top bit
        let low = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        for _ in 0..4 {
            let k = super::super::rng::array::<32>();
            for h in low {
                let mut u = b32(h);
                assert!(agree(&k, &u).is_none(), "{h}");
                u[31] |= 0x80;
                assert!(agree(&k, &u).is_none(), "{h} with the top bit");
                assert_eq!(ladder51(&clamp(&k), &u), [0; 32]);
            }
        }
    }

    #[test]
    fn non_canonical_u_is_reduced() {
        // u = p + 9 is the base point; the top bit of u is ignored
        let k = super::super::rng::array::<32>();
        let mut u = b32("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert_eq!(x25519(&k, &u), x25519_base(&k));
        u = BASEPOINT;
        u[31] |= 0x80;
        assert_eq!(x25519(&k, &u), x25519_base(&k));
    }
}
