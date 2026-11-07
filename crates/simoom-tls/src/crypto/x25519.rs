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
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = kt;
        // the hot loop of every handshake: field operations inlined here only
        let a = x2.add(z2);
        let aa = a.square_inline();
        let b = x2.sub(z2);
        let bb = b.square_inline();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul_inline(a);
        let cb = c.mul_inline(b);
        x3 = da.add(cb).square_inline();
        z3 = x1.mul_inline(da.sub(cb).square_inline());
        x2 = aa.mul_inline(bb);
        z2 = e.mul_inline(aa.add(e.mul_small(121665)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    x2.mul(z2.invert()).to_bytes()
}

/// The u-coordinate 9.
pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// X25519(scalar, 9): the public key.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let k = clamp(scalar);
    let p = super::ed25519::mul_base(&k);
    // u = (Z + Y) / (Z - Y)
    p.z.add(p.y).mul(p.z.sub(p.y).invert()).to_bytes()
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
        }
        assert!(agree(&a, &[0u8; 32]).is_none());
    }
}
