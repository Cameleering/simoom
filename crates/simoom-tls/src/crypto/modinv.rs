//! Constant-time modular inversion for odd moduli below 2^256: the "safegcd" algorithm of
//! Bernstein and Yang ("Fast constant-time gcd computation and modular inversion", 2019) in the
//! form used by libsecp256k1 (`modinv64`): 10 batches of 59 division steps on signed 62-bit
//! limbs, each batch collected into a 2x2 transition matrix that is then applied to the full
//! numbers (f, g) and to the Bezout coefficients (d, e). 590 steps suffice for any 256-bit
//! input (the bound proven for the half-delta variant).
//!
//! Every branch and memory access is independent of the input: the steps use masks, the
//! number of steps is fixed, and the products are 64 x 64 -> 128-bit multiplications. About
//! four times faster than Fermat inversion (255 squarings) with the field multiplications here.

const M62: u64 = u64::MAX >> 2;

/// An integer as five signed 62-bit limbs: sum v[i] * 2^(62 i), the top limb carrying the sign.
#[derive(Clone, Copy, Debug, PartialEq)]
struct S62([i64; 5]);

/// A modulus and its inverse modulo 2^62.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Modulus {
    m: S62,
    inv62: u64,
}

impl Modulus {
    /// `m` odd, below 2^256, little-endian 64-bit limbs.
    pub(crate) const fn new(m: [u64; 4]) -> Modulus {
        // m^-1 mod 2^64 by Newton's iteration (each step doubles the correct low bits)
        let mut inv: u64 = 1;
        let mut i = 0;
        while i < 7 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
            i += 1;
        }
        Modulus { m: to_s62(&m), inv62: inv & M62 }
    }
}

const fn to_s62(a: &[u64; 4]) -> S62 {
    S62([
        (a[0] & M62) as i64,
        (((a[0] >> 62) | (a[1] << 2)) & M62) as i64,
        (((a[1] >> 60) | (a[2] << 4)) & M62) as i64,
        (((a[2] >> 58) | (a[3] << 6)) & M62) as i64,
        (a[3] >> 56) as i64,
    ])
}

fn from_s62(v: &S62) -> [u64; 4] {
    let v = v.0.map(|x| x as u64);
    [v[0] | (v[1] << 62), (v[1] >> 2) | (v[2] << 60), (v[2] >> 4) | (v[3] << 58), (v[3] >> 6) | (v[4] << 56)]
}

/// An opaque all-ones or zero mask from the sign bit of `x`.
#[inline(always)]
fn sign_mask(x: i64) -> u64 {
    simoom_sys::arch::opaque((x >> 63) as u64)
}

/// The transition matrix of 59 division steps, scaled by 2^62.
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 59 constant-time division steps on the low limbs of f and g; returns the new zeta
/// (zeta = -(delta + 1/2)).
fn divsteps_59(mut zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    // u, v, q, r start as the identity times 8 (2^3), so after 59 steps they are scaled by
    // 2^62; they are signed values in [-2^62, 2^62] held as u64 so that shifts are defined.
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    for _ in 3..62 {
        let c1 = sign_mask(zeta); // zeta < 0
        let c2 = simoom_sys::arch::opaque(g & 1).wrapping_neg(); // g odd
                                                                 // x, y, z: f, u, v negated when zeta < 0
        let x = (f ^ c1).wrapping_sub(c1);
        let y = (u ^ c1).wrapping_sub(c1);
        let z = (v ^ c1).wrapping_sub(c1);
        // add them to g, q, r when g is odd
        g = g.wrapping_add(x & c2);
        q = q.wrapping_add(y & c2);
        r = r.wrapping_add(z & c2);
        // when zeta < 0 and g was odd: zeta = -zeta - 2, and (f, u, v) += (g, q, r)
        let c = c1 & c2;
        zeta = (zeta ^ c as i64).wrapping_sub(1);
        f = f.wrapping_add(g & c);
        u = u.wrapping_add(q & c);
        v = v.wrapping_add(r & c);
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    (zeta, Trans { u: u as i64, v: v as i64, q: q as i64, r: r as i64 })
}

#[inline(always)]
fn mul(a: i64, b: i64) -> i128 {
    a as i128 * b as i128
}

/// (f, g) = t * (f, g) / 2^62 (exact).
fn update_fg(f: &mut S62, g: &mut S62, t: &Trans) {
    let (fv, gv) = (f.0, g.0);
    let mut cf = mul(t.u, fv[0]) + mul(t.v, gv[0]);
    let mut cg = mul(t.q, fv[0]) + mul(t.r, gv[0]);
    cf >>= 62;
    cg >>= 62;
    for i in 1..5 {
        cf += mul(t.u, fv[i]) + mul(t.v, gv[i]);
        cg += mul(t.q, fv[i]) + mul(t.r, gv[i]);
        f.0[i - 1] = (cf as u64 & M62) as i64;
        g.0[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f.0[4] = cf as i64;
    g.0[4] = cg as i64;
}

/// (d, e) = (t * (d, e) + m * (md, me)) / 2^62, with md and me chosen so that the division is
/// exact; d and e stay in (-2m, m).
fn update_de(d: &mut S62, e: &mut S62, t: &Trans, m: &Modulus) {
    let (dv, ev) = (d.0, e.0);
    // md, me start as zero, plus (u, q) if d is negative, plus (v, r) if e is negative
    let sd = sign_mask(dv[4]) as i64;
    let se = sign_mask(ev[4]) as i64;
    let mut md = (t.u & sd).wrapping_add(t.v & se);
    let mut me = (t.q & sd).wrapping_add(t.r & se);
    let mut cd = mul(t.u, dv[0]) + mul(t.v, ev[0]);
    let mut ce = mul(t.q, dv[0]) + mul(t.r, ev[0]);
    // correct md, me so that the low 62 bits of t * (d, e) + m * (md, me) are zero
    md = md.wrapping_sub((m.inv62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64);
    me = me.wrapping_sub((m.inv62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64);
    cd += mul(m.m.0[0], md);
    ce += mul(m.m.0[0], me);
    debug_assert!(cd as u64 & M62 == 0 && ce as u64 & M62 == 0);
    cd >>= 62;
    ce >>= 62;
    for i in 1..5 {
        cd += mul(t.u, dv[i]) + mul(t.v, ev[i]) + mul(m.m.0[i], md);
        ce += mul(t.q, dv[i]) + mul(t.r, ev[i]) + mul(m.m.0[i], me);
        d.0[i - 1] = (cd as u64 & M62) as i64;
        e.0[i - 1] = (ce as u64 & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    d.0[4] = cd as i64;
    e.0[4] = ce as i64;
}

/// Brings r from (-2m, m) to [0, m), negated first when `sign` is negative.
fn normalize(r: &mut S62, sign: i64, m: &Modulus) {
    let mut v = r.0;
    let add = sign_mask(v[4]) as i64;
    for i in 0..5 {
        v[i] += m.m.0[i] & add;
    }
    let neg = sign_mask(sign) as i64;
    for x in v.iter_mut() {
        *x = (*x ^ neg).wrapping_sub(neg);
    }
    let carry = |v: &mut [i64; 5]| {
        for i in 0..4 {
            v[i + 1] += v[i] >> 62;
            v[i] &= M62 as i64;
        }
    };
    carry(&mut v);
    let add = sign_mask(v[4]) as i64;
    for i in 0..5 {
        v[i] += m.m.0[i] & add;
    }
    carry(&mut v);
    r.0 = v;
}

/// x^-1 mod m for 0 <= x < m (plain representation, little-endian limbs); 0 maps to 0.
/// Constant time.
pub(crate) fn invert(x: &[u64; 4], m: &Modulus) -> [u64; 4] {
    let mut d = S62([0; 5]);
    let mut e = S62([1, 0, 0, 0, 0]);
    let mut f = m.m;
    let mut g = to_s62(x);
    let mut zeta = -1i64;
    for _ in 0..10 {
        let (z, t) = divsteps_59(zeta, f.0[0] as u64, g.0[0] as u64);
        zeta = z;
        update_de(&mut d, &mut e, &t, m);
        update_fg(&mut f, &mut g, &t);
    }
    // g is now 0 and f = +-gcd = +-1, so d = +-x^-1
    normalize(&mut d, f.0[4], m);
    from_s62(&d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mulmod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
        // schoolbook product, then bit-serial reduction (slow, independent)
        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut c = 0u128;
            for j in 0..4 {
                let v = t[i + j] as u128 + a[i] as u128 * b[j] as u128 + c;
                t[i + j] = v as u64;
                c = v >> 64;
            }
            t[i + 4] = c as u64;
        }
        let mut r = [0u64; 4];
        for bit in (0..512).rev() {
            // r = 2r + bit mod m
            let top = r[3] >> 63;
            for j in (1..4).rev() {
                r[j] = (r[j] << 1) | (r[j - 1] >> 63);
            }
            r[0] = (r[0] << 1) | ((t[bit / 64] >> (bit % 64)) & 1);
            let ge = top == 1 || (0..4).rev().map(|j| (r[j], m[j])).find(|(x, y)| x != y).is_none_or(|(x, y)| x > y);
            if ge {
                let mut br = 0i128;
                for j in 0..4 {
                    let v = r[j] as i128 - m[j] as i128 + br;
                    r[j] = v as u64;
                    br = v >> 64;
                }
            }
        }
        r
    }

    #[test]
    fn limb_conversion_roundtrips() {
        for v in [[0u64; 4], [u64::MAX; 4], [1, 2, 3, 4], [0x8000_0000_0000_0000, 0, 0, 0x0100_0000_0000_0000]] {
            assert_eq!(from_s62(&to_s62(&v)), v);
        }
    }

    #[test]
    fn inverses_for_curve_moduli() {
        let moduli = [
            [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0, 0xffff_ffff_0000_0001], // P-256 p
            [0xf3b9_cac2_fc63_2551, 0xbce6_faad_a717_9e84, 0xffff_ffff_ffff_ffff, 0xffff_ffff_0000_0000], // P-256 n
            [0xffff_ffff_ffff_ffed, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff],       // 2^255 - 19
            [0x5812_631a_5cf5_d3ed, 0x14de_f9de_a2f7_9cd6, 0, 0x1000_0000_0000_0000], // Ed25519 L
            [u64::MAX - 188, u64::MAX, u64::MAX, u64::MAX],                           // 2^256 - 189 (prime)
        ];
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for m in moduli {
            let md = Modulus::new(m);
            assert_eq!(m[0].wrapping_mul(md.inv62) & M62, 1);
            let mut mm1 = m;
            mm1[0] -= 1;
            let mut mm2 = m;
            mm2[0] -= 2;
            let mut xs = vec![[1u64, 0, 0, 0], [2, 0, 0, 0], mm1, mm2, [0, 0, 0, 1], [u64::MAX, 0, 0, 0]];
            for _ in 0..300 {
                let mut x = [next(), next(), next(), next()];
                x[3] %= m[3];
                xs.push(x);
            }
            for x in &xs {
                let inv = invert(x, &md);
                assert_eq!(mulmod(x, &inv, &m), [1, 0, 0, 0], "{x:x?} mod {m:x?}");
            }
            assert_eq!(invert(&[0; 4], &md), [0; 4]);
        }
    }
}
