//! NIST P-256: ECDH, ECDSA signing (RFC 6979 nonces) and verification.
//!
//! - **Field.** 4 x 64-bit limbs in Montgomery form. A multiplication is a schoolbook product
//!   (a dedicated squaring takes 10 limb products instead of 16) followed by a Montgomery
//!   reduction that uses the shape of p: the reduction multiplier is the low limb itself, and
//!   q * p needs one 64 x 64-bit product per limb instead of four.
//! - **Points.** Jacobian coordinates (a = -3 doubling in 4M + 4S, mixed addition in 8M + 3S),
//!   the point at infinity as Z = 0, handled with masks. These formulas are wrong when both
//!   inputs are the same point; the scalar multiplications below never add equal points, which
//!   is proven at `mul_base` and `mul` (the scalar is first replaced by min(k, n - k)).
//! - **Fixed base** (signing, key generation): signed 5-bit digits and a table of
//!   d * 32^i * G for d = 1..16 and each of the 52 digit positions (53 KB, affine, built on
//!   first use), so k * G is 52 mixed additions and no doublings.
//! - **Variable base** (ECDH): the same signed digits over a table of 1..16 * P, 255 doublings
//!   and 52 additions.
//! - **Verification** (public inputs): u1 * G + u2 * Q in one chain of doublings with width-5
//!   NAF digits of both scalars (Straus-Shamir), in variable time.
//! - **Inversions** (mod p and mod n) use constant-time safegcd (`modinv`); on x86-64 with
//!   BMI2/ADX the field and order multiplications are MULX kernels in `simoom_sys::arch`.
//!
//! Every table read of secret-dependent entries scans all entries with masks, so memory access
//! never depends on secret scalars.

use super::sha2::HashAlg;
use std::sync::OnceLock;

type Fe = [u64; 4];

const P: Fe = [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0, 0xffff_ffff_0000_0001];
const N: Fe = [0xf3b9_cac2_fc63_2551, 0xbce6_faad_a717_9e84, 0xffff_ffff_ffff_ffff, 0xffff_ffff_0000_0000];
/// (n - 1) / 2: scalars above it are replaced by n - k.
const N_HALF: Fe = [0x79dc_e561_7e31_92a8, 0xde73_7d56_d38b_cf42, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_8000_0000];
const N0INV: u64 = 0xccd1_c8aa_ee00_bc4f;
/// R^2 mod p and R^2 mod n (R = 2^256).
const RR_P: Fe = [0x0000_0000_0000_0003, 0xffff_fffb_ffff_ffff, 0xffff_ffff_ffff_fffe, 0x0000_0004_ffff_fffd];
const RR_N: Fe = [0x8324_4c95_be79_eea2, 0x4699_799c_49bd_6fa6, 0x2845_b239_2b6b_ec59, 0x66e1_2d94_f3d9_5620];
/// b in Montgomery form.
const B_MONT: Fe = [0xd89c_df62_29c4_bddf, 0xacf0_05cd_7884_3090, 0xe5a2_20ab_f721_2ed6, 0xdc30_061d_0487_4834];
const ONE_MONT: Fe = [0x0000_0000_0000_0001, 0xffff_ffff_0000_0000, 0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_fffe];
const GX: Fe = [0xf4a1_3945_d898_c296, 0x7703_7d81_2deb_33a0, 0xf8bc_e6e5_63a4_40f2, 0x6b17_d1f2_e12c_4247];
const GY: Fe = [0xcbb6_4068_37bf_51f5, 0x2bce_3357_6b31_5ece, 0x8ee7_eb4a_7c0f_9e16, 0x4fe3_42e2_fe1a_7f9b];

#[inline(always)]
fn adc(a: u64, b: u64, c: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 + c as u128;
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub(b as u128 + borrow as u128);
    (t as u64, ((t >> 64) as u64) & 1)
}

#[inline(always)]
fn mac(acc: u64, a: u64, b: u64, c: u64) -> (u64, u64) {
    let t = acc as u128 + a as u128 * b as u128 + c as u128;
    (t as u64, (t >> 64) as u64)
}

/// r = if mask { a } else { b }, with mask all-ones or zero.
#[inline(always)]
fn sel(mask: u64, a: &Fe, b: &Fe) -> Fe {
    [(a[0] & mask) | (b[0] & !mask), (a[1] & mask) | (b[1] & !mask), (a[2] & mask) | (b[2] & !mask), (a[3] & mask) | (b[3] & !mask)]
}

/// Subtracts m once if `hi:t >= m` (inputs below 2m).
#[inline(always)]
fn reduce_once(t: &Fe, hi: u64, m: &Fe) -> Fe {
    let (d0, b) = sbb(t[0], m[0], 0);
    let (d1, b) = sbb(t[1], m[1], b);
    let (d2, b) = sbb(t[2], m[2], b);
    let (d3, b) = sbb(t[3], m[3], b);
    let (_, b) = sbb(hi, 0, b);
    sel(crate::util::ct_mask(1 ^ b), &[d0, d1, d2, d3], t)
}

#[inline(always)]
fn add_mod(a: &Fe, b: &Fe, m: &Fe) -> Fe {
    let (s0, c) = adc(a[0], b[0], 0);
    let (s1, c) = adc(a[1], b[1], c);
    let (s2, c) = adc(a[2], b[2], c);
    let (s3, c) = adc(a[3], b[3], c);
    reduce_once(&[s0, s1, s2, s3], c, m)
}

#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
#[inline(always)]
fn sub_mod(a: &Fe, b: &Fe, m: &Fe) -> Fe {
    let (d0, br) = sbb(a[0], b[0], 0);
    let (d1, br) = sbb(a[1], b[1], br);
    let (d2, br) = sbb(a[2], b[2], br);
    let (d3, br) = sbb(a[3], b[3], br);
    let mask = br.wrapping_neg();
    let (r0, c) = adc(d0, m[0] & mask, 0);
    let (r1, c) = adc(d1, m[1] & mask, c);
    let (r2, c) = adc(d2, m[2] & mask, c);
    let (r3, _) = adc(d3, m[3] & mask, c);
    [r0, r1, r2, r3]
}

/// The 512-bit product a * b.
#[inline(always)]
fn mul_wide(a: &Fe, b: &Fe) -> [u64; 8] {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut c = 0;
        for j in 0..4 {
            let (v, cc) = mac(t[i + j], a[i], b[j], c);
            t[i + j] = v;
            c = cc;
        }
        t[i + 4] = c;
    }
    t
}

/// The 512-bit square a^2: six cross products doubled, plus four squares.
#[inline(always)]
#[cfg(test)]
fn sqr_wide(a: &Fe) -> [u64; 8] {
    let mut t = [0u64; 8];
    let (v, c) = mac(0, a[0], a[1], 0);
    t[1] = v;
    let (v, c) = mac(0, a[0], a[2], c);
    t[2] = v;
    let (v, c) = mac(0, a[0], a[3], c);
    t[3] = v;
    t[4] = c;
    let (v, c) = mac(t[3], a[1], a[2], 0);
    t[3] = v;
    let (v, c) = mac(t[4], a[1], a[3], c);
    t[4] = v;
    t[5] = c;
    let (v, c) = mac(t[5], a[2], a[3], 0);
    t[5] = v;
    t[6] = c;
    t[7] = t[6] >> 63;
    for i in (2..7).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 63);
    }
    t[1] <<= 1;
    let mut c = 0;
    for i in 0..4 {
        let sq = a[i] as u128 * a[i] as u128;
        let (v, cc) = adc(t[2 * i], sq as u64, c);
        t[2 * i] = v;
        let (v, cc) = adc(t[2 * i + 1], (sq >> 64) as u64, cc);
        t[2 * i + 1] = v;
        c = cc;
    }
    t
}

/// Montgomery reduction modulo p of a value below p * 2^256. p = -1 mod 2^64, so the
/// multiplier of each step is the low limb q itself, and q * p = q * p3 * 2^192 + q * 2^96 -
/// q: the low limb cancels, q << 96 lands on the next two limbs and one 64 x 64 product on the
/// two after. Each step's final carry is added by the next step (and the last one is the top
/// bit), so there is no carry ripple through the upper limbs.
#[inline(always)]
fn redc_p(mut t: [u64; 8]) -> Fe {
    let mut carry = 0u64;
    for i in 0..4 {
        let q = t[i];
        let (v, c) = adc(t[i + 1], q << 32, 0);
        t[i + 1] = v;
        let (v, c) = adc(t[i + 2], q >> 32, c);
        t[i + 2] = v;
        let prod = q as u128 * P[3] as u128;
        let (v, c) = adc(t[i + 3], prod as u64, c);
        t[i + 3] = v;
        // the high half of q * p3 is at most 2^64 - 2^32, so adding the previous carry is safe
        let (v, c) = adc(t[i + 4], (prod >> 64) as u64 + carry, c);
        t[i + 4] = v;
        carry = c;
    }
    reduce_once(&[t[4], t[5], t[6], t[7]], carry, &P)
}

/// Montgomery reduction modulo n (generic: q = t * -n^-1 mod 2^64).
#[inline(always)]
fn redc_n(mut t: [u64; 8]) -> Fe {
    let mut carry = 0u64;
    for i in 0..4 {
        let q = t[i].wrapping_mul(N0INV);
        let (_, c) = mac(t[i], q, N[0], 0);
        let (v, c) = mac(t[i + 1], q, N[1], c);
        t[i + 1] = v;
        let (v, c) = mac(t[i + 2], q, N[2], c);
        t[i + 2] = v;
        let (v, c) = mac(t[i + 3], q, N[3], c);
        t[i + 3] = v;
        let (v, c) = adc(t[i + 4], c, carry);
        t[i + 4] = v;
        carry = c;
    }
    reduce_once(&[t[4], t[5], t[6], t[7]], carry, &N)
}

// ---- field mod p (Montgomery form). Out of line: inlining them into every formula would
// add tens of KB for a few percent.

/// a * b mod p in Montgomery form: the MULX kernel when the CPU has it, else portable code.
#[inline(never)]
fn fmul(a: &Fe, b: &Fe) -> Fe {
    match simoom_sys::arch::p256_mul_mont(a, b) {
        Some(r) => r,
        None => fmul_portable(a, b),
    }
}

/// The portable multiplication (CPUs without MULX/ADX); also used for squaring there.
#[cold]
#[inline(never)]
fn fmul_portable(a: &Fe, b: &Fe) -> Fe {
    redc_p(mul_wide(a, b))
}

/// a^2 mod p in Montgomery form (see [`fmul`]).
#[inline(never)]
fn fsqr(a: &Fe) -> Fe {
    match simoom_sys::arch::p256_sqr_mont(a) {
        Some(r) => r,
        None => fmul_portable(a, a),
    }
}

#[inline]
fn fadd(a: &Fe, b: &Fe) -> Fe {
    #[cfg(target_arch = "x86_64")]
    return simoom_sys::arch::p256_add(a, b);
    #[cfg(not(target_arch = "x86_64"))]
    add_mod(a, b, &P)
}

#[inline]
fn fsub(a: &Fe, b: &Fe) -> Fe {
    #[cfg(target_arch = "x86_64")]
    return simoom_sys::arch::p256_sub(a, b);
    #[cfg(not(target_arch = "x86_64"))]
    sub_mod(a, b, &P)
}

#[inline]
fn fdbl(a: &Fe) -> Fe {
    fadd(a, a)
}

fn fneg(a: &Fe) -> Fe {
    fsub(&[0; 4], a)
}

fn to_mont(a: &Fe) -> Fe {
    fmul(a, &RR_P)
}

fn from_mont(a: &Fe) -> Fe {
    redc_p([a[0], a[1], a[2], a[3], 0, 0, 0, 0])
}

/// R^3 mod p and R^3 mod n: a Montgomery multiplication by R^3 turns the plain inverse of
/// a Montgomery-form value back into Montgomery form.
const R3_P: Fe = [0xffff_fffd_0000_000a, 0xffff_ffed_ffff_fff7, 0x0000_0005_ffff_fffc, 0x0000_0018_0000_0001];
const R3_N: Fe = [0xac8e_bec9_0b65_a624, 0x111f_28ae_0c05_55c9, 0x2543_b924_6ba5_e93f, 0x503a_54e7_6407_be65];
const P_INV: super::modinv::Modulus = super::modinv::Modulus::new(P);
const N_INV: super::modinv::Modulus = super::modinv::Modulus::new(N);

/// a^-1 mod p in Montgomery form (0 for 0), constant time (safegcd): (xR)^-1 = x^-1 R^-1 as a
/// plain integer, times R^3 in a Montgomery multiplication.
fn finv(a: &Fe) -> Fe {
    fmul(&super::modinv::invert(a, &P_INV), &R3_P)
}

// ---- scalars mod n

#[inline(never)]
fn nmul(a: &Fe, b: &Fe) -> Fe {
    match simoom_sys::arch::p256_order_mul_mont(a, b) {
        Some(r) => r,
        None => redc_n(mul_wide(a, b)),
    }
}

/// a^-1 mod n in Montgomery form, constant time (see [`finv`]).
fn ninv(a: &Fe) -> Fe {
    nmul(&super::modinv::invert(a, &N_INV), &R3_N)
}

/// All ones if a is zero.
fn is_zero(a: &Fe) -> u64 {
    let z = a[0] | a[1] | a[2] | a[3];
    ((z | z.wrapping_neg()) >> 63).wrapping_sub(1)
}

fn lt(a: &Fe, b: &Fe) -> bool {
    let (_, br) = sbb(a[0], b[0], 0);
    let (_, br) = sbb(a[1], b[1], br);
    let (_, br) = sbb(a[2], b[2], br);
    let (_, br) = sbb(a[3], b[3], br);
    br == 1
}

fn from_be(b: &[u8]) -> Fe {
    debug_assert_eq!(b.len(), 32);
    core::array::from_fn(|i| u64::from_be_bytes(b[24 - 8 * i..32 - 8 * i].try_into().unwrap()))
}

fn to_be(a: &Fe) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[8 * i..8 * i + 8].copy_from_slice(&a[3 - i].to_be_bytes());
    }
    o
}

// ---- scalars as signed digits

/// min(k, n - k) and an all-ones mask when n - k was taken (k < n). The result is at most
/// (n - 1) / 2 < 2^255. Constant time.
fn halve(k: &Fe) -> (Fe, u64) {
    let (_, b) = sbb(N_HALF[0], k[0], 0);
    let (_, b) = sbb(N_HALF[1], k[1], b);
    let (_, b) = sbb(N_HALF[2], k[2], b);
    let (_, b) = sbb(N_HALF[3], k[3], b);
    let neg = crate::util::ct_mask(b);
    let (d0, br) = sbb(N[0], k[0], 0);
    let (d1, br) = sbb(N[1], k[1], br);
    let (d2, br) = sbb(N[2], k[2], br);
    let (d3, _) = sbb(N[3], k[3], br);
    (sel(neg, &[d0, d1, d2, d3], k), neg)
}

/// Signed radix-32 digits in [-15, 16] of k < 2^255: k = sum d[i] * 32^i. Branch-free.
fn booth5(k: &Fe) -> [i8; 52] {
    let mut d = [0i8; 52];
    let mut carry = 0u64;
    for (i, di) in d.iter_mut().enumerate() {
        let bit = 5 * i;
        let (limb, shift) = (bit / 64, bit % 64);
        let mut w = k[limb] >> shift;
        if shift > 59 && limb < 3 {
            w |= k[limb + 1] << (64 - shift);
        }
        let v = (w & 31) + carry;
        carry = (v + 15) >> 5;
        *di = (v as i64 - (carry << 5) as i64) as i8;
    }
    d
}

/// |d| and an all-ones mask when d is negative.
#[inline(always)]
fn digit_abs(d: i8) -> (u64, u64) {
    let m = (d as i64 >> 63) as u64;
    (((d as i64 as u64) ^ m).wrapping_sub(m), crate::util::ct_mask(m & 1))
}

// ---- points

/// A point in Jacobian coordinates (x = X/Z^2, y = Y/Z^3), Montgomery form; Z = 0 is the
/// point at infinity.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[derive(Clone, Copy)]
struct Affine {
    x: Fe,
    y: Fe,
}

const INFINITY: Jac = Jac { x: ONE_MONT, y: ONE_MONT, z: [0; 4] };

fn sel_point(mask: u64, a: &Jac, b: &Jac) -> Jac {
    Jac { x: sel(mask, &a.x, &b.x), y: sel(mask, &a.y, &b.y), z: sel(mask, &a.z, &b.z) }
}

/// Doubling for a = -3 (dbl-2001-b, with Z3 = 2YZ): 4M + 4S. Exception-free: the double of
/// the point at infinity has Z = 0, and P-256 has no point of order 2.
fn double(p: &Jac) -> Jac {
    let delta = fsqr(&p.z);
    let gamma = fsqr(&p.y);
    let beta = fmul(&p.x, &gamma);
    let t = fmul(&fsub(&p.x, &delta), &fadd(&p.x, &delta));
    let alpha = fadd(&fdbl(&t), &t);
    let beta4 = fdbl(&fdbl(&beta));
    let x3 = fsub(&fsqr(&alpha), &fdbl(&beta4));
    let z3 = fdbl(&fmul(&p.y, &p.z));
    let g8 = fdbl(&fdbl(&fdbl(&fsqr(&gamma))));
    let y3 = fsub(&fmul(&alpha, &fsub(&beta4, &x3)), &g8);
    Jac { x: x3, y: y3, z: z3 }
}

/// p + q (add-2007-bl, with Z3 = 2 Z1 Z2 H): 12M + 4S. Either input may be the point at
/// infinity; the inputs must not be the same point (the result is then wrong).
fn add(p: &Jac, q: &Jac) -> Jac {
    let s = add_core(p, q, &add_prep(p, q));
    let s = sel_point(is_zero(&p.z), q, &s);
    sel_point(is_zero(&q.z), p, &s)
}

/// (U1, U2, S1, S2) of add-2007-bl.
fn add_prep(p: &Jac, q: &Jac) -> [Fe; 4] {
    let z1z1 = fsqr(&p.z);
    let z2z2 = fsqr(&q.z);
    [fmul(&p.x, &z2z2), fmul(&q.x, &z1z1), fmul(&p.y, &fmul(&q.z, &z2z2)), fmul(&q.y, &fmul(&p.z, &z1z1))]
}

fn add_core(p: &Jac, q: &Jac, [u1, u2, s1, s2]: &[Fe; 4]) -> Jac {
    let h = fsub(u2, u1);
    let i = fsqr(&fdbl(&h));
    let j = fmul(&h, &i);
    let r = fdbl(&fsub(s2, s1));
    let v = fmul(u1, &i);
    let x3 = fsub(&fsub(&fsqr(&r), &j), &fdbl(&v));
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fdbl(&fmul(s1, &j)));
    let z3 = fdbl(&fmul(&fmul(&p.z, &q.z), &h));
    Jac { x: x3, y: y3, z: z3 }
}

/// p + q for an affine q (madd-2007-bl, with Z3 = 2 Z1 H): 8M + 3S. p may be the point at
/// infinity; q must be a point on the curve, not equal to p.
fn add_affine(p: &Jac, q: &Affine) -> Jac {
    let z1z1 = fsqr(&p.z);
    let u2 = fmul(&q.x, &z1z1);
    let s2 = fmul(&q.y, &fmul(&p.z, &z1z1));
    let h = fsub(&u2, &p.x);
    let hh = fsqr(&h);
    let i = fdbl(&fdbl(&hh));
    let j = fmul(&h, &i);
    let r = fdbl(&fsub(&s2, &p.y));
    let v = fmul(&p.x, &i);
    let x3 = fsub(&fsub(&fsqr(&r), &j), &fdbl(&v));
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fdbl(&fmul(&p.y, &j)));
    let z3 = fdbl(&fmul(&p.z, &h));
    let inf = is_zero(&p.z);
    Jac { x: sel(inf, &q.x, &x3), y: sel(inf, &q.y, &y3), z: sel(inf, &ONE_MONT, &z3) }
}

/// p + q for public points, in variable time, correct for every input (equal points are
/// doubled).
fn add_vartime(p: &Jac, q: &Jac) -> Jac {
    if is_zero(&p.z) != 0 {
        return *q;
    }
    if is_zero(&q.z) != 0 {
        return *p;
    }
    let pre = add_prep(p, q);
    if pre[0] == pre[1] {
        return if pre[2] == pre[3] { double(p) } else { INFINITY };
    }
    add_core(p, q, &pre)
}

fn neg_point(p: &Jac) -> Jac {
    Jac { x: p.x, y: fneg(&p.y), z: p.z }
}

/// k * G, constant time.
///
/// With k' = min(k, n - k) < 2^255 and its signed digits d[i], the loop adds
/// t = d[i] * 32^i * G to s = sum_{j<i} d[j] * 32^j * G. As integers |s| < 32^i * 16/31 <
/// |d[i]| * 32^i, so s != t, and |s - t| < 17 * 32^i < 2^255 < n for i <= 50; for i = 51,
/// d[51] <= 1 and |s - t| < 2^255 * 47/31 < n. So s and t are never the same point; s = -t
/// gives the point at infinity, which the masked selection handles like a zero s.
fn mul_base(k: &Fe) -> Jac {
    let (k, neg) = halve(k);
    let digits = booth5(&k);
    let tbl = base_table();
    let mut acc = INFINITY;
    for (row, &d) in tbl.iter().zip(digits.iter()) {
        let (abs, dneg) = digit_abs(d);
        let mut a = Affine { x: [0; 4], y: [0; 4] };
        for (j, e) in row.iter().enumerate() {
            let m = crate::util::ct_eq_mask(abs, j as u64 + 1);
            a = Affine { x: sel(m, &e.x, &a.x), y: sel(m, &e.y, &a.y) };
        }
        a.y = sel(dneg, &fneg(&a.y), &a.y);
        let s = add_affine(&acc, &a);
        acc = sel_point(crate::util::ct_eq_mask(abs, 0), &acc, &s);
    }
    Jac { x: acc.x, y: sel(neg, &fneg(&acc.y), &acc.y), z: acc.z }
}

/// The base-point table: entry [i][d-1] = d * 32^i * G, affine, Montgomery form.
fn base_table() -> &'static [[Affine; 16]] {
    static T: OnceLock<Vec<[Affine; 16]>> = OnceLock::new();
    T.get_or_init(|| {
        let g = Jac { x: to_mont(&GX), y: to_mont(&GY), z: ONE_MONT };
        let mut proj = Vec::with_capacity(52 * 16);
        let mut base = g;
        for _ in 0..52 {
            let row = multiples(&base);
            proj.extend_from_slice(&row);
            base = double(&row[15]); // 32 * base
        }
        // batch inversion of the Z coordinates (Montgomery's trick); no Z is zero
        let mut prefix = Vec::with_capacity(proj.len());
        let mut acc = ONE_MONT;
        for p in &proj {
            prefix.push(acc);
            acc = fmul(&acc, &p.z);
        }
        let mut inv = finv(&acc);
        let mut out = vec![Affine { x: [0; 4], y: [0; 4] }; proj.len()];
        for i in (0..proj.len()).rev() {
            let zi = fmul(&inv, &prefix[i]);
            inv = fmul(&inv, &proj[i].z);
            let zi2 = fsqr(&zi);
            out[i] = Affine { x: fmul(&proj[i].x, &zi2), y: fmul(&proj[i].y, &fmul(&zi2, &zi)) };
        }
        out.chunks(16).map(|c| c.try_into().unwrap()).collect()
    })
}

/// [1P, 2P, ..., 16P] for a point P that is not the point at infinity (no addition below adds
/// equal points: jP + P with 2 <= j <= 15).
fn multiples(p: &Jac) -> [Jac; 16] {
    let mut t = [*p; 16];
    for i in 1..16 {
        t[i] = if i % 2 == 1 { double(&t[i / 2]) } else { add(&t[i - 1], p) };
    }
    t
}

/// k * P, constant time; P is not the point at infinity.
///
/// With k' = min(k, n - k) and its signed digits, each step computes s = 32 * S * P from the
/// higher digits S and adds t = d * P with |d| <= 16. If S != 0 then |32 S| >= 32 > |d|, and
/// |32 S - d| <= k' + 32 < n, so s and t are never the same point; S = 0 is the point at
/// infinity, which [`add`] handles.
fn mul(p: &Jac, k: &Fe) -> Jac {
    let (k, neg) = halve(k);
    let digits = booth5(&k);
    let tbl = multiples(p);
    let lookup = |d: i8| -> Jac {
        let (abs, dneg) = digit_abs(d);
        let mut r = INFINITY;
        for (j, t) in tbl.iter().enumerate() {
            r = sel_point(crate::util::ct_eq_mask(abs, j as u64 + 1), t, &r);
        }
        Jac { x: r.x, y: sel(dneg, &fneg(&r.y), &r.y), z: r.z }
    };
    let mut acc = lookup(digits[51]);
    for i in (0..51).rev() {
        for _ in 0..5 {
            acc = double(&acc);
        }
        acc = add(&acc, &lookup(digits[i]));
    }
    Jac { x: acc.x, y: sel(neg, &fneg(&acc.y), &acc.y), z: acc.z }
}

/// Width-5 NAF of a public scalar k < 2^256: digits odd in [-15, 15] or zero.
fn wnaf5(k: &Fe) -> [i8; 257] {
    let mut out = [0i8; 257];
    let mut k = [k[0], k[1], k[2], k[3], 0u64];
    let mut i = 0;
    while k.iter().any(|&l| l != 0) {
        if k[0] & 1 == 1 {
            let mut d = (k[0] & 31) as i64;
            if d > 16 {
                d -= 32;
            }
            out[i] = d as i8;
            // k -= d: the low five bits become zero; only a negative d can carry
            if d > 0 {
                k[0] -= d as u64;
            } else {
                let (v, mut c) = k[0].overflowing_add((-d) as u64);
                k[0] = v;
                for l in k.iter_mut().skip(1) {
                    if !c {
                        break;
                    }
                    (*l, c) = l.overflowing_add(1);
                }
            }
        }
        for j in 0..4 {
            k[j] = (k[j] >> 1) | (k[j + 1] << 63);
        }
        k[4] >>= 1;
        i += 1;
    }
    out
}

/// u1 * G + u2 * P for public scalars and P, in variable time (Straus-Shamir: one chain of
/// doublings, width-5 NAF digits of both scalars; the odd multiples of G come from the first
/// row of the fixed-base table).
fn mul2_vartime(u1: &Fe, p: &Jac, u2: &Fe) -> Jac {
    let (n1, n2) = (wnaf5(u1), wnaf5(u2));
    let p2 = double(p);
    let mut odd = [*p; 8];
    for i in 1..8 {
        odd[i] = add_vartime(&odd[i - 1], &p2);
    }
    let g = &base_table()[0];
    let gj = |d: i8| -> Jac {
        let a = &g[(d.unsigned_abs() - 1) as usize];
        Jac { x: a.x, y: if d < 0 { fneg(&a.y) } else { a.y }, z: ONE_MONT }
    };
    let top = (0..257).rev().find(|&i| n1[i] != 0 || n2[i] != 0).unwrap_or(0);
    let mut acc = INFINITY;
    for i in (0..=top).rev() {
        acc = double(&acc);
        let d = n2[i];
        if d > 0 {
            acc = add_vartime(&acc, &odd[(d / 2) as usize]);
        } else if d < 0 {
            acc = add_vartime(&acc, &neg_point(&odd[(-d / 2) as usize]));
        }
        if n1[i] != 0 {
            acc = add_affine_vartime(&acc, &gj(n1[i]));
        }
    }
    acc
}

/// p + q for public points with q affine (Z = 1), in variable time, correct for every input.
fn add_affine_vartime(p: &Jac, q: &Jac) -> Jac {
    if is_zero(&p.z) != 0 {
        return *q;
    }
    let z1z1 = fsqr(&p.z);
    let u2 = fmul(&q.x, &z1z1);
    let s2 = fmul(&q.y, &fmul(&p.z, &z1z1));
    if u2 == p.x {
        return if s2 == p.y { double(p) } else { INFINITY };
    }
    add_affine(p, &Affine { x: q.x, y: q.y })
}

/// Affine (x, y) as plain integers; None for the point at infinity.
fn to_affine(p: &Jac) -> Option<(Fe, Fe)> {
    if is_zero(&p.z) != 0 {
        return None;
    }
    let zi = finv(&p.z);
    let zi2 = fsqr(&zi);
    Some((from_mont(&fmul(&p.x, &zi2)), from_mont(&fmul(&p.y, &fmul(&zi2, &zi)))))
}

fn encode(x: &Fe, y: &Fe) -> [u8; 65] {
    let mut o = [0u8; 65];
    o[0] = 4;
    o[1..33].copy_from_slice(&to_be(x));
    o[33..].copy_from_slice(&to_be(y));
    o
}

/// Decodes and validates an uncompressed point (0x04 || X || Y).
fn decode(data: &[u8]) -> Option<Jac> {
    if data.len() != 65 || data[0] != 4 {
        return None;
    }
    let x = from_be(&data[1..33]);
    let y = from_be(&data[33..]);
    if !lt(&x, &P) || !lt(&y, &P) {
        return None;
    }
    let (xm, ym) = (to_mont(&x), to_mont(&y));
    // y^2 == x^3 - 3x + b
    let lhs = fsqr(&ym);
    let x3 = fmul(&fsqr(&xm), &xm);
    let three_x = fadd(&fdbl(&xm), &xm);
    let rhs = fadd(&fsub(&x3, &three_x), &B_MONT);
    if lhs != rhs {
        return None;
    }
    Some(Jac { x: xm, y: ym, z: ONE_MONT })
}

fn scalar_valid(k: &Fe) -> bool {
    is_zero(k) == 0 && lt(k, &N)
}

/// A random valid private scalar (big-endian).
pub fn generate_private() -> [u8; 32] {
    loop {
        let b = super::rng::array::<32>();
        if scalar_valid(&from_be(&b)) {
            return b;
        }
    }
}

/// The uncompressed public key for a private scalar; None if the scalar is out of range.
pub fn public_key(private: &[u8]) -> Option<[u8; 65]> {
    if private.len() != 32 {
        return None;
    }
    let k = from_be(private);
    if !scalar_valid(&k) {
        return None;
    }
    let (x, y) = to_affine(&mul_base(&k))?;
    Some(encode(&x, &y))
}

/// [`public_key`] without the base-point table: one variable-base multiplication (constant
/// time). For loading a key at start-up, which then neither spends about 0.3 ms building the
/// 53 KB table nor keeps it (and its larger temporaries) in memory before the first handshake
/// that signs or generates a P-256 key share needs it.
pub fn public_key_untabled(private: &[u8]) -> Option<[u8; 65]> {
    if private.len() != 32 {
        return None;
    }
    let k = from_be(private);
    if !scalar_valid(&k) {
        return None;
    }
    let g = Jac { x: to_mont(&GX), y: to_mont(&GY), z: ONE_MONT };
    let (x, y) = to_affine(&mul(&g, &k))?;
    Some(encode(&x, &y))
}

/// ECDH: the x-coordinate of private * peer. Validates the peer point.
pub fn ecdh(private: &[u8], peer: &[u8]) -> Option<[u8; 32]> {
    let q = decode(peer)?;
    if private.len() != 32 {
        return None;
    }
    let k = from_be(private);
    if !scalar_valid(&k) {
        return None;
    }
    let (x, _) = to_affine(&mul(&q, &k))?;
    Some(to_be(&x))
}

/// True if `public` is a valid uncompressed point.
pub fn validate_point(public: &[u8]) -> bool {
    decode(public).is_some()
}

/// bits2int(h) mod n for a digest of at least 32 bytes (truncated to the leftmost 256 bits).
fn hash_to_scalar(h: &[u8]) -> Fe {
    let mut b = [0u8; 32];
    let take = h.len().min(32);
    b[32 - take..].copy_from_slice(&h[..take]);
    let e = from_be(&b);
    reduce_once(&e, 0, &N)
}

/// RFC 6979 deterministic nonce (the `extra`-th valid candidate).
fn rfc6979_k(d: &[u8; 32], h: &[u8], hash: HashAlg, extra: u32) -> Fe {
    let hlen = hash.output_len();
    let h1 = to_be(&hash_to_scalar(h));
    let mut v = [1u8; 64];
    let mut k = [0u8; 64];
    let kk = hash.hmac(&k[..hlen], &[&v[..hlen], &[0], d, &h1]);
    k[..hlen].copy_from_slice(&kk);
    let vv = hash.hmac(&k[..hlen], &[&v[..hlen]]);
    v[..hlen].copy_from_slice(&vv);
    let kk = hash.hmac(&k[..hlen], &[&v[..hlen], &[1], d, &h1]);
    k[..hlen].copy_from_slice(&kk);
    let vv = hash.hmac(&k[..hlen], &[&v[..hlen]]);
    v[..hlen].copy_from_slice(&vv);
    let mut attempt = 0;
    loop {
        let mut t = [0u8; 64];
        let mut tl = 0;
        while tl < 32 {
            let vv = hash.hmac(&k[..hlen], &[&v[..hlen]]);
            v[..hlen].copy_from_slice(&vv);
            let n = hlen.min(32 - tl);
            t[tl..tl + n].copy_from_slice(&vv[..n]);
            tl += n;
        }
        let cand = from_be(&t[..32]);
        if scalar_valid(&cand) {
            if attempt == extra {
                return cand;
            }
            attempt += 1;
        }
        let kk = hash.hmac(&k[..hlen], &[&v[..hlen], &[0]]);
        k[..hlen].copy_from_slice(&kk);
        let vv = hash.hmac(&k[..hlen], &[&v[..hlen]]);
        v[..hlen].copy_from_slice(&vv);
    }
}

fn to_mont_n(a: &Fe) -> Fe {
    nmul(a, &RR_N)
}

fn from_mont_n(a: &Fe) -> Fe {
    redc_n([a[0], a[1], a[2], a[3], 0, 0, 0, 0])
}

/// ECDSA signature over a digest; returns (r, s) as 32-byte big-endian values.
pub fn sign(private: &[u8], digest: &[u8], hash: HashAlg) -> Option<([u8; 32], [u8; 32])> {
    let d_bytes: [u8; 32] = private.try_into().ok()?;
    let d = from_be(&d_bytes);
    if !scalar_valid(&d) {
        return None;
    }
    let e = hash_to_scalar(digest);
    for extra in 0.. {
        let k = rfc6979_k(&d_bytes, digest, hash, extra);
        let Some((x, _)) = to_affine(&mul_base(&k)) else { continue };
        let r = reduce_once(&x, 0, &N);
        if is_zero(&r) != 0 {
            continue;
        }
        let kinv = ninv(&to_mont_n(&k));
        let rd = nmul(&to_mont_n(&r), &to_mont_n(&d));
        let s = from_mont_n(&nmul(&kinv, &add_mod(&to_mont_n(&e), &rd, &N)));
        if is_zero(&s) != 0 {
            continue;
        }
        return Some((to_be(&r), to_be(&s)));
    }
    None
}

/// ECDSA verification over a digest; `r` and `s` are big-endian (leading zeros allowed).
pub fn verify(public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let fix = |b: &[u8]| -> Option<Fe> {
        let b = &b[b.iter().take_while(|x| **x == 0).count()..];
        if b.len() > 32 {
            return None;
        }
        let mut f = [0u8; 32];
        f[32 - b.len()..].copy_from_slice(b);
        Some(from_be(&f))
    };
    let (Some(r), Some(s)) = (fix(r), fix(s)) else { return false };
    if !scalar_valid(&r) || !scalar_valid(&s) {
        return false;
    }
    let Some(q) = decode(public) else { return false };
    let e = hash_to_scalar(digest);
    let w = ninv(&to_mont_n(&s));
    let u1 = nmul(&e, &w);
    let u2 = nmul(&r, &w);
    let pt = mul2_vartime(&u1, &q, &u2);
    match to_affine(&pt) {
        Some((x, _)) => reduce_once(&x, 0, &N) == r,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bug 19: loading a key computes its public key without the base table, and gets the
    // same point.
    #[test]
    fn public_key_untabled_matches_the_table() {
        for i in 1..20u8 {
            let mut d = [0u8; 32];
            d[31] = i;
            d[0] = i.wrapping_mul(37);
            d[15] = 0xa5 ^ i;
            assert_eq!(public_key_untabled(&d), public_key(&d), "{i}");
        }
        let d = generate_private();
        assert_eq!(public_key_untabled(&d), public_key(&d));
        assert!(public_key_untabled(&[0u8; 32]).is_none());
        assert!(public_key_untabled(&[0xff; 32]).is_none());
    }
    use crate::crypto::sha2::Sha256;
    use crate::util::{hex, unhex};

    fn g() -> Jac {
        Jac { x: to_mont(&GX), y: to_mont(&GY), z: ONE_MONT }
    }

    fn sub_n(a: &Fe, b: &Fe) -> Fe {
        sub_mod(a, b, &N)
    }

    /// Reference k * P: affine double-and-add with inversions (slow, independent formulas).
    /// Points in and out are affine, Montgomery form in, plain integers out.
    fn ref_mul(p: Option<(Fe, Fe)>, k: &Fe) -> Option<(Fe, Fe)> {
        let add_aff = |a: Option<(Fe, Fe)>, b: Option<(Fe, Fe)>| -> Option<(Fe, Fe)> {
            let (Some((x1, y1)), Some((x2, y2))) = (a, b) else { return a.or(b) };
            let lambda = if x1 == x2 {
                if y1 != y2 || is_zero(&y1) != 0 {
                    return None;
                }
                let x1s = fsqr(&x1);
                let num = fsub(&fadd(&fdbl(&x1s), &x1s), &fadd(&fdbl(&ONE_MONT), &ONE_MONT));
                fmul(&num, &finv(&fdbl(&y1)))
            } else {
                fmul(&fsub(&y2, &y1), &finv(&fsub(&x2, &x1)))
            };
            let x3 = fsub(&fsub(&fsqr(&lambda), &x1), &x2);
            let y3 = fsub(&fmul(&lambda, &fsub(&x1, &x3)), &y1);
            Some((x3, y3))
        };
        let mut acc = None;
        for i in (0..256).rev() {
            acc = add_aff(acc, acc);
            if (k[i / 64] >> (i % 64)) & 1 == 1 {
                acc = add_aff(acc, p);
            }
        }
        acc.map(|(x, y)| (from_mont(&x), from_mont(&y)))
    }

    #[test]
    fn constants() {
        // R^2 mod p and R^2 mod n, b and 1 in Montgomery form, recomputed slowly
        let mut r = [1u64, 0, 0, 0];
        let mut rn = [1u64, 0, 0, 0];
        for _ in 0..512 {
            r = add_mod(&r, &r, &P);
            rn = add_mod(&rn, &rn, &N);
        }
        assert_eq!(r, RR_P);
        assert_eq!(rn, RR_N);
        let b = from_be(&unhex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"));
        assert_eq!(to_mont(&b), B_MONT);
        assert_eq!(to_mont(&[1, 0, 0, 0]), ONE_MONT);
        assert_eq!(fmul(&RR_P, &RR_P), R3_P);
        assert_eq!(nmul(&RR_N, &RR_N), R3_N);
        assert_eq!(N[0].wrapping_mul(N0INV).wrapping_neg(), 1);
        let mut nm1 = N;
        nm1[0] -= 1;
        let nh: Fe = core::array::from_fn(|i| (nm1[i] >> 1) | if i < 3 { nm1[i + 1] << 63 } else { 0 });
        assert_eq!(nh, N_HALF);
        let a = to_mont(&[5, 6, 7, 8]);
        assert_eq!(from_mont(&fmul(&a, &finv(&a))), [1, 0, 0, 0]);
        let am = to_mont_n(&[9, 8, 7, 6]);
        assert_eq!(from_mont_n(&nmul(&am, &ninv(&am))), [1, 0, 0, 0]);
    }

    #[test]
    fn field_squaring_and_reduction_edges() {
        let mut pm1 = P;
        pm1[0] -= 1;
        let mut vals = vec![[0u64; 4], [1, 0, 0, 0], ONE_MONT, pm1, [u64::MAX, 0, 0, 0], [0, 0, 0, u64::MAX >> 1]];
        for _ in 0..200 {
            vals.push(reduce_once(&from_be(&crate::crypto::rng::array::<32>()), 0, &P));
        }
        for a in &vals {
            assert_eq!(fsqr(a), fmul(a, a));
            // the portable code and the MULX kernel (when the CPU has it) agree
            assert_eq!(redc_p(sqr_wide(a)), fsqr(a));
            assert_eq!(redc_p(mul_wide(a, &vals[2])), fmul(a, &vals[2]));
            let an = reduce_once(a, 0, &N);
            assert_eq!(redc_n(sqr_wide(&an)), nmul(&an, &an));
            assert_eq!(redc_n(mul_wide(&an, &vals[5])), nmul(&an, &vals[5]));
            assert_eq!(from_mont(&to_mont(a)), *a);
            for b in vals.iter().take(10) {
                let ab = fmul(a, b);
                assert!(lt(&ab, &P));
                assert_eq!(ab, fmul(b, a));
                assert_eq!(fsub(&fadd(a, b), b), *a);
                assert_eq!(fadd(a, b), add_mod(a, b, &P));
                assert_eq!(fsub(a, b), sub_mod(a, b, &P));
            }
        }
        // (p - 1)^2 = 1
        assert_eq!(from_mont(&fsqr(&to_mont(&pm1))), [1, 0, 0, 0]);
        assert_eq!(fneg(&[0; 4]), [0; 4]);
        let mut nm1 = N;
        nm1[0] -= 1;
        assert_eq!(from_mont_n(&nmul(&to_mont_n(&nm1), &to_mont_n(&nm1))), [1, 0, 0, 0]);
    }

    #[test]
    fn formulas_agree() {
        let g = g();
        let ga = Affine { x: g.x, y: g.y };
        let p2 = double(&g);
        let p3 = add(&p2, &g);
        assert_eq!(to_affine(&add_affine(&p2, &ga)), to_affine(&p3));
        assert_eq!(to_affine(&add_vartime(&g, &g)), to_affine(&p2));
        assert!(to_affine(&add_vartime(&g, &neg_point(&g))).is_none());
        assert_eq!(to_affine(&add(&INFINITY, &g)), to_affine(&g));
        assert_eq!(to_affine(&add(&g, &INFINITY)), to_affine(&g));
        assert!(to_affine(&double(&INFINITY)).is_none());
        assert_eq!(to_affine(&add_affine(&INFINITY, &ga)), to_affine(&g));
        // p + (-p) is the point at infinity in the constant-time formulas too
        assert!(to_affine(&add(&p3, &neg_point(&p3))).is_none());
        assert!(to_affine(&add_affine(&g, &Affine { x: g.x, y: fneg(&g.y) })).is_none());
        let m = multiples(&g);
        for (i, p) in m.iter().enumerate() {
            assert_eq!(to_affine(p), ref_mul(Some((g.x, g.y)), &[i as u64 + 1, 0, 0, 0]));
        }
    }

    #[test]
    fn digits_reconstruct_the_scalar() {
        let check = |k: Fe| {
            let d = booth5(&k);
            assert!(d.iter().all(|&x| (-15..=16).contains(&x)));
            // sum d[i] 32^i from the top, in 5-limb two's complement
            let mut v = [0u64; 5];
            for &di in d.iter().rev() {
                let mut c = 0u64;
                for l in v.iter_mut() {
                    let t = ((*l as u128) << 5) | c as u128;
                    *l = t as u64;
                    c = (t >> 64) as u64;
                }
                let ext = if di < 0 { u64::MAX } else { 0 };
                let (s, mut cy) = v[0].overflowing_add(di as i64 as u64);
                v[0] = s;
                for l in v.iter_mut().skip(1) {
                    let (s1, c1) = l.overflowing_add(ext);
                    let (s2, c2) = s1.overflowing_add(cy as u64);
                    *l = s2;
                    cy = c1 | c2;
                }
            }
            assert_eq!(&v[..4], &k[..], "{k:x?}");
            assert_eq!(v[4], 0);
        };
        check([0; 4]);
        check([1, 0, 0, 0]);
        check(N_HALF);
        check([u64::MAX, u64::MAX, u64::MAX, (1 << 63) - 1]);
        check([0x0842_1084_2108_4210; 4]);
        for _ in 0..100 {
            let mut k = from_be(&crate::crypto::rng::array::<32>());
            k[3] >>= 1;
            check(k);
        }
    }

    #[test]
    fn wnaf_reconstructs_the_scalar() {
        let mut ks = vec![[0u64; 4], [1, 0, 0, 0], [u64::MAX; 4], N, [31, 0, 0, 0], [17, 0, 0, u64::MAX]];
        for _ in 0..50 {
            ks.push(from_be(&crate::crypto::rng::array::<32>()));
        }
        for k in ks {
            let naf = wnaf5(&k);
            let mut v = [0u64; 5];
            for &d in naf.iter().rev() {
                for j in (1..5).rev() {
                    v[j] = (v[j] << 1) | (v[j - 1] >> 63);
                }
                v[0] <<= 1;
                let ext = if d < 0 { u64::MAX } else { 0 };
                let (s, mut cy) = v[0].overflowing_add(d as i64 as u64);
                v[0] = s;
                for l in v.iter_mut().skip(1) {
                    let (s1, c1) = l.overflowing_add(ext);
                    let (s2, c2) = s1.overflowing_add(cy as u64);
                    *l = s2;
                    cy = c1 | c2;
                }
                assert!(d == 0 || (d % 2 != 0 && (-15..=15).contains(&d)));
            }
            assert_eq!(&v[..4], &k[..]);
        }
    }

    #[test]
    fn scalar_multiplication_edge_cases() {
        let g = g();
        let gaff = Some((g.x, g.y));
        let q = double(&double(&add(&double(&g), &g))); // 12 G
        let qa = to_affine(&q).map(|(x, y)| (to_mont(&x), to_mont(&y)));
        let mut nm1 = N;
        nm1[0] -= 1;
        let mut nm2 = N;
        nm2[0] -= 2;
        let mut nh1 = N_HALF;
        nh1[0] += 1;
        let mut ks: Vec<Fe> = vec![[1, 0, 0, 0], [2, 0, 0, 0], [16, 0, 0, 0], [17, 0, 0, 0], [31, 0, 0, 0], [32, 0, 0, 0], [33, 0, 0, 0]];
        ks.extend_from_slice(&[nm1, nm2, N_HALF, nh1, sub_n(&N, &[16, 0, 0, 0]), sub_n(&N, &[17, 0, 0, 0])]);
        ks.push([0, 0, 0, 1 << 63]); // 2^255
        ks.push([0, 0, 0, 1 << 62]);
        ks.push([u64::MAX, u64::MAX, 0, 0]);
        ks.push([0x8421_0842_1084_2108, 0x4210_8421_0842_1084, 0x2108_4210_8421_0842, 0x1084_2108_4210_8421]);
        for _ in 0..12 {
            ks.push(from_be(&generate_private()));
        }
        for k in &ks {
            let want = ref_mul(gaff, k);
            assert_eq!(to_affine(&mul_base(k)), want, "mul_base {k:x?}");
            assert_eq!(to_affine(&mul(&g, k)), want, "mul {k:x?}");
            assert_eq!(to_affine(&mul2_vartime(k, &g, &[0; 4])), want, "mul2_vartime u1 {k:x?}");
            assert_eq!(to_affine(&mul2_vartime(&[0; 4], &g, k)), want, "mul2_vartime u2 {k:x?}");
            let wq = ref_mul(qa, k);
            assert_eq!(to_affine(&mul(&q, k)), wq, "mul Q {k:x?}");
            assert_eq!(to_affine(&mul2_vartime(&[0; 4], &q, k)), wq, "mul2_vartime Q {k:x?}");
            // u1 G + u2 Q with Q = 12 G is (u1 + 12 u2) G
            let u2 = [7, 0, 0, 0];
            let sum = add_mod(k, &[84, 0, 0, 0], &N);
            assert_eq!(to_affine(&mul2_vartime(k, &q, &u2)), ref_mul(gaff, &sum), "mul2_vartime sum {k:x?}");
        }
        // n * G and 0 * G are the point at infinity
        assert!(to_affine(&mul2_vartime(&N, &g, &[0; 4])).is_none());
        assert!(to_affine(&mul2_vartime(&[1, 0, 0, 0], &g, &sub_n(&N, &[1, 0, 0, 0]))).is_none());
        assert!(to_affine(&mul_base(&[0; 4])).is_none());
        assert!(to_affine(&mul(&g, &[0; 4])).is_none());
        // (n - 1) G = -G
        let (x, y) = to_affine(&mul_base(&nm1)).unwrap();
        assert_eq!(x, GX);
        assert_eq!(fsub(&[0; 4], &to_mont(&GY)), to_mont(&y));
    }

    #[test]
    fn ecdh_rfc5903_and_cavp() {
        let i = unhex("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        let r = unhex("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
        let gi = public_key(&i).unwrap();
        assert_eq!(
            hex(&gi),
            "04dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"
        );
        let gr = public_key(&r).unwrap();
        let s1 = ecdh(&i, &gr).unwrap();
        assert_eq!(hex(&s1), "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de");
        assert_eq!(s1, ecdh(&r, &gi).unwrap());
        let mut bad = gr;
        bad[40] ^= 1;
        assert!(ecdh(&i, &bad).is_none());
        let d = unhex("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let peer = unhex(
            "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
        );
        assert_eq!(hex(&ecdh(&d, &peer).unwrap()), "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");
        assert!(public_key(&[0u8; 32]).is_none());
        assert!(public_key(&to_be(&N)).is_none());
        assert!(ecdh(&to_be(&N), &peer).is_none());
        assert!(ecdh(&[0u8; 32], &peer).is_none());
    }

    #[test]
    fn invalid_points_are_rejected() {
        let d = generate_private();
        let good = public_key(&generate_private()).unwrap();
        // the point at infinity has no uncompressed encoding; 0x00 and compressed forms are refused
        assert!(ecdh(&d, &[0]).is_none());
        let mut compressed = [0u8; 33];
        compressed[0] = 2;
        compressed[1..].copy_from_slice(&good[1..33]);
        assert!(ecdh(&d, &compressed).is_none());
        assert!(ecdh(&d, &good[..64]).is_none());
        let mut wrong_tag = good;
        wrong_tag[0] = 6;
        assert!(ecdh(&d, &wrong_tag).is_none());
        let mut zero = [0u8; 65];
        zero[0] = 4;
        assert!(ecdh(&d, &zero).is_none());
        // coordinates >= p (x = p would be 0 mod p if not range-checked)
        let mut big = good;
        big[1..33].copy_from_slice(&to_be(&P));
        assert!(ecdh(&d, &big).is_none());
        let mut ybig = good;
        ybig[33..].copy_from_slice(&to_be(&P));
        assert!(ecdh(&d, &ybig).is_none());
        // (0, 1) lies on y^2 = x^3 - 3x + 1, a different curve: an invalid-curve point
        let mut other = [0u8; 65];
        other[0] = 4;
        other[64] = 1;
        assert!(ecdh(&d, &other).is_none());
        assert!(!validate_point(&other));
        // -G is valid, and d * (-G) has the same x as d * G
        let gpub = public_key(&to_be(&[1, 0, 0, 0])).unwrap();
        let mut neg = gpub;
        neg[33..].copy_from_slice(&to_be(&sub_mod(&P, &GY, &P)));
        assert!(validate_point(&neg));
        assert_eq!(ecdh(&d, &neg), ecdh(&d, &gpub));
    }

    #[test]
    fn ecdsa_rfc6979() {
        let x = unhex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let pk = public_key(&x).unwrap();
        assert_eq!(
            hex(&pk),
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        );
        let h = Sha256::digest(b"sample");
        let (r, s) = sign(&x, &h, HashAlg::Sha256).unwrap();
        assert_eq!(hex(&r), "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
        assert_eq!(hex(&s), "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
        assert!(verify(&pk, &h, &r, &s));
        let h = Sha256::digest(b"test");
        let (r, s) = sign(&x, &h, HashAlg::Sha256).unwrap();
        assert_eq!(hex(&r), "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367");
        assert_eq!(hex(&s), "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083");
        assert!(verify(&pk, &h, &r, &s));
        assert!(!verify(&pk, &Sha256::digest(b"tesT"), &r, &s));
        let h = HashAlg::Sha384.hash(b"sample");
        let (r, s) = sign(&x, &h, HashAlg::Sha384).unwrap();
        assert_eq!(hex(&r), "0eafea039b20e9b42309fb1d89e213057cbf973dc0cfc8f129edddc800ef7719");
        assert_eq!(hex(&s), "4861f0491e6998b9455193e34e7b0d284ddd7149a74b95b9261f13abde940954");
        assert!(verify(&pk, &h, &r, &s));
    }

    #[test]
    fn random_roundtrip_and_rejections() {
        let d = generate_private();
        let pk = public_key(&d).unwrap();
        let h = Sha256::digest(b"hello");
        let (r, s) = sign(&d, &h, HashAlg::Sha256).unwrap();
        assert!(verify(&pk, &h, &r, &s));
        let mut s2 = s;
        s2[5] ^= 0x10;
        assert!(!verify(&pk, &h, &r, &s2));
        assert!(!verify(&pk, &h, &[0; 32], &s));
        assert!(!verify(&pk, &h, &r, &[0; 32]));
        assert!(!verify(&pk, &h, &to_be(&N), &s));
        assert!(!verify(&pk, &h, &r, &to_be(&N)));
        // r + n (33 bytes) is refused rather than reduced
        let rf = from_be(&r);
        let (a0, c) = adc(rf[0], N[0], 0);
        let (a1, c) = adc(rf[1], N[1], c);
        let (a2, c) = adc(rf[2], N[2], c);
        let (a3, c) = adc(rf[3], N[3], c);
        let mut r_plus_n = vec![c as u8];
        r_plus_n.extend_from_slice(&to_be(&[a0, a1, a2, a3]));
        assert!(!verify(&pk, &h, &r_plus_n, &s));
        // (r, n - s) is the other valid signature (ECDSA malleability)
        assert!(verify(&pk, &h, &r, &to_be(&sub_n(&N, &from_be(&s)))));
        assert!(!verify(&public_key(&generate_private()).unwrap(), &h, &r, &s));
        let mut leading = vec![0u8, 0];
        leading.extend_from_slice(&r);
        assert!(verify(&pk, &h, &leading, &s));
        // digests longer than the order are truncated to the leftmost 256 bits
        let h64 = [0xabu8; 64];
        let (r, s) = sign(&d, &h64, HashAlg::Sha512).unwrap();
        assert!(verify(&pk, &h64, &r, &s));
        assert!(verify(&pk, &h64[..32], &r, &s));
    }

    #[test]
    fn verify_u1_u2_special_values() {
        // With Q = G (d = 1): e = r makes u1 = u2, so the final addition doubles; e = n - r
        // makes u1 = -u2, so it gives the point at infinity, which must be refused.
        let gpub = public_key(&to_be(&[1, 0, 0, 0])).unwrap();
        let k = [12345, 0, 0, 0];
        let (x, _) = to_affine(&mul_base(&k)).unwrap();
        let r = reduce_once(&x, 0, &N);
        let rr = add_mod(&r, &r, &N);
        let s = from_mont_n(&nmul(&ninv(&to_mont_n(&k)), &to_mont_n(&rr)));
        assert!(verify(&gpub, &to_be(&r), &to_be(&r), &to_be(&s)));
        assert!(!verify(&gpub, &to_be(&sub_n(&N, &r)), &to_be(&r), &to_be(&s)));
    }
}

#[cfg(test)]
mod micro {
    use super::*;
    #[test]
    #[ignore]
    fn field_op_timings() {
        let mut a = to_mont(&[1, 2, 3, 4]);
        let b = to_mont(&[5, 6, 7, 8]);
        let n = 10_000_000;
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = fmul(&a, &b);
        }
        println!("fmul {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = fsqr(&a);
        }
        println!("fsqr {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = fadd(&a, &b);
        }
        println!("fadd {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = nmul(&a, &b);
        }
        println!("nmul {:.1} ns {:?}", t.elapsed().as_nanos() as f64 / n as f64, a[0]);
        let g = Jac { x: to_mont(&GX), y: to_mont(&GY), z: ONE_MONT };
        let mut p = g;
        let t = std::time::Instant::now();
        for _ in 0..100_000 {
            p = double(&p);
        }
        println!("double {:.1} ns", t.elapsed().as_nanos() as f64 / 1e5);
        let t = std::time::Instant::now();
        for _ in 0..100_000 {
            p = add(&p, &g);
        }
        println!("add {:.1} ns {:?}", t.elapsed().as_nanos() as f64 / 1e5, p.x[0]);
        let t = std::time::Instant::now();
        for _ in 0..10_000 {
            a = finv(&a);
        }
        println!("finv {:.1} ns {:?}", t.elapsed().as_nanos() as f64 / 1e4, a[0]);
    }
}

#[cfg(test)]
mod micro2 {
    use super::*;
    #[test]
    #[ignore]
    fn sign_breakdown() {
        let k = from_be(&generate_private());
        let _ = mul_base(&k);
        let n = 20_000;
        let t = std::time::Instant::now();
        let mut acc = INFINITY;
        for _ in 0..n {
            acc = mul_base(&k);
        }
        println!("mul_base {:.2} us {:?}", t.elapsed().as_nanos() as f64 / n as f64 / 1e3, acc.x[0]);
        let t = std::time::Instant::now();
        let mut a = to_mont(&k);
        for _ in 0..n {
            a = finv(&a);
        }
        println!("finv {:.2} us", t.elapsed().as_nanos() as f64 / n as f64 / 1e3);
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = ninv(&a);
        }
        println!("ninv {:.2} us", t.elapsed().as_nanos() as f64 / n as f64 / 1e3);
        let d = generate_private();
        let t = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(rfc6979_k(&d, &[1u8; 32], HashAlg::Sha256, 0));
        }
        println!("rfc6979 {:.2} us", t.elapsed().as_nanos() as f64 / n as f64 / 1e3);
        let q = mul_base(&k);
        let t = std::time::Instant::now();
        for _ in 0..2000 {
            acc = mul(&q, &k);
        }
        println!("mul {:.2} us {:?}", t.elapsed().as_nanos() as f64 / 2000.0 / 1e3, acc.x[0]);
        let t = std::time::Instant::now();
        for _ in 0..2000 {
            acc = mul2_vartime(&k, &q, &k);
        }
        println!("mul2_vartime {:.2} us {:?}", t.elapsed().as_nanos() as f64 / 2000.0 / 1e3, acc.x[0]);
    }
}
