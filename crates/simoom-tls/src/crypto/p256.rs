//! NIST P-256: ECDH, ECDSA signing (RFC 6979 nonces) and verification.
//!
//! Field and scalar arithmetic are 4x64-bit Montgomery multiplication with branch-free final
//! subtractions. Points use projective coordinates and the complete formulas of Renes,
//! Costello and Batina (2015, algorithms 4, 5 and 6 for a = -3), so no input is a special case.
//! Variable-base multiplication uses a 4-bit fixed window; base-point multiplication uses a
//! 64 x 15 table of affine multiples (61 KB, built on first use). Every table read scans all
//! entries with masks, so memory access never depends on secret scalars.

use super::sha2::HashAlg;
use std::sync::OnceLock;

type Fe = [u64; 4];

const P: Fe = [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0, 0xffff_ffff_0000_0001];
const N: Fe = [0xf3b9_cac2_fc63_2551, 0xbce6_faad_a717_9e84, 0xffff_ffff_ffff_ffff, 0xffff_ffff_0000_0000];
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
fn mont_mul(a: &Fe, b: &Fe, m: &Fe, minv: u64) -> Fe {
    let mut t = [0u64; 6];
    for &bi in b.iter() {
        let mut c = 0;
        for j in 0..4 {
            let (v, cc) = mac(t[j], a[j], bi, c);
            t[j] = v;
            c = cc;
        }
        let (v, cc) = adc(t[4], c, 0);
        t[4] = v;
        t[5] = cc;
        let q = t[0].wrapping_mul(minv);
        let (_, mut c) = mac(t[0], q, m[0], 0);
        for j in 1..4 {
            let (v, cc) = mac(t[j], q, m[j], c);
            t[j - 1] = v;
            c = cc;
        }
        let (v, cc) = adc(t[4], c, 0);
        t[3] = v;
        t[4] = t[5] + cc;
    }
    reduce_once(&[t[0], t[1], t[2], t[3]], t[4], m)
}

#[inline(always)]
fn add_mod(a: &Fe, b: &Fe, m: &Fe) -> Fe {
    let (s0, c) = adc(a[0], b[0], 0);
    let (s1, c) = adc(a[1], b[1], c);
    let (s2, c) = adc(a[2], b[2], c);
    let (s3, c) = adc(a[3], b[3], c);
    reduce_once(&[s0, s1, s2, s3], c, m)
}

#[inline(always)]
fn sub_mod(a: &Fe, b: &Fe, m: &Fe) -> Fe {
    let (d0, br) = sbb(a[0], b[0], 0);
    let (d1, br) = sbb(a[1], b[1], br);
    let (d2, br) = sbb(a[2], b[2], br);
    let (d3, br) = sbb(a[3], b[3], br);
    let mask = crate::util::ct_mask(br);
    let (r0, c) = adc(d0, m[0] & mask, 0);
    let (r1, c) = adc(d1, m[1] & mask, c);
    let (r2, c) = adc(d2, m[2] & mask, c);
    let (r3, _) = adc(d3, m[3] & mask, c);
    [r0, r1, r2, r3]
}

// ---- field mod p (Montgomery form)

/// Montgomery multiplication mod p using its shape: p = -1 mod 2^64, so the reduction
/// multiplier is the low limb itself, and q * p = q * 2^192 * p3 + q * 2^96 - q needs one
/// 64x64 multiply per step instead of four. Kept out of line: inlining it into every
/// formula would add tens of KB for a few percent.
#[inline(never)]
fn fmul(a: &Fe, b: &Fe) -> Fe {
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
    let mut top = 0u64;
    for i in 0..4 {
        let q = t[i];
        // t[i] - q = 0; add q * 2^96 and q * p3 * 2^192 at limb i
        let (v, c) = adc(t[i + 1], q << 32, 0);
        t[i + 1] = v;
        let (v, c) = adc(t[i + 2], q >> 32, c);
        t[i + 2] = v;
        let prod = q as u128 * P[3] as u128;
        let (v, c) = adc(t[i + 3], prod as u64, c);
        t[i + 3] = v;
        let (v, mut c) = adc(t[i + 4], (prod >> 64) as u64, c);
        t[i + 4] = v;
        for limb in t.iter_mut().skip(i + 5) {
            let (v, cc) = adc(*limb, 0, c);
            *limb = v;
            c = cc;
        }
        top += c;
    }
    reduce_once(&[t[4], t[5], t[6], t[7]], top, &P)
}
#[inline(always)]
fn fsqr(a: &Fe) -> Fe {
    fmul(a, a)
}
#[inline]
fn fadd(a: &Fe, b: &Fe) -> Fe {
    add_mod(a, b, &P)
}
#[inline]
fn fsub(a: &Fe, b: &Fe) -> Fe {
    sub_mod(a, b, &P)
}
fn to_mont(a: &Fe) -> Fe {
    fmul(a, &RR_P)
}
fn from_mont(a: &Fe) -> Fe {
    fmul(a, &[1, 0, 0, 0])
}

fn fsqr_n(a: &Fe, n: usize) -> Fe {
    let mut r = *a;
    for _ in 0..n {
        r = fsqr(&r);
    }
    r
}

/// a^(p-2) with a fixed addition chain (constant time).
fn finv(a: &Fe) -> Fe {
    let x2 = fmul(&fsqr(a), a);
    let x3 = fmul(&fsqr(&x2), a);
    let x6 = fmul(&fsqr_n(&x3, 3), &x3);
    let x12 = fmul(&fsqr_n(&x6, 6), &x6);
    let x15 = fmul(&fsqr_n(&x12, 3), &x3);
    let x30 = fmul(&fsqr_n(&x15, 15), &x15);
    let x32 = fmul(&fsqr_n(&x30, 2), &x2);
    // p - 2 = 2^256 - 2^224 + 2^192 + 2^96 - 3
    let mut t = fmul(&fsqr_n(&x32, 32), a); // x32 * 2^32 + 1
    t = fsqr_n(&t, 128);
    t = fmul(&t, &x32);
    t = fsqr_n(&t, 32);
    t = fmul(&t, &x32);
    t = fsqr_n(&t, 30);
    t = fmul(&t, &x30);
    t = fsqr_n(&t, 2);
    fmul(&t, a)
}

// ---- scalars mod n

fn nmul(a: &Fe, b: &Fe) -> Fe {
    mont_mul(a, b, &N, N0INV)
}

/// a^(n-2) mod n for a in Montgomery form (fixed exponent: constant time).
fn ninv(a: &Fe) -> Fe {
    let mut e = N;
    e[0] -= 2;
    let one = nmul(&[1, 0, 0, 0], &RR_N);
    let mut acc = one;
    // 4-bit fixed window over the public exponent
    let mut tbl = [one; 16];
    for i in 1..16 {
        tbl[i] = nmul(&tbl[i - 1], a);
    }
    for i in (0..64).rev() {
        for _ in 0..4 {
            acc = nmul(&acc, &acc);
        }
        let nib = ((e[i / 16] >> (4 * (i % 16))) & 15) as usize;
        acc = nmul(&acc, &tbl[nib]);
    }
    acc
}

fn is_zero(a: &Fe) -> u64 {
    let z = a[0] | a[1] | a[2] | a[3];
    // all ones if zero
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
    [
        u64::from_be_bytes(b[24..32].try_into().unwrap()),
        u64::from_be_bytes(b[16..24].try_into().unwrap()),
        u64::from_be_bytes(b[8..16].try_into().unwrap()),
        u64::from_be_bytes(b[0..8].try_into().unwrap()),
    ]
}

fn to_be(a: &Fe) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[8 * i..8 * i + 8].copy_from_slice(&a[3 - i].to_be_bytes());
    }
    o
}

// ---- points

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[derive(Clone, Copy)]
struct Affine {
    x: Fe,
    y: Fe,
}

const IDENTITY: Point = Point { x: [0; 4], y: ONE_MONT, z: [0; 4] };

/// Complete addition (RCB algorithm 4, a = -3).
fn add(p: &Point, q: &Point) -> Point {
    let b = &B_MONT;
    let mut t0 = fmul(&p.x, &q.x);
    let mut t1 = fmul(&p.y, &q.y);
    let mut t2 = fmul(&p.z, &q.z);
    let mut t3 = fadd(&p.x, &p.y);
    let mut t4 = fadd(&q.x, &q.y);
    t3 = fmul(&t3, &t4);
    t4 = fadd(&t0, &t1);
    t3 = fsub(&t3, &t4);
    t4 = fadd(&p.y, &p.z);
    let mut x3 = fadd(&q.y, &q.z);
    t4 = fmul(&t4, &x3);
    x3 = fadd(&t1, &t2);
    t4 = fsub(&t4, &x3);
    x3 = fadd(&p.x, &p.z);
    let mut y3 = fadd(&q.x, &q.z);
    x3 = fmul(&x3, &y3);
    y3 = fadd(&t0, &t2);
    y3 = fsub(&x3, &y3);
    let mut z3 = fmul(b, &t2);
    x3 = fsub(&y3, &z3);
    z3 = fadd(&x3, &x3);
    x3 = fadd(&x3, &z3);
    z3 = fsub(&t1, &x3);
    x3 = fadd(&t1, &x3);
    y3 = fmul(b, &y3);
    t1 = fadd(&t2, &t2);
    t2 = fadd(&t1, &t2);
    y3 = fsub(&y3, &t2);
    y3 = fsub(&y3, &t0);
    t1 = fadd(&y3, &y3);
    y3 = fadd(&t1, &y3);
    t1 = fadd(&t0, &t0);
    t0 = fadd(&t1, &t0);
    t0 = fsub(&t0, &t2);
    t1 = fmul(&t4, &y3);
    t2 = fmul(&t0, &y3);
    y3 = fmul(&x3, &z3);
    y3 = fadd(&y3, &t2);
    x3 = fmul(&t3, &x3);
    x3 = fsub(&x3, &t1);
    z3 = fmul(&t4, &z3);
    t1 = fmul(&t3, &t0);
    z3 = fadd(&z3, &t1);
    Point { x: x3, y: y3, z: z3 }
}

/// Mixed addition with an affine point (RCB algorithm 5); `q` must not be the identity.
fn add_affine(p: &Point, q: &Affine) -> Point {
    let b = &B_MONT;
    let mut t0 = fmul(&p.x, &q.x);
    let mut t1 = fmul(&p.y, &q.y);
    let mut t3 = fadd(&q.x, &q.y);
    let mut t4 = fadd(&p.x, &p.y);
    t3 = fmul(&t3, &t4);
    t4 = fadd(&t0, &t1);
    t3 = fsub(&t3, &t4);
    t4 = fmul(&q.y, &p.z);
    t4 = fadd(&t4, &p.y);
    let mut y3 = fmul(&q.x, &p.z);
    y3 = fadd(&y3, &p.x);
    let mut z3 = fmul(b, &p.z);
    let mut x3 = fsub(&y3, &z3);
    z3 = fadd(&x3, &x3);
    x3 = fadd(&x3, &z3);
    z3 = fsub(&t1, &x3);
    x3 = fadd(&t1, &x3);
    y3 = fmul(b, &y3);
    t1 = fadd(&p.z, &p.z);
    let mut t2 = fadd(&t1, &p.z);
    y3 = fsub(&y3, &t2);
    y3 = fsub(&y3, &t0);
    t1 = fadd(&y3, &y3);
    y3 = fadd(&t1, &y3);
    t1 = fadd(&t0, &t0);
    t0 = fadd(&t1, &t0);
    t0 = fsub(&t0, &t2);
    t1 = fmul(&t4, &y3);
    t2 = fmul(&t0, &y3);
    y3 = fmul(&x3, &z3);
    y3 = fadd(&y3, &t2);
    x3 = fmul(&x3, &t3);
    x3 = fsub(&x3, &t1);
    z3 = fmul(&t4, &z3);
    t1 = fmul(&t3, &t0);
    z3 = fadd(&z3, &t1);
    Point { x: x3, y: y3, z: z3 }
}

/// Complete doubling (RCB algorithm 6, a = -3).
fn double(p: &Point) -> Point {
    let b = &B_MONT;
    let mut t0 = fsqr(&p.x);
    let t1 = fsqr(&p.y);
    let mut t2 = fsqr(&p.z);
    let mut t3 = fmul(&p.x, &p.y);
    t3 = fadd(&t3, &t3);
    let mut z3 = fmul(&p.x, &p.z);
    z3 = fadd(&z3, &z3);
    let mut y3 = fmul(b, &t2);
    y3 = fsub(&y3, &z3);
    let mut x3 = fadd(&y3, &y3);
    y3 = fadd(&x3, &y3);
    x3 = fsub(&t1, &y3);
    y3 = fadd(&t1, &y3);
    y3 = fmul(&x3, &y3);
    x3 = fmul(&x3, &t3);
    t3 = fadd(&t2, &t2);
    t2 = fadd(&t2, &t3);
    z3 = fmul(b, &z3);
    z3 = fsub(&z3, &t2);
    z3 = fsub(&z3, &t0);
    t3 = fadd(&z3, &z3);
    z3 = fadd(&z3, &t3);
    t3 = fadd(&t0, &t0);
    t0 = fadd(&t3, &t0);
    t0 = fsub(&t0, &t2);
    t0 = fmul(&t0, &z3);
    y3 = fadd(&y3, &t0);
    t0 = fmul(&p.y, &p.z);
    t0 = fadd(&t0, &t0);
    z3 = fmul(&t0, &z3);
    x3 = fsub(&x3, &z3);
    z3 = fmul(&t0, &t1);
    z3 = fadd(&z3, &z3);
    z3 = fadd(&z3, &z3);
    Point { x: x3, y: y3, z: z3 }
}

fn sel_point(mask: u64, a: &Point, b: &Point) -> Point {
    Point { x: sel(mask, &a.x, &b.x), y: sel(mask, &a.y, &b.y), z: sel(mask, &a.z, &b.z) }
}

/// All-ones if a == b (small public-size integers).
#[inline(always)]
fn eq_mask(a: u64, b: u64) -> u64 {
    crate::util::ct_eq_mask(a, b)
}

/// Nibble `i` (0 = least significant) of a scalar.
#[inline(always)]
fn nibble(k: &Fe, i: usize) -> u64 {
    (k[i / 16] >> (4 * (i % 16))) & 15
}

/// k * P, 4-bit fixed window (k is any 256-bit integer).
fn mul(p: &Point, k: &Fe) -> Point {
    let mut tbl = [IDENTITY; 16];
    tbl[1] = *p;
    for i in 2..16 {
        tbl[i] = if i % 2 == 0 { double(&tbl[i / 2]) } else { add(&tbl[i - 1], p) };
    }
    let lookup = |n: u64| -> Point {
        let mut r = IDENTITY;
        for (j, t) in tbl.iter().enumerate() {
            r = sel_point(eq_mask(n, j as u64), t, &r);
        }
        r
    };
    let mut r = lookup(nibble(k, 63));
    for i in (0..63).rev() {
        r = double(&double(&double(&double(&r))));
        r = add(&r, &lookup(nibble(k, i)));
    }
    r
}

/// The base-point table: entry [i][j-1] = j * 16^i * G, affine, Montgomery form.
fn base_table() -> &'static [[Affine; 15]] {
    static T: OnceLock<Vec<[Affine; 15]>> = OnceLock::new();
    T.get_or_init(|| {
        let g = Point { x: to_mont(&GX), y: to_mont(&GY), z: ONE_MONT };
        let mut proj = Vec::with_capacity(64 * 15);
        let mut base = g;
        for _ in 0..64 {
            let mut acc = base;
            proj.push(acc);
            for _ in 2..=15 {
                acc = add(&acc, &base);
                proj.push(acc);
            }
            base = double(&double(&double(&double(&base))));
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
            out[i] = Affine { x: fmul(&proj[i].x, &zi), y: fmul(&proj[i].y, &zi) };
        }
        out.chunks(15).map(|c| c.try_into().unwrap()).collect()
    })
}

/// k * G with the precomputed table.
fn mul_base(k: &Fe) -> Point {
    let tbl = base_table();
    let mut r = IDENTITY;
    for (i, row) in tbl.iter().enumerate() {
        let n = nibble(k, i);
        let mut a = row[0];
        for (j, e) in row.iter().enumerate().skip(1) {
            let m = eq_mask(n, j as u64 + 1);
            a = Affine { x: sel(m, &e.x, &a.x), y: sel(m, &e.y, &a.y) };
        }
        let s = add_affine(&r, &a);
        r = sel_point(eq_mask(n, 0), &r, &s);
    }
    r
}

/// Affine (x, y) as plain integers; None for the identity.
fn to_affine(p: &Point) -> Option<(Fe, Fe)> {
    if is_zero(&p.z) != 0 {
        return None;
    }
    let zi = finv(&p.z);
    Some((from_mont(&fmul(&p.x, &zi)), from_mont(&fmul(&p.y, &zi))))
}

fn encode(x: &Fe, y: &Fe) -> [u8; 65] {
    let mut o = [0u8; 65];
    o[0] = 4;
    o[1..33].copy_from_slice(&to_be(x));
    o[33..].copy_from_slice(&to_be(y));
    o
}

/// Decodes and validates an uncompressed point (0x04 || X || Y).
fn decode(data: &[u8]) -> Option<Point> {
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
    let three_x = fadd(&fadd(&xm, &xm), &xm);
    let rhs = fadd(&fsub(&x3, &three_x), &B_MONT);
    if lhs != rhs {
        return None;
    }
    Some(Point { x: xm, y: ym, z: ONE_MONT })
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

/// ECDSA signature over a digest; returns (r, s) as 32-byte big-endian values.
pub fn sign(private: &[u8], digest: &[u8], hash: HashAlg) -> Option<([u8; 32], [u8; 32])> {
    let d_bytes: [u8; 32] = private.try_into().ok()?;
    let d = from_be(&d_bytes);
    if !scalar_valid(&d) {
        return None;
    }
    let e = hash_to_scalar(digest);
    let tm = |a: &Fe| nmul(a, &RR_N);
    let fm = |a: &Fe| nmul(a, &[1, 0, 0, 0]);
    for extra in 0.. {
        let k = rfc6979_k(&d_bytes, digest, hash, extra);
        let Some((x, _)) = to_affine(&mul_base(&k)) else { continue };
        let r = reduce_once(&x, 0, &N);
        if is_zero(&r) != 0 {
            continue;
        }
        let kinv = ninv(&tm(&k));
        let rd = nmul(&tm(&r), &tm(&d));
        let s = fm(&nmul(&kinv, &add_mod(&tm(&e), &rd, &N)));
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
    let tm = |a: &Fe| nmul(a, &RR_N);
    let fm = |a: &Fe| nmul(a, &[1, 0, 0, 0]);
    let e = hash_to_scalar(digest);
    let w = ninv(&tm(&s));
    let u1 = fm(&nmul(&tm(&e), &w));
    let u2 = fm(&nmul(&tm(&r), &w));
    let pt = add(&mul_base(&u1), &mul(&q, &u2));
    match to_affine(&pt) {
        Some((x, _)) => reduce_once(&x, 0, &N) == r,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha2::Sha256;
    use crate::util::{hex, unhex};

    fn mont_consts_are_right() -> bool {
        // R^2 mod p and b/1 in Montgomery form, recomputed slowly.
        let mut r = [1u64, 0, 0, 0];
        for _ in 0..512 {
            r = add_mod(&r, &r, &P);
        }
        let b = from_be(&unhex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"));
        let mut rn = [1u64, 0, 0, 0];
        for _ in 0..512 {
            rn = add_mod(&rn, &rn, &N);
        }
        r == RR_P && rn == RR_N && to_mont(&b) == B_MONT && to_mont(&[1, 0, 0, 0]) == ONE_MONT
    }

    #[test]
    fn constants() {
        assert!(mont_consts_are_right());
        // -n^-1 mod 2^64
        assert_eq!(N[0].wrapping_mul(N0INV).wrapping_neg(), 1);
        let a = to_mont(&[5, 6, 7, 8]);
        assert_eq!(from_mont(&fmul(&a, &finv(&a))), [1, 0, 0, 0]);
        let am = nmul(&[9, 8, 7, 6], &RR_N);
        assert_eq!(nmul(&nmul(&am, &ninv(&am)), &[1, 0, 0, 0]), [1, 0, 0, 0]);
    }

    #[test]
    fn formulas_agree() {
        let g = Point { x: to_mont(&GX), y: to_mont(&GY), z: ONE_MONT };
        let p2 = double(&g);
        let p2b = add(&g, &g);
        assert_eq!(to_affine(&p2), to_affine(&p2b));
        let p3 = add_affine(&p2, &Affine { x: g.x, y: g.y });
        assert_eq!(to_affine(&p3), to_affine(&add(&p2, &g)));
        // identity cases
        assert_eq!(to_affine(&add(&IDENTITY, &g)), to_affine(&g));
        assert!(to_affine(&double(&IDENTITY)).is_none());
        assert_eq!(to_affine(&add_affine(&IDENTITY, &Affine { x: g.x, y: g.y })), to_affine(&g));
        // n*G = O, (n-1)*G = -G
        assert!(to_affine(&mul(&g, &N)).is_none());
        let mut n1 = N;
        n1[0] -= 1;
        let (x, y) = to_affine(&mul_base(&n1)).unwrap();
        assert_eq!(x, GX);
        assert_eq!(fsub(&[0; 4], &to_mont(&GY)), to_mont(&y));
        // base table agrees with the window method
        let k = from_be(&unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"));
        assert_eq!(to_affine(&mul_base(&k)), to_affine(&mul(&g, &k)));
        assert_eq!(to_affine(&mul_base(&[0; 4])), None);
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
        let peer = unhex("04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");
        assert_eq!(hex(&ecdh(&d, &peer).unwrap()), "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");
        assert!(public_key(&[0u8; 32]).is_none());
        assert!(public_key(&to_be(&N)).is_none());
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
        assert!(!verify(&pk, &h, &to_be(&N), &s));
        let mut leading = vec![0u8, 0];
        leading.extend_from_slice(&r);
        assert!(verify(&pk, &h, &leading, &s));
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
            a = fadd(&a, &b);
        }
        println!("fadd {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = fsub(&a, &b);
        }
        println!("fsub {:.1} ns {:?}", t.elapsed().as_nanos() as f64 / n as f64, a[0]);
        let g = Point { x: to_mont(&GX), y: to_mont(&GY), z: ONE_MONT };
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
    }
}
