//! Multi-precision arithmetic on little-endian `u64` limb slices: Montgomery
//! multiplication (CIOS), modular add/sub with branch-free final reduction,
//! modular exponentiation. Used by RSA (variable size) and the NIST curves
//! (fixed size).

#[inline(always)]
pub fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
pub fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub(b as u128 + borrow as u128);
    (t as u64, ((t >> 64) as u64) & 1)
}

#[inline(always)]
pub fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = acc as u128 + (a as u128) * (b as u128) + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// -m0^{-1} mod 2^64 (m0 odd).
pub fn mont_m0inv(m0: u64) -> u64 {
    let mut inv: u64 = 1;
    for _ in 0..7 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// r = a - b, returns borrow.
pub fn sub_into(r: &mut [u64], a: &[u64], b: &[u64]) -> u64 {
    let mut borrow = 0;
    for i in 0..r.len() {
        let (v, bo) = sbb(a[i], b[i], borrow);
        r[i] = v;
        borrow = bo;
    }
    borrow
}

/// Constant-time select: r = if flag {a} else {b}; flag must be 0 or 1.
pub fn select(r: &mut [u64], flag: u64, a: &[u64], b: &[u64]) {
    let mask = crate::util::ct_mask(flag);
    for i in 0..r.len() {
        r[i] = (a[i] & mask) | (b[i] & !mask);
    }
}

/// r = (a + b) mod m, with a, b < m.
pub fn mod_add(r: &mut [u64], a: &[u64], b: &[u64], m: &[u64]) {
    let n = m.len();
    let mut carry = 0;
    for i in 0..n {
        let (v, c) = adc(a[i], b[i], carry);
        r[i] = v;
        carry = c;
    }
    let mut borrow = 0;
    for i in 0..n {
        let (_, bo) = sbb(r[i], m[i], borrow);
        borrow = bo;
    }
    // subtract m if the sum overflowed or is >= m
    let mask = crate::util::ct_mask(carry | (borrow ^ 1));
    let mut borrow = 0;
    for i in 0..n {
        let (v, bo) = sbb(r[i], m[i] & mask, borrow);
        r[i] = v;
        borrow = bo;
    }
}

/// r = (a - b) mod m, with a, b < m.
pub fn mod_sub(r: &mut [u64], a: &[u64], b: &[u64], m: &[u64]) {
    let n = m.len();
    let borrow = sub_into(r, a, b);
    let mask = crate::util::ct_mask(borrow);
    let mut carry = 0;
    for i in 0..n {
        let (v, c) = adc(r[i], m[i] & mask, carry);
        r[i] = v;
        carry = c;
    }
}

/// Montgomery product r = a * b * R^{-1} mod m (CIOS). `t` is scratch of length n+2.
pub fn mont_mul(r: &mut [u64], a: &[u64], b: &[u64], m: &[u64], m0inv: u64, t: &mut [u64]) {
    let n = m.len();
    if simoom_sys::arch::bigint_mont_mul(t, a, b, m, m0inv) {
        // the MULX kernel leaves t < 2m in t[..n] and t[n]: subtract m once if t >= m
        let hi = t[n];
        let mut borrow = 0;
        for i in 0..n {
            let (v, bo) = sbb(t[i], m[i], borrow);
            r[i] = v;
            borrow = bo;
        }
        let mask = crate::util::ct_mask((hi != 0) as u64 | (borrow ^ 1));
        for i in 0..n {
            r[i] = (r[i] & mask) | (t[i] & !mask);
        }
        return;
    }
    generic_mont_mul(r, a, b, m, m0inv, t)
}

/// The portable CIOS loop for any limb count.
fn generic_mont_mul(r: &mut [u64], a: &[u64], b: &[u64], m: &[u64], m0inv: u64, t: &mut [u64]) {
    let n = m.len();
    for x in t.iter_mut() {
        *x = 0;
    }
    for i in 0..n {
        let mut c = 0;
        for j in 0..n {
            let (v, cc) = mac(t[j], a[j], b[i], c);
            t[j] = v;
            c = cc;
        }
        let (v, cc) = adc(t[n], c, 0);
        t[n] = v;
        t[n + 1] = cc;
        let q = t[0].wrapping_mul(m0inv);
        let (_, mut c) = mac(t[0], q, m[0], 0);
        for j in 1..n {
            let (v, cc) = mac(t[j], q, m[j], c);
            t[j - 1] = v;
            c = cc;
        }
        let (v, cc) = adc(t[n], c, 0);
        t[n - 1] = v;
        t[n] = t[n + 1] + cc;
    }
    // final conditional subtraction
    let hi = t[n];
    let mut borrow = 0;
    for i in 0..n {
        let (v, bo) = sbb(t[i], m[i], borrow);
        r[i] = v;
        borrow = bo;
    }
    let use_d = (hi != 0) as u64 | (borrow ^ 1);
    let mask = crate::util::ct_mask(use_d);
    for i in 0..n {
        r[i] = (r[i] & mask) | (t[i] & !mask);
    }
}

/// R^2 mod m where R = 2^(64 n).
pub fn mont_r2(m: &[u64]) -> Vec<u64> {
    let n = m.len();
    let mut x = vec![0u64; n];
    x[0] = 1;
    // if m == 1 everything is 0; not a concern for our moduli
    let mut tmp = vec![0u64; n];
    for _ in 0..(128 * n) {
        mod_add(&mut tmp, &x, &x, m);
        x.copy_from_slice(&tmp);
    }
    x
}

/// Big-endian bytes to limbs (exactly `n` limbs, value must fit).
pub fn from_be_bytes(bytes: &[u8], n: usize) -> Option<Vec<u64>> {
    let bytes = {
        let mut i = 0;
        while i < bytes.len() && bytes[i] == 0 {
            i += 1;
        }
        &bytes[i..]
    };
    if bytes.len() > 8 * n {
        return None;
    }
    let mut out = vec![0u64; n];
    for (i, b) in bytes.iter().rev().enumerate() {
        out[i / 8] |= (*b as u64) << (8 * (i % 8));
    }
    Some(out)
}

/// Limbs to big-endian bytes, left-padded to `len` bytes (truncating high zero limbs).
pub fn to_be_bytes(limbs: &[u64], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..len {
        let limb = i / 8;
        if limb < limbs.len() {
            out[len - 1 - i] = (limbs[limb] >> (8 * (i % 8))) as u8;
        }
    }
    out
}

/// a < b (not constant time; for public values).
pub fn lt(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

pub fn is_zero(a: &[u64]) -> bool {
    a.iter().fold(0u64, |acc, x| acc | x) == 0
}

pub fn bit_len(a: &[u64]) -> usize {
    for i in (0..a.len()).rev() {
        if a[i] != 0 {
            return 64 * i + 64 - a[i].leading_zeros() as usize;
        }
    }
    0
}

/// Montgomery context for an odd modulus of arbitrary size.
#[derive(Clone)]
pub struct MontCtx {
    pub m: Vec<u64>,
    pub m0inv: u64,
    pub r2: Vec<u64>,
}

impl MontCtx {
    pub fn new(m: Vec<u64>) -> MontCtx {
        assert!(m[0] & 1 == 1, "modulus must be odd");
        let m0inv = mont_m0inv(m[0]);
        let r2 = mont_r2(&m);
        MontCtx { m, m0inv, r2 }
    }
    pub fn n(&self) -> usize {
        self.m.len()
    }
    pub fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = self.n();
        let mut r = vec![0u64; n];
        let mut t = vec![0u64; n + 2];
        mont_mul(&mut r, a, b, &self.m, self.m0inv, &mut t);
        r
    }
    pub fn to_mont(&self, a: &[u64]) -> Vec<u64> {
        self.mul(a, &self.r2)
    }
    pub fn from_mont(&self, a: &[u64]) -> Vec<u64> {
        let mut one = vec![0u64; self.n()];
        one[0] = 1;
        self.mul(a, &one)
    }
    /// base^exp mod m. `base` must be < m (plain representation). When
    /// `secret_exp` is set, every bit performs a multiplication and selects the
    /// result branch-free (memory access pattern independent of the exponent).
    /// x mod m for a little-endian integer of any length, in constant time: Horner's rule over
    /// chunks of n limbs, acc = acc * R + chunk, with Montgomery multiplications.
    pub fn reduce(&self, x: &[u64]) -> Vec<u64> {
        let n = self.n();
        let mut t = vec![0u64; n + 2];
        let mut one = vec![0u64; n];
        one[0] = 1;
        let mut acc = vec![0u64; n];
        let (mut a, mut c) = (vec![0u64; n], vec![0u64; n]);
        let chunks = x.len().div_ceil(n);
        for i in (0..chunks).rev() {
            let mut chunk = vec![0u64; n];
            let hi = (i * n + n).min(x.len());
            chunk[..hi - i * n].copy_from_slice(&x[i * n..hi]);
            // acc * R mod m
            mont_mul(&mut a, &acc, &self.r2, &self.m, self.m0inv, &mut t);
            // chunk mod m = mont(mont(chunk, R^2), 1)
            mont_mul(&mut c, &chunk, &self.r2, &self.m, self.m0inv, &mut t);
            mont_mul(&mut chunk, &c, &one, &self.m, self.m0inv, &mut t);
            mod_add(&mut acc, &a, &chunk, &self.m);
        }
        acc
    }

    pub fn pow(&self, base: &[u64], exp: &[u64], secret_exp: bool) -> Vec<u64> {
        let n = self.n();
        let mut t = vec![0u64; n + 2];
        let mut b = vec![0u64; n];
        mont_mul(&mut b, base, &self.r2, &self.m, self.m0inv, &mut t);
        let mut one = vec![0u64; n];
        one[0] = 1;
        let mut acc = vec![0u64; n];
        mont_mul(&mut acc, &one, &self.r2, &self.m, self.m0inv, &mut t);
        let mut tmp = vec![0u64; n];
        if !secret_exp {
            // public exponent: plain square-and-multiply (e = 65537 needs 16 squarings)
            for i in (0..bit_len(exp)).rev() {
                mont_mul(&mut tmp, &acc, &acc, &self.m, self.m0inv, &mut t);
                if (exp[i / 64] >> (i % 64)) & 1 == 1 {
                    mont_mul(&mut acc, &tmp, &b, &self.m, self.m0inv, &mut t);
                } else {
                    acc.copy_from_slice(&tmp);
                }
            }
        } else {
            // secret exponent: 4-bit fixed window over the full width, every table entry read
            // with masks (memory access and operation sequence independent of the exponent)
            let mut table = vec![0u64; 16 * n];
            table[..n].copy_from_slice(&acc);
            table[n..2 * n].copy_from_slice(&b);
            for i in 2..16 {
                let (done, rest) = table.split_at_mut(i * n);
                mont_mul(&mut rest[..n], &done[(i - 1) * n..i * n], &b, &self.m, self.m0inv, &mut t);
            }
            let mut entry = vec![0u64; n];
            for w in (0..16 * exp.len()).rev() {
                for _ in 0..4 {
                    mont_mul(&mut tmp, &acc, &acc, &self.m, self.m0inv, &mut t);
                    acc.copy_from_slice(&tmp);
                }
                let nib = (exp[w / 16] >> (4 * (w % 16))) & 15;
                entry.fill(0);
                for (j, e) in table.chunks_exact(n).enumerate() {
                    let d = nib ^ j as u64;
                    let mask = crate::util::ct_eq_mask(d, 0);
                    for (x, y) in entry.iter_mut().zip(e) {
                        *x |= y & mask;
                    }
                }
                mont_mul(&mut tmp, &acc, &entry, &self.m, self.m0inv, &mut t);
                acc.copy_from_slice(&tmp);
            }
        }
        mont_mul(&mut tmp, &acc, &one, &self.m, self.m0inv, &mut t);
        tmp
    }
}

/// Reduce an arbitrary-length big-endian integer modulo m (schoolbook bitwise
/// shift-subtract; used only for key-parsing sanity checks and CRT-free paths).
pub fn reduce_be(bytes: &[u8], m: &[u64]) -> Vec<u64> {
    let n = m.len();
    let mut r = vec![0u64; n];
    let mut tmp = vec![0u64; n];
    for byte in bytes {
        for bit in (0..8).rev() {
            // r = 2r + bit mod m
            mod_add(&mut tmp, &r, &r, m);
            r.copy_from_slice(&tmp);
            if (byte >> bit) & 1 == 1 {
                let mut one = vec![0u64; n];
                one[0] = 1;
                mod_add(&mut tmp, &r, &one, m);
                r.copy_from_slice(&tmp);
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mont_mul_kernel_matches_portable() {
        // the MULX kernel (when the CPU has it) against the generic CIOS loop, for limb counts
        // the kernel takes (multiples of 4) and moduli with high and low top limbs
        let mut seed = 0x6a09_e667_f3bc_c908u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for n in [4usize, 8, 12, 16, 32] {
            for top in [u64::MAX, 1u64 << 63, 0x1234_5678] {
                let mut m: Vec<u64> = (0..n).map(|_| next()).collect();
                m[0] |= 1;
                m[n - 1] = top | 1;
                let m0inv = mont_m0inv(m[0]);
                let below = |x: u64| if x >= top { top >> 1 } else { x };
                for _ in 0..50 {
                    let mut a: Vec<u64> = (0..n).map(|_| next()).collect();
                    let mut b: Vec<u64> = (0..n).map(|_| next()).collect();
                    a[n - 1] = below(a[n - 1]);
                    b[n - 1] = below(b[n - 1]);
                    let mut r = vec![0u64; n];
                    let mut t = vec![0u64; n + 2];
                    mont_mul(&mut r, &a, &b, &m, m0inv, &mut t);
                    // portable reference: the generic loop with a size the kernel refuses
                    let mut r2 = vec![0u64; n];
                    let mut t2 = vec![0u64; n + 2];
                    generic_mont_mul(&mut r2, &a, &b, &m, m0inv, &mut t2);
                    assert_eq!(r, r2, "n = {n}");
                }
                // m - 1 squared
                let mut mm1 = m.clone();
                mm1[0] -= 1;
                let (mut r, mut r2) = (vec![0u64; n], vec![0u64; n]);
                mont_mul(&mut r, &mm1, &mm1, &m, m0inv, &mut vec![0u64; n + 2]);
                generic_mont_mul(&mut r2, &mm1, &mm1, &m, m0inv, &mut vec![0u64; n + 2]);
                assert_eq!(r, r2);
            }
        }
    }

    #[test]
    fn small_modexp() {
        // 4^13 mod 497 = 445
        let ctx = MontCtx::new(vec![497]);
        assert_eq!(ctx.pow(&[4], &[13], false), vec![445]);
        assert_eq!(ctx.pow(&[4], &[13], true), vec![445]);
        // multi-limb: (2^64+1) modulus? use m = 2^127 - 1 (prime): 3^(m-1) = 1
        let m = vec![u64::MAX, (1u64 << 63) - 1];
        let ctx = MontCtx::new(m.clone());
        let mut e = m.clone();
        e[0] -= 1;
        assert_eq!(ctx.pow(&[3, 0], &e, false), vec![1, 0]);
        assert_eq!(reduce_be(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &m), vec![2, 0]);
    }
}
