//! Arithmetic in GF(2^255 - 19) with five 51-bit limbs, shared by X25519 and Ed25519.
//! Branch-free throughout; inversion is safegcd (`modinv`).

// Without Ed25519, X25519 uses only part of this module.
#![cfg_attr(not(feature = "ed25519"), allow(dead_code))]

pub(crate) const MASK: u64 = (1 << 51) - 1;

/// p = 2^255 - 19, for the inversion.
pub(crate) const P_INV: super::modinv::Modulus = super::modinv::Modulus::new([0xffff_ffff_ffff_ffed, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff]);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe(pub [u64; 5]);

#[inline(always)]
fn load8(b: &[u8], i: usize) -> u64 {
    let mut x = [0u8; 8];
    let end = (i + 8).min(b.len());
    x[..end - i].copy_from_slice(&b[i..end]);
    u64::from_le_bytes(x)
}

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    pub fn from_u64(v: u64) -> Fe {
        Fe([v & MASK, v >> 51, 0, 0, 0])
    }

    /// 32 little-endian bytes, ignoring the top bit.
    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        Fe([
            load8(b, 0) & MASK,
            (load8(b, 6) >> 3) & MASK,
            (load8(b, 12) >> 6) & MASK,
            (load8(b, 19) >> 1) & MASK,
            (load8(b, 24) >> 12) & MASK,
        ])
    }

    #[inline(always)]
    fn carry(mut h: [u64; 5]) -> Fe {
        let mut c = h[0] >> 51;
        h[0] &= MASK;
        h[1] += c;
        c = h[1] >> 51;
        h[1] &= MASK;
        h[2] += c;
        c = h[2] >> 51;
        h[2] &= MASK;
        h[3] += c;
        c = h[3] >> 51;
        h[3] &= MASK;
        h[4] += c;
        c = h[4] >> 51;
        h[4] &= MASK;
        h[0] += c * 19;
        c = h[0] >> 51;
        h[0] &= MASK;
        h[1] += c;
        Fe(h)
    }

    /// Canonical encoding (fully reduced).
    #[inline(never)]
    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = Fe::carry(self.0).0;
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        h[4] &= MASK;
        let v = [h[0] | (h[1] << 51), (h[1] >> 13) | (h[2] << 38), (h[2] >> 26) | (h[3] << 25), (h[3] >> 39) | (h[4] << 12)];
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[8 * i..8 * i + 8].copy_from_slice(&v[i].to_le_bytes());
        }
        out
    }

    #[inline(never)]
    pub fn add(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        Fe::carry([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    #[inline(never)]
    pub fn sub(self, o: Fe) -> Fe {
        // + 4p keeps every limb positive (inputs are carried: limbs < 2^52)
        const P4: [u64; 5] = [0x1f_ffff_ffff_ffb4, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc];
        let a = self.0;
        let b = o.0;
        Fe::carry([a[0] + P4[0] - b[0], a[1] + P4[1] - b[1], a[2] + P4[2] - b[2], a[3] + P4[3] - b[3], a[4] + P4[4] - b[4]])
    }

    /// Addition without carrying. Inputs with limbs below 2^53 give limbs below 2^54, which
    /// [`Fe::mul`] and [`Fe::square`] accept (they take limbs up to 2^56).
    #[inline(always)]
    pub fn add_nc(self, o: Fe) -> Fe {
        let (a, b) = (self.0, o.0);
        Fe([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    /// Subtraction without carrying, adding 4p so every limb stays positive: `o` must have
    /// limbs below 2^53 - 76 (any sum of two carried values does); the result has limbs below
    /// `self`'s bound + 2^53.
    #[inline(always)]
    pub fn sub_nc(self, o: Fe) -> Fe {
        const P4: [u64; 5] = [0x1f_ffff_ffff_ffb4, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc];
        let (a, b) = (self.0, o.0);
        Fe([a[0] + P4[0] - b[0], a[1] + P4[1] - b[1], a[2] + P4[2] - b[2], a[3] + P4[3] - b[3], a[4] + P4[4] - b[4]])
    }

    pub fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    #[inline(always)]
    fn reduce_wide(t: [u128; 5]) -> Fe {
        let mut r = [0u64; 5];
        let mut c = t[0] >> 51;
        r[0] = t[0] as u64 & MASK;
        let t1 = t[1] + c;
        c = t1 >> 51;
        r[1] = t1 as u64 & MASK;
        let t2 = t[2] + c;
        c = t2 >> 51;
        r[2] = t2 as u64 & MASK;
        let t3 = t[3] + c;
        c = t3 >> 51;
        r[3] = t3 as u64 & MASK;
        let t4 = t[4] + c;
        c = t4 >> 51;
        r[4] = t4 as u64 & MASK;
        r[0] += c as u64 * 19;
        r[1] += r[0] >> 51;
        r[0] &= MASK;
        Fe(r)
    }

    /// Out of line (size); the X25519 ladder uses [`Fe::mul_inline`].
    #[inline(never)]
    pub fn mul(self, o: Fe) -> Fe {
        self.mul_inline(o)
    }

    #[inline(never)]
    pub fn square(self) -> Fe {
        self.square_inline()
    }

    #[inline(always)]
    pub fn mul_inline(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        let m = |x: u64, y: u64| x as u128 * y as u128;
        let (b1, b2, b3, b4) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
        Fe::reduce_wide([
            m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1),
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2),
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3),
            m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4),
            m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
        ])
    }

    #[inline(always)]
    pub fn square_inline(self) -> Fe {
        let a = self.0;
        let m = |x: u64, y: u64| x as u128 * y as u128;
        let (d0, d1, d2) = (2 * a[0], 2 * a[1], 2 * a[2]);
        let (a3_19, a4_19) = (19 * a[3], 19 * a[4]);
        Fe::reduce_wide([
            m(a[0], a[0]) + m(d1, a4_19) + m(d2, a3_19),
            m(d0, a[1]) + m(d2, a4_19) + m(a[3], a3_19),
            m(d0, a[2]) + m(a[1], a[1]) + m(2 * a[3], a4_19),
            m(d0, a[3]) + m(d1, a[2]) + m(a[4], a4_19),
            m(d0, a[4]) + m(d1, a[3]) + m(a[2], a[2]),
        ])
    }

    pub fn pow2k(self, k: u32) -> Fe {
        let mut r = self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    pub fn mul_small(self, k: u32) -> Fe {
        let a = self.0;
        let k = k as u128;
        Fe::reduce_wide([a[0] as u128 * k, a[1] as u128 * k, a[2] as u128 * k, a[3] as u128 * k, a[4] as u128 * k])
    }

    /// self^(2^250 - 1).
    fn pow_chain(self) -> Fe {
        let z2 = self.square();
        let z9 = z2.pow2k(2).mul(self);
        let z11 = z9.mul(z2);
        let z2_5_0 = z11.square().mul(z9);
        let z2_10_0 = z2_5_0.pow2k(5).mul(z2_5_0);
        let z2_20_0 = z2_10_0.pow2k(10).mul(z2_10_0);
        let z2_40_0 = z2_20_0.pow2k(20).mul(z2_20_0);
        let z2_50_0 = z2_40_0.pow2k(10).mul(z2_10_0);
        let z2_100_0 = z2_50_0.pow2k(50).mul(z2_50_0);
        let z2_200_0 = z2_100_0.pow2k(100).mul(z2_100_0);
        z2_200_0.pow2k(50).mul(z2_50_0)
    }

    /// self^-1 (0 for 0), constant time (safegcd).
    pub fn invert(self) -> Fe {
        let b = self.to_bytes();
        let limbs: [u64; 4] = core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()));
        let inv = super::modinv::invert(&limbs, &P_INV);
        let mut out = [0u8; 32];
        for (i, l) in inv.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&l.to_le_bytes());
        }
        Fe::from_bytes(&out)
    }

    /// self^((p-5)/8).
    pub fn pow22523(self) -> Fe {
        self.pow_chain().pow2k(2).mul(self)
    }

    pub fn is_negative(self) -> u8 {
        self.to_bytes()[0] & 1
    }

    pub fn is_zero(self) -> bool {
        self.to_bytes().iter().fold(0, |a, b| a | b) == 0
    }

    pub fn ct_eq(self, o: Fe) -> bool {
        crate::util::ct_eq(&self.to_bytes(), &o.to_bytes())
    }

    /// `o` when `flag` is 1, self when 0.
    #[inline(always)]
    pub fn select(self, o: Fe, flag: u64) -> Fe {
        let m = crate::util::ct_mask(flag);
        let mut l = self.0;
        for (v, w) in l.iter_mut().zip(o.0) {
            *v ^= m & (*v ^ w);
        }
        Fe(l)
    }

    #[inline(always)]
    pub fn cswap(a: &mut Fe, b: &mut Fe, flag: u64) {
        let m = crate::util::ct_mask(flag);
        for i in 0..5 {
            let t = m & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }
}
