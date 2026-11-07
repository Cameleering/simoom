//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439). Constant time: only
//! additions, rotations and XORs on secret data; Poly1305 uses 64x64-bit multiplies.
//!
//! Bulk keystream is computed four blocks at a time in a lane-parallel layout that the compiler
//! turns into SSE2/NEON code.

#[cfg(feature = "chacha20")]
use crate::util::ct_eq;

const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn init_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let mut st = [0u32; 16];
    st[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        st[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    st[12] = counter;
    for i in 0..3 {
        st[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    st
}

/// One ChaCha20 block (RFC 8439 section 2.3).
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let st = init_state(key, counter, nonce);
    let mut w = st;
    for _ in 0..10 {
        qr(&mut w, 0, 4, 8, 12);
        qr(&mut w, 1, 5, 9, 13);
        qr(&mut w, 2, 6, 10, 14);
        qr(&mut w, 3, 7, 11, 15);
        qr(&mut w, 0, 5, 10, 15);
        qr(&mut w, 1, 6, 11, 12);
        qr(&mut w, 2, 7, 8, 13);
        qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&w[i].wrapping_add(st[i]).to_le_bytes());
    }
    out
}

#[cfg(feature = "chacha20")]
type V = [u32; 4];

#[cfg(feature = "chacha20")]
#[inline(always)]
fn vadd(a: V, b: V) -> V {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3])]
}

#[cfg(feature = "chacha20")]
#[inline(always)]
fn vxorrot(a: V, b: V, r: u32) -> V {
    [(a[0] ^ b[0]).rotate_left(r), (a[1] ^ b[1]).rotate_left(r), (a[2] ^ b[2]).rotate_left(r), (a[3] ^ b[3]).rotate_left(r)]
}

#[cfg(feature = "chacha20")]
#[inline(always)]
fn vqr(s: &mut [V; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = vadd(s[a], s[b]);
    s[d] = vxorrot(s[d], s[a], 16);
    s[c] = vadd(s[c], s[d]);
    s[b] = vxorrot(s[b], s[c], 12);
    s[a] = vadd(s[a], s[b]);
    s[d] = vxorrot(s[d], s[a], 8);
    s[c] = vadd(s[c], s[d]);
    s[b] = vxorrot(s[b], s[c], 7);
}

#[cfg(feature = "chacha20")]
/// Four consecutive keystream blocks starting at `st[12]`.
fn blocks4(st: &[u32; 16], out: &mut [u8; 256]) {
    let mut x: [V; 16] = core::array::from_fn(|i| [st[i]; 4]);
    for (l, c) in x[12].iter_mut().enumerate() {
        *c = c.wrapping_add(l as u32);
    }
    let init = x;
    for _ in 0..10 {
        vqr(&mut x, 0, 4, 8, 12);
        vqr(&mut x, 1, 5, 9, 13);
        vqr(&mut x, 2, 6, 10, 14);
        vqr(&mut x, 3, 7, 11, 15);
        vqr(&mut x, 0, 5, 10, 15);
        vqr(&mut x, 1, 6, 11, 12);
        vqr(&mut x, 2, 7, 8, 13);
        vqr(&mut x, 3, 4, 9, 14);
    }
    for i in 0..16 {
        let v = vadd(x[i], init[i]);
        for (l, w) in v.iter().enumerate() {
            out[64 * l + 4 * i..64 * l + 4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
    }
}

#[cfg(feature = "chacha20")]
/// XORs the ChaCha20 keystream, starting at block `counter`, into `data` (SIMD when the CPU
/// has it).
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let done = simoom_sys::arch::chacha20_xor(key, counter, nonce, data);
    let (counter, rest) = (counter.wrapping_add((done / 64) as u32), &mut data[done..]);
    if rest.is_empty() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // The SIMD code takes whole 256-byte groups: run the tail through it in a padded copy.
        if rest.len() <= 256 {
            let mut buf = [0u8; 256];
            buf[..rest.len()].copy_from_slice(rest);
            if simoom_sys::arch::chacha20_xor(key, counter, nonce, &mut buf) == 256 {
                rest.copy_from_slice(&buf[..rest.len()]);
                return;
            }
        }
        // No SSSE3 (CPUs from before 2006): one block at a time, which keeps the portable
        // four-way code out of x86-64 builds.
        for (i, chunk) in rest.chunks_mut(64).enumerate() {
            let ks = chacha20_block(key, counter.wrapping_add(i as u32), nonce);
            for (d, k) in chunk.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    chacha20_xor_portable(key, counter, nonce, rest);
}

#[cfg(feature = "chacha20")]
/// The portable four-block implementation.
pub fn chacha20_xor_portable(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut st = init_state(key, counter, nonce);
    let mut ks = [0u8; 256];
    let mut chunks = data.chunks_exact_mut(256);
    for chunk in &mut chunks {
        blocks4(&st, &mut ks);
        st[12] = st[12].wrapping_add(4);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
    }
    let rest = chunks.into_remainder();
    if !rest.is_empty() {
        blocks4(&st, &mut ks);
        for (d, k) in rest.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
    }
}

#[cfg(feature = "chacha20")]
/// Poly1305 (radix 2^44, three limbs; long inputs go through the AVX2 kernel of
/// `simoom_sys::arch` when the CPU has it).
pub struct Poly1305 {
    r: [u64; 3],
    s: [u64; 2],
    h: [u64; 3],
    pad: [u64; 2],
    buf: [u8; 16],
    len: usize,
    /// r, r^2, r^3, r^4 as 26-bit limbs, computed on the first long input.
    rpow: Option<[[u64; 5]; 4]>,
}

#[cfg(feature = "chacha20")]
/// Inputs at least this long use the SIMD kernel (below it the setup costs more than it saves).
const SIMD_MIN: usize = 256;

#[cfg(feature = "chacha20")]
/// Radix 2^44 (44, 44, 42 bits; slightly larger limbs allowed) to radix 2^26.
fn to26(h: &[u64; 3]) -> [u64; 5] {
    let lo = h[0] as u128 + ((h[1] as u128) << 44) + (((h[2] & ((1 << 40) - 1)) as u128) << 88);
    let top = h[2] >> 40; // bits from 2^128
    let m = 0x3ff_ffff;
    [lo as u64 & m, (lo >> 26) as u64 & m, (lo >> 52) as u64 & m, (lo >> 78) as u64 & m, ((lo >> 104) as u64) + (top << 24)]
}

#[cfg(feature = "chacha20")]
/// Radix 2^26 (limbs a little above 2^26 allowed) to radix 2^44.
fn to44(h: &[u64; 5]) -> [u64; 3] {
    let lo = h[0] as u128 + ((h[1] as u128) << 26) + ((h[2] as u128) << 52) + ((h[3] as u128) << 78) + (((h[4] & ((1 << 24) - 1)) as u128) << 104);
    let top = h[4] >> 24; // bits from 2^128
    [lo as u64 & M44, (lo >> 44) as u64 & M44, ((lo >> 88) as u64) + (top << 40)]
}

#[cfg(feature = "chacha20")]
const M44: u64 = 0xfff_ffff_ffff;
#[cfg(feature = "chacha20")]
const M42: u64 = 0x3ff_ffff_ffff;

#[cfg(feature = "chacha20")]
impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Poly1305 {
        let t0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        let r0 = t0 & 0xffc_0fff_ffff;
        let r1 = ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff;
        let r2 = (t1 >> 24) & 0x00f_ffff_fc0f;
        Poly1305 {
            r: [r0, r1, r2],
            s: [r1 * 20, r2 * 20],
            h: [0; 3],
            pad: [u64::from_le_bytes(key[16..24].try_into().unwrap()), u64::from_le_bytes(key[24..32].try_into().unwrap())],
            buf: [0; 16],
            len: 0,
            rpow: None,
        }
    }

    /// Limbs of one 16-byte block (with the 2^128 bit when `hibit` is 1).
    #[inline(always)]
    fn limbs(b: &[u8], hibit: u64) -> [u64; 3] {
        let t0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(b[8..16].try_into().unwrap());
        [t0 & M44, ((t0 >> 44) | (t1 << 20)) & M44, ((t1 >> 24) & M42) | (hibit << 40)]
    }

    /// The unreduced product h * r (s = 20 * r1, 20 * r2).
    #[inline(always)]
    fn mul(h: [u64; 3], r: [u64; 3], s: [u64; 2]) -> [u128; 3] {
        let m = |a: u64, b: u64| a as u128 * b as u128;
        [
            m(h[0], r[0]) + m(h[1], s[1]) + m(h[2], s[0]),
            m(h[0], r[1]) + m(h[1], r[0]) + m(h[2], s[1]),
            m(h[0], r[2]) + m(h[1], r[1]) + m(h[2], r[0]),
        ]
    }

    #[inline(always)]
    fn carry(d: [u128; 3]) -> [u64; 3] {
        let [d0, mut d1, mut d2] = d;
        let mut c = (d0 >> 44) as u64;
        let mut h0 = d0 as u64 & M44;
        d1 += c as u128;
        c = (d1 >> 44) as u64;
        let mut h1 = d1 as u64 & M44;
        d2 += c as u128;
        c = (d2 >> 42) as u64;
        let h2 = d2 as u64 & M42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= M44;
        h1 += c;
        [h0, h1, h2]
    }

    #[inline(never)]
    fn blocks(&mut self, mut data: &[u8], hibit: u64) {
        if data.len() >= SIMD_MIN && hibit == 1 {
            let rpow = *self.rpow.get_or_insert_with(|| {
                let (r, s) = (self.r, self.s);
                let r2 = Self::carry(Self::mul(r, r, s));
                let r3 = Self::carry(Self::mul(r2, r, s));
                let r4 = Self::carry(Self::mul(r3, r, s));
                [to26(&r), to26(&r2), to26(&r3), to26(&r4)]
            });
            let mut h26 = to26(&self.h);
            let done = simoom_sys::arch::poly1305_blocks(&mut h26, &rpow, data);
            if done > 0 {
                self.h = to44(&h26);
                data = &data[done..];
            }
        }
        let (r, s) = (self.r, self.s);
        let mut h = self.h;
        let mut pairs = data.chunks_exact(32);
        if pairs.len() > 0 {
            // two blocks per step: h = (h + m1) r^2 + m2 r, two independent product chains
            let r2 = Self::carry(Self::mul(r, r, s));
            let s2 = [r2[1] * 20, r2[2] * 20];
            for b in &mut pairs {
                let m1 = Self::limbs(&b[..16], hibit);
                let m2 = Self::limbs(&b[16..], hibit);
                let a = [h[0] + m1[0], h[1] + m1[1], h[2] + m1[2]];
                let x = Self::mul(a, r2, s2);
                let y = Self::mul(m2, r, s);
                h = Self::carry([x[0] + y[0], x[1] + y[1], x[2] + y[2]]);
            }
        }
        for b in pairs.remainder().chunks_exact(16) {
            let m = Self::limbs(b, hibit);
            h = Self::carry(Self::mul([h[0] + m[0], h[1] + m[1], h[2] + m[2]], r, s));
        }
        self.h = h;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.len > 0 {
            let n = (16 - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len < 16 {
                return;
            }
            let b = self.buf;
            self.blocks(&b, 1);
            self.len = 0;
        }
        let whole = data.len() & !15;
        self.blocks(&data[..whole], 1);
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    /// Absorbs zeros up to the next 16-byte boundary (the AEAD's padding).
    fn pad16(&mut self) {
        if self.len > 0 {
            self.buf[self.len..].fill(0);
            let b = self.buf;
            self.blocks(&b, 1);
            self.len = 0;
        }
    }

    pub fn finish(mut self) -> [u8; 16] {
        if self.len > 0 {
            self.buf[self.len] = 1;
            self.buf[self.len + 1..].fill(0);
            let b = self.buf;
            self.blocks(&b, 0);
        }
        let [mut h0, mut h1, mut h2] = self.h;
        let mut c = h1 >> 44;
        h1 &= M44;
        h2 += c;
        c = h2 >> 42;
        h2 &= M42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= M44;
        h1 += c;
        c = h1 >> 44;
        h1 &= M44;
        h2 += c;
        c = h2 >> 42;
        h2 &= M42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= M44;
        h1 += c;
        // g = h + 5 - 2^130; use it if it did not underflow
        let mut g0 = h0 + 5;
        c = g0 >> 44;
        g0 &= M44;
        let mut g1 = h1 + c;
        c = g1 >> 44;
        g1 &= M44;
        let g2 = (h2 + c).wrapping_sub(1 << 42);
        let mask = crate::util::ct_mask(1 ^ (g2 >> 63));
        h0 = (h0 & !mask) | (g0 & mask);
        h1 = (h1 & !mask) | (g1 & mask);
        h2 = (h2 & !mask) | (g2 & mask);
        // h = (h + pad) mod 2^128
        let lo = h0 | (h1 << 44);
        let hi = (h1 >> 20) | (h2 << 24);
        let (lo, carry) = lo.overflowing_add(self.pad[0]);
        let hi = hi.wrapping_add(self.pad[1]).wrapping_add(carry as u64);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&lo.to_le_bytes());
        out[8..].copy_from_slice(&hi.to_le_bytes());
        out
    }
}

#[cfg(feature = "chacha20")]
/// One-shot Poly1305.
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(msg);
    p.finish()
}

#[cfg(feature = "chacha20")]
/// The ChaCha20-Poly1305 AEAD.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

#[cfg(feature = "chacha20")]
impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305 { key: *key }
    }

    fn tag(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let block0 = chacha20_block(&self.key, 0, nonce);
        let mut p = Poly1305::new(block0[..32].try_into().unwrap());
        p.update(aad);
        p.pad16();
        p.update(ct);
        p.pad16();
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
        p.update(&lens);
        p.finish()
    }

    /// Encrypts `data` in place and returns the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        chacha20_xor(&self.key, 1, nonce, data);
        self.tag(nonce, aad, data)
    }

    /// Checks the tag, then decrypts `data` in place. On failure `data` is left untouched.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        if !ct_eq(&self.tag(nonce, aad, data), tag) {
            return false;
        }
        chacha20_xor(&self.key, 1, nonce, data);
        true
    }
}

#[cfg(feature = "chacha20")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    fn k32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }
    fn n12(s: &str) -> [u8; 12] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn rfc8439_block_and_encryption() {
        let key = k32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        assert_eq!(
            hex(&chacha20_block(&key, 1, &n12("000000090000004a00000000"))),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20_xor(&key, 1, &n12("000000000000004a00000000"), &mut data);
        assert_eq!(
            hex(&data),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        );
    }

    #[test]
    fn poly1305_simd_matches_scalar() {
        // the same tags through the AVX2 kernel (long updates) and the scalar code (16-byte
        // updates), for many lengths, keys with large r and an accumulator near 2^130
        let mut keys = vec![[0xffu8; 32], [0u8; 32]];
        for i in 0..6u8 {
            keys.push(core::array::from_fn(|j| (j as u8).wrapping_mul(37).wrapping_add(i.wrapping_mul(91))));
        }
        let msg: Vec<u8> = (0..3000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let ones = vec![0xffu8; 3000];
        for key in &keys {
            for data in [&msg, &ones] {
                for len in [0usize, 15, 64, 255, 256, 257, 319, 320, 1024, 1500, 2047, 3000] {
                    let fast = poly1305(key, &data[..len]);
                    let mut p = Poly1305::new(key);
                    for c in data[..len].chunks(16) {
                        p.update(c);
                    }
                    assert_eq!(fast, p.finish(), "len {len}");
                    // split updates: a long one after a short one
                    let mut q = Poly1305::new(key);
                    q.update(&data[..len.min(5)]);
                    q.update(&data[len.min(5)..len]);
                    assert_eq!(fast, q.finish(), "split len {len}");
                }
            }
        }
        // RFC 8439 section 2.5.2
        let key = crate::util::unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let tag = poly1305(&key.try_into().unwrap(), &b"Cryptographic Forum Research Group".repeat(10)[..340]);
        let mut p = Poly1305::new(&crate::util::unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap());
        for c in b"Cryptographic Forum Research Group".repeat(10)[..340].chunks(16) {
            p.update(c);
        }
        assert_eq!(tag, p.finish());
    }

    #[test]
    fn fallbacks_without_simd_match() {
        // with the SIMD paths turned off: the one-block loop (x86-64) or the portable four-way
        // code, and the scalar Poly1305
        let key = [0x42u8; 32];
        let nonce = [9u8; 12];
        let src: Vec<u8> = (0..2000u32).map(|i| (i * 7) as u8).collect();
        let mut expect = Vec::new();
        for len in [1usize, 63, 64, 300, 1000, 2000] {
            let mut a = src[..len].to_vec();
            chacha20_xor_portable(&key, 7, &nonce, &mut a);
            expect.push((a, poly1305(&key, &src[..len])));
        }
        simoom_sys::arch::disable_hardware(true);
        let mut got = Vec::new();
        for len in [1usize, 63, 64, 300, 1000, 2000] {
            let mut a = src[..len].to_vec();
            chacha20_xor(&key, 7, &nonce, &mut a);
            got.push((a, poly1305(&key, &src[..len])));
        }
        simoom_sys::arch::disable_hardware(false);
        assert!(got == expect);
    }

    #[test]
    fn simd_matches_portable() {
        let key = [0x17u8; 32];
        let nonce = [5u8; 12];
        for len in [0usize, 1, 63, 64, 255, 256, 257, 511, 512, 513, 767, 1024, 1500, 16384, 16384 + 77] {
            let src: Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
            let (mut a, mut b) = (src.clone(), src.clone());
            chacha20_xor(&key, 0xffff_fff0, &nonce, &mut a);
            chacha20_xor_portable(&key, 0xffff_fff0, &nonce, &mut b);
            assert_eq!(a, b, "len {len}");
        }
    }

    #[test]
    fn four_way_matches_single_blocks() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];
        let mut data = vec![0u8; 1000];
        chacha20_xor(&key, 0xffff_fffe, &nonce, &mut data);
        for (i, c) in data.chunks(64).enumerate() {
            let b = chacha20_block(&key, 0xffff_fffeu32.wrapping_add(i as u32), &nonce);
            assert_eq!(c, &b[..c.len()]);
        }
    }

    #[test]
    fn rfc8439_poly1305() {
        let key = k32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        assert_eq!(hex(&poly1305(&key, b"Cryptographic Forum Research Group")), "a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(hex(&poly1305(&[0u8; 32], &[0u8; 64])), "00000000000000000000000000000000");
        // A.3 vectors 6-11: edge cases of the final reduction.
        let mut key = [0u8; 32];
        key[0] = 2;
        assert_eq!(hex(&poly1305(&key, &[0xff; 16])), "03000000000000000000000000000000");
        let mut key = [0u8; 32];
        key[16] = 0xff;
        key[17..32].fill(0xff);
        key[0] = 2;
        let mut m = [0u8; 16];
        m[0] = 2;
        assert_eq!(hex(&poly1305(&key, &m)), "03000000000000000000000000000000");
        let mut key = [0u8; 32];
        key[0] = 1;
        let msg = unhex("ffffffffffffffffffffffffffffffff f0ffffffffffffffffffffffffffffff 11000000000000000000000000000000");
        assert_eq!(hex(&poly1305(&key, &msg)), "05000000000000000000000000000000");
        let msg = unhex("ffffffffffffffffffffffffffffffff fbfefefefefefefefefefefefefefefe 01010101010101010101010101010101");
        assert_eq!(hex(&poly1305(&key, &msg)), "00000000000000000000000000000000");
        let mut key2 = [0u8; 32];
        key2[0] = 2;
        let msg = unhex("fdffffffffffffffffffffffffffffff");
        assert_eq!(hex(&poly1305(&key2, &msg)), "faffffffffffffffffffffffffffffff");
        let key = k32("0100000000000000040000000000000000000000000000000000000000000000");
        let msg = unhex("e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000");
        assert_eq!(hex(&poly1305(&key, &msg)), "14000000000000005500000000000000");
        // incremental updates
        let key = [5u8; 32];
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let mut p = Poly1305::new(&key);
        for c in data.chunks(7) {
            p.update(c);
        }
        assert_eq!(p.finish(), poly1305(&key, &data));
    }

    #[test]
    fn rfc8439_aead() {
        let key = k32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = n12("070000004041424344454647");
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let a = ChaCha20Poly1305::new(&key);
        let mut buf = pt.to_vec();
        let tag = a.seal(&nonce, &aad, &mut buf);
        assert_eq!(
            hex(&buf),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");
        let mut bad = buf.clone();
        bad[0] ^= 1;
        assert!(!a.open(&nonce, &aad, &mut bad, &tag));
        assert!(a.open(&nonce, &aad, &mut buf, &tag));
        assert_eq!(buf, pt.to_vec());
    }
}

#[cfg(feature = "chacha20")]
#[cfg(test)]
mod micro {
    #[test]
    #[ignore]
    fn chacha_poly_split() {
        let key = [7u8; 32];
        let mut buf = vec![0u8; 16384];
        let n = 20_000;
        let t = std::time::Instant::now();
        for i in 0..n {
            super::chacha20_xor(&key, i as u32, &[0; 12], &mut buf);
        }
        let s = t.elapsed().as_secs_f64();
        println!("chacha20 {:.2} GB/s", n as f64 * 16384.0 / s / 1e9);
        let t = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(super::poly1305(&key, &buf));
        }
        let s = t.elapsed().as_secs_f64();
        println!("poly1305 {:.2} GB/s", n as f64 * 16384.0 / s / 1e9);
    }
}
