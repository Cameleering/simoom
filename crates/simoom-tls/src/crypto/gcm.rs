//! AES-GCM (NIST SP 800-38D) with 96-bit nonces and 128-bit tags.
//!
//! With AES-NI and PCLMULQDQ (or ARMv8 AES and PMULL) the bulk work runs in
//! `simoom_sys::arch::aes_gcm_seal`/`open`, eight blocks per step with one GHASH reduction.
//! Otherwise the bitsliced AES and a constant-time GHASH built on integer multiplication with
//! "holes" (BearSSL's `ghash_ctmul64` method) are used.

use super::aes::{expand_key, Aes, AesSoft};
use crate::util::ct_eq;
use simoom_sys::arch::{self, AesHw, GhashHw};

/// Carry-less 64x64 -> low 64 bits, with integer multiplies on masked operands so that carries
/// fall into unused bit positions. Constant time.
#[inline(always)]
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// Portable constant-time GHASH key.
#[derive(Clone)]
pub struct GhashSoft {
    h0: u64,
    h1: u64,
    h0r: u64,
    h1r: u64,
}

impl GhashSoft {
    pub fn new(h: &[u8; 16]) -> GhashSoft {
        let h1 = u64::from_be_bytes(h[..8].try_into().unwrap());
        let h0 = u64::from_be_bytes(h[8..].try_into().unwrap());
        GhashSoft { h0, h1, h0r: h0.reverse_bits(), h1r: h1.reverse_bits() }
    }

    pub fn update(&self, y: &mut [u8; 16], data: &[u8]) {
        let mut y1 = u64::from_be_bytes(y[..8].try_into().unwrap());
        let mut y0 = u64::from_be_bytes(y[8..].try_into().unwrap());
        let (h0, h1, h0r, h1r) = (self.h0, self.h1, self.h0r, self.h1r);
        let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
        for chunk in data.chunks(16) {
            let mut b = [0u8; 16];
            b[..chunk.len()].copy_from_slice(chunk);
            y1 ^= u64::from_be_bytes(b[..8].try_into().unwrap());
            y0 ^= u64::from_be_bytes(b[8..].try_into().unwrap());
            let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());
            let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);
            let z0 = bmul64(y0, h0);
            let z1 = bmul64(y1, h1);
            let mut z2 = bmul64(y2, h2);
            let mut z0h = bmul64(y0r, h0r);
            let mut z1h = bmul64(y1r, h1r);
            let mut z2h = bmul64(y2r, h2r);
            z2 ^= z0 ^ z1;
            z2h ^= z0h ^ z1h;
            z0h = z0h.reverse_bits() >> 1;
            z1h = z1h.reverse_bits() >> 1;
            z2h = z2h.reverse_bits() >> 1;
            let mut v0 = z0;
            let mut v1 = z0h ^ z2;
            let mut v2 = z1 ^ z2h;
            let mut v3 = z1h;
            v3 = (v3 << 1) | (v2 >> 63);
            v2 = (v2 << 1) | (v1 >> 63);
            v1 = (v1 << 1) | (v0 >> 63);
            v0 <<= 1;
            v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
            v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
            v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
            v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
            y0 = v2;
            y1 = v3;
        }
        y[..8].copy_from_slice(&y1.to_be_bytes());
        y[8..].copy_from_slice(&y0.to_be_bytes());
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // one per connection or key; boxing would add an indirection on the hot path
enum Imp {
    Hw(AesHw, GhashHw),
    Soft(Box<AesSoft>, GhashSoft),
}

/// AES-128-GCM or AES-256-GCM.
#[derive(Clone)]
pub struct AesGcm {
    imp: Imp,
}

impl AesGcm {
    /// `key` is 16 or 32 bytes.
    pub fn new(key: &[u8]) -> AesGcm {
        let (rk, n) = expand_key(key);
        if let Some(aes) = AesHw::new(&rk[..n]) {
            let mut h = [0u8; 16];
            aes.encrypt_block(&mut h);
            if let Some(gh) = GhashHw::new(&h) {
                return AesGcm { imp: Imp::Hw(aes, gh) };
            }
        }
        Self::new_soft(key)
    }

    /// The portable implementation, whatever the CPU (tests and benchmarks).
    pub fn new_soft(key: &[u8]) -> AesGcm {
        let aes = Aes::new_soft(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        let Aes::Soft(s) = aes else { unreachable!() };
        AesGcm { imp: Imp::Soft(s, GhashSoft::new(&h)) }
    }

    /// True if the hardware path is in use.
    pub fn is_hardware(&self) -> bool {
        matches!(self.imp, Imp::Hw(..))
    }

    fn ghash(&self, y: &mut [u8; 16], data: &[u8]) {
        match &self.imp {
            Imp::Hw(_, g) => g.update(y, data),
            Imp::Soft(_, g) => g.update(y, data),
        }
    }

    fn ekj0(&self, nonce: &[u8; 12]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        match &self.imp {
            Imp::Hw(a, _) => a.encrypt_block(&mut j0),
            Imp::Soft(a, _) => {
                let mut four = [0u8; 64];
                four[..16].copy_from_slice(&j0);
                a.encrypt4(&mut four);
                j0.copy_from_slice(&four[..16]);
            }
        }
        j0
    }

    /// CTR from counter 2 over `data` with GHASH of the ciphertext.
    fn crypt(&self, nonce: &[u8; 12], y: &mut [u8; 16], data: &mut [u8], encrypt: bool) {
        let mut ctr = [0u8; 16];
        ctr[..12].copy_from_slice(nonce);
        ctr[15] = 2;
        match &self.imp {
            Imp::Hw(a, g) => {
                // whole 128-byte groups on 256-bit registers when the CPU has VAES, then the rest
                let done = arch::aes_gcm_vaes(a, g, &mut ctr, y, data, encrypt);
                let rest = &mut data[done..];
                if encrypt {
                    arch::aes_gcm_seal(a, g, &mut ctr, y, rest)
                } else {
                    arch::aes_gcm_open(a, g, &mut ctr, y, rest)
                }
            }
            Imp::Soft(a, g) => {
                if !encrypt {
                    g.update(y, data);
                }
                let mut counter = 2u32;
                for chunk in data.chunks_mut(64) {
                    let mut ks = [0u8; 64];
                    for b in 0..4 {
                        ks[16 * b..16 * b + 12].copy_from_slice(nonce);
                        ks[16 * b + 12..16 * b + 16].copy_from_slice(&counter.wrapping_add(b as u32).to_be_bytes());
                    }
                    counter = counter.wrapping_add(4);
                    a.encrypt4(&mut ks);
                    for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                        *d ^= k;
                    }
                }
                if encrypt {
                    g.update(y, data);
                }
            }
        }
    }

    fn finish_tag(&self, nonce: &[u8; 12], mut y: [u8; 16], aad_len: usize, ct_len: usize) -> [u8; 16] {
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(aad_len as u64 * 8).to_be_bytes());
        lens[8..].copy_from_slice(&(ct_len as u64 * 8).to_be_bytes());
        self.ghash(&mut y, &lens);
        let ek = self.ekj0(nonce);
        for (a, b) in y.iter_mut().zip(ek) {
            *a ^= b;
        }
        y
    }

    /// Encrypts `data` in place and returns the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let mut y = [0u8; 16];
        self.ghash(&mut y, aad);
        self.crypt(nonce, &mut y, data, true);
        self.finish_tag(nonce, y, aad.len(), data.len())
    }

    /// Decrypts `data` in place and checks the tag. On failure `data` is zeroed and false is
    /// returned, so unauthenticated plaintext is never exposed.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        let mut y = [0u8; 16];
        self.ghash(&mut y, aad);
        self.crypt(nonce, &mut y, data, false);
        let t = self.finish_tag(nonce, y, aad.len(), data.len());
        if ct_eq(&t, tag) {
            true
        } else {
            crate::util::zeroize(data);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    fn n12(s: &str) -> [u8; 12] {
        unhex(s).try_into().unwrap()
    }

    fn both(key: &[u8]) -> [AesGcm; 2] {
        [AesGcm::new(key), AesGcm::new_soft(key)]
    }

    fn seal_hex(g: &AesGcm, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> String {
        let mut b = pt.to_vec();
        let t = g.seal(nonce, aad, &mut b);
        b.extend_from_slice(&t);
        hex(&b)
    }

    #[test]
    fn gcm_spec_test_cases() {
        // McGrew and Viega test cases 1, 2, 3, 4, 14, 16.
        for g in both(&[0u8; 16]) {
            assert_eq!(seal_hex(&g, &[0; 12], &[], &[]), "58e2fccefa7e3061367f1d57a4e7455a");
            assert_eq!(seal_hex(&g, &[0; 12], &[], &[0u8; 16]), "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
        }
        let p =
            unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let nonce = n12("cafebabefacedbaddecaf888");
        for g in both(&unhex("feffe9928665731c6d6a8f9467308308")) {
            assert_eq!(
                seal_hex(&g, &nonce, &[], &p),
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4"
            );
            let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
            let out = seal_hex(&g, &nonce, &aad, &p[..60]);
            assert_eq!(
                out,
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"
            );
            let mut ct = unhex(&out[..120]);
            let tag = unhex(&out[120..]);
            assert!(g.open(&nonce, &aad, &mut ct, &tag));
            assert_eq!(ct, &p[..60]);
            let mut ct = unhex(&out[..120]);
            ct[3] ^= 1;
            assert!(!g.open(&nonce, &aad, &mut ct, &tag));
            assert!(ct.iter().all(|b| *b == 0));
        }
        for g in both(&[0u8; 32]) {
            assert_eq!(seal_hex(&g, &[0; 12], &[], &[0u8; 16]), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
        }
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        for g in both(&unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")) {
            assert_eq!(
                seal_hex(&g, &nonce, &aad, &p[..60]),
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"
            );
        }
    }

    #[test]
    fn hardware_and_soft_agree_on_every_length() {
        // Covers the 8-block bulk loop, the single-block tail and partial blocks, with a counter
        // that wraps inside a bulk step.
        for key in [&[0x42u8; 16][..], &[0x24u8; 32][..]] {
            let [hw, soft] = both(key);
            let nonce = [0xabu8; 12];
            for len in (0..300).chain([1024, 4096, 16384 + 17]) {
                let pt: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let aad: Vec<u8> = (0..(len % 37)).map(|i| i as u8).collect();
                let (mut a, mut b) = (pt.clone(), pt.clone());
                let ta = hw.seal(&nonce, &aad, &mut a);
                let tb = soft.seal(&nonce, &aad, &mut b);
                assert_eq!(a, b, "len {len}");
                assert_eq!(ta, tb, "len {len}");
                assert!(hw.open(&nonce, &aad, &mut a, &tb));
                assert_eq!(a, pt);
            }
        }
    }

    #[test]
    fn ghash_soft_and_hardware_agree() {
        let h: [u8; 16] = unhex("66e94bd4ef8a2c3b884cfa59ca342b2e").try_into().unwrap();
        let data: Vec<u8> = (0..1000).map(|i| (i * 13) as u8).collect();
        let mut ys = [0u8; 16];
        GhashSoft::new(&h).update(&mut ys, &data);
        if let Some(g) = GhashHw::new(&h) {
            let mut yh = [0u8; 16];
            g.update(&mut yh, &data);
            assert_eq!(yh, ys);
        }
    }
}
