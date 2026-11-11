//! Hardware crypto intrinsics behind safe wrappers, with runtime detection, and the operating
//! system's random number source.
//!
//! - **AES** ([`AesHw`](crate::arch::AesHw)): AES-NI on x86-64, the ARMv8 Cryptography Extension on aarch64. Round
//!   keys come from the caller (the portable, constant-time key schedule in `simoom-tls`), so only
//!   the rounds run here.
//! - **GHASH** ([`GhashHw`](crate::arch::GhashHw)): PCLMULQDQ on x86-64, PMULL on aarch64, with the powers H^1..H^8
//!   precomputed so eight blocks share one reduction.
//! - **AES-GCM bulk** ([`aes_gcm_seal`](crate::arch::aes_gcm_seal), [`aes_gcm_open`](crate::arch::aes_gcm_open)): CTR and GHASH fused, eight blocks per
//!   step.
//! - **SHA-256** ([`sha256_blocks`](crate::arch::sha256_blocks)): SHA-NI on x86-64, the ARMv8 SHA-2 instructions on aarch64.
//! - **Randomness** ([`os_random`](crate::arch::os_random)): `getrandom(2)` on Linux and Android, `getentropy(3)` on the
//!   BSDs and macOS, `BCryptGenRandom` on Windows.
//!
//! A value of [`AesHw`](crate::arch::AesHw) or [`GhashHw`](crate::arch::GhashHw) exists only if the CPU has the instructions (the
//! constructors check), so every method can call the `#[target_feature]` code without asking
//! again. All these instructions run in constant time: no table lookups, no data-dependent
//! branches.

use std::sync::atomic::{AtomicU8, Ordering};

const F_AES: u8 = 1;
const F_CLMUL: u8 = 2;
const F_SHA256: u8 = 4;
const F_SIMD4: u8 = 8;
const F_SIMD8: u8 = 16;
const F_DONE: u8 = 0x80;

static FEATURES: AtomicU8 = AtomicU8::new(0);
static DISABLED: AtomicU8 = AtomicU8::new(0);

fn detect() -> u8 {
    #[allow(unused_mut)]
    let mut f = 0u8;
    #[cfg(target_arch = "x86_64")]
    {
        use crate::cpu::x86;
        let x = crate::cpu::x86_features();
        let ssse3 = x & x86::SSSE3 != 0 && x & x86::SSE41 != 0;
        if ssse3 && x & x86::AES != 0 {
            f |= F_AES;
        }
        if ssse3 && x & x86::PCLMULQDQ != 0 {
            f |= F_CLMUL;
        }
        if ssse3 && x & x86::SHA != 0 {
            f |= F_SHA256;
        }
        if ssse3 {
            f |= F_SIMD4;
        }
        if ssse3 && x & x86::AVX2 != 0 {
            f |= F_SIMD8;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            f |= F_AES;
        }
        if std::arch::is_aarch64_feature_detected!("pmull") {
            f |= F_CLMUL;
        }
        if std::arch::is_aarch64_feature_detected!("sha2") {
            f |= F_SHA256;
        }
    }
    f
}

#[inline]
fn features() -> u8 {
    let mut f = FEATURES.load(Ordering::Relaxed);
    if f == 0 {
        f = detect() | F_DONE;
        FEATURES.store(f, Ordering::Relaxed);
    }
    f & !DISABLED.load(Ordering::Relaxed)
}

/// True if the CPU has AES round instructions (AES-NI or ARMv8 AES).
#[inline]
pub fn has_aes() -> bool {
    features() & F_AES != 0
}

/// True if the CPU has a 64x64-bit carry-less multiply (PCLMULQDQ or PMULL).
#[inline]
pub fn has_clmul() -> bool {
    features() & F_CLMUL != 0
}

/// True if the CPU has SHA-256 instructions (SHA-NI or ARMv8 SHA-2).
#[inline]
pub fn has_sha256() -> bool {
    features() & F_SHA256 != 0
}

/// Turns the hardware paths off (`true`) or back on, process-wide, so tests and benchmarks can
/// exercise the portable fallbacks. Values built while enabled keep working.
pub fn disable_hardware(disabled: bool) {
    DISABLED.store(
        if disabled {
            F_AES | F_CLMUL | F_SHA256 | F_SIMD4 | F_SIMD8
        } else {
            0
        },
        Ordering::Relaxed,
    );
}

/// ChaCha20 keystream XOR with SIMD (x86-64: AVX2 eight blocks per step, SSSE3 four), over
/// the longest prefix of `data` that is a whole number of 256-byte groups. Block counters start
/// at `counter`. Returns the number of bytes processed (0 if the CPU has no SIMD path); the
/// caller handles the rest.
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) -> usize {
    let f = features();
    let mut st = [0u32; 16];
    st[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for i in 0..8 {
        st[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    st[12] = counter;
    for i in 0..3 {
        st[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }
    #[allow(unused_mut)]
    let mut done = 0;
    #[cfg(target_arch = "x86_64")]
    {
        if f & F_SIMD8 != 0 && data.len() >= 512 {
            let n = data.len() / 512 * 512;
            // SAFETY: F_SIMD8 means the CPU has AVX2 (and SSSE3); `n` is a multiple of 512 and at
            // most `data.len()`.
            unsafe { x86::chacha8(&mut st, &mut data[..n]) };
            done = n;
        }
        if f & F_SIMD4 != 0 && data.len() - done >= 256 {
            let n = (data.len() - done) / 256 * 256;
            // SAFETY: F_SIMD4 means the CPU has SSSE3; `n` is a multiple of 256 and the slice is
            // within `data`.
            unsafe { x86::chacha4(&mut st, &mut data[done..done + n]) };
            done += n;
        }
    }
    let _ = (f, &mut st, &data);
    done
}

/// Expanded AES round keys for the hardware AES path (AES-128 or AES-256).
#[derive(Clone)]
pub struct AesHw {
    rk: [[u8; 16]; 15],
    nr: usize,
}

impl std::fmt::Debug for AesHw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AesHw(AES-{})", if self.nr == 10 { 128 } else { 256 })
    }
}

impl AesHw {
    /// Takes the FIPS-197 round keys (11 for AES-128, 15 for AES-256, in the standard byte
    /// order). Returns `None` if the CPU lacks AES instructions or the count is wrong.
    pub fn new(round_keys: &[[u8; 16]]) -> Option<AesHw> {
        if !has_aes() || !(round_keys.len() == 11 || round_keys.len() == 15) {
            return None;
        }
        let mut rk = [[0u8; 16]; 15];
        rk[..round_keys.len()].copy_from_slice(round_keys);
        Some(AesHw {
            rk,
            nr: round_keys.len() - 1,
        })
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: an `AesHw` exists only if `has_aes()` was true (AES-NI, SSSE3, SSE4.1).
        unsafe {
            x86::aes_block(&self.rk, self.nr, block)
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: an `AesHw` exists only if `has_aes()` was true (ARMv8 AES).
        unsafe {
            arm::aes_block(&self.rk, self.nr, block)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = block;
            unreachable!("AesHw is never built on this architecture")
        }
    }
}

/// GHASH key with the powers H^1..H^8 precomputed for the carry-less multiply path.
#[derive(Clone)]
pub struct GhashHw {
    /// H^(i+1) in the internal (byte-reversed) representation.
    h: [[u8; 16]; 8],
}

impl std::fmt::Debug for GhashHw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GhashHw")
    }
}

impl GhashHw {
    /// `h` is the hash subkey E(K, 0^128). Returns `None` if the CPU lacks carry-less multiply.
    pub fn new(h: &[u8; 16]) -> Option<GhashHw> {
        if !has_clmul() {
            return None;
        }
        #[allow(unused_mut)]
        let mut g = GhashHw { h: [[0; 16]; 8] };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `has_clmul()` was true (PCLMULQDQ, SSSE3, SSE4.1).
        unsafe {
            x86::ghash_init(h, &mut g.h)
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: `has_clmul()` was true (PMULL).
        unsafe {
            arm::ghash_init(h, &mut g.h)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let _ = h;
        Some(g)
    }

    /// Absorbs `data` into the GHASH state `y` (standard byte order). A final partial block is
    /// padded with zeros, as GCM requires.
    pub fn update(&self, y: &mut [u8; 16], data: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: a `GhashHw` exists only if `has_clmul()` was true.
        unsafe {
            x86::ghash_update(&self.h, y, data)
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: a `GhashHw` exists only if `has_clmul()` was true.
        unsafe {
            arm::ghash_update(&self.h, y, data)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let _ = (y, data);
    }
}

/// AES-GCM bulk encryption: encrypts `data` in place in CTR mode starting at counter block
/// `ctr` (incremented as a 32-bit big-endian counter, left at the next value) and absorbs the
/// ciphertext into the GHASH state `y`.
pub fn aes_gcm_seal(
    aes: &AesHw,
    gh: &GhashHw,
    ctr: &mut [u8; 16],
    y: &mut [u8; 16],
    data: &mut [u8],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `AesHw` and `GhashHw` values exist only if the CPU has AES-NI and PCLMULQDQ.
    unsafe {
        x86::gcm(&aes.rk, aes.nr, &gh.h, ctr, y, data, true)
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `AesHw` and `GhashHw` values exist only if the CPU has ARMv8 AES and PMULL.
    unsafe {
        arm::gcm(&aes.rk, aes.nr, &gh.h, ctr, y, data, true)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = (aes, gh, ctr, y, data);
}

/// AES-GCM bulk decryption: absorbs the ciphertext `data` into `y`, then decrypts it in place.
pub fn aes_gcm_open(
    aes: &AesHw,
    gh: &GhashHw,
    ctr: &mut [u8; 16],
    y: &mut [u8; 16],
    data: &mut [u8],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `AesHw` and `GhashHw` values exist only if the CPU has AES-NI and PCLMULQDQ.
    unsafe {
        x86::gcm(&aes.rk, aes.nr, &gh.h, ctr, y, data, false)
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `AesHw` and `GhashHw` values exist only if the CPU has ARMv8 AES and PMULL.
    unsafe {
        arm::gcm(&aes.rk, aes.nr, &gh.h, ctr, y, data, false)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = (aes, gh, ctr, y, data);
}

/// Runs the SHA-256 compression function over whole 64-byte blocks with the CPU's SHA
/// instructions. Returns false (and does nothing) if the CPU lacks them or `blocks.len()` is
/// not a multiple of 64.
pub fn sha256_blocks(state: &mut [u32; 8], blocks: &[u8]) -> bool {
    if !has_sha256() || blocks.len() % 64 != 0 {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `has_sha256()` was true (SHA-NI, SSSE3, SSE4.1); the length is a multiple of 64.
    unsafe {
        x86::sha256(state, blocks)
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `has_sha256()` was true (ARMv8 SHA-2); the length is a multiple of 64.
    unsafe {
        arm::sha256(state, blocks)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = state;
    true
}

/// SHA-256 round constants, shared by both architectures.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::x86_64::*;

    // The GHASH representation: a block loaded with its 16 bytes reversed is the 128-bit
    // big-endian integer of the block, whose bit i is the coefficient of x^(127-i) (GCM's
    // reflected bit order). A carry-less product of two such values is the reflected product
    // shifted right by one bit; `ghash_reduce!` shifts it back and reduces it modulo
    // x^128 + x^7 + x^2 + x + 1.

    macro_rules! rev {
        () => {
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        };
    }

    // Accumulates the Karatsuba partial products of a*b into (lo, mid, hi).
    macro_rules! clmul_acc {
        ($lo:ident, $mid:ident, $hi:ident, $a:expr, $b:expr) => {{
            let a = $a;
            let b = $b;
            $lo = _mm_xor_si128($lo, _mm_clmulepi64_si128(a, b, 0x00));
            $hi = _mm_xor_si128($hi, _mm_clmulepi64_si128(a, b, 0x11));
            let a2 = _mm_xor_si128(a, _mm_shuffle_epi32(a, 0x4e));
            let b2 = _mm_xor_si128(b, _mm_shuffle_epi32(b, 0x4e));
            $mid = _mm_xor_si128($mid, _mm_clmulepi64_si128(a2, b2, 0x00));
        }};
    }

    // Combines (lo, mid, hi) into the 256-bit product, shifts it left by one bit and reduces.
    macro_rules! ghash_reduce {
        ($lo:expr, $mid:expr, $hi:expr) => {{
            let (mut lo, mut hi) = ($lo, $hi);
            let mid = _mm_xor_si128($mid, _mm_xor_si128(lo, hi));
            lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
            hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
            let clo = _mm_srli_epi64(lo, 63);
            let chi = _mm_srli_epi64(hi, 63);
            lo = _mm_or_si128(_mm_slli_epi64(lo, 1), _mm_slli_si128(clo, 8));
            hi = _mm_or_si128(
                _mm_or_si128(_mm_slli_epi64(hi, 1), _mm_slli_si128(chi, 8)),
                _mm_srli_si128(clo, 8),
            );
            let g = _mm_xor_si128(
                _mm_xor_si128(_mm_slli_epi64(lo, 63), _mm_slli_epi64(lo, 62)),
                _mm_slli_epi64(lo, 57),
            );
            lo = _mm_xor_si128(lo, _mm_slli_si128(g, 8));
            let f = _mm_xor_si128(
                _mm_xor_si128(lo, _mm_srli_epi64(lo, 1)),
                _mm_xor_si128(_mm_srli_epi64(lo, 2), _mm_srli_epi64(lo, 7)),
            );
            hi = _mm_xor_si128(hi, f);
            let g = _mm_xor_si128(
                _mm_xor_si128(_mm_slli_epi64(lo, 63), _mm_slli_epi64(lo, 62)),
                _mm_slli_epi64(lo, 57),
            );
            _mm_xor_si128(hi, _mm_srli_si128(g, 8))
        }};
    }

    macro_rules! ghash_mul {
        ($a:expr, $b:expr) => {{
            let z = _mm_setzero_si128();
            let (mut lo, mut mid, mut hi) = (z, z, z);
            clmul_acc!(lo, mid, hi, $a, $b);
            ghash_reduce!(lo, mid, hi)
        }};
    }

    macro_rules! ld {
        ($p:expr) => {
            _mm_loadu_si128(($p).as_ptr() as *const __m128i)
        };
    }

    macro_rules! st {
        ($p:expr, $v:expr) => {
            _mm_storeu_si128(($p).as_mut_ptr() as *mut __m128i, $v)
        };
    }

    /// # Safety
    /// The CPU must have AES-NI.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn aes_block(rk: &[[u8; 16]; 15], nr: usize, block: &mut [u8; 16]) {
        // SAFETY: 16-byte unaligned loads and stores of 16-byte arrays; `nr` is 10 or 14, so
        // every index is below 15.
        unsafe {
            let mut x = _mm_xor_si128(ld!(block), ld!(rk[0]));
            for k in &rk[1..nr] {
                x = _mm_aesenc_si128(x, ld!(k));
            }
            x = _mm_aesenclast_si128(x, ld!(rk[nr]));
            st!(block, x);
        }
    }

    /// # Safety
    /// The CPU must have PCLMULQDQ and SSSE3.
    #[target_feature(enable = "pclmulqdq,ssse3,sse2")]
    pub(super) unsafe fn ghash_init(h: &[u8; 16], out: &mut [[u8; 16]; 8]) {
        // SAFETY: unaligned 16-byte loads and stores of 16-byte arrays.
        unsafe {
            let h1 = _mm_shuffle_epi8(ld!(h), rev!());
            let mut p = h1;
            st!(out[0], p);
            for o in out.iter_mut().skip(1) {
                p = ghash_mul!(p, h1);
                st!(o, p);
            }
        }
    }

    /// # Safety
    /// The CPU must have PCLMULQDQ and SSSE3.
    #[target_feature(enable = "pclmulqdq,ssse3,sse2")]
    pub(super) unsafe fn ghash_update(hp: &[[u8; 16]; 8], y: &mut [u8; 16], data: &[u8]) {
        // SAFETY: loads read 16 bytes at offsets `i` with `i + 16 <= data.len()`; the partial
        // tail is copied into a local 16-byte block first. Other loads and stores are 16-byte
        // arrays.
        unsafe {
            let r = rev!();
            let mut h = [_mm_setzero_si128(); 8];
            for (k, v) in h.iter_mut().enumerate() {
                *v = ld!(hp[k]);
            }
            let mut acc = _mm_shuffle_epi8(ld!(y), r);
            let n = data.len();
            let p = data.as_ptr();
            let mut i = 0;
            while i + 128 <= n {
                let z = _mm_setzero_si128();
                let (mut lo, mut mid, mut hi) = (z, z, z);
                let x0 = _mm_xor_si128(
                    acc,
                    _mm_shuffle_epi8(_mm_loadu_si128(p.add(i) as *const __m128i), r),
                );
                clmul_acc!(lo, mid, hi, x0, h[7]);
                for j in 1..8 {
                    let x =
                        _mm_shuffle_epi8(_mm_loadu_si128(p.add(i + 16 * j) as *const __m128i), r);
                    clmul_acc!(lo, mid, hi, x, h[7 - j]);
                }
                acc = ghash_reduce!(lo, mid, hi);
                i += 128;
            }
            while i + 16 <= n {
                let x = _mm_shuffle_epi8(_mm_loadu_si128(p.add(i) as *const __m128i), r);
                acc = ghash_mul!(_mm_xor_si128(acc, x), h[0]);
                i += 16;
            }
            if i < n {
                let mut t = [0u8; 16];
                t[..n - i].copy_from_slice(&data[i..]);
                acc = ghash_mul!(_mm_xor_si128(acc, _mm_shuffle_epi8(ld!(t), r)), h[0]);
            }
            st!(y, _mm_shuffle_epi8(acc, r));
        }
    }

    /// # Safety
    /// The CPU must have AES-NI, PCLMULQDQ and SSSE3; `nr` is 10 or 14.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,sse2")]
    pub(super) unsafe fn gcm(
        rkb: &[[u8; 16]; 15],
        nr: usize,
        hp: &[[u8; 16]; 8],
        ctr: &mut [u8; 16],
        y: &mut [u8; 16],
        data: &mut [u8],
        encrypt: bool,
    ) {
        // SAFETY: loads and stores of the data touch 16 bytes at offsets `i` with
        // `i + 16 <= data.len()`; the partial tail goes through a local 16-byte block. The round
        // key and power arrays are read within their bounds (`nr` <= 14).
        unsafe {
            let r = rev!();
            let mut rk = [_mm_setzero_si128(); 15];
            for k in 0..=nr {
                rk[k] = ld!(rkb[k]);
            }
            let mut h = [_mm_setzero_si128(); 8];
            for (k, v) in h.iter_mut().enumerate() {
                *v = ld!(hp[k]);
            }
            let one = _mm_set_epi32(0, 0, 0, 1);
            // The counter block byte-reversed: its low 32-bit lane is the counter as an integer,
            // so `paddd` performs GCM's inc32.
            let mut c = _mm_shuffle_epi8(ld!(ctr), r);
            let mut acc = _mm_shuffle_epi8(ld!(y), r);
            let n = data.len();
            let p = data.as_mut_ptr();
            let mut i = 0;
            while i + 128 <= n {
                let mut b = [_mm_setzero_si128(); 8];
                for v in b.iter_mut() {
                    *v = _mm_xor_si128(_mm_shuffle_epi8(c, r), rk[0]);
                    c = _mm_add_epi32(c, one);
                }
                let mut x = [_mm_setzero_si128(); 8];
                if !encrypt {
                    for (j, v) in x.iter_mut().enumerate() {
                        *v = _mm_loadu_si128(p.add(i + 16 * j) as *const __m128i);
                    }
                }
                for k in &rk[1..nr] {
                    for v in b.iter_mut() {
                        *v = _mm_aesenc_si128(*v, *k);
                    }
                }
                for v in b.iter_mut() {
                    *v = _mm_aesenclast_si128(*v, rk[nr]);
                }
                if encrypt {
                    for j in 0..8 {
                        x[j] = _mm_xor_si128(
                            b[j],
                            _mm_loadu_si128(p.add(i + 16 * j) as *const __m128i),
                        );
                        _mm_storeu_si128(p.add(i + 16 * j) as *mut __m128i, x[j]);
                    }
                } else {
                    for j in 0..8 {
                        _mm_storeu_si128(
                            p.add(i + 16 * j) as *mut __m128i,
                            _mm_xor_si128(b[j], x[j]),
                        );
                    }
                }
                let z = _mm_setzero_si128();
                let (mut lo, mut mid, mut hi) = (z, z, z);
                clmul_acc!(
                    lo,
                    mid,
                    hi,
                    _mm_xor_si128(acc, _mm_shuffle_epi8(x[0], r)),
                    h[7]
                );
                for j in 1..8 {
                    clmul_acc!(lo, mid, hi, _mm_shuffle_epi8(x[j], r), h[7 - j]);
                }
                acc = ghash_reduce!(lo, mid, hi);
                i += 128;
            }
            while i < n {
                let mut ks = _mm_xor_si128(_mm_shuffle_epi8(c, r), rk[0]);
                c = _mm_add_epi32(c, one);
                for k in &rk[1..nr] {
                    ks = _mm_aesenc_si128(ks, *k);
                }
                ks = _mm_aesenclast_si128(ks, rk[nr]);
                let take = (n - i).min(16);
                let mut t = [0u8; 16];
                t[..take].copy_from_slice(&data[i..i + take]);
                let out = _mm_xor_si128(ld!(t), ks);
                let mut o = [0u8; 16];
                st!(o, out);
                // GHASH absorbs the ciphertext, zero-padded.
                let mut ct = if encrypt { o } else { t };
                ct[take..].fill(0);
                acc = ghash_mul!(_mm_xor_si128(acc, _mm_shuffle_epi8(ld!(ct), r)), h[0]);
                data[i..i + take].copy_from_slice(&o[..take]);
                i += take;
            }
            st!(ctr, _mm_shuffle_epi8(c, r));
            st!(y, _mm_shuffle_epi8(acc, r));
        }
    }

    /// # Safety
    /// The CPU must have SHA-NI, SSSE3 and SSE4.1; `blocks.len()` is a multiple of 64.
    #[target_feature(enable = "sha,ssse3,sse4.1,sse2")]
    pub(super) unsafe fn sha256(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: `state` is 8 u32 (two 16-byte loads and stores); each block load reads 16
        // bytes at offsets below `blocks.len()` (a multiple of 64); `K256` has 64 entries.
        unsafe {
            let swap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
            let mut tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i);
            let mut s1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);
            tmp = _mm_shuffle_epi32(tmp, 0xb1); // CDAB
            s1 = _mm_shuffle_epi32(s1, 0x1b); // EFGH
            let mut s0 = _mm_alignr_epi8(tmp, s1, 8); // ABEF
            s1 = _mm_blend_epi16(s1, tmp, 0xf0); // CDGH
            for block in blocks.chunks_exact(64) {
                let (abef, cdgh) = (s0, s1);
                let mut w = [_mm_setzero_si128(); 16];
                for (j, wj) in w.iter_mut().take(4).enumerate() {
                    *wj = _mm_shuffle_epi8(
                        _mm_loadu_si128(block.as_ptr().add(16 * j) as *const __m128i),
                        swap,
                    );
                }
                for g in 0..12 {
                    let t = _mm_add_epi32(
                        _mm_sha256msg1_epu32(w[g], w[g + 1]),
                        _mm_alignr_epi8(w[g + 3], w[g + 2], 4),
                    );
                    w[g + 4] = _mm_sha256msg2_epu32(t, w[g + 3]);
                }
                for (g, wg) in w.iter().enumerate() {
                    let wk = _mm_add_epi32(
                        *wg,
                        _mm_loadu_si128(super::K256.as_ptr().add(4 * g) as *const __m128i),
                    );
                    s1 = _mm_sha256rnds2_epu32(s1, s0, wk);
                    s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(wk, 0x0e));
                }
                s0 = _mm_add_epi32(s0, abef);
                s1 = _mm_add_epi32(s1, cdgh);
            }
            tmp = _mm_shuffle_epi32(s0, 0x1b); // FEBA
            s1 = _mm_shuffle_epi32(s1, 0xb1); // DCHG
            s0 = _mm_blend_epi16(tmp, s1, 0xf0); // DCBA
            s1 = _mm_alignr_epi8(s1, tmp, 8); // HGFE
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, s0);
            _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, s1);
        }
    }

    // ChaCha20 quarter round on lane-sliced state (one block per lane).
    macro_rules! qr4 {
        ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr, $add:ident, $xor:ident, $r16:ident, $r8:ident, $rot:ident) => {{
            $x[$a] = $add!($x[$a], $x[$b]);
            $x[$d] = $r16!($xor!($x[$d], $x[$a]));
            $x[$c] = $add!($x[$c], $x[$d]);
            $x[$b] = $rot!($xor!($x[$b], $x[$c]), 12);
            $x[$a] = $add!($x[$a], $x[$b]);
            $x[$d] = $r8!($xor!($x[$d], $x[$a]));
            $x[$c] = $add!($x[$c], $x[$d]);
            $x[$b] = $rot!($xor!($x[$b], $x[$c]), 7);
        }};
    }

    macro_rules! rounds {
        ($x:ident, $add:ident, $xor:ident, $r16:ident, $r8:ident, $rot:ident) => {
            for _ in 0..10 {
                qr4!($x, 0, 4, 8, 12, $add, $xor, $r16, $r8, $rot);
                qr4!($x, 1, 5, 9, 13, $add, $xor, $r16, $r8, $rot);
                qr4!($x, 2, 6, 10, 14, $add, $xor, $r16, $r8, $rot);
                qr4!($x, 3, 7, 11, 15, $add, $xor, $r16, $r8, $rot);
                qr4!($x, 0, 5, 10, 15, $add, $xor, $r16, $r8, $rot);
                qr4!($x, 1, 6, 11, 12, $add, $xor, $r16, $r8, $rot);
                qr4!($x, 2, 7, 8, 13, $add, $xor, $r16, $r8, $rot);
                qr4!($x, 3, 4, 9, 14, $add, $xor, $r16, $r8, $rot);
            }
        };
    }

    macro_rules! add128 {
        ($a:expr, $b:expr) => {
            _mm_add_epi32($a, $b)
        };
    }
    macro_rules! xor128 {
        ($a:expr, $b:expr) => {
            _mm_xor_si128($a, $b)
        };
    }
    macro_rules! rot128 {
        ($v:expr, $n:expr) => {{
            let v = $v;
            _mm_or_si128(_mm_slli_epi32(v, $n), _mm_srli_epi32(v, 32 - $n))
        }};
    }
    macro_rules! r16_128 {
        ($v:expr) => {
            _mm_shuffle_epi8(
                $v,
                _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2),
            )
        };
    }
    macro_rules! r8_128 {
        ($v:expr) => {
            _mm_shuffle_epi8(
                $v,
                _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3),
            )
        };
    }
    macro_rules! add256 {
        ($a:expr, $b:expr) => {
            _mm256_add_epi32($a, $b)
        };
    }
    macro_rules! xor256 {
        ($a:expr, $b:expr) => {
            _mm256_xor_si256($a, $b)
        };
    }
    macro_rules! rot256 {
        ($v:expr, $n:expr) => {{
            let v = $v;
            _mm256_or_si256(_mm256_slli_epi32(v, $n), _mm256_srli_epi32(v, 32 - $n))
        }};
    }
    macro_rules! r16_256 {
        ($v:expr) => {
            _mm256_shuffle_epi8(
                $v,
                _mm256_set_epi8(
                    13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11,
                    10, 5, 4, 7, 6, 1, 0, 3, 2,
                ),
            )
        };
    }
    macro_rules! r8_256 {
        ($v:expr) => {
            _mm256_shuffle_epi8(
                $v,
                _mm256_set_epi8(
                    14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8,
                    11, 6, 5, 4, 7, 2, 1, 0, 3,
                ),
            )
        };
    }

    /// Four ChaCha20 blocks per step.
    ///
    /// # Safety
    /// The CPU must have SSSE3; `data.len()` is a multiple of 256.
    #[target_feature(enable = "ssse3,sse2")]
    pub(super) unsafe fn chacha4(st: &mut [u32; 16], data: &mut [u8]) {
        // SAFETY: loads and stores touch 16 bytes at offsets below `data.len()` (a multiple of
        // 256); the state array has 16 words.
        unsafe {
            let p = data.as_mut_ptr();
            for chunk in 0..data.len() / 256 {
                let mut x = [_mm_setzero_si128(); 16];
                for (i, v) in x.iter_mut().enumerate() {
                    *v = _mm_set1_epi32(st[i] as i32);
                }
                x[12] = _mm_add_epi32(x[12], _mm_set_epi32(3, 2, 1, 0));
                let init = x;
                rounds!(x, add128, xor128, r16_128, r8_128, rot128);
                for (v, i) in x.iter_mut().zip(init.iter()) {
                    *v = _mm_add_epi32(*v, *i);
                }
                // transpose each group of four words to block order and XOR into the data
                for g in 0..4 {
                    let (a, b, c, d) = (x[4 * g], x[4 * g + 1], x[4 * g + 2], x[4 * g + 3]);
                    let t0 = _mm_unpacklo_epi32(a, b);
                    let t1 = _mm_unpackhi_epi32(a, b);
                    let t2 = _mm_unpacklo_epi32(c, d);
                    let t3 = _mm_unpackhi_epi32(c, d);
                    let o = [
                        _mm_unpacklo_epi64(t0, t2),
                        _mm_unpackhi_epi64(t0, t2),
                        _mm_unpacklo_epi64(t1, t3),
                        _mm_unpackhi_epi64(t1, t3),
                    ];
                    for (blk, ov) in o.iter().enumerate() {
                        let q = p.add(chunk * 256 + blk * 64 + g * 16) as *mut __m128i;
                        _mm_storeu_si128(q, _mm_xor_si128(_mm_loadu_si128(q), *ov));
                    }
                }
                st[12] = st[12].wrapping_add(4);
            }
        }
    }

    /// Eight ChaCha20 blocks per step.
    ///
    /// # Safety
    /// The CPU must have AVX2; `data.len()` is a multiple of 512.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn chacha8(st: &mut [u32; 16], data: &mut [u8]) {
        // SAFETY: loads and stores touch 32 bytes at offsets below `data.len()` (a multiple of
        // 512); the state array has 16 words.
        unsafe {
            let p = data.as_mut_ptr();
            for chunk in 0..data.len() / 512 {
                let mut x = [_mm256_setzero_si256(); 16];
                for (i, v) in x.iter_mut().enumerate() {
                    *v = _mm256_set1_epi32(st[i] as i32);
                }
                x[12] = _mm256_add_epi32(x[12], _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0));
                let init = x;
                rounds!(x, add256, xor256, r16_256, r8_256, rot256);
                for (v, i) in x.iter_mut().zip(init.iter()) {
                    *v = _mm256_add_epi32(*v, *i);
                }
                // 8x8 transposes: words 0-7 and 8-15 of each block
                for half in 0..2 {
                    let a = &x[8 * half..8 * half + 8];
                    let t: [__m256i; 8] = [
                        _mm256_unpacklo_epi32(a[0], a[1]),
                        _mm256_unpackhi_epi32(a[0], a[1]),
                        _mm256_unpacklo_epi32(a[2], a[3]),
                        _mm256_unpackhi_epi32(a[2], a[3]),
                        _mm256_unpacklo_epi32(a[4], a[5]),
                        _mm256_unpackhi_epi32(a[4], a[5]),
                        _mm256_unpacklo_epi32(a[6], a[7]),
                        _mm256_unpackhi_epi32(a[6], a[7]),
                    ];
                    let u: [__m256i; 8] = [
                        _mm256_unpacklo_epi64(t[0], t[2]),
                        _mm256_unpackhi_epi64(t[0], t[2]),
                        _mm256_unpacklo_epi64(t[1], t[3]),
                        _mm256_unpackhi_epi64(t[1], t[3]),
                        _mm256_unpacklo_epi64(t[4], t[6]),
                        _mm256_unpackhi_epi64(t[4], t[6]),
                        _mm256_unpacklo_epi64(t[5], t[7]),
                        _mm256_unpackhi_epi64(t[5], t[7]),
                    ];
                    for k in 0..4 {
                        let lo = _mm256_permute2x128_si256(u[k], u[k + 4], 0x20); // block k
                        let hi = _mm256_permute2x128_si256(u[k], u[k + 4], 0x31); // block k + 4
                        let q0 = p.add(chunk * 512 + k * 64 + half * 32) as *mut __m256i;
                        let q1 = p.add(chunk * 512 + (k + 4) * 64 + half * 32) as *mut __m256i;
                        _mm256_storeu_si256(q0, _mm256_xor_si256(_mm256_loadu_si256(q0), lo));
                        _mm256_storeu_si256(q1, _mm256_xor_si256(_mm256_loadu_si256(q1), hi));
                    }
                }
                st[12] = st[12].wrapping_add(8);
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use core::arch::aarch64::*;

    // Same representation as on x86-64 (see there), with the 128-bit integer held as two u64
    // halves (`hi`, `lo`) in general registers and PMULL for the 64x64 products.

    #[inline(always)]
    fn rev_load(b: &[u8; 16]) -> (u64, u64) {
        let v = u128::from_be_bytes(*b);
        ((v >> 64) as u64, v as u64)
    }

    #[inline(always)]
    fn rev_store(hi: u64, lo: u64) -> [u8; 16] {
        (((hi as u128) << 64) | lo as u128).to_be_bytes()
    }

    // Reduces the 256-bit product v3:v2:v1:v0 (already shifted left by one bit).
    #[inline(always)]
    fn reduce(v0: u64, mut v1: u64, mut v2: u64, mut v3: u64) -> (u64, u64) {
        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
        (v3, v2)
    }

    // (lo, mid, hi) accumulators of 128-bit partial products -> reduced (hi, lo) halves.
    #[inline(always)]
    fn finish(lo: u128, mid: u128, hi: u128) -> (u64, u64) {
        let mid = mid ^ lo ^ hi;
        let lo = lo ^ (mid << 64);
        let hi = hi ^ (mid >> 64);
        let hi = (hi << 1) | (lo >> 127);
        let lo = lo << 1;
        reduce(lo as u64, (lo >> 64) as u64, hi as u64, (hi >> 64) as u64)
    }

    macro_rules! pmull_acc {
        ($lo:ident, $mid:ident, $hi:ident, $a:expr, $b:expr) => {{
            let (ah, al): (u64, u64) = $a;
            let (bh, bl): (u64, u64) = $b;
            $lo ^= vmull_p64(al, bl);
            $hi ^= vmull_p64(ah, bh);
            $mid ^= vmull_p64(al ^ ah, bl ^ bh);
        }};
    }

    /// # Safety
    /// The CPU must have the ARMv8 AES instructions.
    #[target_feature(enable = "neon,aes")]
    pub(super) unsafe fn aes_block(rk: &[[u8; 16]; 15], nr: usize, block: &mut [u8; 16]) {
        // SAFETY: 16-byte loads and stores of 16-byte arrays; `nr` <= 14.
        unsafe {
            let mut x = vld1q_u8(block.as_ptr());
            for k in &rk[..nr - 1] {
                x = vaesmcq_u8(vaeseq_u8(x, vld1q_u8(k.as_ptr())));
            }
            x = vaeseq_u8(x, vld1q_u8(rk[nr - 1].as_ptr()));
            x = veorq_u8(x, vld1q_u8(rk[nr].as_ptr()));
            vst1q_u8(block.as_mut_ptr(), x);
        }
    }

    /// # Safety
    /// The CPU must have PMULL.
    #[target_feature(enable = "neon,aes")]
    #[allow(unused_unsafe)] // `vmull_p64` became safe to call here in Rust 1.87
    pub(super) unsafe fn ghash_init(h: &[u8; 16], out: &mut [[u8; 16]; 8]) {
        // SAFETY: `vmull_p64` only needs the PMULL feature, which the caller checked.
        unsafe {
            let h1 = rev_load(h);
            let mut p = h1;
            out[0] = rev_store(p.0, p.1);
            for o in out.iter_mut().skip(1) {
                let (mut lo, mut mid, mut hi) = (0u128, 0u128, 0u128);
                pmull_acc!(lo, mid, hi, p, h1);
                p = finish(lo, mid, hi);
                *o = rev_store(p.0, p.1);
            }
        }
    }

    /// # Safety
    /// The CPU must have PMULL.
    #[target_feature(enable = "neon,aes")]
    #[allow(unused_unsafe)] // `vmull_p64` became safe to call here in Rust 1.87
    pub(super) unsafe fn ghash_update(hp: &[[u8; 16]; 8], y: &mut [u8; 16], data: &[u8]) {
        // SAFETY: `vmull_p64` only needs the PMULL feature, which the caller checked; all
        // memory access is through safe slices.
        unsafe {
            let h: [(u64, u64); 8] = core::array::from_fn(|k| rev_load(&hp[k]));
            let mut acc = rev_load(y);
            let mut chunks = data.chunks_exact(128);
            for c in &mut chunks {
                let (mut lo, mut mid, mut hi) = (0u128, 0u128, 0u128);
                for j in 0..8 {
                    let mut x = rev_load(c[16 * j..16 * j + 16].try_into().unwrap());
                    if j == 0 {
                        x = (x.0 ^ acc.0, x.1 ^ acc.1);
                    }
                    pmull_acc!(lo, mid, hi, x, h[7 - j]);
                }
                acc = finish(lo, mid, hi);
            }
            for c in chunks.remainder().chunks(16) {
                let mut t = [0u8; 16];
                t[..c.len()].copy_from_slice(c);
                let x = rev_load(&t);
                let (mut lo, mut mid, mut hi) = (0u128, 0u128, 0u128);
                pmull_acc!(lo, mid, hi, (x.0 ^ acc.0, x.1 ^ acc.1), h[0]);
                acc = finish(lo, mid, hi);
            }
            *y = rev_store(acc.0, acc.1);
        }
    }

    /// # Safety
    /// The CPU must have the ARMv8 AES instructions and PMULL; `nr` is 10 or 14.
    #[target_feature(enable = "neon,aes")]
    pub(super) unsafe fn gcm(
        rkb: &[[u8; 16]; 15],
        nr: usize,
        hp: &[[u8; 16]; 8],
        ctr: &mut [u8; 16],
        y: &mut [u8; 16],
        data: &mut [u8],
        encrypt: bool,
    ) {
        // SAFETY: NEON loads and stores read and write 16-byte local arrays; `ghash_update`
        // needs PMULL, which the caller checked.
        unsafe {
            let rk: [uint8x16_t; 15] = core::array::from_fn(|k| vld1q_u8(rkb[k].as_ptr()));
            let mut counter = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
            let mut blk = *ctr;
            let n = data.len();
            let mut i = 0;
            while i < n {
                let take = (n - i).min(64);
                // Up to four blocks of keystream at a time.
                let mut ks = [0u8; 64];
                let nb = take.div_ceil(16);
                let mut b = [vdupq_n_u8(0); 4];
                for v in b.iter_mut().take(nb) {
                    blk[12..].copy_from_slice(&counter.to_be_bytes());
                    counter = counter.wrapping_add(1);
                    *v = vld1q_u8(blk.as_ptr());
                }
                for k in &rk[..nr - 1] {
                    for v in b.iter_mut().take(nb) {
                        *v = vaesmcq_u8(vaeseq_u8(*v, *k));
                    }
                }
                for (j, v) in b.iter().take(nb).enumerate() {
                    let o = veorq_u8(vaeseq_u8(*v, rk[nr - 1]), rk[nr]);
                    vst1q_u8(ks[16 * j..].as_mut_ptr(), o);
                }
                let chunk = &mut data[i..i + take];
                if !encrypt {
                    ghash_update(hp, y, chunk);
                }
                for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                    *d ^= k;
                }
                if encrypt {
                    ghash_update(hp, y, chunk);
                }
                i += take;
            }
            ctr[12..].copy_from_slice(&counter.to_be_bytes());
        }
    }

    /// # Safety
    /// The CPU must have the ARMv8 SHA-2 instructions; `blocks.len()` is a multiple of 64.
    #[target_feature(enable = "neon,sha2")]
    pub(super) unsafe fn sha256(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: loads and stores of the 8-word state and of 16-byte pieces of whole 64-byte
        // blocks; `K256` has 64 entries.
        unsafe {
            let mut s0 = vld1q_u32(state.as_ptr());
            let mut s1 = vld1q_u32(state.as_ptr().add(4));
            for block in blocks.chunks_exact(64) {
                let (abcd, efgh) = (s0, s1);
                let mut w = [vdupq_n_u32(0); 16];
                for (j, wj) in w.iter_mut().take(4).enumerate() {
                    *wj = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16 * j))));
                }
                for g in 0..12 {
                    w[g + 4] = vsha256su1q_u32(vsha256su0q_u32(w[g], w[g + 1]), w[g + 2], w[g + 3]);
                }
                for (g, wg) in w.iter().enumerate() {
                    let wk = vaddq_u32(*wg, vld1q_u32(super::K256.as_ptr().add(4 * g)));
                    let t = s0;
                    s0 = vsha256hq_u32(s0, s1, wk);
                    s1 = vsha256h2q_u32(s1, t, wk);
                }
                s0 = vaddq_u32(s0, abcd);
                s1 = vaddq_u32(s1, efgh);
            }
            vst1q_u32(state.as_mut_ptr(), s0);
            vst1q_u32(state.as_mut_ptr().add(4), s1);
        }
    }
}

/// Fills `buf` from the operating system's cryptographically secure random source. Returns
/// false if the source failed (callers must treat that as fatal, never fall back to weaker
/// randomness).
pub fn os_random(buf: &mut [u8]) -> bool {
    os_rand::fill(buf)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod os_rand {
    extern "C" {
        fn getrandom(buf: *mut u8, buflen: usize, flags: u32) -> isize;
    }

    pub(super) fn fill(buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let rest = &mut buf[done..];
            // SAFETY: `rest` is a valid, writable region of `rest.len()` bytes; getrandom writes
            // at most that many and returns how many it wrote, or -1.
            let n = unsafe { getrandom(rest.as_mut_ptr(), rest.len(), 0) };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            done += n as usize;
        }
        true
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
mod os_rand {
    extern "C" {
        fn getentropy(buf: *mut u8, buflen: usize) -> i32;
    }

    pub(super) fn fill(buf: &mut [u8]) -> bool {
        for chunk in buf.chunks_mut(256) {
            // SAFETY: `chunk` is valid and writable for its length, which is at most 256, the
            // limit of getentropy.
            if unsafe { getentropy(chunk.as_mut_ptr(), chunk.len()) } != 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(windows)]
mod os_rand {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            len: u32,
            flags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;

    pub(super) fn fill(buf: &mut [u8]) -> bool {
        for chunk in buf.chunks_mut(1 << 30) {
            // SAFETY: a null algorithm handle with BCRYPT_USE_SYSTEM_PREFERRED_RNG is the
            // documented way to use the system RNG; `chunk` is valid and writable for its length,
            // which fits in u32.
            let status = unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status < 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    windows
)))]
mod os_rand {
    pub(super) fn fill(buf: &mut [u8]) -> bool {
        use std::io::Read;
        match std::fs::File::open("/dev/urandom") {
            Ok(mut f) => f.read_exact(buf).is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_fills() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        assert!(os_random(&mut a));
        assert!(os_random(&mut b));
        assert_ne!(a, b);
        let mut empty = [0u8; 0];
        assert!(os_random(&mut empty));
    }

    #[test]
    fn sha256_hardware_matches_known_digest() {
        // "abc", padded: the FIPS 180-4 example.
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;
        let mut st = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];
        if sha256_blocks(&mut st, &block) {
            assert_eq!(
                st,
                [
                    0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c,
                    0xb410ff61, 0xf20015ad
                ]
            );
        }
        assert!(!sha256_blocks(&mut st, &block[..63]));
    }

    #[test]
    fn aes_constructor_checks_round_count() {
        // The AES and GHASH vectors live in simoom-tls, which owns the key schedule.
        assert!(AesHw::new(&[[0u8; 16]; 12]).is_none());
        if has_aes() {
            assert!(AesHw::new(&[[0u8; 16]; 11]).is_some());
        }
    }
}

// ---- Kernels for simoom-tls's public-key arithmetic (added after the code above, kept
// self-contained: own feature detection, honours `disable_hardware`):
// - `opaque`: an optimization barrier for constant-time masks;
// - P-256 field and group-order Montgomery multiplication, X25519 field arithmetic and a
//   big-integer Montgomery multiplication (RSA) with MULX/ADCX/ADOX (BMI2 and ADX);
// - P-256 and X25519 additions and subtractions (ADC/SBB/CMOV, every x86-64 CPU);
// - Poly1305 with AVX2 (at the end of the file).

/// Returns `x` unchanged, hidden from the optimizer, so a mask derived from secret bits cannot
/// be turned back into a branch (LLVM may otherwise rewrite masked selection as a conditional
/// jump). Unlike `core::hint::black_box` the value stays in a register.
#[inline(always)]
pub fn opaque(x: u64) -> u64 {
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    {
        let mut x = x;
        // SAFETY: an empty asm block that only claims to read and write one register.
        unsafe {
            core::arch::asm!("/* {0} */", inout(reg) x, options(pure, nomem, nostack, preserves_flags))
        };
        x
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        core::hint::black_box(x)
    }
}

/// 0 = not yet detected, 1 = absent, 2 = present.
static MULX: AtomicU8 = AtomicU8::new(0);

/// True if the CPU has MULX (BMI2) and ADCX/ADOX (ADX), for the Montgomery kernels below.
#[inline]
pub fn has_mulx() -> bool {
    let mut v = MULX.load(Ordering::Relaxed);
    if v == 0 {
        #[cfg(target_arch = "x86_64")]
        let yes = crate::cpu::x86_features() & (crate::cpu::x86::BMI2 | crate::cpu::x86::ADX) == crate::cpu::x86::BMI2 | crate::cpu::x86::ADX;
        #[cfg(not(target_arch = "x86_64"))]
        let yes = false;
        v = if yes { 2 } else { 1 };
        MULX.store(v, Ordering::Relaxed);
    }
    v == 2 && DISABLED.load(Ordering::Relaxed) == 0
}

/// P-256 field multiplication in Montgomery form (R = 2^256): a * b * R^-1 mod p for a and b
/// below p = 2^256 - 2^224 + 2^192 + 2^96 - 1, in constant time; `None` without MULX/ADX. The
/// product uses the two ADX carry chains; the reduction uses the shape of p (the multiplier of
/// each step is the low limb itself, and q * p is shifts and subtractions, no multiplication).
#[inline]
pub fn p256_mul_mont(a: &[u64; 4], b: &[u64; 4]) -> Option<[u64; 4]> {
    if !has_mulx() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (r0, r1, r2, r3): (u64, u64, u64, u64);
        // SAFETY: `has_mulx()` was true (MULX, ADCX, ADOX). The block reads 4 limbs at `a` and
        // `b`, writes no memory, and declares every register it changes.
        unsafe {
            core::arch::asm!(
                "mov rdx, qword ptr [rdi]",
                "mulx r9, r8, qword ptr [rsi]",
                "mulx r10, rax, qword ptr [rsi + 8]",
                "add r9, rax",
                "mulx r11, rax, qword ptr [rsi + 16]",
                "adc r10, rax",
                "mulx r12, rax, qword ptr [rsi + 24]",
                "adc r11, rax",
                "adc r12, 0",
                "mov rdx, qword ptr [rdi + 8]",
                "xor eax, eax",
                "mov r13, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r9, rax",
                "adcx r10, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mov eax, 0",
                "adox r13, rax",
                "mov rdx, qword ptr [rdi + 16]",
                "xor eax, eax",
                "mov r14, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r13, rax",
                "adcx r14, rcx",
                "mov eax, 0",
                "adox r14, rax",
                "mov rdx, qword ptr [rdi + 24]",
                "xor eax, eax",
                "mov r15, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r13, rax",
                "adcx r14, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r14, rax",
                "adcx r15, rcx",
                "mov eax, 0",
                "adox r15, rax",
                "xor edi, edi",
                "mov rax, r8",
                "shl rax, 32",
                "mov rcx, r8",
                "shr rcx, 32",
                "mov rsi, r8",
                "sub rsi, rax",
                "mov rdx, r8",
                "sbb rdx, rcx",
                "add r9, rax",
                "adc r10, rcx",
                "adc r11, rsi",
                "adc r12, rdx",
                "adc r13, 0",
                "adc r14, 0",
                "adc r15, 0",
                "adc rdi, 0",
                "mov rax, r9",
                "shl rax, 32",
                "mov rcx, r9",
                "shr rcx, 32",
                "mov rsi, r9",
                "sub rsi, rax",
                "mov rdx, r9",
                "sbb rdx, rcx",
                "add r10, rax",
                "adc r11, rcx",
                "adc r12, rsi",
                "adc r13, rdx",
                "adc r14, 0",
                "adc r15, 0",
                "adc rdi, 0",
                "mov rax, r10",
                "shl rax, 32",
                "mov rcx, r10",
                "shr rcx, 32",
                "mov rsi, r10",
                "sub rsi, rax",
                "mov rdx, r10",
                "sbb rdx, rcx",
                "add r11, rax",
                "adc r12, rcx",
                "adc r13, rsi",
                "adc r14, rdx",
                "adc r15, 0",
                "adc rdi, 0",
                "mov rax, r11",
                "shl rax, 32",
                "mov rcx, r11",
                "shr rcx, 32",
                "mov rsi, r11",
                "sub rsi, rax",
                "mov rdx, r11",
                "sbb rdx, rcx",
                "add r12, rax",
                "adc r13, rcx",
                "adc r14, rsi",
                "adc r15, rdx",
                "adc rdi, 0",
                "mov rax, r12",
                "sub rax, -1",
                "mov rdx, r13",
                "mov ecx, 0xffffffff",
                "sbb rdx, rcx",
                "mov rcx, r14",
                "sbb rcx, 0",
                "mov rsi, r15",
                "movabs r8, 0xffffffff00000001",
                "sbb rsi, r8",
                "sbb rdi, 0",
                "cmovc rax, r12",
                "cmovc rdx, r13",
                "cmovc rcx, r14",
                "cmovc rsi, r15",
                inout("rsi") a.as_ptr() => r3,
                inout("rdi") b.as_ptr() => _,
                out("rax") r0,
                out("rdx") r1,
                out("rcx") r2,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(pure, readonly, nostack),
            );
        }
        Some([r0, r1, r2, r3])
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (a, b);
        None
    }
}

/// P-256 field squaring in Montgomery form: a * a * R^-1 mod p for a below p, in constant
/// time; `None` without MULX/ADX. Six cross products doubled plus four squares.
#[inline]
pub fn p256_sqr_mont(a: &[u64; 4]) -> Option<[u64; 4]> {
    if !has_mulx() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (r0, r1, r2, r3): (u64, u64, u64, u64);
        // SAFETY: `has_mulx()` was true (MULX, ADCX, ADOX). The block reads 4 limbs at `a`,
        // writes no memory, and declares every register it changes.
        unsafe {
            core::arch::asm!(
                "mov rdx, qword ptr [rsi]",
                "mulx r10, r9, qword ptr [rsi + 8]",
                "mulx r11, rax, qword ptr [rsi + 16]",
                "add r10, rax",
                "mulx r12, rax, qword ptr [rsi + 24]",
                "adc r11, rax",
                "adc r12, 0",
                "mov rdx, qword ptr [rsi + 8]",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "mulx r13, rdi, qword ptr [rsi + 24]",
                "add r11, rax",
                "adc r12, rcx",
                "adc r13, 0",
                "add r12, rdi",
                "adc r13, 0",
                "mov rdx, qword ptr [rsi + 16]",
                "mulx r14, rax, qword ptr [rsi + 24]",
                "add r13, rax",
                "adc r14, 0",
                "mov r15, 0",
                "add r9, r9",
                "adc r10, r10",
                "adc r11, r11",
                "adc r12, r12",
                "adc r13, r13",
                "adc r14, r14",
                "adc r15, r15",
                "mov rdx, qword ptr [rsi]",
                "mulx rcx, r8, rdx",
                "add r9, rcx",
                "mov rdx, qword ptr [rsi + 8]",
                "mulx rcx, rax, rdx",
                "adc r10, rax",
                "adc r11, rcx",
                "mov rdx, qword ptr [rsi + 16]",
                "mulx rcx, rax, rdx",
                "adc r12, rax",
                "adc r13, rcx",
                "mov rdx, qword ptr [rsi + 24]",
                "mulx rcx, rax, rdx",
                "adc r14, rax",
                "adc r15, rcx",
                "xor edi, edi",
                "mov rax, r8",
                "shl rax, 32",
                "mov rcx, r8",
                "shr rcx, 32",
                "mov rsi, r8",
                "sub rsi, rax",
                "mov rdx, r8",
                "sbb rdx, rcx",
                "add r9, rax",
                "adc r10, rcx",
                "adc r11, rsi",
                "adc r12, rdx",
                "adc r13, 0",
                "adc r14, 0",
                "adc r15, 0",
                "adc rdi, 0",
                "mov rax, r9",
                "shl rax, 32",
                "mov rcx, r9",
                "shr rcx, 32",
                "mov rsi, r9",
                "sub rsi, rax",
                "mov rdx, r9",
                "sbb rdx, rcx",
                "add r10, rax",
                "adc r11, rcx",
                "adc r12, rsi",
                "adc r13, rdx",
                "adc r14, 0",
                "adc r15, 0",
                "adc rdi, 0",
                "mov rax, r10",
                "shl rax, 32",
                "mov rcx, r10",
                "shr rcx, 32",
                "mov rsi, r10",
                "sub rsi, rax",
                "mov rdx, r10",
                "sbb rdx, rcx",
                "add r11, rax",
                "adc r12, rcx",
                "adc r13, rsi",
                "adc r14, rdx",
                "adc r15, 0",
                "adc rdi, 0",
                "mov rax, r11",
                "shl rax, 32",
                "mov rcx, r11",
                "shr rcx, 32",
                "mov rsi, r11",
                "sub rsi, rax",
                "mov rdx, r11",
                "sbb rdx, rcx",
                "add r12, rax",
                "adc r13, rcx",
                "adc r14, rsi",
                "adc r15, rdx",
                "adc rdi, 0",
                "mov rax, r12",
                "sub rax, -1",
                "mov rdx, r13",
                "mov ecx, 0xffffffff",
                "sbb rdx, rcx",
                "mov rcx, r14",
                "sbb rcx, 0",
                "mov rsi, r15",
                "movabs r8, 0xffffffff00000001",
                "sbb rsi, r8",
                "sbb rdi, 0",
                "cmovc rax, r12",
                "cmovc rdx, r13",
                "cmovc rcx, r14",
                "cmovc rsi, r15",
                inout("rsi") a.as_ptr() => r3,
                out("rdi") _,
                out("rax") r0,
                out("rdx") r1,
                out("rcx") r2,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(pure, readonly, nostack),
            );
        }
        Some([r0, r1, r2, r3])
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = a;
        None
    }
}

/// Multiplication modulo the P-256 group order n in Montgomery form: a * b * 2^-256 mod n for
/// a and b below n, in constant time; `None` without MULX/ADX.
#[inline]
pub fn p256_order_mul_mont(a: &[u64; 4], b: &[u64; 4]) -> Option<[u64; 4]> {
    if !has_mulx() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (r0, r1, r2, r3): (u64, u64, u64, u64);
        // SAFETY: `has_mulx()` was true (MULX, ADCX, ADOX). The block reads the 4-limb inputs,
        // writes no memory, and declares every register it changes.
        unsafe {
            core::arch::asm!(
                "mov rdx, qword ptr [rdi]",
                "mulx r9, r8, qword ptr [rsi]",
                "mulx r10, rax, qword ptr [rsi + 8]",
                "add r9, rax",
                "mulx r11, rax, qword ptr [rsi + 16]",
                "adc r10, rax",
                "mulx r12, rax, qword ptr [rsi + 24]",
                "adc r11, rax",
                "adc r12, 0",
                "mov rdx, qword ptr [rdi + 8]",
                "xor eax, eax",
                "mov r13, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r9, rax",
                "adcx r10, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mov eax, 0",
                "adox r13, rax",
                "mov rdx, qword ptr [rdi + 16]",
                "xor eax, eax",
                "mov r14, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r13, rax",
                "adcx r14, rcx",
                "mov eax, 0",
                "adox r14, rax",
                "mov rdx, qword ptr [rdi + 24]",
                "xor eax, eax",
                "mov r15, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r13, rax",
                "adcx r14, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r14, rax",
                "adcx r15, rcx",
                "mov eax, 0",
                "adox r15, rax",
                "xor edi, edi",
                "mov rdx, r8",
                "movabs rax, 0xccd1c8aaee00bc4f",
                "imul rdx, rax",
                "xor eax, eax",
                "movabs rax, 0xf3b9cac2fc632551",
                "mulx rcx, rax, rax",
                "adox r8, rax",
                "adcx r9, rcx",
                "movabs rax, 0xbce6faada7179e84",
                "mulx rcx, rax, rax",
                "adox r9, rax",
                "adcx r10, rcx",
                "movabs rax, 0xffffffffffffffff",
                "mulx rcx, rax, rax",
                "adox r10, rax",
                "adcx r11, rcx",
                "movabs rax, 0xffffffff00000000",
                "mulx rcx, rax, rax",
                "adox r11, rax",
                "adcx r12, rcx",
                "mov eax, 0",
                "adox r12, rax",
                "adcx r13, rax",
                "adox r13, rax",
                "adcx r14, rax",
                "adox r14, rax",
                "adcx r15, rax",
                "adox r15, rax",
                "adcx rdi, rax",
                "adox rdi, rax",
                "mov rdx, r9",
                "movabs rax, 0xccd1c8aaee00bc4f",
                "imul rdx, rax",
                "xor eax, eax",
                "movabs rax, 0xf3b9cac2fc632551",
                "mulx rcx, rax, rax",
                "adox r9, rax",
                "adcx r10, rcx",
                "movabs rax, 0xbce6faada7179e84",
                "mulx rcx, rax, rax",
                "adox r10, rax",
                "adcx r11, rcx",
                "movabs rax, 0xffffffffffffffff",
                "mulx rcx, rax, rax",
                "adox r11, rax",
                "adcx r12, rcx",
                "movabs rax, 0xffffffff00000000",
                "mulx rcx, rax, rax",
                "adox r12, rax",
                "adcx r13, rcx",
                "mov eax, 0",
                "adox r13, rax",
                "adcx r14, rax",
                "adox r14, rax",
                "adcx r15, rax",
                "adox r15, rax",
                "adcx rdi, rax",
                "adox rdi, rax",
                "mov rdx, r10",
                "movabs rax, 0xccd1c8aaee00bc4f",
                "imul rdx, rax",
                "xor eax, eax",
                "movabs rax, 0xf3b9cac2fc632551",
                "mulx rcx, rax, rax",
                "adox r10, rax",
                "adcx r11, rcx",
                "movabs rax, 0xbce6faada7179e84",
                "mulx rcx, rax, rax",
                "adox r11, rax",
                "adcx r12, rcx",
                "movabs rax, 0xffffffffffffffff",
                "mulx rcx, rax, rax",
                "adox r12, rax",
                "adcx r13, rcx",
                "movabs rax, 0xffffffff00000000",
                "mulx rcx, rax, rax",
                "adox r13, rax",
                "adcx r14, rcx",
                "mov eax, 0",
                "adox r14, rax",
                "adcx r15, rax",
                "adox r15, rax",
                "adcx rdi, rax",
                "adox rdi, rax",
                "mov rdx, r11",
                "movabs rax, 0xccd1c8aaee00bc4f",
                "imul rdx, rax",
                "xor eax, eax",
                "movabs rax, 0xf3b9cac2fc632551",
                "mulx rcx, rax, rax",
                "adox r11, rax",
                "adcx r12, rcx",
                "movabs rax, 0xbce6faada7179e84",
                "mulx rcx, rax, rax",
                "adox r12, rax",
                "adcx r13, rcx",
                "movabs rax, 0xffffffffffffffff",
                "mulx rcx, rax, rax",
                "adox r13, rax",
                "adcx r14, rcx",
                "movabs rax, 0xffffffff00000000",
                "mulx rcx, rax, rax",
                "adox r14, rax",
                "adcx r15, rcx",
                "mov eax, 0",
                "adox r15, rax",
                "adcx rdi, rax",
                "adox rdi, rax",
                "mov rax, r12",
                "movabs r8, 0xf3b9cac2fc632551",
                "sub rax, r8",
                "mov rdx, r13",
                "movabs r9, 0xbce6faada7179e84",
                "sbb rdx, r9",
                "mov rcx, r14",
                "sbb rcx, -1",
                "mov rsi, r15",
                "movabs r10, 0xffffffff00000000",
                "sbb rsi, r10",
                "sbb rdi, 0",
                "cmovc rax, r12",
                "cmovc rdx, r13",
                "cmovc rcx, r14",
                "cmovc rsi, r15",
                inout("rsi") a.as_ptr() => r3,
                inout("rdi") b.as_ptr() => _,
                out("rax") r0,
                out("rdx") r1,
                out("rcx") r2,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(pure, readonly, nostack),
            );
        }
        Some([r0, r1, r2, r3])
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (a, b);
        None
    }
}

/// P-256 field addition a + b mod p for a and b below p, in constant time (ADC, SBB and a CMOV
/// select; every x86-64 CPU has them). Values stay in registers.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn p256_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: reads the 4 limbs at `b`, writes no memory; all registers are operands.
    unsafe {
        core::arch::asm!(
            "add {r0}, qword ptr [{b}]",
            "adc {r1}, qword ptr [{b} + 8]",
            "adc {r2}, qword ptr [{b} + 16]",
            "adc {r3}, qword ptr [{b} + 24]",
            "sbb {c}, {c}",
            "mov {t0}, {r0}",
            "mov {t1}, {r1}",
            "mov {t2}, {r2}",
            "mov {t3}, {r3}",
            "sub {t0}, -1",
            "sbb {t1}, {p1}",
            "sbb {t2}, 0",
            "sbb {t3}, {p3}",
            "sbb {c}, 0",
            "cmovnc {r0}, {t0}",
            "cmovnc {r1}, {t1}",
            "cmovnc {r2}, {t2}",
            "cmovnc {r3}, {t3}",
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            b = in(reg) b.as_ptr(),
            p1 = in(reg) 0xffff_ffffu64,
            p3 = in(reg) 0xffff_ffff_0000_0001u64,
            c = out(reg) _,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// P-256 field subtraction a - b mod p for a and b below p, in constant time (see
/// [`p256_add`]): the borrow becomes a mask that selects p to add back.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn p256_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: reads the 4 limbs at `b`, writes no memory; all registers are operands.
    unsafe {
        core::arch::asm!(
            "sub {r0}, qword ptr [{b}]",
            "sbb {r1}, qword ptr [{b} + 8]",
            "sbb {r2}, qword ptr [{b} + 16]",
            "sbb {r3}, qword ptr [{b} + 24]",
            "sbb {m}, {m}",
            "mov {t1}, {m}",
            "and {t1}, {p1}",
            "mov {t3}, {m}",
            "and {t3}, {p3}",
            "add {r0}, {m}",
            "adc {r1}, {t1}",
            "adc {r2}, 0",
            "adc {r3}, {t3}",
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            b = in(reg) b.as_ptr(),
            p1 = in(reg) 0xffff_ffffu64,
            p3 = in(reg) 0xffff_ffff_0000_0001u64,
            m = out(reg) _,
            t1 = out(reg) _,
            t3 = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// Multiplication modulo p = 2^255 - 19 on 4 x 64-bit limbs, for any inputs below 2^256: the
/// result is below 2^256 and congruent to a * b (not fully reduced). Constant time; `None`
/// without MULX/ADX. The high half of the product is folded in times 38 (2^256 = 38 mod p).
#[inline]
pub fn fe25519_mul(a: &[u64; 4], b: &[u64; 4]) -> Option<[u64; 4]> {
    if !has_mulx() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (r0, r1, r2, r3): (u64, u64, u64, u64);
        // SAFETY: `has_mulx()` was true (MULX, ADCX, ADOX). The block reads the 4-limb inputs,
        // writes no memory, and declares every register it changes.
        unsafe {
            core::arch::asm!(
                "mov rdx, qword ptr [rdi]",
                "mulx r9, r8, qword ptr [rsi]",
                "mulx r10, rax, qword ptr [rsi + 8]",
                "add r9, rax",
                "mulx r11, rax, qword ptr [rsi + 16]",
                "adc r10, rax",
                "mulx r12, rax, qword ptr [rsi + 24]",
                "adc r11, rax",
                "adc r12, 0",
                "mov rdx, qword ptr [rdi + 8]",
                "xor eax, eax",
                "mov r13, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r9, rax",
                "adcx r10, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mov eax, 0",
                "adox r13, rax",
                "mov rdx, qword ptr [rdi + 16]",
                "xor eax, eax",
                "mov r14, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r13, rax",
                "adcx r14, rcx",
                "mov eax, 0",
                "adox r14, rax",
                "mov rdx, qword ptr [rdi + 24]",
                "xor eax, eax",
                "mov r15, 0",
                "mulx rcx, rax, qword ptr [rsi + 0]",
                "adox r11, rax",
                "adcx r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adox r12, rax",
                "adcx r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adox r13, rax",
                "adcx r14, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adox r14, rax",
                "adcx r15, rcx",
                "mov eax, 0",
                "adox r15, rax",
                "mov edx, 38",
                "xor eax, eax",
                "mulx rcx, rax, r12",
                "adox r8, rax",
                "adcx r9, rcx",
                "mulx rcx, rax, r13",
                "adox r9, rax",
                "adcx r10, rcx",
                "mulx rcx, rax, r14",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, r15",
                "adox r11, rax",
                "mov eax, 0",
                "adcx rcx, rax",
                "adox rcx, rax",
                "imul rcx, rcx, 38",
                "add r8, rcx",
                "adc r9, 0",
                "adc r10, 0",
                "adc r11, 0",
                "sbb rax, rax",
                "and eax, 38",
                "add r8, rax",
                in("rsi") a.as_ptr(),
                in("rdi") b.as_ptr(),
                out("r8") r0,
                out("r9") r1,
                out("r10") r2,
                out("r11") r3,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(pure, readonly, nostack),
            );
        }
        Some([r0, r1, r2, r3])
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (a, b);
        None
    }
}

/// Squaring modulo 2^255 - 19 (see [`fe25519_mul`]).
#[inline]
pub fn fe25519_sqr(a: &[u64; 4]) -> Option<[u64; 4]> {
    if !has_mulx() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (r0, r1, r2, r3): (u64, u64, u64, u64);
        // SAFETY: `has_mulx()` was true (MULX, ADCX, ADOX). The block reads the 4-limb inputs,
        // writes no memory, and declares every register it changes.
        unsafe {
            core::arch::asm!(
                "mov rdx, qword ptr [rsi]",
                "mulx r10, r9, qword ptr [rsi + 8]",
                "mulx r11, rax, qword ptr [rsi + 16]",
                "add r10, rax",
                "mulx r12, rax, qword ptr [rsi + 24]",
                "adc r11, rax",
                "adc r12, 0",
                "mov rdx, qword ptr [rsi + 8]",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "mulx r13, rdi, qword ptr [rsi + 24]",
                "add r11, rax",
                "adc r12, rcx",
                "adc r13, 0",
                "add r12, rdi",
                "adc r13, 0",
                "mov rdx, qword ptr [rsi + 16]",
                "mulx r14, rax, qword ptr [rsi + 24]",
                "add r13, rax",
                "adc r14, 0",
                "mov r15, 0",
                "add r9, r9",
                "adc r10, r10",
                "adc r11, r11",
                "adc r12, r12",
                "adc r13, r13",
                "adc r14, r14",
                "adc r15, r15",
                "mov rdx, qword ptr [rsi]",
                "mulx rcx, r8, rdx",
                "add r9, rcx",
                "mov rdx, qword ptr [rsi + 8]",
                "mulx rcx, rax, rdx",
                "adc r10, rax",
                "adc r11, rcx",
                "mov rdx, qword ptr [rsi + 16]",
                "mulx rcx, rax, rdx",
                "adc r12, rax",
                "adc r13, rcx",
                "mov rdx, qword ptr [rsi + 24]",
                "mulx rcx, rax, rdx",
                "adc r14, rax",
                "adc r15, rcx",
                "mov edx, 38",
                "xor eax, eax",
                "mulx rcx, rax, r12",
                "adox r8, rax",
                "adcx r9, rcx",
                "mulx rcx, rax, r13",
                "adox r9, rax",
                "adcx r10, rcx",
                "mulx rcx, rax, r14",
                "adox r10, rax",
                "adcx r11, rcx",
                "mulx rcx, rax, r15",
                "adox r11, rax",
                "mov eax, 0",
                "adcx rcx, rax",
                "adox rcx, rax",
                "imul rcx, rcx, 38",
                "add r8, rcx",
                "adc r9, 0",
                "adc r10, 0",
                "adc r11, 0",
                "sbb rax, rax",
                "and eax, 38",
                "add r8, rax",
                in("rsi") a.as_ptr(),
                out("rdi") _,
                out("r8") r0,
                out("r9") r1,
                out("r10") r2,
                out("r11") r3,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(pure, readonly, nostack),
            );
        }
        Some([r0, r1, r2, r3])
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = a;
        None
    }
}

/// a * 121666 modulo 2^255 - 19 on 4 x 64-bit limbs (see [`fe25519_mul`]); the X25519 ladder's
/// (A + 2) / 4 constant. `None` without MULX.
#[inline]
pub fn fe25519_mul121666(a: &[u64; 4]) -> Option<[u64; 4]> {
    if !has_mulx() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (r0, r1, r2, r3): (u64, u64, u64, u64);
        // SAFETY: `has_mulx()` was true (MULX). Reads the 4 limbs at `a`, writes no memory; all
        // registers are operands.
        unsafe {
            core::arch::asm!(
                "mulx {r1}, {r0}, qword ptr [{a}]",
                "mulx {r2}, {t}, qword ptr [{a} + 8]",
                "add {r1}, {t}",
                "mulx {r3}, {t}, qword ptr [{a} + 16]",
                "adc {r2}, {t}",
                "mulx {h}, {t}, qword ptr [{a} + 24]",
                "adc {r3}, {t}",
                "adc {h}, 0",
                "imul {h}, {h}, 38",
                "add {r0}, {h}",
                "adc {r1}, 0",
                "adc {r2}, 0",
                "adc {r3}, 0",
                "sbb {t}, {t}",
                "and {t}, 38",
                "add {r0}, {t}",
                a = in(reg) a.as_ptr(),
                in("rdx") 121666u64,
                r0 = out(reg) r0,
                r1 = out(reg) r1,
                r2 = out(reg) r2,
                r3 = out(reg) r3,
                t = out(reg) _,
                h = out(reg) _,
                options(pure, readonly, nostack),
            );
        }
        Some([r0, r1, r2, r3])
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = a;
        None
    }
}

/// a + b modulo 2^255 - 19 on 4 x 64-bit limbs, for inputs below 2^256 (result below 2^256,
/// not fully reduced): a carry out of bit 256 is folded back as 38, twice. Constant time.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn fe25519_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: reads the 4 limbs at `b`, writes no memory; all registers are operands.
    unsafe {
        core::arch::asm!(
            "add {r0}, qword ptr [{b}]",
            "adc {r1}, qword ptr [{b} + 8]",
            "adc {r2}, qword ptr [{b} + 16]",
            "adc {r3}, qword ptr [{b} + 24]",
            "sbb {c}, {c}",
            "and {c}, 38",
            "add {r0}, {c}",
            "adc {r1}, 0",
            "adc {r2}, 0",
            "adc {r3}, 0",
            "sbb {c}, {c}",
            "and {c}, 38",
            "add {r0}, {c}",
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            b = in(reg) b.as_ptr(),
            c = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// a - b modulo 2^255 - 19 on 4 x 64-bit limbs (see [`fe25519_add`]): a borrow is folded back
/// as -38, twice.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn fe25519_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: reads the 4 limbs at `b`, writes no memory; all registers are operands.
    unsafe {
        core::arch::asm!(
            "sub {r0}, qword ptr [{b}]",
            "sbb {r1}, qword ptr [{b} + 8]",
            "sbb {r2}, qword ptr [{b} + 16]",
            "sbb {r3}, qword ptr [{b} + 24]",
            "sbb {c}, {c}",
            "and {c}, 38",
            "sub {r0}, {c}",
            "sbb {r1}, 0",
            "sbb {r2}, 0",
            "sbb {r3}, 0",
            "sbb {c}, {c}",
            "and {c}, 38",
            "sub {r0}, {c}",
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            b = in(reg) b.as_ptr(),
            c = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// The core of a Montgomery multiplication for big integers with MULX/ADCX/ADOX (interleaved
/// CIOS, four limbs per loop step): leaves t = a * b * 2^(-64 n) mod m, plus possibly m, in
/// `t[..n]` and its top bit in `t[n]`, where n = m.len(); the caller makes the final
/// conditional subtraction. Requires n a non-zero multiple of 4, `a` and `b` of n limbs below
/// m, `t` at least n + 2 limbs (overwritten), and `m0inv` = -m^-1 mod 2^64. Returns false
/// (and does nothing) without MULX/ADX or when the sizes do not fit. Constant time.
pub fn bigint_mont_mul(t: &mut [u64], a: &[u64], b: &[u64], m: &[u64], m0inv: u64) -> bool {
    let n = m.len();
    if !has_mulx() || n == 0 || n % 4 != 0 || a.len() != n || b.len() != n || t.len() < n + 2 {
        return false;
    }
    t[..n + 2].fill(0);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = m0inv;
    #[cfg(target_arch = "x86_64")]
    if n == 16 {
        // 1024-bit moduli (RSA-2048 CRT halves): the same steps with straight-line passes.
        // SAFETY: as below, with n = 16.
        unsafe {
            core::arch::asm!(
            "2:",
            "mov rdx, qword ptr [rdi]",
            "xor r13d, r13d",
            "mulx r12, rax, qword ptr [rsi + 0]",
            "adcx rax, qword ptr [r9 + 0]",
            "adox rax, r13",
            "mov qword ptr [r9 + 0], rax",
            "mulx r13, rax, qword ptr [rsi + 8]",
            "adcx rax, qword ptr [r9 + 8]",
            "adox rax, r12",
            "mov qword ptr [r9 + 8], rax",
            "mulx r12, rax, qword ptr [rsi + 16]",
            "adcx rax, qword ptr [r9 + 16]",
            "adox rax, r13",
            "mov qword ptr [r9 + 16], rax",
            "mulx r13, rax, qword ptr [rsi + 24]",
            "adcx rax, qword ptr [r9 + 24]",
            "adox rax, r12",
            "mov qword ptr [r9 + 24], rax",
            "mulx r12, rax, qword ptr [rsi + 32]",
            "adcx rax, qword ptr [r9 + 32]",
            "adox rax, r13",
            "mov qword ptr [r9 + 32], rax",
            "mulx r13, rax, qword ptr [rsi + 40]",
            "adcx rax, qword ptr [r9 + 40]",
            "adox rax, r12",
            "mov qword ptr [r9 + 40], rax",
            "mulx r12, rax, qword ptr [rsi + 48]",
            "adcx rax, qword ptr [r9 + 48]",
            "adox rax, r13",
            "mov qword ptr [r9 + 48], rax",
            "mulx r13, rax, qword ptr [rsi + 56]",
            "adcx rax, qword ptr [r9 + 56]",
            "adox rax, r12",
            "mov qword ptr [r9 + 56], rax",
            "mulx r12, rax, qword ptr [rsi + 64]",
            "adcx rax, qword ptr [r9 + 64]",
            "adox rax, r13",
            "mov qword ptr [r9 + 64], rax",
            "mulx r13, rax, qword ptr [rsi + 72]",
            "adcx rax, qword ptr [r9 + 72]",
            "adox rax, r12",
            "mov qword ptr [r9 + 72], rax",
            "mulx r12, rax, qword ptr [rsi + 80]",
            "adcx rax, qword ptr [r9 + 80]",
            "adox rax, r13",
            "mov qword ptr [r9 + 80], rax",
            "mulx r13, rax, qword ptr [rsi + 88]",
            "adcx rax, qword ptr [r9 + 88]",
            "adox rax, r12",
            "mov qword ptr [r9 + 88], rax",
            "mulx r12, rax, qword ptr [rsi + 96]",
            "adcx rax, qword ptr [r9 + 96]",
            "adox rax, r13",
            "mov qword ptr [r9 + 96], rax",
            "mulx r13, rax, qword ptr [rsi + 104]",
            "adcx rax, qword ptr [r9 + 104]",
            "adox rax, r12",
            "mov qword ptr [r9 + 104], rax",
            "mulx r12, rax, qword ptr [rsi + 112]",
            "adcx rax, qword ptr [r9 + 112]",
            "adox rax, r13",
            "mov qword ptr [r9 + 112], rax",
            "mulx r13, rax, qword ptr [rsi + 120]",
            "adcx rax, qword ptr [r9 + 120]",
            "adox rax, r12",
            "mov qword ptr [r9 + 120], rax",
            "mov rax, qword ptr [r9 + 128]",
            "adcx rax, r13",
            "mov r14d, 0",
            "adox rax, r14",
            "mov qword ptr [r9 + 128], rax",
            "mov rax, qword ptr [r9 + 136]",
            "adcx rax, r14",
            "adox rax, r14",
            "mov qword ptr [r9 + 136], rax",
            "mov rdx, qword ptr [r9]",
            "imul rdx, r11",
            "xor r13d, r13d",
            "mulx r12, rax, qword ptr [r8 + 0]",
            "adcx rax, qword ptr [r9 + 0]",
            "adox rax, r13",
            "mulx r13, rax, qword ptr [r8 + 8]",
            "adcx rax, qword ptr [r9 + 8]",
            "adox rax, r12",
            "mov qword ptr [r9 + 0], rax",
            "mulx r12, rax, qword ptr [r8 + 16]",
            "adcx rax, qword ptr [r9 + 16]",
            "adox rax, r13",
            "mov qword ptr [r9 + 8], rax",
            "mulx r13, rax, qword ptr [r8 + 24]",
            "adcx rax, qword ptr [r9 + 24]",
            "adox rax, r12",
            "mov qword ptr [r9 + 16], rax",
            "mulx r12, rax, qword ptr [r8 + 32]",
            "adcx rax, qword ptr [r9 + 32]",
            "adox rax, r13",
            "mov qword ptr [r9 + 24], rax",
            "mulx r13, rax, qword ptr [r8 + 40]",
            "adcx rax, qword ptr [r9 + 40]",
            "adox rax, r12",
            "mov qword ptr [r9 + 32], rax",
            "mulx r12, rax, qword ptr [r8 + 48]",
            "adcx rax, qword ptr [r9 + 48]",
            "adox rax, r13",
            "mov qword ptr [r9 + 40], rax",
            "mulx r13, rax, qword ptr [r8 + 56]",
            "adcx rax, qword ptr [r9 + 56]",
            "adox rax, r12",
            "mov qword ptr [r9 + 48], rax",
            "mulx r12, rax, qword ptr [r8 + 64]",
            "adcx rax, qword ptr [r9 + 64]",
            "adox rax, r13",
            "mov qword ptr [r9 + 56], rax",
            "mulx r13, rax, qword ptr [r8 + 72]",
            "adcx rax, qword ptr [r9 + 72]",
            "adox rax, r12",
            "mov qword ptr [r9 + 64], rax",
            "mulx r12, rax, qword ptr [r8 + 80]",
            "adcx rax, qword ptr [r9 + 80]",
            "adox rax, r13",
            "mov qword ptr [r9 + 72], rax",
            "mulx r13, rax, qword ptr [r8 + 88]",
            "adcx rax, qword ptr [r9 + 88]",
            "adox rax, r12",
            "mov qword ptr [r9 + 80], rax",
            "mulx r12, rax, qword ptr [r8 + 96]",
            "adcx rax, qword ptr [r9 + 96]",
            "adox rax, r13",
            "mov qword ptr [r9 + 88], rax",
            "mulx r13, rax, qword ptr [r8 + 104]",
            "adcx rax, qword ptr [r9 + 104]",
            "adox rax, r12",
            "mov qword ptr [r9 + 96], rax",
            "mulx r12, rax, qword ptr [r8 + 112]",
            "adcx rax, qword ptr [r9 + 112]",
            "adox rax, r13",
            "mov qword ptr [r9 + 104], rax",
            "mulx r13, rax, qword ptr [r8 + 120]",
            "adcx rax, qword ptr [r9 + 120]",
            "adox rax, r12",
            "mov qword ptr [r9 + 112], rax",
            "mov rax, qword ptr [r9 + 128]",
            "adcx rax, r13",
            "mov r14d, 0",
            "adox rax, r14",
            "mov qword ptr [r9 + 120], rax",
            "mov rax, qword ptr [r9 + 136]",
            "adcx rax, r14",
            "adox rax, r14",
            "mov qword ptr [r9 + 128], rax",
            "mov qword ptr [r9 + 136], r14",
            "lea rdi, [rdi + 8]",
            "dec r15",
            "jnz 2b",
                in("rsi") a.as_ptr(),
                inout("rdi") b.as_ptr() => _,
                in("r8") m.as_ptr(),
                in("r9") t.as_mut_ptr(),
                in("r11") m0inv,
                inout("r15") n => _,
                out("rax") _,
                out("rdx") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                options(nostack),
            );
        }
        return true;
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `has_mulx()` was true (MULX, ADCX, ADOX). The block reads n limbs at `a`, `b`
    // and `m`, reads and writes the first n + 2 limbs of `t` (the offsets used are below
    // 8 (n + 2) bytes; the shifted stores write t[j - 1] for j >= 1), and declares every
    // register it changes. Labels are local numeric labels.
    unsafe {
        core::arch::asm!(
            "2:",
            // ---- t += a * b[i]
            "mov rdx, qword ptr [rdi]",
            "mov rcx, r10",
            "shr rcx, 2",
            "xor r14d, r14d",
            "xor r13d, r13d",
            "3:",
            "mulx r12, rax, qword ptr [rsi + r14]",
            "adcx rax, qword ptr [r9 + r14]",
            "adox rax, r13",
            "mov qword ptr [r9 + r14], rax",
            "mulx r13, rax, qword ptr [rsi + r14 + 8]",
            "adcx rax, qword ptr [r9 + r14 + 8]",
            "adox rax, r12",
            "mov qword ptr [r9 + r14 + 8], rax",
            "mulx r12, rax, qword ptr [rsi + r14 + 16]",
            "adcx rax, qword ptr [r9 + r14 + 16]",
            "adox rax, r13",
            "mov qword ptr [r9 + r14 + 16], rax",
            "mulx r13, rax, qword ptr [rsi + r14 + 24]",
            "adcx rax, qword ptr [r9 + r14 + 24]",
            "adox rax, r12",
            "mov qword ptr [r9 + r14 + 24], rax",
            "lea r14, [r14 + 32]",
            "lea rcx, [rcx - 1]",
            "jrcxz 4f",
            "jmp 3b",
            "4:",
            "mov rax, qword ptr [r9 + r14]",
            "adcx rax, r13",
            "mov r12d, 0",
            "adox rax, r12",
            "mov qword ptr [r9 + r14], rax",
            "mov rax, qword ptr [r9 + r14 + 8]",
            "adcx rax, r12",
            "adox rax, r12",
            "mov qword ptr [r9 + r14 + 8], rax",
            // ---- t = (t + q * m) / 2^64 with q = t[0] * m0inv
            "mov rdx, qword ptr [r9]",
            "imul rdx, r11",
            "mov rcx, r10",
            "shr rcx, 2",
            "xor r14d, r14d",
            "xor r13d, r13d",
            "mulx r12, rax, qword ptr [r8]",
            "adcx rax, qword ptr [r9]",
            "adox rax, r13",
            "mulx r13, rax, qword ptr [r8 + 8]",
            "adcx rax, qword ptr [r9 + 8]",
            "adox rax, r12",
            "mov qword ptr [r9], rax",
            "mulx r12, rax, qword ptr [r8 + 16]",
            "adcx rax, qword ptr [r9 + 16]",
            "adox rax, r13",
            "mov qword ptr [r9 + 8], rax",
            "mulx r13, rax, qword ptr [r8 + 24]",
            "adcx rax, qword ptr [r9 + 24]",
            "adox rax, r12",
            "mov qword ptr [r9 + 16], rax",
            "lea r14, [r14 + 32]",
            "lea rcx, [rcx - 1]",
            "jrcxz 6f",
            "5:",
            "mulx r12, rax, qword ptr [r8 + r14]",
            "adcx rax, qword ptr [r9 + r14]",
            "adox rax, r13",
            "mov qword ptr [r9 + r14 - 8], rax",
            "mulx r13, rax, qword ptr [r8 + r14 + 8]",
            "adcx rax, qword ptr [r9 + r14 + 8]",
            "adox rax, r12",
            "mov qword ptr [r9 + r14], rax",
            "mulx r12, rax, qword ptr [r8 + r14 + 16]",
            "adcx rax, qword ptr [r9 + r14 + 16]",
            "adox rax, r13",
            "mov qword ptr [r9 + r14 + 8], rax",
            "mulx r13, rax, qword ptr [r8 + r14 + 24]",
            "adcx rax, qword ptr [r9 + r14 + 24]",
            "adox rax, r12",
            "mov qword ptr [r9 + r14 + 16], rax",
            "lea r14, [r14 + 32]",
            "lea rcx, [rcx - 1]",
            "jrcxz 6f",
            "jmp 5b",
            "6:",
            "mov rax, qword ptr [r9 + r14]",
            "adcx rax, r13",
            "mov r12d, 0",
            "adox rax, r12",
            "mov qword ptr [r9 + r14 - 8], rax",
            "mov rax, qword ptr [r9 + r14 + 8]",
            "adcx rax, r12",
            "adox rax, r12",
            "mov qword ptr [r9 + r14], rax",
            "mov qword ptr [r9 + r14 + 8], r12",
            "lea rdi, [rdi + 8]",
            "dec r15",
            "jnz 2b",
            in("rsi") a.as_ptr(),
            inout("rdi") b.as_ptr() => _,
            in("r8") m.as_ptr(),
            in("r9") t.as_mut_ptr(),
            in("r10") n,
            in("r11") m0inv,
            inout("r15") n => _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            options(nostack),
        );
    }
    true
}

#[cfg(test)]
mod bignum_tests {
    use super::*;

    /// Portable reference: a * b * 2^-256 mod m by bit-serial reduction.
    fn reference(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
        // t = a * b (512 bits)
        let mut t = [0u64; 9];
        for i in 0..4 {
            let mut c = 0u128;
            for j in 0..4 {
                let v = t[i + j] as u128 + a[i] as u128 * b[j] as u128 + c;
                t[i + j] = v as u64;
                c = v >> 64;
            }
            t[i + 4] = c as u64;
        }
        // divide by 2^256 modulo m: 256 halvings (add m when odd)
        for _ in 0..256 {
            if t[0] & 1 == 1 {
                let mut c = 0u128;
                for j in 0..9 {
                    let v = t[j] as u128 + if j < 4 { m[j] as u128 } else { 0 } + c;
                    t[j] = v as u64;
                    c = v >> 64;
                }
            }
            for j in 0..8 {
                t[j] = (t[j] >> 1) | (t[j + 1] << 63);
            }
            t[8] >>= 1;
        }
        // now t < 2m: subtract once if needed
        let ge = t[4] != 0
            || (0..4)
                .rev()
                .map(|j| (t[j], m[j]))
                .find(|(x, y)| x != y)
                .is_none_or(|(x, y)| x > y);
        if ge {
            let mut br = 0i128;
            for j in 0..4 {
                let v = t[j] as i128 - m[j] as i128 + br;
                t[j] = v as u64;
                br = v >> 64;
            }
        }
        [t[0], t[1], t[2], t[3]]
    }

    #[test]
    fn fe25519_kernels_match_reference() {
        if !has_mulx() {
            return;
        }
        let p = [
            0xffff_ffff_ffff_ffed,
            u64::MAX,
            u64::MAX,
            0x7fff_ffff_ffff_ffff,
        ];
        // the canonical residue of x < 2^256 (< 3p)
        let canon = |x: [u64; 4]| -> [u64; 4] {
            let mut x = x;
            for _ in 0..2 {
                let ge = (0..4)
                    .rev()
                    .map(|j| (x[j], p[j]))
                    .find(|(a, b)| a != b)
                    .is_none_or(|(a, b)| a > b);
                if ge {
                    let mut br = 0i128;
                    for j in 0..4 {
                        let v = x[j] as i128 - p[j] as i128 + br;
                        x[j] = v as u64;
                        br = v >> 64;
                    }
                }
            }
            x
        };
        let mut seed = 0x0bad_5eed_1234_5678u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut vals = vec![
            [0u64; 4],
            [1, 0, 0, 0],
            p,
            [u64::MAX; 4],
            [u64::MAX - 37, u64::MAX, u64::MAX, u64::MAX],
            [38, 0, 0, 0],
        ];
        for _ in 0..2000 {
            vals.push([next(), next(), next(), next()]);
        }
        // reference(x, y) = x y 2^-256 mod p, so reference(c, 1) == reference(a, b) iff c = a b
        let one = [1u64, 0, 0, 0];
        for (i, a) in vals.iter().enumerate() {
            let b = &vals[(i * 11 + 5) % vals.len()];
            let (ca, cb) = (canon(*a), canon(*b));
            let m = fe25519_mul(a, b).unwrap();
            assert_eq!(
                reference(&canon(m), &one, &p),
                reference(&ca, &cb, &p),
                "mul {a:x?} {b:x?}"
            );
            let s = fe25519_sqr(a).unwrap();
            assert_eq!(
                reference(&canon(s), &one, &p),
                reference(&ca, &ca, &p),
                "sqr {a:x?}"
            );
            let k = fe25519_mul121666(a).unwrap();
            assert_eq!(
                reference(&canon(k), &one, &p),
                reference(&ca, &[121666, 0, 0, 0], &p),
                "mul121666 {a:x?}"
            );
            #[cfg(target_arch = "x86_64")]
            {
                let sum = canon(fe25519_add(a, b));
                let diff = canon(fe25519_sub(a, b));
                assert_eq!(canon(fe25519_sub(&sum, &cb)), ca);
                assert_eq!(canon(fe25519_add(&diff, &cb)), ca);
                assert_eq!(canon(fe25519_add(&fe25519_sub(&[0; 4], b), b)), [0; 4]);
            }
        }
    }

    #[test]
    fn p256_kernels_match_reference() {
        if !has_mulx() {
            return;
        }
        let p = [
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_ffff,
            0,
            0xffff_ffff_0000_0001,
        ];
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut pm1 = p;
        pm1[0] -= 1;
        let mut vals = vec![
            [0u64; 4],
            [1, 0, 0, 0],
            pm1,
            [u64::MAX, u64::MAX, u64::MAX, 0xffff_ffff_0000_0000],
        ];
        for _ in 0..2000 {
            let mut x = [next(), next(), next(), next()];
            if x[3] >= p[3] {
                x[3] = p[3] - 1;
            }
            vals.push(x);
        }
        for (i, a) in vals.iter().enumerate() {
            assert_eq!(p256_sqr_mont(a).unwrap(), reference(a, a, &p), "{a:x?}");
            let b = &vals[(i * 7 + 3) % vals.len()];
            assert_eq!(
                p256_mul_mont(a, b).unwrap(),
                reference(a, b, &p),
                "{a:x?} {b:x?}"
            );
            assert_eq!(p256_mul_mont(a, &pm1).unwrap(), reference(a, &pm1, &p));
            #[cfg(target_arch = "x86_64")]
            {
                // a + b and a - b against u128 arithmetic modulo p
                let (s, d) = (p256_add(a, b), p256_sub(a, b));
                let wide = |x: &[u64; 4]| -> [u128; 4] { x.map(|v| v as u128) };
                let (aw, bw) = (wide(a), wide(b));
                let mut sum = [0u64; 5];
                let mut c = 0u128;
                for j in 0..4 {
                    let v = aw[j] + bw[j] + c;
                    sum[j] = v as u64;
                    c = v >> 64;
                }
                sum[4] = c as u64;
                let ge = sum[4] != 0
                    || (0..4)
                        .rev()
                        .map(|j| (sum[j], p[j]))
                        .find(|(x, y)| x != y)
                        .is_none_or(|(x, y)| x > y);
                if ge {
                    let mut br = 0i128;
                    for j in 0..4 {
                        let v = sum[j] as i128 - p[j] as i128 + br;
                        sum[j] = v as u64;
                        br = v >> 64;
                    }
                }
                assert_eq!(s, [sum[0], sum[1], sum[2], sum[3]]);
                assert_eq!(p256_add(&d, b), *a, "a - b + b");
            }
        }
        let n = [
            0xf3b9_cac2_fc63_2551,
            0xbce6_faad_a717_9e84,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_0000_0000,
        ];
        let mut nm1 = n;
        nm1[0] -= 1;
        vals[2] = nm1;
        for v in vals.iter_mut().skip(3) {
            if v[3] >= n[3] {
                v[3] = n[3] - 1;
            }
        }
        for (i, a) in vals.iter().enumerate() {
            assert_eq!(
                p256_order_mul_mont(a, a).unwrap(),
                reference(a, a, &n),
                "{a:x?}"
            );
            let b = &vals[(i * 5 + 1) % vals.len()];
            assert_eq!(
                p256_order_mul_mont(a, b).unwrap(),
                reference(a, b, &n),
                "{a:x?} {b:x?}"
            );
            assert_eq!(
                p256_order_mul_mont(a, &nm1).unwrap(),
                reference(a, &nm1, &n)
            );
        }
    }
}

#[cfg(test)]
mod bignum_timing {
    #[test]
    #[ignore]
    fn kernel_latency() {
        let mut a = [1u64, 2, 3, 4];
        let b = [5u64, 6, 7, 8];
        let n = 20_000_000;
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = super::p256_mul_mont(&a, &b).unwrap();
        }
        println!(
            "p256_mul_mont {:.2} ns",
            t.elapsed().as_nanos() as f64 / n as f64
        );
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = super::p256_sqr_mont(&a).unwrap();
        }
        println!(
            "p256_sqr_mont {:.2} ns",
            t.elapsed().as_nanos() as f64 / n as f64
        );
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = super::p256_order_mul_mont(&a, &b).unwrap();
        }
        println!(
            "order_mul {:.2} ns",
            t.elapsed().as_nanos() as f64 / n as f64
        );
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = super::fe25519_mul(&a, &b).unwrap();
        }
        println!(
            "fe25519_mul latency {:.2} ns",
            t.elapsed().as_nanos() as f64 / n as f64
        );
        let mut c = [9u64, 8, 7, 6];
        let mut d = [3u64, 1, 4, 1];
        let mut e = [2u64, 7, 1, 8];
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = super::fe25519_mul(&a, &b).unwrap();
            c = super::fe25519_mul(&c, &b).unwrap();
            d = super::fe25519_mul(&d, &b).unwrap();
            e = super::fe25519_mul(&e, &b).unwrap();
        }
        println!(
            "fe25519_mul 4 chains {:.2} ns per mul {:?}",
            t.elapsed().as_nanos() as f64 / n as f64 / 4.0,
            (a[0] ^ c[0] ^ d[0] ^ e[0])
        );
        let t = std::time::Instant::now();
        let mut x = 1u64;
        for _ in 0..n {
            x = std::hint::black_box(x.wrapping_mul(3).wrapping_add(1));
        }
        println!(
            "calibration (black_box mul-add) {:.2} ns {x}",
            t.elapsed().as_nanos() as f64 / n as f64
        );
    }
}

// ---- Poly1305 with AVX2 (for simoom-tls). Self-contained.

/// Absorbs the longest prefix of `data` that is a whole number of 64-byte groups into the
/// Poly1305 accumulator, with AVX2: four 16-byte blocks (each with the 2^128 bit) per step in
/// four lanes of radix-2^26 limbs, Horner's rule with r^4 in each lane and a final
/// multiplication of the lanes by r^4, r^3, r^2 and r. `h` is the accumulator and `rpow` holds
/// r, r^2, r^3, r^4, all as five 26-bit limbs (limbs a little above 2^26 are fine; the result
/// has the same form). Returns the number of bytes absorbed: 0 without AVX2. Constant time.
pub fn poly1305_blocks(h: &mut [u64; 5], rpow: &[[u64; 5]; 4], data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if features() & F_SIMD8 != 0 && data.len() >= 64 {
            let n = data.len() / 64 * 64;
            // SAFETY: F_SIMD8 means the CPU has AVX2; `n` is a non-zero multiple of 64 and at
            // most `data.len()`.
            unsafe { x86_poly::blocks(h, rpow, &data[..n]) };
            return n;
        }
    }
    let _ = (h, rpow, data);
    0
}

#[cfg(target_arch = "x86_64")]
mod x86_poly {
    use core::arch::x86_64::*;

    macro_rules! m {
        ($x:expr, $y:expr) => {
            _mm256_mul_epu32($x, $y)
        };
    }
    macro_rules! add {
        ($x:expr, $y:expr) => {
            _mm256_add_epi64($x, $y)
        };
    }

    /// d = a * r mod 2^130 - 5 per lane, unreduced (s = 5 r).
    ///
    /// # Safety
    /// The CPU must have AVX2.
    #[target_feature(enable = "avx2")]
    #[inline]
    #[allow(unused_unsafe)] // the intrinsics are safe to call here from Rust 1.87
    unsafe fn mul(a: &[__m256i; 5], r: &[__m256i; 5], s: &[__m256i; 5]) -> [__m256i; 5] {
        // SAFETY: AVX2 is available (the caller's contract); register-only intrinsics.
        unsafe {
            [
                add!(
                    add!(
                        add!(m!(a[0], r[0]), m!(a[1], s[4])),
                        add!(m!(a[2], s[3]), m!(a[3], s[2]))
                    ),
                    m!(a[4], s[1])
                ),
                add!(
                    add!(
                        add!(m!(a[0], r[1]), m!(a[1], r[0])),
                        add!(m!(a[2], s[4]), m!(a[3], s[3]))
                    ),
                    m!(a[4], s[2])
                ),
                add!(
                    add!(
                        add!(m!(a[0], r[2]), m!(a[1], r[1])),
                        add!(m!(a[2], r[0]), m!(a[3], s[4]))
                    ),
                    m!(a[4], s[3])
                ),
                add!(
                    add!(
                        add!(m!(a[0], r[3]), m!(a[1], r[2])),
                        add!(m!(a[2], r[1]), m!(a[3], r[0]))
                    ),
                    m!(a[4], s[4])
                ),
                add!(
                    add!(
                        add!(m!(a[0], r[4]), m!(a[1], r[3])),
                        add!(m!(a[2], r[2]), m!(a[3], r[1]))
                    ),
                    m!(a[4], r[0])
                ),
            ]
        }
    }

    /// Partial carry: every limb below 2^26 except limbs 1 and 4 (a little above).
    ///
    /// # Safety
    /// The CPU must have AVX2.
    #[target_feature(enable = "avx2")]
    #[inline]
    #[allow(unused_unsafe)] // the intrinsics are safe to call here from Rust 1.87
    unsafe fn carry(mut d: [__m256i; 5]) -> [__m256i; 5] {
        // SAFETY: AVX2 is available (the caller's contract); register-only intrinsics.
        unsafe {
            // two carry chains in parallel (3 -> 4 and 0 -> 1, then 4 -> 0 and 1 -> 2, then 2 -> 3
            // and 0 -> 1, then 3 -> 4): four steps deep instead of seven
            let m26 = _mm256_set1_epi64x(0x3ff_ffff);
            let (c3, c0) = (_mm256_srli_epi64(d[3], 26), _mm256_srli_epi64(d[0], 26));
            d[3] = _mm256_and_si256(d[3], m26);
            d[0] = _mm256_and_si256(d[0], m26);
            d[4] = add!(d[4], c3);
            d[1] = add!(d[1], c0);
            let (c4, c1) = (_mm256_srli_epi64(d[4], 26), _mm256_srli_epi64(d[1], 26));
            d[4] = _mm256_and_si256(d[4], m26);
            d[1] = _mm256_and_si256(d[1], m26);
            d[0] = add!(d[0], add!(c4, _mm256_slli_epi64(c4, 2)));
            d[2] = add!(d[2], c1);
            let (c2, c0) = (_mm256_srli_epi64(d[2], 26), _mm256_srli_epi64(d[0], 26));
            d[2] = _mm256_and_si256(d[2], m26);
            d[0] = _mm256_and_si256(d[0], m26);
            d[3] = add!(d[3], c2);
            d[1] = add!(d[1], c0);
            let c = _mm256_srli_epi64(d[3], 26);
            d[3] = _mm256_and_si256(d[3], m26);
            d[4] = add!(d[4], c);
            d
        }
    }

    /// Four blocks (64 bytes at `p`) as radix-2^26 limbs; lanes hold blocks 0, 2, 1, 3.
    ///
    /// # Safety
    /// 64 bytes at `p` must be readable.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn load(p: *const u8) -> [__m256i; 5] {
        // SAFETY: the caller guarantees AVX2 and 64 readable bytes at `p`.
        unsafe {
            let m26 = _mm256_set1_epi64x(0x3ff_ffff);
            let (v0, v1) = (
                _mm256_loadu_si256(p as *const __m256i),
                _mm256_loadu_si256(p.add(32) as *const __m256i),
            );
            let lo = _mm256_unpacklo_epi64(v0, v1);
            let hi = _mm256_unpackhi_epi64(v0, v1);
            [
                _mm256_and_si256(lo, m26),
                _mm256_and_si256(_mm256_srli_epi64(lo, 26), m26),
                _mm256_and_si256(
                    _mm256_or_si256(_mm256_srli_epi64(lo, 52), _mm256_slli_epi64(hi, 12)),
                    m26,
                ),
                _mm256_and_si256(_mm256_srli_epi64(hi, 14), m26),
                _mm256_or_si256(_mm256_srli_epi64(hi, 40), _mm256_set1_epi64x(1 << 24)),
            ]
        }
    }

    /// # Safety
    /// The CPU must have AVX2; `data.len()` is a non-zero multiple of 64.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn blocks(h: &mut [u64; 5], rpow: &[[u64; 5]; 4], data: &[u8]) {
        // SAFETY: AVX2 is available; every `load` reads 64 bytes at an offset below
        // `data.len()`, a multiple of 64.
        unsafe {
            let mut r4 = [_mm256_setzero_si256(); 5];
            let mut s4 = r4;
            let mut rf = r4;
            let mut sf = r4;
            for i in 0..5 {
                r4[i] = _mm256_set1_epi64x(rpow[3][i] as i64);
                s4[i] = _mm256_set1_epi64x(5 * rpow[3][i] as i64);
                // lanes hold blocks 0, 2, 1, 3 of the last group: multipliers r^4, r^2, r^3, r
                rf[i] = _mm256_set_epi64x(
                    rpow[0][i] as i64,
                    rpow[2][i] as i64,
                    rpow[1][i] as i64,
                    rpow[3][i] as i64,
                );
                sf[i] = add!(rf[i], _mm256_slli_epi64(rf[i], 2));
            }
            let p = data.as_ptr();
            let mut a = load(p);
            for (i, x) in a.iter_mut().enumerate() {
                *x = add!(*x, _mm256_set_epi64x(0, 0, 0, h[i] as i64));
            }
            for g in 1..data.len() / 64 {
                a = carry(mul(&a, &r4, &s4));
                let m = load(p.add(64 * g));
                for i in 0..5 {
                    a[i] = add!(a[i], m[i]);
                }
            }
            let d = mul(&a, &rf, &sf);
            // horizontal sums (each lane is below 2^58), then a full carry chain
            let mut s = [0u64; 5];
            for i in 0..5 {
                let x = _mm_add_epi64(
                    _mm256_castsi256_si128(d[i]),
                    _mm256_extracti128_si256(d[i], 1),
                );
                s[i] = (_mm_cvtsi128_si64(x) as u64).wrapping_add(_mm_extract_epi64(x, 1) as u64);
            }
            const M26: u64 = 0x3ff_ffff;
            for i in 0..4 {
                s[i + 1] += s[i] >> 26;
                s[i] &= M26;
            }
            s[0] += (s[4] >> 26) * 5;
            s[4] &= M26;
            s[1] += s[0] >> 26;
            s[0] &= M26;
            *h = s;
        }
    }
}

// ---- AES-GCM with VAES and VPCLMULQDQ on 256-bit registers (for simoom-tls). Self-contained.

/// 0 = not yet detected, 1 = absent, 2 = present.
static VAES: AtomicU8 = AtomicU8::new(0);

/// True if the CPU has VAES and VPCLMULQDQ with AVX2 (Zen 3, Ice Lake and later).
pub fn has_vaes() -> bool {
    let mut v = VAES.load(Ordering::Relaxed);
    if v == 0 {
        #[cfg(target_arch = "x86_64")]
        let yes = features() & F_SIMD8 != 0 && features() & F_AES != 0 && features() & F_CLMUL != 0 && {
            // CPUID leaf 7: ECX bit 9 is VAES, bit 10 VPCLMULQDQ
            let ecx = core::arch::x86_64::__cpuid_count(7, 0).ecx;
            ecx & (3 << 9) == 3 << 9
        };
        #[cfg(not(target_arch = "x86_64"))]
        let yes = false;
        v = if yes { 2 } else { 1 };
        VAES.store(v, Ordering::Relaxed);
    }
    v == 2 && DISABLED.load(Ordering::Relaxed) == 0
}

/// AES-GCM bulk encryption or decryption with VAES and VPCLMULQDQ over the longest prefix of
/// `data` that is a whole number of 128-byte groups: two blocks per instruction, eight blocks
/// per GHASH reduction. Same contract as [`aes_gcm_seal`] and [`aes_gcm_open`] for that
/// prefix; returns the number of bytes processed (0 without the instructions: the caller then
/// uses those functions for everything).
pub fn aes_gcm_vaes(aes: &AesHw, gh: &GhashHw, ctr: &mut [u8; 16], y: &mut [u8; 16], data: &mut [u8], encrypt: bool) -> usize {
    let n = data.len() / 128 * 128;
    if n == 0 || !has_vaes() {
        return 0;
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `has_vaes()` was true (AVX2, VAES, VPCLMULQDQ, AES-NI, PCLMULQDQ, SSSE3); `n` is
    // a multiple of 128 within `data`.
    unsafe {
        x86_vaes::crypt(&aes.rk, aes.nr, &gh.h, ctr, y, &mut data[..n], encrypt)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (aes, gh, ctr, y, encrypt);
    n
}

#[cfg(target_arch = "x86_64")]
mod x86_vaes {
    use core::arch::x86_64::*;

    /// # Safety
    /// The CPU must have AVX2, VAES, VPCLMULQDQ, AES-NI, PCLMULQDQ and SSSE3; `nr` is 10 or 14;
    /// `data.len()` is a multiple of 128.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    #[allow(unused_unsafe)]
    pub(super) unsafe fn crypt(
        rkb: &[[u8; 16]; 15],
        nr: usize,
        hp: &[[u8; 16]; 8],
        ctr: &mut [u8; 16],
        y: &mut [u8; 16],
        data: &mut [u8],
        encrypt: bool,
    ) {
        // SAFETY: loads and stores of the data are 32 bytes at offsets below `data.len()` (a
        // multiple of 128); the key and power arrays are read within bounds (`nr` <= 14).
        unsafe {
            let r1 = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let r = _mm256_broadcastsi128_si256(r1);
            let mut rk = [_mm256_setzero_si256(); 15];
            for k in 0..=nr {
                rk[k] = _mm256_broadcastsi128_si256(_mm_loadu_si128(rkb[k].as_ptr() as *const __m128i));
            }
            // pair j holds blocks 2j (low lane) and 2j + 1, multiplied by H^(8-2j) and H^(7-2j)
            let ld = |k: usize| _mm_loadu_si128(hp[k].as_ptr() as *const __m128i);
            let mut h = [_mm256_setzero_si256(); 4];
            let mut hm = [_mm256_setzero_si256(); 4];
            for j in 0..4 {
                h[j] = _mm256_set_m128i(ld(6 - 2 * j), ld(7 - 2 * j));
                hm[j] = _mm256_xor_si256(h[j], _mm256_shuffle_epi32(h[j], 0x4e));
            }
            let c0 = _mm_shuffle_epi8(_mm_loadu_si128(ctr.as_ptr() as *const __m128i), r1);
            let mut c = _mm256_set_m128i(_mm_add_epi32(c0, _mm_set_epi32(0, 0, 0, 1)), c0);
            let two = _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2);
            let mut acc = _mm_shuffle_epi8(_mm_loadu_si128(y.as_ptr() as *const __m128i), r1);
            let p = data.as_mut_ptr();
            for g in 0..data.len() / 128 {
                let base = 128 * g;
                let mut b = [_mm256_setzero_si256(); 4];
                for v in b.iter_mut() {
                    *v = _mm256_xor_si256(_mm256_shuffle_epi8(c, r), rk[0]);
                    c = _mm256_add_epi32(c, two);
                }
                let mut x = [_mm256_setzero_si256(); 4];
                for (j, v) in x.iter_mut().enumerate() {
                    *v = _mm256_loadu_si256(p.add(base + 32 * j) as *const __m256i);
                }
                for k in &rk[1..nr] {
                    for v in b.iter_mut() {
                        *v = _mm256_aesenc_epi128(*v, *k);
                    }
                }
                for j in 0..4 {
                    b[j] = _mm256_xor_si256(_mm256_aesenclast_epi128(b[j], rk[nr]), x[j]);
                    _mm256_storeu_si256(p.add(base + 32 * j) as *mut __m256i, b[j]);
                }
                // GHASH of the ciphertext: the output when encrypting, the input when decrypting
                let ct = if encrypt { b } else { x };
                let z = _mm256_setzero_si256();
                let (mut lo, mut mid, mut hi) = (z, z, z);
                for j in 0..4 {
                    let mut a = _mm256_shuffle_epi8(ct[j], r);
                    if j == 0 {
                        a = _mm256_xor_si256(a, _mm256_inserti128_si256(z, acc, 0));
                    }
                    lo = _mm256_xor_si256(lo, _mm256_clmulepi64_epi128(a, h[j], 0x00));
                    hi = _mm256_xor_si256(hi, _mm256_clmulepi64_epi128(a, h[j], 0x11));
                    let a2 = _mm256_xor_si256(a, _mm256_shuffle_epi32(a, 0x4e));
                    mid = _mm256_xor_si256(mid, _mm256_clmulepi64_epi128(a2, hm[j], 0x00));
                }
                let fold = |v: __m256i| _mm_xor_si128(_mm256_castsi256_si128(v), _mm256_extracti128_si256(v, 1));
                acc = reduce(fold(lo), fold(mid), fold(hi));
            }
            let c = _mm256_castsi256_si128(c);
            _mm_storeu_si128(ctr.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(c, r1));
            _mm_storeu_si128(y.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(acc, r1));
        }
    }

    /// The Karatsuba (lo, mid, hi) to the reduced GHASH value (the steps of the main kernel).
    #[target_feature(enable = "sse2")]
    #[allow(unused_unsafe)]
    unsafe fn reduce(lo: __m128i, mid: __m128i, hi: __m128i) -> __m128i {
        // SAFETY: register-only SSE2 intrinsics.
        unsafe {
            let (mut lo, mut hi) = (lo, hi);
            let mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
            lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
            hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
            let clo = _mm_srli_epi64(lo, 63);
            let chi = _mm_srli_epi64(hi, 63);
            lo = _mm_or_si128(_mm_slli_epi64(lo, 1), _mm_slli_si128(clo, 8));
            hi = _mm_or_si128(_mm_or_si128(_mm_slli_epi64(hi, 1), _mm_slli_si128(chi, 8)), _mm_srli_si128(clo, 8));
            let g = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(lo, 63), _mm_slli_epi64(lo, 62)), _mm_slli_epi64(lo, 57));
            lo = _mm_xor_si128(lo, _mm_slli_si128(g, 8));
            let f = _mm_xor_si128(_mm_xor_si128(lo, _mm_srli_epi64(lo, 1)), _mm_xor_si128(_mm_srli_epi64(lo, 2), _mm_srli_epi64(lo, 7)));
            hi = _mm_xor_si128(hi, f);
            let g = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(lo, 63), _mm_slli_epi64(lo, 62)), _mm_slli_epi64(lo, 57));
            _mm_xor_si128(hi, _mm_srli_si128(g, 8))
        }
    }
}
