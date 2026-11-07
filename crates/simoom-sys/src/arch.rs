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
        let ssse3 = std::is_x86_feature_detected!("ssse3") && std::is_x86_feature_detected!("sse4.1");
        if ssse3 && std::is_x86_feature_detected!("aes") {
            f |= F_AES;
        }
        if ssse3 && std::is_x86_feature_detected!("pclmulqdq") {
            f |= F_CLMUL;
        }
        if ssse3 && std::is_x86_feature_detected!("sha") {
            f |= F_SHA256;
        }
        if ssse3 {
            f |= F_SIMD4;
        }
        if ssse3 && std::is_x86_feature_detected!("avx2") {
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
    DISABLED.store(if disabled { F_AES | F_CLMUL | F_SHA256 | F_SIMD4 | F_SIMD8 } else { 0 }, Ordering::Relaxed);
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
        st[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    st[12] = counter;
    for i in 0..3 {
        st[13 + i] = u32::from_le_bytes([nonce[4 * i], nonce[4 * i + 1], nonce[4 * i + 2], nonce[4 * i + 3]]);
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
        Some(AesHw { rk, nr: round_keys.len() - 1 })
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
pub fn aes_gcm_seal(aes: &AesHw, gh: &GhashHw, ctr: &mut [u8; 16], y: &mut [u8; 16], data: &mut [u8]) {
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
pub fn aes_gcm_open(aes: &AesHw, gh: &GhashHw, ctr: &mut [u8; 16], y: &mut [u8; 16], data: &mut [u8]) {
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
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
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
            hi = _mm_or_si128(_mm_or_si128(_mm_slli_epi64(hi, 1), _mm_slli_si128(chi, 8)), _mm_srli_si128(clo, 8));
            let g = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(lo, 63), _mm_slli_epi64(lo, 62)), _mm_slli_epi64(lo, 57));
            lo = _mm_xor_si128(lo, _mm_slli_si128(g, 8));
            let f = _mm_xor_si128(
                _mm_xor_si128(lo, _mm_srli_epi64(lo, 1)),
                _mm_xor_si128(_mm_srli_epi64(lo, 2), _mm_srli_epi64(lo, 7)),
            );
            hi = _mm_xor_si128(hi, f);
            let g = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(lo, 63), _mm_slli_epi64(lo, 62)), _mm_slli_epi64(lo, 57));
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
                let x0 = _mm_xor_si128(acc, _mm_shuffle_epi8(_mm_loadu_si128(p.add(i) as *const __m128i), r));
                clmul_acc!(lo, mid, hi, x0, h[7]);
                for j in 1..8 {
                    let x = _mm_shuffle_epi8(_mm_loadu_si128(p.add(i + 16 * j) as *const __m128i), r);
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
                        x[j] = _mm_xor_si128(b[j], _mm_loadu_si128(p.add(i + 16 * j) as *const __m128i));
                        _mm_storeu_si128(p.add(i + 16 * j) as *mut __m128i, x[j]);
                    }
                } else {
                    for j in 0..8 {
                        _mm_storeu_si128(p.add(i + 16 * j) as *mut __m128i, _mm_xor_si128(b[j], x[j]));
                    }
                }
                let z = _mm_setzero_si128();
                let (mut lo, mut mid, mut hi) = (z, z, z);
                clmul_acc!(lo, mid, hi, _mm_xor_si128(acc, _mm_shuffle_epi8(x[0], r)), h[7]);
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
                    *wj = _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr().add(16 * j) as *const __m128i), swap);
                }
                for g in 0..12 {
                    let t = _mm_add_epi32(_mm_sha256msg1_epu32(w[g], w[g + 1]), _mm_alignr_epi8(w[g + 3], w[g + 2], 4));
                    w[g + 4] = _mm_sha256msg2_epu32(t, w[g + 3]);
                }
                for (g, wg) in w.iter().enumerate() {
                    let wk = _mm_add_epi32(*wg, _mm_loadu_si128(super::K256.as_ptr().add(4 * g) as *const __m128i));
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
            _mm_shuffle_epi8($v, _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
        };
    }
    macro_rules! r8_128 {
        ($v:expr) => {
            _mm_shuffle_epi8($v, _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3))
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
                    13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
                ),
            )
        };
    }
    macro_rules! r8_256 {
        ($v:expr) => {
            _mm256_shuffle_epi8(
                $v,
                _mm256_set_epi8(
                    14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
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
                    let o = [_mm_unpacklo_epi64(t0, t2), _mm_unpackhi_epi64(t0, t2), _mm_unpacklo_epi64(t1, t3), _mm_unpackhi_epi64(t1, t3)];
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

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
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
        fn BCryptGenRandom(algorithm: *mut core::ffi::c_void, buffer: *mut u8, len: u32, flags: u32) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;

    pub(super) fn fill(buf: &mut [u8]) -> bool {
        for chunk in buf.chunks_mut(1 << 30) {
            // SAFETY: a null algorithm handle with BCRYPT_USE_SYSTEM_PREFERRED_RNG is the
            // documented way to use the system RNG; `chunk` is valid and writable for its length,
            // which fits in u32.
            let status = unsafe {
                BCryptGenRandom(std::ptr::null_mut(), chunk.as_mut_ptr(), chunk.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
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
            0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        if sha256_blocks(&mut st, &block) {
            assert_eq!(st, [0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad]);
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
