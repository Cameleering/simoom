//! SIMD byte scanning for the HTTP parsers, with runtime detection and a scalar fallback.
//!
//! The parsers ask one question many times: "how long is the run of bytes, starting here, that
//! belong to this class?" (a token, a request target, a field value). The first byte outside the
//! class is the delimiter (`:`, SP, CR) or an invalid byte, so finding and validating happen in
//! one pass. [`scan`] answers it; [`find_byte`] is a plain `memchr`.
//!
//! Kernels: SSSE3/SSE4.2 (16 bytes per step) and AVX2 (32) on x86-64, NEON (16) on aarch64. Class
//! membership uses the nibble-table method: a 16-byte table indexed by the low nibble holds, per
//! high nibble 0..7, whether that byte is in the class, so any set of ASCII bytes is exact. Bytes
//! 0x80..=0xFF are either all in or all out of a class. The level is detected once and cached;
//! [`force`] overrides it for benchmarks.

use std::sync::atomic::{AtomicU8, Ordering};

/// A scanning implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Portable byte-at-a-time code.
    Scalar = 1,
    /// SSSE3 + SSE4.2, 16 bytes per step (x86-64).
    Sse42 = 2,
    /// AVX2, 32 bytes per step (x86-64).
    Avx2 = 3,
    /// NEON, 16 bytes per step (aarch64).
    Neon = 4,
}

/// A set of byte values, usable by every kernel.
#[derive(Debug)]
pub struct ByteClass {
    table: [bool; 256],
    lo: [u8; 16],
    high: bool,
}

impl ByteClass {
    /// Builds a class from single ASCII bytes and inclusive ASCII ranges; `high` adds every byte
    /// from 0x80 to 0xFF.
    pub const fn new(singles: &[u8], ranges: &[(u8, u8)], high: bool) -> ByteClass {
        let mut table = [false; 256];
        let mut i = 0;
        while i < singles.len() {
            assert!(singles[i] < 0x80);
            table[singles[i] as usize] = true;
            i += 1;
        }
        let mut r = 0;
        while r < ranges.len() {
            let (a, b) = ranges[r];
            assert!(a <= b && b < 0x80);
            let mut c = a as usize;
            while c <= b as usize {
                table[c] = true;
                c += 1;
            }
            r += 1;
        }
        if high {
            let mut c = 0x80;
            while c < 256 {
                table[c] = true;
                c += 1;
            }
        }
        let mut lo = [0u8; 16];
        let mut c = 0;
        while c < 128 {
            if table[c] {
                lo[c & 15] |= 1 << (c >> 4);
            }
            c += 1;
        }
        ByteClass { table, lo, high }
    }

    /// True if `b` is in the class.
    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.table[b as usize]
    }
}

/// RFC 9110 `tchar`: the bytes of a token (method, field name, transfer coding).
pub static TCHAR: ByteClass =
    ByteClass::new(b"!#$%&'*+-.^_`|~", &[(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')], false);

/// RFC 9110 field-value bytes: HTAB, SP, VCHAR and obs-text. Stops at CR, LF, NUL, DEL and every
/// other control byte.
pub static FIELD_VALUE: ByteClass = ByteClass::new(b"\t", &[(0x20, 0x7e)], true);

/// RFC 3986 bytes of a request target other than `%` (checked separately with its two hex
/// digits) and `[` `]` (IP literals only): unreserved, sub-delims, `:`, `@`, `/`, `?`.
pub static URI: ByteClass = ByteClass::new(
    b"-._~!$&'()*+,;=:@/?",
    &[(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')],
    false,
);

static LEVEL: AtomicU8 = AtomicU8::new(0);

fn from_u8(n: u8) -> Level {
    match n {
        2 => Level::Sse42,
        3 => Level::Avx2,
        4 => Level::Neon,
        _ => Level::Scalar,
    }
}

/// True if this CPU can run `level`.
pub fn available(level: Level) -> bool {
    match level {
        Level::Scalar => true,
        #[cfg(target_arch = "x86_64")]
        Level::Sse42 => {
            use crate::cpu::x86;
            crate::cpu::x86_features() & (x86::SSE42 | x86::SSSE3) == x86::SSE42 | x86::SSSE3
        }
        #[cfg(target_arch = "x86_64")]
        Level::Avx2 => available(Level::Sse42) && crate::cpu::x86_features() & crate::cpu::x86::AVX2 != 0,
        #[cfg(target_arch = "aarch64")]
        Level::Neon => std::arch::is_aarch64_feature_detected!("neon"),
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

fn detect() -> Level {
    for l in [Level::Avx2, Level::Sse42, Level::Neon] {
        if available(l) {
            return l;
        }
    }
    Level::Scalar
}

/// The level in use: the best one this CPU supports, unless [`force`] chose another.
#[inline]
pub fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        0 => {
            let l = detect();
            LEVEL.store(l as u8, Ordering::Relaxed);
            l
        }
        n => from_u8(n),
    }
}

/// Uses `level` from now on, process-wide; returns false (and changes nothing) if the CPU lacks
/// it. Meant for benchmarks and tests.
pub fn force(level: Level) -> bool {
    if !available(level) {
        return false;
    }
    LEVEL.store(level as u8, Ordering::Relaxed);
    true
}

/// Length of the run of bytes at the start of `buf` that are in `class`: the index of the first
/// byte outside it, or `buf.len()`.
#[inline]
pub fn scan(buf: &[u8], class: &ByteClass) -> usize {
    dispatch_scan(level(), buf, class)
}

/// [`scan`] with an explicit level; an unavailable level falls back to scalar.
pub fn scan_at(level: Level, buf: &[u8], class: &ByteClass) -> usize {
    let level = if available(level) { level } else { Level::Scalar };
    dispatch_scan(level, buf, class)
}

/// Index of the first `byte` in `buf`.
#[inline]
pub fn find_byte(buf: &[u8], byte: u8) -> Option<usize> {
    dispatch_find(level(), buf, byte)
}

/// [`find_byte`] with an explicit level; an unavailable level falls back to scalar.
pub fn find_byte_at(level: Level, buf: &[u8], byte: u8) -> Option<usize> {
    let level = if available(level) { level } else { Level::Scalar };
    dispatch_find(level, buf, byte)
}

/// Offsets of one header field line at the start of `buf`, found in a single dispatch:
/// `(name_end, value_start, value_end)`. `name_end` is the length of the [`TCHAR`] run. If the
/// byte there is `:`, `value_start` is past the colon and any SP/HTAB, and `value_end` ends the
/// [`FIELD_VALUE`] run from there (trailing whitespace included); otherwise both equal
/// `name_end`. The caller checks the bytes at `name_end` and `value_end`.
#[inline]
pub fn field_line(buf: &[u8]) -> (usize, usize, usize) {
    match level() {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `level()` only returns levels that `available` accepted.
        Level::Avx2 => unsafe { x86::field_line_avx2(buf) },
        #[cfg(target_arch = "x86_64")]
        // SAFETY: as above: the CPU has SSSE3 and SSE4.2.
        Level::Sse42 => unsafe { x86::field_line_sse(buf) },
        #[cfg(target_arch = "aarch64")]
        // SAFETY: as above: the CPU has NEON.
        Level::Neon => unsafe { arm::field_line_neon(buf) },
        _ => field_line_with(buf, scan_scalar),
    }
}

#[inline(always)]
fn field_line_with(buf: &[u8], scan: impl Fn(&[u8], &ByteClass) -> usize) -> (usize, usize, usize) {
    let n = scan(buf, &TCHAR);
    if buf.get(n) != Some(&b':') {
        return (n, n, n);
    }
    let mut v = n + 1;
    while v < buf.len() && (buf[v] == b' ' || buf[v] == b'\t') {
        v += 1;
    }
    (n, v, v + scan(&buf[v..], &FIELD_VALUE))
}

fn scan_scalar(buf: &[u8], class: &ByteClass) -> usize {
    buf.iter().position(|&b| !class.table[b as usize]).unwrap_or(buf.len())
}

// `level` is always one that `available` accepted.
#[inline]
fn dispatch_scan(level: Level, buf: &[u8], class: &ByteClass) -> usize {
    if buf.len() < 16 {
        return scan_scalar(buf, class);
    }
    match level {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the level was checked by `available`: the CPU has SSSE3 and SSE4.2; the buffer
        // is at least 16 bytes long.
        Level::Sse42 => unsafe { x86::scan_sse(buf, class) },
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the level was checked by `available`: the CPU has AVX2, SSSE3 and SSE4.2; the
        // buffer is at least 16 bytes long.
        Level::Avx2 => unsafe { x86::scan_avx2(buf, class) },
        #[cfg(target_arch = "aarch64")]
        // SAFETY: the level was checked by `available`: the CPU has NEON; the buffer is at least
        // 16 bytes long.
        Level::Neon => unsafe { arm::scan_neon(buf, class) },
        _ => scan_scalar(buf, class),
    }
}

#[inline]
fn dispatch_find(level: Level, buf: &[u8], byte: u8) -> Option<usize> {
    if buf.len() < 16 {
        return buf.iter().position(|&b| b == byte);
    }
    match level {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: SSE2 is part of the x86-64 baseline; the buffer is at least 16 bytes long.
        Level::Sse42 => unsafe { x86::find_sse2(buf, byte) },
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the level was checked by `available`: the CPU has AVX2; the buffer is at least
        // 16 bytes long.
        Level::Avx2 => unsafe { x86::find_avx2(buf, byte) },
        #[cfg(target_arch = "aarch64")]
        // SAFETY: the level was checked by `available`: the CPU has NEON; the buffer is at least
        // 16 bytes long.
        Level::Neon => unsafe { arm::find_neon(buf, byte) },
        _ => buf.iter().position(|&b| b == byte),
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::ByteClass;
    use core::arch::x86_64::*;

    // Mask (one bit per byte) of the bytes of `$v` that are NOT in the class.
    macro_rules! notin128 {
        ($v:expr, $lo_t:expr, $hi_t:expr, $high:expr) => {{
            let v = $v;
            let nib = _mm_set1_epi8(0x0f);
            let lo = _mm_and_si128(v, nib);
            let hi = _mm_and_si128(_mm_srli_epi16(v, 4), nib);
            let bits = _mm_and_si128(_mm_shuffle_epi8($lo_t, lo), _mm_shuffle_epi8($hi_t, hi));
            let mut out = _mm_cmpeq_epi8(bits, _mm_setzero_si128());
            if $high {
                out = _mm_andnot_si128(_mm_cmplt_epi8(v, _mm_setzero_si128()), out);
            }
            _mm_movemask_epi8(out) as u32
        }};
    }

    macro_rules! hi_table {
        () => {
            _mm_setr_epi8(1, 2, 4, 8, 16, 32, 64, -128, 0, 0, 0, 0, 0, 0, 0, 0)
        };
    }

    macro_rules! eq_mask128 {
        ($p:expr, $needle:expr) => {
            _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128($p as *const __m128i), $needle)) as u32
        };
    }

    /// # Safety
    /// The CPU must have AVX2 (which implies SSSE3 and SSE4.2).
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn field_line_avx2(buf: &[u8]) -> (usize, usize, usize) {
        super::field_line_with(buf, |b, c| {
            if b.len() < 16 {
                return super::scan_scalar(b, c);
            }
            // SAFETY: the caller guarantees AVX2; `b` has at least 16 bytes.
            unsafe { scan_avx2(b, c) }
        })
    }

    /// # Safety
    /// The CPU must have SSSE3 and SSE4.2.
    #[target_feature(enable = "ssse3,sse4.2")]
    pub(super) unsafe fn field_line_sse(buf: &[u8]) -> (usize, usize, usize) {
        super::field_line_with(buf, |b, c| {
            if b.len() < 16 {
                return super::scan_scalar(b, c);
            }
            // SAFETY: the caller guarantees SSSE3 and SSE4.2; `b` has at least 16 bytes.
            unsafe { scan_sse(b, c) }
        })
    }

    /// # Safety
    /// The CPU must have SSSE3 and SSE4.2, and `buf.len() >= 16`.
    #[target_feature(enable = "ssse3,sse4.2")]
    pub(super) unsafe fn scan_sse(buf: &[u8], class: &ByteClass) -> usize {
        let n = buf.len();
        let p = buf.as_ptr();
        // SAFETY: every load reads 16 bytes at an offset `i` with `i + 16 <= n`, inside `buf`
        // (the tail block starts at `n - 16 >= 0`); `class.lo` is 16 bytes. Loads are unaligned.
        unsafe {
            let lo_t = _mm_loadu_si128(class.lo.as_ptr() as *const __m128i);
            let hi_t = hi_table!();
            let mut i = 0;
            while i + 16 <= n {
                let m = notin128!(_mm_loadu_si128(p.add(i) as *const __m128i), lo_t, hi_t, class.high);
                if m != 0 {
                    return i + m.trailing_zeros() as usize;
                }
                i += 16;
            }
            if i < n {
                // Overlapping last block; drop the bytes already checked.
                let start = n - 16;
                let m = notin128!(_mm_loadu_si128(p.add(start) as *const __m128i), lo_t, hi_t, class.high)
                    >> (i - start);
                if m != 0 {
                    return i + m.trailing_zeros() as usize;
                }
            }
            n
        }
    }

    /// # Safety
    /// The CPU must have AVX2 (which implies SSSE3 and SSE4.2), and `buf.len() >= 16`.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn scan_avx2(buf: &[u8], class: &ByteClass) -> usize {
        let n = buf.len();
        let p = buf.as_ptr();
        // SAFETY: 32-byte loads at `i` with `i + 32 <= n` and 16-byte loads at `i` with
        // `i + 16 <= n` stay inside `buf`; `class.lo` is 16 bytes.
        unsafe {
            let lo_t = _mm_loadu_si128(class.lo.as_ptr() as *const __m128i);
            let hi_t = hi_table!();
            let lo_t2 = _mm256_broadcastsi128_si256(lo_t);
            let hi_t2 = _mm256_broadcastsi128_si256(hi_t);
            let nib = _mm256_set1_epi8(0x0f);
            let zero = _mm256_setzero_si256();
            let mut i = 0;
            while i + 32 <= n {
                let v = _mm256_loadu_si256(p.add(i) as *const __m256i);
                let lo = _mm256_and_si256(v, nib);
                let hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), nib);
                let bits = _mm256_and_si256(_mm256_shuffle_epi8(lo_t2, lo), _mm256_shuffle_epi8(hi_t2, hi));
                let mut out = _mm256_cmpeq_epi8(bits, zero);
                if class.high {
                    out = _mm256_andnot_si256(_mm256_cmpgt_epi8(zero, v), out);
                }
                let m = _mm256_movemask_epi8(out) as u32;
                if m != 0 {
                    return i + m.trailing_zeros() as usize;
                }
                i += 32;
            }
            if i + 16 <= n {
                let m = notin128!(_mm_loadu_si128(p.add(i) as *const __m128i), lo_t, hi_t, class.high);
                if m != 0 {
                    return i + m.trailing_zeros() as usize;
                }
                i += 16;
            }
            if i < n {
                let start = n - 16;
                let m = notin128!(_mm_loadu_si128(p.add(start) as *const __m128i), lo_t, hi_t, class.high)
                    >> (i - start);
                if m != 0 {
                    return i + m.trailing_zeros() as usize;
                }
            }
            n
        }
    }

    /// # Safety
    /// `buf.len() >= 16` (SSE2 is baseline on x86-64).
    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn find_sse2(buf: &[u8], byte: u8) -> Option<usize> {
        let n = buf.len();
        let p = buf.as_ptr();
        // SAFETY: every 16-byte load is at `i` with `i + 16 <= n`, inside `buf`.
        unsafe {
            let needle = _mm_set1_epi8(byte as i8);
            let mut i = 0;
            while i + 16 <= n {
                let m = eq_mask128!(p.add(i), needle);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
                i += 16;
            }
            if i < n {
                let start = n - 16;
                let m = eq_mask128!(p.add(start), needle) >> (i - start);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
            }
            None
        }
    }

    /// # Safety
    /// The CPU must have AVX2, and `buf.len() >= 16`.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn find_avx2(buf: &[u8], byte: u8) -> Option<usize> {
        let n = buf.len();
        let p = buf.as_ptr();
        // SAFETY: 32-byte loads at `i` with `i + 32 <= n`; 16-byte loads at `i` with
        // `i + 16 <= n`, and the tail block at `n - 16 >= 0`. All inside `buf`.
        unsafe {
            let needle = _mm256_set1_epi8(byte as i8);
            let mut i = 0;
            while i + 32 <= n {
                let m = _mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256(p.add(i) as *const __m256i), needle))
                    as u32;
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
                i += 32;
            }
            let needle = _mm_set1_epi8(byte as i8);
            if i + 16 <= n {
                let m = eq_mask128!(p.add(i), needle);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
                i += 16;
            }
            if i < n {
                let start = n - 16;
                let m = eq_mask128!(p.add(start), needle) >> (i - start);
                if m != 0 {
                    return Some(i + m.trailing_zeros() as usize);
                }
            }
            None
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::ByteClass;
    use core::arch::aarch64::*;

    // 64-bit mask, four bits per byte, of the 0xFF lanes of `$m`.
    macro_rules! nibble_mask {
        ($m:expr) => {
            vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8($m), 4)), 0)
        };
    }

    macro_rules! notin_neon {
        ($v:expr, $lo_t:expr, $hi_t:expr, $high:expr) => {{
            let v = $v;
            let nib = vdupq_n_u8(0x0f);
            let bits = vandq_u8(vqtbl1q_u8($lo_t, vandq_u8(v, nib)), vqtbl1q_u8($hi_t, vshrq_n_u8(v, 4)));
            let mut out = vceqq_u8(bits, vdupq_n_u8(0));
            if $high {
                out = vbicq_u8(out, vcgeq_u8(v, vdupq_n_u8(0x80)));
            }
            nibble_mask!(out)
        }};
    }

    const HI: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 0, 0, 0, 0, 0, 0, 0, 0];

    /// # Safety
    /// The CPU must have NEON.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn field_line_neon(buf: &[u8]) -> (usize, usize, usize) {
        super::field_line_with(buf, |b, c| {
            if b.len() < 16 {
                return super::scan_scalar(b, c);
            }
            // SAFETY: the caller guarantees NEON; `b` has at least 16 bytes.
            unsafe { scan_neon(b, c) }
        })
    }

    /// # Safety
    /// The CPU must have NEON, and `buf.len() >= 16`.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn scan_neon(buf: &[u8], class: &ByteClass) -> usize {
        let n = buf.len();
        let p = buf.as_ptr();
        // SAFETY: every 16-byte load is at `i` with `i + 16 <= n`, inside `buf`; the tables are
        // 16 bytes.
        unsafe {
            let lo_t = vld1q_u8(class.lo.as_ptr());
            let hi_t = vld1q_u8(HI.as_ptr());
            let mut i = 0;
            while i + 16 <= n {
                let m = notin_neon!(vld1q_u8(p.add(i)), lo_t, hi_t, class.high);
                if m != 0 {
                    return i + (m.trailing_zeros() / 4) as usize;
                }
                i += 16;
            }
            if i < n {
                let start = n - 16;
                let m = notin_neon!(vld1q_u8(p.add(start)), lo_t, hi_t, class.high) >> (4 * (i - start));
                if m != 0 {
                    return i + (m.trailing_zeros() / 4) as usize;
                }
            }
            n
        }
    }

    /// # Safety
    /// The CPU must have NEON, and `buf.len() >= 16`.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn find_neon(buf: &[u8], byte: u8) -> Option<usize> {
        let n = buf.len();
        let p = buf.as_ptr();
        // SAFETY: every 16-byte load is at `i` with `i + 16 <= n`, inside `buf`.
        unsafe {
            let needle = vdupq_n_u8(byte);
            let mut i = 0;
            while i + 16 <= n {
                let m = nibble_mask!(vceqq_u8(vld1q_u8(p.add(i)), needle));
                if m != 0 {
                    return Some(i + (m.trailing_zeros() / 4) as usize);
                }
                i += 16;
            }
            if i < n {
                let start = n - 16;
                let m = nibble_mask!(vceqq_u8(vld1q_u8(p.add(start)), needle)) >> (4 * (i - start));
                if m != 0 {
                    return Some(i + (m.trailing_zeros() / 4) as usize);
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn levels() -> Vec<Level> {
        [Level::Scalar, Level::Sse42, Level::Avx2, Level::Neon].into_iter().filter(|&l| available(l)).collect()
    }

    #[test]
    fn classes_match_the_rfc_sets() {
        for b in 0..=255u8 {
            let tchar = b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
            assert_eq!(TCHAR.contains(b), tchar, "{b}");
            let fv = b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80;
            assert_eq!(FIELD_VALUE.contains(b), fv, "{b}");
            let uri = b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&b);
            assert_eq!(URI.contains(b), uri, "{b}");
        }
    }

    #[test]
    fn simd_and_scalar_agree_on_random_inputs() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let lv = levels();
        let classes = [&TCHAR, &FIELD_VALUE, &URI];
        let mut buf = Vec::new();
        for round in 0..20_000 {
            let len = (rng.next() % 100) as usize;
            buf.clear();
            // Mostly in-class bytes with a rare outsider, so runs are long and stops vary.
            let class = classes[round % 3];
            while buf.len() < len {
                let b = rng.next() as u8;
                if class.contains(b) || rng.next() % 40 == 0 {
                    buf.push(b);
                }
            }
            let needle = buf.get((rng.next() as usize) % (buf.len() + 1)).copied().unwrap_or(b'\r');
            for &l in &lv {
                // Several suffixes too, so each alignment and tail length is covered.
                for s in [0, 1, 3, 15, 17] {
                    if s <= buf.len() {
                        let b = &buf[s..];
                        assert_eq!(scan_at(l, b, class), scan_scalar(b, class), "{l:?} {b:?}");
                        assert_eq!(find_byte_at(l, b, needle), b.iter().position(|&x| x == needle), "{l:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn every_byte_value_stops_correctly_at_every_position() {
        for &l in &levels() {
            for class in [&TCHAR, &FIELD_VALUE, &URI] {
                for len in [16usize, 31, 32, 33, 64, 70] {
                    for pos in 0..len {
                        for b in 0..=255u8 {
                            let mut buf = vec![b'a'; len];
                            buf[pos] = b;
                            let want = if class.contains(b) { len } else { pos };
                            assert_eq!(scan_at(l, &buf, class), want, "{l:?} len {len} pos {pos} byte {b}");
                        }
                        let mut buf = vec![0u8; len];
                        buf[pos] = b'\n';
                        assert_eq!(find_byte_at(l, &buf, b'\n'), Some(pos));
                    }
                }
            }
        }
    }

    #[test]
    fn field_line_matches_two_scans() {
        let mut rng = Rng(42);
        let pool = b"abcXY-_:: \t\r\n\x00\x7f\xc3;=\"";
        for _ in 0..20_000 {
            let len = (rng.next() % 70) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    if rng.next() % 3 == 0 {
                        pool[(rng.next() as usize) % pool.len()]
                    } else {
                        b'a' + (rng.next() % 26) as u8
                    }
                })
                .collect();
            let want = field_line_with(&buf, scan_scalar);
            assert_eq!(field_line(&buf), want, "{buf:?}");
            let (n, vs, ve) = want;
            assert_eq!(n, scan_scalar(&buf, &TCHAR));
            if buf.get(n) == Some(&b':') {
                assert!(vs > n && buf[n + 1..vs].iter().all(|&b| b == b' ' || b == b'\t'));
                assert_eq!(ve, vs + scan_scalar(&buf[vs..], &FIELD_VALUE));
            } else {
                assert_eq!((vs, ve), (n, n));
            }
        }
        assert_eq!(field_line(b"Host:  example.com\r\n"), (4, 7, 18));
        assert_eq!(field_line(b"Bad Name: x"), (3, 3, 3));
    }

    #[test]
    fn force_and_level() {
        let before = level();
        assert!(available(before));
        assert!(force(Level::Scalar));
        assert_eq!(level(), Level::Scalar);
        assert!(force(before));
        assert_eq!(level(), before);
    }
}
