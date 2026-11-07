//! Small helpers: constant-time comparison and selection, hex for tests and diagnostics.

/// Constant-time equality of two slices. The lengths are not secret.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    core::hint::black_box(d) == 0
}

/// An all-ones (flag = 1) or all-zero (flag = 0) mask, hidden from the optimizer so that it
/// cannot turn masked selection back into a branch (LLVM's cmov-to-branch conversion would
/// otherwise make table lookups and swaps leak through the branch predictor).
#[inline(always)]
pub fn ct_mask(flag: u64) -> u64 {
    core::hint::black_box(flag).wrapping_neg()
}

/// All-ones if `a == b`, else zero, as an opaque mask.
#[inline(always)]
pub fn ct_eq_mask(a: u64, b: u64) -> u64 {
    let d = a ^ b;
    ct_mask(1 ^ ((d | d.wrapping_neg()) >> 63))
}

/// Lower-case hex.
pub fn hex(data: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

/// Decodes hex, ignoring whitespace and `:`. Panics on bad input (constants and tests only).
pub fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b':').collect();
    assert!(digits.len() % 2 == 0, "odd hex length");
    let val = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    };
    digits.chunks(2).map(|p| val(p[0]) << 4 | val(p[1])).collect()
}

/// Best-effort zeroing of secret material (not elided: the writes go through `black_box`).
pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(buf);
}
