//! CRC-32 (IEEE 802.3, used by gzip) and Adler-32 (used by zlib).

use std::sync::OnceLock;

/// Slicing-by-8 tables, built on first use (8 KiB at run time instead of in the binary).
fn tables() -> &'static [[u32; 256]; 8] {
    static T: OnceLock<Box<[[u32; 256]; 8]>> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = Box::new([[0u32; 256]; 8]);
        for i in 0..256 {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            t[0][i] = c;
        }
        for k in 1..8 {
            for i in 0..256 {
                let p = t[k - 1][i];
                t[k][i] = (p >> 8) ^ t[0][(p & 0xFF) as usize];
            }
        }
        t
    })
}

/// Incremental CRC-32.
#[derive(Clone, Copy, Debug)]
pub struct Crc32(u32);

impl Default for Crc32 {
    fn default() -> Self {
        Crc32::new()
    }
}

impl Crc32 {
    /// A fresh checksum.
    pub fn new() -> Crc32 {
        Crc32(0)
    }

    /// Adds `data`.
    pub fn update(&mut self, data: &[u8]) {
        let t = tables();
        let mut c = !self.0;
        let mut chunks = data.chunks_exact(8);
        for ch in &mut chunks {
            let w = u64::from_le_bytes([ch[0], ch[1], ch[2], ch[3], ch[4], ch[5], ch[6], ch[7]]) ^ c as u64;
            c = t[7][(w & 0xFF) as usize]
                ^ t[6][((w >> 8) & 0xFF) as usize]
                ^ t[5][((w >> 16) & 0xFF) as usize]
                ^ t[4][((w >> 24) & 0xFF) as usize]
                ^ t[3][((w >> 32) & 0xFF) as usize]
                ^ t[2][((w >> 40) & 0xFF) as usize]
                ^ t[1][((w >> 48) & 0xFF) as usize]
                ^ t[0][(w >> 56) as usize];
        }
        for &b in chunks.remainder() {
            c = t[0][((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
        self.0 = !c;
    }

    /// The checksum of everything added so far.
    pub fn value(&self) -> u32 {
        self.0
    }
}

/// CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.value()
}

/// Incremental Adler-32.
#[derive(Clone, Copy, Debug)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

impl Default for Adler32 {
    fn default() -> Self {
        Adler32::new()
    }
}

impl Adler32 {
    /// A fresh checksum (value 1).
    pub fn new() -> Adler32 {
        Adler32 { a: 1, b: 0 }
    }

    /// Adds `data`.
    pub fn update(&mut self, data: &[u8]) {
        const MOD: u32 = 65521;
        // 5552 is the largest n with 255 n (n + 1) / 2 + (n + 1) (MOD - 1) < 2^32.
        let (mut a, mut b) = (self.a, self.b);
        for chunk in data.chunks(5552) {
            let mut quads = chunk.chunks_exact(4);
            for q in &mut quads {
                a += q[0] as u32;
                b += a;
                a += q[1] as u32;
                b += a;
                a += q[2] as u32;
                b += a;
                a += q[3] as u32;
                b += a;
            }
            for &x in quads.remainder() {
                a += x as u32;
                b += a;
            }
            a %= MOD;
            b %= MOD;
        }
        self.a = a;
        self.b = b;
    }

    /// The checksum of everything added so far.
    pub fn value(&self) -> u32 {
        (self.b << 16) | self.a
    }
}

/// Adler-32 of `data`.
pub fn adler32(data: &[u8]) -> u32 {
    let mut c = Adler32::new();
    c.update(data);
    c.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        // incremental equals one-shot, across the 8-byte and 5552-byte boundaries
        let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        let (mut c, mut a) = (Crc32::new(), Adler32::new());
        for part in data.chunks(1234) {
            c.update(part);
            a.update(part);
        }
        assert_eq!(c.value(), crc32(&data));
        assert_eq!(a.value(), adler32(&data));
        let all_ff = vec![0xFFu8; 100_000];
        let mut slow = Adler32 { a: 1, b: 0 };
        for &x in &all_ff {
            slow.a = (slow.a + x as u32) % 65521;
            slow.b = (slow.b + slow.a) % 65521;
        }
        assert_eq!(adler32(&all_ff), slow.value());
    }
}
