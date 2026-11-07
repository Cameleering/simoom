//! Variable-length integers (RFC 9000 §16) and a bounds-checked reader.

/// Largest value a varint can hold (2^62 - 1).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Encoded size of `v` in bytes (1, 2, 4 or 8). `v` must be at most [`VARINT_MAX`].
#[inline]
pub fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Appends `v` as a varint. Panics in debug builds when `v` exceeds [`VARINT_MAX`].
#[inline]
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    debug_assert!(v <= VARINT_MAX);
    match varint_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Writes `v` as a varint of exactly `len` bytes (used for patched length fields).
pub fn put_varint_fixed(out: &mut [u8], v: u64, len: usize) {
    let b = v.to_be_bytes();
    out[..len].copy_from_slice(&b[8 - len..]);
    out[0] |= match len {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
}

/// A cursor over a byte slice; every read is bounds-checked.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    #[inline]
    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    pub fn u16(&mut self) -> Option<u16> {
        let s = self.bytes(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        let s = self.bytes(4)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    #[inline]
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    /// Reads a varint, returning the value and its encoded length.
    #[inline]
    pub fn varint_with_len(&mut self) -> Option<(u64, usize)> {
        let first = *self.buf.get(self.pos)?;
        let len = 1usize << (first >> 6);
        let s = self.bytes(len)?;
        let mut v = (first & 0x3f) as u64;
        for &b in &s[1..] {
            v = (v << 8) | b as u64;
        }
        Some((v, len))
    }
    #[inline]
    pub fn varint(&mut self) -> Option<u64> {
        self.varint_with_len().map(|(v, _)| v)
    }
    /// Reads a varint length followed by that many bytes.
    pub fn vbytes(&mut self) -> Option<&'a [u8]> {
        let n = self.varint()?;
        if n > self.remaining() as u64 {
            return None;
        }
        self.bytes(n as usize)
    }
}

/// Decodes a single varint from the front of `buf`.
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    Reader::new(buf).varint_with_len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_appendix_a1_examples() {
        let cases: [(&[u8], u64); 4] = [
            (&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c], 151_288_809_941_952_652),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (bytes, v) in cases {
            assert_eq!(get_varint(bytes), Some((v, bytes.len())));
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out, bytes);
        }
        // A two-byte encoding of 37 decodes too (non-minimal is legal for varints).
        assert_eq!(get_varint(&[0x40, 0x25]), Some((37, 2)));
        assert_eq!(get_varint(&[0x40]), None);
        assert_eq!(get_varint(&[]), None);
    }

    #[test]
    fn boundaries() {
        for v in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, VARINT_MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out.len(), varint_len(v));
            assert_eq!(get_varint(&out), Some((v, out.len())));
            let mut fixed = [0u8; 8];
            put_varint_fixed(&mut fixed, v.min(16383), 2);
            assert_eq!(get_varint(&fixed[..2]).unwrap().0, v.min(16383));
        }
    }
}
