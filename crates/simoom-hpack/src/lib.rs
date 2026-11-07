//! HPACK (RFC 7541) for simoom.
//!
//! - [`Decoder`]: decodes header blocks into a callback, with a cap on the dynamic table size
//!   (the value we advertise in `SETTINGS_HEADER_TABLE_SIZE`) and on the decoded header list
//!   size. Literal strings that are not Huffman coded are passed straight from the input;
//!   Huffman strings are decoded into two reusable scratch buffers, and the dynamic table keeps
//!   all entries in one byte buffer, so steady-state decoding does not allocate.
//! - [`Encoder`]: indexes repeated fields, never indexes sensitive ones (`authorization`,
//!   `proxy-authorization`, `cookie`, `set-cookie`), and does not index fields whose values are
//!   usually unique (`content-length`, `etag`, validators, `:path` with a query).
//! - [`huffman`]: table-driven Huffman decoding, four bits per step, and encoding.
//!
//! ```
//! use simoom_hpack::{Decoder, Encoder};
//! let mut enc = Encoder::new(4096);
//! let mut dec = Decoder::new(4096, 16 * 1024);
//! let mut block = Vec::new();
//! enc.encode(&[(b":method", b"GET"), (b"x-id", b"42")], &mut block);
//! let mut got = Vec::new();
//! dec.decode(&block, &mut |n: &[u8], v: &[u8]| got.push((n.to_vec(), v.to_vec()))).unwrap();
//! assert_eq!(got[1], (b"x-id".to_vec(), b"42".to_vec()));
//! ```
#![forbid(unsafe_code)]

mod decoder;
mod encoder;
pub mod huffman;
mod table;

pub use decoder::Decoder;
pub use encoder::{is_sensitive, Encoder};
pub use table::STATIC_TABLE;

use std::fmt;

/// The protocol's initial dynamic table size (RFC 7541 §4.2, RFC 9113 §6.5.2).
pub const DEFAULT_TABLE_SIZE: usize = 4096;

/// Size of a header field for table and list accounting: name + value + 32 (RFC 7541 §4.1).
#[inline]
pub fn field_size(name: &[u8], value: &[u8]) -> usize {
    name.len() + value.len() + 32
}

/// HPACK decoding errors. Every error except [`Error::HeaderListTooLarge`] leaves the decoder
/// out of step with the peer's encoder and maps to the HTTP/2 connection error
/// `COMPRESSION_ERROR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The block ends in the middle of a representation.
    Truncated,
    /// A prefix integer is too large.
    IntegerOverflow,
    /// An index outside the static and dynamic tables (or index 0).
    InvalidIndex,
    /// Invalid Huffman data: EOS in the string, bad or overlong padding.
    Huffman,
    /// A dynamic table size update above the allowed maximum or after the first field.
    InvalidTableSizeUpdate,
    /// The decoded list is larger than the cap. The block was still decoded completely, so the
    /// decoder stays in step with the encoder and the connection can continue; fields after the
    /// limit were not passed to the callback.
    HeaderListTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated header block",
            Error::IntegerOverflow => "integer overflow",
            Error::InvalidIndex => "invalid table index",
            Error::Huffman => "invalid huffman string",
            Error::InvalidTableSizeUpdate => "invalid dynamic table size update",
            Error::HeaderListTooLarge => "header list too large",
        })
    }
}

impl std::error::Error for Error {}

/// Byte-slice equality for short strings, done with word loads instead of a `memcmp` call
/// (header names and values are mostly under 32 bytes).
#[inline]
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if n != b.len() {
        return false;
    }
    if n >= 8 {
        #[inline(always)]
        fn w(s: &[u8], i: usize) -> u64 {
            u64::from_ne_bytes(s[i..i + 8].try_into().unwrap_or([0; 8]))
        }
        let mut i = 0;
        while i + 8 <= n {
            if w(a, i) != w(b, i) {
                return false;
            }
            i += 8;
        }
        i == n || w(a, n - 8) == w(b, n - 8)
    } else if n >= 4 {
        #[inline(always)]
        fn w(s: &[u8], i: usize) -> u32 {
            u32::from_ne_bytes(s[i..i + 4].try_into().unwrap_or([0; 4]))
        }
        w(a, 0) == w(b, 0) && w(a, n - 4) == w(b, n - 4)
    } else {
        a.iter().zip(b).all(|(x, y)| x == y)
    }
}

/// Encodes `value` with an N-bit prefix (RFC 7541 §5.1); `first` holds the high bits of the
/// first byte.
pub fn encode_integer(value: usize, prefix_bits: u8, first: u8, out: &mut Vec<u8>) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    let mut v = value - max;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decodes an N-bit prefix integer at `buf[*pos]`. At most four continuation bytes are
/// accepted (values up to about 2^28), far above anything a header block can carry.
pub fn decode_integer(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<usize, Error> {
    let max = (1usize << prefix_bits) - 1;
    let first = *buf.get(*pos).ok_or(Error::Truncated)? as usize & max;
    *pos += 1;
    if first < max {
        return Ok(first);
    }
    let mut value = max;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or(Error::Truncated)? as usize;
        *pos += 1;
        if shift > 21 {
            return Err(Error::IntegerOverflow);
        }
        value += (b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// Encodes a string literal, Huffman coded when that is shorter and `huffman` is set.
pub fn encode_string(s: &[u8], huffman: bool, out: &mut Vec<u8>) {
    if huffman {
        let hlen = huffman::encoded_len(s);
        if hlen < s.len() {
            encode_integer(hlen, 7, 0x80, out);
            huffman::encode(s, out);
            return;
        }
    }
    encode_integer(s.len(), 7, 0, out);
    out.extend_from_slice(s);
}

/// Reads a string literal: a slice of `block` when it is raw, or the Huffman-decoded bytes in
/// `scratch`.
pub(crate) fn read_string<'a>(block: &'a [u8], pos: &mut usize, scratch: &'a mut Vec<u8>) -> Result<&'a [u8], Error> {
    let huff = *block.get(*pos).ok_or(Error::Truncated)? & 0x80 != 0;
    let len = decode_integer(block, pos, 7)?;
    if len > block.len() - *pos {
        return Err(Error::Truncated);
    }
    let raw = &block[*pos..*pos + len];
    *pos += len;
    if huff {
        scratch.clear();
        huffman::decode(raw, scratch)?;
        Ok(scratch)
    } else {
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_c1() {
        let mut out = Vec::new();
        encode_integer(10, 5, 0, &mut out);
        assert_eq!(out, [0b01010]);
        out.clear();
        encode_integer(1337, 5, 0, &mut out);
        assert_eq!(out, [31, 154, 10]);
        let mut pos = 0;
        assert_eq!(decode_integer(&out, &mut pos, 5), Ok(1337));
        assert_eq!(pos, 3);
        out.clear();
        encode_integer(42, 8, 0, &mut out);
        assert_eq!(out, [42]);
        for v in [0usize, 30, 31, 127, 128, 255, 16_383, 1 << 20, (1 << 28) - 1] {
            for p in 1..=8u8 {
                let mut o = Vec::new();
                encode_integer(v, p, 0, &mut o);
                let mut pos = 0;
                assert_eq!(decode_integer(&o, &mut pos, p), Ok(v), "{v} prefix {p}");
                assert_eq!(pos, o.len());
            }
        }
        let mut pos = 0;
        assert_eq!(decode_integer(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], &mut pos, 5), Err(Error::IntegerOverflow));
        let mut pos = 0;
        assert_eq!(decode_integer(&[0x1f, 0xff], &mut pos, 5), Err(Error::Truncated));
        let mut pos = 0;
        assert_eq!(decode_integer(&[], &mut pos, 5), Err(Error::Truncated));
    }

    #[test]
    fn short_equality() {
        let s = b"abcdefghijklmnopqrstuvwxyz0123456789";
        for i in 0..s.len() {
            for j in i..s.len() {
                let a = &s[i..j];
                assert!(bytes_eq(a, &a.to_vec()));
                let mut b = a.to_vec();
                for k in 0..b.len() {
                    b[k] ^= 1;
                    assert!(!bytes_eq(a, &b));
                    b[k] ^= 1;
                }
                if j < s.len() {
                    assert!(!bytes_eq(a, &s[i..j + 1]), "different lengths");
                }
            }
        }
    }

    #[test]
    fn strings() {
        let mut out = Vec::new();
        encode_string(b"www.example.com", true, &mut out);
        assert_eq!(out[0], 0x8c);
        let mut scratch = Vec::new();
        let mut pos = 0;
        assert_eq!(read_string(&out, &mut pos, &mut scratch).unwrap(), b"www.example.com");
        out.clear();
        encode_string(b"\xff\xfe", true, &mut out); // Huffman would be longer
        assert_eq!(out, [2, 0xff, 0xfe]);
        let mut pos = 0;
        assert_eq!(read_string(&[5, b'a'], &mut pos, &mut scratch), Err(Error::Truncated));
    }
}
