//! HPACK Huffman coding (RFC 7541 §5.2 and Appendix B).
//!
//! Decoding walks a finite-state machine four bits at a time: the states are the 256 internal
//! nodes of the code tree, and each (state, nibble) pair maps to the next state, at most one
//! emitted symbol (the shortest code is 5 bits) and whether the bits since the last symbol are
//! valid padding. The 16 KiB table is built once on first use rather than stored in the binary.

use std::sync::OnceLock;

use crate::Error;

/// RFC 7541 Appendix B: (code, bit length) for symbols 0..=256 (256 = EOS).
const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// Number of bytes `data` occupies once Huffman encoded.
pub fn encoded_len(data: &[u8]) -> usize {
    let bits: usize = data.iter().map(|&b| CODES[b as usize].1 as usize).sum();
    bits.div_ceil(8)
}

/// Huffman-encodes `data`, appending to `out` (padded with the EOS prefix).
pub fn encode(data: &[u8], out: &mut Vec<u8>) {
    out.reserve(data.len());
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        let (code, len) = CODES[b as usize];
        acc = (acc << len) | code as u64;
        nbits += len as u32;
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        let pad = 8 - nbits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
}

const EMIT: u32 = 1 << 16;
const FAIL: u32 = 1 << 17;
const ACCEPT: u32 = 1 << 18;

/// Entry `state * 16 + nibble`: bits 0-7 next state, 8-15 symbol, then EMIT, FAIL, ACCEPT.
fn fsm() -> &'static [u32; 4096] {
    static FSM: OnceLock<Box<[u32; 4096]>> = OnceLock::new();
    FSM.get_or_init(build_fsm)
}

fn build_fsm() -> Box<[u32; 4096]> {
    // Code tree: children of internal node i; 0x8000 | symbol marks a leaf, 0 an empty slot.
    let mut tree: Vec<[u16; 2]> = vec![[0, 0]];
    // per internal node: depth, and whether the path from the root is all one bits
    let mut depth: Vec<u8> = vec![0];
    let mut ones: Vec<bool> = vec![true];
    for (sym, &(code, len)) in CODES.iter().enumerate() {
        let mut node = 0usize;
        for i in (0..len).rev() {
            let bit = ((code >> i) & 1) as usize;
            if i == 0 {
                tree[node][bit] = 0x8000 | sym as u16;
            } else if tree[node][bit] == 0 {
                tree.push([0, 0]);
                depth.push(depth[node] + 1);
                ones.push(ones[node] && bit == 1);
                let idx = tree.len() - 1;
                tree[node][bit] = idx as u16;
                node = idx;
            } else {
                node = tree[node][bit] as usize;
            }
        }
    }
    debug_assert_eq!(tree.len(), 256);
    let mut t = Box::new([0u32; 4096]);
    for state in 0..tree.len() {
        for nib in 0..16usize {
            let mut node = state;
            let mut entry = 0u32;
            for i in (0..4).rev() {
                let c = tree[node][(nib >> i) & 1];
                if c & 0x8000 != 0 {
                    let sym = (c & 0x1ff) as u32;
                    if sym == 256 {
                        entry |= FAIL;
                        break;
                    }
                    entry |= EMIT | (sym << 8);
                    node = 0;
                } else {
                    node = c as usize;
                }
            }
            if node == 0 || (ones[node] && depth[node] <= 7) {
                entry |= ACCEPT;
            }
            t[state * 16 + nib] = entry | node as u32;
        }
    }
    t
}

/// Decodes a Huffman-encoded string, appending to `out`.
pub fn decode(data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let t = fsm();
    // at most 8/5 symbols per byte
    out.reserve(data.len() * 8 / 5 + 1);
    let mut e = ACCEPT; // state 0, nothing pending
    for &byte in data {
        // the masks keep the index in range, so there are no bounds checks
        e = t[(((e & 0xff) << 4) | (byte >> 4) as u32) as usize & 0xfff];
        if e & (EMIT | FAIL) != 0 {
            if e & FAIL != 0 {
                return Err(Error::Huffman);
            }
            out.push((e >> 8) as u8);
        }
        e = t[(((e & 0xff) << 4) | (byte & 0xf) as u32) as usize & 0xfff];
        if e & (EMIT | FAIL) != 0 {
            if e & FAIL != 0 {
                return Err(Error::Huffman);
            }
            out.push((e >> 8) as u8);
        }
    }
    if e & ACCEPT != 0 {
        Ok(())
    } else {
        Err(Error::Huffman)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn dec(b: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        decode(b, &mut out).map(|_| out)
    }

    #[test]
    fn rfc_examples() {
        let mut out = Vec::new();
        encode(b"www.example.com", &mut out);
        assert_eq!(out, hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"));
        assert_eq!(dec(&out).unwrap(), b"www.example.com");
        assert_eq!(encoded_len(b"www.example.com"), 12);
        assert_eq!(dec(&hex("a8eb 1064 9cbf")).unwrap(), b"no-cache");
        assert_eq!(dec(&hex("25a8 49e9 5ba9 7d7f")).unwrap(), b"custom-key");
        assert_eq!(dec(&hex("25a8 49e9 5bb8 e8b4 bf")).unwrap(), b"custom-value");
        assert_eq!(dec(&hex("6402")).unwrap(), b"302");
        assert_eq!(dec(&hex("aec3 771a 4b")).unwrap(), b"private");
        assert_eq!(dec(&hex("d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff")).unwrap(), b"Mon, 21 Oct 2013 20:13:21 GMT");
        assert_eq!(dec(&hex("9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3")).unwrap(), b"https://www.example.com");
    }

    #[test]
    fn all_bytes_round_trip() {
        let data: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        let mut out = Vec::new();
        encode(&data, &mut out);
        assert_eq!(out.len(), encoded_len(&data));
        assert_eq!(dec(&out).unwrap(), data);
        for n in 0..64usize {
            let s: Vec<u8> = (0..n).map(|i| (i * 37 + n) as u8).collect();
            let mut o = Vec::new();
            encode(&s, &mut o);
            assert_eq!(dec(&o).unwrap(), s);
        }
        assert_eq!(dec(&[]).unwrap(), b"");
    }

    #[test]
    fn invalid_padding_and_eos() {
        // 'a' = 00011; padding must be ones
        assert!(dec(&[0b0001_1000]).is_err());
        assert_eq!(dec(&[0b0001_1111]).unwrap(), b"a");
        // a full byte of ones is more than 7 bits of padding
        assert!(dec(&[0b0001_1111, 0xff]).is_err());
        assert!(dec(&[0xff]).is_err());
        // EOS (30 ones) inside the string
        assert!(dec(&[0xff, 0xff, 0xff, 0xff]).is_err());
        // ends inside a code that is not an EOS prefix
        assert!(dec(&[0xfe]).is_err());
    }
}
