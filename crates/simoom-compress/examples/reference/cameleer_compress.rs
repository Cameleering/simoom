//! Cameleer's DEFLATE, gzip and zlib code (`cameleer-core/src/dataformat/compress.rs`, same
//! owner and licence), copied verbatim between its "Checksums" and "ZIP" sections, as the
//! baseline for `bench_compress`. Only the error type is replaced.
#![allow(dead_code, clippy::all)]

type Result<T> = std::result::Result<T, String>;

fn data_err(msg: impl Into<String>) -> String {
    msg.into()
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

fn crc_table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static T: OnceLock<[u32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    })
}

/// CRC-32 (IEEE 802.3) checksum.
pub fn crc32(data: &[u8]) -> u32 {
    let t = crc_table();
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = t[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Adler-32 checksum.
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

const LEN_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] =
    [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// ---------------------------------------------------------------------------
// Inflate
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0, buf: 0, cnt: 0 }
    }
    fn need(&mut self, n: u32) -> Result<()> {
        while self.cnt < n {
            let b = *self.data.get(self.pos).ok_or_else(|| data_err("Unexpected end of compressed data"))?;
            self.pos += 1;
            self.buf |= (b as u64) << self.cnt;
            self.cnt += 8;
        }
        Ok(())
    }
    fn bits(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        self.need(n)?;
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }
    fn align(&mut self) {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
    }
    /// Byte position after the consumed bits (whole bytes still buffered are given back).
    fn byte_pos(&self) -> usize {
        self.pos - (self.cnt / 8) as usize
    }
}

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Huffman> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        let mut left: i32 = 1;
        for len in 1..16 {
            left <<= 1;
            left -= counts[len] as i32;
            if left < 0 {
                return Err(data_err("Invalid Huffman code (over-subscribed)"));
            }
        }
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huffman { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader) -> Result<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= br.bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - count < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(data_err("Invalid Huffman code"))
    }
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut l = [0u8; 288];
    for (i, x) in l.iter_mut().enumerate() {
        *x = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    (Huffman::new(&l).unwrap(), Huffman::new(&[5u8; 30]).unwrap())
}

fn inflate_codes(br: &mut BitReader, out: &mut Vec<u8>, lit: &Huffman, dist: &Huffman, limit: usize) -> Result<()> {
    loop {
        let sym = lit.decode(br)?;
        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            return Ok(());
        } else {
            let s = (sym - 257) as usize;
            if s >= 29 {
                return Err(data_err("Invalid length symbol"));
            }
            let len = LEN_BASE[s] as usize + br.bits(LEN_EXTRA[s] as u32)? as usize;
            let ds = dist.decode(br)? as usize;
            if ds >= 30 {
                return Err(data_err("Invalid distance symbol"));
            }
            let d = DIST_BASE[ds] as usize + br.bits(DIST_EXTRA[ds] as u32)? as usize;
            if d > out.len() {
                return Err(data_err("Invalid distance (too far back)"));
            }
            let start = out.len() - d;
            for k in 0..len {
                let b = out[start + k];
                out.push(b);
            }
        }
        if out.len() > limit {
            return Err(data_err("Decompressed data exceeds the size limit"));
        }
    }
}

/// Inflate raw DEFLATE data. Returns the output and the number of input bytes consumed.
pub fn inflate_raw(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    inflate_limited(data, usize::MAX / 2)
}

fn inflate_limited(data: &[u8], limit: usize) -> Result<(Vec<u8>, usize)> {
    let mut br = BitReader::new(data);
    let mut out = Vec::with_capacity(data.len() * 3);
    loop {
        let last = br.bits(1)?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                br.align();
                let len = br.bits(16)? as usize;
                let nlen = br.bits(16)? as usize;
                if len != (!nlen & 0xFFFF) {
                    return Err(data_err("Invalid stored block lengths"));
                }
                // remaining buffered bits are whole bytes after align
                for _ in 0..len {
                    out.push(br.bits(8)? as u8);
                }
            }
            1 => {
                let (l, d) = fixed_tables();
                inflate_codes(&mut br, &mut out, &l, &d, limit)?;
            }
            2 => {
                let hlit = br.bits(5)? as usize + 257;
                let hdist = br.bits(5)? as usize + 1;
                let hclen = br.bits(4)? as usize + 4;
                if hlit > 286 || hdist > 30 {
                    return Err(data_err("Invalid dynamic block header"));
                }
                let mut cl = [0u8; 19];
                for &idx in CL_ORDER.iter().take(hclen) {
                    cl[idx] = br.bits(3)? as u8;
                }
                let clh = Huffman::new(&cl)?;
                let mut lens = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < hlit + hdist {
                    let sym = clh.decode(&mut br)?;
                    match sym {
                        0..=15 => {
                            lens[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return Err(data_err("Repeat with no previous length"));
                            }
                            let prev = lens[i - 1];
                            let n = 3 + br.bits(2)? as usize;
                            if i + n > lens.len() {
                                return Err(data_err("Too many code lengths"));
                            }
                            for _ in 0..n {
                                lens[i] = prev;
                                i += 1;
                            }
                        }
                        17 | 18 => {
                            let n = if sym == 17 { 3 + br.bits(3)? as usize } else { 11 + br.bits(7)? as usize };
                            if i + n > lens.len() {
                                return Err(data_err("Too many code lengths"));
                            }
                            i += n;
                        }
                        _ => return Err(data_err("Invalid code length symbol")),
                    }
                }
                if lens[256] == 0 {
                    return Err(data_err("Missing end-of-block code"));
                }
                let lit = Huffman::new(&lens[..hlit])?;
                let dist = Huffman::new(&lens[hlit..])?;
                inflate_codes(&mut br, &mut out, &lit, &dist, limit)?;
            }
            _ => return Err(data_err("Invalid block type")),
        }
        if out.len() > limit {
            return Err(data_err("Decompressed data exceeds the size limit"));
        }
        if last == 1 {
            break;
        }
    }
    br.align();
    Ok((out, br.byte_pos()))
}

/// Inflate raw DEFLATE data.
pub fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    Ok(inflate_raw(data)?.0)
}

// ---------------------------------------------------------------------------
// Deflate
// ---------------------------------------------------------------------------

struct BitWriter {
    out: Vec<u8>,
    buf: u64,
    cnt: u32,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter { out: Vec::new(), buf: 0, cnt: 0 }
    }
    fn put(&mut self, v: u32, n: u32) {
        self.buf |= (v as u64) << self.cnt;
        self.cnt += n;
        while self.cnt >= 8 {
            self.out.push(self.buf as u8);
            self.buf >>= 8;
            self.cnt -= 8;
        }
    }
    /// Write a Huffman code (MSB-first) of `n` bits.
    fn put_code(&mut self, code: u32, n: u32) {
        let mut rev = 0u32;
        for i in 0..n {
            if code & (1 << i) != 0 {
                rev |= 1 << (n - 1 - i);
            }
        }
        self.put(rev, n);
    }
    fn flush(mut self) -> Vec<u8> {
        if self.cnt > 0 {
            self.out.push(self.buf as u8);
        }
        self.out
    }
}

fn fixed_lit(w: &mut BitWriter, sym: u32) {
    match sym {
        0..=143 => w.put_code(0x30 + sym, 8),
        144..=255 => w.put_code(0x190 + (sym - 144), 9),
        256..=279 => w.put_code(sym - 256, 7),
        _ => w.put_code(0xC0 + (sym - 280), 8),
    }
}

fn len_code(len: usize) -> (usize, u32, u32) {
    let mut i = 28;
    while LEN_BASE[i] as usize > len {
        i -= 1;
    }
    (i, (len - LEN_BASE[i] as usize) as u32, LEN_EXTRA[i] as u32)
}

fn dist_code(d: usize) -> (usize, u32, u32) {
    let mut i = 29;
    while DIST_BASE[i] as usize > d {
        i -= 1;
    }
    (i, (d - DIST_BASE[i] as usize) as u32, DIST_EXTRA[i] as u32)
}

/// Compress to raw DEFLATE. `level` 0 = stored blocks, 1-9 = LZ77 + fixed Huffman
/// (higher levels search longer hash chains).
pub fn deflate(data: &[u8], level: u32) -> Vec<u8> {
    if level == 0 {
        let mut out = Vec::new();
        if data.is_empty() {
            out.extend_from_slice(&[1, 0, 0, 0xFF, 0xFF]);
            return out;
        }
        let chunks: Vec<&[u8]> = data.chunks(65535).collect();
        for (i, c) in chunks.iter().enumerate() {
            out.push(if i + 1 == chunks.len() { 1 } else { 0 });
            let len = c.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(c);
        }
        return out;
    }
    const WSIZE: usize = 32768;
    const HBITS: u32 = 15;
    let max_chain = match level {
        1..=3 => 16,
        4..=6 => 64,
        _ => 256,
    };
    let mut w = BitWriter::new();
    w.put(1, 1); // final block
    w.put(1, 2); // fixed Huffman
    let n = data.len();
    let mut head = vec![usize::MAX; 1 << HBITS];
    let mut prev = vec![usize::MAX; WSIZE];
    let hash = |i: usize| -> usize {
        let v = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | data[i + 2] as u32;
        (v.wrapping_mul(2654435761) >> (32 - HBITS)) as usize
    };
    let insert = |i: usize, head: &mut Vec<usize>, prev: &mut Vec<usize>| {
        if i + 2 < n {
            let h = hash(i);
            prev[i % WSIZE] = head[h];
            head[h] = i;
        }
    };
    let mut i = 0;
    while i < n {
        let mut best_len = 0;
        let mut best_dist = 0;
        if i + 2 < n {
            let h = hash(i);
            let mut cand = head[h];
            let mut chain = 0;
            let max_len = (n - i).min(258);
            while cand != usize::MAX && chain < max_chain {
                if i - cand > WSIZE - 1 {
                    break;
                }
                if data[cand + best_len.min(max_len - 1)] == data[i + best_len.min(max_len - 1)] {
                    let mut l = 0;
                    while l < max_len && data[cand + l] == data[i + l] {
                        l += 1;
                    }
                    if l > best_len {
                        best_len = l;
                        best_dist = i - cand;
                        if l == max_len {
                            break;
                        }
                    }
                }
                let p = prev[cand % WSIZE];
                if p == usize::MAX || p >= cand {
                    break;
                }
                cand = p;
                chain += 1;
            }
        }
        if best_len >= 3 {
            let (lc, lextra, lbits) = len_code(best_len);
            fixed_lit(&mut w, 257 + lc as u32);
            w.put(lextra, lbits);
            let (dc, dextra, dbits) = dist_code(best_dist);
            w.put_code(dc as u32, 5);
            w.put(dextra, dbits);
            for k in 0..best_len {
                insert(i + k, &mut head, &mut prev);
            }
            i += best_len;
        } else {
            fixed_lit(&mut w, data[i] as u32);
            insert(i, &mut head, &mut prev);
            i += 1;
        }
    }
    fixed_lit(&mut w, 256);
    w.flush()
}

// ---------------------------------------------------------------------------
// gzip / zlib
// ---------------------------------------------------------------------------

/// Compress to the gzip format.
pub fn gzip_compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, if level >= 9 { 2 } else { 0 }, 255];
    out.extend(deflate(data, level));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// Decompress gzip data (supports multiple members, FEXTRA/FNAME/FCOMMENT/FHCRC).
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < data.len() {
        let d = &data[p..];
        if d.len() < 18 || d[0] != 0x1f || d[1] != 0x8b {
            if p > 0 && d.iter().all(|&b| b == 0) {
                break; // trailing padding
            }
            return Err(data_err("Not in GZIP format"));
        }
        if d[2] != 8 {
            return Err(data_err("Unsupported GZIP compression method"));
        }
        let flags = d[3];
        let mut i = 10;
        if flags & 4 != 0 {
            let xlen = u16::from_le_bytes([d[i], d[i + 1]]) as usize;
            i += 2 + xlen;
        }
        if flags & 8 != 0 {
            while i < d.len() && d[i] != 0 {
                i += 1;
            }
            i += 1;
        }
        if flags & 16 != 0 {
            while i < d.len() && d[i] != 0 {
                i += 1;
            }
            i += 1;
        }
        if flags & 2 != 0 {
            i += 2;
        }
        if i >= d.len() {
            return Err(data_err("Truncated GZIP header"));
        }
        let (member, used) = inflate_raw(&d[i..])?;
        let t = i + used;
        if t + 8 > d.len() {
            return Err(data_err("Truncated GZIP trailer"));
        }
        let crc = u32::from_le_bytes([d[t], d[t + 1], d[t + 2], d[t + 3]]);
        let size = u32::from_le_bytes([d[t + 4], d[t + 5], d[t + 6], d[t + 7]]);
        if crc != crc32(&member) {
            return Err(data_err("Corrupt GZIP trailer (CRC mismatch)"));
        }
        if size != member.len() as u32 {
            return Err(data_err("Corrupt GZIP trailer (size mismatch)"));
        }
        out.extend(member);
        p += t + 8;
    }
    Ok(out)
}

/// Compress to the zlib format (what `java.util.zip.Deflater` produces).
pub fn zlib_compress(data: &[u8], level: u32) -> Vec<u8> {
    let flevel = match level {
        0 | 1 => 0,
        2..=5 => 1,
        6 => 2,
        _ => 3,
    };
    let cmf = 0x78u8;
    let mut flg = flevel << 6;
    let rem = ((cmf as u16) << 8 | flg as u16) % 31;
    if rem != 0 {
        flg += (31 - rem) as u8;
    }
    let mut out = vec![cmf, flg];
    out.extend(deflate(data, level));
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Decompress zlib data (raw DEFLATE is accepted as a fallback).
pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() >= 2 && data[0] & 0x0f == 8 && ((data[0] as u16) << 8 | data[1] as u16).is_multiple_of(31) {
        if data[1] & 0x20 != 0 {
            return Err(data_err("zlib preset dictionaries are not supported"));
        }
        let (out, used) = inflate_raw(&data[2..])?;
        let t = 2 + used;
        if t + 4 <= data.len() {
            let a = u32::from_be_bytes([data[t], data[t + 1], data[t + 2], data[t + 3]]);
            if a != adler32(&out) {
                return Err(data_err("Incorrect data check (Adler-32 mismatch)"));
            }
        }
        return Ok(out);
    }
    inflate(data)
}

