//! Brotli encoder (RFC 7932), qualities 0-11 mapped onto one design: LZ77 over a window of up
//! to 4 MiB, meta-blocks of up to 1 MiB with one block type per category, one literal,
//! command and distance prefix code each (no context modelling, no static dictionary
//! references), the last-distance code and implicit distances where they apply, and
//! uncompressed meta-blocks for data that doesn't compress. Higher qualities search longer
//! hash chains and add lazy matching.
//!
//! Streams are bit-packed across meta-blocks; [`BrotliEncoder::flush`] ends the current
//! meta-block and byte-aligns with an empty metadata block, so everything so far decodes.

use super::decode::{COPY, INS};
use crate::deflate::{build_lengths, gen_codes};
use crate::fastlz::Fast;
use crate::lz::{Lz, Seq};

/// Bytes per meta-block.
const META: usize = 1 << 20;

const CL_ORDER: [usize; 18] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[derive(Default)]
struct Bits {
    acc: u64,
    n: u32,
}

impl Bits {
    #[inline(always)]
    fn put(&mut self, out: &mut Vec<u8>, v: u32, bits: u32) {
        if bits == 0 {
            return;
        }
        self.acc |= ((v as u64) & ((1u64 << bits) - 1)) << self.n;
        self.n += bits;
        if self.n >= 32 {
            out.extend_from_slice(&(self.acc as u32).to_le_bytes());
            self.acc >>= 32;
            self.n -= 32;
        }
    }

    fn align(&mut self, out: &mut Vec<u8>) {
        while self.n > 0 {
            out.push(self.acc as u8);
            self.acc >>= 8;
            self.n = self.n.saturating_sub(8);
        }
        self.acc = 0;
    }
}

pub(crate) struct BrotliEncoder {
    lgwin: u32,
    lz: Lz,
    /// The match finder of qualities 0 and 1 (zstd's fast one: one hash table, the last
    /// distance checked first, matches extended backwards, faster skipping without matches),
    /// standing in for the reference's one-pass fragment compressor.
    fast: Option<Fast>,
    pending: usize,
    bits: Bits,
    started: bool,
    finished: bool,
    /// The decoder's last distance (the ring's newest entry).
    last_dist: u32,
    seqs: Vec<Seq>,
    pub(crate) total_in: u64,
}

impl BrotliEncoder {
    pub(crate) fn new(quality: u32) -> BrotliEncoder {
        let q = quality.min(11);
        let (lgwin, hbits, depth, lazy, nice, skip) = match q {
            0 | 1 => (18, 14, 1, false, 32, true),
            2 => (19, 16, 1, false, 32, true),
            3 => (20, 17, 4, false, 32, true),
            4 => (21, 17, 8, false, 64, true),
            5 => (22, 17, 16, true, 96, false),
            6..=8 => (22, 17, 32, true, 128, false),
            _ => (22, 18, 128, true, 258, false),
        };
        BrotliEncoder {
            lgwin,
            lz: Lz::new((1usize << lgwin) - 16, hbits, depth, lazy, nice, skip, 1 << 16),
            fast: if q <= 1 { Some(Fast::new((1usize << lgwin) - 16, if q == 0 { 12 } else { 14 }, if q == 0 { 8 } else { 6 }, 0).with_strength(if q == 0 { 7 } else { 8 })) } else { None },
            pending: 0,
            bits: Bits::default(),
            started: false,
            finished: false,
            last_dist: 4,
            seqs: Vec::new(),
            total_in: 0,
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.finished
    }

    fn start(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        let w = self.lgwin;
        let b = &mut self.bits;
        match w {
            16 => b.put(out, 0, 1),
            17 => {
                b.put(out, 1, 1);
                b.put(out, 0, 3);
                b.put(out, 0, 3);
            }
            18..=24 => {
                b.put(out, 1, 1);
                b.put(out, w - 17, 3);
            }
            _ => {
                b.put(out, 1, 1);
                b.put(out, 0, 3);
                b.put(out, w - 8, 3);
            }
        }
    }

    pub(crate) fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        assert!(!self.finished, "Encoder::encode after finish");
        self.start(out);
        self.total_in += input.len() as u64;
        self.lz.buf.extend_from_slice(input);
        while self.lz.buf.len() - self.pending >= META {
            self.meta_block(self.pending + META, out);
        }
    }

    pub(crate) fn flush(&mut self, out: &mut Vec<u8>) {
        assert!(!self.finished, "Encoder::flush after finish");
        self.start(out);
        if self.lz.buf.len() > self.pending {
            self.meta_block(self.lz.buf.len(), out);
        }
        // an empty metadata meta-block, then byte alignment
        let b = &mut self.bits;
        b.put(out, 0, 1); // ISLAST
        b.put(out, 3, 2); // MNIBBLES = 0
        b.put(out, 0, 1); // reserved
        b.put(out, 0, 2); // MSKIPBYTES = 0
        b.align(out);
    }

    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) {
        if self.finished {
            return;
        }
        self.start(out);
        while self.lz.buf.len() > self.pending {
            let end = (self.pending + META).min(self.lz.buf.len());
            self.meta_block(end, out);
        }
        // ISLAST, ISLASTEMPTY
        self.bits.put(out, 1, 1);
        self.bits.put(out, 1, 1);
        self.bits.align(out);
        self.finished = true;
    }

    fn meta_block(&mut self, end: usize, out: &mut Vec<u8>) {
        let start = self.pending;
        let mlen = end - start;
        self.seqs.clear();
        let mut seqs = std::mem::take(&mut self.seqs);
        let tail = match &mut self.fast {
            Some(f) => {
                // in pieces no longer than the window (the matcher's bound on sources is taken
                // from a piece's end); each piece's trailing literals open the next one
                let mut at = start;
                let mut carry = 0usize;
                while at < end {
                    let to = (at + (64 << 10)).min(end);
                    let first = seqs.len();
                    let t = f.parse(&self.lz.buf, self.lz.base, at, to, &mut seqs);
                    if let Some(s) = seqs.get_mut(first) {
                        s.lit += carry as u32;
                        carry = t;
                    } else {
                        carry += t;
                    }
                    at = to;
                }
                carry
            }
            None => self.lz.parse(start, end, &mut seqs),
        };
        // commands: (insert, copy, distance or 0 for "none")
        let mut cmds: Vec<(u32, u32, u32)> = seqs.iter().map(|s| (s.lit, s.len, s.dist)).collect();
        if tail > 0 {
            cmds.push((tail as u32, 4, 0));
        }
        self.seqs = seqs;
        let mut lit_f = [0u32; 256];
        let mut cmd_f = vec![0u32; 704];
        let mut dist_f = vec![0u32; 64];
        // (command code, insert extra, copy extra, distance code, distance extra bits, value)
        let mut coded = Vec::with_capacity(cmds.len());
        let mut last = self.last_dist;
        let mut p = start;
        let mut extra_bits = 0u64;
        for &(ins, copy, dist) in &cmds {
            for &b in &self.lz.buf[p..p + ins as usize] {
                lit_f[b as usize] += 1;
            }
            p += (ins + copy) as usize;
            let (ic, ie, ib) = len_code(&INS, ins);
            let (cc, ce, cb) = len_code(&COPY, copy);
            extra_bits += (ib + cb) as u64;
            // dist 0: the trailing literals, after which the meta-block ends (no distance)
            let implicit = (dist == 0 || dist == last) && ic < 8 && cc < 16;
            let code = cmd_code(ic, cc, implicit);
            let dcode = if implicit || dist == 0 {
                None
            } else if dist == last {
                Some((0u32, 0u32, 0u32))
            } else {
                last = dist;
                let v = dist + 3;
                let nbits = 31 - v.leading_zeros() - 1;
                let x = 2 * (nbits - 1) + ((v >> nbits) & 1);
                Some((16 + x, v - ((2 + (x & 1)) << nbits), nbits))
            };
            cmd_f[code as usize] += 1;
            if let Some((d, _, nb)) = dcode {
                dist_f[d as usize] += 1;
                extra_bits += nb as u64;
            }
            coded.push((code, ie, ib, ce, cb, dcode));
        }
        let mut lit_l = vec![0u8; 256];
        let mut cmd_l = vec![0u8; 704];
        let mut dist_l = vec![0u8; 64];
        build_lengths(&lit_f, 15, &mut lit_l);
        build_lengths(&cmd_f, 15, &mut cmd_l);
        build_lengths(&dist_f, 15, &mut dist_l);
        let cost = |f: &[u32], l: &[u8]| -> u64 { f.iter().zip(l).map(|(&a, &b)| a as u64 * b as u64).sum() };
        let used = |l: &[u8]| l.iter().filter(|&&x| x != 0).count() as u64;
        let header = 8 * 16 + 5 * (used(&lit_l) + used(&cmd_l) + used(&dist_l));
        let est = cost(&lit_f, &lit_l) + cost(&cmd_f, &cmd_l) + cost(&dist_f, &dist_l) + extra_bits + header;
        let b = &mut self.bits;
        if est > (mlen as u64 + 8) * 8 {
            // an uncompressed meta-block; the decoder's distance ring is unchanged
            write_mlen(b, out, mlen);
            b.put(out, 1, 1); // ISUNCOMPRESSED
            b.align(out);
            out.extend_from_slice(&self.lz.buf[start..end]);
        } else {
            write_mlen(b, out, mlen);
            b.put(out, 0, 1); // ISUNCOMPRESSED
            for _ in 0..3 {
                b.put(out, 0, 1); // NBLTYPES - 1 = 0
            }
            b.put(out, 0, 2); // NPOSTFIX
            b.put(out, 0, 4); // NDIRECT
            b.put(out, 0, 2); // context mode of the one literal block type
            b.put(out, 0, 1); // NTREESL - 1 = 0
            b.put(out, 0, 1); // NTREESD - 1 = 0
            let lit_c = write_code(b, out, &lit_l);
            let mut lit_code = [(0u16, 0u8); 256];
            lit_code[..lit_c.len().min(256)].copy_from_slice(&lit_c[..lit_c.len().min(256)]);
            let cmd_c = write_code(b, out, &cmd_l);
            let dist_c = write_code(b, out, &dist_l);
            let mut p = start;
            for (k, &(code, ie, ib, ce, cb, dcode)) in coded.iter().enumerate() {
                let (ins, copy, _) = cmds[k];
                let (c, l) = cmd_c[code as usize];
                b.put(out, c as u32, l as u32);
                b.put(out, ie, ib);
                b.put(out, ce, cb);
                // literals: codes (at most 15 bits) go straight into the accumulator, a word out
                // whenever 32 bits are pending
                for &x in &self.lz.buf[p..p + ins as usize] {
                    let (c, l) = lit_code[x as usize];
                    b.acc |= (c as u64) << b.n;
                    b.n += l as u32;
                    if b.n >= 32 {
                        out.extend_from_slice(&(b.acc as u32).to_le_bytes());
                        b.acc >>= 32;
                        b.n -= 32;
                    }
                }
                p += (ins + copy) as usize;
                if p > end {
                    break; // the last command: the meta-block ends after its literals
                }
                if let Some((d, e, nb)) = dcode {
                    let (c, l) = dist_c[d as usize];
                    b.put(out, c as u32, l as u32);
                    b.put(out, e, nb);
                }
            }
            self.last_dist = last;
        }
        self.pending = end;
        let keep = 1usize << self.lgwin;
        if self.pending > keep + META {
            let d = self.pending - keep;
            self.lz.slide(d);
            self.pending -= d;
        }
    }
}

/// ISLAST = 0 and MLEN in the fewest nibbles.
fn write_mlen(b: &mut Bits, out: &mut Vec<u8>, mlen: usize) {
    let v = (mlen - 1) as u32;
    let nibbles = if v < 1 << 16 {
        4
    } else if v < 1 << 20 {
        5
    } else {
        6
    };
    b.put(out, 0, 1);
    b.put(out, nibbles - 4, 2);
    b.put(out, v, 4 * nibbles);
}

/// (code, extra value, extra bits) of an insert or copy length.
#[inline(always)]
fn len_code(t: &[(u32, u32); 24], n: u32) -> (usize, u32, u32) {
    // lengths are mostly short: scan up from the small codes
    let mut i = 0;
    while i < 23 && t[i + 1].0 <= n {
        i += 1;
    }
    (i, n - t[i].0, t[i].1)
}

fn cmd_code(ic: usize, cc: usize, implicit: bool) -> u32 {
    let cell = if implicit {
        if cc < 8 {
            0
        } else {
            1
        }
    } else {
        match (ic / 8, cc / 8) {
            (0, 0) => 2,
            (0, 1) => 3,
            (1, 0) => 4,
            (1, 1) => 5,
            (0, _) => 6,
            (_, 0) => 7,
            (1, _) => 8,
            (_, 1) => 9,
            _ => 10,
        }
    };
    (cell * 64 + ((ic & 7) << 3) + (cc & 7)) as u32
}

/// Writes a prefix code for `lens` (section 3.4/3.5) and returns the (code, length) to send
/// each symbol with.
fn write_code(b: &mut Bits, out: &mut Vec<u8>, lens: &[u8]) -> Vec<(u16, u8)> {
    let size = lens.len();
    let used: Vec<usize> = (0..size).filter(|&s| lens[s] != 0).collect();
    let mut codes16 = vec![0u16; size];
    if used.len() <= 4 {
        let mut syms: Vec<usize> = if used.is_empty() { vec![0] } else { used.clone() };
        syms.sort_by_key(|&s| (lens[s], s));
        let abits = usize::BITS - (size - 1).leading_zeros();
        b.put(out, 1, 2);
        b.put(out, syms.len() as u32 - 1, 2);
        for &s in &syms {
            b.put(out, s as u32, abits);
        }
        let mut l = vec![0u8; size];
        match syms.len() {
            1 => return vec![(0, 0); size],
            2 => {
                l[syms[0]] = 1;
                l[syms[1]] = 1;
            }
            3 => {
                l[syms[0]] = 1;
                l[syms[1]] = 2;
                l[syms[2]] = 2;
            }
            _ => {
                let skew = lens[syms[0]] == 1;
                b.put(out, skew as u32, 1);
                if skew {
                    l[syms[0]] = 1;
                    l[syms[1]] = 2;
                    l[syms[2]] = 3;
                    l[syms[3]] = 3;
                } else {
                    for &s in &syms {
                        l[s] = 2;
                    }
                }
            }
        }
        gen_codes(&l, &mut codes16);
        return codes16.iter().zip(&l).map(|(&c, &n)| (c, n)).collect();
    }
    // run-length code the lengths: literal 0-15, 17 for runs of three or more zeros
    let last = *used.last().expect("non-empty");
    let mut rle: Vec<(u8, u8)> = Vec::new();
    let mut i = 0;
    while i <= last {
        let l = lens[i];
        if l != 0 {
            rle.push((l, 0));
            i += 1;
            continue;
        }
        let mut run = 0;
        while i + run <= last && lens[i + run] == 0 {
            run += 1;
        }
        i += run;
        if run < 3 {
            for _ in 0..run {
                rle.push((0, 0));
            }
        } else {
            let at = rle.len();
            let mut r = run - 3;
            loop {
                rle.push((17, (r & 7) as u8));
                r >>= 3;
                if r == 0 {
                    break;
                }
                r -= 1;
            }
            rle[at..].reverse();
        }
    }
    let mut cf = [0u32; 18];
    for &(s, _) in &rle {
        cf[s as usize] += 1;
    }
    let mut cl = [0u8; 18];
    build_lengths(&cf, 5, &mut cl);
    let single = cl.iter().filter(|&&x| x != 0).count() == 1;
    let hskip = if cl[1] == 0 && cl[2] == 0 {
        if cl[3] == 0 {
            3
        } else {
            2
        }
    } else {
        0
    };
    b.put(out, hskip, 2);
    let mut space: i32 = 32;
    for &o in &CL_ORDER[hskip as usize..] {
        let v = cl[o];
        // the fixed code for code length code lengths
        let (bits, n) = match v {
            0 => (0, 2),
            1 => (7, 4),
            2 => (3, 3),
            3 => (2, 2),
            4 => (1, 2),
            _ => (15, 4),
        };
        b.put(out, bits, n);
        if v != 0 {
            space -= 32 >> v;
            if space <= 0 {
                break;
            }
        }
    }
    let mut clc = [0u16; 18];
    gen_codes(&cl, &mut clc);
    for &(s, x) in &rle {
        if !single {
            b.put(out, clc[s as usize] as u32, cl[s as usize] as u32);
        }
        if s == 17 {
            b.put(out, x as u32, 3);
        }
    }
    gen_codes(lens, &mut codes16);
    codes16.iter().zip(lens).map(|(&c, &n)| (c, n)).collect()
}
