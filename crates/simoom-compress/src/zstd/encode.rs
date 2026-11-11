//! zstd encoder (RFC 8878): one frame, 128 KiB blocks, Huffman-coded literals (direct or
//! FSE-coded weights), sequences coded with predefined, RLE or fitted FSE tables (whichever is
//! smallest), repeat offsets, and the XXH64 content checksum. Levels 1-2 are greedy with a
//! single hash probe, 3-5 search hash chains, 6 and up add lazy matching; the window is
//! 512 KiB to 2 MiB, inside the 8 MiB HTTP limit.

use super::fse::{highbit, huf_codes, normalize, write_ncount, BitWriter, CTable, Xxh64};
use super::{LL_BITS, LL_NORM, ML_BITS, ML_NORM, OF_NORM};
use crate::deflate::build_lengths;
use crate::fastlz::Fast;
use simoom_sys::codec::SeqCode;
use crate::lz::{Lz, Seq};

const MAGIC: u32 = 0xFD2F_B528;
const BLOCK: usize = 128 * 1024;

pub(crate) struct ZstdEncoder {
    wlog: u32,
    /// The input buffer, and the match finder of levels 4 and up.
    lz: Lz,
    /// The match finder of levels 1 to 3.
    fast: Option<Fast>,
    /// Index in `lz.buf` of the first byte not yet coded.
    pending: usize,
    hash: Xxh64,
    started: bool,
    finished: bool,
    reps: [u32; 3],
    seqs: Vec<Seq>,
    codes: Vec<SeqCode>,
    pub(crate) total_in: u64,
}

impl ZstdEncoder {
    pub(crate) fn new(level: u32) -> ZstdEncoder {
        let level = level.clamp(1, 22);
        // levels 1 to 3: zstd's parameters for inputs over 256 KiB (window log, short hash log,
        // short hash bytes, long hash log)
        let fast = match level {
            1 => Some((19, 13, 6, 0)),
            2 => Some((20, 15, 6, 16)),
            3 => Some((21, 16, 5, 17)),
            _ => None,
        };
        let (wlog, hbits, depth, lazy, nice, skip) = match level {
            1..=3 => (fast.map_or(19, |f| f.0), 14, 1, false, 32, true),
            4 => (20, 17, 8, false, 64, true),
            5 => (21, 17, 16, false, 96, false),
            6..=9 => (21, 17, 32, true, 128, false),
            _ => (21, 18, 128, true, 256, false),
        };
        ZstdEncoder {
            wlog,
            lz: Lz::new(1 << wlog, hbits, depth, lazy, nice, skip, 1 << 16),
            fast: fast.map(|(w, s, m, l)| Fast::new(1 << w, s, m, l)),
            pending: 0,
            hash: Xxh64::default(),
            started: false,
            finished: false,
            reps: [1, 4, 8],
            seqs: Vec::new(),
            codes: Vec::new(),
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
        out.extend_from_slice(&MAGIC.to_le_bytes());
        // no content size, checksum, not single-segment; window descriptor 2^wlog
        out.push(0x04);
        out.push(((self.wlog - 10) << 3) as u8);
    }

    pub(crate) fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        assert!(!self.finished, "Encoder::encode after finish");
        self.start(out);
        self.hash.update(input);
        self.total_in += input.len() as u64;
        self.lz.buf.extend_from_slice(input);
        while self.lz.buf.len() - self.pending >= BLOCK {
            self.block(self.pending + BLOCK, false, out);
        }
    }

    pub(crate) fn flush(&mut self, out: &mut Vec<u8>) {
        assert!(!self.finished, "Encoder::flush after finish");
        self.start(out);
        if self.lz.buf.len() > self.pending {
            self.block(self.lz.buf.len(), false, out);
        }
    }

    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) {
        if self.finished {
            return;
        }
        self.start(out);
        while self.lz.buf.len() - self.pending > BLOCK {
            self.block(self.pending + BLOCK, false, out);
        }
        self.block(self.lz.buf.len(), true, out);
        out.extend_from_slice(&(self.hash.digest() as u32).to_le_bytes());
        self.finished = true;
    }

    /// Codes `lz.buf[pending..end]` as one block.
    fn block(&mut self, end: usize, last: bool, out: &mut Vec<u8>) {
        let start = self.pending;
        let raw_len = end - start;
        let hdr = |ty: u32, size: usize| -> [u8; 3] {
            let v = (last as u32) | (ty << 1) | ((size as u32) << 3);
            [v as u8, (v >> 8) as u8, (v >> 16) as u8]
        };
        if raw_len == 0 {
            out.extend_from_slice(&hdr(0, 0));
        } else {
            let data = &self.lz.buf[start..end];
            if data.iter().all(|&b| b == data[0]) && raw_len > 3 {
                out.extend_from_slice(&hdr(1, raw_len));
                out.push(data[0]);
            } else {
                let saved_reps = self.reps;
                match self.compress(start, end) {
                    Some(body) if body.len() < raw_len => {
                        out.extend_from_slice(&hdr(2, body.len()));
                        out.extend_from_slice(&body);
                    }
                    _ => {
                        self.reps = saved_reps;
                        out.extend_from_slice(&hdr(0, raw_len));
                        out.extend_from_slice(&self.lz.buf[start..end]);
                    }
                }
            }
        }
        self.pending = end;
        // keep one window of history before the pending bytes
        let keep = 1usize << self.wlog;
        if self.pending > keep + BLOCK {
            let d = self.pending - keep;
            self.lz.slide(d);
            self.pending -= d;
        }
    }

    /// The literals and sequences sections of a compressed block.
    fn compress(&mut self, start: usize, end: usize) -> Option<Vec<u8>> {
        self.seqs.clear();
        let mut seqs = std::mem::take(&mut self.seqs);
        let tail = match &mut self.fast {
            Some(f) => f.parse(&self.lz.buf, self.lz.base, start, end, &mut seqs),
            None => self.lz.parse(start, end, &mut seqs),
        };
        let buf = &self.lz.buf;
        // the literals, gathered 16 bytes at a time into room with slack (a copy of each short
        // run's exact length would call memcpy per sequence)
        let mut lits = vec![0u8; end - start + 16];
        let mut n = 0;
        let mut p = start;
        for s in &seqs {
            let l = s.lit as usize;
            if p + l + 16 <= buf.len() {
                let mut k = 0;
                while k < l {
                    lits[n + k..n + k + 16].copy_from_slice(&buf[p + k..p + k + 16]);
                    k += 16;
                }
            } else {
                lits[n..n + l].copy_from_slice(&buf[p..p + l]);
            }
            n += l;
            p += l + s.len as usize;
        }
        lits[n..n + tail].copy_from_slice(&buf[end - tail..end]);
        lits.truncate(n + tail);
        let mut body = Vec::with_capacity((end - start) / 2);
        write_literals(&lits, &mut body);
        self.write_sequences(&seqs, &mut body);
        self.seqs = seqs;
        Some(body)
    }

    fn write_sequences(&mut self, seqs: &[Seq], out: &mut Vec<u8>) {
        let n = seqs.len();
        if n < 128 {
            out.push(n as u8);
        } else if n < 0x7F00 {
            out.push(((n >> 8) + 128) as u8);
            out.push(n as u8);
        } else {
            out.push(255);
            out.extend_from_slice(&((n - 0x7F00) as u16).to_le_bytes());
        }
        if n == 0 {
            return;
        }
        // codes and extra values
        // codes and histograms in one pass, into arrays kept across blocks
        let mut codes = std::mem::take(&mut self.codes);
        codes.clear();
        codes.reserve(n);
        let mut reps = self.reps;
        let mut hl = [0u32; 36];
        let mut ho = [0u32; 32];
        let mut hm = [0u32; 53];
        for s in seqs {
            let ll = s.lit;
            let ofv = offset_value(&mut reps, s.dist, ll == 0);
            let ofc = highbit(ofv);
            let mlb = s.len - 3;
            let (lc, mc) = (ll_code(ll), ml_code(mlb));
            codes.push(SeqCode { ll_code: lc, of_code: ofc as u8, ml_code: mc, ll_bits: LL_BITS[lc as usize], ml_bits: ML_BITS[mc as usize], ll, ofv, mlb });
            hl[lc as usize] += 1;
            ho[ofc as usize & 31] += 1;
            hm[mc as usize] += 1;
        }
        self.reps = reps;
        let hist: [&[u32]; 3] = [&hl, &ho, &hm];
        let specs: [(&[i16], u32, u32); 3] = [(&LL_NORM, 6, 9), (&OF_NORM, 5, 8), (&ML_NORM, 6, 9)];
        let mut modes = 0u8;
        let mut tables: Vec<CTable> = Vec::new();
        let mut desc = Vec::new();
        for (k, &(def, deflog, maxlog)) in specs.iter().enumerate() {
            let h = hist[k];
            let used: Vec<usize> = (0..h.len()).filter(|&s| h[s] > 0).collect();
            let (mode, table) = if used.len() == 1 {
                desc.push(used[0] as u8);
                (1, CTable::rle(used[0] as u8, h.len()))
            } else {
                let maxs = *used.last().unwrap_or(&0);
                let min_log = (highbit(maxs as u32 + 1) + 2).max(5);
                let log = (highbit(n as u32) + 1).clamp(min_log.min(maxlog), maxlog);
                let norm = normalize(&h[..=maxs], n as u32, log);
                let mut w = BitWriter::default();
                write_ncount(&mut w, &norm, log);
                w.align();
                let fse_cost = CTable::cost(&norm, log, h).map(|c| c + 8 * w.bytes().len() as u64);
                let def_cost = CTable::cost(def, deflog, h);
                match (def_cost, fse_cost) {
                    (Some(d), Some(f)) if d <= f => (0, CTable::build(def, deflog)),
                    (_, Some(_)) => {
                        desc.extend_from_slice(w.bytes());
                        (2, CTable::build(&norm, log))
                    }
                    (Some(_), None) => (0, CTable::build(def, deflog)),
                    (None, None) => unreachable!("a fitted table always codes its own histogram"),
                }
            };
            modes |= mode << (6 - 2 * k);
            tables.push(table);
        }
        out.push(modes);
        out.extend_from_slice(&desc);
        // the bitstream, last sequence first; whole bytes go out after the states (<= 26 bits),
        // the length extras (<= 32) and the offset extra (<= 31)
        let [ll_t, of_t, ml_t] = [&tables[0], &tables[1], &tables[2]];
        if simoom_sys::codec::fast() {
            simoom_sys::codec::zstd_seq_stream(&codes, [ll_t.enc(), of_t.enc(), ml_t.enc()], out);
            self.codes = codes;
            return;
        }
        let mut w = BitWriter::with_capacity(8 * n + 16);
        let last = codes[n - 1];
        let mut ll_s = ll_t.init(last.ll_code);
        let mut of_s = of_t.init(last.of_code);
        let mut ml_s = ml_t.init(last.ml_code);
        // after the states at most 33 bits are pending; the length extras (<= 32) fit unless
        // long, and the offset extra (<= 31) goes after a write when needed (zstd's
        // ZSTD_encodeSequences)
        macro_rules! extras {
            ($c:expr) => {{
                let c = $c;
                let (lb, mb) = (c.ll_bits as u32, c.ml_bits as u32);
                if w.pending() + lb + mb > 63 {
                    w.flush_bytes();
                }
                w.add(c.ll as u64, lb);
                w.add(c.mlb as u64, mb);
                if w.pending() + c.of_code as u32 > 63 {
                    w.flush_bytes();
                }
                w.add(c.ofv as u64, c.of_code as u32);
                w.flush_bytes();
            }};
        }
        extras!(last);
        for c in codes[..n - 1].iter().rev() {
            of_t.encode_add(&mut w, &mut of_s, c.of_code);
            ml_t.encode_add(&mut w, &mut ml_s, c.ml_code);
            ll_t.encode_add(&mut w, &mut ll_s, c.ll_code);
            w.flush_bytes();
            extras!(c);
        }
        ml_t.flush(&mut w, ml_s);
        of_t.flush(&mut w, of_s);
        ll_t.flush(&mut w, ll_s);
        out.extend_from_slice(&w.close());
        self.codes = codes;
    }
}

/// The offset value for a match (repeat codes 1-3, or the offset + 3), updating `reps` as the
/// decoder will.
#[inline(always)]
fn offset_value(reps: &mut [u32; 3], dist: u32, ll0: bool) -> u32 {
    let [r0, r1, r2] = *reps;
    // the repeat index the decoder will see (0-2, or 3 for r0 - 1 after no literals)
    let idx = if !ll0 {
        if dist == r0 {
            return 1;
        } else if dist == r1 {
            1
        } else if dist == r2 {
            2
        } else {
            4
        }
    } else if dist == r1 {
        1
    } else if dist == r2 {
        2
    } else if dist == r0.wrapping_sub(1) && dist != 0 {
        3
    } else {
        4
    };
    if idx == 4 {
        *reps = [dist, r0, r1];
        return dist + 3;
    }
    *reps = if idx == 1 { [dist, r0, r2] } else { [dist, r0, r1] };
    idx - ll0 as u32 + 1
}

fn ll_code(ll: u32) -> u8 {
    const T: [u8; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 23,
        23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    ];
    if ll < 64 {
        T[ll as usize]
    } else {
        (highbit(ll) + 19) as u8
    }
}

fn ml_code(mlb: u32) -> u8 {
    const T: [u8; 128] = {
        let mut t = [0u8; 128];
        let mut i = 0;
        while i < 128 {
            t[i] = if i < 32 {
                i as u8
            } else if i < 34 {
                32
            } else if i < 36 {
                33
            } else if i < 38 {
                34
            } else if i < 40 {
                35
            } else if i < 44 {
                36
            } else if i < 48 {
                37
            } else if i < 56 {
                38
            } else if i < 64 {
                39
            } else if i < 80 {
                40
            } else if i < 96 {
                41
            } else {
                42
            };
            i += 1;
        }
        t
    };
    if mlb < 128 {
        T[mlb as usize]
    } else {
        (highbit(mlb) + 36) as u8
    }
}

/// The literals section: raw, RLE or Huffman (one or four streams), whichever is smallest.
fn write_literals(lits: &[u8], out: &mut Vec<u8>) {
    let n = lits.len();
    let raw_header = |out: &mut Vec<u8>, ty: u8| {
        if n < 32 {
            out.push(((n as u8) << 3) | ty);
        } else if n < 4096 {
            out.push((((n & 15) as u8) << 4) | 0b0100 | ty);
            out.push((n >> 4) as u8);
        } else {
            out.push((((n & 15) as u8) << 4) | 0b1100 | ty);
            out.push((n >> 4) as u8);
            out.push((n >> 12) as u8);
        }
    };
    if n > 0 && lits.iter().all(|&b| b == lits[0]) {
        raw_header(out, 1);
        out.push(lits[0]);
        return;
    }
    if n >= 64 {
        if let Some(h) = huffman_literals(lits) {
            if h.len() + 2 < n {
                out.extend_from_slice(&h);
                return;
            }
        }
    }
    raw_header(out, 0);
    out.extend_from_slice(lits);
}

fn huffman_literals(lits: &[u8]) -> Option<Vec<u8>> {
    let n = lits.len();
    let mut freq = [0u32; 256];
    for &b in lits {
        freq[b as usize] += 1;
    }
    // zstd's quick test: no symbol much more frequent than average, not worth a code
    let largest = *freq.iter().max().unwrap_or(&0) as usize;
    if largest <= (n >> 7) + 4 {
        return None;
    }
    let mut lens = [0u8; 256];
    build_lengths(&freq, 11, &mut lens);
    // the coded size, before coding it
    let bits: u64 = freq.iter().zip(&lens).map(|(&f, &l)| f as u64 * l as u64).sum();
    if bits / 8 + 8 >= n as u64 - (n as u64 >> 6) {
        return None;
    }
    let last = lens.iter().rposition(|&l| l != 0)?;
    let (codes, _max_bits, weights) = huf_codes(&lens[..=last]);
    // tree description: direct 4-bit weights (up to 128 of them) or FSE-coded weights
    let mut tree = Vec::new();
    let nw = last; // the last symbol's weight is implied
    if nw <= 128 {
        tree.push((127 + nw) as u8);
        for pair in weights[..nw].chunks(2) {
            tree.push((pair[0] << 4) | pair.get(1).copied().unwrap_or(0));
        }
    } else {
        let fw = fse_weights(&weights[..nw])?;
        if fw.len() >= 128 {
            return None;
        }
        tree.push(fw.len() as u8);
        tree.extend_from_slice(&fw);
    }
    let four = n >= 256;
    let mut code = [(0u16, 0u8); 256];
    code[..codes.len()].copy_from_slice(&codes);
    // last symbol first, four (<= 44 bits) per write
    let stream = |part: &[u8]| -> Vec<u8> {
        let mut w = BitWriter::with_capacity(part.len() * 11 / 8 + 16);
        for c in part.rchunks(4) {
            for &b in c.iter().rev() {
                let (c, l) = code[b as usize];
                w.add(c as u64, l as u32);
            }
            w.flush_bytes();
        }
        w.close()
    };
    let mut payload = tree;
    if four {
        let seg = n.div_ceil(4);
        let parts = [&lits[..seg], &lits[seg..2 * seg], &lits[2 * seg..3 * seg], &lits[3 * seg..]];
        let s: Vec<Vec<u8>> = parts.iter().map(|p| stream(p)).collect();
        for x in &s[..3] {
            if x.len() > 0xFFFF {
                return None;
            }
            payload.extend_from_slice(&(x.len() as u16).to_le_bytes());
        }
        for x in &s {
            payload.extend_from_slice(x);
        }
    } else {
        payload.extend_from_slice(&stream(lits));
    }
    let comp = payload.len();
    let (sf, bits, hl) = if !four {
        if n >= 1024 || comp >= 1024 {
            return None;
        }
        (0u64, 10u32, 3usize)
    } else if n < 1024 && comp < 1024 {
        (1, 10, 3)
    } else if n < 16384 && comp < 16384 {
        (2, 14, 4)
    } else {
        (3, 18, 5)
    };
    if comp >= 1 << bits {
        return None;
    }
    let h: u64 = 2 | (sf << 2) | ((n as u64) << 4) | ((comp as u64) << (4 + bits));
    let mut out = Vec::with_capacity(hl + comp);
    out.extend_from_slice(&h.to_le_bytes()[..hl]);
    out.extend_from_slice(&payload);
    Some(out)
}

/// Huffman weights coded with FSE (two interleaved states, accuracy log at most 6).
fn fse_weights(w: &[u8]) -> Option<Vec<u8>> {
    if w.len() < 2 {
        return None;
    }
    let mut counts = [0u32; 13];
    for &x in w {
        counts[x as usize] += 1;
    }
    let maxs = counts.iter().rposition(|&c| c > 0)?;
    let log = 6;
    let norm = normalize(&counts[..=maxs], w.len() as u32, log);
    let t = CTable::build(&norm, log);
    let mut bw = BitWriter::default();
    write_ncount(&mut bw, &norm, log);
    bw.align();
    let mut out = bw.into_vec();
    let mut b = BitWriter::default();
    let mut i = w.len();
    let (mut s1, mut s2);
    if w.len() % 2 == 1 {
        i -= 1;
        s1 = t.init(w[i]);
        i -= 1;
        s2 = t.init(w[i]);
        i -= 1;
        t.encode(&mut b, &mut s1, w[i]);
    } else {
        i -= 1;
        s2 = t.init(w[i]);
        i -= 1;
        s1 = t.init(w[i]);
    }
    while i > 0 {
        i -= 1;
        t.encode(&mut b, &mut s2, w[i]);
        i -= 1;
        t.encode(&mut b, &mut s1, w[i]);
    }
    t.flush(&mut b, s2);
    t.flush(&mut b, s1);
    out.extend_from_slice(&b.close());
    Some(out)
}
