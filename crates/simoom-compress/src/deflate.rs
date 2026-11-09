//! Streaming DEFLATE encoder (RFC 1951) with the zlib (RFC 1950) and gzip (RFC 1952)
//! containers.
//!
//! LZ77 over a 32 KiB window with hash chains (3-byte hash, 32K heads), zlib's level table:
//! levels 1-3 are greedy and insert only short matches into the chains, levels 4-9 use lazy
//! matching (a match is emitted only if the next position doesn't start a longer one). Each
//! block is written as stored, fixed-Huffman or dynamic-Huffman, whichever is smallest;
//! dynamic codes are length-limited Huffman codes (15 bits, 7 for the code length code).
//!
//! Memory: a 64 KiB input window, 128 KiB of hash heads and chains (16-bit positions) and a
//! 64 KiB symbol buffer, allocated on first use; level 0 needs only the window.

use crate::checksum::{Adler32, Crc32};
use crate::tables::{fixed_lit_len, CL_ORDER, DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA};
use crate::Format;

const W: usize = 32 * 1024;
const WMASK: usize = W - 1;
const BUF: usize = 2 * W;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
const MAX_DIST: usize = W - MIN_LOOKAHEAD;
const HBITS: u32 = 15;
const HSIZE: usize = 1 << HBITS;
/// A length-3 match farther than this costs more than three literals.
const TOO_FAR: usize = 4096;
/// Symbols per block.
const SYMS: usize = 16 * 1024 - 1;

#[derive(Clone, Copy)]
struct Cfg {
    good: u16,
    lazy: u16,
    nice: u16,
    chain: u16,
    lazy_mode: bool,
}

const fn cfg(good: u16, lazy: u16, nice: u16, chain: u16, lazy_mode: bool) -> Cfg {
    Cfg { good, lazy, nice, chain, lazy_mode }
}

/// zlib's configuration table (deflate.c); `lazy` is the insert limit for levels 1-3.
const CFG: [Cfg; 10] = [
    cfg(0, 0, 0, 0, false),
    cfg(4, 4, 8, 4, false),
    cfg(4, 5, 16, 8, false),
    cfg(4, 6, 32, 32, false),
    cfg(4, 4, 16, 16, true),
    cfg(8, 16, 32, 32, true),
    cfg(8, 16, 128, 128, true),
    cfg(8, 32, 128, 256, true),
    cfg(32, 128, 258, 1024, true),
    cfg(32, 258, 258, 4096, true),
];

/// Length-symbol index (0..29) of a match length minus 3.
fn len_sym(l3: usize) -> usize {
    let len = l3 + 3;
    let mut i = 28;
    while LEN_BASE[i] as usize > len {
        i -= 1;
    }
    i
}

/// Distance-symbol index (0..30) of a distance.
#[inline(always)]
fn dist_sym(d: usize) -> usize {
    let d1 = d - 1;
    if d1 < 4 {
        d1
    } else {
        // Two symbols per power of two above 4.
        let lg = 31 - (d1 as u32).leading_zeros() as usize;
        2 * lg + ((d1 >> (lg - 1)) & 1)
    }
}

struct LenTable([u8; 256]);

fn len_table() -> &'static LenTable {
    static T: std::sync::OnceLock<LenTable> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u8; 256];
        for (i, e) in t.iter_mut().enumerate() {
            *e = len_sym(i) as u8;
        }
        LenTable(t)
    })
}

/// LSB-first bit output.
#[derive(Default, Clone, Copy)]
struct BitWriter {
    bb: u64,
    cnt: u32,
}

impl BitWriter {
    #[inline(always)]
    fn put(&mut self, out: &mut Vec<u8>, v: u32, n: u32) {
        self.bb |= (v as u64) << self.cnt;
        self.cnt += n;
        if self.cnt >= 32 {
            out.extend_from_slice(&(self.bb as u32).to_le_bytes());
            self.bb >>= 32;
            self.cnt -= 32;
        }
    }

    /// Pads to a byte boundary and writes out every buffered byte.
    fn align(&mut self, out: &mut Vec<u8>) {
        while self.cnt > 0 {
            out.push(self.bb as u8);
            self.bb >>= 8;
            self.cnt = self.cnt.saturating_sub(8);
        }
        self.bb = 0;
    }
}

/// Code lengths for `freq`, limited to `max_len` bits (Huffman's algorithm, then the Kraft
/// adjustment that miniz uses: overlong codes are moved to `max_len` and shorter codes are
/// lengthened until the code is complete again).
fn build_lengths(freq: &[u32], max_len: usize, lens: &mut [u8]) {
    let n_sym = freq.len();
    lens[..n_sym].fill(0);
    let mut leaves = [(0u32, 0u16); 288];
    let mut n = 0;
    for (s, &f) in freq.iter().enumerate() {
        if f != 0 {
            leaves[n] = (f, s as u16);
            n += 1;
        }
    }
    if n == 0 {
        return;
    }
    if n == 1 {
        lens[leaves[0].1 as usize] = 1;
        return;
    }
    let leaves = &mut leaves[..n];
    leaves.sort_unstable();
    let mut weight = [0u32; 2 * 288];
    let mut parent = [0u16; 2 * 288];
    for i in 0..n {
        weight[i] = leaves[i].0;
    }
    // Two queues: the sorted leaves and the internal nodes, created in nondecreasing weight.
    let (mut li, mut ii) = (0, n);
    for k in n..2 * n - 1 {
        let mut pick = || {
            if li < n && (ii >= k || weight[li] <= weight[ii]) {
                li += 1;
                li - 1
            } else {
                ii += 1;
                ii - 1
            }
        };
        let a = pick();
        let b = pick();
        weight[k] = weight[a].saturating_add(weight[b]);
        parent[a] = k as u16;
        parent[b] = k as u16;
    }
    let mut depth = [0u16; 2 * 288];
    for k in (0..2 * n - 2).rev() {
        depth[k] = depth[parent[k] as usize] + 1;
    }
    let mut bl = [0u32; 33];
    for &d in &depth[..n] {
        bl[(d as usize).min(32)] += 1;
    }
    for i in max_len + 1..=32 {
        bl[max_len] += bl[i];
        bl[i] = 0;
    }
    let mut total: u64 = (1..=max_len).map(|i| (bl[i] as u64) << (max_len - i)).sum();
    while total != 1 << max_len {
        bl[max_len] -= 1;
        for i in (1..max_len).rev() {
            if bl[i] != 0 {
                bl[i] -= 1;
                bl[i + 1] += 2;
                break;
            }
        }
        total -= 1;
    }
    // The rarest symbols get the longest codes.
    let mut i = 0;
    for len in (1..=max_len).rev() {
        for _ in 0..bl[len] {
            lens[leaves[i].1 as usize] = len as u8;
            i += 1;
        }
    }
}

/// Canonical codes for `lens`, bit-reversed for LSB-first output.
fn gen_codes(lens: &[u8], codes: &mut [u16]) {
    let mut count = [0u16; 16];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for l in 1..16 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    for (s, &l) in lens.iter().enumerate() {
        if l != 0 {
            codes[s] = next[l as usize].reverse_bits() >> (16 - l as u32);
            next[l as usize] += 1;
        } else {
            codes[s] = 0;
        }
    }
}

struct Fixed {
    lcode: [u16; 288],
    llen: [u8; 288],
    dcode: [u16; 30],
}

fn fixed() -> &'static Fixed {
    static F: std::sync::OnceLock<Fixed> = std::sync::OnceLock::new();
    F.get_or_init(|| {
        let mut f = Fixed { lcode: [0; 288], llen: [0; 288], dcode: [0; 30] };
        for (i, l) in f.llen.iter_mut().enumerate() {
            *l = fixed_lit_len(i);
        }
        gen_codes(&f.llen, &mut f.lcode);
        gen_codes(&[5u8; 30], &mut f.dcode);
        f
    })
}

/// A streaming compressor producing raw DEFLATE, zlib or gzip data.
///
/// [`Encoder::encode`] buffers input and appends compressed bytes to `out` as blocks fill;
/// [`Encoder::flush`] makes everything given so far decodable (a sync flush: an empty stored
/// block ends on a byte boundary, as zlib's `Z_SYNC_FLUSH` does); [`Encoder::finish`] writes the
/// last block and the trailer. Levels 0 (stored) to 9; 6 is the usual default.
pub struct Encoder {
    format: Format,
    level: u8,
    cfg: Cfg,
    buf: Vec<u8>,
    head: Vec<u16>,
    prev: Vec<u16>,
    pos: usize,
    /// Start of the bytes the pending symbols cover; negative once slid out of the window
    /// (the block can then not be stored).
    block_start: isize,
    raw_end: usize,
    cur_len: usize,
    cur_dist: usize,
    match_available: bool,
    syms: Vec<u32>,
    lfreq: [u32; 286],
    dfreq: [u32; 30],
    bw: BitWriter,
    header_done: bool,
    finished: bool,
    crc: Crc32,
    adler: Adler32,
    total_in: u64,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").field("format", &self.format).field("level", &self.level).field("total_in", &self.total_in).finish()
    }
}

impl Encoder {
    /// An encoder for `format` at `level` (0-9; higher values are treated as 9).
    /// [`Format::ZlibOrRaw`] produces zlib.
    pub fn new(format: Format, level: u32) -> Encoder {
        let level = level.min(9) as u8;
        let format = if format == Format::ZlibOrRaw { Format::Zlib } else { format };
        Encoder {
            format,
            level,
            cfg: CFG[level as usize],
            buf: Vec::new(),
            head: Vec::new(),
            prev: Vec::new(),
            pos: 0,
            block_start: 0,
            raw_end: 0,
            cur_len: MIN_MATCH - 1,
            cur_dist: 0,
            match_available: false,
            syms: Vec::new(),
            lfreq: [0; 286],
            dfreq: [0; 30],
            bw: BitWriter::default(),
            header_done: false,
            finished: false,
            crc: Crc32::new(),
            adler: Adler32::new(),
            total_in: 0,
        }
    }

    /// Starts a new stream with the same format and level, keeping the allocations.
    pub fn reset(&mut self) {
        let (mut buf, mut head, mut prev, mut syms) =
            (std::mem::take(&mut self.buf), std::mem::take(&mut self.head), std::mem::take(&mut self.prev), std::mem::take(&mut self.syms));
        buf.clear();
        head.fill(0);
        prev.fill(0);
        syms.clear();
        *self = Encoder { buf, head, prev, syms, ..Encoder::new(self.format, self.level as u32) };
    }

    /// The container format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Uncompressed bytes taken so far.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// [`Encoder::finish`] has been called.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Compresses `input`, appending any completed output to `out`.
    pub fn encode(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        assert!(!self.finished, "Encoder::encode after finish");
        self.start(out);
        match self.format {
            Format::Gzip => self.crc.update(input),
            Format::Zlib => self.adler.update(input),
            _ => {}
        }
        self.total_in += input.len() as u64;
        while !input.is_empty() {
            if self.buf.len() == BUF {
                self.make_room(out);
            }
            let n = input.len().min(BUF - self.buf.len());
            self.buf.extend_from_slice(&input[..n]);
            input = &input[n..];
            self.process(false, out);
        }
    }

    /// Sync flush: everything given so far becomes decodable from `out`, which ends on a byte
    /// boundary. Costs 5 bytes or so; compression continues with the same window.
    pub fn flush(&mut self, out: &mut Vec<u8>) {
        assert!(!self.finished, "Encoder::flush after finish");
        self.start(out);
        self.process(true, out);
        self.emit_block(false, out);
        // An empty stored block.
        self.bw.put(out, 0, 3);
        self.bw.align(out);
        out.extend_from_slice(&[0, 0, 0xFF, 0xFF]);
    }

    /// Writes the last block and the container trailer. The encoder is then finished until
    /// [`Encoder::reset`].
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if self.finished {
            return;
        }
        self.start(out);
        if self.level > 0 {
            self.process(true, out);
        }
        self.emit_block(true, out);
        self.bw.align(out);
        match self.format {
            Format::Gzip => {
                out.extend_from_slice(&self.crc.value().to_le_bytes());
                out.extend_from_slice(&(self.total_in as u32).to_le_bytes());
            }
            Format::Zlib => out.extend_from_slice(&self.adler.value().to_be_bytes()),
            _ => {}
        }
        self.finished = true;
    }

    /// Writes the container header and allocates on first use.
    fn start(&mut self, out: &mut Vec<u8>) {
        if self.header_done {
            return;
        }
        self.header_done = true;
        match self.format {
            Format::Gzip => {
                let xfl = match self.level {
                    9 => 2,
                    0 | 1 => 4,
                    _ => 0,
                };
                // OS 255 (unknown), no timestamp.
                out.extend_from_slice(&[0x1F, 0x8B, 8, 0, 0, 0, 0, 0, xfl, 255]);
            }
            Format::Zlib => {
                let flevel: u16 = match self.level {
                    0 | 1 => 0,
                    2..=5 => 1,
                    6 => 2,
                    _ => 3,
                };
                let mut h = (0x78u16 << 8) | (flevel << 6);
                h += 31 - h % 31;
                out.extend_from_slice(&h.to_be_bytes());
            }
            _ => {}
        }
        if self.buf.capacity() < BUF {
            self.buf.reserve_exact(BUF - self.buf.len());
        }
        if self.level > 0 && self.head.is_empty() {
            self.head = vec![0; HSIZE];
            self.prev = vec![0; W];
            self.syms = Vec::with_capacity(SYMS + 1);
        }
    }

    /// The window is full: emit (level 0) or slide it down by 32 KiB.
    fn make_room(&mut self, out: &mut Vec<u8>) {
        if self.level == 0 {
            self.stored_flush(false, out);
            return;
        }
        debug_assert!(self.pos >= W);
        self.buf.drain(..W);
        self.pos -= W;
        self.raw_end -= W;
        self.block_start -= W as isize;
        for h in self.head.iter_mut().chain(self.prev.iter_mut()) {
            *h = if *h as usize >= W { *h - W as u16 } else { 0 };
        }
    }

    /// Level 0: writes the buffered bytes as stored blocks.
    fn stored_flush(&mut self, last: bool, out: &mut Vec<u8>) {
        let data = std::mem::take(&mut self.buf);
        write_stored(&mut self.bw, &data, last, out);
        self.buf = data;
        self.buf.clear();
    }

    #[inline(always)]
    fn hash(&self, p: usize) -> usize {
        let b = &self.buf;
        let v = (b[p] as u32) | (b[p + 1] as u32) << 8 | (b[p + 2] as u32) << 16;
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HBITS)) as usize
    }

    /// Inserts position `p` into the chains; returns the previous head.
    #[inline(always)]
    fn insert(&mut self, p: usize) -> usize {
        let h = self.hash(p);
        let cand = self.head[h] as usize;
        self.prev[p & WMASK] = cand as u16;
        self.head[h] = p as u16;
        cand
    }

    fn longest_match(&self, cur: usize, mut cand: usize, prev_len: usize) -> (usize, usize) {
        let buf = &self.buf[..];
        let max_len = MAX_MATCH.min(buf.len() - cur);
        let mut best = prev_len;
        if best >= max_len {
            return (0, 0);
        }
        let mut chain = self.cfg.chain as usize;
        if prev_len >= self.cfg.good as usize {
            chain >>= 2;
        }
        let nice = (self.cfg.nice as usize).min(max_len);
        let limit = cur.saturating_sub(MAX_DIST);
        let mut best_dist = 0;
        loop {
            if buf[cand + best] == buf[cur + best] && buf[cand] == buf[cur] && buf[cand + 1] == buf[cur + 1] {
                let len = match_len(buf, cand, cur, max_len);
                if len > best {
                    best = len;
                    best_dist = cur - cand;
                    if len >= nice {
                        break;
                    }
                }
            }
            chain -= 1;
            if chain == 0 {
                break;
            }
            let next = self.prev[cand & WMASK] as usize;
            if next >= cand || next < limit {
                break;
            }
            cand = next;
        }
        if best_dist == 0 {
            (0, 0)
        } else {
            (best, best_dist)
        }
    }

    #[inline(always)]
    fn lit(&mut self, p: usize, out: &mut Vec<u8>) {
        let b = self.buf[p];
        self.syms.push(b as u32);
        self.lfreq[b as usize] += 1;
        self.raw_end = p + 1;
        if self.syms.len() >= SYMS {
            self.emit_block(false, out);
        }
    }

    #[inline(always)]
    fn mat(&mut self, p: usize, len: usize, dist: usize, out: &mut Vec<u8>) {
        self.syms.push(((dist as u32) << 8) | (len - MIN_MATCH) as u32);
        self.lfreq[257 + len_table().0[len - MIN_MATCH] as usize] += 1;
        self.dfreq[dist_sym(dist)] += 1;
        self.raw_end = p + len;
        if self.syms.len() >= SYMS {
            self.emit_block(false, out);
        }
    }

    /// Runs the matcher over the buffered input. Without `flush` it keeps `MIN_LOOKAHEAD`
    /// bytes back, so that every match search sees the longest possible match.
    fn process(&mut self, flush: bool, out: &mut Vec<u8>) {
        if self.level == 0 {
            if flush {
                self.stored_flush(false, out);
            }
            return;
        }
        if self.cfg.lazy_mode {
            self.lazy(flush, out)
        } else {
            self.greedy(flush, out)
        }
    }

    fn greedy(&mut self, flush: bool, out: &mut Vec<u8>) {
        loop {
            let look = self.buf.len() - self.pos;
            if look == 0 || (look < MIN_LOOKAHEAD && !flush) {
                return;
            }
            let p = self.pos;
            let mut len = 0;
            let mut dist = 0;
            if look >= MIN_MATCH {
                let cand = self.insert(p);
                if cand < p && p - cand <= MAX_DIST {
                    (len, dist) = self.longest_match(p, cand, MIN_MATCH - 1);
                }
            }
            if len >= MIN_MATCH {
                self.mat(p, len, dist, out);
                if len <= self.cfg.lazy as usize {
                    for q in p + 1..p + len {
                        if q + MIN_MATCH <= self.buf.len() {
                            self.insert(q);
                        }
                    }
                }
                self.pos = p + len;
            } else {
                self.lit(p, out);
                self.pos = p + 1;
            }
        }
    }

    fn lazy(&mut self, flush: bool, out: &mut Vec<u8>) {
        loop {
            let look = self.buf.len() - self.pos;
            if look == 0 || (look < MIN_LOOKAHEAD && !flush) {
                break;
            }
            let p = self.pos;
            let prev_len = self.cur_len;
            let prev_dist = self.cur_dist;
            self.cur_len = MIN_MATCH - 1;
            if look >= MIN_MATCH {
                let cand = self.insert(p);
                if cand < p && p - cand <= MAX_DIST && prev_len < self.cfg.lazy as usize {
                    let (l, d) = self.longest_match(p, cand, prev_len.max(MIN_MATCH - 1));
                    if l >= MIN_MATCH && !(l == MIN_MATCH && d > TOO_FAR) {
                        self.cur_len = l;
                        self.cur_dist = d;
                    }
                }
            }
            if prev_len >= MIN_MATCH && self.cur_len <= prev_len {
                // The match at p - 1 wins.
                let start = p - 1;
                let end = start + prev_len;
                self.mat(start, prev_len, prev_dist, out);
                for q in p + 1..end {
                    if q + MIN_MATCH <= self.buf.len() {
                        self.insert(q);
                    }
                }
                self.pos = end;
                self.match_available = false;
                self.cur_len = MIN_MATCH - 1;
            } else if self.match_available {
                self.lit(p - 1, out);
                self.pos = p + 1;
            } else {
                self.match_available = true;
                self.pos = p + 1;
            }
        }
        if flush && self.match_available {
            self.lit(self.pos - 1, out);
            self.match_available = false;
            self.cur_len = MIN_MATCH - 1;
        }
    }

    /// Writes the pending symbols as one block (stored, fixed or dynamic, the smallest).
    fn emit_block(&mut self, last: bool, out: &mut Vec<u8>) {
        if self.level == 0 {
            if last {
                self.stored_flush(true, out);
            }
            return;
        }
        if self.syms.is_empty() && !last {
            return;
        }
        self.lfreq[256] = 1;
        let mut llen = [0u8; 286];
        let mut dlen = [0u8; 30];
        build_lengths(&self.lfreq, 15, &mut llen);
        build_lengths(&self.dfreq, 15, &mut dlen);
        // Some decoders want two distance codes; give an unused one a length as zlib does.
        if dlen.iter().filter(|&&l| l != 0).count() < 2 {
            match dlen.iter().position(|&l| l != 0) {
                None => {
                    dlen[0] = 1;
                    dlen[1] = 1;
                }
                Some(u) => {
                    dlen[u] = 1;
                    dlen[if u == 0 { 1 } else { 0 }] = 1;
                }
            }
        }
        let nlit = 257 + llen[257..].iter().rposition(|&l| l != 0).map_or(0, |i| i + 1);
        let ndist = 1 + dlen.iter().rposition(|&l| l != 0).unwrap_or(0);

        // Code length sequence, run-length coded (16: repeat previous, 17/18: zeros).
        let mut all = [0u8; 316];
        all[..nlit].copy_from_slice(&llen[..nlit]);
        all[nlit..nlit + ndist].copy_from_slice(&dlen[..ndist]);
        let all = &all[..nlit + ndist];
        let mut rle = [(0u8, 0u8); 316];
        let mut nr = 0;
        let mut i = 0;
        while i < all.len() {
            let l = all[i];
            let mut run = 1;
            while i + run < all.len() && all[i + run] == l {
                run += 1;
            }
            let mut r = run;
            if l == 0 {
                while r >= 11 {
                    let k = r.min(138);
                    rle[nr] = (18, (k - 11) as u8);
                    nr += 1;
                    r -= k;
                }
                if r >= 3 {
                    rle[nr] = (17, (r - 3) as u8);
                    nr += 1;
                    r = 0;
                }
            } else {
                rle[nr] = (l, 0);
                nr += 1;
                r -= 1;
                while r >= 3 {
                    let k = r.min(6);
                    rle[nr] = (16, (k - 3) as u8);
                    nr += 1;
                    r -= k;
                }
            }
            for _ in 0..r {
                rle[nr] = (l, 0);
                nr += 1;
            }
            i += run;
        }
        let rle = &rle[..nr];
        let mut cfreq = [0u32; 19];
        for &(s, _) in rle {
            cfreq[s as usize] += 1;
        }
        let mut clen = [0u8; 19];
        build_lengths(&cfreq, 7, &mut clen);
        let nclen = 4.max(19 - CL_ORDER.iter().rev().take_while(|&&s| clen[s] == 0).count());

        // Sizes in bits.
        let extra: u64 = (0..29).map(|s| self.lfreq[257 + s] as u64 * LEN_EXTRA[s] as u64).sum::<u64>()
            + (0..30).map(|s| self.dfreq[s] as u64 * DIST_EXTRA[s] as u64).sum::<u64>();
        let mut dyn_bits: u64 = 3 + 14 + 3 * nclen as u64 + extra;
        for &(s, _) in rle {
            dyn_bits += clen[s as usize] as u64 + [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7][s as usize];
        }
        let mut fixed_bits: u64 = 3 + extra;
        for s in 0..286 {
            let f = self.lfreq[s] as u64;
            dyn_bits += f * llen[s] as u64;
            fixed_bits += f * fixed_lit_len(s) as u64;
        }
        for s in 0..30 {
            dyn_bits += self.dfreq[s] as u64 * dlen[s] as u64;
            fixed_bits += self.dfreq[s] as u64 * 5;
        }
        let raw: Option<(usize, usize)> = if self.block_start >= 0 { Some((self.block_start as usize, self.raw_end)) } else { None };
        let stored_bits = raw.map(|(a, b)| {
            let n = (b - a) as u64;
            n * 8 + 42 * n.div_ceil(65535).max(1)
        });

        if stored_bits.is_some_and(|s| s <= dyn_bits.min(fixed_bits)) {
            let (a, b) = raw.unwrap_or_default();
            let data = std::mem::take(&mut self.buf);
            write_stored(&mut self.bw, &data[a..b], last, out);
            self.buf = data;
        } else if fixed_bits <= dyn_bits {
            let f = fixed();
            self.bw.put(out, last as u32, 1);
            self.bw.put(out, 1, 2);
            self.write_syms(&f.lcode[..286], &f.llen[..286], &f.dcode, &[5; 30], out);
        } else {
            let mut lcode = [0u16; 286];
            let mut dcode = [0u16; 30];
            let mut ccode = [0u16; 19];
            gen_codes(&llen, &mut lcode);
            gen_codes(&dlen, &mut dcode);
            gen_codes(&clen, &mut ccode);
            let bw = &mut self.bw;
            bw.put(out, last as u32, 1);
            bw.put(out, 2, 2);
            bw.put(out, (nlit - 257) as u32, 5);
            bw.put(out, (ndist - 1) as u32, 5);
            bw.put(out, (nclen - 4) as u32, 4);
            for &s in &CL_ORDER[..nclen] {
                bw.put(out, clen[s] as u32, 3);
            }
            for &(s, x) in rle {
                bw.put(out, ccode[s as usize] as u32, clen[s as usize] as u32);
                match s {
                    16 => bw.put(out, x as u32, 2),
                    17 => bw.put(out, x as u32, 3),
                    18 => bw.put(out, x as u32, 7),
                    _ => {}
                }
            }
            self.write_syms(&lcode, &llen, &dcode, &dlen, out);
        }
        self.syms.clear();
        self.lfreq = [0; 286];
        self.dfreq = [0; 30];
        self.block_start = self.raw_end as isize;
    }

    fn write_syms(&mut self, lcode: &[u16], llen: &[u8], dcode: &[u16], dlen: &[u8], out: &mut Vec<u8>) {
        let lt = &len_table().0;
        let bw = &mut self.bw;
        for &s in &self.syms {
            let dist = (s >> 8) as usize;
            if dist == 0 {
                bw.put(out, lcode[s as usize] as u32, llen[s as usize] as u32);
            } else {
                let l3 = (s & 0xFF) as usize;
                let ls = lt[l3] as usize;
                let lv = 257 + ls;
                bw.put(out, lcode[lv] as u32, llen[lv] as u32);
                if LEN_EXTRA[ls] > 0 {
                    bw.put(out, (l3 + 3 - LEN_BASE[ls] as usize) as u32, LEN_EXTRA[ls] as u32);
                }
                let ds = dist_sym(dist);
                bw.put(out, dcode[ds] as u32, dlen[ds] as u32);
                if DIST_EXTRA[ds] > 0 {
                    bw.put(out, (dist - DIST_BASE[ds] as usize) as u32, DIST_EXTRA[ds] as u32);
                }
            }
        }
        bw.put(out, lcode[256] as u32, llen[256] as u32);
    }
}

/// Stored blocks of at most 65535 bytes; only the last carries BFINAL when `last`.
fn write_stored(bw: &mut BitWriter, data: &[u8], last: bool, out: &mut Vec<u8>) {
    let mut chunks = data.chunks(65535).peekable();
    if data.is_empty() {
        bw.put(out, last as u32, 3);
        bw.align(out);
        out.extend_from_slice(&[0, 0, 0xFF, 0xFF]);
        return;
    }
    while let Some(c) = chunks.next() {
        let fin = last && chunks.peek().is_none();
        bw.put(out, fin as u32, 3);
        bw.align(out);
        let n = c.len() as u16;
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(!n).to_le_bytes());
        out.extend_from_slice(c);
    }
}

#[inline(always)]
fn match_len(buf: &[u8], a: usize, b: usize, max: usize) -> usize {
    let (x, y) = (&buf[a..a + max], &buf[b..b + max]);
    let mut n = 0;
    while n + 8 <= max {
        let p = u64::from_le_bytes([x[n], x[n + 1], x[n + 2], x[n + 3], x[n + 4], x[n + 5], x[n + 6], x[n + 7]]);
        let q = u64::from_le_bytes([y[n], y[n + 1], y[n + 2], y[n + 3], y[n + 4], y[n + 5], y[n + 6], y[n + 7]]);
        let d = p ^ q;
        if d != 0 {
            return n + (d.trailing_zeros() / 8) as usize;
        }
        n += 8;
    }
    while n < max && x[n] == y[n] {
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_tables() {
        for d in 1..=32768usize {
            let s = dist_sym(d);
            assert!(DIST_BASE[s] as usize <= d && d < DIST_BASE[s] as usize + (1 << DIST_EXTRA[s]), "dist {d}");
        }
        for l in 3..=258usize {
            let s = len_sym(l - 3);
            assert!(LEN_BASE[s] as usize <= l, "len {l}");
            assert!(s == 28 || l < LEN_BASE[s] as usize + (1 << LEN_EXTRA[s]), "len {l}");
        }
        assert_eq!(len_sym(255), 28);
    }

    #[test]
    fn length_limit_holds() {
        // Fibonacci frequencies give a degenerate tree that is far deeper than 15.
        let mut freq = [0u32; 40];
        let (mut a, mut b) = (1u32, 1u32);
        for f in freq.iter_mut() {
            *f = a;
            let c = a.saturating_add(b);
            a = b;
            b = c;
        }
        let mut lens = [0u8; 40];
        build_lengths(&freq, 15, &mut lens);
        assert!(lens.iter().all(|&l| (1..=15).contains(&l)));
        let kraft: f64 = lens.iter().map(|&l| 0.5f64.powi(l as i32)).sum();
        assert!((kraft - 1.0).abs() < 1e-12, "{kraft}");
        let mut lens7 = [0u8; 19];
        build_lengths(&freq[..19], 7, &mut lens7);
        assert!(lens7.iter().all(|&l| (1..=7).contains(&l)));
    }
}
