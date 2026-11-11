//! Brotli decoder (RFC 7932).
//!
//! The decoder works in small transactions over its carried input: the stream header, one
//! meta-block header, one command header, one literal, one distance. Each transaction either
//! completes or, when the input runs out in the middle, is rolled back (input position, decoder
//! scalars and output) and retried when more input arrives. So the decoder resumes at any input
//! boundary, and the carried input never holds more than one unfinished transaction. Copies
//! and uncompressed meta-blocks are done in chunks between transactions, so the output stops
//! at the window's high-water mark however long a command is.
//!
//! Memory: the window (at most twice the stream's window size, which is capped by
//! [`super::DEFAULT_MAX_WINDOW`] or the caller's limit), the Huffman tables of the current
//! meta-block, and the static dictionary (shared, built on first use).

use super::dict::{dictionary, NDBITS, OFFSETS};
use super::tables::{CONTEXT_LUT, TRANSFORMS};
use crate::window::{copy_back, Carry, Flow, Window};
use crate::{Error, ErrorKind};

fn bad(msg: &'static str) -> Error {
    Error::invalid(msg)
}

/// The input ran out inside a transaction.
struct Under;

/// Either an input underrun (retry later) or an error.
enum Fail {
    Under,
    Err(Error),
}

impl From<Under> for Fail {
    fn from(_: Under) -> Fail {
        Fail::Under
    }
}

impl From<Error> for Fail {
    fn from(e: Error) -> Fail {
        Fail::Err(e)
    }
}

type R<T> = Result<T, Fail>;

/// LSB-first bit reader over the carried input; `pos` counts bits.
#[derive(Clone, Copy)]
struct Br<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Br<'_> {
    /// The next 64 bits (zero beyond the end) and how many of them are real.
    #[inline(always)]
    fn peek(&self) -> (u64, usize) {
        let byte = self.pos >> 3;
        let sh = self.pos & 7;
        let v = if let Some(w) = self.buf.get(byte..byte + 8) {
            u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]])
        } else {
            let mut t = [0u8; 8];
            let rest = self.buf.get(byte..).unwrap_or(&[]);
            t[..rest.len()].copy_from_slice(rest);
            u64::from_le_bytes(t)
        };
        (v >> sh, (self.buf.len() * 8).saturating_sub(self.pos))
    }

    #[inline(always)]
    fn bits(&mut self, n: u32) -> Result<u32, Under> {
        if n == 0 {
            return Ok(0);
        }
        let (v, avail) = self.peek();
        if (n as usize) > avail {
            return Err(Under);
        }
        self.pos += n as usize;
        Ok((v & ((1u64 << n) - 1)) as u32)
    }

    fn avail_bytes(&self) -> usize {
        self.buf.len().saturating_sub(self.pos.div_ceil(8))
    }

    /// Skips to the next byte boundary; the skipped bits must be zero.
    fn align_zero(&mut self) -> Result<(), Fail> {
        let r = (8 - (self.pos & 7)) & 7;
        if self.bits(r as u32)? != 0 {
            return Err(Fail::Err(bad("non-zero padding bits")));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Prefix codes
// ---------------------------------------------------------------------------------------------

const ROOT: u32 = 8;

/// A canonical prefix code as a lookup table: entries `symbol << 16 | sub << 8 | len`;
/// `sub` set means `symbol` is the offset of a second-level table of `len` index bits.
#[derive(Clone, Debug, Default)]
pub(crate) struct Huff {
    t: Vec<u32>,
}

impl Huff {
    /// From code lengths (0 = unused). A single used symbol gets a zero-bit code.
    fn build(&mut self, lens: &[u8]) -> Result<(), Error> {
        let mut count = [0u16; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let used: usize = count.iter().map(|&c| c as usize).sum();
        self.t.clear();
        if used == 0 {
            return Err(bad("empty prefix code"));
        }
        if used == 1 {
            let s = lens.iter().position(|&l| l != 0).unwrap_or(0) as u32;
            self.t.resize(1 << ROOT, s << 16);
            return Ok(());
        }
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - c as i32;
            if left < 0 {
                return Err(bad("over-subscribed prefix code"));
            }
        }
        if left != 0 {
            return Err(bad("incomplete prefix code"));
        }
        let mut next = [0u16; 16];
        let mut code = 0u16;
        for l in 1..16 {
            code = (code + count[l - 1]) << 1;
            next[l] = code;
        }
        let size = 1usize << ROOT;
        self.t.resize(size, 0);
        let mut revs = vec![0u16; lens.len()];
        let mut sub_max = [0u8; 1 << ROOT];
        for (s, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let c = next[l as usize];
            next[l as usize] += 1;
            let r = c.reverse_bits() >> (16 - l as u32);
            revs[s] = r;
            if l as u32 > ROOT {
                let p = r as usize & (size - 1);
                sub_max[p] = sub_max[p].max(l);
            }
        }
        for (p, &m) in sub_max.iter().enumerate() {
            if m > 0 {
                let sb = m as u32 - ROOT;
                let off = self.t.len();
                self.t.resize(off + (1 << sb), 0);
                self.t[p] = ((off as u32) << 16) | (1 << 8) | sb;
            }
        }
        for (s, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = l as u32;
            let r = revs[s] as usize;
            if l <= ROOT {
                let mut i = r;
                while i < size {
                    self.t[i] = ((s as u32) << 16) | l;
                    i += 1 << l;
                }
            } else {
                let sub = self.t[r & (size - 1)];
                let off = (sub >> 16) as usize;
                let sb = sub & 0xFF;
                let sl = l - ROOT;
                let mut i = r >> ROOT;
                while i < (1 << sb) {
                    self.t[off + i] = ((s as u32) << 16) | (sl + ROOT);
                    i += 1 << sl;
                }
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn read(&self, br: &mut Br<'_>) -> Result<u32, Under> {
        let (v, avail) = br.peek();
        let mut e = self.t[(v & 0xFF) as usize];
        if e & 0x100 != 0 {
            let off = (e >> 16) as usize;
            let sb = e & 0xFF;
            e = self.t[off + ((v >> ROOT) as usize & ((1 << sb) - 1))];
        }
        let n = (e & 0xFF) as usize;
        if n > avail {
            return Err(Under);
        }
        br.pos += n;
        Ok(e >> 16)
    }
}

const CL_ORDER: [usize; 18] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const CL_PREFIX_LEN: [u8; 16] = [2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4];
const CL_PREFIX_VAL: [u8; 16] = [0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5];

fn alphabet_bits(size: usize) -> u32 {
    usize::BITS - (size - 1).leading_zeros()
}

/// Reads a prefix code over `size` symbols (section 3.4, 3.5).
fn read_code(br: &mut Br<'_>, size: usize, out: &mut Huff, lens: &mut Vec<u8>) -> R<()> {
    lens.clear();
    lens.resize(size, 0);
    let hskip = br.bits(2)?;
    if hskip == 1 {
        let nsym = br.bits(2)? as usize + 1;
        let nb = alphabet_bits(size);
        let mut syms = [0usize; 4];
        for s in syms.iter_mut().take(nsym) {
            *s = br.bits(nb)? as usize;
            if *s >= size {
                return Err(bad("prefix code symbol out of range").into());
            }
        }
        for i in 0..nsym {
            for j in i + 1..nsym {
                if syms[i] == syms[j] {
                    return Err(bad("duplicate symbol in a simple prefix code").into());
                }
            }
        }
        match nsym {
            1 => lens[syms[0]] = 1,
            2 => {
                lens[syms[0]] = 1;
                lens[syms[1]] = 1;
            }
            3 => {
                lens[syms[0]] = 1;
                lens[syms[1]] = 2;
                lens[syms[2]] = 2;
            }
            _ => {
                if br.bits(1)? == 0 {
                    for &s in &syms {
                        lens[s] = 2;
                    }
                } else {
                    lens[syms[0]] = 1;
                    lens[syms[1]] = 2;
                    lens[syms[2]] = 3;
                    lens[syms[3]] = 3;
                }
            }
        }
        out.build(lens)?;
        return Ok(());
    }
    // complex: code length code lengths
    let mut clens = [0u8; 18];
    let mut space: i32 = 32;
    let mut num = 0;
    for &o in &CL_ORDER[hskip as usize..] {
        let (v, avail) = br.peek();
        let idx = (v & 15) as usize;
        let l = CL_PREFIX_LEN[idx] as usize;
        if l > avail {
            return Err(Fail::Under);
        }
        br.pos += l;
        let len = CL_PREFIX_VAL[idx];
        clens[o] = len;
        if len != 0 {
            space -= 32 >> len;
            num += 1;
            if space <= 0 {
                break;
            }
        }
    }
    if !(num == 1 || space == 0) {
        return Err(bad("invalid code length code").into());
    }
    let mut clh = Huff::default();
    clh.build(&clens)?;
    let mut sym = 0usize;
    let mut space: i32 = 32768;
    let mut prev = 8u8;
    let mut repeat = 0usize;
    let mut repeat_len = 0u8;
    while sym < size && space > 0 {
        let c = clh.read(br)? as u8;
        if c < 16 {
            repeat = 0;
            if c != 0 {
                lens[sym] = c;
                prev = c;
                space -= 32768 >> c;
            }
            sym += 1;
        } else {
            let (extra, new_len) = if c == 16 { (2, prev) } else { (3, 0) };
            if repeat_len != new_len {
                repeat = 0;
                repeat_len = new_len;
            }
            let old = repeat;
            if repeat > 0 {
                repeat = (repeat - 2) << extra;
            }
            repeat += br.bits(extra)? as usize + 3;
            let delta = repeat - old;
            if sym + delta > size {
                return Err(bad("code lengths past the alphabet").into());
            }
            if repeat_len != 0 {
                for l in &mut lens[sym..sym + delta] {
                    *l = repeat_len;
                }
                space -= (delta as i32) * (32768 >> repeat_len);
            }
            sym += delta;
        }
    }
    if space != 0 {
        return Err(bad("invalid prefix code lengths").into());
    }
    out.build(lens)?;
    Ok(())
}

fn var_u8(br: &mut Br<'_>) -> Result<u32, Under> {
    if br.bits(1)? == 0 {
        return Ok(0);
    }
    let n = br.bits(3)?;
    if n == 0 {
        return Ok(1);
    }
    Ok((1 << n) + br.bits(n)?)
}

const BLEN: [(u32, u32); 26] = [
    (1, 2),
    (5, 2),
    (9, 2),
    (13, 2),
    (17, 3),
    (25, 3),
    (33, 3),
    (41, 3),
    (49, 4),
    (65, 4),
    (81, 4),
    (97, 4),
    (113, 5),
    (145, 5),
    (177, 5),
    (209, 5),
    (241, 6),
    (305, 6),
    (369, 7),
    (497, 8),
    (753, 9),
    (1265, 10),
    (2289, 11),
    (4337, 12),
    (8433, 13),
    (16625, 24),
];

pub(crate) const INS: [(u32, u32); 24] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 1),
    (8, 1),
    (10, 2),
    (14, 2),
    (18, 3),
    (26, 3),
    (34, 4),
    (50, 4),
    (66, 5),
    (98, 5),
    (130, 6),
    (194, 7),
    (322, 8),
    (578, 9),
    (1090, 10),
    (2114, 12),
    (6210, 14),
    (22594, 24),
];

pub(crate) const COPY: [(u32, u32); 24] = [
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 1),
    (12, 1),
    (14, 2),
    (18, 2),
    (22, 3),
    (30, 3),
    (38, 4),
    (54, 4),
    (70, 5),
    (102, 5),
    (134, 6),
    (198, 7),
    (326, 8),
    (582, 9),
    (1094, 10),
    (2118, 24),
];

/// Insert and copy length code ranges per 64-symbol cell of the command alphabet.
pub(crate) const CELL_INS: [u32; 11] = [0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16];
pub(crate) const CELL_COPY: [u32; 11] = [0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16];

fn block_len(br: &mut Br<'_>, h: &Huff) -> Result<u32, Under> {
    let s = h.read(br)? as usize;
    let (base, n) = BLEN[s];
    Ok(base + br.bits(n)?)
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    StreamHeader,
    MetaHeader,
    /// The literal context map, then the distance one, then the prefix codes one by one.
    CmapLit,
    CmapDist,
    Tree(u16),
    Uncompressed,
    Metadata,
    Command,
    Literals,
    Distance,
    Copy,
    Done,
}

/// Block switching state of one category.
#[derive(Clone, Copy, Default)]
struct Blocks {
    n: u32,
    ty: u32,
    count: u32,
    last: u32,
    second: u32,
}

/// The scalars a transaction may change; restored when it runs out of input.
#[derive(Clone, Copy)]
struct Scalars {
    phase: Phase,
    last: bool,
    meta_left: u32,
    skip_left: u32,
    blocks: [Blocks; 3],
    npostfix: u32,
    ndirect: u32,
    ntrees_l: u16,
    ntrees_d: u16,
    insert_left: u32,
    copy_len: u32,
    implicit_dist: bool,
    dist_rb: [u32; 4],
    dist_idx: usize,
    copy_left: u32,
    copy_dist: u32,
    pos: u64,
}

impl Default for Scalars {
    fn default() -> Self {
        Scalars {
            phase: Phase::StreamHeader,
            last: false,
            meta_left: 0,
            skip_left: 0,
            blocks: [Blocks::default(); 3],
            npostfix: 0,
            ndirect: 0,
            ntrees_l: 0,
            ntrees_d: 0,
            insert_left: 0,
            copy_len: 0,
            implicit_dist: false,
            dist_rb: [16, 15, 11, 4],
            dist_idx: 3,
            copy_left: 0,
            copy_dist: 0,
            pos: 0,
        }
    }
}

#[derive(Clone, Default)]
struct Tables {
    btype: [Huff; 3],
    bcount: [Huff; 3],
    modes: Vec<u8>,
    cmap_lit: Vec<u8>,
    cmap_dist: Vec<u8>,
    lit: Vec<Huff>,
    cmd: Vec<Huff>,
    dist: Vec<Huff>,
    lens: Vec<u8>,
}


#[derive(Clone)]
pub(crate) struct BrotliDecoder {
    s: Scalars,
    t: Tables,
    carry: Carry,
    /// Bits of the first carried byte already consumed.
    bitoff: usize,
    pub(crate) win: Window,
    max_window: usize,
    /// The window size the stream declared.
    wsize: usize,
    pub(crate) total_in: u64,
}

impl BrotliDecoder {
    pub(crate) fn new(limit: u64, max_window: usize) -> BrotliDecoder {
        BrotliDecoder { s: Scalars::default(), t: Tables::default(), carry: Carry::default(), bitoff: 0, win: Window::new(limit), max_window, wsize: 0, total_in: 0 }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.s.phase == Phase::Done
    }

    /// Bytes carried over (input taken but not yet decoded).
    pub(crate) fn carried(&self) -> usize {
        self.carry.buf.len()
    }

    /// Feeds `input` (all of it is taken) and decodes until the output reaches the window's
    /// high-water mark, the input runs out, or the stream ends. A transaction that ran out of
    /// input is retried from its start with the next input; the largest transaction is one
    /// prefix code or one context map, which bounds that work.
    pub(crate) fn run(&mut self, input: &[u8]) -> Result<Flow, Error> {
        self.total_in += input.len() as u64;
        if self.is_done() {
            return Ok(Flow::Done);
        }
        let mut carry = std::mem::take(&mut self.carry);
        let r = carry.run(input, |buf| {
            let mut br = Br { buf, pos: self.bitoff };
            let r = self.steps(&mut br);
            let used = br.pos / 8;
            self.bitoff = br.pos & 7;
            (used, r)
        });
        self.carry = carry;
        r
    }

    fn steps(&mut self, br: &mut Br<'_>) -> Result<Flow, Error> {
        loop {
            if self.s.phase == Phase::Done {
                return Ok(Flow::Done);
            }
            if self.win.buf.len() >= self.win.stop() {
                return Ok(Flow::Full);
            }
            let saved = self.s;
            let saved_br = *br;
            let saved_len = self.win.buf.len();
            match self.step(br) {
                Ok(()) => {}
                Err(Fail::Under) => {
                    self.s = saved;
                    *br = saved_br;
                    self.win.buf.truncate(saved_len);
                    return Ok(Flow::Need);
                }
                Err(Fail::Err(e)) => return Err(e),
            }
        }
    }

    fn step(&mut self, br: &mut Br<'_>) -> R<()> {
        match self.s.phase {
            Phase::StreamHeader => {
                let w = if br.bits(1)? == 0 {
                    16
                } else {
                    let n = br.bits(3)?;
                    if n != 0 {
                        17 + n
                    } else {
                        match br.bits(3)? {
                            0 => 17,
                            1 => return Err(bad("large-window Brotli is not supported").into()),
                            m => 8 + m,
                        }
                    }
                };
                let size = (1usize << w) - 16;
                if size > self.max_window {
                    return Err(Error::new(ErrorKind::LimitExceeded, "Brotli window larger than allowed").into());
                }
                self.wsize = size;
                self.win.hist = size;
                self.s.phase = Phase::MetaHeader;
            }
            Phase::MetaHeader => self.meta_header(br)?,
            Phase::CmapLit => {
                self.s.npostfix = br.bits(2)?;
                self.s.ndirect = br.bits(4)? << self.s.npostfix;
                let nlit = self.s.blocks[0].n as usize;
                let t = &mut self.t;
                t.modes.clear();
                for _ in 0..nlit {
                    t.modes.push(br.bits(2)? as u8);
                }
                let n = var_u8(br)? as usize + 1;
                read_cmap(br, n, 64 * nlit, &mut t.cmap_lit, &mut t.lens)?;
                self.s.ntrees_l = n as u16;
                self.s.phase = Phase::CmapDist;
            }
            Phase::CmapDist => {
                let n = var_u8(br)? as usize + 1;
                let t = &mut self.t;
                read_cmap(br, n, 4 * self.s.blocks[2].n as usize, &mut t.cmap_dist, &mut t.lens)?;
                self.s.ntrees_d = n as u16;
                t.lit.resize(self.s.ntrees_l as usize, Huff::default());
                t.cmd.resize(self.s.blocks[1].n as usize, Huff::default());
                t.dist.resize(n, Huff::default());
                self.s.phase = Phase::Tree(0);
            }
            Phase::Tree(k) => {
                let (nl, nc) = (self.s.ntrees_l as usize, self.s.blocks[1].n as usize);
                let k = k as usize;
                let t = &mut self.t;
                if k < nl {
                    read_code(br, 256, &mut t.lit[k], &mut t.lens)?;
                } else if k < nl + nc {
                    read_code(br, 704, &mut t.cmd[k - nl], &mut t.lens)?;
                } else {
                    let dsize = 16 + self.s.ndirect as usize + (48 << self.s.npostfix);
                    read_code(br, dsize, &mut t.dist[k - nl - nc], &mut t.lens)?;
                }
                self.s.phase = if k + 1 == nl + nc + self.s.ntrees_d as usize { Phase::Command } else { Phase::Tree(k as u16 + 1) };
            }
            Phase::Uncompressed => {
                let room = self.win.stop().saturating_sub(self.win.buf.len()).max(1);
                let n = (self.s.meta_left as usize).min(br.avail_bytes()).min(room);
                if n == 0 {
                    return Err(Fail::Under);
                }
                let at = br.pos / 8;
                self.win.buf.extend_from_slice(&br.buf[at..at + n]);
                br.pos += n * 8;
                self.s.meta_left -= n as u32;
                self.s.pos += n as u64;
                if self.s.meta_left == 0 {
                    self.end_meta();
                }
            }
            Phase::Metadata => {
                let n = (self.s.skip_left as usize).min(br.avail_bytes());
                if n == 0 && self.s.skip_left > 0 {
                    return Err(Fail::Under);
                }
                br.pos += n * 8;
                self.s.skip_left -= n as u32;
                if self.s.skip_left == 0 {
                    self.s.phase = Phase::MetaHeader;
                }
            }
            Phase::Command => {
                self.command(br)?;
                // With input to spare, run the command's literals, distance and copy in the
                // same transaction (one snapshot per command instead of four): a literal takes
                // at most 15 bits and a distance with its block switch under 64 bytes.
                if br.avail_bytes() >= 128 + 2 * self.s.insert_left as usize {
                    self.literals(br)?;
                    if self.s.phase == Phase::Distance {
                        self.distance(br)?;
                        if self.s.phase == Phase::Copy {
                            let room = self.win.stop().saturating_sub(self.win.buf.len());
                            let n = self.s.copy_left as usize;
                            if n <= room {
                                copy_back(&mut self.win.buf, self.s.copy_dist as usize, n);
                                self.s.copy_left = 0;
                                self.s.pos += n as u64;
                                self.after_command();
                            }
                        }
                    }
                }
            }
            Phase::Literals => self.literals(br)?,
            Phase::Distance => self.distance(br)?,
            Phase::Copy => {
                let room = self.win.stop().saturating_sub(self.win.buf.len()).max(1);
                let n = (self.s.copy_left as usize).min(room).min(1 << 16);
                copy_back(&mut self.win.buf, self.s.copy_dist as usize, n);
                self.s.copy_left -= n as u32;
                self.s.pos += n as u64;
                if self.s.copy_left == 0 {
                    self.after_command();
                }
            }
            Phase::Done => {}
        }
        Ok(())
    }

    fn end_meta(&mut self) {
        self.s.phase = if self.s.last { Phase::Done } else { Phase::MetaHeader };
    }

    fn after_command(&mut self) {
        if self.s.meta_left == 0 {
            self.end_meta();
        } else {
            self.s.phase = Phase::Command;
        }
    }

    fn meta_header(&mut self, br: &mut Br<'_>) -> R<()> {
        let last = br.bits(1)? == 1;
        if last && br.bits(1)? == 1 {
            self.s.phase = Phase::Done;
            return Ok(());
        }
        let nibbles = match br.bits(2)? {
            3 => 0,
            n => n + 4,
        };
        if nibbles == 0 {
            if last {
                return Err(bad("metadata in the last meta-block").into());
            }
            if br.bits(1)? != 0 {
                return Err(bad("reserved bit set").into());
            }
            let nbytes = br.bits(2)?;
            let mut skip = 0u32;
            for i in 0..nbytes {
                let b = br.bits(8)?;
                if i + 1 == nbytes && nbytes > 1 && b == 0 {
                    return Err(bad("non-minimal metadata length").into());
                }
                skip |= b << (8 * i);
            }
            br.align_zero()?;
            self.s.skip_left = if nbytes == 0 { 0 } else { skip + 1 };
            self.s.phase = Phase::Metadata;
            return Ok(());
        }
        let mut mlen = 0u32;
        for i in 0..nibbles {
            let v = br.bits(4)?;
            if i + 1 == nibbles && nibbles > 4 && v == 0 {
                return Err(bad("non-minimal meta-block length").into());
            }
            mlen |= v << (4 * i);
        }
        let mlen = mlen + 1;
        self.s.last = last;
        self.s.meta_left = mlen;
        if !last && br.bits(1)? == 1 {
            br.align_zero()?;
            self.s.phase = Phase::Uncompressed;
            return Ok(());
        }
        let t = &mut self.t;
        for c in 0..3 {
            let n = var_u8(br)? + 1;
            let b = &mut self.s.blocks[c];
            *b = Blocks { n, ty: 0, count: 1 << 24, last: 0, second: 1 };
            if n >= 2 {
                read_code(br, n as usize + 2, &mut t.btype[c], &mut t.lens)?;
                read_code(br, 26, &mut t.bcount[c], &mut t.lens)?;
                self.s.blocks[c].count = block_len(br, &t.bcount[c])?;
            }
        }
        self.s.phase = Phase::CmapLit;
        Ok(())
    }

    /// The next symbol's block type for category `c` (reads a block switch when due).
    #[inline(always)]
    fn switch(&mut self, br: &mut Br<'_>, c: usize) -> Result<u32, Under> {
        let b = self.s.blocks[c];
        if b.n < 2 {
            return Ok(0);
        }
        if b.count == 0 {
            let code = self.t.btype[c].read(br)?;
            let ty = match code {
                0 => b.second,
                1 => (b.last + 1) % b.n,
                x => x - 2,
            };
            let ty = if ty >= b.n { ty % b.n } else { ty };
            let count = block_len(br, &self.t.bcount[c])?;
            self.s.blocks[c] = Blocks { n: b.n, ty, count: count - 1, last: ty, second: b.last };
            Ok(ty)
        } else {
            self.s.blocks[c].count -= 1;
            Ok(b.ty)
        }
    }

    fn command(&mut self, br: &mut Br<'_>) -> R<()> {
        let ty = self.switch(br, 1)? as usize;
        let code = self.t.cmd[ty].read(br)? as usize;
        let cell = code >> 6;
        let ic = (CELL_INS[cell] + ((code as u32 >> 3) & 7)) as usize;
        let cc = (CELL_COPY[cell] + (code as u32 & 7)) as usize;
        let (ib, ie) = INS[ic];
        let (cb, ce) = COPY[cc];
        self.s.insert_left = ib + br.bits(ie)?;
        self.s.copy_len = cb + br.bits(ce)?;
        self.s.implicit_dist = code < 128;
        self.s.phase = Phase::Literals;
        Ok(())
    }

    fn literals(&mut self, br: &mut Br<'_>) -> R<()> {
        // A batch of literals; each needs at most ~70 bits, so with 64 carried bytes left the
        // batch can't run out of input midway and needs no per-literal snapshot.
        let want = self.s.insert_left.min(self.s.meta_left).min(4096) as usize;
        self.win.buf.reserve(want);
        // one literal block type: no switches, the mode and context map are fixed; a literal
        // takes at most 15 bits, so `fast` of them can't run out of input
        let fast = if self.s.blocks[0].n < 2 { want.min(br.avail_bytes() * 8 / 15) } else { 0 };
        if fast > 0 {
            let n = fast;
            {
                let t = &self.t;
                let buf = &mut self.win.buf;
                if self.s.ntrees_l == 1 {
                    let tree = &t.lit[0];
                    for _ in 0..n {
                        let b = tree.read(br)? as u8;
                        buf.push(b);
                    }
                } else {
                    let lut = &CONTEXT_LUT[t.modes[0] as usize];
                    let cmap = &t.cmap_lit[..64];
                    let len = buf.len();
                    // (the stream position, not the buffer: one-shot output may hold earlier
                    // bytes)
                    let mut p1 = if self.s.pos > 0 { buf[len - 1] } else { 0 };
                    let mut p2 = if self.s.pos > 1 { buf[len - 2] } else { 0 };
                    for _ in 0..n {
                        let ctx = (lut[p1 as usize] | lut[256 + p2 as usize]) as usize & 63;
                        let b = t.lit[cmap[ctx] as usize].read(br)? as u8;
                        buf.push(b);
                        p2 = p1;
                        p1 = b;
                    }
                }
                self.s.insert_left -= n as u32;
                self.s.meta_left -= n as u32;
                self.s.pos += n as u64;
            }
        } else {
            let mut n = 0;
            while self.s.insert_left > 0 && self.s.meta_left > 0 && n < 4096 {
                if br.avail_bytes() < 64 && n > 0 {
                    break;
                }
                let ty = self.switch(br, 0)? as usize;
                let len = self.win.buf.len();
                // (the stream position, not the buffer: one-shot output may hold earlier bytes)
                let p1 = if self.s.pos > 0 { self.win.buf[len - 1] } else { 0 };
                let p2 = if self.s.pos > 1 { self.win.buf[len - 2] } else { 0 };
                let lut = &CONTEXT_LUT[self.t.modes[ty] as usize];
                let ctx = (lut[p1 as usize] | lut[256 + p2 as usize]) as usize;
                let tree = self.t.cmap_lit[64 * ty + ctx] as usize;
                let b = self.t.lit[tree].read(br)? as u8;
                self.win.buf.push(b);
                self.s.insert_left -= 1;
                self.s.meta_left -= 1;
                self.s.pos += 1;
                n += 1;
            }
        }
        if self.s.insert_left > 0 && self.s.meta_left > 0 {
            return Ok(());
        }
        if self.s.insert_left > 0 {
            return Err(bad("insert past the end of the meta-block").into());
        }
        if self.s.meta_left == 0 {
            self.end_meta();
        } else {
            self.s.phase = Phase::Distance;
        }
        Ok(())
    }

    fn distance(&mut self, br: &mut Br<'_>) -> R<()> {
        let copy_len = self.s.copy_len;
        let (dist, code0) = if self.s.implicit_dist {
            (self.s.dist_rb[self.s.dist_idx], true)
        } else {
            let ty = self.switch(br, 2)? as usize;
            let ctx = if copy_len > 4 { 3 } else { copy_len as usize - 2 };
            let tree = self.t.cmap_dist[4 * ty + ctx] as usize;
            let d = self.t.dist[tree].read(br)?;
            (self.decode_dist(br, d)?, d == 0)
        };
        let max = (self.wsize as u64).min(self.s.pos) as u32;
        if dist > max {
            // static dictionary
            let len = copy_len as usize;
            if !(4..=24).contains(&len) {
                return Err(bad("invalid dictionary reference length").into());
            }
            let word_id = (dist - max - 1) as usize;
            let nbits = NDBITS[len];
            let idx = word_id & ((1 << nbits) - 1);
            let tr = word_id >> nbits;
            if tr >= TRANSFORMS.len() {
                return Err(bad("invalid dictionary transform").into());
            }
            let off = OFFSETS[len] as usize + idx * len;
            let word = &dictionary()[off..off + len];
            let before = self.win.buf.len();
            transform(word, tr, &mut self.win.buf);
            let n = (self.win.buf.len() - before) as u32;
            if n > self.s.meta_left {
                return Err(bad("dictionary word past the end of the meta-block").into());
            }
            self.s.meta_left -= n;
            self.s.pos += n as u64;
            self.after_command();
            return Ok(());
        }
        if !code0 {
            self.s.dist_idx = (self.s.dist_idx + 1) & 3;
            self.s.dist_rb[self.s.dist_idx] = dist;
        }
        if copy_len > self.s.meta_left {
            return Err(bad("copy past the end of the meta-block").into());
        }
        self.s.meta_left -= copy_len;
        self.s.copy_left = copy_len;
        self.s.copy_dist = dist;
        self.s.phase = Phase::Copy;
        Ok(())
    }

    fn decode_dist(&self, br: &mut Br<'_>, d: u32) -> R<u32> {
        let rb = &self.s.dist_rb;
        let at = |k: usize| rb[(self.s.dist_idx + 4 - k) & 3] as i64;
        let v: i64 = match d {
            0 => at(0),
            1 => at(1),
            2 => at(2),
            3 => at(3),
            4..=9 => {
                const D: [i64; 6] = [-1, 1, -2, 2, -3, 3];
                at(0) + D[d as usize - 4]
            }
            10..=15 => {
                const D: [i64; 6] = [-1, 1, -2, 2, -3, 3];
                at(1) + D[d as usize - 10]
            }
            _ if d < 16 + self.s.ndirect => (d - 15) as i64,
            _ => {
                let np = self.s.npostfix;
                let x = d - self.s.ndirect - 16;
                let nbits = 1 + (x >> (np + 1));
                let hcode = x >> np;
                let lcode = x & ((1 << np) - 1);
                let offset = ((2 + (hcode & 1)) << nbits) - 4;
                let extra = br.bits(nbits)?;
                (((offset + extra) as i64) << np) + lcode as i64 + self.s.ndirect as i64 + 1
            }
        };
        if v <= 0 || v > u32::MAX as i64 {
            return Err(bad("invalid distance").into());
        }
        Ok(v as u32)
    }
}

/// Reads a context map of `size` entries over `ntrees` trees (section 7.3).
fn read_cmap(br: &mut Br<'_>, ntrees: usize, size: usize, out: &mut Vec<u8>, lens: &mut Vec<u8>) -> R<()> {
    out.clear();
    out.resize(size, 0);
    if ntrees < 2 {
        return Ok(());
    }
    let rlemax = if br.bits(1)? == 1 { br.bits(4)? as usize + 1 } else { 0 };
    let mut h = Huff::default();
    read_code(br, ntrees + rlemax, &mut h, lens)?;
    let mut i = 0;
    while i < size {
        let s = h.read(br)? as usize;
        if s == 0 {
            out[i] = 0;
            i += 1;
        } else if s <= rlemax {
            let run = (1usize << s) + br.bits(s as u32)? as usize;
            if i + run > size {
                return Err(bad("context map run too long").into());
            }
            for v in &mut out[i..i + run] {
                *v = 0;
            }
            i += run;
        } else {
            out[i] = (s - rlemax) as u8;
            i += 1;
        }
    }
    if br.bits(1)? == 1 {
        // inverse move-to-front
        let mut mtf: Vec<u8> = (0..=255u8).collect();
        for v in out.iter_mut() {
            let idx = *v as usize;
            let val = mtf[idx];
            *v = val;
            mtf.copy_within(0..idx, 1);
            mtf[0] = val;
        }
    }
    Ok(())
}

/// Applies dictionary transform `t` to `word`, appending to `out` (Appendix B).
pub(crate) fn transform(word: &[u8], t: usize, out: &mut Vec<u8>) {
    let (prefix, ty, suffix) = TRANSFORMS[t];
    out.extend_from_slice(prefix);
    let mut w = word;
    match ty {
        1..=9 => w = &w[..w.len().saturating_sub(ty as usize)],
        12..=20 => w = &w[(ty as usize - 11).min(w.len())..],
        _ => {}
    }
    let start = out.len();
    out.extend_from_slice(w);
    if ty == 10 {
        ferment(&mut out[start..]);
    } else if ty == 11 {
        let mut i = start;
        while i < out.len() {
            i += ferment(&mut out[i..]);
        }
    }
    out.extend_from_slice(suffix);
}

/// Upper-cases the first character of `p` (the RFC's "Ferment"); returns its length.
fn ferment(p: &mut [u8]) -> usize {
    if p.is_empty() {
        return 1;
    }
    if p[0] < 192 {
        if p[0].is_ascii_lowercase() {
            p[0] ^= 32;
        }
        return 1;
    }
    if p[0] < 224 {
        if p.len() > 1 {
            p[1] ^= 32;
        }
        return 2.min(p.len());
    }
    if p.len() > 2 {
        p[2] ^= 5;
    }
    3.min(p.len())
}
