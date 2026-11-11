//! Streaming DEFLATE decoder (RFC 1951) with the zlib (RFC 1950) and gzip (RFC 1952)
//! containers.
//!
//! Huffman codes are decoded through lookup tables: a 10-bit primary table for literals and
//! lengths, 8 bits for distances, with second-level tables for longer codes. The bit buffer is
//! 64 bits wide and refilled eight bytes at a time while the input lasts, so the common path
//! decodes a literal or a whole match (at most 48 bits) after a single refill.
//!
//! The decoder is resumable at any input boundary: before each symbol it records the bit
//! buffer, and when the input runs out in the middle of a symbol it rewinds to that point and
//! asks for more. Input bytes are never copied; at most 63 bits are carried between calls.
//!
//! Memory is bounded: a streaming decoder keeps a 64 KiB window (32 KiB of history plus up to
//! 32 KiB of output not yet handed out), its Huffman tables (about 8 KiB) and its header state.

use crate::checksum::{Adler32, Crc32};
use crate::tables::{fixed_lit_len, CL_ORDER, DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA};
use crate::{Error, ErrorKind, Format};
use std::sync::OnceLock;

/// The DEFLATE history size.
const HIST: usize = 32 * 1024;
/// A streaming decoder decodes into its window until the window holds this many bytes.
const STOP: usize = 2 * HIST;
/// Window capacity: `STOP` plus room for the last match (258 bytes).
const CAP: usize = STOP + 320;

// Table entries: [value:16][extra:8][kind:3][len:5].
const K_LIT: u32 = 0;
const K_LEN: u32 = 1;
const K_EOB: u32 = 2;
const K_SUB: u32 = 3;
const K_BAD: u32 = 4;

#[inline(always)]
const fn ent(kind: u32, len: u32, extra: u32, value: u32) -> u32 {
    (value << 16) | (extra << 8) | (kind << 5) | len
}
#[inline(always)]
fn e_len(e: u32) -> u32 {
    e & 31
}
#[inline(always)]
fn e_kind(e: u32) -> u32 {
    (e >> 5) & 7
}
#[inline(always)]
fn e_extra(e: u32) -> u32 {
    (e >> 8) & 0xFF
}
#[inline(always)]
fn e_val(e: u32) -> u32 {
    e >> 16
}

const LIT_BITS: u32 = 10;
const DIST_BITS: u32 = 8;
const CL_BITS: u32 = 7;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Lit,
    Dist,
    CodeLen,
}

fn sym_entry(kind: Kind, s: usize) -> u32 {
    match kind {
        Kind::Lit => match s {
            0..=255 => ent(K_LIT, 0, 0, s as u32),
            256 => ent(K_EOB, 0, 0, 0),
            257..=285 => ent(K_LEN, 0, LEN_EXTRA[s - 257] as u32, LEN_BASE[s - 257] as u32),
            _ => ent(K_BAD, 0, 0, 0),
        },
        Kind::Dist => match s {
            0..=29 => ent(K_LEN, 0, DIST_EXTRA[s] as u32, DIST_BASE[s] as u32),
            _ => ent(K_BAD, 0, 0, 0),
        },
        Kind::CodeLen => ent(K_LIT, 0, 0, s as u32),
    }
}

/// Builds a decoding table for the canonical code given by `lens` (RFC 1951 §3.2.2).
fn build(lens: &[u8], tbits: u32, kind: Kind, t: &mut Vec<u32>) -> Result<(), Error> {
    let mut count = [0u16; 16];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let max = (1..16).rev().find(|&l| count[l] != 0).unwrap_or(0);
    let mut left: i32 = 1;
    for &c in &count[1..] {
        left = (left << 1) - c as i32;
        if left < 0 {
            return Err(Error::invalid("over-subscribed Huffman code"));
        }
    }
    // An incomplete code is accepted only as a single code of length 1 (as zlib does), or no
    // code at all (a block without distances).
    if left > 0 && max != 0 && (kind == Kind::CodeLen || max != 1) {
        return Err(Error::invalid("incomplete Huffman code"));
    }
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for l in 1..16 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    let size = 1usize << tbits;
    t.clear();
    t.resize(size, ent(K_BAD, tbits, 0, 0));
    let mut revs = [0u16; 320];
    let mut sub_max = [0u8; 1 << LIT_BITS];
    for (s, &l) in lens.iter().enumerate() {
        if l == 0 {
            continue;
        }
        let c = next[l as usize];
        next[l as usize] += 1;
        let r = c.reverse_bits() >> (16 - l as u32);
        revs[s] = r;
        if l as u32 > tbits {
            let p = r as usize & (size - 1);
            sub_max[p] = sub_max[p].max(l);
        }
    }
    if max as u32 > tbits {
        for (p, &m) in sub_max.iter().enumerate().take(size) {
            if m > 0 {
                let sb = m as u32 - tbits;
                let off = t.len();
                t.resize(off + (1 << sb), ent(K_BAD, sb, 0, 0));
                t[p] = ent(K_SUB, tbits, sb, off as u32);
            }
        }
    }
    for (s, &l) in lens.iter().enumerate() {
        if l == 0 {
            continue;
        }
        let l = l as u32;
        let r = revs[s] as usize;
        let e = sym_entry(kind, s);
        if l <= tbits {
            let mut i = r;
            while i < size {
                t[i] = e | l;
                i += 1 << l;
            }
        } else {
            let sub = t[r & (size - 1)];
            let off = e_val(sub) as usize;
            let sb = e_extra(sub);
            let sl = l - tbits;
            let mut i = r >> tbits;
            while i < (1 << sb) {
                t[off + i] = e | sl;
                i += 1 << sl;
            }
        }
    }
    Ok(())
}

fn fixed_tables() -> &'static (Vec<u32>, Vec<u32>) {
    static T: OnceLock<(Vec<u32>, Vec<u32>)> = OnceLock::new();
    T.get_or_init(|| {
        let mut lens = [0u8; 288];
        for (i, l) in lens.iter_mut().enumerate() {
            *l = fixed_lit_len(i);
        }
        let (mut lit, mut dist) = (Vec::new(), Vec::new());
        build(&lens, LIT_BITS, Kind::Lit, &mut lit).expect("fixed literal code");
        build(&[5u8; 32], DIST_BITS, Kind::Dist, &mut dist).expect("fixed distance code");
        (lit, dist)
    })
}

/// The bit buffer: bits are consumed from the low end.
#[derive(Default, Clone, Copy)]
struct Bits {
    bb: u64,
    cnt: u32,
}

impl Bits {
    /// Loads input until at least 56 bits are buffered or the input ends. Bits above `cnt` may
    /// hold the next input bytes (loaded but not counted); they are loaded again, with the same
    /// values, by the next refill.
    #[inline(always)]
    fn refill(&mut self, inp: &[u8], pos: &mut usize) {
        if let Some(w) = inp.get(*pos..*pos + 8) {
            let w = u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]);
            self.bb |= w << self.cnt;
            *pos += ((63 - self.cnt) >> 3) as usize;
            self.cnt |= 56;
        } else {
            while self.cnt < 56 && *pos < inp.len() {
                self.bb |= (inp[*pos] as u64) << self.cnt;
                *pos += 1;
                self.cnt += 8;
            }
        }
    }

    /// Takes `n` (at most 32, at most `cnt`) bits.
    #[inline(always)]
    fn take(&mut self, n: u32) -> u32 {
        let v = (self.bb & ((1u64 << n) - 1)) as u32;
        self.bb >>= n;
        self.cnt -= n;
        v
    }

    #[inline(always)]
    fn drop_bits(&mut self, n: u32) {
        self.bb >>= n;
        self.cnt -= n;
    }

    fn align(&mut self) {
        let r = self.cnt & 7;
        self.drop_bits(r);
    }

    /// Clears the bits above `cnt` (between calls the next input is unknown).
    fn mask(&mut self) {
        self.bb &= (1u64 << self.cnt) - 1;
    }

    /// One byte; the buffer must be byte aligned.
    fn byte(&mut self, inp: &[u8], pos: &mut usize) -> Option<u8> {
        if self.cnt < 8 {
            self.refill(inp, pos);
            if self.cnt < 8 {
                return None;
            }
        }
        Some(self.take(8) as u8)
    }
}

/// Why a decoding step returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flow {
    /// The input is used up (or the stream is complete and nothing more is expected).
    Need,
    /// The output reached the stop mark.
    Full,
    /// The stream is complete.
    Done,
}

enum CodesEnd {
    Need,
    Full,
    BlockEnd,
}

/// Copies a match of `len` bytes from `dist` bytes back.
#[inline(always)]
fn copy_match(out: &mut Vec<u8>, dist: usize, len: usize) {
    let start = out.len() - dist;
    if dist >= len {
        out.extend_from_within(start..start + len);
    } else if dist == 1 {
        let b = out[start];
        out.resize(out.len() + len, b);
    } else {
        // Overlapping copy: the copied region doubles each round and stays a whole number of
        // periods, so every byte equals the one `dist` before it.
        let mut left = len;
        while left > 0 {
            let n = left.min(out.len() - start);
            out.extend_from_within(start..start + n);
            left -= n;
        }
    }
}

/// Decodes literal/length codes until the end of the block, the end of the input or `stop`.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn codes(bits: &mut Bits, inp: &[u8], pos: &mut usize, out: &mut Vec<u8>, base: usize, stop: usize, lit: &[u32], dist: &[u32]) -> Result<CodesEnd, Error> {
    const LMASK: u64 = (1 << LIT_BITS) - 1;
    const DMASK: u64 = (1 << DIST_BITS) - 1;
    loop {
        if out.len() >= stop {
            return Ok(CodesEnd::Full);
        }
        bits.refill(inp, pos);
        let saved = *bits;
        let mut e = lit[(bits.bb & LMASK) as usize];
        if e_kind(e) == K_LIT && e_len(e) <= bits.cnt {
            bits.drop_bits(e_len(e));
            out.push(e_val(e) as u8);
            continue;
        }
        let mut used = 0;
        if e_kind(e) == K_SUB {
            used = LIT_BITS;
            e = lit[(e_val(e) as u64 + ((bits.bb >> LIT_BITS) & ((1 << e_extra(e)) - 1))) as usize];
        }
        let l = used + e_len(e);
        if l > bits.cnt {
            return Ok(CodesEnd::Need);
        }
        match e_kind(e) {
            K_LIT => {
                bits.drop_bits(l);
                out.push(e_val(e) as u8);
            }
            K_LEN => {
                bits.drop_bits(l);
                let x = e_extra(e);
                if x > bits.cnt {
                    *bits = saved;
                    return Ok(CodesEnd::Need);
                }
                let length = (e_val(e) + bits.take(x)) as usize;
                let mut d = dist[(bits.bb & DMASK) as usize];
                let mut used = 0;
                if e_kind(d) == K_SUB {
                    used = DIST_BITS;
                    d = dist[(e_val(d) as u64 + ((bits.bb >> DIST_BITS) & ((1 << e_extra(d)) - 1))) as usize];
                }
                let l = used + e_len(d);
                if l > bits.cnt {
                    *bits = saved;
                    return Ok(CodesEnd::Need);
                }
                if e_kind(d) != K_LEN {
                    return Err(Error::invalid("invalid distance code"));
                }
                bits.drop_bits(l);
                let x = e_extra(d);
                if x > bits.cnt {
                    *bits = saved;
                    return Ok(CodesEnd::Need);
                }
                let distance = (e_val(d) + bits.take(x)) as usize;
                if distance > out.len() - base {
                    return Err(Error::invalid("distance too far back"));
                }
                copy_match(out, distance, length);
            }
            K_EOB => {
                bits.drop_bits(l);
                return Ok(CodesEnd::BlockEnd);
            }
            _ => return Err(Error::invalid("invalid literal/length code")),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St {
    Header,
    Block,
    StoredLen,
    Stored(u32),
    DynCounts,
    DynCl(usize),
    DynLens(usize),
    Codes,
    Trailer,
    /// After a gzip member: another member may follow.
    Member,
    Done,
}

/// A streaming decompressor for raw DEFLATE, zlib or gzip data.
///
/// Feed input with [`Inflate::decode`] (output appended to a `Vec`) or
/// [`Inflate::decode_into`] (output into a slice, for a fixed per-call bound), then call
/// [`Inflate::finish`] once the input has ended to check that the stream was complete.
/// [`Inflate::with_limit`] caps the total output (decompression bombs).
///
/// gzip streams may hold several members, which are decoded one after another (RFC 1952 §2.2).
/// Bytes after the last member that do not start another member are ignored.
#[derive(Clone)]
pub(crate) struct Inflate {
    format: Format,
    orig: Format,
    st: St,
    bits: Bits,
    last: bool,
    fixed: bool,
    lit: Vec<u32>,
    dist: Vec<u32>,
    cl: Vec<u32>,
    nlit: usize,
    ndist: usize,
    nclen: usize,
    lens: [u8; 320],
    clens: [u8; 19],
    /// Header and trailer parsing.
    hdr: [u8; 10],
    hn: usize,
    hstage: u8,
    hskip: usize,
    hcrc: Crc32,
    crc: Crc32,
    adler: Adler32,
    member_out: u64,
    /// The window (streaming) and the bytes of it not yet handed out.
    win: Vec<u8>,
    flushed: usize,
    /// Checksummed up to this index of the current output buffer.
    ck: usize,
    total_in: u64,
    total_out: u64,
    limit: u64,
}

impl std::fmt::Debug for Inflate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inflate").field("format", &self.format).field("total_in", &self.total_in).field("total_out", &self.total_out).finish()
    }
}

impl Inflate {
    /// A decoder that fails with [`ErrorKind::LimitExceeded`] once the output would pass `limit`
    /// bytes.
    pub fn with_limit(format: Format, limit: u64) -> Inflate {
        Inflate {
            format,
            orig: format,
            st: St::Header,
            bits: Bits::default(),
            last: false,
            fixed: false,
            lit: Vec::new(),
            dist: Vec::new(),
            cl: Vec::new(),
            nlit: 0,
            ndist: 0,
            nclen: 0,
            lens: [0; 320],
            clens: [0; 19],
            hdr: [0; 10],
            hn: 0,
            hstage: 0,
            hskip: 0,
            hcrc: Crc32::new(),
            crc: Crc32::new(),
            adler: Adler32::new(),
            member_out: 0,
            win: Vec::new(),
            flushed: 0,
            ck: 0,
            total_in: 0,
            total_out: 0,
            limit,
        }
    }

    /// Starts over with a new stream of the same format and limit, keeping the allocations.
    pub fn reset(&mut self) {
        let win = std::mem::take(&mut self.win);
        let (lit, dist, cl) = (std::mem::take(&mut self.lit), std::mem::take(&mut self.dist), std::mem::take(&mut self.cl));
        *self = Inflate { win, lit, dist, cl, ..Inflate::with_limit(self.orig, self.limit) };
        self.win.clear();
    }

    /// The container format. A [`Format::ZlibOrRaw`] decoder reports [`Format::Zlib`] or
    /// [`Format::Raw`] once it has seen the first bytes.
    pub fn format(&self) -> Format {
        self.format
    }

    /// The stream is complete (for gzip: at least one member is).
    pub fn is_done(&self) -> bool {
        matches!(self.st, St::Done | St::Member)
    }

    /// Decoded bytes not yet returned by [`Inflate::decode_into`].
    pub fn has_pending(&self) -> bool {
        self.flushed < self.win.len()
    }

    /// Compressed bytes consumed so far.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Decompressed bytes returned so far.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Decodes `input`, appending the output to `out`. Returns the number of input bytes
    /// consumed: all of them, unless the stream ended before.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, Error> {
        let mut pos = 0;
        let mut win = std::mem::take(&mut self.win);
        if win.capacity() < CAP {
            win.reserve_exact(CAP - win.len());
        }
        let r = loop {
            if let Err(e) = self.hand_out(&win, usize::MAX, |s| out.extend_from_slice(s)) {
                break Err(e);
            }
            self.slide(&mut win);
            match self.run(input, &mut pos, &mut win, 0, STOP) {
                Ok(Flow::Full) => continue,
                Ok(_) => break self.hand_out(&win, usize::MAX, |s| out.extend_from_slice(s)),
                Err(e) => break Err(e),
            }
        };
        self.win = win;
        self.bits.mask();
        self.total_in += pos as u64;
        r.map(|_| pos)
    }

    /// Decodes `input` into `output`. Returns `(consumed, written)`. Stops when `output` is
    /// full; call again with the rest of the input (and with an empty input, while
    /// [`Inflate::has_pending`], to collect the remaining output).
    pub fn decode_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize), Error> {
        let mut pos = 0;
        let mut written = 0;
        let mut win = std::mem::take(&mut self.win);
        if win.capacity() < CAP {
            win.reserve_exact(CAP - win.len());
        }
        let mut flow = None;
        let r = loop {
            let room = output.len() - written;
            let res = self.hand_out(&win, room, |s| {
                output[written..written + s.len()].copy_from_slice(s);
                written += s.len();
            });
            if let Err(e) = res {
                break Err(e);
            }
            if self.flushed < win.len() || matches!(flow, Some(Flow::Need) | Some(Flow::Done)) {
                break Ok(());
            }
            self.slide(&mut win);
            match self.run(input, &mut pos, &mut win, 0, STOP) {
                Ok(f) => flow = Some(f),
                Err(e) => break Err(e),
            }
        };
        self.win = win;
        self.bits.mask();
        self.total_in += pos as u64;
        r.map(|_| (pos, written))
    }

    /// Checks that the stream ended properly: [`ErrorKind::Truncated`] if more input was
    /// expected.
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.is_done() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Truncated, "compressed data ended early"))
        }
    }

    /// One-shot decoding into `out` (no window copy): the output buffer is the history.
    pub(crate) fn decode_all(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
        let base = out.len();
        self.ck = base;
        let mut pos = 0;
        let stop = base.saturating_add(limit).saturating_add(1);
        let flow = self.run(input, &mut pos, out, base, stop)?;
        self.sum(out);
        if out.len() - base > limit {
            return Err(Error::new(ErrorKind::LimitExceeded, "decompressed data exceeds the limit"));
        }
        self.total_in += pos as u64;
        self.total_out += (out.len() - base) as u64;
        match flow {
            Flow::Done => Ok(()),
            _ if self.is_done() => Ok(()),
            _ => Err(Error::new(ErrorKind::Truncated, "compressed data ended early")),
        }
    }

    /// Hands out pending window bytes (at most `room`), after the limit check.
    fn hand_out(&mut self, win: &[u8], room: usize, mut f: impl FnMut(&[u8])) -> Result<(), Error> {
        self.sum(win);
        let pending = win.len() - self.flushed;
        if pending == 0 {
            return Ok(());
        }
        if self.total_out + pending as u64 > self.limit {
            return Err(Error::new(ErrorKind::LimitExceeded, "decompressed data exceeds the limit"));
        }
        let n = pending.min(room);
        if n > 0 {
            f(&win[self.flushed..self.flushed + n]);
            self.flushed += n;
            self.total_out += n as u64;
        }
        Ok(())
    }

    /// Keeps the last 32 KiB of a full window.
    fn slide(&mut self, win: &mut Vec<u8>) {
        if win.len() >= STOP && self.flushed == win.len() {
            let d = win.len() - HIST;
            win.drain(..d);
            self.flushed -= d;
            self.ck -= d;
        }
    }

    /// Updates the container checksum over output not yet summed.
    fn sum(&mut self, out: &[u8]) {
        if self.ck < out.len() {
            let s = &out[self.ck..];
            match self.format {
                Format::Gzip => {
                    self.crc.update(s);
                    self.member_out += s.len() as u64;
                }
                Format::Zlib => self.adler.update(s),
                _ => {}
            }
            self.ck = out.len();
        }
    }

    fn run(&mut self, inp: &[u8], pos: &mut usize, out: &mut Vec<u8>, base: usize, stop: usize) -> Result<Flow, Error> {
        loop {
            match self.st {
                St::Header => {
                    if !self.header(inp, pos)? {
                        return Ok(Flow::Need);
                    }
                    self.st = St::Block;
                }
                St::Block => {
                    self.bits.refill(inp, pos);
                    if self.bits.cnt < 3 {
                        return Ok(Flow::Need);
                    }
                    self.last = self.bits.take(1) == 1;
                    self.st = match self.bits.take(2) {
                        0 => St::StoredLen,
                        1 => {
                            self.fixed = true;
                            St::Codes
                        }
                        2 => St::DynCounts,
                        _ => return Err(Error::invalid("invalid block type")),
                    };
                }
                St::StoredLen => {
                    self.bits.align();
                    self.bits.refill(inp, pos);
                    if self.bits.cnt < 32 {
                        return Ok(Flow::Need);
                    }
                    let len = self.bits.take(16);
                    let nlen = self.bits.take(16);
                    if len != (!nlen & 0xFFFF) {
                        return Err(Error::invalid("invalid stored block lengths"));
                    }
                    self.st = St::Stored(len);
                }
                St::Stored(mut left) => {
                    while left > 0 && self.bits.cnt >= 8 && out.len() < stop {
                        out.push(self.bits.take(8) as u8);
                        left -= 1;
                    }
                    if left > 0 && self.bits.cnt < 8 {
                        // Aligned and empty: copy straight from the input. The bits above
                        // `cnt` may hold stale input, which a later refill must not see.
                        self.bits.bb = 0;
                        let n = (left as usize).min(inp.len() - *pos).min(stop.saturating_sub(out.len()));
                        out.extend_from_slice(&inp[*pos..*pos + n]);
                        *pos += n;
                        left -= n as u32;
                    }
                    if left > 0 {
                        self.st = St::Stored(left);
                        return Ok(if out.len() >= stop { Flow::Full } else { Flow::Need });
                    }
                    self.st = if self.last { self.end_of_data(out) } else { St::Block };
                }
                St::DynCounts => {
                    self.bits.refill(inp, pos);
                    if self.bits.cnt < 14 {
                        return Ok(Flow::Need);
                    }
                    self.nlit = self.bits.take(5) as usize + 257;
                    self.ndist = self.bits.take(5) as usize + 1;
                    self.nclen = self.bits.take(4) as usize + 4;
                    if self.nlit > 286 || self.ndist > 30 {
                        return Err(Error::invalid("invalid dynamic block header"));
                    }
                    self.clens = [0; 19];
                    self.st = St::DynCl(0);
                }
                St::DynCl(mut i) => {
                    while i < self.nclen {
                        if self.bits.cnt < 3 {
                            self.bits.refill(inp, pos);
                            if self.bits.cnt < 3 {
                                self.st = St::DynCl(i);
                                return Ok(Flow::Need);
                            }
                        }
                        self.clens[CL_ORDER[i]] = self.bits.take(3) as u8;
                        i += 1;
                    }
                    build(&self.clens, CL_BITS, Kind::CodeLen, &mut self.cl)?;
                    self.st = St::DynLens(0);
                }
                St::DynLens(mut i) => {
                    let total = self.nlit + self.ndist;
                    while i < total {
                        self.bits.refill(inp, pos);
                        let saved = self.bits;
                        let e = self.cl[(self.bits.bb & ((1 << CL_BITS) - 1)) as usize];
                        let l = e_len(e);
                        if l > self.bits.cnt {
                            self.st = St::DynLens(i);
                            return Ok(Flow::Need);
                        }
                        if e_kind(e) == K_BAD {
                            return Err(Error::invalid("invalid code length code"));
                        }
                        self.bits.drop_bits(l);
                        let sym = e_val(e);
                        let (n, val) = match sym {
                            0..=15 => (1, sym as u8),
                            16 => {
                                if i == 0 {
                                    return Err(Error::invalid("repeat with no previous length"));
                                }
                                if self.bits.cnt < 2 {
                                    self.bits = saved;
                                    self.st = St::DynLens(i);
                                    return Ok(Flow::Need);
                                }
                                (3 + self.bits.take(2) as usize, self.lens[i - 1])
                            }
                            17 => {
                                if self.bits.cnt < 3 {
                                    self.bits = saved;
                                    self.st = St::DynLens(i);
                                    return Ok(Flow::Need);
                                }
                                (3 + self.bits.take(3) as usize, 0)
                            }
                            _ => {
                                if self.bits.cnt < 7 {
                                    self.bits = saved;
                                    self.st = St::DynLens(i);
                                    return Ok(Flow::Need);
                                }
                                (11 + self.bits.take(7) as usize, 0)
                            }
                        };
                        if i + n > total {
                            return Err(Error::invalid("too many code lengths"));
                        }
                        self.lens[i..i + n].fill(val);
                        i += n;
                    }
                    if self.lens[256] == 0 {
                        return Err(Error::invalid("no end-of-block code"));
                    }
                    build(&self.lens[..self.nlit], LIT_BITS, Kind::Lit, &mut self.lit)?;
                    build(&self.lens[self.nlit..total], DIST_BITS, Kind::Dist, &mut self.dist)?;
                    self.fixed = false;
                    self.st = St::Codes;
                }
                St::Codes => {
                    let (lit, dist): (&[u32], &[u32]) = if self.fixed {
                        let t = fixed_tables();
                        (&t.0, &t.1)
                    } else {
                        (&self.lit, &self.dist)
                    };
                    match codes(&mut self.bits, inp, pos, out, base, stop, lit, dist)? {
                        CodesEnd::Need => return Ok(Flow::Need),
                        CodesEnd::Full => return Ok(Flow::Full),
                        CodesEnd::BlockEnd => self.st = if self.last { self.end_of_data(out) } else { St::Block },
                    }
                }
                St::Trailer => {
                    let need = if self.format == Format::Gzip { 8 } else { 4 };
                    while self.hn < need {
                        match self.bits.byte(inp, pos) {
                            Some(b) => {
                                self.hdr[self.hn] = b;
                                self.hn += 1;
                            }
                            None => return Ok(Flow::Need),
                        }
                    }
                    let h = &self.hdr;
                    if self.format == Format::Gzip {
                        let crc = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
                        let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
                        if crc != self.crc.value() {
                            return Err(Error::new(ErrorKind::Checksum, "gzip CRC-32 mismatch"));
                        }
                        if size != self.member_out as u32 {
                            return Err(Error::new(ErrorKind::Checksum, "gzip length mismatch"));
                        }
                        self.st = St::Member;
                    } else {
                        if u32::from_be_bytes([h[0], h[1], h[2], h[3]]) != self.adler.value() {
                            return Err(Error::new(ErrorKind::Checksum, "zlib Adler-32 mismatch"));
                        }
                        self.st = St::Done;
                    }
                }
                St::Member => {
                    self.bits.refill(inp, pos);
                    if self.bits.cnt >= 8 && self.bits.bb & 0xFF != 0x1F {
                        self.st = St::Done;
                    } else if self.bits.cnt >= 16 && self.bits.bb & 0xFFFF == 0x8B1F {
                        self.hn = 0;
                        self.hstage = 0;
                        self.crc = Crc32::new();
                        self.member_out = 0;
                        self.st = St::Header;
                    } else if self.bits.cnt >= 16 {
                        self.st = St::Done;
                    } else {
                        return Ok(Flow::Need);
                    }
                }
                St::Done => return Ok(Flow::Done),
            }
        }
    }

    /// After the last block: byte-align and go on to the trailer.
    fn end_of_data(&mut self, out: &[u8]) -> St {
        self.sum(out);
        self.bits.align();
        self.hn = 0;
        match self.format {
            Format::Gzip | Format::Zlib => St::Trailer,
            _ => St::Done,
        }
    }

    /// Parses the container header; `Ok(true)` when done.
    fn header(&mut self, inp: &[u8], pos: &mut usize) -> Result<bool, Error> {
        match self.format {
            Format::Raw => Ok(true),
            Format::Zlib | Format::ZlibOrRaw => {
                self.bits.refill(inp, pos);
                if self.bits.cnt < 16 {
                    return Ok(false);
                }
                let cmf = (self.bits.bb & 0xFF) as u32;
                let flg = ((self.bits.bb >> 8) & 0xFF) as u32;
                let valid = cmf & 0x0F == 8 && cmf >> 4 <= 7 && ((cmf << 8) | flg) % 31 == 0;
                if !valid {
                    if self.format == Format::ZlibOrRaw {
                        self.format = Format::Raw;
                        return Ok(true);
                    }
                    return Err(Error::invalid("invalid zlib header"));
                }
                if flg & 0x20 != 0 {
                    return Err(Error::invalid("zlib preset dictionaries are not supported"));
                }
                self.bits.drop_bits(16);
                self.format = Format::Zlib;
                self.adler = Adler32::new();
                Ok(true)
            }
            Format::Gzip => self.gzip_header(inp, pos),
            #[allow(unreachable_patterns)]
            _ => Err(Error::invalid("not a DEFLATE format")),
        }
    }

    fn gzip_header(&mut self, inp: &[u8], pos: &mut usize) -> Result<bool, Error> {
        const FHCRC: u8 = 2;
        const FEXTRA: u8 = 4;
        const FNAME: u8 = 8;
        const FCOMMENT: u8 = 16;
        loop {
            match self.hstage {
                // The fixed 10 bytes.
                0 => {
                    if self.hn == 0 {
                        self.hcrc = Crc32::new();
                    }
                    while self.hn < 10 {
                        let Some(b) = self.bits.byte(inp, pos) else { return Ok(false) };
                        self.hdr[self.hn] = b;
                        self.hn += 1;
                    }
                    let h = self.hdr;
                    if h[0] != 0x1F || h[1] != 0x8B {
                        return Err(Error::invalid("not gzip data"));
                    }
                    if h[2] != 8 {
                        return Err(Error::invalid("unknown gzip compression method"));
                    }
                    if h[3] & 0xE0 != 0 {
                        return Err(Error::invalid("reserved gzip flags set"));
                    }
                    self.hcrc.update(&h);
                    self.hn = 0;
                    self.hstage = 1;
                }
                // FEXTRA: length, then that many bytes.
                1 => {
                    if self.hdr[3] & FEXTRA == 0 {
                        self.hstage = 3;
                        continue;
                    }
                    let mut l = [0u8; 2];
                    while self.hn < 2 {
                        let Some(b) = self.bits.byte(inp, pos) else { return Ok(false) };
                        self.hcrc.update(&[b]);
                        self.hdr[8 + self.hn] = b;
                        self.hn += 1;
                    }
                    l.copy_from_slice(&self.hdr[8..10]);
                    self.hskip = u16::from_le_bytes(l) as usize;
                    self.hstage = 2;
                }
                2 => {
                    while self.hskip > 0 {
                        let Some(b) = self.bits.byte(inp, pos) else { return Ok(false) };
                        self.hcrc.update(&[b]);
                        self.hskip -= 1;
                    }
                    self.hstage = 3;
                }
                // FNAME and FCOMMENT: zero-terminated, skipped.
                3 | 4 => {
                    let flag = if self.hstage == 3 { FNAME } else { FCOMMENT };
                    if self.hdr[3] & flag != 0 {
                        loop {
                            let Some(b) = self.bits.byte(inp, pos) else { return Ok(false) };
                            self.hcrc.update(&[b]);
                            if b == 0 {
                                break;
                            }
                        }
                    }
                    self.hstage += 1;
                    self.hn = 0;
                }
                5 => {
                    if self.hdr[3] & FHCRC != 0 {
                        while self.hn < 2 {
                            let Some(b) = self.bits.byte(inp, pos) else { return Ok(false) };
                            self.hdr[8 + self.hn] = b;
                            self.hn += 1;
                        }
                        let want = u16::from_le_bytes([self.hdr[8], self.hdr[9]]);
                        if want != self.hcrc.value() as u16 {
                            return Err(Error::new(ErrorKind::Checksum, "gzip header CRC mismatch"));
                        }
                    }
                    self.hstage = 6;
                    self.crc = Crc32::new();
                    self.member_out = 0;
                    return Ok(true);
                }
                _ => return Ok(true),
            }
        }
    }
}
