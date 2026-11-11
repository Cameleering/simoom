//! zstd decoder (RFC 8878): frames and skippable frames, raw, RLE and compressed blocks,
//! Huffman literals (one or four streams, tree reuse), FSE sequences (predefined, RLE,
//! compressed and repeated tables), repeat offsets, the content checksum, and dictionaries.
//!
//! Input is carried until a whole unit (a frame header, a block, a checksum) is there, so the
//! decoder resumes at any input boundary; a block is at most 128 KiB, which bounds the carry.
//! The window (the frame's `Window_Size`, refused above the configured maximum, by default
//! 8 MiB as RFC 9659 asks of HTTP) bounds the history; output comes out block by block.

use super::fse::{read_ncount, Bits, DTable, HufTable, SeqE, SeqTable, Xxh64};
use super::{LL_BASE, LL_BITS, LL_NORM, ML_BASE, ML_BITS, ML_NORM, OF_NORM};
use crate::window::{Carry, Flow, Window};
use std::sync::OnceLock;
use crate::{Error, ErrorKind};

fn bad(msg: &'static str) -> Error {
    Error::invalid(msg)
}

const MAGIC: u32 = 0xFD2F_B528;
const DICT_MAGIC: u32 = 0xEC30_A437;
const BLOCK_MAX: usize = 128 * 1024;
/// Slack after the literals and after a block's output, so copies can move 16 bytes at a time.
const WILD: usize = 32;

/// The (code base, extra bits, largest code) of literal lengths, offsets and match lengths.
const KINDS: [(&[u32], &[u8], usize); 3] = [(&LL_BASE, &LL_BITS, 35), (&[], &[], 31), (&ML_BASE, &ML_BITS, 52)];

/// The predefined sequence tables (literal lengths, offsets, match lengths), built once.
fn predefined() -> &'static [SeqTable; 3] {
    static T: OnceLock<[SeqTable; 3]> = OnceLock::new();
    T.get_or_init(|| {
        let mk = |norm: &[i16], log: u32, k: usize| {
            let (b, x, m) = KINDS[k];
            SeqTable::from_fse(&DTable::build(norm, log).expect("predefined table"), b, x, m).expect("predefined table")
        };
        [mk(&LL_NORM, 6, 0), mk(&OF_NORM, 5, 1), mk(&ML_NORM, 6, 2)]
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St {
    /// Before a frame (or between frames: `seen` frames so far).
    Frame,
    Skip(u32),
    Block,
    Checksum,
}

/// A loaded dictionary: its id (0 for raw content), entropy tables and repeat offsets (for
/// formatted dictionaries), and content.
#[derive(Clone, Debug, Default)]
pub(crate) struct Dict {
    pub(crate) id: u32,
    huf: Option<HufTable>,
    tables: Option<[SeqTable; 3]>,
    reps: [u32; 3],
    pub(crate) content: Vec<u8>,
}

impl Dict {
    /// A zstd dictionary (magic, id, entropy tables, repeat offsets, content) or, without the
    /// magic, raw content.
    pub(crate) fn parse(d: &[u8]) -> Result<Dict, Error> {
        if d.len() < 8 || u32::from_le_bytes([d[0], d[1], d[2], d[3]]) != DICT_MAGIC {
            return Ok(Dict { id: 0, huf: None, tables: None, reps: [1, 4, 8], content: d.to_vec() });
        }
        let id = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
        let mut p = 8;
        let (huf, n) = HufTable::read(&d[p..])?;
        p += n;
        let mut tables: [SeqTable; 3] = Default::default();
        // order in the dictionary: offsets, match lengths, literal lengths
        for (i, (max, log)) in [(31usize, 8u32), (52, 9), (35, 9)].into_iter().enumerate() {
            let (norm, l, used) = read_ncount(&d[p..], max, log)?;
            let k = [1, 2, 0][i];
            let (b, x, m) = KINDS[k];
            tables[k] = SeqTable::from_fse(&DTable::build(&norm, l)?, b, x, m)?;
            p += used;
        }
        let r = d.get(p..p + 12).ok_or(bad("truncated dictionary"))?;
        let reps = [0, 4, 8].map(|o| u32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]));
        if reps.iter().any(|&x| x == 0 || x as usize > d.len()) {
            return Err(bad("invalid dictionary repeat offsets"));
        }
        Ok(Dict { id, huf: Some(huf), tables: Some(tables), reps, content: d[p + 12..].to_vec() })
    }
}

#[derive(Clone)]
pub(crate) struct ZstdDecoder {
    st: St,
    carry: Carry,
    pub(crate) win: Window,
    max_window: usize,
    frames: u32,
    // frame
    wsize: usize,
    frame_pos: u64,
    content_size: Option<u64>,
    checksum: bool,
    hash: Xxh64,
    dict_len: usize,
    // entropy state carried across blocks
    huf: Option<HufTable>,
    /// The sequence tables (literal lengths, offsets, match lengths) at 0, 512 and 1024, next
    /// states absolute (so one masked index reaches any of them), their accuracy logs, and
    /// whether each is set.
    seq: Box<[SeqE; 2048]>,
    logs: [u32; 3],
    have: [bool; 3],
    reps: [u32; 3],
    dicts: Vec<Dict>,
    /// The block's literals, then at least `WILD` bytes of slack.
    lits: Vec<u8>,
    nlits: usize,

    /// Bytes after the last frame that start no frame (ignored, as gzip trailing bytes are).
    trailing: bool,
    pub(crate) total_in: u64,
}


impl ZstdDecoder {
    pub(crate) fn new(limit: u64, max_window: usize) -> ZstdDecoder {
        ZstdDecoder {
            st: St::Frame,
            carry: Carry::default(),
            win: Window::new(limit),
            max_window,
            frames: 0,
            wsize: 0,
            frame_pos: 0,
            content_size: None,
            checksum: false,
            hash: Xxh64::default(),
            dict_len: 0,
            huf: None,
            seq: Box::new([SeqE::default(); 2048]),
            logs: [0; 3],
            have: [false; 3],
            reps: [1, 4, 8],
            dicts: Vec::new(),
            lits: Vec::new(),
            nlits: 0,
            trailing: false,
            total_in: 0,
        }
    }

    pub(crate) fn add_dict(&mut self, d: Dict) {
        self.dicts.retain(|x| x.id != d.id);
        self.dicts.push(d);
    }

    /// At a frame boundary after at least one frame.
    pub(crate) fn is_done(&self) -> bool {
        self.frames > 0 && self.st == St::Frame
    }

    pub(crate) fn carried(&self) -> usize {
        self.carry.buf.len()
    }

    pub(crate) fn run(&mut self, input: &[u8]) -> Result<Flow, Error> {
        self.total_in += input.len() as u64;
        let mut carry = std::mem::take(&mut self.carry);
        let r = carry.run(input, |buf| {
            let mut pos = 0;
            let r = loop {
                if self.win.buf.len() >= self.win.stop() {
                    break Ok(Flow::Full);
                }
                match self.step(&buf[pos..]) {
                    Ok(Some(n)) => pos += n,
                    Ok(None) => break Ok(if self.is_done() && buf.len() == pos { Flow::Done } else { Flow::Need }),
                    Err(e) => break Err(e),
                }
                if self.trailing {
                    // bytes after the last frame that start no frame: ignored
                    pos = buf.len();
                    break Ok(Flow::Done);
                }
            };
            (pos, r)
        });
        self.carry = carry;
        r
    }

    /// One unit: `Some(bytes used)`, or `None` when it isn't all there yet.
    fn step(&mut self, b: &[u8]) -> Result<Option<usize>, Error> {
        match self.st {
            St::Frame => self.frame_header(b),
            St::Skip(left) => {
                let n = (left as usize).min(b.len());
                if n == 0 {
                    return Ok(None);
                }
                self.st = if n as u32 == left { St::Frame } else { St::Skip(left - n as u32) };
                Ok(Some(n))
            }
            St::Block => {
                if b.len() < 3 {
                    return Ok(None);
                }
                let h = u32::from_le_bytes([b[0], b[1], b[2], 0]);
                let last = h & 1 == 1;
                let ty = (h >> 1) & 3;
                let size = (h >> 3) as usize;
                let max = BLOCK_MAX.min(self.wsize.max(1));
                let need = match ty {
                    0 => size,
                    1 => 1,
                    2 => size,
                    _ => return Err(bad("reserved block type")),
                };
                if (ty != 1 && size > max) || (ty == 1 && size > BLOCK_MAX) {
                    return Err(bad("block larger than allowed"));
                }
                if b.len() < 3 + need {
                    return Ok(None);
                }
                let start = self.win.buf.len();
                let body = &b[3..3 + need];
                match ty {
                    0 => self.win.buf.extend_from_slice(body),
                    1 => self.win.buf.resize(start + size, body[0]),
                    _ => self.compressed(body)?,
                }
                let produced = self.win.buf.len() - start;
                if self.checksum {
                    self.hash.update(&self.win.buf[start..]);
                }
                self.frame_pos += produced as u64;
                self.win.check()?;
                if last {
                    if let Some(cs) = self.content_size {
                        if cs != self.frame_pos {
                            return Err(Error::new(ErrorKind::Checksum, "zstd content size mismatch"));
                        }
                    }
                    if self.checksum {
                        self.st = St::Checksum;
                    } else {
                        self.end_frame();
                    }
                }
                Ok(Some(3 + need))
            }
            St::Checksum => {
                if b.len() < 4 {
                    return Ok(None);
                }
                let want = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                if want != self.hash.digest() as u32 {
                    return Err(Error::new(ErrorKind::Checksum, "zstd checksum mismatch"));
                }
                self.end_frame();
                Ok(Some(4))
            }
        }
    }

    fn end_frame(&mut self) {
        self.frames += 1;
        self.st = St::Frame;
    }

    fn frame_header(&mut self, b: &[u8]) -> Result<Option<usize>, Error> {
        if b.len() < 4 {
            if self.frames > 0 && !b.is_empty() && b[0] != 0x28 && b[0] & 0xF0 != 0x50 {
                self.trailing = true;
            }
            return Ok(None);
        }
        let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            if b.len() < 8 {
                return Ok(None);
            }
            self.st = St::Skip(u32::from_le_bytes([b[4], b[5], b[6], b[7]]));
            if let St::Skip(0) = self.st {
                self.st = St::Frame;
            }
            return Ok(Some(8));
        }
        if magic != MAGIC {
            if self.frames > 0 {
                self.trailing = true;
                return Ok(None);
            }
            return Err(bad("not zstd data"));
        }
        if b.len() < 5 {
            return Ok(None);
        }
        let fhd = b[4];
        let fcs_flag = fhd >> 6;
        let single = fhd & 0x20 != 0;
        if fhd & 0x08 != 0 {
            return Err(bad("reserved frame header bit set"));
        }
        let checksum = fhd & 0x04 != 0;
        let did_len = [0, 1, 2, 4][(fhd & 3) as usize];
        let fcs_len = match fcs_flag {
            0 => single as usize,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let len = 5 + (!single) as usize + did_len + fcs_len;
        if b.len() < len {
            return Ok(None);
        }
        let mut p = 5;
        let mut wsize = 0u64;
        if !single {
            let wd = b[p];
            p += 1;
            let log = 10 + (wd >> 3) as u32;
            let base = 1u64 << log;
            wsize = base + (base / 8) * (wd & 7) as u64;
        }
        let mut did = 0u32;
        for i in 0..did_len {
            did |= (b[p + i] as u32) << (8 * i);
        }
        p += did_len;
        let mut fcs = None;
        if fcs_len > 0 {
            let mut v = 0u64;
            for i in 0..fcs_len {
                v |= (b[p + i] as u64) << (8 * i);
            }
            if fcs_len == 2 {
                v += 256;
            }
            fcs = Some(v);
        }
        if single {
            wsize = fcs.unwrap_or(0);
        }
        if wsize > self.max_window as u64 {
            return Err(Error::new(ErrorKind::LimitExceeded, "zstd window larger than allowed"));
        }
        self.wsize = wsize as usize;
        self.content_size = fcs;
        self.checksum = checksum;
        self.hash = Xxh64::default();
        self.frame_pos = 0;
        self.huf = None;
        self.have = [false; 3];
        self.reps = [1, 4, 8];
        self.dict_len = 0;
        if did != 0 || (!self.dicts.is_empty() && self.dicts.iter().any(|d| d.id == 0)) {
            let i = self.dicts.iter().position(|d| d.id == did).ok_or(Error::new(ErrorKind::Invalid, "zstd dictionary not available"))?;
            self.huf = self.dicts[i].huf.clone();
            self.reps = self.dicts[i].reps;
            if let Some(t) = self.dicts[i].tables.clone() {
                for (k, t) in t.iter().enumerate() {
                    self.install(k, t);
                }
                self.have = [true; 3];
            }
            // the dictionary content is history before the frame, never handed out
            self.win.check()?;
            debug_assert!(!self.win.has_pending());
            let d = &self.dicts[i];
            self.win.buf.extend_from_slice(&d.content);
            self.win.flushed = self.win.buf.len();
            self.dict_len = d.content.len();
        }
        self.win.hist = self.wsize.max(self.dict_len).max(1);
        if let Some(cs) = fcs {
            // room for the declared content (bounded: the declaration is not trusted)
            let room = self.win.stop().saturating_sub(self.win.buf.len()).min(cs as usize).min(self.win.limit.saturating_sub(self.win.total_out) as usize).min(16 << 20);
            self.win.buf.reserve(room);
        }
        self.st = St::Block;
        Ok(Some(len))
    }

    fn compressed(&mut self, b: &[u8]) -> Result<(), Error> {
        let used = self.literals(b)?;
        self.sequences(&b[used..])
    }

    /// The literals section into `self.lits`; returns its size.
    fn literals(&mut self, b: &[u8]) -> Result<usize, Error> {
        let h0 = *b.first().ok_or(bad("truncated literals"))?;
        let ty = h0 & 3;
        let sf = (h0 >> 2) & 3;
        if self.lits.len() < BLOCK_MAX + WILD {
            self.lits.resize(BLOCK_MAX + WILD, 0);
        }
        if ty < 2 {
            let (hl, regen) = match sf {
                0 | 2 => (1, (h0 >> 3) as usize),
                1 => (2, (h0 as usize >> 4) | ((*b.get(1).ok_or(bad("truncated literals"))? as usize) << 4)),
                _ => {
                    let x = b.get(..3).ok_or(bad("truncated literals"))?;
                    (3, (x[0] as usize >> 4) | (x[1] as usize) << 4 | (x[2] as usize) << 12)
                }
            };
            if regen > BLOCK_MAX {
                return Err(bad("too many literals"));
            }
            self.nlits = regen;
            if ty == 0 {
                let d = b.get(hl..hl + regen).ok_or(bad("truncated literals"))?;
                self.lits[..regen].copy_from_slice(d);
                return Ok(hl + regen);
            }
            let v = *b.get(hl).ok_or(bad("truncated literals"))?;
            self.lits[..regen].fill(v);
            return Ok(hl + 1);
        }
        let (hl, bits, streams) = match sf {
            0 => (3, 10, 1),
            1 => (3, 10, 4),
            2 => (4, 14, 4),
            _ => (5, 18, 4),
        };
        let x = b.get(..hl).ok_or(bad("truncated literals"))?;
        let mut v = 0u64;
        for (i, &y) in x.iter().enumerate() {
            v |= (y as u64) << (8 * i);
        }
        let regen = ((v >> 4) & ((1 << bits) - 1)) as usize;
        let comp = ((v >> (4 + bits)) & ((1 << bits) - 1)) as usize;
        if regen > BLOCK_MAX {
            return Err(bad("too many literals"));
        }
        let mut d = b.get(hl..hl + comp).ok_or(bad("truncated literals"))?;
        if ty == 2 {
            let (t, n) = HufTable::read(d)?;
            self.huf = Some(t);
            d = &d[n..];
        }
        let huf = self.huf.as_ref().ok_or(bad("treeless literals without a previous tree"))?;
        let out = &mut self.lits[..regen];
        if streams == 4 {
            huf.decode4(d, out)?;
        } else {
            huf.decode1(d, out)?;
        }
        self.nlits = regen;
        Ok(hl + comp)
    }

    fn sequences(&mut self, b: &[u8]) -> Result<(), Error> {
        let b0 = *b.first().ok_or(bad("truncated sequences"))? as usize;
        let (n, mut p) = if b0 == 0 {
            (0, 1)
        } else if b0 < 128 {
            (b0, 1)
        } else if b0 < 255 {
            (((b0 - 128) << 8) + *b.get(1).ok_or(bad("truncated sequences"))? as usize, 2)
        } else {
            let x = b.get(1..3).ok_or(bad("truncated sequences"))?;
            (x[0] as usize + ((x[1] as usize) << 8) + 0x7F00, 3)
        };
        let nl = self.nlits;
        if n == 0 {
            if p != b.len() {
                return Err(bad("trailing bytes after the sequences"));
            }
            self.win.buf.extend_from_slice(&self.lits[..nl]);
            return Ok(());
        }
        let modes = *b.get(p).ok_or(bad("truncated sequences"))?;
        p += 1;
        if modes & 3 != 0 {
            return Err(bad("reserved sequence mode bits set"));
        }
        // literal lengths, offsets, match lengths
        let maxlog = [9u32, 8, 9];
        for (i, mode) in [modes >> 6, modes >> 4 & 3, modes >> 2 & 3].into_iter().enumerate() {
            let (base, bits, max) = KINDS[i];
            match mode {
                0 => self.install(i, &predefined()[i]),
                1 => {
                    let s = *b.get(p).ok_or(bad("truncated sequences"))?;
                    p += 1;
                    if s as usize > max {
                        return Err(bad("RLE symbol out of range"));
                    }
                    self.install(i, &SeqTable::from_fse(&DTable::rle(s), base, bits, max)?);
                }
                2 => {
                    let (norm, log, used) = read_ncount(b.get(p..).unwrap_or(&[]), max, maxlog[i])?;
                    p += used;
                    self.install(i, &SeqTable::from_fse(&DTable::build(&norm, log)?, base, bits, max)?);
                }
                _ => {
                    if !self.have[i] {
                        return Err(bad("repeated table without a previous one"));
                    }
                }
            }
            self.have[i] = true;
        }
        let start = self.win.buf.len();
        // room for the most a block can produce (less when the frame's content size says so)
        let mut room = BLOCK_MAX;
        if let Some(cs) = self.content_size {
            room = room.min(cs.saturating_sub(self.frame_pos) as usize);
        }
        let mut buf = std::mem::take(&mut self.win.buf);
        buf.resize(start + room + WILD, 0);
        let seqs = b.get(p..).unwrap_or(&[]);
        let r = self.execute(seqs, n, &mut buf[..], start);
        match r {
            Ok(end) => buf.truncate(end),
            Err(_) => buf.truncate(start),
        }
        self.win.buf = buf;
        r.map(|_| ())
    }

    /// Puts table `t` in place `k` of the combined table.
    fn install(&mut self, k: usize, t: &SeqTable) {
        let at = 512 * k;
        for (o, e) in self.seq[at..at + t.t.len()].iter_mut().zip(&t.t) {
            *o = SeqE { next: e.next + at as u16, ..*e };
        }
        self.logs[k] = t.log;
    }

    /// Decodes and executes the `n` sequences of `b` (after the table modes) into `buf` from
    /// `start` on (the room after `start`, less `WILD` bytes of slack, is what the block may
    /// produce). Returns the output's end.
    fn execute(&mut self, b: &[u8], n: usize, buf: &mut [u8], start: usize) -> Result<usize, Error> {
        if b.len() >= 8 && b[b.len() - 1] != 0 && simoom_sys::codec::fast() {
            return self.execute_fast(b, n, buf, start);
        }
        self.execute_safe(b, n, buf, start)
    }

    /// The pointer-code loop in simoom-sys (same results as [`ZstdDecoder::execute_safe`]).
    fn execute_fast(&mut self, b: &[u8], n: usize, buf: &mut [u8], start: usize) -> Result<usize, Error> {
        use simoom_sys::codec::{zstd_sequences, SeqError, Sequences};
        let nl = self.nlits;
        let r = zstd_sequences(Sequences {
            table: &self.seq,
            logs: self.logs,
            bits: b,
            n,
            lits: &self.lits[..nl + WILD],
            out: buf,
            start,
            reps: self.reps,
            wmax: self.wsize.max(self.dict_len),
            hist: (self.frame_pos as usize + self.dict_len).wrapping_sub(start),
        });
        let (op, lp, reps) = r.map_err(|e| {
            bad(match e {
                SeqError::Literals => "literal length past the literals",
                SeqError::ZeroOffset => "zero repeat offset",
                SeqError::Window => "offset beyond the window",
                SeqError::Size => "block decodes to more than 128 KiB",
                SeqError::Bitstream => "sequence bitstream not fully used",
            })
        })?;
        let rest = nl - lp;
        let lim = buf.len() - WILD;
        if op + rest > lim {
            return Err(bad("block decodes to more than 128 KiB"));
        }
        buf[op..op + rest].copy_from_slice(&self.lits[lp..nl]);
        self.reps = reps;
        Ok(op + rest)
    }

    /// The safe reference implementation of the sequence loop.
    // (the last sequence's state updates are skipped, leaving assignments unread)
    #[allow(unused_assignments)]
    fn execute_safe(&mut self, b: &[u8], n: usize, buf: &mut [u8], start: usize) -> Result<usize, Error> {
        let t = &*self.seq;
        let mut br = Bits::new(b)?;
        br.reload();
        let mut s_ll = br.read(self.logs[0]) as usize;
        let mut s_of = 512 + br.read(self.logs[1]) as usize;
        let mut s_ml = 1024 + br.read(self.logs[2]) as usize;
        br.reload();
        let mut reps = self.reps;
        let wmax = self.wsize.max(self.dict_len);
        // an offset must reach no further back than the history before the block plus what the
        // block produced so far: `off <= hist + op`, with `hist` relative to `start`
        let hist = (self.frame_pos as usize + self.dict_len).wrapping_sub(start);
        // the literals not used yet, then `WILD` bytes of slack
        let mut lits = &self.lits[..self.nlits + WILD];
        let mut op = start;
        // the output's limit
        let lim = buf.len() - WILD;
        // One sequence. Bits between reloads: offset (<= 31) and match length (<= 16) extra bits,
        // then a reload if the three extras take 31 or more, then the literal length extra
        // (<= 16) and the three state updates (<= 26), as zstd's ZSTD_decodeSequence.
        macro_rules! sequence {
            ($update:expr) => {{
                let ll_e = t[s_ll & 2047];
                let of_e = t[s_of & 2047];
                let ml_e = t[s_ml & 2047];
                let ofb = br.read(of_e.add as u32) as u32;
                let ml = (ml_e.base + br.read(ml_e.add as u32) as u32) as usize;
                if of_e.add as u32 + ml_e.add as u32 + ll_e.add as u32 >= 31 {
                    br.reload();
                }
                let ll = (ll_e.base + br.read(ll_e.add as u32) as u32) as usize;
                if $update {
                    s_ll = ll_e.next as usize + br.read(ll_e.nbits as u32) as usize;
                    s_ml = ml_e.next as usize + br.read(ml_e.nbits as u32) as usize;
                    s_of = of_e.next as usize + br.read(of_e.nbits as u32) as usize;
                    br.reload();
                }
                // repeat offsets (section 3.1.1.5)
                let off = if of_e.add > 1 {
                    let o = of_e.base + ofb;
                    reps = [o, reps[0], reps[1]];
                    o
                } else {
                    // 1 to 3 are the repeat offsets, shifted by one when there are no literals
                    let v = of_e.base + ofb + (ll == 0) as u32;
                    let o = match v {
                        1 => reps[0],
                        2 => reps[1],
                        3 => reps[2],
                        _ => reps[0].wrapping_sub(1),
                    };
                    if v != 1 {
                        reps = [o, reps[0], if v == 2 { reps[2] } else { reps[1] }];
                    }
                    o
                } as usize;
                let end = op + ll + ml;
                if (ll + WILD > lits.len()) | (end > lim) | (off.wrapping_sub(1) >= wmax) | (off > hist.wrapping_add(op + ll)) {
                    return Err(if ll + WILD > lits.len() {
                        bad("literal length past the literals")
                    } else if off == 0 {
                        bad("zero repeat offset")
                    } else if off > wmax || off > hist.wrapping_add(op + ll) {
                        bad("offset beyond the window")
                    } else {
                        bad("block decodes to more than 128 KiB")
                    });
                }
                // literals, 16 bytes at a time (the first copy also when there are none)
                buf[op..op + 16].copy_from_slice(&lits[..16]);
                let mut i = 16;
                while i < ll {
                    buf[op + i..op + i + 16].copy_from_slice(&lits[i..i + 16]);
                    i += 16;
                }
                lits = &lits[ll..];
                copy_match(buf, op + ll, off, ml);
                op = end;
            }};
        }
        for _ in 1..n {
            sequence!(true);
        }
        sequence!(false);
        if !br.finished() {
            return Err(bad("sequence bitstream not fully used"));
        }
        let rest = lits.len() - WILD;
        if op + rest > lim {
            return Err(bad("block decodes to more than 128 KiB"));
        }
        buf[op..op + rest].copy_from_slice(&lits[..rest]);
        self.reps = reps;
        Ok(op + rest)
    }
}

/// Copies `ml` (at least 3) bytes from `off` back to `buf[op..]`, overlapping allowed, in 8 or
/// 16 byte steps (zstd's `ZSTD_execSequence`); may write up to 15 bytes past the end of the
/// match (the caller leaves `WILD` bytes of slack).
#[inline(always)]
fn copy_match(buf: &mut [u8], op: usize, off: usize, ml: usize) {
    let end = op + ml;
    if off >= 16 {
        // one bounds check for the whole match: the window from the source to the end (and
        // slack); in it the source starts at 0 and the destination at `off`
        let w = &mut buf[op - off..end + 16];
        let mut k = 0;
        loop {
            w.copy_within(k..k + 16, off + k);
            k += 16;
            if k >= ml {
                break;
            }
        }
    } else if off == 1 {
        let b = buf[op - 1];
        buf[op..end].fill(b);
    } else {
        // spread the first 8 bytes so the distance becomes at least 8 (a multiple of `off`)
        let mut d = op;
        let mut s;
        if off < 8 {
            const D32: [usize; 8] = [0, 1, 2, 1, 4, 4, 4, 4];
            const D64: [usize; 8] = [8, 8, 8, 7, 8, 9, 10, 11];
            s = op - off;
            buf[d] = buf[s];
            buf[d + 1] = buf[s + 1];
            buf[d + 2] = buf[s + 2];
            buf[d + 3] = buf[s + 3];
            s += D32[off];
            buf.copy_within(s..s + 4, d + 4);
            d += 8;
            s = d - (off - D32[off] + D64[off]);
        } else {
            s = op - off;
            buf.copy_within(s..s + 8, d);
            d += 8;
            s += 8;
        }
        while d < end {
            buf.copy_within(s..s + 8, d);
            d += 8;
            s += 8;
        }
    }
}
