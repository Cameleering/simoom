//! Finite State Entropy (RFC 8878 section 4.1) and the bitstreams around it, plus the Huffman
//! literal code (section 4.2).

use crate::Error;

fn bad(msg: &'static str) -> Error {
    Error::invalid(msg)
}

#[inline(always)]
pub(crate) fn highbit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

// ---------------------------------------------------------------------------------------------
// Bitstreams
// ---------------------------------------------------------------------------------------------

/// Reads a backward bitstream (FSE and Huffman payloads): the last byte holds a 1-bit end
/// marker; reads go from there towards the start, and `read(n)` returns the `n` bits just
/// below the current position. Reading past the start yields zeros and sets `overflow`.
pub(crate) struct BackReader<'a> {
    buf: &'a [u8],
    /// Bits left before the start.
    pos: i64,
}

impl<'a> BackReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Result<BackReader<'a>, Error> {
        let last = *buf.last().ok_or(bad("empty bitstream"))?;
        if last == 0 {
            return Err(bad("bitstream without end marker"));
        }
        let pos = (buf.len() as i64) * 8 - 8 + highbit(last as u32) as i64;
        Ok(BackReader { buf, pos })
    }

    #[inline(always)]
    fn word(&self, bit: i64) -> u64 {
        // the 64 bits starting at `bit` (which may be negative: bits before the start are 0)
        if bit >= 0 {
            let b = (bit >> 3) as usize;
            let sh = (bit & 7) as u32;
            let v = if let Some(w) = self.buf.get(b..b + 8) {
                u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]])
            } else {
                let mut t = [0u8; 8];
                let rest = &self.buf[b.min(self.buf.len())..];
                t[..rest.len()].copy_from_slice(rest);
                u64::from_le_bytes(t)
            };
            v >> sh
        } else if bit > -64 {
            self.word(0) << ((-bit) as u32)
        } else {
            0
        }
    }

    /// The next `n` (at most 56) bits.
    #[inline(always)]
    pub(crate) fn read(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        self.pos -= n as i64;
        self.word(self.pos) & ((1u64 << n) - 1)
    }

    pub(crate) fn overflow(&self) -> bool {
        self.pos < 0
    }

    #[cfg(test)]
    pub(crate) fn finished(&self) -> bool {
        self.pos == 0
    }
}

/// The fast backward bitstream reader of the hot loops (sequences, Huffman literals): a 64-bit
/// container refilled from the byte before the bits consumed, as zstd's `BIT_DStream`. Reads
/// between two `reload`s must total at most 56 bits. Reading past the start never panics: the
/// bits are garbage, and `finished` (checked at the end) fails.
#[derive(Clone, Copy)]
pub(crate) struct Bits<'a> {
    buf: &'a [u8],
    /// Start of the 8 bytes in `c` (0 for streams shorter than 8 bytes).
    ptr: usize,
    c: u64,
    /// Bits of `c` consumed, from the top.
    pub(crate) used: u32,
}

impl<'a> Bits<'a> {
    /// The reader at byte `ptr` (`buf.len() >= 8`) with `used` bits of those 8 bytes consumed.
    fn at(buf: &'a [u8], ptr: usize, used: u32) -> Bits<'a> {
        Bits { buf, ptr, c: load64(buf, ptr), used }
    }

    pub(crate) fn new(buf: &'a [u8]) -> Result<Bits<'a>, Error> {
        let last = *buf.last().ok_or(bad("empty bitstream"))?;
        if last == 0 {
            return Err(bad("bitstream without end marker"));
        }
        let used = 8 - highbit(last as u32);
        if buf.len() >= 8 {
            let ptr = buf.len() - 8;
            Ok(Bits { buf, ptr, c: load64(buf, ptr), used })
        } else {
            let mut c = 0u64;
            for (i, &b) in buf.iter().enumerate() {
                c |= (b as u64) << (8 * i);
            }
            Ok(Bits { buf, ptr: 0, c, used: used + 8 * (8 - buf.len() as u32) })
        }
    }

    /// Refills the container: afterwards at least 57 bits can be read, unless the stream is
    /// near its start.
    #[inline(always)]
    pub(crate) fn reload(&mut self) {
        let step = (self.used >> 3) as usize;
        if step <= self.ptr {
            self.ptr -= step;
            self.used &= 7;
        } else {
            self.used -= 8 * self.ptr as u32;
            self.ptr = 0;
        }
        if let Some(w) = self.buf[self.ptr..].first_chunk::<8>() {
            self.c = u64::from_le_bytes(*w);
        }
    }

    /// The next `n` (at most 56) bits, not consumed.
    #[inline(always)]
    pub(crate) fn look(&self, n: u32) -> u64 {
        (self.c << (self.used & 63)) >> 1 >> (63 - n)
    }

    #[inline(always)]
    pub(crate) fn read(&mut self, n: u32) -> u64 {
        let v = self.look(n);
        self.used += n;
        v
    }

    /// One Huffman symbol through an 11-bit table.
    #[inline(always)]
    pub(crate) fn huf(&mut self, t: &[u16; 2048]) -> u8 {
        let e = t[((self.c << (self.used & 63)) >> 53) as usize];
        self.used += (e & 0xFF) as u32;
        (e >> 8) as u8
    }

    /// Every bit was read, and no more.
    pub(crate) fn finished(&self) -> bool {
        self.ptr == 0 && self.used == 64
    }
}

#[inline(always)]
fn load64(b: &[u8], at: usize) -> u64 {
    let w = &b[at..at + 8];
    u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]])
}

/// Writes LSB-first; `close` adds the end marker of a backward bitstream. Bytes go into a
/// buffer kept 8 bytes longer than what is written, so whole words are stored at once.
#[derive(Default)]
pub(crate) struct BitWriter {
    buf: Vec<u8>,
    pos: usize,
    acc: u64,
    n: u32,
}

impl BitWriter {
    pub(crate) fn with_capacity(n: usize) -> BitWriter {
        BitWriter { buf: vec![0; n + 8], pos: 0, acc: 0, n: 0 }
    }

    /// The bytes written out so far.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    #[inline(always)]
    pub(crate) fn put(&mut self, v: u64, bits: u32) {
        self.add(v, bits);
        if self.n >= 32 {
            self.flush_bytes();
        }
    }

    /// Adds bits without writing any out: the caller keeps the pending bits under 64 and calls
    /// [`BitWriter::flush_bytes`] (zstd's `BIT_addBits`).
    #[inline(always)]
    pub(crate) fn add(&mut self, v: u64, bits: u32) {
        self.acc |= (v & ((1u64 << bits) - 1)) << self.n;
        self.n += bits;
    }

    /// Bits added and not written out yet.
    #[inline(always)]
    pub(crate) fn pending(&self) -> u32 {
        self.n
    }

    /// Writes out the whole bytes pending (at most 7 bits stay).
    #[inline(always)]
    pub(crate) fn flush_bytes(&mut self) {
        if self.pos + 8 > self.buf.len() {
            self.grow();
        }
        self.buf[self.pos..self.pos + 8].copy_from_slice(&self.acc.to_le_bytes());
        let k = self.n >> 3;
        self.pos += k as usize;
        self.acc >>= 8 * k;
        self.n &= 7;
    }

    #[cold]
    fn grow(&mut self) {
        self.buf.resize(2 * self.buf.len() + 64, 0);
    }

    /// Writes the remaining bits, padding the last byte with zeros.
    pub(crate) fn align(&mut self) {
        self.n = (self.n + 7) & !7;
        self.flush_bytes();
        self.acc = 0;
    }

    pub(crate) fn close(mut self) -> Vec<u8> {
        self.put(1, 1);
        self.align();
        self.into_vec()
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        self.buf.truncate(self.pos);
        self.buf
    }
}

// ---------------------------------------------------------------------------------------------
// Distributions
// ---------------------------------------------------------------------------------------------

/// Reads an FSE table description (section 4.1.1). Returns the normalized counts, the
/// accuracy log and the bytes used.
pub(crate) fn read_ncount(src: &[u8], max_symbol: usize, max_log: u32) -> Result<(Vec<i16>, u32, usize), Error> {
    let mut pos = 0usize; // bits
    let bit = |pos: usize, n: u32| -> Result<u32, Error> {
        let b = pos >> 3;
        let mut t = [0u8; 8];
        let rest = src.get(b..).unwrap_or(&[]);
        let k = rest.len().min(8);
        t[..k].copy_from_slice(&rest[..k]);
        if pos + n as usize > src.len() * 8 {
            return Err(bad("truncated FSE table description"));
        }
        Ok(((u64::from_le_bytes(t) >> (pos & 7)) & ((1u64 << n) - 1)) as u32)
    };
    let log = bit(pos, 4)? + 5;
    pos += 4;
    if log > max_log {
        return Err(bad("FSE accuracy log too large"));
    }
    let mut norm = Vec::with_capacity(max_symbol + 1);
    let mut remaining: i32 = (1 << log) + 1;
    let mut threshold: i32 = 1 << log;
    let mut nbits = log + 1;
    while remaining > 1 {
        if norm.len() > max_symbol {
            return Err(bad("FSE table description has too many symbols"));
        }
        let max = (2 * threshold - 1) - remaining;
        let low = bit(pos, nbits - 1)? as i32;
        let v = if low < max {
            pos += nbits as usize - 1;
            low
        } else {
            let mut v = bit(pos, nbits)? as i32;
            if v >= threshold {
                v -= max;
            }
            pos += nbits as usize;
            v
        };
        let count = v - 1;
        remaining -= count.abs();
        norm.push(count as i16);
        if count == 0 {
            loop {
                let r = bit(pos, 2)?;
                pos += 2;
                for _ in 0..r {
                    norm.push(0);
                }
                if r != 3 {
                    break;
                }
            }
            if norm.len() > max_symbol + 1 {
                return Err(bad("FSE table description has too many symbols"));
            }
        }
        while remaining < threshold && threshold > 1 {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 {
        return Err(bad("invalid FSE table description"));
    }
    Ok((norm, log, pos.div_ceil(8)))
}

/// Writes an FSE table description for `norm` (whose last entry must be non-zero).
pub(crate) fn write_ncount(w: &mut BitWriter, norm: &[i16], log: u32) {
    w.put((log - 5) as u64, 4);
    let mut remaining: i32 = (1 << log) + 1;
    let mut threshold: i32 = 1 << log;
    let mut nbits = log + 1;
    let mut s = 0usize;
    let mut prev0 = false;
    while s < norm.len() && remaining > 1 {
        if prev0 {
            let start = s;
            while s < norm.len() && norm[s] == 0 {
                s += 1;
            }
            let mut rep = s - start;
            while rep >= 3 {
                w.put(3, 2);
                rep -= 3;
            }
            w.put(rep as u64, 2);
            if s >= norm.len() {
                break;
            }
        }
        let count = norm[s] as i32;
        s += 1;
        let max = (2 * threshold - 1) - remaining;
        remaining -= count.abs();
        let mut v = count + 1;
        if v >= threshold {
            v += max;
        }
        w.put(v as u64, if v < max { nbits - 1 } else { nbits });
        prev0 = count == 0;
        while remaining < threshold && threshold > 1 {
            nbits -= 1;
            threshold >>= 1;
        }
    }
}

/// Normalizes `counts` (total `total`) to sum to `1 << log`; symbols seen rarely get -1 (a
/// "less than one" probability).
pub(crate) fn normalize(counts: &[u32], total: u32, log: u32) -> Vec<i16> {
    let size = 1i64 << log;
    let mut norm = vec![0i16; counts.len()];
    let mut sum: i64 = 0;
    let mut largest = 0;
    for (s, &c) in counts.iter().enumerate() {
        if c == 0 {
            continue;
        }
        let p = (c as i64 * size) / total as i64;
        if p == 0 {
            norm[s] = -1;
            sum += 1;
        } else {
            // round to nearest
            let rem = (c as i64 * size) % total as i64;
            let p = if rem * 2 >= total as i64 { p + 1 } else { p };
            norm[s] = p as i16;
            sum += p;
        }
        if c > counts[largest] {
            largest = s;
        }
    }
    let mut diff = size - sum;
    if diff >= 0 {
        norm[largest] += diff as i16;
        return norm;
    }
    // too many slots handed out: take them back from the most probable symbols
    while diff < 0 {
        let mut best = None;
        for (s, &n) in norm.iter().enumerate() {
            if n > 1 && best.is_none_or(|b: usize| n > norm[b]) {
                best = Some(s);
            }
        }
        let Some(b) = best else { break };
        let take = ((-diff) as i16).min(norm[b] - 1).max(1);
        norm[b] -= take;
        diff += take as i64;
    }
    norm
}

// ---------------------------------------------------------------------------------------------
// Decoding tables
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct DEntry {
    pub(crate) symbol: u8,
    pub(crate) nbits: u8,
    pub(crate) base: u16,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DTable {
    pub(crate) log: u32,
    pub(crate) t: Vec<DEntry>,
}

impl DTable {
    pub(crate) fn rle(symbol: u8) -> DTable {
        DTable { log: 0, t: vec![DEntry { symbol, nbits: 0, base: 0 }] }
    }

    pub(crate) fn build(norm: &[i16], log: u32) -> Result<DTable, Error> {
        let size = 1usize << log;
        let mut t = vec![DEntry::default(); size];
        let mut high = size - 1;
        let mut next = vec![0u32; norm.len()];
        for (s, &n) in norm.iter().enumerate() {
            if n == -1 {
                t[high].symbol = s as u8;
                high = high.wrapping_sub(1);
                next[s] = 1;
            } else if n > 0 {
                next[s] = n as u32;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut p = 0usize;
        for (s, &n) in norm.iter().enumerate() {
            for _ in 0..n.max(0) {
                t[p].symbol = s as u8;
                loop {
                    p = (p + step) & mask;
                    if high == usize::MAX || p <= high {
                        break;
                    }
                }
            }
        }
        if p != 0 {
            return Err(bad("FSE distribution does not fill the table"));
        }
        for e in t.iter_mut() {
            let s = e.symbol as usize;
            let x = next[s];
            next[s] += 1;
            let nb = log - highbit(x);
            e.nbits = nb as u8;
            e.base = ((x << nb) as usize - size) as u16;
        }
        Ok(DTable { log, t })
    }
}

/// A sequence decoding table: per state the code's base value and extra bits (folded in from
/// the code tables, as zstd's `ZSTD_seqSymbol`), and the next-state base and bits.
pub(crate) use simoom_sys::codec::SeqEntry as SeqE;

#[derive(Clone, Debug, Default)]
pub(crate) struct SeqTable {
    pub(crate) log: u32,
    pub(crate) t: Vec<SeqE>,
}

impl SeqTable {
    /// From an FSE table whose symbols are codes into `base`/`bits` (offsets: `base` empty,
    /// the code is the number of extra bits, and the base of codes 2 and up has the 3 of the
    /// repeat codes taken off, as zstd's `OF_base`).
    pub(crate) fn from_fse(dt: &DTable, base: &[u32], bits: &[u8], max: usize) -> Result<SeqTable, Error> {
        if dt.t.len() > 512 {
            return Err(bad("FSE table too large"));
        }
        let mut t = vec![SeqE::default(); dt.t.len()];
        for (o, e) in t.iter_mut().zip(&dt.t) {
            let s = e.symbol as usize;
            if s > max {
                return Err(bad("invalid sequence code"));
            }
            let (b, a) = if !base.is_empty() {
                (base[s], bits[s])
            } else if s > 1 {
                ((1u32 << s) - 3, s as u8)
            } else {
                (1u32 << s, s as u8)
            };
            *o = SeqE { base: b, add: a, nbits: e.nbits, next: e.base };
        }
        Ok(SeqTable { log: dt.log, t })
    }
}

// ---------------------------------------------------------------------------------------------
// Encoding tables
// ---------------------------------------------------------------------------------------------

use simoom_sys::codec::SymTT;

/// Fixed sizes (logs up to 9, symbols up to 63) let lookups mask instead of checking.
pub(crate) struct CTable {
    pub(crate) log: u32,
    states: Box<[u16; 512]>,
    tt: Box<[SymTT; 64]>,
}

impl CTable {
    pub(crate) fn build(norm: &[i16], log: u32) -> CTable {
        let size = 1usize << log;
        let mut cumul = vec![0u32; norm.len() + 1];
        let mut symbols = vec![0u8; size];
        let mut high = size - 1;
        for (s, &n) in norm.iter().enumerate() {
            if n == -1 {
                cumul[s + 1] = cumul[s] + 1;
                symbols[high] = s as u8;
                high = high.wrapping_sub(1);
            } else {
                cumul[s + 1] = cumul[s] + n.max(0) as u32;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut p = 0usize;
        for (s, &n) in norm.iter().enumerate() {
            for _ in 0..n.max(0) {
                symbols[p] = s as u8;
                loop {
                    p = (p + step) & mask;
                    if high == usize::MAX || p <= high {
                        break;
                    }
                }
            }
        }
        let mut states = Box::new([0u16; 512]);
        let mut c = cumul.clone();
        for (u, &s) in symbols.iter().enumerate() {
            let s = s as usize;
            states[c[s] as usize] = (size + u) as u16;
            c[s] += 1;
        }
        let mut tt = Box::new([SymTT::default(); 64]);
        let mut total: i32 = 0;
        for (s, &n) in norm.iter().enumerate() {
            match n {
                0 => tt[s].delta_nbits = ((log + 1) << 16) - (1 << log),
                -1 | 1 => {
                    tt[s].delta_nbits = (log << 16) - (1 << log);
                    tt[s].delta_find = total - 1;
                    total += 1;
                }
                n => {
                    let n = n as u32;
                    let max_out = log - highbit(n - 1);
                    let min_plus = n << max_out;
                    tt[s].delta_nbits = (max_out << 16).wrapping_sub(min_plus);
                    tt[s].delta_find = total - n as i32;
                    total += n as i32;
                }
            }
        }
        CTable { log, states, tt }
    }

    /// The table as the pointer-code writer takes it.
    pub(crate) fn enc(&self) -> simoom_sys::codec::FseEnc<'_> {
        simoom_sys::codec::FseEnc { states: &self.states, tt: &self.tt, log: self.log }
    }

    /// The table of a stream of one symbol (RLE mode): every symbol takes no bits.
    pub(crate) fn rle(s: u8, symbols: usize) -> CTable {
        let _ = (s, symbols);
        CTable { log: 0, states: Box::new([0; 512]), tt: Box::new([SymTT::default(); 64]) }
    }

    /// The first state, for the last symbol of the stream.
    pub(crate) fn init(&self, s: u8) -> u32 {
        let t = self.tt[s as usize & 63];
        let nb = (t.delta_nbits + (1 << 15)) >> 16;
        let v = (nb << 16).wrapping_sub(t.delta_nbits);
        self.states[((v >> nb) as i32 + t.delta_find) as usize & 511] as u32
    }

    /// As [`CTable::encode`], without writing out (see [`BitWriter::add`]).
    #[inline(always)]
    pub(crate) fn encode_add(&self, w: &mut BitWriter, state: &mut u32, s: u8) {
        let t = self.tt[s as usize & 63];
        let nb = (state.wrapping_add(t.delta_nbits)) >> 16;
        w.add(*state as u64, nb);
        *state = self.states[((*state >> nb) as i32 + t.delta_find) as usize & 511] as u32;
    }

    #[inline(always)]
    pub(crate) fn encode(&self, w: &mut BitWriter, state: &mut u32, s: u8) {
        let t = self.tt[s as usize & 63];
        let nb = (state.wrapping_add(t.delta_nbits)) >> 16;
        w.put(*state as u64, nb);
        *state = self.states[((*state >> nb) as i32 + t.delta_find) as usize & 511] as u32;
    }

    pub(crate) fn flush(&self, w: &mut BitWriter, state: u32) {
        w.put(state as u64, self.log);
    }

    /// Bits to code `counts` with this table, roughly (for choosing between tables).
    pub(crate) fn cost(norm: &[i16], log: u32, counts: &[u32]) -> Option<u64> {
        let mut bits = 0f64;
        for (s, &c) in counts.iter().enumerate() {
            if c == 0 {
                continue;
            }
            let n = *norm.get(s)?;
            if n == 0 {
                return None;
            }
            let p = if n == -1 { 1.0 } else { n as f64 };
            bits += c as f64 * (log as f64 - p.log2());
        }
        Some(bits as u64)
    }
}

// ---------------------------------------------------------------------------------------------
// Huffman literals (section 4.2)
// ---------------------------------------------------------------------------------------------

/// A Huffman decoding table indexed by the next 11 bits (the longest code zstd allows), entries
/// `symbol << 8 | bits`: shorter codes repeat, so every lookup shifts by a constant.
#[derive(Clone, Debug)]
pub(crate) struct HufTable {
    pub(crate) t: Box<[u16; 2048]>,
}

impl HufTable {
    /// From the weights of every symbol (the last one included); `max_bits` is the longest
    /// code (weights sum, as `2^(w-1)`, to `2^max_bits`).
    pub(crate) fn from_weights(w: &[u8], max_bits: u32) -> Result<HufTable, Error> {
        let max_w = *w.iter().max().unwrap_or(&0) as u32;
        if max_w == 0 || max_w > max_bits || max_bits > 11 {
            return Err(bad("invalid Huffman weights"));
        }
        let mut rank = [0usize; 13];
        let mut counts = [0usize; 13];
        for &x in w {
            counts[x as usize] += 1;
        }
        let mut next = 0;
        for x in 1..=max_w as usize {
            rank[x] = next;
            next += counts[x] << (x - 1);
        }
        if next != 1 << max_bits {
            return Err(bad("invalid Huffman weights"));
        }
        // in units of the 11-bit table
        let scale = 11 - max_bits;
        let mut t = Box::new([0u16; 2048]);
        for (s, &x) in w.iter().enumerate() {
            if x == 0 {
                continue;
            }
            let len = 1usize << (x as u32 - 1 + scale);
            let nb = (max_bits + 1 - x as u32) as u16;
            let at = rank[x as usize] << scale;
            t[at..at + len].fill((s as u16) << 8 | nb);
            rank[x as usize] += 1 << (x - 1);
        }
        Ok(HufTable { t })
    }

    /// Reads a tree description (section 4.2.1); returns the table and the bytes used.
    pub(crate) fn read(src: &[u8]) -> Result<(HufTable, usize), Error> {
        let h = *src.first().ok_or(bad("truncated Huffman tree"))? as usize;
        let mut w: Vec<u8>;
        let used;
        if h >= 128 {
            let n = h - 127;
            let bytes = n.div_ceil(2);
            let d = src.get(1..1 + bytes).ok_or(bad("truncated Huffman tree"))?;
            w = Vec::with_capacity(n + 1);
            for i in 0..n {
                w.push(if i % 2 == 0 { d[i / 2] >> 4 } else { d[i / 2] & 15 });
            }
            used = 1 + bytes;
        } else {
            let d = src.get(1..1 + h).ok_or(bad("truncated Huffman tree"))?;
            let (norm, log, hdr) = read_ncount(d, 255, 6)?;
            let table = DTable::build(&norm, log)?;
            let mut br = BackReader::new(&d[hdr..])?;
            let mut s1 = br.read(log) as usize;
            let mut s2 = br.read(log) as usize;
            w = Vec::new();
            loop {
                if w.len() > 254 {
                    return Err(bad("too many Huffman weights"));
                }
                let e = table.t[s1];
                w.push(e.symbol);
                s1 = e.base as usize + br.read(e.nbits as u32) as usize;
                if br.overflow() {
                    w.push(table.t[s2].symbol);
                    break;
                }
                let e = table.t[s2];
                w.push(e.symbol);
                s2 = e.base as usize + br.read(e.nbits as u32) as usize;
                if br.overflow() {
                    w.push(table.t[s1].symbol);
                    break;
                }
            }
            used = 1 + h;
        }
        if w.len() > 255 || w.iter().any(|&x| x > 11) {
            return Err(bad("invalid Huffman weights"));
        }
        // the last weight is implied
        let total: u32 = w.iter().filter(|&&x| x > 0).map(|&x| 1u32 << (x - 1)).sum();
        if total == 0 {
            return Err(bad("invalid Huffman weights"));
        }
        let max_bits = highbit(total) + 1;
        let rest = (1u32 << max_bits) - total;
        if !rest.is_power_of_two() || max_bits > 11 {
            return Err(bad("invalid Huffman weights"));
        }
        w.push((highbit(rest) + 1) as u8);
        Ok((HufTable::from_weights(&w, max_bits)?, used))
    }

    /// Decodes one stream filling `out`.
    pub(crate) fn decode1(&self, src: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let mut br = Bits::new(src)?;
        let t = &*self.t;
        let mut chunks = out.chunks_exact_mut(4);
        for c in &mut chunks {
            br.reload();
            for o in c.iter_mut() {
                *o = br.huf(t);
            }
        }
        for o in chunks.into_remainder() {
            br.reload();
            *o = br.huf(t);
        }
        if !br.finished() {
            return Err(bad("Huffman stream not fully used"));
        }
        Ok(())
    }

    /// Decodes four streams (`src` starts with the jump table) filling `out`, interleaved.
    pub(crate) fn decode4(&self, src: &[u8], out: &mut [u8]) -> Result<(), Error> {
        if src.len() < 6 {
            return Err(bad("truncated literal jump table"));
        }
        let regen = out.len();
        let s = [u16::from_le_bytes([src[0], src[1]]) as usize, u16::from_le_bytes([src[2], src[3]]) as usize, u16::from_le_bytes([src[4], src[5]]) as usize];
        let d = &src[6..];
        if s[0] + s[1] + s[2] > d.len() {
            return Err(bad("invalid literal jump table"));
        }
        let seg = regen.div_ceil(4);
        if seg * 3 > regen {
            return Err(bad("invalid literal stream sizes"));
        }
        let (d0, r) = d.split_at(s[0]);
        let (d1, r) = r.split_at(s[1]);
        let (d2, d3) = r.split_at(s[2]);
        let (mut b0, mut b1, mut b2, mut b3) = (Bits::new(d0)?, Bits::new(d1)?, Bits::new(d2)?, Bits::new(d3)?);
        let t = &*self.t;
        let mut done = 0;
        if d0.len() >= 8 && d1.len() >= 8 && d2.len() >= 8 && d3.len() >= 8 {
            // The fast loop (zstd's HUF_decompress4X1_usingDTable_internal_fast): each stream is
            // a left-aligned 64-bit container with a marker bit below the unread bits, so the
            // bits consumed since the last load are its trailing zeros, and an input position.
            // Five symbols per stream between loads (at most 55 bits).
            let st = [0, s[0], s[0] + s[1], s[0] + s[1] + s[2]];
            let mut ip = [st[0] + b0.ptr, st[1] + b1.ptr, st[2] + b2.ptr, st[3] + b3.ptr];
            let used = [b0.used, b1.used, b2.used, b3.used];
            let mut bits = [0u64; 4];
            for j in 0..4 {
                bits[j] = (load64(d, ip[j]) | 1) << used[j];
            }
            let n3 = regen - 3 * seg;
            if simoom_sys::codec::fast() {
                let (p, b, dn) = simoom_sys::codec::huf4(simoom_sys::codec::Huf4 { table: t, src: d, starts: st, pos: ip, bits, out: &mut *out, seg, done });
                (ip, bits, done) = (p, b, dn);
            }
            loop {
                // rounds that can neither read before a stream's start (at most 7 bytes each)
                // nor write past stream 3's output
                let mut rounds = (n3 - done) / 5;
                for j in 0..4 {
                    rounds = rounds.min((ip[j] - st[j]) / 7);
                }
                if rounds == 0 {
                    break;
                }
                for _ in 0..rounds {
                    let w = &mut out[done..done + 3 * seg + 5];
                    for i in 0..5 {
                        for j in 0..4 {
                            let e = t[(bits[j] >> 53) as usize];
                            bits[j] <<= e & 63;
                            w[j * seg + i] = (e >> 8) as u8;
                        }
                    }
                    done += 5;
                    for j in 0..4 {
                        let z = bits[j].trailing_zeros();
                        ip[j] -= (z >> 3) as usize;
                        bits[j] = (load64(d, ip[j]) | 1) << (z & 7);
                    }
                }
            }
            b0 = Bits::at(d0, ip[0] - st[0], bits[0].trailing_zeros());
            b1 = Bits::at(d1, ip[1] - st[1], bits[1].trailing_zeros());
            b2 = Bits::at(d2, ip[2] - st[2], bits[2].trailing_zeros());
            b3 = Bits::at(d3, ip[3] - st[3], bits[3].trailing_zeros());
        }
        let (o0, r) = out.split_at_mut(seg);
        let (o1, r) = r.split_at_mut(seg);
        let (o2, o3) = r.split_at_mut(seg);
        let (o0, o1, o2, o3) = (&mut o0[done..], &mut o1[done..], &mut o2[done..], &mut o3[done..]);
        // the rest of the streams in lockstep, four symbols each per round (4 x 11 bits per
        // reload)
        let rounds = o3.len() / 4;
        for (((c0, c1), c2), c3) in o0.chunks_exact_mut(4).zip(o1.chunks_exact_mut(4)).zip(o2.chunks_exact_mut(4)).zip(o3.chunks_exact_mut(4)) {
            b0.reload();
            b1.reload();
            b2.reload();
            b3.reload();
            for j in 0..4 {
                c0[j] = b0.huf(t);
                c1[j] = b1.huf(t);
                c2[j] = b2.huf(t);
                c3[j] = b3.huf(t);
            }
        }
        for (b, o) in [(&mut b0, o0), (&mut b1, o1), (&mut b2, o2), (&mut b3, o3)] {
            for x in o[4 * rounds..].iter_mut() {
                b.reload();
                *x = b.huf(t);
            }
            if !b.finished() {
                return Err(bad("Huffman stream not fully used"));
            }
        }
        Ok(())
    }
}

/// Huffman codes for encoding: (code, bits) per symbol, from code lengths (max 11).
pub(crate) fn huf_codes(lens: &[u8]) -> (Vec<(u16, u8)>, u32, Vec<u8>) {
    let max_bits = *lens.iter().max().unwrap_or(&0) as u32;
    let w: Vec<u8> = lens.iter().map(|&l| if l == 0 { 0 } else { (max_bits + 1 - l as u32) as u8 }).collect();
    let mut counts = vec![0usize; max_bits as usize + 2];
    for &x in &w {
        counts[x as usize] += 1;
    }
    let mut rank = vec![0usize; max_bits as usize + 2];
    let mut next = 0;
    for x in 1..=max_bits as usize {
        rank[x] = next;
        next += counts[x] << (x - 1);
    }
    let mut codes = vec![(0u16, 0u8); lens.len()];
    for (s, &x) in w.iter().enumerate() {
        if x == 0 {
            continue;
        }
        let x = x as usize;
        codes[s] = ((rank[x] >> (x - 1)) as u16, lens[s]);
        rank[x] += 1 << (x - 1);
    }
    (codes, max_bits, w)
}

// ---------------------------------------------------------------------------------------------
// XXH64 (content checksum)
// ---------------------------------------------------------------------------------------------

const P1: u64 = 11_400_714_785_074_694_791;
const P2: u64 = 14_029_467_366_897_019_727;
const P3: u64 = 1_609_587_929_392_839_161;
const P4: u64 = 9_650_029_242_287_828_579;
const P5: u64 = 2_870_177_450_012_600_261;

#[inline(always)]
fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

fn merge(h: u64, v: u64) -> u64 {
    (h ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

/// Incremental XXH64 with seed 0.
#[derive(Clone, Debug)]
pub(crate) struct Xxh64 {
    v: [u64; 4],
    buf: [u8; 32],
    n: usize,
    total: u64,
}

impl Default for Xxh64 {
    fn default() -> Self {
        Xxh64 { v: [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)], buf: [0; 32], n: 0, total: 0 }
    }
}

impl Xxh64 {
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.n > 0 {
            let k = (32 - self.n).min(data.len());
            self.buf[self.n..self.n + k].copy_from_slice(&data[..k]);
            self.n += k;
            data = &data[k..];
            if self.n < 32 {
                return;
            }
            let b = self.buf;
            self.stripe(&b);
            self.n = 0;
        }
        let mut c = data.chunks_exact(32);
        for s in &mut c {
            self.stripe(s);
        }
        let r = c.remainder();
        self.buf[..r.len()].copy_from_slice(r);
        self.n = r.len();
    }

    #[inline(always)]
    fn stripe(&mut self, s: &[u8]) {
        for i in 0..4 {
            let lane = u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
            self.v[i] = round(self.v[i], lane);
        }
    }

    pub(crate) fn digest(&self) -> u64 {
        let mut h = if self.total >= 32 {
            let v = self.v;
            let mut h = v[0].rotate_left(1).wrapping_add(v[1].rotate_left(7)).wrapping_add(v[2].rotate_left(12)).wrapping_add(v[3].rotate_left(18));
            for x in v {
                h = merge(h, x);
            }
            h
        } else {
            P5
        };
        h = h.wrapping_add(self.total);
        let mut r = &self.buf[..self.n];
        while r.len() >= 8 {
            let k = u64::from_le_bytes(r[..8].try_into().expect("8 bytes"));
            h ^= round(0, k);
            h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            r = &r[8..];
        }
        if r.len() >= 4 {
            let k = u32::from_le_bytes(r[..4].try_into().expect("4 bytes")) as u64;
            h ^= k.wrapping_mul(P1);
            h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
            r = &r[4..];
        }
        for &b in r {
            h ^= (b as u64).wrapping_mul(P5);
            h = h.rotate_left(11).wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^= h >> 32;
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxh64_known_values() {
        let h = |d: &[u8]| {
            let mut x = Xxh64::default();
            x.update(d);
            x.digest()
        };
        assert_eq!(h(b""), 0xEF46_DB37_51D8_E999);
        assert_eq!(h(b"a"), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(h(b"abc"), 0x44BC_2CF5_AD77_0999);
        let long: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut x = Xxh64::default();
        for c in long.chunks(7) {
            x.update(c);
        }
        assert_eq!(x.digest(), h(&long));
    }

    #[test]
    fn ncount_round_trip_and_tables() {
        let counts = [100u32, 50, 25, 12, 6, 3, 1, 1, 0, 0, 0, 2];
        let total: u32 = counts.iter().sum();
        for log in 5..=9 {
            let norm = normalize(&counts, total, log);
            let sum: i32 = norm.iter().map(|&n| if n == -1 { 1 } else { n as i32 }).sum();
            assert_eq!(sum, 1 << log);
            let mut w = BitWriter::default();
            write_ncount(&mut w, &norm, log);
            w.align();
            let (back, l, _) = read_ncount(w.bytes(), 255, 9).unwrap();
            assert_eq!((back, l), (norm.clone(), log));
            // encode then decode a symbol sequence
            let ct = CTable::build(&norm, log);
            let dt = DTable::build(&norm, log).unwrap();
            let syms: Vec<u8> = (0..500).map(|i| [0u8, 1, 0, 2, 0, 1, 3, 4, 0, 5, 11, 6, 7, 0][i % 14]).collect();
            let mut bw = BitWriter::default();
            let mut st = ct.init(*syms.last().unwrap());
            for &s in syms[..syms.len() - 1].iter().rev() {
                ct.encode(&mut bw, &mut st, s);
            }
            ct.flush(&mut bw, st);
            let bytes = bw.close();
            let mut br = BackReader::new(&bytes).unwrap();
            let mut state = br.read(log) as usize;
            let mut got = Vec::new();
            for i in 0..syms.len() {
                let e = dt.t[state];
                got.push(e.symbol);
                if i + 1 < syms.len() {
                    state = e.base as usize + br.read(e.nbits as u32) as usize;
                }
            }
            assert_eq!(got, syms, "log {log}");
            assert!(br.finished());
        }
    }
}
