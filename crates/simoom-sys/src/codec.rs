//! Codec inner loops as unchecked pointer code (owned by the simoom-compress work).
//!
//! simoom-compress keeps a safe implementation of each loop as the reference; these are the
//! fast versions it calls when [`fast`] says so. Every loop establishes its bounds before it
//! starts (sizes, slack after the buffers) and checks per step exactly what the untrusted input
//! controls (lengths, offsets), so no input can make it read or write outside the slices it was
//! given. The tests and fuzzers of simoom-compress compare the two implementations on every
//! input.

use std::cell::Cell;

thread_local! {
    static SAFE_ONLY: Cell<bool> = const { Cell::new(false) };
}

/// Whether callers should use these loops (`false` after [`set_safe_only`] on this thread).
#[inline]
pub fn fast() -> bool {
    !SAFE_ONLY.with(Cell::get)
}

/// Makes [`fast`] return `false` on this thread (`true`) or `true` again (`false`): for tests
/// and fuzzing that compare the safe reference implementations with these loops.
pub fn set_safe_only(on: bool) {
    SAFE_ONLY.with(|c| c.set(on));
}

/// Bytes of slack the zstd loops need after the literals and after the output limit.
pub const WILD: usize = 32;

/// A zstd sequence decoding table entry: the code's base value and extra bits, and the next
/// state's base and bits (zstd's `ZSTD_seqSymbol`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct SeqEntry {
    pub base: u32,
    pub add: u8,
    pub nbits: u8,
    pub next: u16,
}

/// The inputs of [`zstd_sequences`].
pub struct Sequences<'a> {
    /// Literal lengths at 0, offsets at 512, match lengths at 1024 (next states absolute).
    pub table: &'a [SeqEntry; 2048],
    /// Accuracy logs of the three tables (each at most 9).
    pub logs: [u32; 3],
    /// The sequences bitstream; at least 8 bytes, the last one non-zero.
    pub bits: &'a [u8],
    /// Number of sequences, at least 1.
    pub n: usize,
    /// The block's literals followed by [`WILD`] bytes of slack.
    pub lits: &'a [u8],
    /// The output: decoding writes from `start` on; the last [`WILD`] bytes are slack, so the
    /// block may produce `out.len() - WILD - start` bytes.
    pub out: &'a mut [u8],
    pub start: usize,
    pub reps: [u32; 3],
    /// The largest offset allowed (the window).
    pub wmax: usize,
    /// History before `start` that offsets may reach, relative to `start` (wrapping): an
    /// offset must be at most `hist + (position - start)`.
    pub hist: usize,
}

/// Why [`zstd_sequences`] stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqError {
    Literals,
    ZeroOffset,
    Window,
    Size,
    Bitstream,
}

/// Decodes and executes a zstd block's sequences (RFC 8878 section 3.1.1.3.2 and 3.1.1.4).
/// Returns the end of the output written (the remaining literals after the last sequence are
/// left to the caller) and the repeat offsets; the bytes after the end up to the slack are
/// garbage. Same results as simoom-compress's safe `execute`.
///
/// # Panics
/// If the preconditions on [`Sequences`] do not hold (they are checked on entry).
pub fn zstd_sequences(s: Sequences<'_>) -> Result<(usize, usize, [u32; 3]), SeqError> {
    #[cfg(target_arch = "x86_64")]
    if crate::bits::bmi2() {
        // SAFETY: the CPU has BMI1, BMI2 and LZCNT (checked at run time by `bmi2()`), which is
        // all `sequences_bmi2` requires beyond its safe signature.
        return unsafe { sequences_bmi2(s) };
    }
    sequences(s)
}

/// [`sequences`] compiled with BMI1, BMI2 and LZCNT (variable shifts without `cl`).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1,bmi2,lzcnt")]
unsafe fn sequences_bmi2(s: Sequences<'_>) -> Result<(usize, usize, [u32; 3]), SeqError> {
    sequences(s)
}

// (the last sequence's state updates are skipped, leaving assignments unread)
#[allow(unused_assignments)]
#[inline(always)]
fn sequences(s: Sequences<'_>) -> Result<(usize, usize, [u32; 3]), SeqError> {
    let Sequences { table, logs, bits, n, lits, out, start, mut reps, wmax, hist } = s;
    assert!(bits.len() >= 8 && bits[bits.len() - 1] != 0 && n >= 1);
    assert!(lits.len() >= WILD && out.len() >= start + WILD && logs.iter().all(|&l| l <= 9));
    let lim = out.len() - WILD;
    let tp = table.as_ptr();
    let bp = bits.as_ptr();
    // the bit reader (zstd's BIT_DStream): `c` holds the 8 bytes at `ptr`, `used` bits of
    // them consumed from the top; `ptr` stays in 0..=bits.len() - 8
    let mut ptr = bits.len() - 8;
    let last = bits[bits.len() - 1];
    let mut used = 8 - (31 - (last as u32).leading_zeros());
    // SAFETY: `ptr + 8 <= bits.len()`.
    let mut c = u64::from_le_bytes(unsafe { std::ptr::read_unaligned(bp.add(ptr) as *const [u8; 8]) });
    macro_rules! reload {
        () => {{
            let step = ((used >> 3) as usize).min(ptr);
            ptr -= step;
            used -= 8 * step as u32;
            // SAFETY: `ptr` only decreases and stays `<= bits.len() - 8`, so the 8 bytes are
            // inside `bits`.
            c = u64::from_le_bytes(unsafe { std::ptr::read_unaligned(bp.add(ptr) as *const [u8; 8]) });
        }};
    }
    macro_rules! read {
        ($nb:expr) => {{
            let nb = $nb as u32;
            let v = c.wrapping_shl(used) >> 1 >> (63u32.wrapping_sub(nb) & 63);
            used += nb;
            v
        }};
    }
    macro_rules! entry {
        ($s:expr) => {
            // SAFETY: the index is masked to the table's 2048 entries.
            unsafe { *tp.add($s & 2047) }
        };
    }
    let mut s_ll = read!(logs[0]) as usize;
    let mut s_of = 512 + read!(logs[1]) as usize;
    let mut s_ml = 1024 + read!(logs[2]) as usize;
    reload!();
    let lits_n = lits.len() - WILD;
    // the next literal and how many are left (the slice has WILD bytes of slack after them)
    let mut litp = lits.as_ptr();
    let mut lits_left = lits_n;
    let o = out.as_mut_ptr();
    let mut op = start;
    // one bound for every offset: at most `lit_end` (inside the buffer) and at most
    // `hist + lit_end` (the history); the second is the lower one exactly when `hist` is
    // negative (as a wrapping number)
    let h = if (hist as isize) < 0 { hist } else { 0 };
    // (Decoding into a small batch first and executing it after, as libzstd's long-offset
    // path does, was measured: the same instruction count and more mispredicted branches.)
    // (Pipelining by one sequence with a prefetch of the next match source was measured too:
    // no faster, more instructions.)
    macro_rules! decode {
        ($update:expr) => {{
            let ll_e = entry!(s_ll);
            let of_e = entry!(s_of);
            let ml_e = entry!(s_ml);
            let ofb = read!(of_e.add) as u32;
            let ml = (ml_e.base + read!(ml_e.add) as u32) as usize;
            if of_e.add as u32 + ml_e.add as u32 + ll_e.add as u32 >= 31 {
                reload!();
            }
            let ll = (ll_e.base + read!(ll_e.add) as u32) as usize;
            if $update {
                s_ll = ll_e.next as usize + read!(ll_e.nbits) as usize;
                s_ml = ml_e.next as usize + read!(ml_e.nbits) as usize;
                s_of = of_e.next as usize + read!(of_e.nbits) as usize;
                reload!();
            }
            let off = if of_e.add > 1 {
                let x = of_e.base.wrapping_add(ofb);
                reps = [x, reps[0], reps[1]];
                x
            } else {
                let v = of_e.base + ofb + (ll == 0) as u32;
                let x = match v {
                    1 => reps[0],
                    2 => reps[1],
                    3 => reps[2],
                    _ => reps[0].wrapping_sub(1),
                };
                if v != 1 {
                    reps = [x, reps[0], if v == 2 { reps[2] } else { reps[1] }];
                }
                x
            } as usize;
            (ll, ml, off)
        }};
    }
    macro_rules! execute {
        ($ll:expr, $ml:expr, $off:expr) => {{
            let (ll, ml, off) = ($ll, $ml, $off);
            let lit_end = op + ll;
            let end = lit_end + ml;
            // everything the input controls, checked before any copy: the literals exist, the
            // output stays under the limit, the offset is non-zero, inside the window, the
            // history and the buffer
            if (ll > lits_left) | (end > lim) | (off.wrapping_sub(1) >= wmax) | (off > lit_end.wrapping_add(h)) {
                return Err(if ll > lits_left {
                    SeqError::Literals
                } else if off == 0 {
                    SeqError::ZeroOffset
                } else if off >= wmax.wrapping_add(1) || off > lit_end.wrapping_add(h) {
                    SeqError::Window
                } else {
                    SeqError::Size
                });
            }
            // SAFETY: literals: `ll <= lits_left`, so reading 16-byte chunks up to `ll + 15`
            // bytes past `litp` stays in `lits` (WILD bytes of slack after the last literal);
            // writing up to `lit_end + 15 < lim + WILD = out.len()` stays in `out`. The slices
            // are distinct.
            unsafe {
                let d = o.add(op);
                let mut i = 0;
                loop {
                    std::ptr::copy_nonoverlapping(litp.add(i), d.add(i), 16);
                    i += 16;
                    if i >= ll {
                        break;
                    }
                }
                litp = litp.add(ll);
            }
            lits_left -= ll;
            // SAFETY: match: `off <= lit_end` (since `h <= 0` as a signed number), so the source
            // `lit_end - off` is inside `out`; all writes end before `end + 16 <= lim + 16 <
            // out.len()`, and reads trail the writes.
            unsafe { copy_match(o, lit_end, off, ml) };
            op = end;
        }};
    }
    for _ in 1..n {
        let (ll, ml, off) = decode!(true);
        execute!(ll, ml, off);
    }
    let (ll, ml, off) = decode!(false);
    execute!(ll, ml, off);
    if !(ptr == 0 && used == 64) {
        return Err(SeqError::Bitstream);
    }
    Ok((op, lits_n - lits_left, reps))
}

/// Copies `ml` (at least 1) bytes from `off` (at least 1) back to `o + op`, overlapping
/// allowed (zstd's `ZSTD_execSequence`).
///
/// # Safety
/// `o` points into a buffer with `off <= op` and at least `op + ml + 16` bytes.
#[inline(always)]
unsafe fn copy_match(o: *mut u8, op: usize, off: usize, ml: usize) {
    let end = op + ml;
    // SAFETY (for every access below): sources are at `>= op - off >= 0` and below the
    // destination being written; destinations are below `end + 16`, inside the buffer by the
    // caller's contract. Each 16- or 8-byte copy has source and destination at least that far
    // apart, so they do not overlap.
    unsafe {
        if off >= 16 {
            let (mut sp, mut dp) = (o.add(op - off), o.add(op));
            let e = o.add(end);
            loop {
                std::ptr::copy_nonoverlapping(sp, dp, 16);
                dp = dp.add(16);
                sp = sp.add(16);
                if dp >= e {
                    break;
                }
            }
        } else if off == 1 {
            std::ptr::write_bytes(o.add(op), *o.add(op - 1), ml);
        } else {
            const D32: [usize; 8] = [0, 1, 2, 1, 4, 4, 4, 4];
            const D64: [usize; 8] = [8, 8, 8, 7, 8, 9, 10, 11];
            let mut d = op;
            let mut s = op - off;
            if off < 8 {
                *o.add(d) = *o.add(s);
                *o.add(d + 1) = *o.add(s + 1);
                *o.add(d + 2) = *o.add(s + 2);
                *o.add(d + 3) = *o.add(s + 3);
                s += D32[off];
                std::ptr::copy_nonoverlapping(o.add(s), o.add(d + 4), 4);
                d += 8;
                s = d - (off - D32[off] + D64[off]);
            } else {
                std::ptr::copy_nonoverlapping(o.add(s), o.add(d), 8);
                d += 8;
                s += 8;
            }
            while d < end {
                std::ptr::copy_nonoverlapping(o.add(s), o.add(d), 8);
                d += 8;
                s += 8;
            }
        }
    }
}

/// The state of zstd's four-stream Huffman fast loop (HUF_decompress4X1 "fast"): per stream a
/// left-aligned 64-bit container with a marker bit below the unread bits, and its position in
/// the input.
pub struct Huf4<'a> {
    /// Entries `symbol << 8 | bits`, indexed by the next 11 bits.
    pub table: &'a [u16; 2048],
    /// The four streams, one after another.
    pub src: &'a [u8],
    /// Where each stream starts in `src`.
    pub starts: [usize; 4],
    /// Each stream's position (the 8 bytes loaded last): `starts[j] <= pos[j]`,
    /// `pos[j] + 8 <= src.len()`.
    pub pos: [usize; 4],
    pub bits: [u64; 4],
    /// The output: stream `j` writes `out[j * seg + i]`; stream 3 has `out.len() - 3 * seg`.
    pub out: &'a mut [u8],
    pub seg: usize,
    /// Symbols per stream done so far.
    pub done: usize,
}

/// Runs the four-stream fast loop as far as it can go without reading before a stream's start
/// or writing past stream 3's output (five symbols per stream per round); returns the updated
/// positions, containers and symbol count. Same results as simoom-compress's safe loop.
///
/// # Panics
/// If the position or size preconditions of [`Huf4`] do not hold (checked on entry).
pub fn huf4(h: Huf4<'_>) -> ([usize; 4], [u64; 4], usize) {
    #[cfg(target_arch = "x86_64")]
    if crate::bits::bmi2() {
        // SAFETY: the CPU has BMI1, BMI2 and LZCNT (checked at run time by `bmi2()`), which is
        // all `huf4_bmi2` requires beyond its safe signature.
        return unsafe { huf4_bmi2(h) };
    }
    huf4_loop(h)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1,bmi2,lzcnt")]
unsafe fn huf4_bmi2(h: Huf4<'_>) -> ([usize; 4], [u64; 4], usize) {
    huf4_loop(h)
}

#[inline(always)]
fn huf4_loop(h: Huf4<'_>) -> ([usize; 4], [u64; 4], usize) {
    let Huf4 { table, src, starts, mut pos, mut bits, out, seg, mut done } = h;
    assert!(out.len() >= 3 * seg && done <= out.len() - 3 * seg && done <= seg);
    for j in 0..4 {
        assert!(starts[j] <= pos[j] && pos[j] + 8 <= src.len());
    }
    let n3 = out.len() - 3 * seg;
    let t = table.as_ptr();
    let sp = src.as_ptr();
    let o = out.as_mut_ptr();
    loop {
        let mut rounds = (n3 - done) / 5;
        for j in 0..4 {
            rounds = rounds.min((pos[j] - starts[j]) / 7);
        }
        if rounds == 0 {
            break;
        }
        for _ in 0..rounds {
            for i in 0..5 {
                for j in 0..4 {
                    // SAFETY: the table index is a 64-bit value shifted right by 53, so below
                    // 2048. The output index `j * seg + done + i` is below `3 * seg + n3 =
                    // out.len()`: `done + 5 <= n3 <= seg` holds for every round counted above.
                    unsafe {
                        let e = *t.add((bits[j] >> 53) as usize);
                        bits[j] <<= e & 63;
                        *o.add(j * seg + done + i) = (e >> 8) as u8;
                    }
                }
            }
            done += 5;
            for j in 0..4 {
                let z = bits[j].trailing_zeros();
                pos[j] -= (z >> 3) as usize;
                // SAFETY: a round consumes at most 55 bits (7 bytes) per stream, and the round
                // count keeps `pos[j] - 7 * rounds >= starts[j]`; `pos[j]` only decreases, so
                // `pos[j] + 8 <= src.len()` still holds.
                bits[j] = (u64::from_le_bytes(unsafe { std::ptr::read_unaligned(sp.add(pos[j]) as *const [u8; 8]) }) | 1) << (z & 7);
            }
        }
    }
    (pos, bits, done)
}

/// One match of an LZ77 parse: `lit` literals, then `len` bytes from `dist` back.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    pub lit: u32,
    pub len: u32,
    pub dist: u32,
}

/// The inputs of [`zstd_fast`].
pub struct FastIn<'a> {
    pub buf: &'a [u8],
    /// Stream position of `buf[0]`.
    pub base: u64,
    pub from: usize,
    /// End of the block (`from <= to <= buf.len()`); matches never reach past it.
    pub to: usize,
    /// Short-hash table (a power of two entries) over `mls` (5 to 8) bytes, `small_log` bits.
    pub small: &'a mut [u32],
    pub small_log: u32,
    pub mls: u32,
    /// Long-hash table over 8 bytes for double fast (`long_log > 0`, a power of two entries).
    pub long: &'a mut [u32],
    pub long_log: u32,
    pub max_dist: usize,
    pub rep: [u32; 2],
    /// Skip one more byte for every `1 << strength` bytes without a match (zstd: 8).
    pub strength: u32,
    pub out: &'a mut Vec<Match>,
}


#[inline(always)]
fn fhash(v: u64, mls: u32, log: u32) -> usize {
    let p: u64 = match mls {
        5 => 889_523_592_379,
        6 => 227_718_039_650_203,
        7 => 58_295_818_150_454_627,
        _ => 0xCF1B_BCDC_B7A5_6463,
    };
    ((v << (64 - 8 * mls)).wrapping_mul(p) >> (64 - log)) as usize
}

/// Bytes equal at `a` and `b`, up to `max`.
///
/// # Safety
/// `p` points to a buffer holding `a + max` and `b + max` bytes.
#[inline(always)]
unsafe fn count_raw(p: *const u8, a: usize, b: usize, max: usize) -> usize {
    let mut n = 0;
    // SAFETY: every read is below `a + max` or `b + max`, inside the buffer by the contract.
    unsafe {
        while n + 8 <= max {
            let x = std::ptr::read_unaligned(p.add(a + n) as *const u64) ^ std::ptr::read_unaligned(p.add(b + n) as *const u64);
            if x != 0 {
                return n + (x.to_le().trailing_zeros() / 8) as usize;
            }
            n += 8;
        }
        while n < max && *p.add(a + n) == *p.add(b + n) {
            n += 1;
        }
    }
    n
}

/// zstd's fast (level 1: one table) and double-fast (levels 2-3: `long_log > 0`) match finders
/// over `buf[from..to]`, appending matches to `out`; returns the literals left after the last
/// match and the repeat offsets. Same results as simoom-compress's safe `Fast`.
///
/// Every read is at a position the loops keep at most `to - 8` (`to - 9` for double fast) or
/// below a position already read, or inside a match count bounded by `to`; tables are indexed
/// by masked hashes.
///
/// # Panics
/// If `from <= to <= buf.len()` or the table sizes (non-zero powers of two) do not hold.
pub fn zstd_fast(p: FastIn<'_>) -> (usize, [u32; 2]) {
    #[cfg(target_arch = "x86_64")]
    if crate::bits::bmi2() {
        // SAFETY: the CPU has BMI1, BMI2 and LZCNT (checked at run time by `bmi2()`), which is
        // all `fast_bmi2` requires beyond its safe signature.
        return unsafe { fast_bmi2(p) };
    }
    fast_impl(p)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1,bmi2,lzcnt")]
unsafe fn fast_bmi2(p: FastIn<'_>) -> (usize, [u32; 2]) {
    fast_impl(p)
}

#[inline(always)]
fn fast_impl(p: FastIn<'_>) -> (usize, [u32; 2]) {
    let FastIn { buf, base, from, to, small, small_log: slog, mls, long, long_log: llog, max_dist, rep, strength, out } = p;
    assert!((2..=12).contains(&strength));
    // the block may not be longer than the window: the bound `low` on match sources is taken
    // from the block's end, and every `ip - low` below assumes `low <= from <= ip`
    assert!(from <= to && to <= buf.len() && to.saturating_sub(max_dist) <= from && small.len().is_power_of_two() && (5..=8).contains(&mls));
    assert!(llog == 0 || long.len().is_power_of_two());
    let bp = buf.as_ptr();
    let sp = small.as_mut_ptr();
    let lp = long.as_mut_ptr();
    // SAFETY (the macros): reads are inside `buf` by the invariants in the function docs (every
    // position read is at most `to - 8`, and `to <= buf.len()`); table indices are masked with
    // `len - 1` of their power-of-two table.
    macro_rules! r32 {
        ($i:expr) => {
            unsafe { std::ptr::read_unaligned(bp.add($i) as *const u32).to_le() }
        };
    }
    macro_rules! r64 {
        ($i:expr) => {
            unsafe { std::ptr::read_unaligned(bp.add($i) as *const u64).to_le() }
        };
    }
    macro_rules! b8 {
        ($i:expr) => {
            unsafe { *bp.add($i) }
        };
    }
    macro_rules! cnt {
        ($a:expr, $b:expr, $m:expr) => {
            unsafe { count_raw(bp, $a, $b, $m) }
        };
    }
    macro_rules! tget {
        (small, $h:expr) => {
            {
                let h = $h;
                unsafe { *sp.add(h) }
            }
        };
        (long, $h:expr) => {
            {
                let h = $h;
                unsafe { *lp.add(h) }
            }
        };
    }
    macro_rules! tset {
        (small, $h:expr, $v:expr) => {
            {
                let (h, v) = ($h, $v);
                unsafe { *sp.add(h) = v }
            }
        };
        (long, $h:expr, $v:expr) => {
            {
                let (h, v) = ($h, $v);
                unsafe { *lp.add(h) = v }
            }
        };
    }
    let _ = (&lp, &max_dist);
    if llog > 0 {
        let small = &mut *small;
        let long = &mut *long;
        let _ = (&small, &long);

        
            let (smask, lmask) = (small.len() - 1, long.len() - 1);
        
        
            let [mut r0, mut r1] = rep;
            let pos = |i: usize| (base + i as u64) as u32;
            let lowest = |i: usize| i.saturating_sub(max_dist);
            let mut anchor = from;
            let mut ip = from + (from == 0) as usize;
            if to < 9 {
                return (to - from, rep);
            }
            let ilimit = to - 9;
            while ip < ilimit {
                let v = r64!(ip);
                let hl = fhash(v, 8, llog) & lmask;
                let hs = fhash(v, mls, slog) & smask;
                let cl = tget!(long, hl);
                let cs = tget!(small, hs);
                tset!(long, hl, pos(ip));
                tset!(small, hs, pos(ip));
                let low = lowest(ip);
                let start;
                let ml;
                let r = r0 as usize;
                if r > 0 && ip + 1 - lowest(ip + 1) >= r && r32!(ip + 1 - r) == r32!(ip + 1) {
                    start = ip + 1;
                    ml = 4 + cnt!(start + 4 - r, start + 4, to - start - 4);
                    out.push(Match { lit: (start - anchor) as u32, len: ml as u32, dist: r as u32 });
                } else {
                    let dl = pos(ip).wrapping_sub(cl) as usize;
                    let ds = pos(ip).wrapping_sub(cs) as usize;
                    let (mut s, d, mut len);
                    if dl != 0 && dl <= ip - low && r64!(ip - dl) == v {
                        s = ip;
                        d = dl;
                        len = 8 + cnt!(ip + 8 - dl, ip + 8, to - ip - 8);
                    } else if ds != 0 && ds <= ip - low && r32!(ip - ds) == v as u32 {
                        // a long match one byte ahead beats the short one
                        let v1 = r64!(ip + 1);
                        let hl1 = fhash(v1, 8, llog) & lmask;
                        let cl1 = tget!(long, hl1);
                        tset!(long, hl1, pos(ip + 1));
                        let dl1 = pos(ip + 1).wrapping_sub(cl1) as usize;
                        if dl1 != 0 && dl1 <= ip + 1 - lowest(ip + 1) && r64!(ip + 1 - dl1) == v1 {
                            s = ip + 1;
                            d = dl1;
                            len = 8 + cnt!(ip + 9 - dl1, ip + 9, to - ip - 9);
                        } else {
                            s = ip;
                            d = ds;
                            len = 4 + cnt!(ip + 4 - ds, ip + 4, to - ip - 4);
                        }
                    } else {
                        ip += ((ip - anchor) >> strength) + 1;
                        continue;
                    }
                    let mut m = s - d;
                    let low = lowest(s);
                    while s > anchor && m > low && b8!(s - 1) == b8!(m - 1) {
                        s -= 1;
                        m -= 1;
                        len += 1;
                    }
                    start = s;
                    ml = len;
                    r1 = r0;
                    r0 = d as u32;
                    out.push(Match { lit: (start - anchor) as u32, len: ml as u32, dist: d as u32 });
                }
                ip = start + ml;
                anchor = ip;
                if ip <= ilimit {
                    // index positions of the match
                    let p2 = start + 2;
                    let v2 = r64!(p2);
                    tset!(long, fhash(v2, 8, llog) & lmask, pos(p2));
                    tset!(small, fhash(v2, mls, slog) & smask, pos(p2));
                    let v3 = r64!(ip - 2);
                    tset!(long, fhash(v3, 8, llog) & lmask, pos(ip - 2));
                    tset!(small, fhash(v3, mls, slog) & smask, pos(ip - 2));
                    tset!(long, fhash(r64!(ip - 1), 8, llog) & lmask, pos(ip - 1));
                    while ip <= ilimit {
                        let r = r1 as usize;
                        if r == 0 || ip - lowest(ip) < r || r32!(ip - r) != r32!(ip) {
                            break;
                        }
                        let ml = 4 + cnt!(ip + 4 - r, ip + 4, to - ip - 4);
                        std::mem::swap(&mut r0, &mut r1);
                        let v = r64!(ip);
                        tset!(small, fhash(v, mls, slog) & smask, pos(ip));
                        tset!(long, fhash(v, 8, llog) & lmask, pos(ip));
                        out.push(Match { lit: 0, len: ml as u32, dist: r as u32 });
                        ip += ml;
                        anchor = ip;
                    }
                }
            }
            (to - anchor, [r0, r1])
    } else {
        let small = &mut *small;
        let _ = &small;

        
            let smask = small.len() - 1;
        
            let pos = |i: usize| (base + i as u64) as u32;
            let hash_at = |i: usize| fhash(r64!(i), mls, slog) & smask;
            if to < from + 16 {
                return (to - from, rep);
            }
            // matches start no lower than this (the window from the block's end, as zstd's prefix)
            let low = to.saturating_sub(max_dist);
            let ilimit = to - 8;
            let mut anchor = from;
            let mut ip0 = from + (from == low) as usize;
            let [mut r0, mut r1] = rep;
            let (mut saved0, mut saved1) = (0, 0);
            let max_rep = (ip0 - low) as u32;
            if r1 > max_rep {
                saved1 = r1;
                r1 = 0;
            }
            if r0 > max_rep {
                saved0 = r0;
                r0 = 0;
            }
            let found = |ip: usize, m: u32| {
                let d = pos(ip).wrapping_sub(m) as usize;
                d != 0 && d <= ip - low && r32!(ip - d) == r32!(ip)
            };
            'start: loop {
                let mut step = 2;
                let mut next_step = ip0 + (1 << (strength - 1));
                let mut ip1 = ip0 + 1;
                let mut ip2 = ip0 + step;
                let mut ip3 = ip2 + 1;
                if ip3 >= ilimit {
                    break;
                }
                let mut h0 = hash_at(ip0);
                let mut h1 = hash_at(ip1);
                let mut midx = tget!(small, h0);
                let cur0;
                let mut m0;
                let mut ml;
                let rep_match;
                loop {
                    let mut c = ip0;
                    tset!(small, h0, pos(ip0));
                    if r0 > 0 && r32!(ip2 - r0 as usize) == r32!(ip2) {
                        cur0 = c;
                        ip0 = ip2;
                        m0 = ip0 - r0 as usize;
                        ml = (m0 > low && b8!(ip0 - 1) == b8!(m0 - 1)) as usize;
                        ip0 -= ml;
                        m0 -= ml;
                        ml += 4;
                        tset!(small, h1, pos(ip1));
                        rep_match = true;
                        break;
                    }
                    if found(ip0, midx) {
                        cur0 = c;
                        tset!(small, h1, pos(ip1));
                        m0 = 0;
                        ml = 0;
                        rep_match = false;
                        break;
                    }
                    midx = tget!(small, h1);
                    h0 = h1;
                    h1 = hash_at(ip2);
                    ip0 = ip1;
                    ip1 = ip2;
                    ip2 = ip3;
                    c = ip0;
                    tset!(small, h0, pos(ip0));
                    if found(ip0, midx) {
                        cur0 = c;
                        if step <= 4 {
                            tset!(small, h1, pos(ip1));
                        }
                        m0 = 0;
                        ml = 0;
                        rep_match = false;
                        break;
                    }
                    midx = tget!(small, h1);
                    h0 = h1;
                    h1 = hash_at(ip2);
                    ip0 = ip1;
                    ip1 = ip2;
                    ip2 = ip0 + step;
                    ip3 = ip1 + step;
                    if ip2 >= next_step {
                        step += 1;
                        next_step += 1 << (strength - 1);
                    }
                    if ip3 >= ilimit {
                        break 'start;
                    }
                }
                if !rep_match {
                    // a new offset; extend backwards over the pending literals
                    let d = pos(ip0).wrapping_sub(midx) as usize;
                    m0 = ip0 - d;
                    r1 = r0;
                    r0 = d as u32;
                    ml = 4;
                    while ip0 > anchor && m0 > low && b8!(ip0 - 1) == b8!(m0 - 1) {
                        ip0 -= 1;
                        m0 -= 1;
                        ml += 1;
                    }
                }
                ml += cnt!(m0 + ml, ip0 + ml, to - ip0 - ml);
                out.push(Match { lit: (ip0 - anchor) as u32, len: ml as u32, dist: (ip0 - m0) as u32 });
                ip0 += ml;
                anchor = ip0;
                if ip0 <= ilimit {
                    tset!(small, hash_at(cur0 + 2), pos(cur0 + 2));
                    tset!(small, hash_at(ip0 - 2), pos(ip0 - 2));
                    // the second-to-last offset right away (no literals in between)
                    while r1 > 0 && ip0 <= ilimit && r32!(ip0) == r32!(ip0 - r1 as usize) {
                        let r = r1 as usize;
                        let ml = 4 + cnt!(ip0 + 4 - r, ip0 + 4, to - ip0 - 4);
                        std::mem::swap(&mut r0, &mut r1);
                        tset!(small, hash_at(ip0), pos(ip0));
                        out.push(Match { lit: 0, len: ml as u32, dist: r as u32 });
                        ip0 += ml;
                        anchor = ip0;
                    }
                }
            }
            // offsets set aside as out of the window come back (zstd's offsetSaved logic)
            saved1 = if saved0 != 0 && r0 != 0 { saved0 } else { saved1 };
            (to - anchor, [if r0 != 0 { r0 } else { saved0 }, if r1 != 0 { r1 } else { saved1 }])
    }
}

/// An FSE encoding table entry (zstd's `FSE_symbolCompressionTransform`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SymTT {
    pub delta_nbits: u32,
    pub delta_find: i32,
}

/// An FSE encoding table: next states (log at most 9) and per-symbol transforms (symbols
/// below 64).
#[derive(Clone, Copy)]
pub struct FseEnc<'a> {
    pub states: &'a [u16; 512],
    pub tt: &'a [SymTT; 64],
    pub log: u32,
}

/// One zstd sequence ready to code: the three codes, the extra-bit counts of the lengths, and
/// the extra values (the offset value's extra bits are `of_code` of them).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeqCode {
    pub ll_code: u8,
    pub of_code: u8,
    pub ml_code: u8,
    pub ll_bits: u8,
    pub ml_bits: u8,
    pub ll: u32,
    pub ofv: u32,
    pub mlb: u32,
}

/// Writes the sequences bitstream of a zstd block (RFC 8878 section 4.1.2: last sequence first,
/// the three FSE states interleaved, extras, end marker) for `codes` (at least one) with tables
/// `[literal lengths, offsets, match lengths]`, appending it to `out`. Same bytes as
/// simoom-compress's safe writer.
pub fn zstd_seq_stream(codes: &[SeqCode], t: [FseEnc<'_>; 3], out: &mut Vec<u8>) {
    #[cfg(target_arch = "x86_64")]
    if crate::bits::bmi2() {
        // SAFETY: the CPU has BMI1, BMI2 and LZCNT (checked at run time by `bmi2()`), which is
        // all `seq_stream_bmi2` requires beyond its safe signature.
        return unsafe { seq_stream_bmi2(codes, t, out) };
    }
    seq_stream(codes, t, out)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1,bmi2,lzcnt")]
unsafe fn seq_stream_bmi2(codes: &[SeqCode], t: [FseEnc<'_>; 3], out: &mut Vec<u8>) {
    seq_stream(codes, t, out)
}

// (the final flush leaves its state updates unread)
#[allow(unused_assignments)]
#[inline(always)]
fn seq_stream(codes: &[SeqCode], t: [FseEnc<'_>; 3], out: &mut Vec<u8>) {
    assert!(!codes.is_empty() && t.iter().all(|x| x.log <= 9));
    let n = codes.len();
    let start = out.len();
    // each sequence writes at most 26 + 32 + 31 bits; plus the states and the end marker
    let cap = 13 * n + 64;
    out.resize(start + cap + 8, 0);
    let o = out.as_mut_ptr();
    let mut pos = start;
    let mut acc = 0u64;
    let mut nb = 0u32;
    macro_rules! add {
        ($v:expr, $b:expr) => {{
            let b = $b as u32;
            acc |= ($v as u64 & ((1u64 << b) - 1)) << nb;
            nb += b;
        }};
    }
    macro_rules! flush {
        () => {{
            // SAFETY: `pos` grows by at most 13 bytes per sequence plus the fixed parts, so
            // `pos + 8 <= start + cap + 8 = out.len()`.
            unsafe { std::ptr::write_unaligned(o.add(pos) as *mut [u8; 8], acc.to_le_bytes()) };
            let k = nb >> 3;
            pos += k as usize;
            acc = if k == 8 { 0 } else { acc >> (8 * k) };
            nb &= 7;
        }};
    }
    let init = |x: &FseEnc<'_>, s: u8| {
        let tt = x.tt[s as usize & 63];
        let b = (tt.delta_nbits.wrapping_add(1 << 15)) >> 16;
        let v = (b << 16).wrapping_sub(tt.delta_nbits);
        x.states[((v >> b) as i32).wrapping_add(tt.delta_find) as usize & 511] as u32
    };
    let [ll_t, of_t, ml_t] = t;
    let last = codes[n - 1];
    let mut ll_s = init(&ll_t, last.ll_code);
    let mut of_s = init(&of_t, last.of_code);
    let mut ml_s = init(&ml_t, last.ml_code);
    macro_rules! enc {
        ($x:expr, $st:expr, $sym:expr) => {{
            let tt = $x.tt[$sym as usize & 63];
            let b = $st.wrapping_add(tt.delta_nbits) >> 16;
            add!($st, b);
            $st = $x.states[(($st >> b) as i32).wrapping_add(tt.delta_find) as usize & 511] as u32;
        }};
    }
    macro_rules! extras {
        ($c:expr) => {{
            let c = $c;
            if nb + c.ll_bits as u32 + c.ml_bits as u32 > 63 {
                flush!();
            }
            add!(c.ll, c.ll_bits);
            add!(c.mlb, c.ml_bits);
            if nb + c.of_code as u32 > 63 {
                flush!();
            }
            add!(c.ofv, c.of_code);
            flush!();
        }};
    }
    extras!(last);
    for c in codes[..n - 1].iter().rev() {
        enc!(of_t, of_s, c.of_code);
        enc!(ml_t, ml_s, c.ml_code);
        enc!(ll_t, ll_s, c.ll_code);
        flush!();
        extras!(c);
    }
    add!(ml_s, ml_t.log);
    flush!();
    add!(of_s, of_t.log);
    flush!();
    add!(ll_s, ll_t.log);
    add!(1u64, 1u32);
    nb = (nb + 7) & !7;
    flush!();
    out.truncate(pos);
}
