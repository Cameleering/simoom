//! The match finders of zstd's fast levels, after zstd's `ZSTD_compressBlock_fast` (level 1: one
//! hash table) and `ZSTD_compressBlock_doubleFast` (levels 2 and 3: a table of 8-byte hashes and
//! one of short hashes): check the last offset one byte ahead first, then the tables; extend
//! matches backwards over the pending literals; skip faster the longer nothing matches; after a
//! match, index two of its positions and try the second-to-last offset at once.
//!
//! Positions are stream positions as `u32` (as in [`crate::lz::Lz`], so the buffer can slide);
//! every candidate is checked against the window and verified.

use crate::lz::Seq;


pub(crate) struct Fast {
    /// Short hash: `small_log` bits over `mls` bytes.
    small: Vec<u32>,
    small_log: u32,
    mls: u32,
    /// Long hash over 8 bytes (double fast only).
    long: Vec<u32>,
    long_log: u32,
    max_dist: usize,
    /// The last two offsets, as the matcher sees them.
    rep: [u32; 2],
    /// Skip one more byte for every `1 << strength` bytes without a match (zstd: 8).
    strength: u32,
}

const P5: u64 = 889_523_592_379;
const P6: u64 = 227_718_039_650_203;
const P7: u64 = 58_295_818_150_454_627;
const P8: u64 = 0xCF1B_BCDC_B7A5_6463;

#[inline(always)]
fn read32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(*b[i..].first_chunk::<4>().expect("4 bytes"))
}

#[inline(always)]
fn read64(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(*b[i..].first_chunk::<8>().expect("8 bytes"))
}

/// zstd's `ZSTD_hashPtr` for 5 to 8 bytes.
#[inline(always)]
fn hash(v: u64, mls: u32, log: u32) -> usize {
    let p = match mls {
        5 => P5,
        6 => P6,
        7 => P7,
        _ => P8,
    };
    ((v << (64 - 8 * mls)).wrapping_mul(p) >> (64 - log)) as usize
}

/// Bytes equal at `a` and `b` (`a < b`), up to `max`.
#[inline(always)]
fn count(buf: &[u8], a: usize, b: usize, max: usize) -> usize {
    let (x, y) = (&buf[a..a + max], &buf[b..b + max]);
    let mut n = 0;
    while n + 8 <= max {
        let d = u64::from_le_bytes(*x[n..].first_chunk::<8>().expect("8 bytes")) ^ u64::from_le_bytes(*y[n..].first_chunk::<8>().expect("8 bytes"));
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

impl Fast {
    /// Skips faster through data without matches (a smaller `strength`).
    #[cfg(feature = "brotli")]
    pub(crate) fn with_strength(mut self, strength: u32) -> Fast {
        self.strength = strength;
        self
    }

    /// One table (`long_log == 0`) or two.
    pub(crate) fn new(max_dist: usize, small_log: u32, mls: u32, long_log: u32) -> Fast {
        Fast { small: Vec::new(), small_log, mls, long: Vec::new(), long_log, max_dist, rep: [1, 4], strength: 8 }
    }

    /// Parses `buf[from..to]` (`base` is the stream position of `buf[0]`) into `out`; matches
    /// never reach past `to`. Returns how many literals are left after the last match.
    /// The block must not be longer than the window (`to - from <= max_dist`).
    pub(crate) fn parse(&mut self, buf: &[u8], base: u64, from: usize, to: usize, out: &mut Vec<Seq>) -> usize {
        assert!(to - from <= self.max_dist, "block longer than the window");
        if self.small.is_empty() {
            self.small = vec![0; 1 << self.small_log];
            if self.long_log > 0 {
                self.long = vec![0; 1 << self.long_log];
            }
        }
        if simoom_sys::codec::fast() {
            let (tail, rep) = simoom_sys::codec::zstd_fast(simoom_sys::codec::FastIn {
                buf,
                base,
                from,
                to,
                small: &mut self.small,
                small_log: self.small_log,
                mls: self.mls,
                long: &mut self.long,
                long_log: self.long_log,
                max_dist: self.max_dist,
                rep: self.rep,
                strength: self.strength,
                out,
            });
            self.rep = rep;
            return tail;
        }
        if self.long_log > 0 {
            self.double(buf, base, from, to, out)
        } else {
            self.single(buf, base, from, to, out)
        }
    }

    /// Level 1, a port of zstd's `ZSTD_compressBlock_fast_noDict_generic`: positions in pairs
    /// (`ip0`, `ip1`), the last offset checked at `ip2`, the gap between pairs growing by one
    /// every 128 bytes without a match.
    fn single(&mut self, buf: &[u8], base: u64, from: usize, to: usize, out: &mut Vec<Seq>) -> usize {
        let (mls, slog) = (self.mls, self.small_log);
        let smask = self.small.len() - 1;
        let small = &mut self.small[..];
        let pos = |i: usize| (base + i as u64) as u32;
        let hash_at = |i: usize| hash(read64(buf, i), mls, slog) & smask;
        if to < from + 16 {
            return to - from;
        }
        // matches start no lower than this (the window from the block's end, as zstd's prefix)
        let low = to.saturating_sub(self.max_dist);
        let ilimit = to - 8;
        let mut anchor = from;
        let mut ip0 = from + (from == low) as usize;
        let [mut r0, mut r1] = self.rep;
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
            d != 0 && d <= ip - low && read32(buf, ip - d) == read32(buf, ip)
        };
        'start: loop {
            let mut step = 2;
            let mut next_step = ip0 + (1 << (self.strength - 1));
            let mut ip1 = ip0 + 1;
            let mut ip2 = ip0 + step;
            let mut ip3 = ip2 + 1;
            if ip3 >= ilimit {
                break;
            }
            let mut h0 = hash_at(ip0);
            let mut h1 = hash_at(ip1);
            let mut midx = small[h0];
            let cur0;
            let mut m0;
            let mut ml;
            let rep_match;
            loop {
                let mut c = ip0;
                small[h0] = pos(ip0);
                if r0 > 0 && read32(buf, ip2 - r0 as usize) == read32(buf, ip2) {
                    cur0 = c;
                    ip0 = ip2;
                    m0 = ip0 - r0 as usize;
                    ml = (m0 > low && buf[ip0 - 1] == buf[m0 - 1]) as usize;
                    ip0 -= ml;
                    m0 -= ml;
                    ml += 4;
                    small[h1] = pos(ip1);
                    rep_match = true;
                    break;
                }
                if found(ip0, midx) {
                    cur0 = c;
                    small[h1] = pos(ip1);
                    m0 = 0;
                    ml = 0;
                    rep_match = false;
                    break;
                }
                midx = small[h1];
                h0 = h1;
                h1 = hash_at(ip2);
                ip0 = ip1;
                ip1 = ip2;
                ip2 = ip3;
                c = ip0;
                small[h0] = pos(ip0);
                if found(ip0, midx) {
                    cur0 = c;
                    if step <= 4 {
                        small[h1] = pos(ip1);
                    }
                    m0 = 0;
                    ml = 0;
                    rep_match = false;
                    break;
                }
                midx = small[h1];
                h0 = h1;
                h1 = hash_at(ip2);
                ip0 = ip1;
                ip1 = ip2;
                ip2 = ip0 + step;
                ip3 = ip1 + step;
                if ip2 >= next_step {
                    step += 1;
                    next_step += 1 << (self.strength - 1);
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
                while ip0 > anchor && m0 > low && buf[ip0 - 1] == buf[m0 - 1] {
                    ip0 -= 1;
                    m0 -= 1;
                    ml += 1;
                }
            }
            ml += count(buf, m0 + ml, ip0 + ml, to - ip0 - ml);
            out.push(Seq { lit: (ip0 - anchor) as u32, len: ml as u32, dist: (ip0 - m0) as u32 });
            ip0 += ml;
            anchor = ip0;
            if ip0 <= ilimit {
                small[hash_at(cur0 + 2)] = pos(cur0 + 2);
                small[hash_at(ip0 - 2)] = pos(ip0 - 2);
                // the second-to-last offset right away (no literals in between)
                while r1 > 0 && ip0 <= ilimit && read32(buf, ip0) == read32(buf, ip0 - r1 as usize) {
                    let r = r1 as usize;
                    let ml = 4 + count(buf, ip0 + 4 - r, ip0 + 4, to - ip0 - 4);
                    std::mem::swap(&mut r0, &mut r1);
                    small[hash_at(ip0)] = pos(ip0);
                    out.push(Seq { lit: 0, len: ml as u32, dist: r as u32 });
                    ip0 += ml;
                    anchor = ip0;
                }
            }
        }
        // offsets set aside as out of the window come back (zstd's offsetSaved logic)
        saved1 = if saved0 != 0 && r0 != 0 { saved0 } else { saved1 };
        self.rep = [if r0 != 0 { r0 } else { saved0 }, if r1 != 0 { r1 } else { saved1 }];
        to - anchor
    }

    fn double(&mut self, buf: &[u8], base: u64, from: usize, to: usize, out: &mut Vec<Seq>) -> usize {
        let (mls, slog, llog) = (self.mls, self.small_log, self.long_log);
        let (smask, lmask) = (self.small.len() - 1, self.long.len() - 1);
        let small = &mut self.small[..];
        let long = &mut self.long[..];
        let [mut r0, mut r1] = self.rep;
        let pos = |i: usize| (base + i as u64) as u32;
        let lowest = |i: usize| i.saturating_sub(self.max_dist);
        let mut anchor = from;
        let mut ip = from + (from == 0) as usize;
        if to < 9 {
            return to - from;
        }
        let ilimit = to - 9;
        while ip < ilimit {
            let v = read64(buf, ip);
            let hl = hash(v, 8, llog) & lmask;
            let hs = hash(v, mls, slog) & smask;
            let cl = long[hl];
            let cs = small[hs];
            long[hl] = pos(ip);
            small[hs] = pos(ip);
            let low = lowest(ip);
            let start;
            let ml;
            let r = r0 as usize;
            if r > 0 && ip + 1 - lowest(ip + 1) >= r && read32(buf, ip + 1 - r) == read32(buf, ip + 1) {
                start = ip + 1;
                ml = 4 + count(buf, start + 4 - r, start + 4, to - start - 4);
                out.push(Seq { lit: (start - anchor) as u32, len: ml as u32, dist: r as u32 });
            } else {
                let dl = pos(ip).wrapping_sub(cl) as usize;
                let ds = pos(ip).wrapping_sub(cs) as usize;
                let (mut s, d, mut len);
                if dl != 0 && dl <= ip - low && read64(buf, ip - dl) == v {
                    s = ip;
                    d = dl;
                    len = 8 + count(buf, ip + 8 - dl, ip + 8, to - ip - 8);
                } else if ds != 0 && ds <= ip - low && read32(buf, ip - ds) == v as u32 {
                    // a long match one byte ahead beats the short one
                    let v1 = read64(buf, ip + 1);
                    let hl1 = hash(v1, 8, llog) & lmask;
                    let cl1 = long[hl1];
                    long[hl1] = pos(ip + 1);
                    let dl1 = pos(ip + 1).wrapping_sub(cl1) as usize;
                    if dl1 != 0 && dl1 <= ip + 1 - lowest(ip + 1) && read64(buf, ip + 1 - dl1) == v1 {
                        s = ip + 1;
                        d = dl1;
                        len = 8 + count(buf, ip + 9 - dl1, ip + 9, to - ip - 9);
                    } else {
                        s = ip;
                        d = ds;
                        len = 4 + count(buf, ip + 4 - ds, ip + 4, to - ip - 4);
                    }
                } else {
                    ip += ((ip - anchor) >> self.strength) + 1;
                    continue;
                }
                let mut m = s - d;
                let low = lowest(s);
                while s > anchor && m > low && buf[s - 1] == buf[m - 1] {
                    s -= 1;
                    m -= 1;
                    len += 1;
                }
                start = s;
                ml = len;
                r1 = r0;
                r0 = d as u32;
                out.push(Seq { lit: (start - anchor) as u32, len: ml as u32, dist: d as u32 });
            }
            ip = start + ml;
            anchor = ip;
            if ip <= ilimit {
                // index positions of the match
                let p2 = start + 2;
                let v2 = read64(buf, p2);
                long[hash(v2, 8, llog) & lmask] = pos(p2);
                small[hash(v2, mls, slog) & smask] = pos(p2);
                let v3 = read64(buf, ip - 2);
                long[hash(v3, 8, llog) & lmask] = pos(ip - 2);
                small[hash(v3, mls, slog) & smask] = pos(ip - 2);
                long[hash(read64(buf, ip - 1), 8, llog) & lmask] = pos(ip - 1);
                while ip <= ilimit {
                    let r = r1 as usize;
                    if r == 0 || ip - lowest(ip) < r || read32(buf, ip - r) != read32(buf, ip) {
                        break;
                    }
                    let ml = 4 + count(buf, ip + 4 - r, ip + 4, to - ip - 4);
                    std::mem::swap(&mut r0, &mut r1);
                    let v = read64(buf, ip);
                    small[hash(v, mls, slog) & smask] = pos(ip);
                    long[hash(v, 8, llog) & lmask] = pos(ip);
                    out.push(Seq { lit: 0, len: ml as u32, dist: r as u32 });
                    ip += ml;
                    anchor = ip;
                }
            }
        }
        self.rep = [r0, r1];
        to - anchor
    }
}
