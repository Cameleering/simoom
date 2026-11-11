//! An LZ77 match finder for the Brotli and zstd encoders: a 4-byte hash with optional hash
//! chains (bounded to 128 Ki entries) and an optional one-step lazy evaluation. Positions are
//! stored as 32-bit stream positions, so the buffer can slide without rewriting the tables;
//! every candidate is verified byte by byte.

/// One match: `lit` literals, then `len` bytes from `dist` back.
pub(crate) use simoom_sys::codec::Match as Seq;

pub(crate) struct Lz {
    pub(crate) buf: Vec<u8>,
    /// Stream position of `buf[0]`.
    pub(crate) base: u64,
    head: Vec<u32>,
    chain: Vec<u32>,
    hbits: u32,
    cmask: usize,
    depth: u32,
    lazy: bool,
    nice: usize,
    /// Skip ahead faster through data without matches (the fast levels).
    skip: bool,
    pub(crate) max_dist: usize,
    max_len: usize,
}

impl Lz {
    pub(crate) fn new(max_dist: usize, hbits: u32, depth: u32, lazy: bool, nice: usize, skip: bool, max_len: usize) -> Lz {
        let clog = if depth > 1 { (usize::BITS - max_dist.leading_zeros()).min(17) } else { 0 };
        Lz {
            buf: Vec::new(),
            base: 0,
            head: Vec::new(),
            chain: if depth > 1 { vec![0; 1 << clog] } else { Vec::new() },
            hbits,
            cmask: (1usize << clog).wrapping_sub(1),
            depth: depth.max(1),
            lazy,
            nice,
            skip,
            max_dist,
            max_len,
        }
    }

    #[inline(always)]
    fn hash(&self, i: usize) -> usize {
        let b = &self.buf[i..i + 4];
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - self.hbits)) as usize
    }

    /// Records position `i` and returns the previous head of its hash.
    #[inline(always)]
    fn insert(&mut self, i: usize) -> u32 {
        if self.head.is_empty() {
            self.head = vec![0; 1 << self.hbits];
        }
        let h = self.hash(i);
        let p = (self.base + i as u64) as u32;
        let c = self.head[h];
        self.head[h] = p;
        if !self.chain.is_empty() {
            self.chain[p as usize & self.cmask] = c;
        }
        c
    }

    fn longest(&self, i: usize, mut c: u32, to: usize) -> (usize, usize) {
        let max_len = (to - i).min(self.max_len);
        if max_len < 4 {
            return (0, 0);
        }
        let p = (self.base + i as u64) as u32;
        let (mut best, mut bd) = (3usize, 0usize);
        let lim = self.max_dist.min(i);
        let buf = &self.buf[..];
        let mut d = p.wrapping_sub(c) as usize;
        for _ in 0..self.depth {
            if d == 0 || d > lim {
                break;
            }
            let j = i - d;
            if buf[j + best] == buf[i + best] && buf[j] == buf[i] {
                let l = match_len(buf, j, i, max_len);
                if l > best {
                    best = l;
                    bd = d;
                    if l >= self.nice || l == max_len {
                        break;
                    }
                }
            }
            if self.chain.is_empty() {
                break;
            }
            c = self.chain[c as usize & self.cmask];
            let nd = p.wrapping_sub(c) as usize;
            if nd <= d {
                break;
            }
            d = nd;
        }
        if bd == 0 {
            (0, 0)
        } else {
            (best, bd)
        }
    }

    /// Parses `buf[from..to]` into `out`; matches never reach past `to`. Returns how many
    /// literals are left after the last match.
    pub(crate) fn parse(&mut self, from: usize, to: usize, out: &mut Vec<Seq>) -> usize {
        let mut i = from;
        let mut lit_start = from;
        let mut misses = 0usize;
        while i + 4 <= to {
            let c = self.insert(i);
            let (mut len, mut dist) = self.longest(i, c, to);
            if len < 4 {
                misses += 1;
                i += if self.skip { 1 + (misses >> 6) } else { 1 };
                continue;
            }
            let mut probed = false;
            if self.lazy && len < self.nice && i + 5 <= to {
                let c2 = self.insert(i + 1);
                let (l2, d2) = self.longest(i + 1, c2, to);
                if l2 > len {
                    i += 1;
                    len = l2;
                    dist = d2;
                } else {
                    probed = true;
                }
            }
            out.push(Seq { lit: (i - lit_start) as u32, len: len as u32, dist: dist as u32 });
            // index the positions the match covers (a sample of long ones)
            let end = (i + len).min(to.saturating_sub(3));
            let mut q = i + 1 + probed as usize;
            let step = if len > 64 { len / 8 } else { 1 };
            while q < end {
                self.insert(q);
                q += step;
            }
            i += len;
            lit_start = i;
            misses = 0;
        }
        to - lit_start
    }

    /// Drops `buf[..n]`.
    pub(crate) fn slide(&mut self, n: usize) {
        self.buf.drain(..n);
        self.base += n as u64;
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
