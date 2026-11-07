//! Per-loop buffer pool in size classes.
//!
//! Buffers are plain `Vec<u8>`s whose capacity is exactly one of the class sizes. [`BufPool::get`]
//! hands out an empty buffer of the smallest class that fits; [`BufPool::put`] takes it back for
//! reuse, up to a cap per class (beyond that, or for a capacity that is not a class size, the
//! buffer is freed). A pool belongs to one loop thread, so there is no locking.

/// Default class sizes: 2 KiB, 16 KiB, 64 KiB.
pub const DEFAULT_CLASSES: [usize; 3] = [2048, 16 * 1024, 64 * 1024];

/// Counters of a [`BufPool`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Buffers handed out that were newly allocated.
    pub allocated: u64,
    /// Buffers handed out that were reused from the pool.
    pub reused: u64,
    /// Buffers taken back and kept.
    pub returned: u64,
    /// Buffers taken back and freed (pool full or odd size).
    pub freed: u64,
    /// Buffers kept in the pool now.
    pub cached: usize,
    /// Bytes kept in the pool now.
    pub cached_bytes: usize,
}

/// A pool of byte buffers in size classes. See the [module docs](self).
#[derive(Debug)]
pub struct BufPool {
    classes: [usize; 3],
    free: [Vec<Vec<u8>>; 3],
    max_cached: [usize; 3],
    stats: PoolStats,
}

impl BufPool {
    /// A pool with the given class sizes (ascending) and at most `max_cached` buffers kept per
    /// class (the larger classes keep a quarter and a sixteenth of that).
    pub fn new(classes: [usize; 3], max_cached: usize) -> BufPool {
        assert!(classes[0] > 0 && classes[0] < classes[1] && classes[1] < classes[2], "class sizes must ascend");
        BufPool {
            classes,
            free: [Vec::new(), Vec::new(), Vec::new()],
            max_cached: [max_cached, (max_cached / 4).max(1), (max_cached / 16).max(1)],
            stats: PoolStats::default(),
        }
    }

    /// The class sizes.
    pub fn classes(&self) -> [usize; 3] {
        self.classes
    }

    /// An empty buffer with capacity of at least `min` bytes: the smallest class that fits, or
    /// exactly `min` when it is larger than every class.
    #[inline]
    pub fn get(&mut self, min: usize) -> Vec<u8> {
        for (i, &size) in self.classes.iter().enumerate() {
            if min <= size {
                if let Some(b) = self.free[i].pop() {
                    self.stats.reused += 1;
                    self.stats.cached -= 1;
                    self.stats.cached_bytes -= size;
                    return b;
                }
                self.stats.allocated += 1;
                return Vec::with_capacity(size);
            }
        }
        self.stats.allocated += 1;
        Vec::with_capacity(min)
    }

    /// Takes a buffer back. It is cleared and kept if its capacity is a class size and that
    /// class is not full; otherwise it is freed.
    #[inline]
    pub fn put(&mut self, mut buf: Vec<u8>) {
        let cap = buf.capacity();
        for (i, &size) in self.classes.iter().enumerate() {
            if cap == size {
                if self.free[i].len() < self.max_cached[i] {
                    buf.clear();
                    self.free[i].push(buf);
                    self.stats.returned += 1;
                    self.stats.cached += 1;
                    self.stats.cached_bytes += size;
                } else {
                    self.stats.freed += 1;
                }
                return;
            }
        }
        self.stats.freed += 1;
    }

    /// Frees cached buffers until at most `keep` remain in each class (for trimming after a
    /// burst).
    pub fn trim(&mut self, keep: usize) {
        for i in 0..3 {
            while self.free[i].len() > keep {
                self.free[i].pop();
                self.stats.cached -= 1;
                self.stats.cached_bytes -= self.classes[i];
                self.stats.freed += 1;
            }
        }
    }

    /// Counters.
    pub fn stats(&self) -> PoolStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_buffers_by_class() {
        let mut p = BufPool::new(DEFAULT_CLASSES, 4);
        let a = p.get(100);
        assert_eq!(a.capacity(), 2048);
        let a_ptr = a.as_ptr();
        p.put(a);
        let mut b = p.get(2048);
        assert_eq!(b.as_ptr(), a_ptr, "the same allocation comes back");
        b.extend_from_slice(b"dirty");
        p.put(b);
        let c = p.get(1);
        assert!(c.is_empty(), "returned buffers are cleared");
        assert_eq!(p.get(3000).capacity(), 16 * 1024);
        assert_eq!(p.get(70_000).capacity(), 70_000);
        let s = p.stats();
        assert_eq!((s.allocated, s.reused), (3, 2));
    }

    #[test]
    fn caps_the_cache_and_frees_odd_sizes() {
        let mut p = BufPool::new(DEFAULT_CLASSES, 2);
        let bufs: Vec<Vec<u8>> = (0..5).map(|_| p.get(10)).collect();
        for b in bufs {
            p.put(b);
        }
        assert_eq!(p.stats().cached, 2);
        assert_eq!(p.stats().freed, 3);
        p.put(Vec::with_capacity(100));
        assert_eq!(p.stats().freed, 4);
        assert_eq!(p.stats().cached_bytes, 4096);
        p.trim(0);
        assert_eq!(p.stats().cached, 0);
    }
}
