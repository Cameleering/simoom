//! A set of disjoint half-open `u64` ranges, kept sorted. Used for ACK ranges, received
//! packet numbers and stream retransmission bookkeeping.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet {
    r: Vec<(u64, u64)>,
}

impl RangeSet {
    pub fn new() -> Self {
        RangeSet { r: Vec::new() }
    }
    pub fn is_empty(&self) -> bool {
        self.r.is_empty()
    }
    /// Number of disjoint ranges.
    pub fn len(&self) -> usize {
        self.r.len()
    }
    pub fn min(&self) -> Option<u64> {
        self.r.first().map(|x| x.0)
    }
    /// The largest contained value.
    pub fn max(&self) -> Option<u64> {
        self.r.last().map(|x| x.1 - 1)
    }
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u64, u64)> + '_ {
        self.r.iter().copied()
    }
    pub fn first(&self) -> Option<(u64, u64)> {
        self.r.first().copied()
    }
    pub fn contains(&self, v: u64) -> bool {
        match self.r.binary_search_by(|&(s, _)| s.cmp(&v)) {
            Ok(_) => true,
            Err(0) => false,
            Err(i) => v < self.r[i - 1].1,
        }
    }
    /// True if all of `[s, e)` is in the set.
    pub fn contains_range(&self, s: u64, e: u64) -> bool {
        if s >= e {
            return true;
        }
        match self.r.binary_search_by(|&(x, _)| x.cmp(&s)) {
            Ok(i) => e <= self.r[i].1,
            Err(0) => false,
            Err(i) => e <= self.r[i - 1].1,
        }
    }
    /// Inserts `[s, e)`; returns true if anything new was added.
    pub fn insert(&mut self, s: u64, e: u64) -> bool {
        if s >= e {
            return false;
        }
        // Fast path: append at the end (the common in-order case).
        if let Some(last) = self.r.last_mut() {
            if s > last.1 {
                self.r.push((s, e));
                return true;
            }
            if s >= last.0 {
                if e <= last.1 {
                    return false;
                }
                last.1 = e;
                return true;
            }
        } else {
            self.r.push((s, e));
            return true;
        }
        // First range whose end >= s.
        let i = self.r.partition_point(|&(_, end)| end < s);
        let mut j = i;
        let (mut ns, mut ne) = (s, e);
        while j < self.r.len() && self.r[j].0 <= e {
            ns = ns.min(self.r[j].0);
            ne = ne.max(self.r[j].1);
            j += 1;
        }
        if j == i + 1 && self.r[i] == (ns, ne) {
            return false;
        }
        self.r.splice(i..j, std::iter::once((ns, ne)));
        true
    }
    /// Removes `[s, e)`.
    pub fn remove(&mut self, s: u64, e: u64) {
        if s >= e || self.r.is_empty() {
            return;
        }
        let mut out = Vec::with_capacity(self.r.len() + 1);
        for &(a, b) in &self.r {
            if b <= s || a >= e {
                out.push((a, b));
            } else {
                if a < s {
                    out.push((a, s));
                }
                if b > e {
                    out.push((e, b));
                }
            }
        }
        self.r = out;
    }
    /// Removes everything below `v`.
    pub fn remove_below(&mut self, v: u64) {
        let i = self.r.partition_point(|&(_, e)| e <= v);
        self.r.drain(..i);
        if let Some(f) = self.r.first_mut() {
            if f.0 < v {
                f.0 = v;
            }
        }
    }
    /// Drops the lowest ranges so at most `n` remain.
    pub fn truncate_low(&mut self, n: usize) {
        if self.r.len() > n {
            let k = self.r.len() - n;
            self.r.drain(..k);
        }
    }
    /// Removes and returns the lowest range, clipped to at most `max_len` values.
    pub fn pop_min(&mut self, max_len: u64) -> Option<(u64, u64)> {
        let f = self.r.first_mut()?;
        let (s, e) = *f;
        if e - s > max_len {
            f.0 = s + max_len;
            Some((s, s + max_len))
        } else {
            self.r.remove(0);
            Some((s, e))
        }
    }
    pub fn clear(&mut self) {
        self.r.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_merge_remove() {
        let mut s = RangeSet::new();
        assert!(s.insert(10, 20));
        assert!(s.insert(30, 40));
        assert!(!s.insert(12, 15));
        assert!(s.insert(5, 10));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![(5, 20), (30, 40)]);
        assert!(s.insert(20, 30));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![(5, 40)]);
        s.remove(10, 12);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![(5, 10), (12, 40)]);
        assert!(s.contains(5) && !s.contains(10) && s.contains(39) && !s.contains(40));
        assert!(s.contains_range(12, 40) && !s.contains_range(9, 13));
        s.remove_below(13);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![(13, 40)]);
        assert_eq!(s.pop_min(5), Some((13, 18)));
        assert_eq!(s.max(), Some(39));
        let mut t = RangeSet::new();
        for i in (0..100).rev().step_by(2) {
            t.insert(i, i + 1);
        }
        assert_eq!(t.len(), 50);
        t.insert(0, 100);
        assert_eq!(t.len(), 1);
    }
}
