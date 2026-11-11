//! The static table (RFC 7541 Appendix A) and the dynamic table (§2.3.2, §4).

use std::collections::VecDeque;

use crate::bytes_eq;

/// The static table, 1-based in the protocol (index `i` is `STATIC_TABLE[i - 1]`).
pub static STATIC_TABLE: [(&[u8], &[u8]); 61] = STATIC_ENTRIES;

/// [`STATIC_TABLE`] as a constant, for the name lookup built at compile time.
const STATIC_ENTRIES: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// The longest name in the static table (`access-control-allow-origin`).
const MAX_NAME: usize = 27;

/// The static names by length, built at compile time: `NAMES.0[NAMES.1[n]..NAMES.1[n + 1]]`
/// holds (first index, entries) of each distinct name of length `n`. A lookup compares a few
/// names of the right length; a `match` on the names cost about 2 KB of code per caller.
static NAMES: ([(u8, u8); 61], [u8; MAX_NAME + 2]) = names_by_len();

const fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn names_by_len() -> ([(u8, u8); 61], [u8; MAX_NAME + 2]) {
    let t = &STATIC_ENTRIES;
    let mut names = [(0u8, 0u8); 61];
    let mut starts = [0u8; MAX_NAME + 2];
    let mut k = 0;
    let mut len = 0;
    while len <= MAX_NAME {
        starts[len] = k as u8;
        let mut i = 0;
        while i < t.len() {
            assert!(t[i].0.len() <= MAX_NAME);
            if t[i].0.len() == len && (i == 0 || !same(t[i - 1].0, t[i].0)) {
                let mut n = 1;
                while i + n < t.len() && same(t[i + n].0, t[i].0) {
                    n += 1;
                }
                names[k] = (i as u8 + 1, n as u8);
                k += 1;
            }
            i += 1;
        }
        len += 1;
    }
    starts[MAX_NAME + 1] = k as u8;
    (names, starts)
}

/// The 1-based static indices that carry `name`: (first, count).
pub(crate) fn static_name(name: &[u8]) -> Option<(usize, usize)> {
    let n = name.len();
    if n > MAX_NAME {
        return None;
    }
    let (names, starts) = &NAMES;
    for &(first, count) in &names[starts[n] as usize..starts[n + 1] as usize] {
        if bytes_eq(STATIC_TABLE[first as usize - 1].0, name) {
            return Some((first as usize, count as usize));
        }
    }
    None
}

/// A dynamic table entry: offset of the name in the byte buffer, name and value lengths.
#[derive(Clone, Copy, Debug)]
struct Entry {
    off: u32,
    name: u32,
    value: u32,
}

/// Where the name of a new entry comes from.
pub(crate) enum Name<'a> {
    Bytes(&'a [u8]),
    /// An existing dynamic entry (0 = newest); copied before it can be evicted.
    Dyn(usize),
}

/// The dynamic table. All names and values live back to back in one byte buffer that only
/// grows at the end; evicting moves no bytes, and the dead prefix is dropped once it is larger
/// than the live part, so inserts do not allocate in steady state and the buffer stays below
/// about twice the maximum size.
#[derive(Debug, Clone)]
pub(crate) struct DynTable {
    buf: Vec<u8>,
    entries: VecDeque<Entry>, // front = newest
    size: usize,
    max: usize,
}

impl DynTable {
    pub(crate) fn new(max: usize) -> Self {
        DynTable { buf: Vec::new(), entries: VecDeque::new(), size: 0, max }
    }

    pub(crate) fn size(&self) -> usize {
        self.size
    }

    pub(crate) fn max(&self) -> usize {
        self.max
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub(crate) fn get(&self, i: usize) -> Option<(&[u8], &[u8])> {
        let e = self.entries.get(i)?;
        let (o, n, v) = (e.off as usize, e.name as usize, e.value as usize);
        Some((&self.buf[o..o + n], &self.buf[o + n..o + n + v]))
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.size = 0;
        self.buf.clear();
    }

    pub(crate) fn set_max(&mut self, max: usize) {
        self.max = max;
        self.evict(0);
        if self.entries.is_empty() {
            self.buf.clear();
        }
    }

    fn evict(&mut self, incoming: usize) {
        while self.size + incoming > self.max {
            match self.entries.pop_back() {
                Some(e) => self.size -= e.name as usize + e.value as usize + 32,
                None => break,
            }
        }
    }

    pub(crate) fn insert(&mut self, name: Name<'_>, value: &[u8]) {
        let nlen = match name {
            Name::Bytes(b) => b.len(),
            Name::Dyn(i) => self.entries[i].name as usize,
        };
        let s = nlen + value.len() + 32;
        if s > self.max {
            // RFC 7541 §4.4: an entry larger than the table empties it
            self.entries.clear();
            self.size = 0;
            self.buf.clear();
            return;
        }
        // Append first (a dynamic name is copied while its entry still exists), then evict:
        // eviction never moves bytes.
        let off = self.buf.len();
        match name {
            Name::Bytes(b) => self.buf.extend_from_slice(b),
            Name::Dyn(i) => {
                let o = self.entries[i].off as usize;
                self.buf.extend_from_within(o..o + nlen);
            }
        }
        self.buf.extend_from_slice(value);
        self.evict(s);
        self.entries.push_front(Entry { off: off as u32, name: nlen as u32, value: value.len() as u32 });
        self.size += s;
        // drop the dead prefix once it outweighs the live bytes
        let start = self.entries.back().map_or(0, |e| e.off as usize);
        if start > 1024 && start * 2 > self.buf.len() {
            self.buf.drain(..start);
            for e in self.entries.iter_mut() {
                e.off -= start as u32;
            }
        }
    }

    /// Finds `name` (and `value`): (index of a full match, index of the first name match),
    /// 0-based from the newest entry. Lengths are compared before any bytes.
    #[inline]
    pub(crate) fn find(&self, name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
        let mut name_idx = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.name as usize != name.len() {
                continue;
            }
            let o = e.off as usize;
            if !bytes_eq(&self.buf[o..o + name.len()], name) {
                continue;
            }
            if e.value as usize == value.len() && bytes_eq(&self.buf[o + name.len()..o + name.len() + value.len()], value) {
                return (Some(i), Some(i));
            }
            name_idx.get_or_insert(i);
        }
        (None, name_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_lookup_matches_table() {
        for (i, (n, _)) in STATIC_TABLE.iter().enumerate() {
            let (first, count) = static_name(n).unwrap();
            assert!(first <= i + 1 && i + 1 < first + count, "{}", String::from_utf8_lossy(n));
            assert_eq!(STATIC_TABLE[first - 1].0, *n);
        }
        assert!(static_name(b"x-unknown").is_none());
        assert!(static_name(b":protocol").is_none());
    }

    #[test]
    fn eviction_and_compaction() {
        let mut t = DynTable::new(200);
        for i in 0..1000u32 {
            let v = format!("value-{i}");
            if i % 3 == 0 && t.len() > 0 {
                t.insert(Name::Dyn(t.len() - 1), v.as_bytes()); // name of the oldest entry
            } else {
                t.insert(Name::Bytes(b"name"), v.as_bytes());
            }
            assert!(t.size() <= 200);
            assert_eq!(t.get(0).unwrap(), (&b"name"[..], v.as_bytes()));
            assert!(t.buf.len() <= 2 * 200 + 2048);
        }
        // a name referring to the only entry, which the insert evicts
        let mut t = DynTable::new(60);
        t.insert(Name::Bytes(b"abcdefgh"), b"1");
        t.insert(Name::Dyn(0), b"2");
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(0).unwrap(), (&b"abcdefgh"[..], &b"2"[..]));
        t.insert(Name::Bytes(&[b'x'; 300]), b"");
        assert_eq!(t.len(), 0);
        assert_eq!(t.size(), 0);
        t.insert(Name::Bytes(b"a"), b"b");
        t.set_max(0);
        assert_eq!(t.len(), 0);
    }
}
