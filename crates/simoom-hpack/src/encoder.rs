//! The header block encoder (RFC 7541 §6, §7.1).

use crate::table::{static_name, DynTable, Name, STATIC_TABLE};
use crate::{bytes_eq, encode_integer, encode_string, field_size, DEFAULT_TABLE_SIZE};

/// Fields whose values must never enter a compression context (RFC 7541 §7.1.3): they are
/// sent as never-indexed literals, so intermediaries keep them out of their tables too.
pub fn is_sensitive(name: &[u8]) -> bool {
    matches!(name, b"authorization" | b"proxy-authorization" | b"cookie" | b"set-cookie")
}

/// Static indices (bits of a mask) of the sensitive names: `authorization` (23), `cookie` (32),
/// `proxy-authorization` (49), `set-cookie` (55). They are all in the static table.
const SENSITIVE: u64 = 1 << 23 | 1 << 32 | 1 << 49 | 1 << 55;

/// Static indices of names whose values rarely repeat: `age` (21), `content-length` (28),
/// `content-range` (30), `etag` (34), `if-match` (39), `if-modified-since` (40),
/// `if-none-match` (41), `last-modified` (44), `location` (46).
const RARE: u64 = 1 << 21 | 1 << 28 | 1 << 30 | 1 << 34 | 1 << 39 | 1 << 40 | 1 << 41 | 1 << 44 | 1 << 46;

/// Fields whose values rarely repeat on a connection: indexing them would only churn the table.
/// `idx` is the name's first static index (0: not in the table).
fn rarely_repeats(idx: usize, name: &[u8], value: &[u8]) -> bool {
    match idx {
        4 => value.len() > 64 || value.contains(&b'?'), // :path
        0 => matches!(name, b"x-request-id" | b"traceparent" | b"tracestate"),
        i => RARE >> i & 1 != 0,
    }
}

/// A stateful header block encoder.
///
/// Exact static or dynamic matches are sent as indexed fields; other fields are literals with
/// incremental indexing, except sensitive fields (never indexed), fields whose values rarely
/// repeat, and fields larger than half the table (without indexing). Strings are Huffman coded
/// when that is shorter.
#[derive(Debug, Clone)]
pub struct Encoder {
    table: DynTable,
    /// The largest table we are willing to keep, whatever the peer allows.
    limit: usize,
    /// Smallest size the table passed through since the last block, and whether an update is due.
    pending_min: usize,
    pending: bool,
    /// Use Huffman coding when it is shorter (default true).
    pub huffman: bool,
    /// Add literals to the dynamic table (default true).
    pub indexing: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Encoder::new(DEFAULT_TABLE_SIZE)
    }
}

impl Encoder {
    /// An encoder that keeps at most `limit` bytes of dynamic table. The peer's table starts at
    /// 4096 (the protocol default); a smaller limit is announced in the first block.
    pub fn new(limit: usize) -> Self {
        let size = limit.min(DEFAULT_TABLE_SIZE);
        Encoder {
            table: DynTable::new(size),
            limit,
            pending_min: size,
            pending: size != DEFAULT_TABLE_SIZE,
            huffman: true,
            indexing: true,
        }
    }

    /// Applies the peer's SETTINGS_HEADER_TABLE_SIZE. The encoder uses the smaller of that and
    /// its own limit, and announces the change at the start of the next block.
    pub fn set_peer_max_table_size(&mut self, peer: usize) {
        let size = peer.min(self.limit);
        if size != self.table.max() {
            self.pending_min = self.pending_min.min(size);
            self.pending = true;
            self.table.set_max(size);
        }
    }

    /// Current dynamic table size in octets.
    pub fn table_size(&self) -> usize {
        self.table.size()
    }

    /// Number of dynamic table entries.
    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    /// Starts a header block: emits any pending dynamic table size updates (RFC 7541 §4.2).
    pub fn begin_block(&mut self, out: &mut Vec<u8>) {
        if self.pending {
            let max = self.table.max();
            if self.pending_min < max {
                encode_integer(self.pending_min, 5, 0x20, out);
            }
            encode_integer(max, 5, 0x20, out);
            self.pending = false;
            self.pending_min = max;
        }
    }

    /// Encodes a whole header block.
    pub fn encode(&mut self, fields: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
        self.begin_block(out);
        for (n, v) in fields {
            self.field(n, v, out);
        }
    }

    /// Encodes one field of the current block (after [`Encoder::begin_block`]).
    pub fn field(&mut self, name: &[u8], value: &[u8], out: &mut Vec<u8>) {
        let mut name_idx = 0usize;
        if let Some((first, count)) = static_name(name) {
            name_idx = first;
            for i in first..first + count {
                if bytes_eq(STATIC_TABLE[i - 1].1, value) {
                    encode_integer(i, 7, 0x80, out);
                    return;
                }
            }
        }
        let static_idx = name_idx;
        // the same as `is_sensitive(name)`, from the static index
        let sensitive = SENSITIVE >> static_idx & 1 != 0;
        let (full, by_name) = self.table.find(name, value);
        if let (Some(i), false) = (full, sensitive) {
            encode_integer(STATIC_TABLE.len() + 1 + i, 7, 0x80, out);
            return;
        }
        if let (0, Some(i)) = (name_idx, by_name) {
            name_idx = STATIC_TABLE.len() + 1 + i;
        }
        let index = self.indexing
            && !sensitive
            && !rarely_repeats(static_idx, name, value)
            && field_size(name, value) <= self.table.max() / 2;
        let (prefix, first) = if sensitive {
            (4, 0x10)
        } else if index {
            (6, 0x40)
        } else {
            (4, 0x00)
        };
        encode_integer(name_idx, prefix, first, out);
        if name_idx == 0 {
            encode_string(name, self.huffman, out);
        }
        encode_string(value, self.huffman, out);
        if index {
            self.table.insert(Name::Bytes(name), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The index masks agree with the names they stand for.
    #[test]
    fn masks_match_the_names() {
        let rare: [&[u8]; 9] = [b"content-length", b"content-range", b"etag", b"if-none-match", b"if-modified-since", b"if-match", b"last-modified", b"age", b"location"];
        for (i, (n, _)) in STATIC_TABLE.iter().enumerate() {
            let first = static_name(n).unwrap().0;
            if first != i + 1 {
                continue;
            }
            assert_eq!(SENSITIVE >> first & 1 != 0, is_sensitive(n), "{}", String::from_utf8_lossy(n));
            if first != 4 {
                assert_eq!(rarely_repeats(first, n, b"x"), rare.contains(n), "{}", String::from_utf8_lossy(n));
            }
        }
        assert!(rarely_repeats(4, b":path", b"/a?b=1"));
        assert!(!rarely_repeats(4, b":path", b"/a"));
        for n in [&b"x-request-id"[..], b"traceparent", b"tracestate"] {
            assert!(rarely_repeats(0, n, b"1"));
        }
        assert!(!rarely_repeats(0, b"x-other", b"1"));
    }
}
