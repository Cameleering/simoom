//! The header block decoder (RFC 7541 §3, §6).

use crate::table::{DynTable, Name, STATIC_TABLE};
use crate::{decode_integer, field_size, read_string, Error};

/// A stateful header block decoder.
#[derive(Debug, Clone)]
pub struct Decoder {
    table: DynTable,
    /// Upper bound for dynamic table size updates: our SETTINGS_HEADER_TABLE_SIZE.
    max_allowed: usize,
    /// Cap on the decoded list (name + value + 32 per field).
    max_list: usize,
    name_buf: Vec<u8>,
    value_buf: Vec<u8>,
}

impl Decoder {
    /// A decoder whose dynamic table may grow to `max_table_size` (the value advertised in
    /// SETTINGS_HEADER_TABLE_SIZE) and whose decoded header lists are capped at `max_list_size`.
    pub fn new(max_table_size: usize, max_list_size: usize) -> Self {
        Decoder {
            table: DynTable::new(max_table_size),
            max_allowed: max_table_size,
            max_list: max_list_size,
            name_buf: Vec::new(),
            value_buf: Vec::new(),
        }
    }

    /// Changes the largest table size the peer may select (after our new SETTINGS were
    /// acknowledged). A smaller value shrinks the table at once.
    pub fn set_max_allowed(&mut self, max: usize) {
        self.max_allowed = max;
        if self.table.max() > max {
            self.table.set_max(max);
        }
    }

    /// Changes the header list cap.
    pub fn set_max_list_size(&mut self, max: usize) {
        self.max_list = max;
    }

    /// Current dynamic table size in octets (RFC 7541 §4.1).
    pub fn table_size(&self) -> usize {
        self.table.size()
    }

    /// Current dynamic table maximum (the last size update).
    pub fn table_max_size(&self) -> usize {
        self.table.max()
    }

    /// Number of dynamic table entries.
    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    /// Dynamic table entry `i` (0 = newest).
    pub fn table_entry(&self, i: usize) -> Option<(&[u8], &[u8])> {
        self.table.get(i)
    }

    #[inline]
    fn lookup(&self, idx: usize) -> Result<(&[u8], &[u8]), Error> {
        if idx == 0 {
            Err(Error::InvalidIndex)
        } else if idx <= STATIC_TABLE.len() {
            Ok(STATIC_TABLE[idx - 1])
        } else {
            self.table.get(idx - STATIC_TABLE.len() - 1).ok_or(Error::InvalidIndex)
        }
    }

    /// Decodes one complete header block, passing each field (name, value) to `emit` in order.
    ///
    /// When the list grows past the cap the rest of the block is still decoded, to keep the
    /// dynamic table in step, but not emitted, and [`Error::HeaderListTooLarge`] is returned.
    pub fn decode(&mut self, block: &[u8], emit: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), Error> {
        let mut pos = 0;
        let mut size = 0usize;
        let mut over = false;
        let mut seen_field = false;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                // indexed field (§6.1)
                let idx = decode_integer(block, &mut pos, 7)?;
                let (n, v) = self.lookup(idx)?;
                seen_field = true;
                size += field_size(n, v);
                if size > self.max_list {
                    over = true;
                }
                if !over {
                    emit(n, v);
                }
                continue;
            }
            if b & 0xe0 == 0x20 {
                // dynamic table size update (§6.3): only before the first field
                if seen_field {
                    return Err(Error::InvalidTableSizeUpdate);
                }
                let s = decode_integer(block, &mut pos, 5)?;
                if s > self.max_allowed {
                    return Err(Error::InvalidTableSizeUpdate);
                }
                self.table.set_max(s);
                continue;
            }
            // literals: with incremental indexing (01), without (0000), never indexed (0001)
            let indexing = b & 0x40 != 0;
            let idx = decode_integer(block, &mut pos, if indexing { 6 } else { 4 })?;
            seen_field = true;
            let dyn_name = idx > STATIC_TABLE.len();
            if dyn_name && idx - STATIC_TABLE.len() - 1 >= self.table.len() {
                return Err(Error::InvalidIndex);
            }
            let lit_name: &[u8] = if idx == 0 { read_string(block, &mut pos, &mut self.name_buf)? } else { &[] };
            let value = read_string(block, &mut pos, &mut self.value_buf)?;
            let name: &[u8] = if idx == 0 {
                lit_name
            } else if dyn_name {
                self.table.get(idx - STATIC_TABLE.len() - 1).map_or(&[][..], |e| e.0)
            } else {
                STATIC_TABLE[idx - 1].0
            };
            size += field_size(name, value);
            if size > self.max_list {
                over = true;
            }
            if !indexing || field_size(name, value) > self.table.max() {
                // emit from the sources; an oversized entry then just empties the table
                if !over {
                    emit(name, value);
                }
                if indexing {
                    self.table.clear(); // RFC 7541 §4.4
                }
                continue;
            }
            let src = if idx == 0 {
                Name::Bytes(lit_name)
            } else if dyn_name {
                Name::Dyn(idx - STATIC_TABLE.len() - 1)
            } else {
                Name::Bytes(STATIC_TABLE[idx - 1].0)
            };
            self.table.insert(src, value);
            if !over {
                if let Some((n, v)) = self.table.get(0) {
                    emit(n, v);
                }
            }
        }
        if over {
            Err(Error::HeaderListTooLarge)
        } else {
            Ok(())
        }
    }
}
