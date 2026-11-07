//! QPACK decoder (RFC 9204 sections 3, 4.3, 4.4 and 4.5).

use std::collections::VecDeque;

use crate::prim::{get_int, get_span, put_int, span_bytes, Short, STATIC_TABLE};
use crate::{Error, Field};

/// Result of decoding a field section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// The decoded field lines.
    Fields(Vec<Field>),
    /// The section references entries not yet received; it is kept and returned by
    /// [`Decoder::on_encoder_stream`] once they arrive.
    Blocked,
}

/// A QPACK decoder for one HTTP/3 connection.
#[derive(Debug)]
pub struct Decoder {
    max_cap: u64,
    max_blocked: u64,
    max_section: u64,
    cap: u64,
    size: u64,
    entries: VecDeque<Field>,
    inserted: u64,
    /// Insert count the encoder knows we have (Section Acks and Insert Count Increments sent).
    acked: u64,
    blocked: Vec<(u64, u64, Vec<u8>)>,
    enc_buf: Vec<u8>,
    out: Vec<u8>,
}

impl Decoder {
    /// `max_table_capacity` and `max_blocked_streams` are the values announced in our SETTINGS
    /// (SETTINGS_QPACK_MAX_TABLE_CAPACITY, SETTINGS_QPACK_BLOCKED_STREAMS);
    /// `max_field_section_size` bounds each decoded section (RFC 9114 4.2.2).
    pub fn new(max_table_capacity: u64, max_blocked_streams: u64, max_field_section_size: u64) -> Self {
        Decoder {
            max_cap: max_table_capacity.min(crate::MAX_INT),
            max_blocked: max_blocked_streams,
            max_section: max_field_section_size,
            cap: 0,
            size: 0,
            entries: VecDeque::new(),
            inserted: 0,
            acked: 0,
            blocked: Vec::new(),
            enc_buf: Vec::new(),
            out: Vec::new(),
        }
    }

    /// Number of entries inserted into the dynamic table so far.
    pub fn insert_count(&self) -> u64 {
        self.inserted
    }

    /// Current dynamic table size in bytes (entries counted as name + value + 32).
    pub fn table_size(&self) -> u64 {
        self.size
    }

    /// Number of streams currently blocked.
    pub fn blocked_streams(&self) -> usize {
        let mut n = 0;
        for (i, b) in self.blocked.iter().enumerate() {
            if !self.blocked[..i].iter().any(|x| x.0 == b.0) {
                n += 1;
            }
        }
        n
    }

    /// Decodes a field section received on request stream `stream_id`.
    pub fn decode(&mut self, stream_id: u64, block: &[u8]) -> Result<Decoded, Error> {
        if block.len() as u64 > self.max_section.saturating_add(64) {
            return Err(Error::FieldSectionTooLarge);
        }
        match self.decode_block(block) {
            Ok((fields, ric)) => {
                self.ack_section(stream_id, ric);
                Ok(Decoded::Fields(fields))
            }
            Err(Error::Blocked) => {
                if !self.blocked.iter().any(|b| b.0 == stream_id)
                    && self.blocked_streams() as u64 >= self.max_blocked
                {
                    return Err(Error::DecompressionFailed);
                }
                let ric = self.required_insert_count(block)?;
                self.blocked.push((stream_id, ric, block.to_vec()));
                Ok(Decoded::Blocked)
            }
            Err(e) => Err(e),
        }
    }

    fn ack_section(&mut self, stream_id: u64, ric: u64) {
        if ric > 0 {
            put_int(&mut self.out, 0x80, 7, stream_id);
            self.acked = self.acked.max(ric);
        }
    }

    /// Processes bytes from the peer's encoder stream. Returns the streams that became
    /// unblocked, in the order they blocked, with their decode results.
    #[allow(clippy::type_complexity)]
    pub fn on_encoder_stream(&mut self, data: &[u8]) -> Result<Vec<(u64, Result<Vec<Field>, Error>)>, Error> {
        let mut buf = std::mem::take(&mut self.enc_buf);
        buf.extend_from_slice(data);
        let mut pos = 0;
        let r = loop {
            let start = pos;
            match self.instruction(&buf, &mut pos) {
                Ok(()) => {}
                Err(Short::Incomplete) => {
                    pos = start;
                    break Ok(());
                }
                Err(Short::Invalid) => break Err(Error::EncoderStream),
            }
        };
        r?;
        buf.drain(..pos);
        // a partial instruction can hold at most one entry, Huffman-coded at <= 30 bits a byte
        if buf.len() as u64 > self.max_cap.saturating_mul(4).saturating_add(64) {
            return Err(Error::EncoderStream);
        }
        self.enc_buf = buf;
        let mut done = Vec::new();
        if self.blocked.iter().any(|b| b.1 <= self.inserted) {
            let blocked = std::mem::take(&mut self.blocked);
            for (sid, ric, block) in blocked {
                if ric > self.inserted {
                    self.blocked.push((sid, ric, block));
                    continue;
                }
                let r = self.decode_block(&block).map(|(f, ric)| {
                    self.ack_section(sid, ric);
                    f
                });
                done.push((sid, r));
            }
        }
        Ok(done)
    }

    /// The stream was reset or abandoned before its field sections were fully processed: drops
    /// its blocked sections and queues a Stream Cancellation. Call it only for streams whose
    /// sections were not all decoded.
    pub fn cancel_stream(&mut self, stream_id: u64) {
        self.blocked.retain(|b| b.0 != stream_id);
        if self.max_cap > 0 {
            put_int(&mut self.out, 0x40, 6, stream_id);
        }
    }

    /// Appends pending decoder-stream instructions to `out`: Section Acknowledgments, Stream
    /// Cancellations, then an Insert Count Increment for inserts not yet acknowledged.
    pub fn take_decoder_stream(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.out);
        if self.inserted > self.acked {
            put_int(out, 0x00, 6, self.inserted - self.acked);
            self.acked = self.inserted;
        }
    }

    fn dropped(&self) -> u64 {
        self.inserted - self.entries.len() as u64
    }

    fn entry(&self, abs: u64) -> Option<&Field> {
        let d = self.dropped();
        if abs < d || abs >= self.inserted {
            return None;
        }
        self.entries.get((abs - d) as usize)
    }

    fn insert(&mut self, f: Field) -> Result<(), Short> {
        let size = f.size();
        if size > self.cap {
            return Err(Short::Invalid);
        }
        while self.size + size > self.cap {
            let e = self.entries.pop_front().ok_or(Short::Invalid)?;
            self.size -= e.size();
        }
        self.size += size;
        self.entries.push_back(f);
        self.inserted += 1;
        Ok(())
    }

    /// Parses and applies one encoder-stream instruction (RFC 9204 4.3). Nothing changes when
    /// the instruction is incomplete.
    fn instruction(&mut self, buf: &[u8], pos: &mut usize) -> Result<(), Short> {
        let b = *buf.get(*pos).ok_or(Short::Incomplete)?;
        let limit = self.max_cap.saturating_mul(4).saturating_add(64);
        if b & 0x80 != 0 {
            // Insert with Name Reference
            let idx = get_int(buf, pos, 6)?;
            let v = get_span(buf, pos, 7)?;
            if (v.end - v.start) as u64 > limit {
                return Err(Short::Invalid);
            }
            let name = if b & 0x40 != 0 {
                STATIC_TABLE.get(idx as usize).ok_or(Short::Invalid)?.0.as_bytes().to_vec()
            } else {
                let abs = self.inserted.checked_sub(idx + 1).ok_or(Short::Invalid)?;
                self.entry(abs).ok_or(Short::Invalid)?.name.clone()
            };
            let value = span_bytes(buf, v)?;
            self.insert(Field { name, value })
        } else if b & 0x40 != 0 {
            // Insert with Literal Name
            let n = get_span(buf, pos, 5)?;
            let v = get_span(buf, pos, 7)?;
            if (v.end - n.start) as u64 > limit {
                return Err(Short::Invalid);
            }
            let name = span_bytes(buf, n)?;
            let value = span_bytes(buf, v)?;
            self.insert(Field { name, value })
        } else if b & 0x20 != 0 {
            // Set Dynamic Table Capacity
            let cap = get_int(buf, pos, 5)?;
            if cap > self.max_cap {
                return Err(Short::Invalid);
            }
            self.cap = cap;
            while self.size > self.cap {
                let e = self.entries.pop_front().ok_or(Short::Invalid)?;
                self.size -= e.size();
            }
            Ok(())
        } else {
            // Duplicate
            let idx = get_int(buf, pos, 5)?;
            let abs = self.inserted.checked_sub(idx + 1).ok_or(Short::Invalid)?;
            let f = self.entry(abs).ok_or(Short::Invalid)?.clone();
            self.insert(f)
        }
    }

    /// Decodes the Required Insert Count of a section (RFC 9204 4.5.1.1).
    fn required_insert_count(&self, block: &[u8]) -> Result<u64, Error> {
        let mut pos = 0;
        let enc = get_int(block, &mut pos, 8).map_err(|_| Error::DecompressionFailed)?;
        if enc == 0 {
            return Ok(0);
        }
        let max_entries = self.max_cap / 32;
        let full_range = 2 * max_entries;
        if enc > full_range {
            return Err(Error::DecompressionFailed);
        }
        let max_value = self.inserted + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped + enc - 1;
        if ric > max_value {
            if ric <= full_range {
                return Err(Error::DecompressionFailed);
            }
            ric -= full_range;
        }
        if ric == 0 {
            return Err(Error::DecompressionFailed);
        }
        Ok(ric)
    }

    /// Decodes a whole section. Returns `Error::Blocked` when it needs entries not yet received.
    fn decode_block(&self, block: &[u8]) -> Result<(Vec<Field>, u64), Error> {
        let ric = self.required_insert_count(block)?;
        if ric > self.inserted {
            return Err(Error::Blocked);
        }
        let fail = |_| Error::DecompressionFailed;
        let mut pos = 0;
        get_int(block, &mut pos, 8).map_err(fail)?;
        let sign = *block.get(pos).ok_or(Error::DecompressionFailed)? & 0x80 != 0;
        let delta = get_int(block, &mut pos, 7).map_err(fail)?;
        let base = if sign {
            ric.checked_sub(delta + 1).ok_or(Error::DecompressionFailed)?
        } else {
            ric.checked_add(delta).ok_or(Error::DecompressionFailed)?
        };
        let mut fields = Vec::new();
        let mut total = 0u64;
        let mut max_ref: Option<u64> = None;
        // resolves a dynamic absolute index, which must lie below the Required Insert Count
        let mut dyn_ref = |abs: Option<u64>| -> Result<&Field, Error> {
            let abs = abs.filter(|&a| a < ric).ok_or(Error::DecompressionFailed)?;
            max_ref = Some(max_ref.map_or(abs, |m: u64| m.max(abs)));
            self.entry(abs).ok_or(Error::DecompressionFailed)
        };
        let static_ref = |idx: u64| -> Result<(&'static [u8], &'static [u8]), Error> {
            let (n, v) = STATIC_TABLE.get(idx as usize).ok_or(Error::DecompressionFailed)?;
            Ok((n.as_bytes(), v.as_bytes()))
        };
        while pos < block.len() {
            let b = block[pos];
            let field = if b & 0x80 != 0 {
                // Indexed Field Line
                let idx = get_int(block, &mut pos, 6).map_err(fail)?;
                if b & 0x40 != 0 {
                    let (n, v) = static_ref(idx)?;
                    Field::new(n, v)
                } else {
                    dyn_ref(base.checked_sub(idx + 1))?.clone()
                }
            } else if b & 0x40 != 0 {
                // Literal Field Line with Name Reference
                let idx = get_int(block, &mut pos, 4).map_err(fail)?;
                let name = if b & 0x10 != 0 {
                    static_ref(idx)?.0.to_vec()
                } else {
                    dyn_ref(base.checked_sub(idx + 1))?.name.clone()
                };
                let v = get_span(block, &mut pos, 7).map_err(fail)?;
                Field { name, value: span_bytes(block, v).map_err(fail)? }
            } else if b & 0x20 != 0 {
                // Literal Field Line with Literal Name
                let n = get_span(block, &mut pos, 3).map_err(fail)?;
                let v = get_span(block, &mut pos, 7).map_err(fail)?;
                Field { name: span_bytes(block, n).map_err(fail)?, value: span_bytes(block, v).map_err(fail)? }
            } else if b & 0x10 != 0 {
                // Indexed Field Line with Post-Base Index
                let idx = get_int(block, &mut pos, 4).map_err(fail)?;
                dyn_ref(base.checked_add(idx))?.clone()
            } else {
                // Literal Field Line with Post-Base Name Reference
                let idx = get_int(block, &mut pos, 3).map_err(fail)?;
                let name = dyn_ref(base.checked_add(idx))?.name.clone();
                let v = get_span(block, &mut pos, 7).map_err(fail)?;
                Field { name, value: span_bytes(block, v).map_err(fail)? }
            };
            total += field.size();
            if total > self.max_section {
                return Err(Error::FieldSectionTooLarge);
            }
            fields.push(field);
        }
        // the Required Insert Count must be exactly what the references need (RFC 9204 2.2.3)
        if ric != max_ref.map_or(0, |m| m + 1) {
            return Err(Error::DecompressionFailed);
        }
        Ok((fields, ric))
    }
}
