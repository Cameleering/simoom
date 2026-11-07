//! QPACK encoder (RFC 9204 sections 2.1, 4.3, 4.4 and 4.5).

use std::collections::VecDeque;

use crate::prim::{get_int, put_int, put_str, static_find, Short};
use crate::Error;

#[derive(Debug)]
struct Entry {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Entry {
    fn size(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64 + 32
    }
}

/// An outstanding field section with dynamic references, waiting for its Section Ack.
#[derive(Debug)]
struct Section {
    stream: u64,
    ric: u64,
    min_ref: u64,
}

/// How one field line is represented.
enum Rep {
    Static(u64),
    StaticName(u64),
    Dyn(u64),
    DynName(u64),
    Literal,
}

/// A QPACK encoder for one HTTP/3 connection.
#[derive(Debug)]
pub struct Encoder {
    max_cap: u64,
    cap: u64,
    peer_max_entries: u64,
    peer_blocked: u64,
    entries: VecDeque<Entry>,
    size: u64,
    inserted: u64,
    /// Known Received Count: inserts the decoder has acknowledged.
    known: u64,
    sections: Vec<Section>,
    enc_out: Vec<u8>,
    dec_buf: Vec<u8>,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Names whose values are never put in the dynamic table and are sent as never-indexed literals.
fn sensitive(name: &[u8]) -> bool {
    name == b"authorization" || name == b"proxy-authorization"
}

impl Encoder {
    /// A static-table-only encoder: it never writes to the encoder stream and every section has
    /// a Required Insert Count of 0.
    pub fn new() -> Self {
        Self::with_dynamic_table(0)
    }

    /// An encoder that uses a dynamic table of up to `max_capacity` bytes, limited further by the
    /// peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY (see [`Encoder::set_peer_settings`]).
    pub fn with_dynamic_table(max_capacity: u64) -> Self {
        Encoder {
            max_cap: max_capacity,
            cap: 0,
            peer_max_entries: 0,
            peer_blocked: 0,
            entries: VecDeque::new(),
            size: 0,
            inserted: 0,
            known: 0,
            sections: Vec::new(),
            enc_out: Vec::new(),
            dec_buf: Vec::new(),
        }
    }

    /// Applies the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS.
    /// Takes effect only before the first insertion.
    pub fn set_peer_settings(&mut self, max_table_capacity: u64, blocked_streams: u64) {
        if self.inserted > 0 {
            return;
        }
        self.peer_max_entries = max_table_capacity / 32;
        self.peer_blocked = blocked_streams;
        let cap = self.max_cap.min(max_table_capacity);
        if cap != self.cap {
            self.cap = cap;
            put_int(&mut self.enc_out, 0x20, 5, cap);
        }
    }

    /// Number of entries inserted so far.
    pub fn insert_count(&self) -> u64 {
        self.inserted
    }

    /// Number of inserts the decoder has acknowledged.
    pub fn known_received_count(&self) -> u64 {
        self.known
    }

    fn dropped(&self) -> u64 {
        self.inserted - self.entries.len() as u64
    }

    fn blocking_streams(&self) -> u64 {
        let mut n = 0;
        for (i, s) in self.sections.iter().enumerate() {
            if s.ric > self.known && !self.sections[..i].iter().any(|x| x.stream == s.stream && x.ric > self.known) {
                n += 1;
            }
        }
        n
    }

    /// Whether the entry `abs` may be referenced from a section on `stream`; `blocking` records
    /// that this section may block the stream.
    fn can_ref(&self, abs: u64, stream: u64, blocking: &mut bool) -> bool {
        if abs < self.known || *blocking {
            return true;
        }
        let stream_blocked = self.sections.iter().any(|s| s.stream == stream && s.ric > self.known);
        if stream_blocked || self.blocking_streams() < self.peer_blocked {
            *blocking = true;
            return true;
        }
        false
    }

    /// Evicts acknowledged, unreferenced entries until `size` more bytes fit. Changes nothing and
    /// returns false when that is not possible.
    fn make_room(&mut self, size: u64, cur_min_ref: u64) -> bool {
        if size > self.cap {
            return false;
        }
        let min_ref = self.sections.iter().map(|s| s.min_ref).min().unwrap_or(u64::MAX).min(cur_min_ref);
        let mut free = self.cap - self.size;
        let mut n = 0;
        let d = self.dropped();
        for (i, e) in self.entries.iter().enumerate() {
            if free >= size {
                break;
            }
            let abs = d + i as u64;
            if abs >= self.known || abs >= min_ref {
                return false;
            }
            free += e.size();
            n += 1;
        }
        if free < size {
            return false;
        }
        for _ in 0..n {
            let e = self.entries.pop_front().expect("counted above");
            self.size -= e.size();
        }
        true
    }

    fn find(&self, name: &[u8], value: &[u8]) -> (Option<u64>, Option<u64>) {
        let d = self.dropped();
        let mut name_idx = None;
        for (i, e) in self.entries.iter().enumerate().rev() {
            if e.name == name {
                if e.value == value {
                    return (Some(d + i as u64), Some(d + i as u64));
                }
                name_idx.get_or_insert(d + i as u64);
            }
        }
        (None, name_idx)
    }

    /// Inserts an entry, writing the instruction to the encoder stream. Returns its index.
    fn insert(&mut self, name: &[u8], value: &[u8], cur_min_ref: u64) -> Option<u64> {
        let size = name.len() as u64 + value.len() as u64 + 32;
        // name references are resolved before eviction by the decoder (RFC 9204 3.2.2)
        let sname = static_find(name, b"").1;
        let dname = if sname.is_none() { self.find(name, value).1 } else { None };
        if !self.make_room(size, cur_min_ref) {
            return None;
        }
        if let Some(i) = sname {
            put_int(&mut self.enc_out, 0xc0, 6, i as u64);
        } else if let Some(abs) = dname {
            put_int(&mut self.enc_out, 0x80, 6, self.inserted - 1 - abs);
        } else {
            put_str(&mut self.enc_out, 0x40, 5, name);
        }
        put_str(&mut self.enc_out, 0, 7, value);
        self.entries.push_back(Entry { name: name.to_vec(), value: value.to_vec() });
        self.size += size;
        self.inserted += 1;
        Some(self.inserted - 1)
    }

    /// Encodes a field section for `stream_id` into `out`. Field names must already be lowercase.
    pub fn encode(&mut self, stream_id: u64, fields: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
        let mut reps = Vec::with_capacity(fields.len());
        let mut blocking = false;
        let mut min_ref = u64::MAX;
        let mut max_ref: Option<u64> = None;
        for &(name, value) in fields {
            let (sfull, sname) = static_find(name, value);
            let rep = if let Some(i) = sfull {
                Rep::Static(i as u64)
            } else if self.cap == 0 || sensitive(name) {
                sname.map_or(Rep::Literal, |i| Rep::StaticName(i as u64))
            } else {
                let (dfull, dname) = self.find(name, value);
                let mut abs = dfull;
                if abs.is_none() && (name.len() + value.len() + 32) as u64 <= self.cap * 3 / 4 {
                    abs = self.insert(name, value, min_ref);
                }
                match abs {
                    Some(a) if self.can_ref(a, stream_id, &mut blocking) => Rep::Dyn(a),
                    _ => match (sname, dname) {
                        (Some(i), _) => Rep::StaticName(i as u64),
                        (None, Some(a)) if self.dropped() <= a && self.can_ref(a, stream_id, &mut blocking) => {
                            Rep::DynName(a)
                        }
                        _ => Rep::Literal,
                    },
                }
            };
            if let Rep::Dyn(a) | Rep::DynName(a) = rep {
                min_ref = min_ref.min(a);
                max_ref = Some(max_ref.map_or(a, |m| m.max(a)));
            }
            reps.push(rep);
        }
        let ric = max_ref.map_or(0, |m| m + 1);
        let base = self.inserted;
        if ric == 0 {
            out.extend_from_slice(&[0, 0]);
        } else {
            put_int(out, 0, 8, ric % (2 * self.peer_max_entries) + 1);
            put_int(out, 0, 7, base - ric);
            self.sections.push(Section { stream: stream_id, ric, min_ref });
        }
        for (rep, &(name, value)) in reps.iter().zip(fields) {
            let never = if sensitive(name) { 0x20 } else { 0 };
            match *rep {
                Rep::Static(i) => put_int(out, 0xc0, 6, i),
                Rep::Dyn(a) => put_int(out, 0x80, 6, base - 1 - a),
                Rep::StaticName(i) => {
                    put_int(out, 0x50 | never, 4, i);
                    put_str(out, 0, 7, value);
                }
                Rep::DynName(a) => {
                    put_int(out, 0x40 | never, 4, base - 1 - a);
                    put_str(out, 0, 7, value);
                }
                Rep::Literal => {
                    put_str(out, 0x20 | (never >> 1), 3, name);
                    put_str(out, 0, 7, value);
                }
            }
        }
    }

    /// Processes bytes from the peer's decoder stream (RFC 9204 4.4).
    pub fn on_decoder_stream(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut buf = std::mem::take(&mut self.dec_buf);
        buf.extend_from_slice(data);
        let mut pos = 0;
        loop {
            let start = pos;
            match self.instruction(&buf, &mut pos) {
                Ok(()) => {}
                Err(Short::Incomplete) => {
                    pos = start;
                    break;
                }
                Err(Short::Invalid) => return Err(Error::DecoderStream),
            }
        }
        buf.drain(..pos);
        if buf.len() > 16 {
            return Err(Error::DecoderStream);
        }
        self.dec_buf = buf;
        Ok(())
    }

    fn instruction(&mut self, buf: &[u8], pos: &mut usize) -> Result<(), Short> {
        let b = *buf.get(*pos).ok_or(Short::Incomplete)?;
        if b & 0x80 != 0 {
            // Section Acknowledgment
            let stream = get_int(buf, pos, 7)?;
            let i = self.sections.iter().position(|s| s.stream == stream).ok_or(Short::Invalid)?;
            let s = self.sections.remove(i);
            self.known = self.known.max(s.ric);
        } else if b & 0x40 != 0 {
            // Stream Cancellation
            let stream = get_int(buf, pos, 6)?;
            self.sections.retain(|s| s.stream != stream);
        } else {
            // Insert Count Increment
            let inc = get_int(buf, pos, 6)?;
            if inc == 0 || inc > self.inserted - self.known {
                return Err(Short::Invalid);
            }
            self.known += inc;
        }
        Ok(())
    }

    /// Appends pending encoder-stream instructions to `out`.
    pub fn take_encoder_stream(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.enc_out);
    }
}
