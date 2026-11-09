//! Streams (RFC 9000 §2–4): send and receive buffers, stream and connection flow control,
//! stream limits, STOP_SENDING and RESET_STREAM.

use crate::coding::varint_len;
use crate::error::*;
use crate::frame::{self, MAX_STREAMS_LIMIT};
use crate::ranges::RangeSet;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

/// A fast hasher for integer keys (stream IDs). Not DoS-relevant: stream IDs are bounded by
/// the stream limits we grant.
#[derive(Default)]
pub struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(5) ^ b as u64).wrapping_mul(0x51_7cc1_b727_220a_95);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (n ^ (n >> 32)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

pub type IdMap<V> = HashMap<u64, V, BuildHasherDefault<IdHasher>>;

#[inline]
pub fn is_bidi(id: u64) -> bool {
    id & 2 == 0
}
#[inline]
pub fn is_server_initiated(id: u64) -> bool {
    id & 1 == 1
}

/// Stream limits and windows configured locally.
#[derive(Clone, Debug)]
pub struct StreamConfig {
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub stream_window_bidi_local: u64,
    pub stream_window_bidi_remote: u64,
    pub stream_window_uni: u64,
    pub conn_window: u64,
    /// Unacknowledged bytes buffered per send stream.
    pub send_buffer: u64,
}

/// A frame that must be (re)sent for stream bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    MaxData,
    MaxStreamData(u64),
    MaxStreams(bool),
    DataBlocked,
    StreamDataBlocked(u64),
    StreamsBlocked(bool),
    ResetStream(u64),
    StopSending(u64),
}

#[derive(Default)]
pub struct SendStream {
    buf: VecDeque<u8>,
    /// Stream offset of `buf[0]`.
    base: u64,
    /// Next offset never sent.
    sent: u64,
    retransmit: RangeSet,
    acked: RangeSet,
    /// Peer's MAX_STREAM_DATA.
    max_data: u64,
    fin: bool,
    fin_sent: bool,
    fin_acked: bool,
    reset: Option<(u64, u64)>,
    reset_acked: bool,
    stopped: Option<u64>,
    blocked_at: Option<u64>,
    want_writable: bool,
    queued: bool,
}

impl SendStream {
    fn end(&self) -> u64 {
        self.base + self.buf.len() as u64
    }
    fn has_pending(&self) -> bool {
        self.reset.is_none()
            && (!self.retransmit.is_empty() || self.sent < self.end() || (self.fin && !self.fin_sent))
    }
    fn is_done(&self) -> bool {
        if self.reset.is_some() {
            return self.reset_acked;
        }
        self.fin_acked && self.buf.is_empty()
    }
}

#[derive(Default)]
pub struct RecvStream {
    data: VecDeque<u8>,
    /// Offset of `data[0]`: everything below was read by the application.
    read: u64,
    ooo: BTreeMap<u64, Vec<u8>>,
    max_data: u64,
    window: u64,
    highest: u64,
    final_size: Option<u64>,
    reset: Option<u64>,
    reset_delivered: bool,
    stop: Option<u64>,
    fin_delivered: bool,
    notified: bool,
}

impl RecvStream {
    fn contiguous_end(&self) -> u64 {
        self.read + self.data.len() as u64
    }
    fn is_done(&self) -> bool {
        self.fin_delivered || self.reset_delivered || (self.stop.is_some() && self.final_size.is_some())
    }
    /// Inserts `[off, off+len)` keeping `ooo` non-overlapping.
    fn insert(&mut self, mut off: u64, mut d: &[u8]) {
        let cend = self.contiguous_end();
        if off < cend {
            let skip = (cend - off).min(d.len() as u64) as usize;
            d = &d[skip..];
            off += skip as u64;
        }
        if d.is_empty() {
            return;
        }
        if off == cend {
            self.data.extend(d);
            // Pull in out-of-order chunks that became contiguous.
            while let Some((&o, _)) = self.ooo.first_key_value() {
                let end = self.contiguous_end();
                if o > end {
                    break;
                }
                let chunk = self.ooo.pop_first().unwrap().1;
                let skip = (end - o) as usize;
                if skip < chunk.len() {
                    self.data.extend(&chunk[skip..]);
                }
            }
            return;
        }
        // Out of order: insert only the gaps not already buffered.
        let end = off + d.len() as u64;
        let mut cur = off;
        let mut pieces: Vec<(u64, u64)> = Vec::new();
        let start_key = self.ooo.range(..off).next_back().map(|(&k, v)| (k, k + v.len() as u64));
        if let Some((_, e)) = start_key {
            if e > cur {
                cur = e;
            }
        }
        for (&k, v) in self.ooo.range(off..end) {
            if k > cur {
                pieces.push((cur, k));
            }
            cur = cur.max(k + v.len() as u64);
        }
        if cur < end {
            pieces.push((cur, end));
        }
        for (s, e) in pieces {
            let piece = &d[(s - off) as usize..(e - off) as usize];
            // Coalesce with the chunk ending at `s` and the one starting at `e`, so the map
            // holds one entry per gap rather than one per frame.
            let mut key = s;
            let mut buf = match self.ooo.range(..s).next_back() {
                Some((&k, v)) if k + v.len() as u64 == s => {
                    key = k;
                    let mut v = self.ooo.remove(&k).unwrap();
                    v.extend_from_slice(piece);
                    v
                }
                _ => piece.to_vec(),
            };
            if let Some(next) = self.ooo.remove(&e) {
                buf.extend_from_slice(&next);
            }
            self.ooo.insert(key, buf);
        }
    }

    /// Out-of-order chunks (gaps) currently buffered.
    fn gaps(&self) -> usize {
        self.ooo.len()
    }
}

/// Out-of-order chunks a connection may buffer, over all its streams. Adjacent chunks are
/// merged, so this bounds the number of holes, not the data: honest loss leaves a few holes per
/// stream, while a peer that sends one byte at every other offset would otherwise cost a heap
/// allocation and a tree node per byte of flow-control window. It is counted per connection, so
/// opening many streams does not multiply it.
pub const MAX_RECV_GAPS: usize = 1024;

pub struct Stream {
    pub send: Option<SendStream>,
    pub recv: Option<RecvStream>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEvent {
    Opened(u64),
    Readable(u64),
    Writable(u64),
    Stopped(u64, u64),
    Reset(u64, u64),
    Available(bool),
}

pub struct Streams {
    is_server: bool,
    cfg: StreamConfig,
    map: IdMap<Stream>,
    // Locally initiated: next index and the peer's limit.
    next: [u64; 2],
    peer_max: [u64; 2],
    blocked_sent: [Option<u64>; 2],
    // Remotely initiated: opened count, granted limit, closed count.
    remote_opened: [u64; 2],
    local_max: [u64; 2],
    remote_closed: [u64; 2],
    // Peer's initial per-stream limits.
    peer_bidi_local: u64,
    peer_bidi_remote: u64,
    peer_uni: u64,
    // Connection flow control: sending.
    pub send_max_data: u64,
    written: u64,
    data_blocked_at: Option<u64>,
    // Connection flow control: receiving.
    recv_max_data: u64,
    recv_highest: u64,
    recv_consumed: u64,
    /// Out-of-order chunks buffered over all streams (bounded by [`MAX_RECV_GAPS`]).
    recv_gaps: usize,
    send_queue: VecDeque<u64>,
    pub control: VecDeque<Control>,
    pub events: VecDeque<StreamEvent>,
}

/// Index 0 = bidi, 1 = uni.
#[inline]
fn dir(id: u64) -> usize {
    ((id >> 1) & 1) as usize
}

impl Streams {
    pub fn new(is_server: bool, cfg: StreamConfig) -> Self {
        Streams {
            is_server,
            map: IdMap::default(),
            next: [0; 2],
            peer_max: [0; 2],
            blocked_sent: [None; 2],
            remote_opened: [0; 2],
            local_max: [cfg.max_streams_bidi, cfg.max_streams_uni],
            remote_closed: [0; 2],
            peer_bidi_local: 0,
            peer_bidi_remote: 0,
            peer_uni: 0,
            send_max_data: 0,
            written: 0,
            data_blocked_at: None,
            recv_max_data: cfg.conn_window,
            recv_highest: 0,
            recv_consumed: 0,
            recv_gaps: 0,
            send_queue: VecDeque::new(),
            control: VecDeque::new(),
            events: VecDeque::new(),
            cfg,
        }
    }

    /// Applies the peer's transport parameters.
    pub fn set_peer_params(&mut self, p: &crate::params::TransportParams) {
        self.peer_max = [p.initial_max_streams_bidi, p.initial_max_streams_uni];
        self.peer_bidi_local = p.initial_max_stream_data_bidi_local;
        self.peer_bidi_remote = p.initial_max_stream_data_bidi_remote;
        self.peer_uni = p.initial_max_stream_data_uni;
        self.send_max_data = p.initial_max_data;
    }

    fn local(&self, id: u64) -> bool {
        is_server_initiated(id) == self.is_server
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn new_stream(&self, id: u64) -> Stream {
        let local = self.local(id);
        let bidi = is_bidi(id);
        let send = if bidi || local {
            // Peer's limit for data we send: their "remote" for our streams, "local" for theirs.
            let max = if !bidi {
                self.peer_uni
            } else if local {
                self.peer_bidi_remote
            } else {
                self.peer_bidi_local
            };
            Some(SendStream { max_data: max, ..Default::default() })
        } else {
            None
        };
        let recv = if bidi || !local {
            let w = if !bidi {
                self.cfg.stream_window_uni
            } else if local {
                self.cfg.stream_window_bidi_local
            } else {
                self.cfg.stream_window_bidi_remote
            };
            Some(RecvStream { max_data: w, window: w, ..Default::default() })
        } else {
            None
        };
        Stream { send, recv }
    }

    /// Opens a locally initiated stream.
    pub fn open(&mut self, bidi: bool) -> Result<u64, StreamError> {
        let d = (!bidi) as usize;
        if self.next[d] >= self.peer_max[d] {
            if self.blocked_sent[d] != Some(self.peer_max[d]) {
                self.blocked_sent[d] = Some(self.peer_max[d]);
                self.control.push_back(Control::StreamsBlocked(bidi));
            }
            return Err(StreamError::LimitReached);
        }
        let id = self.next[d] << 2 | (d as u64) << 1 | self.is_server as u64;
        self.next[d] += 1;
        let s = self.new_stream(id);
        self.map.insert(id, s);
        Ok(id)
    }

    /// Looks up a stream named in a received frame, creating peer-initiated streams (and
    /// all lower-numbered ones of the same type) as needed. `Ok(None)` means the stream is
    /// already closed and the frame should be ignored.
    fn get_or_open(&mut self, id: u64, ty: u64) -> Result<Option<&mut Stream>, TransportError> {
        let d = dir(id);
        let idx = id >> 2;
        if self.local(id) {
            if idx >= self.next[d] {
                return Err(TransportError::frame(STREAM_STATE_ERROR, ty, "frame for a stream not yet opened"));
            }
        } else if idx >= self.remote_opened[d] {
            if idx >= self.local_max[d] {
                return Err(TransportError::frame(STREAM_LIMIT_ERROR, ty, "stream limit exceeded"));
            }
            for i in self.remote_opened[d]..=idx {
                let sid = i << 2 | (d as u64) << 1 | (!self.is_server) as u64;
                let s = self.new_stream(sid);
                self.map.insert(sid, s);
                self.events.push_back(StreamEvent::Opened(sid));
            }
            self.remote_opened[d] = idx + 1;
        }
        Ok(self.map.get_mut(&id))
    }

    // ---- received frames ----

    pub fn on_stream(&mut self, id: u64, off: u64, data: &[u8], fin: bool) -> Result<(), TransportError> {
        let ty = frame::STREAM;
        if self.local(id) && !is_bidi(id) {
            return Err(TransportError::frame(STREAM_STATE_ERROR, ty, "STREAM on a send-only stream"));
        }
        let conn_max = self.recv_max_data;
        let mut conn_highest = self.recv_highest;
        let mut gaps_total = self.recv_gaps;
        let Some(s) = self.get_or_open(id, ty)? else { return Ok(()) };
        let r = s.recv.as_mut().unwrap();
        let end = off + data.len() as u64;
        if end > r.max_data {
            return Err(TransportError::frame(FLOW_CONTROL_ERROR, ty, "stream flow control exceeded"));
        }
        if let Some(fs) = r.final_size {
            if end > fs || (fin && end != fs) {
                return Err(TransportError::frame(FINAL_SIZE_ERROR, ty, "final size changed"));
            }
        }
        if fin {
            if end < r.highest {
                return Err(TransportError::frame(FINAL_SIZE_ERROR, ty, "final size below received data"));
            }
            r.final_size = Some(end);
        }
        if end > r.highest {
            conn_highest += end - r.highest;
            if conn_highest > conn_max {
                return Err(TransportError::frame(FLOW_CONTROL_ERROR, ty, "connection flow control exceeded"));
            }
            r.highest = end;
        }
        if r.reset.is_some() || r.stop.is_some() {
            self.recv_highest = conn_highest;
            return Ok(());
        }
        let before = r.contiguous_end();
        let gaps_before = r.gaps();
        r.insert(off, data);
        gaps_total = gaps_total + r.gaps() - gaps_before;
        if gaps_total > MAX_RECV_GAPS {
            return Err(TransportError::frame(PROTOCOL_VIOLATION, ty, "too many out-of-order stream fragments"));
        }
        let readable = r.contiguous_end() > before || (r.final_size == Some(r.contiguous_end()) && !r.fin_delivered);
        if readable && !r.notified {
            r.notified = true;
            self.events.push_back(StreamEvent::Readable(id));
        }
        self.recv_highest = conn_highest;
        self.recv_gaps = gaps_total;
        Ok(())
    }

    pub fn on_reset(&mut self, id: u64, code: u64, final_size: u64) -> Result<(), TransportError> {
        let ty = frame::RESET_STREAM;
        if self.local(id) && !is_bidi(id) {
            return Err(TransportError::frame(STREAM_STATE_ERROR, ty, "RESET_STREAM on a send-only stream"));
        }
        let conn_max = self.recv_max_data;
        let mut conn_highest = self.recv_highest;
        let mut gaps_total = self.recv_gaps;
        let Some(s) = self.get_or_open(id, ty)? else { return Ok(()) };
        let r = s.recv.as_mut().unwrap();
        if let Some(fs) = r.final_size {
            if fs != final_size {
                return Err(TransportError::frame(FINAL_SIZE_ERROR, ty, "final size changed"));
            }
        }
        if final_size < r.highest {
            return Err(TransportError::frame(FINAL_SIZE_ERROR, ty, "final size below received data"));
        }
        if final_size > r.max_data {
            return Err(TransportError::frame(FLOW_CONTROL_ERROR, ty, "final size exceeds flow control"));
        }
        conn_highest += final_size - r.highest;
        if conn_highest > conn_max {
            return Err(TransportError::frame(FLOW_CONTROL_ERROR, ty, "connection flow control exceeded"));
        }
        r.highest = final_size;
        r.final_size = Some(final_size);
        let mut released = None;
        if r.reset.is_none() && !r.fin_delivered {
            r.reset = Some(code);
            // Unread bytes no longer count against the connection window.
            released = Some(final_size - r.read);
            r.data.clear();
            gaps_total -= r.gaps();
            r.ooo.clear();
        }
        self.recv_highest = conn_highest;
        self.recv_gaps = gaps_total;
        if let Some(rel) = released {
            self.recv_consumed += rel;
            self.events.push_back(StreamEvent::Reset(id, code));
            self.maybe_max_data();
        }
        self.maybe_remove(id);
        Ok(())
    }

    pub fn on_stop_sending(&mut self, id: u64, code: u64) -> Result<(), TransportError> {
        let ty = frame::STOP_SENDING;
        if !self.local(id) && !is_bidi(id) {
            return Err(TransportError::frame(STREAM_STATE_ERROR, ty, "STOP_SENDING on a receive-only stream"));
        }
        let Some(s) = self.get_or_open(id, ty)? else { return Ok(()) };
        let snd = s.send.as_mut().unwrap();
        if snd.stopped.is_some() {
            return Ok(());
        }
        snd.stopped = Some(code);
        // RFC 9000 §3.5: respond with RESET_STREAM.
        let reset = snd.reset.is_none() && !(snd.fin && snd.fin_acked);
        if reset {
            snd.reset = Some((code, snd.end()));
            snd.retransmit.clear();
        }
        self.events.push_back(StreamEvent::Stopped(id, code));
        if reset {
            self.control.push_back(Control::ResetStream(id));
        }
        Ok(())
    }

    pub fn on_max_stream_data(&mut self, id: u64, max: u64) -> Result<(), TransportError> {
        let ty = frame::MAX_STREAM_DATA;
        if !self.local(id) && !is_bidi(id) {
            return Err(TransportError::frame(STREAM_STATE_ERROR, ty, "MAX_STREAM_DATA on a receive-only stream"));
        }
        let Some(s) = self.get_or_open(id, ty)? else { return Ok(()) };
        let snd = s.send.as_mut().unwrap();
        if max > snd.max_data {
            snd.max_data = max;
            if snd.want_writable {
                snd.want_writable = false;
                self.events.push_back(StreamEvent::Writable(id));
            }
        }
        Ok(())
    }

    pub fn on_stream_data_blocked(&mut self, id: u64) -> Result<(), TransportError> {
        let ty = frame::STREAM_DATA_BLOCKED;
        if self.local(id) && !is_bidi(id) {
            return Err(TransportError::frame(STREAM_STATE_ERROR, ty, "STREAM_DATA_BLOCKED on a send-only stream"));
        }
        self.get_or_open(id, ty)?;
        Ok(())
    }

    pub fn on_max_data(&mut self, max: u64) {
        if max > self.send_max_data {
            self.send_max_data = max;
            // Wake every stream that was blocked on connection credit.
            for (&id, s) in self.map.iter_mut() {
                if let Some(snd) = s.send.as_mut() {
                    if snd.want_writable {
                        snd.want_writable = false;
                        self.events.push_back(StreamEvent::Writable(id));
                    }
                }
            }
        }
    }

    pub fn on_max_streams(&mut self, bidi: bool, max: u64) {
        let d = (!bidi) as usize;
        if max > self.peer_max[d] {
            let was_blocked = self.next[d] >= self.peer_max[d];
            self.peer_max[d] = max;
            if was_blocked {
                self.events.push_back(StreamEvent::Available(bidi));
            }
        }
    }

    pub fn on_streams_blocked(&mut self, bidi: bool, limit: u64) {
        // The peer wants more streams; MAX_STREAMS is raised as streams close.
        let _ = (bidi, limit);
    }

    // ---- application API ----

    /// Buffers `data` for sending; returns how many bytes were accepted.
    pub fn write(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize, StreamError> {
        let conn_room = self.send_max_data - self.written;
        let cap = self.cfg.send_buffer;
        let s = self.map.get_mut(&id).ok_or(StreamError::UnknownStream)?;
        let snd = s.send.as_mut().ok_or(StreamError::InvalidDirection)?;
        if let Some(code) = snd.stopped {
            return Err(StreamError::Stopped(code));
        }
        if snd.reset.is_some() || snd.fin {
            return Err(StreamError::Finished);
        }
        let end = snd.end();
        let stream_room = snd.max_data.saturating_sub(end);
        let buf_room = cap.saturating_sub(snd.buf.len() as u64);
        let n = (data.len() as u64).min(stream_room).min(conn_room).min(buf_room) as usize;
        if n == 0 && !data.is_empty() {
            snd.want_writable = true;
            if stream_room == 0 && snd.blocked_at != Some(snd.max_data) {
                snd.blocked_at = Some(snd.max_data);
                self.control.push_back(Control::StreamDataBlocked(id));
            }
            if conn_room == 0 && self.data_blocked_at != Some(self.send_max_data) {
                self.data_blocked_at = Some(self.send_max_data);
                self.control.push_back(Control::DataBlocked);
            }
            return Err(StreamError::Blocked);
        }
        snd.buf.extend(&data[..n]);
        self.written += n as u64;
        if n < data.len() {
            snd.want_writable = true;
        } else if fin {
            snd.fin = true;
        }
        if !snd.queued && snd.has_pending() {
            snd.queued = true;
            self.send_queue.push_back(id);
        }
        Ok(n)
    }

    /// Reads in-order data; returns (bytes, fin reached).
    pub fn read(&mut self, id: u64, out: &mut [u8]) -> Result<(usize, bool), StreamError> {
        let s = self.map.get_mut(&id).ok_or(StreamError::UnknownStream)?;
        let r = s.recv.as_mut().ok_or(StreamError::InvalidDirection)?;
        if let Some(code) = r.reset {
            r.reset_delivered = true;
            self.maybe_remove(id);
            return Err(StreamError::Reset(code));
        }
        let n = out.len().min(r.data.len());
        let (a, b) = r.data.as_slices();
        if n <= a.len() {
            out[..n].copy_from_slice(&a[..n]);
        } else {
            out[..a.len()].copy_from_slice(a);
            out[a.len()..n].copy_from_slice(&b[..n - a.len()]);
        }
        r.data.drain(..n);
        r.read += n as u64;
        let fin = r.data.is_empty() && r.final_size == Some(r.read);
        if n == 0 && !fin {
            r.notified = false;
            return Err(StreamError::WouldBlock);
        }
        if r.data.is_empty() {
            r.notified = false;
        }
        // Stream credit: top up when less than half the window is left.
        if r.final_size.is_none() && r.max_data - r.read < r.window / 2 {
            r.max_data = r.read + r.window;
            self.control.push_back(Control::MaxStreamData(id));
        }
        if fin {
            r.fin_delivered = true;
        }
        self.recv_consumed += n as u64;
        self.maybe_max_data();
        if fin {
            self.maybe_remove(id);
        }
        Ok((n, fin))
    }

    fn maybe_max_data(&mut self) {
        if self.recv_max_data - self.recv_consumed < self.cfg.conn_window / 2 {
            self.recv_max_data = self.recv_consumed + self.cfg.conn_window;
            self.control.push_back(Control::MaxData);
        }
    }

    /// Abandons sending with RESET_STREAM.
    pub fn reset(&mut self, id: u64, code: u64) -> Result<(), StreamError> {
        let s = self.map.get_mut(&id).ok_or(StreamError::UnknownStream)?;
        let snd = s.send.as_mut().ok_or(StreamError::InvalidDirection)?;
        if snd.reset.is_some() || (snd.fin && snd.fin_acked) {
            return Ok(());
        }
        snd.reset = Some((code, snd.end()));
        snd.retransmit.clear();
        self.control.push_back(Control::ResetStream(id));
        Ok(())
    }

    /// Asks the peer to stop sending with STOP_SENDING; buffered data is discarded.
    pub fn stop(&mut self, id: u64, code: u64) -> Result<(), StreamError> {
        let s = self.map.get_mut(&id).ok_or(StreamError::UnknownStream)?;
        let r = s.recv.as_mut().ok_or(StreamError::InvalidDirection)?;
        if r.stop.is_some() || r.reset.is_some() || r.fin_delivered {
            return Ok(());
        }
        r.stop = Some(code);
        let unread = r.data.len() as u64;
        r.data.clear();
        self.recv_gaps -= r.gaps();
        r.ooo.clear();
        r.read = r.highest;
        self.recv_consumed += unread;
        if r.final_size.is_none() {
            self.control.push_back(Control::StopSending(id));
        }
        self.maybe_max_data();
        self.maybe_remove(id);
        Ok(())
    }

    // ---- packet assembly ----

    pub fn has_pending_data(&self) -> bool {
        !self.send_queue.is_empty()
    }

    /// Writes STREAM frames into `out` while at least `min_room` bytes are left before
    /// `limit`; records (id, off, len, fin) in `sent`.
    pub fn write_frames(&mut self, out: &mut Vec<u8>, limit: usize, sent: &mut Vec<crate::recovery::SentFrame>) {
        let mut rounds = self.send_queue.len();
        while rounds > 0 && out.len() + 8 < limit {
            rounds -= 1;
            let Some(id) = self.send_queue.pop_front() else { break };
            let Some(snd) = self.map.get_mut(&id).and_then(|s| s.send.as_mut()) else { continue };
            snd.queued = false;
            if !snd.has_pending() {
                continue;
            }
            let room = limit - out.len();
            let (off, avail, is_retx) = if let Some((s, e)) = snd.retransmit.first() {
                (s, e - s, true)
            } else {
                (snd.sent, snd.end() - snd.sent, false)
            };
            let hdr = frame::stream_overhead(id, off, room);
            if room <= hdr {
                snd.queued = true;
                self.send_queue.push_front(id);
                break;
            }
            let len = avail.min((room - hdr) as u64) as usize;
            let end = off + len as u64;
            let fin = snd.fin && end == snd.end() && (!is_retx || snd.sent == snd.end());
            if len == 0 && !fin {
                continue;
            }
            frame::put_stream_header(out, id, off, len, fin);
            let start = (off - snd.base) as usize;
            copy_range(&snd.buf, start, len, out);
            if is_retx {
                snd.retransmit.remove(off, end);
            } else {
                snd.sent = end;
            }
            if fin {
                snd.fin_sent = true;
            }
            sent.push(crate::recovery::SentFrame::Stream { id, off, len: len as u32, fin });
            if snd.has_pending() {
                snd.queued = true;
                self.send_queue.push_back(id);
            }
        }
    }

    /// Writes one control frame if it fits; returns false when it does not.
    pub fn write_control(&mut self, c: Control, out: &mut Vec<u8>, limit: usize) -> Option<bool> {
        let mut tmp = [0u64; 3];
        let (ty, n) = match c {
            Control::MaxData => {
                tmp[0] = self.recv_max_data;
                (frame::MAX_DATA, 1)
            }
            Control::MaxStreamData(id) => {
                let r = self.map.get(&id).and_then(|s| s.recv.as_ref())?;
                if r.final_size.is_some() || r.stop.is_some() {
                    return None;
                }
                tmp[0] = id;
                tmp[1] = r.max_data;
                (frame::MAX_STREAM_DATA, 2)
            }
            Control::MaxStreams(bidi) => {
                tmp[0] = self.local_max[(!bidi) as usize];
                (if bidi { frame::MAX_STREAMS_BIDI } else { frame::MAX_STREAMS_UNI }, 1)
            }
            Control::DataBlocked => {
                if self.written < self.send_max_data {
                    return None;
                }
                tmp[0] = self.send_max_data;
                (frame::DATA_BLOCKED, 1)
            }
            Control::StreamDataBlocked(id) => {
                let snd = self.map.get(&id).and_then(|s| s.send.as_ref())?;
                if snd.end() < snd.max_data || snd.reset.is_some() {
                    return None;
                }
                tmp[0] = id;
                tmp[1] = snd.max_data;
                (frame::STREAM_DATA_BLOCKED, 2)
            }
            Control::StreamsBlocked(bidi) => {
                let d = (!bidi) as usize;
                if self.next[d] < self.peer_max[d] {
                    return None;
                }
                tmp[0] = self.peer_max[d];
                (if bidi { frame::STREAMS_BLOCKED_BIDI } else { frame::STREAMS_BLOCKED_UNI }, 1)
            }
            Control::ResetStream(id) => {
                let snd = self.map.get(&id).and_then(|s| s.send.as_ref())?;
                let (code, fs) = snd.reset?;
                if snd.reset_acked {
                    return None;
                }
                tmp = [id, code, fs];
                (frame::RESET_STREAM, 3)
            }
            Control::StopSending(id) => {
                let r = self.map.get(&id).and_then(|s| s.recv.as_ref())?;
                let code = r.stop?;
                if r.final_size.is_some() {
                    return None;
                }
                tmp[0] = id;
                tmp[1] = code;
                (frame::STOP_SENDING, 2)
            }
        };
        let size = 1 + tmp[..n].iter().map(|&v| varint_len(v)).sum::<usize>();
        if out.len() + size > limit {
            return Some(false);
        }
        frame::put_simple(out, ty, &tmp[..n]);
        Some(true)
    }

    // ---- acknowledgements and loss ----

    pub fn on_stream_acked(&mut self, id: u64, off: u64, len: u64, fin: bool) {
        let Some(snd) = self.map.get_mut(&id).and_then(|s| s.send.as_mut()) else { return };
        // Only the part above `base` matters. An acknowledgement of bytes already released
        // (the original packet and its retransmission both acknowledged, as after a blackout)
        // must not be recorded: a range below `base` would stay first in `acked` forever, the
        // prefix check below would never pass again, and the send buffer would stay full.
        let lo = off.max(snd.base);
        if off + len > lo {
            snd.acked.insert(lo, off + len);
            // Release the acknowledged prefix.
            if let Some((s, e)) = snd.acked.first() {
                if s <= snd.base && e > snd.base {
                    let n = (e - snd.base) as usize;
                    snd.buf.drain(..n.min(snd.buf.len()));
                    snd.base = e;
                    snd.acked.remove_below(e);
                    snd.retransmit.remove_below(e);
                    if snd.want_writable {
                        snd.want_writable = false;
                        self.events.push_back(StreamEvent::Writable(id));
                    }
                }
            }
        }
        if fin {
            snd.fin_acked = true;
        }
        self.maybe_remove(id);
    }

    pub fn on_stream_lost(&mut self, id: u64, off: u64, len: u64, fin: bool) {
        let Some(snd) = self.map.get_mut(&id).and_then(|s| s.send.as_mut()) else { return };
        if snd.reset.is_some() {
            return;
        }
        let end = off + len;
        let lo = off.max(snd.base);
        if end > lo {
            snd.retransmit.insert(lo, end);
            // Do not resend what has since been acknowledged.
            for (s, e) in snd.acked.clone().iter() {
                snd.retransmit.remove(s, e);
            }
        }
        if fin && !snd.fin_acked {
            snd.fin_sent = false;
        }
        if !snd.queued && snd.has_pending() {
            snd.queued = true;
            self.send_queue.push_back(id);
        }
    }

    pub fn on_reset_acked(&mut self, id: u64) {
        if let Some(snd) = self.map.get_mut(&id).and_then(|s| s.send.as_mut()) {
            snd.reset_acked = true;
        }
        self.maybe_remove(id);
    }

    /// Removes a fully closed stream and, for peer streams, raises the stream limit.
    fn maybe_remove(&mut self, id: u64) {
        let Some(s) = self.map.get(&id) else { return };
        let send_done = s.send.as_ref().is_none_or(|x| x.is_done());
        let recv_done = s.recv.as_ref().is_none_or(|x| x.is_done());
        if !(send_done && recv_done) {
            return;
        }
        let s = self.map.remove(&id).unwrap();
        if let Some(snd) = &s.send {
            // Credit reserved for never-sent bytes stays consumed (it was counted against
            // the peer's window when written).
            let _ = snd;
        }
        if !self.local(id) {
            let d = dir(id);
            self.remote_closed[d] += 1;
            let max = if d == 0 { self.cfg.max_streams_bidi } else { self.cfg.max_streams_uni };
            let new = (self.remote_closed[d] + max).min(MAX_STREAMS_LIMIT);
            if new - self.local_max[d] >= (max / 2).max(1) {
                self.local_max[d] = new;
                self.control.push_back(Control::MaxStreams(d == 0));
            }
        }
    }

    /// True if the stream exists.
    pub fn contains(&self, id: u64) -> bool {
        self.map.contains_key(&id)
    }

    /// Bytes buffered and not yet acknowledged on a send stream.
    pub fn unacked(&self, id: u64) -> Option<u64> {
        self.map.get(&id)?.send.as_ref().map(|s| s.buf.len() as u64)
    }

    /// How many more bytes `write` would accept now.
    pub fn writable(&self, id: u64) -> Option<u64> {
        let snd = self.map.get(&id)?.send.as_ref()?;
        if snd.fin || snd.reset.is_some() {
            return Some(0);
        }
        Some(
            snd.max_data
                .saturating_sub(snd.end())
                .min(self.send_max_data - self.written)
                .min(self.cfg.send_buffer.saturating_sub(snd.buf.len() as u64)),
        )
    }
}

/// Appends `buf[start..start + len]` to `out`.
fn copy_range(buf: &VecDeque<u8>, start: usize, len: usize, out: &mut Vec<u8>) {
    let (a, b) = buf.as_slices();
    if start < a.len() {
        let n = (a.len() - start).min(len);
        out.extend_from_slice(&a[start..start + n]);
        out.extend_from_slice(&b[..len - n]);
    } else {
        let s = start - a.len();
        out.extend_from_slice(&b[s..s + len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::TransportParams;

    fn server() -> Streams {
        let mut s = Streams::new(
            true,
            StreamConfig {
                max_streams_bidi: 2,
                max_streams_uni: 1,
                stream_window_bidi_local: 100,
                stream_window_bidi_remote: 100,
                stream_window_uni: 100,
                conn_window: 150,
                send_buffer: 1000,
            },
        );
        let p = TransportParams {
            initial_max_data: 50,
            initial_max_stream_data_bidi_local: 30,
            initial_max_stream_data_bidi_remote: 30,
            initial_max_stream_data_uni: 30,
            initial_max_streams_bidi: 1,
            initial_max_streams_uni: 1,
            ..Default::default()
        };
        s.set_peer_params(&p);
        s
    }

    #[test]
    fn receive_side_enforcement() {
        let mut s = server();
        // Client bidi streams 0 and 4 are allowed, 8 exceeds the limit of 2.
        s.on_stream(0, 0, b"abc", false).unwrap();
        assert_eq!(s.on_stream(8, 0, b"x", false).unwrap_err().code, STREAM_LIMIT_ERROR);
        // Opening stream 4 implicitly is fine; it also announces stream 4.
        s.on_stream(4, 0, b"", false).unwrap();
        // Stream flow control (window 100).
        assert_eq!(s.on_stream(0, 98, b"xyz", false).unwrap_err().code, FLOW_CONTROL_ERROR);
        // Connection flow control (150 in total across streams).
        s.on_stream(0, 0, &[0; 100], false).unwrap();
        assert_eq!(s.on_stream(4, 0, &[0; 51], false).unwrap_err().code, FLOW_CONTROL_ERROR);
        // Final size rules.
        let mut s = server();
        s.on_stream(0, 0, b"hello", true).unwrap();
        assert_eq!(s.on_stream(0, 0, b"hello!", false).unwrap_err().code, FINAL_SIZE_ERROR);
        assert_eq!(s.on_stream(0, 0, b"hel", true).unwrap_err().code, FINAL_SIZE_ERROR);
        assert_eq!(s.on_reset(0, 1, 4).unwrap_err().code, FINAL_SIZE_ERROR);
        let mut s = server();
        s.on_stream(0, 0, b"hello", false).unwrap();
        assert_eq!(s.on_stream(0, 0, b"he", true).unwrap_err().code, FINAL_SIZE_ERROR);
        // Our own streams: unopened ones and send-only directions.
        let mut s = server();
        assert_eq!(s.on_stream(1, 0, b"x", false).unwrap_err().code, STREAM_STATE_ERROR);
        let uni = s.open(false).unwrap();
        assert_eq!(uni, 3);
        assert_eq!(s.on_stream(3, 0, b"x", false).unwrap_err().code, STREAM_STATE_ERROR);
        assert_eq!(s.on_stop_sending(2, 0).unwrap_err().code, STREAM_STATE_ERROR); // client uni
        assert_eq!(s.on_max_stream_data(2, 5).unwrap_err().code, STREAM_STATE_ERROR);
    }

    #[test]
    fn reassembly_out_of_order_and_overlapping() {
        let mut s = server();
        s.on_stream(0, 6, b"ghij", false).unwrap();
        s.on_stream(0, 3, b"defgh", false).unwrap();
        s.on_stream(0, 8, b"ijkl", true).unwrap();
        let mut out = [0u8; 32];
        assert_eq!(s.read(0, &mut out), Err(StreamError::WouldBlock));
        s.on_stream(0, 0, b"abcd", false).unwrap();
        let (n, fin) = s.read(0, &mut out).unwrap();
        assert_eq!(&out[..n], b"abcdefghijkl");
        assert!(fin);
        assert_eq!(s.events.iter().filter(|e| matches!(e, StreamEvent::Readable(0))).count(), 1);
    }

    fn wide() -> Streams {
        let w = 1 << 20;
        Streams::new(
            true,
            StreamConfig {
                max_streams_bidi: 4,
                max_streams_uni: 4,
                stream_window_bidi_local: w,
                stream_window_bidi_remote: w,
                stream_window_uni: w,
                conn_window: w,
                send_buffer: 1000,
            },
        )
    }

    fn gaps(s: &Streams, id: u64) -> usize {
        s.map.get(&id).unwrap().recv.as_ref().unwrap().gaps()
    }

    #[test]
    fn adjacent_out_of_order_chunks_merge_and_reassemble() {
        // Chunks of 1..=7 bytes over 0..2000 delivered out of order (odd ones, then even ones,
        // then all again as duplicates): adjacent buffered chunks merge, so the map holds one
        // entry per gap, and the data comes out intact.
        let data: Vec<u8> = (0..2000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut chunks = Vec::new();
        let mut off = 0usize;
        while off < data.len() {
            let end = (off + 1 + off % 7).min(data.len());
            chunks.push((off, end));
            off = end;
        }
        let mut st = wide();
        let odd = (1..chunks.len()).filter(|i| i % 2 == 1);
        let even = (1..chunks.len()).filter(|i| i % 2 == 0);
        for i in odd.chain(even).chain(1..chunks.len()) {
            let (a, b) = chunks[i];
            st.on_stream(0, a as u64, &data[a..b], b == data.len()).unwrap();
            assert!(gaps(&st, 0) <= chunks.len() / 2 + 1);
        }
        assert_eq!(gaps(&st, 0), 1, "everything after the first hole merged into one chunk");
        st.on_stream(0, 0, &data[..chunks[0].1], false).unwrap();
        let mut out = vec![0u8; 4096];
        let (n, fin) = st.read(0, &mut out).unwrap();
        assert_eq!(&out[..n], &data[..]);
        assert!(fin);
    }

    #[test]
    fn too_many_out_of_order_gaps_is_an_error() {
        let mut st = wide();
        for i in 0..MAX_RECV_GAPS as u64 {
            st.on_stream(0, 2 + 2 * i, b"x", false).unwrap();
        }
        assert_eq!(gaps(&st, 0), MAX_RECV_GAPS);
        let e = st.on_stream(0, 2 + 2 * MAX_RECV_GAPS as u64, b"x", false).unwrap_err();
        assert_eq!(e.code, PROTOCOL_VIOLATION);
    }

    /// The cap is per connection: spreading holes over many streams does not multiply it, and
    /// a reset stream gives its holes back.
    #[test]
    fn out_of_order_gap_cap_is_per_connection() {
        let mut st = wide();
        let per = (MAX_RECV_GAPS / 4) as u64;
        for id in [0u64, 4, 8, 12] {
            for i in 0..per {
                st.on_stream(id, 2 + 2 * i, b"x", false).unwrap();
            }
        }
        assert_eq!(st.recv_gaps, MAX_RECV_GAPS);
        let e = st.on_stream(4, 2 + 2 * per, b"x", false).unwrap_err();
        assert_eq!(e.code, PROTOCOL_VIOLATION, "one more hole on any stream is over the connection's cap");
        let mut st = wide();
        for i in 0..per {
            st.on_stream(0, 2 + 2 * i, b"x", false).unwrap();
        }
        st.on_reset(0, 0, 2 + 2 * per).unwrap();
        assert_eq!(st.recv_gaps, 0, "a reset stream's holes no longer count");
        // Filling holes merges chunks and lowers the count.
        st.on_stream(4, 2, b"x", false).unwrap();
        st.on_stream(4, 4, b"x", false).unwrap();
        assert_eq!(st.recv_gaps, 2);
        st.on_stream(4, 3, b"x", false).unwrap();
        assert_eq!(st.recv_gaps, 1, "adjacent chunks merged into one hole");
        st.on_stream(4, 0, b"xx", false).unwrap();
        assert_eq!(st.recv_gaps, 0);
    }

    #[test]
    fn send_side_credit_and_limits() {
        let mut s = server();
        let id = s.open(true).unwrap();
        assert_eq!(id, 1);
        assert_eq!(s.open(true), Err(StreamError::LimitReached));
        assert_eq!(s.control.back(), Some(&Control::StreamsBlocked(true)));
        // Stream credit 30.
        assert_eq!(s.write(id, &[1; 100], false), Ok(30));
        assert_eq!(s.write(id, &[1; 1], false), Err(StreamError::Blocked));
        assert!(s.control.contains(&Control::StreamDataBlocked(id)));
        s.on_max_stream_data(id, 100).unwrap();
        assert_eq!(s.events.back(), Some(&StreamEvent::Writable(id)));
        // Connection credit 50: 20 more.
        assert_eq!(s.write(id, &[1; 100], false), Ok(20));
        assert!(s.write(id, &[1; 1], false).is_err());
        assert!(s.control.contains(&Control::DataBlocked));
        s.on_max_streams(true, 2);
        assert_eq!(s.events.back(), Some(&StreamEvent::Available(true)));
        // Frames carry the data and acks free the buffer.
        let mut out = Vec::new();
        let mut sent = Vec::new();
        s.write_frames(&mut out, 1000, &mut sent);
        assert_eq!(sent, vec![crate::recovery::SentFrame::Stream { id, off: 0, len: 50, fin: false }]);
        s.on_stream_lost(id, 10, 20, false);
        out.clear();
        sent.clear();
        s.write_frames(&mut out, 1000, &mut sent);
        assert_eq!(sent, vec![crate::recovery::SentFrame::Stream { id, off: 10, len: 20, fin: false }]);
        s.on_stream_acked(id, 0, 50, false);
        assert_eq!(s.unacked(id), Some(0));
        // A late acknowledgement of the retransmission, for bytes already released, must not
        // block later releases (found by the interop runner's blackhole case).
        s.on_stream_acked(id, 10, 20, false);
        s.on_max_data(1000);
        s.on_max_stream_data(id, 1000).unwrap();
        assert_eq!(s.write(id, &[2; 30], false), Ok(30));
        out.clear();
        sent.clear();
        s.write_frames(&mut out, 1000, &mut sent);
        s.on_stream_acked(id, 50, 30, false);
        assert_eq!(s.unacked(id), Some(0), "the buffer is released after a stale acknowledgement");
    }

    #[test]
    fn peer_streams_raise_max_streams_when_closed() {
        let mut s = server();
        s.on_stream(0, 0, b"a", true).unwrap();
        let mut b = [0u8; 4];
        s.read(0, &mut b).unwrap();
        s.write(0, b"", true).unwrap();
        let mut out = Vec::new();
        let mut sent = Vec::new();
        s.write_frames(&mut out, 1000, &mut sent);
        s.on_stream_acked(0, 0, 0, true);
        assert!(!s.contains(0));
        assert!(s.control.contains(&Control::MaxStreams(true)));
        // Stream 8 (index 2) is now allowed.
        s.on_stream(8, 0, b"x", false).unwrap();
    }
}
