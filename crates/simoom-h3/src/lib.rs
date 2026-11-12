//! Sans-io HTTP/3 (RFC 9114) for simoom, on top of [`simoom_quic::Connection`] streams.
//!
//! [`Http3`] owns the HTTP/3 state of one QUIC connection: the control and QPACK streams,
//! SETTINGS, GOAWAY, and the frame parser of every request stream. Feed it the QUIC events
//! of its connection with [`Http3::handle`], then drain [`Http3::poll_event`]. A server
//! answers [`H3Event::Headers`] with [`Http3::send_headers`] and [`Http3::send_body`]; body
//! sending reports how much was accepted, so a slow client pushes back on the handler.
//!
//! The same type acts as a client ([`Http3::send_request`]), used by the tests.

#![forbid(unsafe_code)]

mod frame;
mod validate;

pub use frame::Settings;
pub use simoom_qpack::Field;
pub use validate::{pseudo, validate_request, validate_response, validate_trailers, Validated};

use simoom_qpack::{Decoded, Decoder, Encoder};
use simoom_quic::coding::{put_varint, varint_len, Reader};
use simoom_quic::stream::{is_bidi, is_server_initiated, IdMap};
use simoom_quic::{Connection, Event, StreamError};
use std::collections::VecDeque;
use std::time::Instant;

/// The DATA frame queued when a stream has room for less than a frame header and a byte
/// ([`Http3::send_body`]).
const SMALL_FRAME: usize = 16 * 1024;

/// Registers with QUIC that a stream with no room left wants to write, so it reports
/// [`Event::StreamWritable`] when credit arrives. Offering a byte to a stream with no room is
/// refused (`Blocked`) and does exactly that; nothing is written.
fn mark_blocked(conn: &mut Connection, stream: u64) {
    if conn.stream_writable(stream) == Some(0) {
        let r = conn.stream_send(stream, &[0], false);
        debug_assert!(!matches!(r, Ok(n) if n > 0), "a stream with no room accepted data");
    }
}

/// HTTP/3 error codes (RFC 9114 §8.1).
pub mod code {
    pub const NO_ERROR: u64 = 0x100;
    pub const GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    pub const INTERNAL_ERROR: u64 = 0x102;
    pub const STREAM_CREATION_ERROR: u64 = 0x103;
    pub const CLOSED_CRITICAL_STREAM: u64 = 0x104;
    pub const FRAME_UNEXPECTED: u64 = 0x105;
    pub const FRAME_ERROR: u64 = 0x106;
    pub const EXCESSIVE_LOAD: u64 = 0x107;
    pub const ID_ERROR: u64 = 0x108;
    pub const SETTINGS_ERROR: u64 = 0x109;
    pub const MISSING_SETTINGS: u64 = 0x10a;
    pub const REQUEST_REJECTED: u64 = 0x10b;
    pub const REQUEST_CANCELLED: u64 = 0x10c;
    pub const REQUEST_INCOMPLETE: u64 = 0x10d;
    pub const MESSAGE_ERROR: u64 = 0x10e;
    pub const CONNECT_ERROR: u64 = 0x10f;
    pub const VERSION_FALLBACK: u64 = 0x110;
}

/// A connection-level HTTP/3 error; the connection is closed with this code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H3Error {
    pub code: u64,
    pub reason: &'static str,
}

impl H3Error {
    pub const fn new(code: u64, reason: &'static str) -> Self {
        H3Error { code, reason }
    }
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP/3 error 0x{:x}: {}", self.code, self.reason)
    }
}

impl std::error::Error for H3Error {}

/// Errors of the per-request API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// Unknown or finished stream.
    UnknownStream,
    /// Headers were already sent, or not yet sent before a body.
    InvalidState,
    /// The field section is larger than the peer allows.
    HeadersTooLarge,
    /// The peer sent GOAWAY: no new requests.
    GoingAway,
    Stream(StreamError),
}

impl From<StreamError> for SendError {
    fn from(e: StreamError) -> Self {
        SendError::Stream(e)
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// SETTINGS_MAX_FIELD_SECTION_SIZE we announce and enforce.
    pub max_field_section_size: u64,
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY we announce (decoder side).
    pub qpack_max_table_capacity: u64,
    /// SETTINGS_QPACK_BLOCKED_STREAMS we announce.
    pub qpack_blocked_streams: u64,
    /// Use a dynamic table when encoding, up to this capacity (0 = static table only).
    pub qpack_encoder_capacity: u64,
    /// Body bytes buffered per stream before reading from QUIC stops (backpressure).
    pub body_buffer: usize,
    /// Server: announce SETTINGS_ENABLE_CONNECT_PROTOCOL and accept extended CONNECT with
    /// `:protocol` (RFC 9220, WebSocket over HTTP/3). Without it such requests are malformed.
    pub enable_connect_protocol: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_field_section_size: 16 << 10,
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            qpack_encoder_capacity: 0,
            body_buffer: 64 << 10,
            enable_connect_protocol: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum H3Event {
    /// Request headers (server) or response headers (client), validated.
    Headers { stream: u64, fields: Vec<Field> },
    /// Body bytes are available on `stream`: call [`Http3::recv_body`].
    Data { stream: u64 },
    Trailers { stream: u64, fields: Vec<Field> },
    /// The peer finished the message (all body bytes have been read).
    Finished { stream: u64 },
    /// The peer abandoned the stream, or we rejected a malformed message with `code`.
    Reset { stream: u64, code: u64 },
    /// More body may be sent on `stream`.
    Writable { stream: u64 },
    /// The peer sent GOAWAY.
    GoAway { id: u64 },
    /// The connection failed with this HTTP/3 error and is closing.
    Error(H3Error),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UniKind {
    Unknown,
    Control,
    Encoder,
    Decoder,
}

struct UniIn {
    kind: UniKind,
    buf: Vec<u8>,
}

#[derive(Default)]
struct Req {
    inbuf: Vec<u8>,
    body: VecDeque<u8>,
    /// Bytes left in the current DATA frame, or in an unknown frame being skipped.
    data_left: u64,
    skip_left: u64,
    headers_done: bool,
    trailers_done: bool,
    /// Waiting for QPACK encoder-stream data.
    blocked: bool,
    fin_seen: bool,
    finished: bool,
    content_length: Option<u64>,
    body_len: u64,
    data_event: bool,
    // Sending.
    out: Vec<u8>,
    headers_sent: bool,
    finish_after_out: bool,
    send_done: bool,
    want_writable: bool,
}

pub struct Http3 {
    is_server: bool,
    cfg: Config,
    encoder: Encoder,
    decoder: Decoder,
    control_out: Option<u64>,
    encoder_out: Option<u64>,
    decoder_out: Option<u64>,
    pending_uni: VecDeque<(u64, Vec<u8>)>,
    uni: IdMap<UniIn>,
    have: [bool; 3],
    peer_settings: Option<Settings>,
    reqs: IdMap<Req>,
    events: VecDeque<H3Event>,
    pending_fields: VecDeque<(u64, Option<Vec<Field>>)>,
    goaway_sent: Option<u64>,
    goaway_recv: Option<u64>,
    max_request: Option<u64>,
    failed: bool,
    scratch: Vec<u8>,
}

impl Http3 {
    pub fn new(is_server: bool, cfg: Config) -> Self {
        let encoder = if cfg.qpack_encoder_capacity > 0 {
            Encoder::with_dynamic_table(cfg.qpack_encoder_capacity)
        } else {
            Encoder::new()
        };
        let decoder = Decoder::new(cfg.qpack_max_table_capacity, cfg.qpack_blocked_streams, cfg.max_field_section_size);
        Http3 {
            is_server,
            encoder,
            decoder,
            control_out: None,
            encoder_out: None,
            decoder_out: None,
            pending_uni: VecDeque::new(),
            uni: IdMap::default(),
            have: [false; 3],
            peer_settings: None,
            reqs: IdMap::default(),
            events: VecDeque::new(),
            pending_fields: VecDeque::new(),
            goaway_sent: None,
            goaway_recv: None,
            max_request: None,
            failed: false,
            scratch: vec![0; 16 << 10],
            cfg,
        }
    }

    pub fn poll_event(&mut self) -> Option<H3Event> {
        self.events.pop_front()
    }

    /// The peer (a server) accepts extended CONNECT (RFC 9220): its SETTINGS carried
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL = 1. `None` until its SETTINGS arrived.
    pub fn peer_connect_protocol(&self) -> Option<bool> {
        self.peer_settings.as_ref().map(|s| s.enable_connect_protocol == Some(1))
    }

    /// The peer's SETTINGS, once received.
    pub fn peer_settings(&self) -> Option<&Settings> {
        self.peer_settings.as_ref()
    }

    /// Request streams currently tracked.
    pub fn active_streams(&self) -> usize {
        self.reqs.len()
    }

    /// Opens the control and QPACK streams and sends SETTINGS. [`Http3::handle`] does this
    /// on [`Event::Connected`]; call it directly if the connection was established before.
    pub fn open(&mut self, conn: &mut Connection) {
        if self.control_out.is_some() {
            return;
        }
        let mut b = Vec::with_capacity(32);
        put_varint(&mut b, 0x00);
        Settings {
            max_field_section_size: Some(self.cfg.max_field_section_size),
            qpack_max_table_capacity: Some(self.cfg.qpack_max_table_capacity),
            qpack_blocked_streams: Some(self.cfg.qpack_blocked_streams),
            enable_connect_protocol: (self.is_server && self.cfg.enable_connect_protocol).then_some(1),
        }
        .encode(&mut b);
        self.control_out = self.open_uni(conn, b);
        self.encoder_out = self.open_uni(conn, vec![0x02]);
        self.decoder_out = self.open_uni(conn, vec![0x03]);
    }

    fn open_uni(&mut self, conn: &mut Connection, prefix: Vec<u8>) -> Option<u64> {
        let id = conn.open_uni().ok()?;
        self.pending_uni.push_back((id, prefix));
        self.flush_uni(conn);
        Some(id)
    }

    fn flush_uni(&mut self, conn: &mut Connection) {
        for e in self.pending_uni.iter_mut() {
            if let Ok(k) = conn.stream_send(e.0, &e.1, false) {
                e.1.drain(..k);
            }
        }
        self.pending_uni.retain(|e| !e.1.is_empty());
    }

    fn send_uni(&mut self, conn: &mut Connection, id: Option<u64>, data: &[u8]) {
        let Some(id) = id else { return };
        if data.is_empty() {
            return;
        }
        if let Some(e) = self.pending_uni.iter_mut().find(|e| e.0 == id) {
            e.1.extend_from_slice(data);
            return;
        }
        self.pending_uni.push_back((id, data.to_vec()));
        self.flush_uni(conn);
    }

    /// Writes queued QPACK instructions.
    fn flush_qpack(&mut self, conn: &mut Connection) {
        let mut b = Vec::new();
        self.decoder.take_decoder_stream(&mut b);
        let d = self.decoder_out;
        self.send_uni(conn, d, &b);
        b.clear();
        self.encoder.take_encoder_stream(&mut b);
        let e = self.encoder_out;
        self.send_uni(conn, e, &b);
    }

    fn fail(&mut self, now: Instant, conn: &mut Connection, e: H3Error) {
        if self.failed {
            return;
        }
        self.failed = true;
        conn.close(now, e.code, e.reason.as_bytes());
        self.events.push_back(H3Event::Error(e));
    }

    /// A stream error: abandon both directions of a request with `code`.
    fn reject(&mut self, conn: &mut Connection, id: u64, code: u64) {
        self.reset_stream(conn, id, code);
        self.events.push_back(H3Event::Reset { stream: id, code });
    }

    /// Feeds one QUIC event of this connection.
    pub fn handle(&mut self, now: Instant, conn: &mut Connection, ev: &Event) {
        if self.failed {
            return;
        }
        let r = match *ev {
            Event::Connected => {
                self.open(conn);
                Ok(())
            }
            Event::StreamOpened(id) => self.on_opened(conn, id),
            Event::StreamReadable(id) => self.on_readable(conn, id),
            Event::StreamWritable(id) => {
                self.on_writable(conn, id);
                Ok(())
            }
            Event::StreamReset { id, code } => self.on_reset(conn, id, code),
            Event::StreamStopped { id, code } => self.on_stopped(id, code),
            Event::Closed(_) | Event::StreamsAvailable(_) | Event::PathMigrated(_) => Ok(()),
        };
        let r = r.and_then(|_| self.resume_unblocked(conn));
        if let Err(e) = r {
            self.fail(now, conn, e);
            return;
        }
        self.flush_qpack(conn);
    }

    fn is_local_critical(&self, id: u64) -> bool {
        Some(id) == self.control_out || Some(id) == self.encoder_out || Some(id) == self.decoder_out
    }

    fn on_stopped(&mut self, id: u64, code_: u64) -> Result<(), H3Error> {
        if self.is_local_critical(id) {
            return Err(H3Error::new(code::CLOSED_CRITICAL_STREAM, "critical stream stopped"));
        }
        if let Some(r) = self.reqs.get_mut(&id) {
            // STOP_SENDING ends only our sending direction; the other side goes on (RFC 9114
            // §4.1.1: a server may answer before it has read the whole request, and the client
            // must not discard a complete response because its request was cut off). Once our
            // side was already finished there is nothing to report: quinn, for one, stops every
            // request stream it has not read to the end, with code 0. While we were still
            // sending, H3_NO_ERROR means "answered without the rest"; any other code abandons it.
            let was_done = r.send_done;
            r.send_done = true;
            r.out.clear();
            if !was_done && code_ != code::NO_ERROR {
                self.events.push_back(H3Event::Reset { stream: id, code: code_ });
            }
            self.maybe_drop(id);
        }
        Ok(())
    }

    fn on_opened(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        if is_bidi(id) {
            if !self.is_server || is_server_initiated(id) {
                return Err(H3Error::new(code::STREAM_CREATION_ERROR, "unexpected bidirectional stream"));
            }
            if self.goaway_sent.is_some_and(|g| id >= g) {
                let _ = conn.stream_stop(id, code::REQUEST_REJECTED);
                let _ = conn.stream_reset(id, code::REQUEST_REJECTED);
                return Ok(());
            }
            self.max_request = Some(self.max_request.map_or(id, |m| m.max(id)));
            self.reqs.insert(id, Req::default());
        } else {
            self.uni.insert(id, UniIn { kind: UniKind::Unknown, buf: Vec::new() });
        }
        Ok(())
    }

    fn on_reset(&mut self, conn: &mut Connection, id: u64, code_: u64) -> Result<(), H3Error> {
        if let Some(u) = self.uni.get(&id) {
            if u.kind != UniKind::Unknown {
                return Err(H3Error::new(code::CLOSED_CRITICAL_STREAM, "critical stream reset"));
            }
            self.uni.remove(&id);
            return Ok(());
        }
        if let Some(r) = self.reqs.remove(&id) {
            if !r.headers_done || r.blocked {
                self.decoder.cancel_stream(id);
            }
            self.events.push_back(H3Event::Reset { stream: id, code: code_ });
            // Our side of a reset request is abandoned too (RFC 9114 §4.1.1).
            if !r.send_done {
                let _ = conn.stream_reset(id, code::REQUEST_CANCELLED);
            }
        }
        Ok(())
    }

    fn on_writable(&mut self, conn: &mut Connection, id: u64) {
        if self.pending_uni.iter().any(|e| e.0 == id) {
            self.flush_uni(conn);
            return;
        }
        let Some(r) = self.reqs.get_mut(&id) else { return };
        if !r.out.is_empty() {
            if let Ok(k) = conn.stream_send(id, &r.out, false) {
                r.out.drain(..k);
            }
            if r.out.is_empty() && r.finish_after_out {
                let _ = conn.stream_finish(id);
                r.send_done = true;
            }
        }
        if r.out.is_empty() && r.want_writable && !r.send_done {
            r.want_writable = false;
            self.events.push_back(H3Event::Writable { stream: id });
        }
        self.maybe_drop(id);
    }

    fn on_readable(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        if self.uni.contains_key(&id) {
            return self.read_uni(conn, id);
        }
        if self.reqs.contains_key(&id) {
            return self.pump(conn, id);
        }
        // A stream we rejected or no longer track: discard what arrives.
        let mut b = std::mem::take(&mut self.scratch);
        while let Ok((n, fin)) = conn.stream_recv(id, &mut b) {
            if n == 0 || fin {
                break;
            }
        }
        self.scratch = b;
        Ok(())
    }

    // ------------------------------------------------------------- unidirectional

    fn read_uni(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        let mut b = std::mem::take(&mut self.scratch);
        let res = self.read_uni_inner(conn, id, &mut b);
        self.scratch = b;
        res
    }

    fn read_uni_inner(&mut self, conn: &mut Connection, id: u64, b: &mut [u8]) -> Result<(), H3Error> {
        loop {
            let (n, fin) = match conn.stream_recv(id, b) {
                Ok(x) => x,
                Err(_) => return Ok(()),
            };
            let Some(u) = self.uni.get_mut(&id) else { return Ok(()) };
            if u.kind == UniKind::Unknown {
                u.buf.extend_from_slice(&b[..n]);
                let Some((ty, len)) = Reader::new(&u.buf).varint_with_len() else {
                    if fin {
                        self.uni.remove(&id);
                        return Ok(());
                    }
                    if n == 0 {
                        return Ok(());
                    }
                    continue;
                };
                let kind = match ty {
                    0x00 => UniKind::Control,
                    0x02 => UniKind::Encoder,
                    0x03 => UniKind::Decoder,
                    0x01 => {
                        return Err(if self.is_server {
                            H3Error::new(code::STREAM_CREATION_ERROR, "push stream from a client")
                        } else {
                            H3Error::new(code::ID_ERROR, "push stream without MAX_PUSH_ID")
                        })
                    }
                    _ => {
                        // Unknown stream types are ignored (RFC 9114 §6.2).
                        let _ = conn.stream_stop(id, code::STREAM_CREATION_ERROR);
                        self.uni.remove(&id);
                        return Ok(());
                    }
                };
                let slot = kind as usize - 1;
                if self.have[slot] {
                    return Err(H3Error::new(code::STREAM_CREATION_ERROR, "duplicate critical stream"));
                }
                self.have[slot] = true;
                let u = self.uni.get_mut(&id).unwrap();
                u.kind = kind;
                let pending = u.buf.split_off(len);
                u.buf.clear();
                self.uni_data(id, kind, &pending)?;
            } else if n > 0 {
                let kind = u.kind;
                self.uni_data(id, kind, &b[..n])?;
            }
            if fin {
                return Err(H3Error::new(code::CLOSED_CRITICAL_STREAM, "critical stream closed"));
            }
            if n == 0 {
                return Ok(());
            }
        }
    }

    fn uni_data(&mut self, id: u64, kind: UniKind, data: &[u8]) -> Result<(), H3Error> {
        match kind {
            UniKind::Encoder => {
                let unblocked = self
                    .decoder
                    .on_encoder_stream(data)
                    .map_err(|e| H3Error::new(e.code(), "QPACK encoder stream error"))?;
                for (sid, res) in unblocked {
                    if let Some(r) = self.reqs.get_mut(&sid) {
                        r.blocked = false;
                    }
                    match res {
                        Ok(f) => self.pending_fields.push_back((sid, Some(f))),
                        Err(simoom_qpack::Error::FieldSectionTooLarge) => self.pending_fields.push_back((sid, None)),
                        Err(e) => return Err(H3Error::new(e.code(), "QPACK decompression failed")),
                    }
                }
                Ok(())
            }
            UniKind::Decoder => self
                .encoder
                .on_decoder_stream(data)
                .map_err(|e| H3Error::new(e.code(), "QPACK decoder stream error")),
            UniKind::Control => {
                let u = self.uni.get_mut(&id).unwrap();
                u.buf.extend_from_slice(data);
                let buf = std::mem::take(&mut u.buf);
                let used = self.control_frames(&buf)?;
                let u = self.uni.get_mut(&id).unwrap();
                u.buf = buf[used..].to_vec();
                Ok(())
            }
            UniKind::Unknown => Ok(()),
        }
    }

    /// Parses complete control-stream frames; returns the bytes consumed.
    fn control_frames(&mut self, buf: &[u8]) -> Result<usize, H3Error> {
        let mut pos = 0;
        loop {
            let mut r = Reader::new(&buf[pos..]);
            let (Some(ty), Some(len)) = (r.varint(), r.varint()) else {
                if buf.len() - pos > 16 {
                    return Err(H3Error::new(code::FRAME_ERROR, "bad frame header"));
                }
                return Ok(pos);
            };
            if self.peer_settings.is_none() && ty != frame::SETTINGS {
                return Err(H3Error::new(code::MISSING_SETTINGS, "first control frame is not SETTINGS"));
            }
            // Control frames are small; refuse to buffer large ones.
            if len > 16 << 10 {
                return Err(H3Error::new(code::EXCESSIVE_LOAD, "control frame too large"));
            }
            if (r.remaining() as u64) < len {
                return Ok(pos);
            }
            let payload = r.bytes(len as usize).unwrap();
            pos += r.position();
            match ty {
                frame::SETTINGS => {
                    if self.peer_settings.is_some() {
                        return Err(H3Error::new(code::FRAME_UNEXPECTED, "second SETTINGS"));
                    }
                    let s = Settings::decode(payload)?;
                    self.encoder
                        .set_peer_settings(s.qpack_max_table_capacity.unwrap_or(0), s.qpack_blocked_streams.unwrap_or(0));
                    self.peer_settings = Some(s);
                }
                frame::GOAWAY => {
                    let id = frame::single_varint(payload)?;
                    if !self.is_server && (is_server_initiated(id) || !is_bidi(id)) {
                        return Err(H3Error::new(code::ID_ERROR, "GOAWAY with a non-request stream ID"));
                    }
                    if self.goaway_recv.is_some_and(|g| id > g) {
                        return Err(H3Error::new(code::ID_ERROR, "GOAWAY ID increased"));
                    }
                    self.goaway_recv = Some(id);
                    self.events.push_back(H3Event::GoAway { id });
                }
                frame::MAX_PUSH_ID => {
                    if !self.is_server {
                        return Err(H3Error::new(code::FRAME_UNEXPECTED, "MAX_PUSH_ID from a server"));
                    }
                    frame::single_varint(payload)?;
                }
                frame::CANCEL_PUSH => {
                    frame::single_varint(payload)?;
                }
                frame::DATA | frame::HEADERS | frame::PUSH_PROMISE => {
                    return Err(H3Error::new(code::FRAME_UNEXPECTED, "frame not allowed on the control stream"))
                }
                t if frame::is_reserved_h2(t) => return Err(H3Error::new(code::FRAME_UNEXPECTED, "HTTP/2 frame type")),
                _ => {} // Unknown and reserved (grease) frames are ignored.
            }
        }
    }

    // ------------------------------------------------------------- request streams

    fn pump(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        let mut b = std::mem::take(&mut self.scratch);
        let res = self.pump_inner(conn, id, &mut b);
        self.scratch = b;
        res
    }

    /// Reads from QUIC into the request's buffers and parses frames, stopping when the body
    /// buffer is full so QUIC flow control pushes back on the peer.
    fn pump_inner(&mut self, conn: &mut Connection, id: u64, b: &mut [u8]) -> Result<(), H3Error> {
        loop {
            let Some(r) = self.reqs.get_mut(&id) else { return Ok(()) };
            if r.fin_seen || r.blocked || r.body.len() >= self.cfg.body_buffer || r.inbuf.len() > b.len() * 2 {
                break;
            }
            match conn.stream_recv(id, b) {
                Ok((n, fin)) => {
                    r.inbuf.extend_from_slice(&b[..n]);
                    r.fin_seen = fin;
                    self.parse(conn, id)?;
                    if n == 0 && !fin {
                        break;
                    }
                }
                Err(StreamError::Reset(c)) => return self.on_reset(conn, id, c),
                Err(_) => break,
            }
        }
        self.parse(conn, id)?;
        self.after_parse(conn, id);
        Ok(())
    }

    fn after_parse(&mut self, conn: &mut Connection, id: u64) {
        let Some(r) = self.reqs.get_mut(&id) else { return };
        if !r.body.is_empty() && !r.data_event {
            r.data_event = true;
            self.events.push_back(H3Event::Data { stream: id });
        }
        if r.fin_seen && !r.finished && r.inbuf.is_empty() && !r.blocked {
            if r.data_left > 0 || r.skip_left > 0 {
                self.reject(conn, id, code::FRAME_ERROR);
            } else if !r.headers_done {
                self.reject(conn, id, code::REQUEST_INCOMPLETE);
            } else if r.content_length.is_some_and(|cl| cl != r.body_len) {
                self.reject(conn, id, code::MESSAGE_ERROR);
            } else if r.body.is_empty() {
                r.finished = true;
                self.events.push_back(H3Event::Finished { stream: id });
                self.maybe_drop(id);
            }
        }
    }

    fn parse(&mut self, conn: &mut Connection, id: u64) -> Result<(), H3Error> {
        loop {
            let max_fs = self.cfg.max_field_section_size;
            let body_cap = self.cfg.body_buffer;
            let Some(r) = self.reqs.get_mut(&id) else { return Ok(()) };
            if r.blocked || r.inbuf.is_empty() {
                return Ok(());
            }
            if r.data_left > 0 {
                if r.body.len() >= body_cap {
                    return Ok(());
                }
                let n = (r.data_left as usize).min(r.inbuf.len()).min(body_cap - r.body.len());
                r.body.extend(&r.inbuf[..n]);
                r.inbuf.drain(..n);
                r.data_left -= n as u64;
                r.body_len += n as u64;
                if r.content_length.is_some_and(|cl| r.body_len > cl) {
                    self.reject(conn, id, code::MESSAGE_ERROR);
                    return Ok(());
                }
                continue;
            }
            if r.skip_left > 0 {
                let n = (r.skip_left as usize).min(r.inbuf.len());
                r.inbuf.drain(..n);
                r.skip_left -= n as u64;
                continue;
            }
            let mut rd = Reader::new(&r.inbuf);
            let (Some(ty), Some(len)) = (rd.varint(), rd.varint()) else {
                if r.inbuf.len() > 16 {
                    return Err(H3Error::new(code::FRAME_ERROR, "bad frame header"));
                }
                return Ok(());
            };
            let hdr = rd.position();
            match ty {
                frame::DATA => {
                    if !r.headers_done || r.trailers_done {
                        return Err(H3Error::new(code::FRAME_UNEXPECTED, "DATA before HEADERS or after trailers"));
                    }
                    r.inbuf.drain(..hdr);
                    r.data_left = len;
                }
                frame::HEADERS => {
                    if r.trailers_done {
                        return Err(H3Error::new(code::FRAME_UNEXPECTED, "HEADERS after trailers"));
                    }
                    if len > max_fs + 1024 {
                        self.reject(conn, id, code::EXCESSIVE_LOAD);
                        return Ok(());
                    }
                    if ((r.inbuf.len() - hdr) as u64) < len {
                        return Ok(());
                    }
                    let end = hdr + len as usize;
                    let block: Vec<u8> = r.inbuf[hdr..end].to_vec();
                    r.inbuf.drain(..end);
                    match self.decoder.decode(id, &block) {
                        Ok(Decoded::Fields(f)) => self.on_fields(conn, id, f),
                        Ok(Decoded::Blocked) => {
                            self.reqs.get_mut(&id).unwrap().blocked = true;
                            return Ok(());
                        }
                        Err(simoom_qpack::Error::FieldSectionTooLarge) => {
                            self.reject(conn, id, code::EXCESSIVE_LOAD);
                            return Ok(());
                        }
                        Err(e) => return Err(H3Error::new(e.code(), "QPACK decompression failed")),
                    }
                }
                frame::PUSH_PROMISE => {
                    return Err(if self.is_server {
                        H3Error::new(code::FRAME_UNEXPECTED, "PUSH_PROMISE from a client")
                    } else {
                        H3Error::new(code::ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID")
                    })
                }
                frame::SETTINGS | frame::GOAWAY | frame::MAX_PUSH_ID | frame::CANCEL_PUSH => {
                    return Err(H3Error::new(code::FRAME_UNEXPECTED, "control frame on a request stream"))
                }
                t if frame::is_reserved_h2(t) => return Err(H3Error::new(code::FRAME_UNEXPECTED, "HTTP/2 frame type")),
                _ => {
                    r.inbuf.drain(..hdr);
                    r.skip_left = len;
                }
            }
        }
    }

    fn on_fields(&mut self, conn: &mut Connection, id: u64, fields: Vec<Field>) {
        let is_server = self.is_server;
        let Some(r) = self.reqs.get_mut(&id) else { return };
        if !r.headers_done {
            let mut res = if is_server { validate_request(&fields) } else { validate_response(&fields) };
            if is_server && !self.cfg.enable_connect_protocol && fields.iter().any(|f| f.name == b":protocol") {
                res = Err(());
            }
            match res {
                Ok(v) => {
                    if !v.informational {
                        r.headers_done = true;
                        r.content_length = v.content_length;
                    }
                    self.events.push_back(H3Event::Headers { stream: id, fields });
                }
                Err(()) => self.reject(conn, id, code::MESSAGE_ERROR),
            }
        } else if validate_trailers(&fields).is_err() {
            self.reject(conn, id, code::MESSAGE_ERROR);
        } else {
            r.trailers_done = true;
            self.events.push_back(H3Event::Trailers { stream: id, fields });
        }
    }

    /// Applies field sections that QPACK unblocked and resumes their streams.
    fn resume_unblocked(&mut self, conn: &mut Connection) -> Result<(), H3Error> {
        while let Some((id, f)) = self.pending_fields.pop_front() {
            match f {
                None => self.reject(conn, id, code::EXCESSIVE_LOAD),
                Some(f) => {
                    self.on_fields(conn, id, f);
                    self.pump(conn, id)?;
                }
            }
        }
        Ok(())
    }

    /// Reads body bytes; returns (bytes, finished). Finished is reported once the peer's
    /// fin was received and every body byte was read.
    pub fn recv_body(&mut self, now: Instant, conn: &mut Connection, stream: u64, out: &mut [u8]) -> Result<(usize, bool), SendError> {
        let r = self.reqs.get_mut(&stream).ok_or(SendError::UnknownStream)?;
        let n = out.len().min(r.body.len());
        let (a, b) = r.body.as_slices();
        if n <= a.len() {
            out[..n].copy_from_slice(&a[..n]);
        } else {
            out[..a.len()].copy_from_slice(a);
            out[a.len()..n].copy_from_slice(&b[..n - a.len()]);
        }
        r.body.drain(..n);
        if r.body.is_empty() {
            r.data_event = false;
        }
        // Refill from QUIC now that there is room; a parse error here closes later.
        if let Err(e) = self.pump(conn, stream) {
            self.fail(now, conn, e);
        }
        let Some(r) = self.reqs.get_mut(&stream) else { return Ok((n, true)) };
        let fin = r.finished || (r.fin_seen && r.inbuf.is_empty() && r.body.is_empty() && r.data_left == 0 && r.headers_done);
        if fin && !r.finished {
            r.finished = true;
            self.events.push_back(H3Event::Finished { stream });
            self.maybe_drop(stream);
        }
        Ok((n, fin))
    }

    fn maybe_drop(&mut self, id: u64) {
        if self.reqs.get(&id).is_some_and(|r| r.finished && r.send_done && r.out.is_empty()) {
            self.reqs.remove(&id);
        }
    }

    // ------------------------------------------------------------- sending

    fn encode_headers(&mut self, id: u64, fields: &[(&[u8], &[u8])], out: &mut Vec<u8>) -> Result<(), SendError> {
        if let Some(max) = self.peer_settings.as_ref().and_then(|s| s.max_field_section_size) {
            let size: u64 = fields.iter().map(|(n, v)| n.len() as u64 + v.len() as u64 + 32).sum();
            if size > max {
                return Err(SendError::HeadersTooLarge);
            }
        }
        let mut block = Vec::with_capacity(64);
        self.encoder.encode(id, fields, &mut block);
        put_varint(out, frame::HEADERS);
        put_varint(out, block.len() as u64);
        out.extend_from_slice(&block);
        Ok(())
    }

    fn write_frame(&mut self, conn: &mut Connection, id: u64, bytes: Vec<u8>, fin: bool) -> Result<(), SendError> {
        let r = self.reqs.get_mut(&id).ok_or(SendError::UnknownStream)?;
        if r.out.is_empty() {
            let k = match conn.stream_send(id, &bytes, fin) {
                Ok(k) => k,
                Err(StreamError::Blocked) => 0,
                Err(e) => return Err(e.into()),
            };
            if k < bytes.len() {
                r.out.extend_from_slice(&bytes[k..]);
                r.finish_after_out = fin;
            } else if fin {
                r.send_done = true;
            }
        } else {
            r.out.extend_from_slice(&bytes);
            r.finish_after_out = fin;
        }
        Ok(())
    }

    /// Sends response headers (server) or request headers (client). Interim 1xx
    /// responses may precede the final one.
    pub fn send_headers(&mut self, conn: &mut Connection, stream: u64, fields: &[(&[u8], &[u8])], fin: bool) -> Result<(), SendError> {
        let r = self.reqs.get(&stream).ok_or(SendError::UnknownStream)?;
        if r.send_done || r.headers_sent {
            return Err(SendError::InvalidState);
        }
        let interim = self.is_server && fields.iter().any(|(n, v)| *n == b":status" && v.first() == Some(&b'1'));
        let mut b = Vec::with_capacity(128);
        self.encode_headers(stream, fields, &mut b)?;
        self.write_frame(conn, stream, b, fin && !interim)?;
        if !interim {
            self.reqs.get_mut(&stream).unwrap().headers_sent = true;
        }
        self.flush_qpack(conn);
        self.maybe_drop(stream);
        Ok(())
    }

    /// Sends body bytes in a DATA frame; returns how many were accepted. Zero means the
    /// stream is blocked: wait for [`H3Event::Writable`].
    pub fn send_body(&mut self, conn: &mut Connection, stream: u64, data: &[u8], fin: bool) -> Result<usize, SendError> {
        let r = self.reqs.get_mut(&stream).ok_or(SendError::UnknownStream)?;
        if !r.headers_sent || r.send_done {
            return Err(SendError::InvalidState);
        }
        if !r.out.is_empty() {
            r.want_writable = true;
            return Ok(0);
        }
        if data.is_empty() {
            if fin {
                conn.stream_finish(stream)?;
                r.send_done = true;
                self.maybe_drop(stream);
            }
            return Ok(0);
        }
        let room = conn.stream_writable(stream).unwrap_or(0) as usize;
        let hdr_len = 1 + varint_len(data.len() as u64);
        if room == 0 {
            r.want_writable = true;
            mark_blocked(conn, stream);
            return Ok(0);
        }
        if room <= hdr_len {
            // Room for less than a frame header and a byte: queue a small frame and offer it.
            // QUIC takes what fits and remembers that the stream wants to write; the rest
            // leaves from `out` when credit arrives.
            let n = data.len().min(SMALL_FRAME);
            let all = n == data.len() && fin;
            let mut b = Vec::with_capacity(9 + n);
            put_varint(&mut b, frame::DATA);
            put_varint(&mut b, n as u64);
            b.extend_from_slice(&data[..n]);
            if n < data.len() {
                r.want_writable = true;
            }
            self.write_frame(conn, stream, b, all)?;
            if all {
                self.maybe_drop(stream);
            }
            return Ok(n);
        }
        let n = data.len().min(room - hdr_len);
        let mut h = Vec::with_capacity(9);
        put_varint(&mut h, frame::DATA);
        put_varint(&mut h, n as u64);
        let all = n == data.len() && fin;
        conn.stream_send(stream, &h, false)?;
        conn.stream_send(stream, &data[..n], all)?;
        if all {
            r.send_done = true;
            self.maybe_drop(stream);
        } else if n < data.len() {
            // The frame used all the room. QUIC accepted everything it was offered, so it does
            // not know the stream wants more: tell it, or MAX_STREAM_DATA (MAX_DATA, an ack
            // freeing the send buffer) would never wake the stream and a response larger than
            // the peer's window would stall for good.
            r.want_writable = true;
            mark_blocked(conn, stream);
        }
        Ok(n)
    }

    /// Sends trailers and finishes the stream.
    pub fn send_trailers(&mut self, conn: &mut Connection, stream: u64, fields: &[(&[u8], &[u8])]) -> Result<(), SendError> {
        let r = self.reqs.get(&stream).ok_or(SendError::UnknownStream)?;
        if !r.headers_sent || r.send_done {
            return Err(SendError::InvalidState);
        }
        let mut b = Vec::new();
        self.encode_headers(stream, fields, &mut b)?;
        self.write_frame(conn, stream, b, true)?;
        self.flush_qpack(conn);
        self.maybe_drop(stream);
        Ok(())
    }

    /// Abandons a request with a stream error (both directions).
    pub fn reset_stream(&mut self, conn: &mut Connection, stream: u64, code_: u64) {
        let _ = conn.stream_stop(stream, code_);
        let _ = conn.stream_reset(stream, code_);
        if let Some(r) = self.reqs.remove(&stream) {
            if !r.headers_done || r.blocked {
                self.decoder.cancel_stream(stream);
            }
        }
        self.flush_qpack(conn);
    }

    /// Client: opens a request stream and sends its headers.
    pub fn send_request(&mut self, conn: &mut Connection, fields: &[(&[u8], &[u8])], fin: bool) -> Result<u64, SendError> {
        if self.goaway_recv.is_some() {
            return Err(SendError::GoingAway);
        }
        let id = conn.open_bi()?;
        self.reqs.insert(id, Req::default());
        self.send_headers(conn, id, fields, fin)?;
        Ok(id)
    }

    /// Server: starts a graceful shutdown. Requests on streams below the returned ID are
    /// still served; later ones are rejected with H3_REQUEST_REJECTED.
    pub fn goaway(&mut self, conn: &mut Connection) -> u64 {
        let id = self.max_request.map_or(0, |m| m + 4);
        let id = self.goaway_sent.map_or(id, |g| g.min(id));
        self.goaway_sent = Some(id);
        let mut b = Vec::with_capacity(10);
        put_varint(&mut b, frame::GOAWAY);
        put_varint(&mut b, varint_len(id) as u64);
        put_varint(&mut b, id);
        let c = self.control_out;
        self.send_uni(conn, c, &b);
        id
    }

    /// True once GOAWAY was sent and no request streams remain.
    pub fn is_idle_after_goaway(&self) -> bool {
        self.goaway_sent.is_some() && self.reqs.is_empty()
    }
}
