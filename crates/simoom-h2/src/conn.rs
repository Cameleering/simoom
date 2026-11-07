//! The sans-io connection: preface, settings, stream states, flow control, PING, GOAWAY,
//! RST_STREAM, header blocks and the DoS budgets.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

use simoom_hpack::{Decoder, Encoder, Error as HpackError};

use crate::budget::{Kind as Budget, Meter};
use crate::frame::{self, be32, flag, kind, setting, ErrorCode, FrameHeader, DEFAULT_WINDOW, HEADER_LEN, MAX_WINDOW, PREFACE};
use crate::headers::{connection_specific, valid_name, valid_value, Headers, Kind as HeadKind};
use crate::upgrade::{base64url_decode, base64url_encode};
use crate::{Config, Error, Event};

/// Which end of the connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Hasher for stream ids: one multiply, rotated so the bucket bits are well mixed.
#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, b: &[u8]) {
        for &x in b {
            self.0 = (self.0.rotate_left(8) ^ x as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }
    fn write_u32(&mut self, n: u32) {
        self.0 = (n as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(32);
    }
}

type StreamMap = HashMap<u32, Stream, BuildHasherDefault<IdHasher>>;

#[derive(Debug, Default)]
struct Stream {
    send_window: i64,
    recv_window: i64,
    /// DATA bytes delivered to the application and not yet released.
    unreleased: u32,
    /// Released bytes not yet announced with a stream WINDOW_UPDATE.
    unacked: u32,
    /// DATA payload received, for the content-length check.
    received: u64,
    content_length: Option<u64>,
    remote_end: bool,
    local_end: bool,
    reset: bool,
    /// The reset came from the peer: later frames are STREAM_CLOSED errors, not ignored.
    peer_reset: bool,
    /// Counted in `open_count`.
    open: bool,
    /// Counted in `handlers`: the application's work for it has not finished.
    handler: bool,
    final_sent: bool,
    final_recv: bool,
    blocked: bool,
    /// The request was HEAD: the response's content-length describes no body.
    head: bool,
}

impl Stream {
    fn closed(&self) -> bool {
        self.reset || (self.local_end && self.remote_end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Server: waiting for the client magic.
    Preface,
    /// Waiting for the peer's first SETTINGS frame.
    Settings,
    Open,
    Closed,
}

/// A header block being reassembled from HEADERS + CONTINUATION.
#[derive(Clone, Copy, Debug)]
struct Block {
    stream: u32,
    end_stream: bool,
    self_dep: bool,
    frames: u32,
}

type R = Result<(), (ErrorCode, &'static str)>;

fn perr(msg: &'static str) -> R {
    Err((ErrorCode::PROTOCOL_ERROR, msg))
}

fn calm(msg: &'static str) -> R {
    Err((ErrorCode::ENHANCE_YOUR_CALM, msg))
}

const BDP_PING: [u8; 8] = *b"simoomBD";
const SHUTDOWN_PING: [u8; 8] = *b"simoomGA";
/// At most one window-tuning PING per this many milliseconds.
const BDP_INTERVAL_MS: u64 = 500;

/// Our SETTINGS values for `role` (also the h2c `HTTP2-Settings` payload).
fn local_settings(role: Role, c: &Config) -> Vec<(u16, u32)> {
    let mut s = Vec::with_capacity(6);
    if c.header_table_size != 4096 {
        s.push((setting::HEADER_TABLE_SIZE, c.header_table_size));
    }
    if role == Role::Client {
        s.push((setting::ENABLE_PUSH, 0));
    } else {
        s.push((setting::MAX_CONCURRENT_STREAMS, c.max_concurrent_streams));
    }
    if c.initial_window_size != DEFAULT_WINDOW {
        s.push((setting::INITIAL_WINDOW_SIZE, c.initial_window_size));
    }
    if c.max_frame_size != frame::MIN_FRAME_SIZE {
        s.push((setting::MAX_FRAME_SIZE, c.max_frame_size));
    }
    s.push((setting::MAX_HEADER_LIST_SIZE, c.max_header_list_size));
    s
}

/// The `HTTP2-Settings` header value a client sends with an h2c upgrade request.
pub fn http2_settings_header(config: &Config) -> String {
    let mut p = Vec::new();
    for (id, v) in local_settings(Role::Client, &sanitize(config.clone())) {
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&v.to_be_bytes());
    }
    base64url_encode(&p)
}

fn sanitize(mut c: Config) -> Config {
    c.max_frame_size = c.max_frame_size.clamp(frame::MIN_FRAME_SIZE, frame::MAX_FRAME_SIZE);
    c.initial_window_size = c.initial_window_size.min(MAX_WINDOW);
    c.connection_window_size = c.connection_window_size.clamp(DEFAULT_WINDOW, MAX_WINDOW);
    c.max_stream_window = c.max_stream_window.clamp(c.initial_window_size, MAX_WINDOW);
    c.max_connection_window = c.max_connection_window.clamp(c.connection_window_size, MAX_WINDOW);
    c.max_send_buffer = c.max_send_buffer.max(1024);
    c
}

/// One HTTP/2 connection, either end.
pub struct Connection {
    role: Role,
    cfg: Config,
    phase: Phase,
    now: u64,
    out: Vec<u8>,
    out_pos: usize,
    enc: Encoder,
    dec: Decoder,
    streams: StreamMap,
    rx: Headers,
    hb: Option<Block>,
    hb_buf: Vec<u8>,
    scratch: Vec<u8>,
    // peer settings
    peer_initial_window: u32,
    peer_max_frame: usize,
    peer_max_concurrent: u32,
    // flow control
    send_window: i64,
    recv_window: i64,
    conn_target: u32,
    conn_unacked: u32,
    stream_target: u32,
    /// Window a new stream gets: `stream_target`, or 65535 when that is larger and our first
    /// SETTINGS is not yet acknowledged.
    stream_effective: u32,
    first_settings_acked: bool,
    settings_unacked: u32,
    settings_deadline: Option<u64>,
    // streams
    next_stream_id: u32,
    last_peer_stream: u32,
    open_count: u32,
    handlers: u32,
    // shutdown
    goaway_sent: Option<u32>,
    graceful_deadline: Option<u64>,
    goaway_recv: Option<u32>,
    close_code: Option<ErrorCode>,
    // window auto-tuning
    bdp_sent: bool,
    bdp_bytes: u64,
    bdp_last: Option<u64>,
    meter: Meter,
    recent_resets: [u32; 16],
    recent_pos: usize,
    recent_closed: [u32; 16],
    closed_pos: usize,
    blocked: Vec<u32>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("role", &self.role)
            .field("phase", &self.phase)
            .field("streams", &self.streams.len())
            .field("handlers", &self.handlers)
            .finish()
    }
}

impl Connection {
    fn new(role: Role, cfg: Config) -> Connection {
        let cfg = sanitize(cfg);
        let mut c = Connection {
            role,
            phase: Phase::Settings,
            now: 0,
            out: Vec::with_capacity(1024),
            out_pos: 0,
            enc: Encoder::new(cfg.encoder_table_size as usize),
            dec: Decoder::new((cfg.header_table_size as usize).max(4096), cfg.max_header_list_size as usize),
            streams: StreamMap::default(),
            rx: Headers::default(),
            hb: None,
            hb_buf: Vec::new(),
            scratch: Vec::new(),
            peer_initial_window: DEFAULT_WINDOW,
            peer_max_frame: frame::MIN_FRAME_SIZE as usize,
            peer_max_concurrent: u32::MAX,
            send_window: DEFAULT_WINDOW as i64,
            recv_window: cfg.connection_window_size as i64,
            conn_target: cfg.connection_window_size,
            conn_unacked: 0,
            stream_target: cfg.initial_window_size,
            stream_effective: cfg.initial_window_size.max(DEFAULT_WINDOW),
            first_settings_acked: false,
            settings_unacked: 0,
            settings_deadline: None,
            next_stream_id: if role == Role::Client { 1 } else { 2 },
            last_peer_stream: 0,
            open_count: 0,
            handlers: 0,
            goaway_sent: None,
            graceful_deadline: None,
            goaway_recv: None,
            close_code: None,
            bdp_sent: false,
            bdp_bytes: 0,
            bdp_last: None,
            meter: Meter::new(&cfg.budgets),
            recent_resets: [0; 16],
            recent_pos: 0,
            recent_closed: [0; 16],
            closed_pos: 0,
            blocked: Vec::new(),
            cfg,
        };
        if role == Role::Client {
            c.out.extend_from_slice(PREFACE);
        }
        frame::write_settings(&mut c.out, &local_settings(role, &c.cfg));
        c.settings_unacked = 1;
        if c.conn_target > DEFAULT_WINDOW {
            frame::write_window_update(&mut c.out, 0, c.conn_target - DEFAULT_WINDOW);
        }
        c
    }

    /// A server connection. It expects the client preface; its own SETTINGS are already in
    /// [`Connection::output`].
    pub fn server(cfg: Config) -> Connection {
        let mut c = Connection::new(Role::Server, cfg);
        c.phase = Phase::Preface;
        c
    }

    /// A client connection (h2c prior knowledge, or h2 after ALPN). The preface and SETTINGS are
    /// already in [`Connection::output`], and requests can be sent at once.
    pub fn client(cfg: Config) -> Connection {
        Connection::new(Role::Client, cfg)
    }

    /// A server connection after an HTTP/1.1 `Upgrade: h2c` request (RFC 7540 §3.2) was
    /// answered with `101 Switching Protocols`. `http2_settings` is the request's
    /// `HTTP2-Settings` value. The request itself becomes stream 1, half-closed (remote) with
    /// its handler running: answer it with [`Connection::send_response`] on stream 1.
    pub fn server_upgrade(cfg: Config, http2_settings: &[u8]) -> Result<Connection, Error> {
        let payload = base64url_decode(http2_settings).ok_or(Error::InvalidUpgradeSettings)?;
        if payload.len() % 6 != 0 {
            return Err(Error::InvalidUpgradeSettings);
        }
        let mut c = Connection::server(cfg);
        if c.apply_settings(&payload).is_err() {
            return Err(Error::InvalidUpgradeSettings);
        }
        let s = Stream {
            send_window: c.peer_initial_window as i64,
            recv_window: 0,
            remote_end: true,
            open: true,
            handler: true,
            ..Stream::default()
        };
        c.streams.insert(1, s);
        c.open_count = 1;
        c.handlers = 1;
        c.last_peer_stream = 1;
        Ok(c)
    }

    /// A client connection after the server answered our HTTP/1.1 `Upgrade: h2c` request with
    /// `101`. The upgrade request is stream 1, half-closed (local); its response arrives as
    /// events for stream 1. `head` says whether that request was HEAD.
    pub fn client_upgrade(cfg: Config, head: bool) -> Connection {
        let mut c = Connection::client(cfg);
        let s = Stream {
            send_window: c.peer_initial_window as i64,
            recv_window: c.stream_effective as i64,
            local_end: true,
            open: true,
            final_sent: true,
            head,
            ..Stream::default()
        };
        c.streams.insert(1, s);
        c.open_count = 1;
        c.next_stream_id = 3;
        c
    }

    // ------------------------------------------------------------------ output

    /// Bytes waiting to be written to the transport.
    pub fn output(&self) -> &[u8] {
        &self.out[self.out_pos..]
    }

    /// Marks `n` bytes of [`Connection::output`] as written.
    pub fn advance_output(&mut self, n: usize) {
        self.out_pos = (self.out_pos + n).min(self.out.len());
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
            if self.out.capacity() > 4 * self.cfg.max_send_buffer {
                self.out = Vec::with_capacity(16 * 1024);
            }
        } else if self.out_pos > 64 * 1024 && self.out_pos * 2 > self.out.len() {
            self.out.drain(..self.out_pos);
            self.out_pos = 0;
        }
    }

    fn pending(&self) -> usize {
        self.out.len() - self.out_pos
    }

    // ------------------------------------------------------------------ state

    /// This end's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// True when the transport should be closed once [`Connection::output`] is flushed: after a
    /// connection error, or after a GOAWAY (sent or received) once every stream is done.
    pub fn wants_close(&self) -> bool {
        self.phase == Phase::Closed || ((self.goaway_sent.is_some() || self.goaway_recv.is_some()) && self.streams.is_empty())
    }

    /// The error code of the GOAWAY we closed the connection with.
    pub fn close_code(&self) -> Option<ErrorCode> {
        self.close_code
    }

    /// Streams whose handler work is still running (server).
    pub fn active_handlers(&self) -> u32 {
        self.handlers
    }

    /// Streams open or half-closed.
    pub fn open_streams(&self) -> u32 {
        self.open_count
    }

    /// Streams the engine still tracks (open, or closed with work running).
    pub fn tracked_streams(&self) -> usize {
        self.streams.len()
    }

    /// The peer's SETTINGS_MAX_CONCURRENT_STREAMS.
    pub fn peer_max_concurrent_streams(&self) -> u32 {
        self.peer_max_concurrent
    }

    /// True when a client may open another stream now.
    pub fn can_open_stream(&self) -> bool {
        self.role == Role::Client
            && self.phase != Phase::Closed
            && self.goaway_recv.is_none()
            && self.goaway_sent.is_none()
            && self.open_count < self.peer_max_concurrent
            && self.next_stream_id <= MAX_WINDOW
    }

    /// Bytes `stream` may send now: the smaller of its window, the connection window and the
    /// room in the output buffer.
    pub fn send_capacity(&self, stream: u32) -> usize {
        match self.streams.get(&stream) {
            Some(s) if !s.reset && !s.local_end => {
                let room = self.cfg.max_send_buffer.saturating_sub(self.pending()) as i64;
                s.send_window.min(self.send_window).min(room).max(0) as usize
            }
            _ => 0,
        }
    }

    /// The connection's current receive targets (connection, per stream), after auto-tuning.
    pub fn receive_windows(&self) -> (u32, u32) {
        (self.conn_target, self.stream_target)
    }

    /// The next deadline (settings acknowledgement, graceful shutdown) for
    /// [`Connection::handle_timeout`].
    pub fn poll_timeout(&self) -> Option<u64> {
        match (self.settings_deadline, self.graceful_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Fires due timers.
    pub fn handle_timeout(&mut self, now: u64, sink: &mut dyn FnMut(Event<'_>)) {
        self.now = now;
        if self.phase == Phase::Closed {
            return;
        }
        if self.settings_deadline.is_some_and(|d| now >= d) {
            self.conn_error(ErrorCode::SETTINGS_TIMEOUT, "SETTINGS not acknowledged", sink);
            return;
        }
        if self.graceful_deadline.is_some_and(|d| now >= d) {
            self.final_goaway();
        }
    }

    // ------------------------------------------------------------------ input

    /// Processes received bytes at time `now` (monotonic milliseconds from any origin).
    /// Returns how many bytes were consumed; the caller keeps the rest and passes it again with
    /// more data. A buffer of `max_frame_size + 9` bytes always makes progress. Input processing
    /// pauses (returns early) while more than twice `max_send_buffer` of output is waiting, so a
    /// peer that does not read cannot make us queue unbounded replies. After the connection is
    /// closed all input is consumed and ignored.
    pub fn recv(&mut self, input: &[u8], now: u64, sink: &mut dyn FnMut(Event<'_>)) -> usize {
        self.now = now;
        if self.settings_unacked > 0 && self.settings_deadline.is_none() {
            self.settings_deadline = Some(now + self.cfg.settings_timeout_ms);
        }
        let mut pos = 0;
        while self.phase != Phase::Closed {
            if self.pending() > 2 * self.cfg.max_send_buffer {
                break;
            }
            let rest = &input[pos..];
            if self.phase == Phase::Preface {
                let n = rest.len().min(PREFACE.len());
                if rest[..n] != PREFACE[..n] {
                    self.conn_error(ErrorCode::PROTOCOL_ERROR, "invalid connection preface", sink);
                    break;
                }
                if n < PREFACE.len() {
                    break;
                }
                pos += n;
                self.phase = Phase::Settings;
                continue;
            }
            if rest.len() < HEADER_LEN {
                break;
            }
            let h = FrameHeader::parse(rest);
            if h.len > self.cfg.max_frame_size as usize {
                self.conn_error(ErrorCode::FRAME_SIZE_ERROR, "frame larger than SETTINGS_MAX_FRAME_SIZE", sink);
                break;
            }
            if rest.len() - HEADER_LEN < h.len {
                break;
            }
            pos += HEADER_LEN + h.len;
            if let Err((code, msg)) = self.on_frame(h, &rest[HEADER_LEN..HEADER_LEN + h.len], sink) {
                self.conn_error(code, msg, sink);
            }
        }
        if self.phase == Phase::Closed {
            input.len()
        } else {
            pos
        }
    }

    fn conn_error(&mut self, code: ErrorCode, msg: &'static str, sink: &mut dyn FnMut(Event<'_>)) {
        if self.phase == Phase::Closed {
            return;
        }
        frame::write_goaway(&mut self.out, self.last_peer_stream, code, msg.as_bytes());
        self.phase = Phase::Closed;
        self.close_code = Some(code);
        self.hb = None;
        self.settings_deadline = None;
        self.graceful_deadline = None;
        sink(Event::Closed { code });
    }

    fn hit(&mut self, b: Budget) -> bool {
        self.meter.hit(b, self.now)
    }

    fn is_idle(&self, id: u32) -> bool {
        let ours = (id & 1 == 1) == (self.role == Role::Client);
        if ours {
            id >= self.next_stream_id
        } else {
            id > self.last_peer_stream
        }
    }

    fn remember_reset(&mut self, id: u32) {
        self.recent_resets[self.recent_pos] = id;
        self.recent_pos = (self.recent_pos + 1) % self.recent_resets.len();
    }

    fn recently_reset(&self, id: u32) -> bool {
        self.recent_resets.contains(&id)
    }

    fn recently_closed(&self, id: u32) -> bool {
        self.recent_closed.contains(&id)
    }

    fn on_frame(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if self.phase == Phase::Settings {
            if h.kind != kind::SETTINGS || h.has(flag::ACK) {
                return perr("the first frame must be SETTINGS");
            }
            self.phase = Phase::Open;
        }
        if let Some(b) = &self.hb {
            if h.kind != kind::CONTINUATION || h.stream != b.stream {
                return perr("expected CONTINUATION");
            }
        }
        match h.kind {
            kind::DATA => self.on_data(h, p, sink),
            kind::HEADERS => self.on_headers(h, p, sink),
            kind::PRIORITY => self.on_priority(h, p, sink),
            kind::RST_STREAM => self.on_rst(h, p, sink),
            kind::SETTINGS => self.on_settings(h, p, sink),
            kind::PUSH_PROMISE => perr("PUSH_PROMISE is disabled"),
            kind::PING => self.on_ping(h, p, sink),
            kind::GOAWAY => self.on_goaway(h, p, sink),
            kind::WINDOW_UPDATE => self.on_window_update(h, p, sink),
            kind::CONTINUATION => self.on_continuation(h, p, sink),
            _ => Ok(()), // unknown frame types are ignored (RFC 9113 §4.1)
        }
    }

    fn unpad<'a>(h: &FrameHeader, p: &'a [u8]) -> Result<&'a [u8], (ErrorCode, &'static str)> {
        if !h.has(flag::PADDED) {
            return Ok(p);
        }
        let Some(&pad) = p.first() else {
            return Err((ErrorCode::FRAME_SIZE_ERROR, "padded frame without pad length"));
        };
        if pad as usize >= p.len() {
            return Err((ErrorCode::PROTOCOL_ERROR, "padding longer than the payload"));
        }
        Ok(&p[1..p.len() - pad as usize])
    }

    // ------------------------------------------------------------------ DATA

    fn on_data(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        let id = h.stream;
        if id == 0 {
            return perr("DATA on stream 0");
        }
        let data = Self::unpad(&h, p)?;
        let flen = p.len() as u32;
        if flen as i64 > self.recv_window {
            return Err((ErrorCode::FLOW_CONTROL_ERROR, "connection receive window exceeded"));
        }
        self.recv_window -= flen as i64;
        let end = h.has(flag::END_STREAM);
        if data.is_empty() && !end && self.hit(Budget::Empty) {
            return calm("too many empty frames");
        }
        let idle = self.is_idle(id);
        let client = self.role == Role::Client;
        enum Next {
            Closed,
            Ignore,
            StreamError(ErrorCode),
            Deliver,
        }
        let next = match self.streams.get_mut(&id) {
            None if idle => return perr("DATA on an idle stream"),
            None => Next::Closed,
            Some(s) if s.peer_reset || (s.remote_end && !s.reset) => Next::StreamError(ErrorCode::STREAM_CLOSED),
            Some(s) if s.reset => Next::Ignore,
            Some(s) if client && !s.final_recv => Next::StreamError(ErrorCode::PROTOCOL_ERROR),
            Some(s) if flen as i64 > s.recv_window => Next::StreamError(ErrorCode::FLOW_CONTROL_ERROR),
            Some(s) => {
                s.recv_window -= flen as i64;
                s.received += data.len() as u64;
                let bad_length = match s.content_length {
                    Some(cl) if !s.head => s.received > cl || (end && s.received != cl),
                    _ => false,
                };
                if bad_length {
                    Next::StreamError(ErrorCode::PROTOCOL_ERROR)
                } else {
                    s.unreleased += data.len() as u32;
                    if end {
                        s.remote_end = true;
                    }
                    Next::Deliver
                }
            }
        };
        match next {
            Next::Closed => {
                self.release_conn(flen);
                if !self.recently_reset(id) {
                    // a stream that closed normally: not remembered as one we reset
                    frame::write_rst(&mut self.out, id, ErrorCode::STREAM_CLOSED);
                    if self.hit(Budget::RstSent) {
                        return calm("too many stream errors");
                    }
                }
            }
            Next::Ignore => self.release_conn(flen),
            Next::StreamError(code) => {
                self.release_conn(flen);
                self.stream_error(id, code, sink)?;
            }
            Next::Deliver => {
                let pad = flen - data.len() as u32;
                if pad > 0 {
                    self.credit(id, pad);
                }
                sink(Event::Data { stream: id, data, end_stream: end });
                if !data.is_empty() {
                    self.bdp_on_data(data.len());
                }
                if end {
                    self.update(id);
                }
            }
        }
        Ok(())
    }

    /// Returns `n` bytes of connection credit, announcing it once half the window is unused.
    fn release_conn(&mut self, n: u32) {
        if n == 0 || self.phase == Phase::Closed {
            return;
        }
        self.conn_unacked += n;
        if self.conn_unacked >= self.conn_target / 2 {
            frame::write_window_update(&mut self.out, 0, self.conn_unacked);
            self.recv_window += self.conn_unacked as i64;
            self.conn_unacked = 0;
        }
    }

    /// Returns `n` bytes of credit on a stream and the connection.
    fn credit(&mut self, id: u32, n: u32) {
        if let Some(s) = self.streams.get_mut(&id) {
            if !s.reset && !s.remote_end && self.phase != Phase::Closed {
                s.unacked += n;
                if s.unacked >= self.stream_target / 2 {
                    frame::write_window_update(&mut self.out, id, s.unacked);
                    s.recv_window += s.unacked as i64;
                    s.unacked = 0;
                }
            }
        }
        self.release_conn(n);
    }

    /// Tells the engine the application consumed `n` bytes of DATA on `stream`, so the peer may
    /// send more. Releasing more than was delivered is ignored.
    pub fn release(&mut self, stream: u32, n: usize) {
        let Some(s) = self.streams.get_mut(&stream) else { return };
        let n = n.min(s.unreleased as usize) as u32;
        if n == 0 {
            return;
        }
        s.unreleased -= n;
        self.credit(stream, n);
    }

    fn bdp_on_data(&mut self, n: usize) {
        if !self.cfg.window_autotune || self.phase == Phase::Closed {
            return;
        }
        if self.bdp_sent {
            self.bdp_bytes += n as u64;
            return;
        }
        if self.conn_target >= self.cfg.max_connection_window && self.stream_target >= self.cfg.max_stream_window {
            return;
        }
        if self.bdp_last.is_some_and(|t| self.now < t + BDP_INTERVAL_MS) {
            return;
        }
        frame::write_ping(&mut self.out, BDP_PING, false);
        self.bdp_sent = true;
        self.bdp_bytes = n as u64;
        self.bdp_last = Some(self.now);
    }

    /// A window-tuning PING came back: `bdp_bytes` arrived in about one round trip. Window
    /// updates go out once half a window is released, so a flow held back by a window delivers
    /// between half and all of it per round trip; at half or more the window doubles (towards
    /// twice the sample), up to the configured cap.
    fn bdp_ack(&mut self) {
        self.bdp_sent = false;
        let sample = self.bdp_bytes.min(MAX_WINDOW as u64) as u32;
        let grow = |target: u32, max: u32| -> u32 {
            if sample as u64 * 2 >= target as u64 {
                (sample.saturating_mul(2)).max(target.saturating_mul(2)).min(max).max(target)
            } else {
                target
            }
        };
        let conn = grow(self.conn_target, self.cfg.max_connection_window);
        if conn > self.conn_target {
            let delta = conn - self.conn_target;
            self.conn_target = conn;
            self.recv_window += delta as i64;
            frame::write_window_update(&mut self.out, 0, delta);
        }
        let stream = grow(self.stream_target, self.cfg.max_stream_window);
        if stream > self.stream_target {
            let delta = (stream - self.stream_target) as i64;
            self.stream_target = stream;
            self.stream_effective = self.stream_effective.max(stream);
            for s in self.streams.values_mut() {
                if !s.remote_end && !s.reset {
                    s.recv_window += delta;
                }
            }
            frame::write_settings(&mut self.out, &[(setting::INITIAL_WINDOW_SIZE, stream)]);
            self.settings_unacked += 1;
            if self.settings_deadline.is_none() {
                self.settings_deadline = Some(self.now + self.cfg.settings_timeout_ms);
            }
        }
    }

    // ------------------------------------------------------------------ resets

    /// Sends RST_STREAM. `caused` marks resets the peer provoked; they count against the
    /// rst_sent budget.
    fn send_rst(&mut self, id: u32, code: ErrorCode, caused: bool) -> R {
        frame::write_rst(&mut self.out, id, code);
        self.remember_reset(id);
        if caused && self.hit(Budget::RstSent) {
            return calm("too many stream errors");
        }
        Ok(())
    }

    /// Marks a stream reset and returns its unreleased connection credit. Reports whether the
    /// application knows the stream.
    fn mark_reset(&mut self, id: u32) -> bool {
        let client = self.role == Role::Client;
        let (credit, known) = match self.streams.get_mut(&id) {
            Some(s) if !s.reset => {
                s.reset = true;
                let c = s.unreleased;
                s.unreleased = 0;
                (c, s.handler || client)
            }
            _ => return false,
        };
        self.release_conn(credit);
        known
    }

    /// A stream error (RFC 9113 §5.4.2) the peer caused.
    fn stream_error(&mut self, id: u32, code: ErrorCode, sink: &mut dyn FnMut(Event<'_>)) -> R {
        if self.mark_reset(id) {
            sink(Event::Reset { stream: id, code, remote: false });
        }
        let r = self.send_rst(id, code, true);
        self.update(id);
        r
    }

    /// Updates the open count and forgets the stream once it is closed and its work finished.
    fn update(&mut self, id: u32) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        if !s.closed() {
            return;
        }
        if s.open {
            s.open = false;
            self.open_count -= 1;
        }
        if !s.handler {
            let credit = s.unreleased;
            self.streams.remove(&id);
            self.recent_closed[self.closed_pos] = id;
            self.closed_pos = (self.closed_pos + 1) % self.recent_closed.len();
            self.release_conn(credit);
        }
    }

    // ------------------------------------------------------------------ HEADERS

    fn header_cap(&self) -> usize {
        self.cfg.max_header_list_size as usize
    }

    fn on_headers(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        let id = h.stream;
        if id == 0 {
            return perr("HEADERS on stream 0");
        }
        let mut frag = Self::unpad(&h, p)?;
        let mut self_dep = false;
        if h.has(flag::PRIORITY) {
            if frag.len() < 5 {
                return Err((ErrorCode::FRAME_SIZE_ERROR, "HEADERS too short for its priority fields"));
            }
            self_dep = be32(frag) & 0x7fff_ffff == id;
            frag = &frag[5..];
        }
        let end = h.has(flag::END_STREAM);
        if h.has(flag::END_HEADERS) {
            return self.on_block(id, end, self_dep, frag, sink);
        }
        if frag.is_empty() && self.hit(Budget::Empty) {
            return calm("too many empty frames");
        }
        if frag.len() > self.header_cap() {
            return calm("header block too large");
        }
        self.hb = Some(Block { stream: id, end_stream: end, self_dep, frames: 1 });
        self.hb_buf.clear();
        self.hb_buf.extend_from_slice(frag);
        Ok(())
    }

    fn on_continuation(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        let Some(mut b) = self.hb.take() else {
            return perr("CONTINUATION without HEADERS");
        };
        b.frames += 1;
        if b.frames > self.cfg.max_continuation_frames + 1 {
            return calm("too many CONTINUATION frames");
        }
        if p.is_empty() && !h.has(flag::END_HEADERS) && self.hit(Budget::Empty) {
            return calm("too many empty frames");
        }
        if self.hb_buf.len() + p.len() > self.header_cap() {
            return calm("header block too large");
        }
        self.hb_buf.extend_from_slice(p);
        if !h.has(flag::END_HEADERS) {
            self.hb = Some(b);
            return Ok(());
        }
        let buf = std::mem::take(&mut self.hb_buf);
        let r = self.on_block(b.stream, b.end_stream, b.self_dep, &buf, sink);
        self.hb_buf = buf;
        r
    }

    /// A complete header block on stream `id`.
    fn on_block(&mut self, id: u32, end: bool, self_dep: bool, block: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if block.len() > self.header_cap() {
            return calm("header block too large");
        }
        let server = self.role == Role::Server;
        let existing = self.streams.get(&id).map(|s| (s.reset && !s.peer_reset, s.remote_end || s.peer_reset, s.final_recv));
        let kind = match existing {
            Some((_, _, final_recv)) if server || final_recv => HeadKind::Trailers,
            Some(_) => HeadKind::Response,
            None => HeadKind::Request,
        };
        // always decode: the HPACK context must stay in step even for blocks we refuse
        self.rx.reset(kind);
        let rx = &mut self.rx;
        let too_large = match self.dec.decode(block, &mut |n: &[u8], v: &[u8]| rx.push(n, v)) {
            Ok(()) => false,
            Err(HpackError::HeaderListTooLarge) => true,
            Err(_) => return Err((ErrorCode::COMPRESSION_ERROR, "HPACK decoding failed")),
        };
        self.rx.finish();
        let peer_initiated = (id & 1 == 1) == server;
        if !peer_initiated && server {
            return perr("client stream ids must be odd");
        }
        if peer_initiated && !server {
            return perr("server-initiated streams are not allowed (push is disabled)");
        }
        match existing {
            Some((true, _, _)) => Ok(()),
            Some((_, true, _)) => self.stream_error(id, ErrorCode::STREAM_CLOSED, sink),
            Some(_) if self_dep || too_large || self.rx.malformed().is_some() => {
                self.stream_error(id, ErrorCode::PROTOCOL_ERROR, sink)
            }
            Some(_) if kind == HeadKind::Trailers => {
                let s = self.streams.get_mut(&id).expect("stream exists");
                let bad_length = s.content_length.is_some_and(|cl| !s.head && cl != s.received);
                if !end || bad_length {
                    return self.stream_error(id, ErrorCode::PROTOCOL_ERROR, sink);
                }
                s.remote_end = true;
                sink(Event::Trailers { stream: id, trailers: &self.rx });
                self.update(id);
                Ok(())
            }
            Some(_) => {
                // client: a response
                let status = self.rx.status().unwrap_or(0);
                let s = self.streams.get_mut(&id).expect("stream exists");
                if status < 200 {
                    if end {
                        return self.stream_error(id, ErrorCode::PROTOCOL_ERROR, sink);
                    }
                    sink(Event::Headers { stream: id, headers: &self.rx, end_stream: false });
                    return Ok(());
                }
                s.final_recv = true;
                s.content_length = self.rx.content_length();
                if end && !s.head && s.content_length.is_some_and(|cl| cl != 0) {
                    return self.stream_error(id, ErrorCode::PROTOCOL_ERROR, sink);
                }
                s.remote_end = end;
                sink(Event::Headers { stream: id, headers: &self.rx, end_stream: end });
                if end {
                    self.update(id);
                }
                Ok(())
            }
            None if server => {
                if id <= self.last_peer_stream {
                    if self.recently_reset(id) {
                        return Ok(());
                    }
                    if self.recently_closed(id) {
                        return Err((ErrorCode::STREAM_CLOSED, "HEADERS on a closed stream"));
                    }
                    return perr("stream id lower than a previous one");
                }
                self.last_peer_stream = id;
                self.new_request(id, end, self_dep, too_large, sink)
            }
            None => {
                if self.is_idle(id) {
                    return perr("HEADERS on an idle stream");
                }
                Ok(())
            }
        }
    }

    fn new_request(&mut self, id: u32, end: bool, self_dep: bool, too_large: bool, sink: &mut dyn FnMut(Event<'_>)) -> R {
        if self.goaway_sent.is_some_and(|last| id > last) {
            self.remember_reset(id);
            return Ok(()); // after our final GOAWAY: ignored (RFC 9113 §6.8)
        }
        if self_dep {
            return self.send_rst(id, ErrorCode::PROTOCOL_ERROR, true);
        }
        if too_large {
            // RFC 9113 §8.2.2 / RFC 6585: answer 431 without running a handler
            self.write_block(id, true, |enc, out| enc.field(b":status", b"431", out));
            if !end {
                return self.send_rst(id, ErrorCode::NO_ERROR, true);
            }
            self.remember_reset(id);
            if self.hit(Budget::RstSent) {
                return calm("too many refused requests");
            }
            return Ok(());
        }
        let max = self.cfg.max_concurrent_streams;
        if self.open_count >= max || self.handlers >= max {
            return self.send_rst(id, ErrorCode::REFUSED_STREAM, true);
        }
        if self.rx.malformed().is_some() || (end && self.rx.content_length().is_some_and(|cl| cl != 0)) {
            return self.send_rst(id, ErrorCode::PROTOCOL_ERROR, true);
        }
        let s = Stream {
            send_window: self.peer_initial_window as i64,
            recv_window: self.stream_effective as i64,
            remote_end: end,
            open: true,
            handler: true,
            content_length: self.rx.content_length(),
            head: self.rx.method() == Some(b"HEAD"),
            ..Stream::default()
        };
        self.streams.insert(id, s);
        self.open_count += 1;
        self.handlers += 1;
        sink(Event::Headers { stream: id, headers: &self.rx, end_stream: end });
        Ok(())
    }

    // ------------------------------------------------------------------ control frames

    fn on_priority(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if h.stream == 0 {
            return perr("PRIORITY on stream 0");
        }
        if self.hit(Budget::Priority) {
            return calm("too many PRIORITY frames");
        }
        if p.len() != 5 {
            return self.stream_error(h.stream, ErrorCode::FRAME_SIZE_ERROR, sink);
        }
        if be32(p) & 0x7fff_ffff == h.stream {
            return self.stream_error(h.stream, ErrorCode::PROTOCOL_ERROR, sink);
        }
        Ok(()) // priorities are not used (RFC 9113 §5.3.2)
    }

    fn on_rst(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if h.stream == 0 {
            return perr("RST_STREAM on stream 0");
        }
        if p.len() != 4 {
            return Err((ErrorCode::FRAME_SIZE_ERROR, "RST_STREAM length"));
        }
        if self.is_idle(h.stream) {
            return perr("RST_STREAM on an idle stream");
        }
        if self.hit(Budget::RstReceived) {
            return calm("too many RST_STREAM frames");
        }
        if self.mark_reset(h.stream) {
            sink(Event::Reset { stream: h.stream, code: ErrorCode(be32(p)), remote: true });
        }
        if let Some(s) = self.streams.get_mut(&h.stream) {
            s.peer_reset = true;
        }
        self.update(h.stream);
        Ok(())
    }

    /// Applies a SETTINGS payload from the peer.
    fn apply_settings(&mut self, p: &[u8]) -> R {
        for c in p.chunks_exact(6) {
            let id = u16::from_be_bytes([c[0], c[1]]);
            let v = be32(&c[2..]);
            match id {
                setting::HEADER_TABLE_SIZE => self.enc.set_peer_max_table_size(v as usize),
                setting::ENABLE_PUSH => {
                    if v > 1 || (v == 1 && self.role == Role::Client) {
                        return perr("invalid SETTINGS_ENABLE_PUSH");
                    }
                }
                setting::MAX_CONCURRENT_STREAMS => self.peer_max_concurrent = v,
                setting::INITIAL_WINDOW_SIZE => {
                    if v > MAX_WINDOW {
                        return Err((ErrorCode::FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE too large"));
                    }
                    let delta = v as i64 - self.peer_initial_window as i64;
                    self.peer_initial_window = v;
                    let mut overflow = false;
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                        overflow |= s.send_window > MAX_WINDOW as i64;
                    }
                    if overflow {
                        return Err((ErrorCode::FLOW_CONTROL_ERROR, "stream window overflow"));
                    }
                }
                setting::MAX_FRAME_SIZE => {
                    if !(frame::MIN_FRAME_SIZE..=frame::MAX_FRAME_SIZE).contains(&v) {
                        return perr("invalid SETTINGS_MAX_FRAME_SIZE");
                    }
                    self.peer_max_frame = v as usize;
                }
                _ => {} // MAX_HEADER_LIST_SIZE is advisory; unknown settings are ignored
            }
        }
        Ok(())
    }

    fn on_settings(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if h.stream != 0 {
            return perr("SETTINGS on a stream");
        }
        if h.has(flag::ACK) {
            if !p.is_empty() {
                return Err((ErrorCode::FRAME_SIZE_ERROR, "SETTINGS ACK with a payload"));
            }
            if self.settings_unacked > 0 {
                self.settings_unacked -= 1;
                self.settings_deadline = if self.settings_unacked > 0 { Some(self.now + self.cfg.settings_timeout_ms) } else { None };
                if !self.first_settings_acked {
                    self.first_settings_acked = true;
                    self.dec.set_max_allowed(self.cfg.header_table_size as usize);
                    if self.stream_effective > self.stream_target {
                        let delta = self.stream_effective as i64 - self.stream_target as i64;
                        self.stream_effective = self.stream_target;
                        for s in self.streams.values_mut() {
                            s.recv_window -= delta;
                        }
                    }
                }
            }
            return Ok(());
        }
        if p.len() % 6 != 0 {
            return Err((ErrorCode::FRAME_SIZE_ERROR, "SETTINGS length"));
        }
        if self.hit(Budget::Settings) {
            return calm("too many SETTINGS frames");
        }
        self.apply_settings(p)?;
        frame::write_settings_ack(&mut self.out);
        sink(Event::Settings);
        Ok(())
    }

    fn on_ping(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if h.stream != 0 {
            return perr("PING on a stream");
        }
        if p.len() != 8 {
            return Err((ErrorCode::FRAME_SIZE_ERROR, "PING length"));
        }
        let mut data = [0u8; 8];
        data.copy_from_slice(p);
        if h.has(flag::ACK) {
            if data == BDP_PING && self.bdp_sent {
                self.bdp_ack();
            } else if data == SHUTDOWN_PING && self.graceful_deadline.is_some() {
                self.final_goaway();
            } else {
                if self.hit(Budget::Ping) {
                    return calm("too many PING frames");
                }
                sink(Event::Pong { data });
            }
            return Ok(());
        }
        if self.hit(Budget::Ping) {
            return calm("too many PING frames");
        }
        frame::write_ping(&mut self.out, data, true);
        Ok(())
    }

    fn on_goaway(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if h.stream != 0 {
            return perr("GOAWAY on a stream");
        }
        if p.len() < 8 {
            return Err((ErrorCode::FRAME_SIZE_ERROR, "GOAWAY length"));
        }
        let last = be32(p) & 0x7fff_ffff;
        let code = ErrorCode(be32(&p[4..]));
        self.goaway_recv = Some(self.goaway_recv.map_or(last, |l| l.min(last)));
        sink(Event::GoAway { last_stream: last, code, debug: &p[8..] });
        // streams we opened above `last` were not processed: the application may retry them
        let client = self.role == Role::Client;
        let refused: Vec<u32> = self
            .streams
            .iter()
            .filter(|(&id, s)| (id & 1 == 1) == client && id > last && !s.reset)
            .map(|(&id, _)| id)
            .collect();
        for id in refused {
            if self.mark_reset(id) {
                sink(Event::Reset { stream: id, code: ErrorCode::REFUSED_STREAM, remote: true });
            }
            self.update(id);
        }
        Ok(())
    }

    fn on_window_update(&mut self, h: FrameHeader, p: &[u8], sink: &mut dyn FnMut(Event<'_>)) -> R {
        if p.len() != 4 {
            return Err((ErrorCode::FRAME_SIZE_ERROR, "WINDOW_UPDATE length"));
        }
        let inc = be32(p) & 0x7fff_ffff;
        if inc < 1024 && self.hit(Budget::SmallWindowUpdate) {
            return calm("too many small WINDOW_UPDATE frames");
        }
        let id = h.stream;
        if id == 0 {
            if inc == 0 {
                return perr("WINDOW_UPDATE with a zero increment");
            }
            self.send_window += inc as i64;
            if self.send_window > MAX_WINDOW as i64 {
                return Err((ErrorCode::FLOW_CONTROL_ERROR, "connection window overflow"));
            }
            return Ok(());
        }
        if self.is_idle(id) {
            return perr("WINDOW_UPDATE on an idle stream");
        }
        let code = match self.streams.get_mut(&id) {
            None => return Ok(()),
            Some(s) if s.reset => return Ok(()),
            Some(_) if inc == 0 => ErrorCode::PROTOCOL_ERROR,
            Some(s) => {
                s.send_window += inc as i64;
                if s.send_window <= MAX_WINDOW as i64 {
                    return Ok(());
                }
                ErrorCode::FLOW_CONTROL_ERROR
            }
        };
        self.stream_error(id, code, sink)
    }

    // ------------------------------------------------------------------ sending

    /// Writes a header block on `id`, as HEADERS plus CONTINUATION frames when it is larger
    /// than the peer's maximum frame size.
    fn write_block(&mut self, id: u32, end: bool, fields: impl FnOnce(&mut Encoder, &mut Vec<u8>)) {
        let at = self.out.len();
        frame::write_header(&mut self.out, 0, kind::HEADERS, 0, id);
        self.enc.begin_block(&mut self.out);
        fields(&mut self.enc, &mut self.out);
        let len = self.out.len() - at - HEADER_LEN;
        let fl = if end { flag::END_STREAM } else { 0 };
        if len <= self.peer_max_frame {
            frame::patch_header(&mut self.out, at, len, fl | flag::END_HEADERS);
        } else {
            self.scratch.clear();
            self.scratch.extend_from_slice(&self.out[at + HEADER_LEN..]);
            self.out.truncate(at);
            frame::write_headers(&mut self.out, id, &self.scratch, end, self.peer_max_frame);
        }
    }

    fn check_fields(fields: &[(&[u8], &[u8])]) -> Result<(), Error> {
        for (n, v) in fields {
            if !valid_name(n) || connection_specific(n) || (*n == b"te" && *v != b"trailers") || !valid_value(v) {
                return Err(Error::InvalidHeader);
            }
        }
        Ok(())
    }

    fn sendable(&self, stream: u32) -> Result<(), Error> {
        if self.phase == Phase::Closed {
            return Err(Error::ConnectionClosed);
        }
        match self.streams.get(&stream) {
            None => Err(Error::UnknownStream),
            Some(s) if s.reset => Err(Error::StreamReset),
            Some(s) if s.local_end => Err(Error::StreamClosed),
            Some(_) => Ok(()),
        }
    }

    /// Server: sends response headers on `stream`. A status below 200 sends an informational
    /// response (101 is not allowed in HTTP/2); then the final one follows.
    pub fn send_response(&mut self, stream: u32, status: u16, fields: &[(&[u8], &[u8])], end_stream: bool) -> Result<(), Error> {
        if self.role != Role::Server {
            return Err(Error::WrongRole);
        }
        if !(100..1000).contains(&status) || status == 101 || (status < 200 && end_stream) {
            return Err(Error::InvalidHeader);
        }
        Self::check_fields(fields)?;
        self.sendable(stream)?;
        let s = self.streams.get_mut(&stream).expect("checked");
        if s.final_sent {
            return Err(Error::HeadersAlreadySent);
        }
        if status >= 200 {
            s.final_sent = true;
        }
        if end_stream {
            s.local_end = true;
        }
        let digits = [b'0' + (status / 100) as u8, b'0' + (status / 10 % 10) as u8, b'0' + (status % 10) as u8];
        self.write_block(stream, end_stream, |enc, out| {
            enc.field(b":status", &digits, out);
            for (n, v) in fields {
                enc.field(n, v, out);
            }
        });
        if end_stream {
            self.update(stream);
        }
        Ok(())
    }

    /// Client: opens a stream with a request. `authority` may be empty; `path` is ignored for
    /// CONNECT. Returns the new stream id.
    #[allow(clippy::too_many_arguments)]
    pub fn send_request(
        &mut self,
        method: &[u8],
        scheme: &[u8],
        authority: &[u8],
        path: &[u8],
        fields: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u32, Error> {
        if self.role != Role::Client {
            return Err(Error::WrongRole);
        }
        if self.phase == Phase::Closed {
            return Err(Error::ConnectionClosed);
        }
        if self.goaway_recv.is_some() || self.goaway_sent.is_some() {
            return Err(Error::GoingAway);
        }
        if self.next_stream_id > MAX_WINDOW {
            return Err(Error::StreamIdsExhausted);
        }
        if self.open_count >= self.peer_max_concurrent {
            return Err(Error::StreamLimit);
        }
        let connect = method == b"CONNECT";
        if method.is_empty()
            || !method.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !valid_value(scheme)
            || !valid_value(authority)
            || (!connect && (path.is_empty() || !valid_value(path)))
        {
            return Err(Error::InvalidHeader);
        }
        Self::check_fields(fields)?;
        let id = self.next_stream_id;
        self.next_stream_id += 2;
        let s = Stream {
            send_window: self.peer_initial_window as i64,
            recv_window: self.stream_effective as i64,
            local_end: end_stream,
            open: true,
            final_sent: true,
            head: method == b"HEAD",
            ..Stream::default()
        };
        self.streams.insert(id, s);
        self.open_count += 1;
        self.write_block(id, end_stream, |enc, out| {
            enc.field(b":method", method, out);
            if !connect {
                enc.field(b":scheme", scheme, out);
            }
            if !authority.is_empty() {
                enc.field(b":authority", authority, out);
            }
            if !connect {
                enc.field(b":path", path, out);
            }
            for (n, v) in fields {
                enc.field(n, v, out);
            }
        });
        Ok(id)
    }

    /// Sends trailers, ending the stream.
    pub fn send_trailers(&mut self, stream: u32, fields: &[(&[u8], &[u8])]) -> Result<(), Error> {
        Self::check_fields(fields)?;
        self.sendable(stream)?;
        let s = self.streams.get_mut(&stream).expect("checked");
        if !s.final_sent {
            return Err(Error::HeadersNotSent);
        }
        s.local_end = true;
        self.write_block(stream, true, |enc, out| {
            for (n, v) in fields {
                enc.field(n, v, out);
            }
        });
        self.update(stream);
        Ok(())
    }

    /// Sends body bytes on `stream`, as much as the stream window, the connection window and
    /// the output buffer cap allow. Returns how many bytes were accepted; `end_stream` applies
    /// only when all of `data` was accepted. When fewer were accepted the stream is remembered,
    /// and [`Connection::poll_writable`] reports it once it can send again.
    pub fn send_data(&mut self, stream: u32, data: &[u8], end_stream: bool) -> Result<usize, Error> {
        self.sendable(stream)?;
        let room = self.cfg.max_send_buffer.saturating_sub(self.pending()) as i64;
        let max_frame = self.peer_max_frame;
        let s = self.streams.get_mut(&stream).expect("checked");
        if !s.final_sent {
            return Err(Error::HeadersNotSent);
        }
        let cap = s.send_window.min(self.send_window).min(room).max(0) as usize;
        let n = data.len().min(cap);
        let fin = end_stream && n == data.len();
        if n < data.len() && !s.blocked {
            s.blocked = true;
            self.blocked.push(stream);
        }
        if n == 0 && !fin {
            return Ok(0);
        }
        s.send_window -= n as i64;
        self.send_window -= n as i64;
        if n == 0 {
            frame::write_data(&mut self.out, stream, &[], true);
        } else {
            let mut chunks = data[..n].chunks(max_frame).peekable();
            while let Some(c) = chunks.next() {
                frame::write_data(&mut self.out, stream, c, fin && chunks.peek().is_none());
            }
        }
        if fin {
            s.local_end = true;
            self.update(stream);
        }
        Ok(n)
    }

    /// A stream that was short of capacity in [`Connection::send_data`] and can send again.
    /// Call it after [`Connection::recv`] and [`Connection::advance_output`] until it returns
    /// `None`.
    pub fn poll_writable(&mut self) -> Option<u32> {
        if self.send_window <= 0 || self.pending() >= self.cfg.max_send_buffer || self.phase == Phase::Closed {
            return None;
        }
        let mut i = 0;
        while i < self.blocked.len() {
            let id = self.blocked[i];
            match self.streams.get_mut(&id) {
                Some(s) if s.blocked && !s.reset && !s.local_end => {
                    if s.send_window > 0 {
                        s.blocked = false;
                        self.blocked.swap_remove(i);
                        return Some(id);
                    }
                    i += 1;
                }
                Some(s) => {
                    s.blocked = false;
                    self.blocked.swap_remove(i);
                }
                None => {
                    self.blocked.swap_remove(i);
                }
            }
        }
        None
    }

    /// Resets `stream` with `code` at the application's request.
    pub fn reset(&mut self, stream: u32, code: ErrorCode) {
        if self.phase == Phase::Closed || !self.streams.get(&stream).is_some_and(|s| !s.closed()) {
            return;
        }
        self.mark_reset(stream);
        let _ = self.send_rst(stream, code, false);
        self.update(stream);
    }

    /// The application's work for `stream` is finished: it no longer counts against the
    /// concurrency limit. A stream we have not ended is reset with CANCEL; a request body that
    /// was not read to the end is cut off with RST_STREAM(NO_ERROR) (RFC 9113 §8.1).
    pub fn stream_finished(&mut self, stream: u32) {
        let Some(s) = self.streams.get_mut(&stream) else { return };
        if s.handler {
            s.handler = false;
            self.handlers -= 1;
        }
        if !s.closed() && self.phase != Phase::Closed {
            let code = if s.local_end { ErrorCode::NO_ERROR } else { ErrorCode::CANCEL };
            self.mark_reset(stream);
            let _ = self.send_rst(stream, code, false);
        }
        if let Some(s) = self.streams.get_mut(&stream) {
            if !s.closed() {
                // the connection is closed: just forget the stream
                s.reset = true;
            }
        }
        self.update(stream);
    }

    /// Sends a PING; the answer arrives as [`Event::Pong`].
    pub fn ping(&mut self, data: [u8; 8]) {
        if self.phase != Phase::Closed {
            frame::write_ping(&mut self.out, data, false);
        }
    }

    /// Starts a graceful shutdown (RFC 9113 §6.8). A server sends GOAWAY with the largest
    /// stream id and a PING, then, after the PING round trip (or `graceful_timeout_ms`), the
    /// final GOAWAY with the last stream it accepted. Streams already accepted run to the end;
    /// [`Connection::wants_close`] turns true when they are done.
    pub fn shutdown(&mut self, now: u64) {
        self.now = now;
        if self.phase == Phase::Closed || self.goaway_sent.is_some() || self.graceful_deadline.is_some() {
            return;
        }
        if self.role == Role::Server && self.phase == Phase::Open {
            frame::write_goaway(&mut self.out, MAX_WINDOW, ErrorCode::NO_ERROR, b"");
            frame::write_ping(&mut self.out, SHUTDOWN_PING, false);
            self.graceful_deadline = Some(now + self.cfg.graceful_timeout_ms);
        } else {
            self.final_goaway();
        }
    }

    fn final_goaway(&mut self) {
        self.graceful_deadline = None;
        if self.goaway_sent.is_none() && self.phase != Phase::Closed {
            frame::write_goaway(&mut self.out, self.last_peer_stream, ErrorCode::NO_ERROR, b"");
            self.goaway_sent = Some(self.last_peer_stream);
        }
    }

    /// Closes the connection at once with GOAWAY(`code`). No events follow.
    pub fn close(&mut self, code: ErrorCode, debug: &[u8]) {
        if self.phase == Phase::Closed {
            return;
        }
        frame::write_goaway(&mut self.out, self.last_peer_stream, code, debug);
        self.phase = Phase::Closed;
        self.close_code = Some(code);
        self.settings_deadline = None;
        self.graceful_deadline = None;
    }
}
