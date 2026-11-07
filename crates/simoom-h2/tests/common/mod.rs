//! Shared helpers: a raw frame writer for playing a misbehaving peer, owned copies of events,
//! and a pump that moves bytes between two engines.
#![allow(dead_code)]

use simoom_h2::frame::{self, flag, kind, FrameHeader};
use simoom_h2::{Config, Connection, ErrorCode, Event};
use simoom_hpack::Encoder;

/// An owned copy of an [`Event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ev {
    Headers { stream: u32, method: Option<String>, path: Option<String>, status: Option<u16>, fields: Vec<(String, String)>, end: bool },
    Data { stream: u32, data: Vec<u8>, end: bool },
    Trailers { stream: u32, fields: Vec<(String, String)> },
    Reset { stream: u32, code: ErrorCode, remote: bool },
    Settings,
    Pong([u8; 8]),
    GoAway { last: u32, code: ErrorCode },
    Closed(ErrorCode),
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

pub fn own(ev: Event<'_>) -> Ev {
    match ev {
        Event::Headers { stream, headers, end_stream } => Ev::Headers {
            stream,
            method: headers.method().map(s),
            path: headers.path().map(s),
            status: headers.status(),
            fields: headers.iter().map(|(n, v)| (s(n), s(v))).collect(),
            end: end_stream,
        },
        Event::Data { stream, data, end_stream } => Ev::Data { stream, data: data.to_vec(), end: end_stream },
        Event::Trailers { stream, trailers } => Ev::Trailers { stream, fields: trailers.iter().map(|(n, v)| (s(n), s(v))).collect() },
        Event::Reset { stream, code, remote } => Ev::Reset { stream, code, remote },
        Event::Settings => Ev::Settings,
        Event::Pong { data } => Ev::Pong(data),
        Event::GoAway { last_stream, code, .. } => Ev::GoAway { last: last_stream, code },
        Event::Closed { code } => Ev::Closed(code),
    }
}

/// An owned frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub h: FrameHeader,
    pub p: Vec<u8>,
}

impl Frame {
    pub fn code(&self) -> ErrorCode {
        let off = if self.h.kind == kind::GOAWAY { 4 } else { 0 };
        ErrorCode(u32::from_be_bytes(self.p[off..off + 4].try_into().unwrap()))
    }
}

/// Takes and parses everything `c` wants to write.
pub fn drain(c: &mut Connection) -> Vec<Frame> {
    let out = c.output().to_vec();
    c.advance_output(out.len());
    let mut v = Vec::new();
    let mut rest: &[u8] = &out;
    if rest.starts_with(simoom_h2::PREFACE) {
        rest = &rest[24..];
    }
    for (h, p) in frame::split_frames(rest) {
        v.push(Frame { h, p: p.to_vec() });
    }
    v
}

/// Feeds bytes and returns (events, frames written). Asserts the engine consumed everything.
pub fn feed(c: &mut Connection, bytes: &[u8], now: u64) -> (Vec<Ev>, Vec<Frame>) {
    let mut evs = Vec::new();
    let n = c.recv(bytes, now, &mut |e| evs.push(own(e)));
    assert_eq!(n, bytes.len(), "engine left input unconsumed");
    (evs, drain(c))
}

pub fn goaway(frames: &[Frame]) -> Option<ErrorCode> {
    frames.iter().find(|f| f.h.kind == kind::GOAWAY).map(|f| f.code())
}

pub fn rst(frames: &[Frame], stream: u32) -> Option<ErrorCode> {
    frames.iter().find(|f| f.h.kind == kind::RST_STREAM && f.h.stream == stream).map(|f| f.code())
}

/// Raw frames as a misbehaving client would write them.
#[derive(Default)]
pub struct Raw {
    pub buf: Vec<u8>,
    pub enc: Encoder,
}

impl Raw {
    pub fn new() -> Raw {
        Raw { buf: Vec::new(), enc: Encoder::new(4096) }
    }
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
    pub fn preface(&mut self) -> &mut Self {
        self.buf.extend_from_slice(simoom_h2::PREFACE);
        self.settings(&[])
    }
    pub fn raw(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> &mut Self {
        frame::write_header(&mut self.buf, payload.len(), kind, flags, stream);
        self.buf.extend_from_slice(payload);
        self
    }
    pub fn settings(&mut self, v: &[(u16, u32)]) -> &mut Self {
        frame::write_settings(&mut self.buf, v);
        self
    }
    pub fn settings_ack(&mut self) -> &mut Self {
        frame::write_settings_ack(&mut self.buf);
        self
    }
    pub fn ping(&mut self, d: [u8; 8]) -> &mut Self {
        frame::write_ping(&mut self.buf, d, false);
        self
    }
    pub fn data(&mut self, stream: u32, d: &[u8], end: bool) -> &mut Self {
        frame::write_data(&mut self.buf, stream, d, end);
        self
    }
    pub fn rst(&mut self, stream: u32, code: ErrorCode) -> &mut Self {
        frame::write_rst(&mut self.buf, stream, code);
        self
    }
    pub fn window_update(&mut self, stream: u32, inc: u32) -> &mut Self {
        frame::write_window_update(&mut self.buf, stream, inc);
        self
    }
    pub fn priority(&mut self, stream: u32, dep: u32) -> &mut Self {
        let mut p = dep.to_be_bytes().to_vec();
        p.push(15);
        self.raw(kind::PRIORITY, 0, stream, &p)
    }
    /// HPACK-encodes `fields` (pseudo-headers included) into a block.
    pub fn block(&mut self, fields: &[(&str, &str)]) -> Vec<u8> {
        let mut b = Vec::new();
        self.enc.begin_block(&mut b);
        for (n, v) in fields {
            self.enc.field(n.as_bytes(), v.as_bytes(), &mut b);
        }
        b
    }
    pub fn headers(&mut self, stream: u32, fields: &[(&str, &str)], end_stream: bool) -> &mut Self {
        let b = self.block(fields);
        let fl = flag::END_HEADERS | if end_stream { flag::END_STREAM } else { 0 };
        self.raw(kind::HEADERS, fl, stream, &b)
    }
    pub fn get(&mut self, stream: u32) -> &mut Self {
        self.headers(stream, &GET, true)
    }
}

pub const GET: [(&str, &str); 4] = [(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "example.com")];
pub const POST: [(&str, &str); 4] = [(":method", "POST"), (":scheme", "https"), (":path", "/upload"), (":authority", "example.com")];

/// A server that has completed the handshake with a raw client (preface, SETTINGS and the ACK
/// of the server's SETTINGS exchanged; output drained).
pub fn server(cfg: Config) -> (Connection, Raw) {
    let mut srv = Connection::server(cfg);
    let mut raw = Raw::new();
    raw.preface().settings_ack();
    let (evs, frames) = feed(&mut srv, &raw.take(), 0);
    assert_eq!(evs, [Ev::Settings]);
    assert!(frames.iter().any(|f| f.h.kind == kind::SETTINGS && f.h.has(flag::ACK)));
    (srv, raw)
}

/// Default config without window auto-tuning (no PINGs from the engine).
pub fn quiet() -> Config {
    Config { window_autotune: false, ..Config::default() }
}

/// Moves bytes between a client and a server until neither has anything to send. Events go to
/// the two callbacks, which may act on the engines through the returned queues.
pub fn pump(client: &mut Connection, server: &mut Connection, now: u64, cev: &mut Vec<Ev>, sev: &mut Vec<Ev>) {
    for _ in 0..10_000 {
        let c2s = client.output().to_vec();
        client.advance_output(c2s.len());
        let s2c = server.output().to_vec();
        server.advance_output(s2c.len());
        if c2s.is_empty() && s2c.is_empty() {
            return;
        }
        let mut off = 0;
        while off < c2s.len() {
            let n = server.recv(&c2s[off..], now, &mut |e| sev.push(own(e)));
            off += n;
            if n == 0 {
                // output backpressure: let the client read
                let s2c = server.output().to_vec();
                server.advance_output(s2c.len());
                client.recv(&s2c, now, &mut |e| cev.push(own(e)));
            }
        }
        let mut off = 0;
        while off < s2c.len() {
            let n = client.recv(&s2c[off..], now, &mut |e| cev.push(own(e)));
            off += n;
            if n == 0 {
                let c2s = client.output().to_vec();
                client.advance_output(c2s.len());
                server.recv(&c2s, now, &mut |e| sev.push(own(e)));
            }
        }
    }
    panic!("pump did not settle");
}
