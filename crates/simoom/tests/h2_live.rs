//! An h2spec-style HTTP/2 conformance runner that drives raw frames over a socket (plan §7.3).
//!
//! It covers h2spec's server test list (generic, RFC 9113 sections 3.5, 4, 5, 6 and 8, and
//! RFC 7541 HPACK), written from the RFCs; nothing is taken from h2spec itself.
//!
//! - `h2_conformance_h2c` and `h2_conformance_h2_tls` (hermetic, part of `cargo test`) run every
//!   case against an in-process simoom server.
//! - `h2_conformance_live` (`#[ignore]`) runs them against a running server:
//!
//! ```text
//! SIMOOM_H2_LIVE_H2C=127.0.0.1:8080 SIMOOM_H2_LIVE_H2=127.0.0.1:8443 SIMOOM_H2_LIVE_CA=ca.pem \
//!     cargo test -p simoom --features full --test h2_live -- --ignored --nocapture
//! ```
//!
//! (`examples/conformance_server.rs` is such a server; `GET /` must answer with a body of at
//! least 8 bytes.) A connection error passes on a GOAWAY with the expected code or a close; a
//! stream error on an RST_STREAM or GOAWAY with the expected code, or a close (h2spec's rules).

#![cfg(feature = "http2")]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- constants

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 1;
const ACK: u8 = 1;
const END_HEADERS: u8 = 4;
const PADDED: u8 = 8;
const PRIO: u8 = 0x20;

const NO_ERROR: u32 = 0;
const PROTOCOL_ERROR: u32 = 1;
const FLOW_CONTROL_ERROR: u32 = 3;
const STREAM_CLOSED: u32 = 5;
const FRAME_SIZE_ERROR: u32 = 6;
const REFUSED_STREAM: u32 = 7;
const COMPRESSION_ERROR: u32 = 9;

const S_HEADER_TABLE_SIZE: u16 = 1;
const S_ENABLE_PUSH: u16 = 2;
const S_MAX_CONCURRENT_STREAMS: u16 = 3;
const S_INITIAL_WINDOW_SIZE: u16 = 4;
const S_MAX_FRAME_SIZE: u16 = 5;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Error cases that passed only because the connection closed (no GOAWAY or RST_STREAM seen).
static CLOSE_ONLY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const WAIT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------- transport

trait Io {
    fn send(&mut self, b: &[u8]) -> std::io::Result<()>;
    /// Bytes read, `Ok(None)` on a timeout tick, `Err` on close.
    fn recv(&mut self) -> Result<Option<Vec<u8>>, ()>;
}

struct Plain(TcpStream);

impl Io for Plain {
    fn send(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.0.write_all(b)
    }
    fn recv(&mut self) -> Result<Option<Vec<u8>>, ()> {
        let mut tmp = vec![0u8; 65536];
        match self.0.read(&mut tmp) {
            Ok(0) => Err(()),
            Ok(n) => Ok(Some(tmp[..n].to_vec())),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(None),
            Err(_) => Err(()),
        }
    }
}

#[cfg(feature = "tls-client")]
struct Tls {
    s: TcpStream,
    c: simoom_tls::ClientConnection,
}

#[cfg(feature = "tls-client")]
impl Tls {
    fn connect(addr: SocketAddr, roots: simoom_tls::x509::RootStore) -> Result<Tls, String> {
        let s = TcpStream::connect(addr).map_err(|e| e.to_string())?;
        s.set_nodelay(true).ok();
        s.set_read_timeout(Some(Duration::from_millis(20))).ok();
        let cfg = std::sync::Arc::new(simoom_tls::ClientConfig::new(roots).with_alpn(&[b"h2"]));
        let c = simoom_tls::ClientConnection::new(cfg, "localhost").map_err(|e| format!("{e:?}"))?;
        let mut t = Tls { s, c };
        let start = Instant::now();
        while t.c.is_handshaking() {
            t.flush();
            if t.pump().is_err() || start.elapsed() > WAIT {
                return Err("TLS handshake failed".into());
            }
        }
        t.flush();
        if t.c.alpn_protocol() != Some(b"h2") {
            return Err("ALPN did not select h2".into());
        }
        Ok(t)
    }
    fn flush(&mut self) {
        if self.c.wants_write() {
            let mut out = Vec::new();
            self.c.write_tls_into(&mut out);
            let _ = self.s.write_all(&out);
        }
    }
    fn pump(&mut self) -> Result<bool, ()> {
        let mut tmp = vec![0u8; 65536];
        match self.s.read(&mut tmp) {
            Ok(0) => Err(()),
            Ok(n) => {
                let mut off = 0;
                while off < n {
                    off += self.c.read_tls(&tmp[off..n]);
                    if self.c.process_new_packets().is_err() {
                        return Err(());
                    }
                }
                Ok(true)
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(false),
            Err(_) => Err(()),
        }
    }
}

#[cfg(feature = "tls-client")]
impl Io for Tls {
    fn send(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.c.write_plaintext(b).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        self.flush();
        Ok(())
    }
    fn recv(&mut self) -> Result<Option<Vec<u8>>, ()> {
        if self.c.plaintext().is_empty() {
            if self.c.peer_has_closed() {
                return Err(());
            }
            let r = self.pump();
            self.flush();
            r?;
        }
        if self.c.plaintext().is_empty() {
            return if self.c.peer_has_closed() { Err(()) } else { Ok(None) };
        }
        let mut b = vec![0u8; 65536];
        let n = self.c.read_plaintext(&mut b);
        Ok(Some(b[..n].to_vec()))
    }
}

// ---------------------------------------------------------------- frames and HPACK

#[derive(Debug, Clone)]
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    p: Vec<u8>,
}

impl Frame {
    fn code(&self) -> u32 {
        let o = if self.kind == GOAWAY { 4 } else { 0 };
        if self.p.len() < o + 4 {
            return u32::MAX;
        }
        u32::from_be_bytes(self.p[o..o + 4].try_into().unwrap())
    }
}

fn frame(kind: u8, flags: u8, stream: u32, p: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(9 + p.len());
    b.extend_from_slice(&(p.len() as u32).to_be_bytes()[1..]);
    b.push(kind);
    b.push(flags);
    b.extend_from_slice(&stream.to_be_bytes());
    b.extend_from_slice(p);
    b
}

fn settings(v: &[(u16, u32)]) -> Vec<u8> {
    let mut p = Vec::new();
    for (k, x) in v {
        p.extend_from_slice(&k.to_be_bytes());
        p.extend_from_slice(&x.to_be_bytes());
    }
    frame(SETTINGS, 0, 0, &p)
}

/// RFC 7541 §5.1 integer with an `n`-bit prefix; `first` holds the pattern bits.
fn hint(out: &mut Vec<u8>, first: u8, n: u8, mut v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(first | v as u8);
        return;
    }
    out.push(first | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

fn hstr(out: &mut Vec<u8>, s: &[u8]) {
    hint(out, 0, 7, s.len());
    out.extend_from_slice(s);
}

/// Literal header field without indexing, new name (RFC 7541 §6.2.2).
fn lit(out: &mut Vec<u8>, n: &str, v: &str) {
    out.push(0);
    hstr(out, n.as_bytes());
    hstr(out, v.as_bytes());
}

fn block(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (n, v) in fields {
        lit(&mut b, n, v);
    }
    b
}

// ---------------------------------------------------------------- connection

struct Conn {
    io: Box<dyn Io>,
    inbuf: Vec<u8>,
    scheme: &'static str,
    server_settings: Vec<(u16, u32)>,
    closed: bool,
    /// Frames read but not yet examined by an expectation.
    seen: Vec<Frame>,
}

#[derive(Clone)]
enum Target {
    H2c(SocketAddr),
    #[cfg(feature = "tls-client")]
    H2(SocketAddr, simoom_tls::x509::RootStore),
}

impl Target {
    fn open(&self) -> Result<Conn, String> {
        let (io, scheme): (Box<dyn Io>, &'static str) = match self {
            Target::H2c(a) => {
                let s = TcpStream::connect(a).map_err(|e| e.to_string())?;
                s.set_nodelay(true).ok();
                s.set_read_timeout(Some(Duration::from_millis(20))).ok();
                (Box::new(Plain(s)), "http")
            }
            #[cfg(feature = "tls-client")]
            Target::H2(a, roots) => (Box::new(Tls::connect(*a, roots.clone())?), "https"),
        };
        Ok(Conn { io, inbuf: Vec::new(), scheme, server_settings: Vec::new(), closed: false, seen: Vec::new() })
    }
}

impl Conn {
    fn send(&mut self, b: &[u8]) {
        if self.io.send(b).is_err() {
            self.closed = true;
        }
    }
    fn raw(&mut self, kind: u8, flags: u8, stream: u32, p: &[u8]) {
        self.send(&frame(kind, flags, stream, p));
    }

    /// The next frame, or None on timeout or close (`closed` tells which).
    fn next(&mut self, deadline: Instant) -> Option<Frame> {
        if !self.seen.is_empty() {
            return Some(self.seen.remove(0));
        }
        loop {
            if self.inbuf.len() >= 9 {
                let len = u32::from_be_bytes([0, self.inbuf[0], self.inbuf[1], self.inbuf[2]]) as usize;
                if self.inbuf.len() >= 9 + len {
                    let f = Frame {
                        kind: self.inbuf[3],
                        flags: self.inbuf[4],
                        stream: u32::from_be_bytes(self.inbuf[5..9].try_into().unwrap()) & 0x7fff_ffff,
                        p: self.inbuf[9..9 + len].to_vec(),
                    };
                    self.inbuf.drain(..9 + len);
                    // Acknowledge the server's SETTINGS and answer its PINGs like h2spec does.
                    if f.kind == SETTINGS && f.flags & ACK == 0 {
                        self.raw(SETTINGS, ACK, 0, &[]);
                    }
                    if f.kind == PING && f.flags & ACK == 0 && f.p.len() == 8 {
                        let p = f.p.clone();
                        self.raw(PING, ACK, 0, &p);
                    }
                    return Some(f);
                }
            }
            if self.closed || Instant::now() > deadline {
                return None;
            }
            match self.io.recv() {
                Ok(Some(b)) => self.inbuf.extend_from_slice(&b),
                Ok(None) => {}
                Err(()) => self.closed = true,
            }
        }
    }

    /// Preface, our SETTINGS, the server's SETTINGS and the ACK of ours.
    fn handshake(&mut self, ours: &[(u16, u32)]) -> Result<(), String> {
        self.send(PREFACE);
        self.send(&settings(ours));
        let deadline = Instant::now() + WAIT;
        let (mut got_settings, mut got_ack) = (false, false);
        while !(got_settings && got_ack) {
            let f = self.next(deadline).ok_or("handshake: no SETTINGS / ACK from the server")?;
            if f.kind == SETTINGS && f.flags & ACK == 0 {
                got_settings = true;
                for c in f.p.chunks_exact(6) {
                    self.server_settings.push((u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes(c[2..6].try_into().unwrap())));
                }
            } else if f.kind == SETTINGS {
                got_ack = true;
            } else if f.kind == GOAWAY {
                return Err(format!("handshake: GOAWAY {}", f.code()));
            }
        }
        Ok(())
    }

    fn setting(&self, k: u16) -> Option<u32> {
        self.server_settings.iter().rev().find(|(x, _)| *x == k).map(|(_, v)| *v)
    }

    fn req(&self, method: &'static str, path: &'static str) -> Vec<(&'static str, &'static str)> {
        vec![(":method", method), (":scheme", self.scheme), (":path", path), (":authority", "localhost")]
    }

    fn get(&mut self, stream: u32) {
        let b = block(&self.req("GET", "/"));
        self.raw(HEADERS, END_HEADERS | END_STREAM, stream, &b);
    }

    /// A POST whose body is still open.
    fn post_open(&mut self, stream: u32) {
        let b = block(&self.req("POST", "/"));
        self.raw(HEADERS, END_HEADERS, stream, &b);
    }

    // ------------------------------------------------------------ expectations

    fn conn_error(&mut self, codes: &[u32]) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.next(deadline) {
                Some(f) if f.kind == GOAWAY => {
                    return if codes.contains(&f.code()) { Ok(()) } else { Err(format!("GOAWAY {} (expected {codes:?})", f.code())) };
                }
                Some(_) => {}
                None if self.closed => {
                    CLOSE_ONLY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                None => return Err(format!("timeout waiting for GOAWAY {codes:?}")),
            }
        }
    }

    fn stream_error(&mut self, stream: u32, codes: &[u32]) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.next(deadline) {
                Some(f) if f.kind == GOAWAY || (f.kind == RST_STREAM && f.stream == stream) => {
                    return if codes.contains(&f.code()) {
                        Ok(())
                    } else {
                        Err(format!("{} {} (expected {codes:?})", if f.kind == GOAWAY { "GOAWAY" } else { "RST_STREAM" }, f.code()))
                    };
                }
                Some(_) => {}
                None if self.closed => {
                    CLOSE_ONLY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                None => return Err(format!("timeout waiting for a stream error {codes:?} on {stream}")),
            }
        }
    }

    /// A response HEADERS on `stream`.
    fn response(&mut self, stream: u32) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.next(deadline) {
                Some(f) if f.kind == HEADERS && f.stream == stream => return Ok(()),
                Some(f) if f.kind == GOAWAY => return Err(format!("GOAWAY {}", f.code())),
                Some(f) if f.kind == RST_STREAM && f.stream == stream => return Err(format!("RST_STREAM {}", f.code())),
                Some(_) => {}
                None if self.closed => return Err("connection closed".into()),
                None => return Err(format!("timeout waiting for a response on {stream}")),
            }
        }
    }

    /// Reads until the server ends `stream` (END_STREAM on HEADERS or DATA).
    fn until_end(&mut self, stream: u32) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.next(deadline) {
                Some(f) if (f.kind == DATA || f.kind == HEADERS) && f.stream == stream && f.flags & END_STREAM != 0 => return Ok(()),
                Some(f) if f.kind == GOAWAY => return Err(format!("GOAWAY {}", f.code())),
                Some(_) => {}
                None => return Err(format!("stream {stream} did not end")),
            }
        }
    }

    /// A DATA frame on `stream`; returns its payload length.
    fn data(&mut self, stream: u32) -> Result<usize, String> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.next(deadline) {
                Some(f) if f.kind == DATA && f.stream == stream => return Ok(f.p.len()),
                Some(f) if f.kind == GOAWAY => return Err(format!("GOAWAY {}", f.code())),
                Some(f) if f.kind == RST_STREAM && f.stream == stream => return Err(format!("RST_STREAM {}", f.code())),
                Some(_) => {}
                None if self.closed => return Err("connection closed".into()),
                None => return Err(format!("timeout waiting for DATA on {stream}")),
            }
        }
    }

    fn ping_ack(&mut self, data: [u8; 8]) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.next(deadline) {
                Some(f) if f.kind == PING && f.flags & ACK != 0 => {
                    return if f.p == data { Ok(()) } else { Err(format!("PING ACK with {:?}, expected {data:?}", f.p)) };
                }
                Some(f) if f.kind == GOAWAY => return Err(format!("GOAWAY {}", f.code())),
                Some(_) => {}
                None if self.closed => return Err("connection closed".into()),
                None => return Err("timeout waiting for a PING ACK".into()),
            }
        }
    }

    fn settings_ack(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.next(deadline) {
                Some(f) if f.kind == SETTINGS && f.flags & ACK != 0 => return Ok(()),
                Some(f) if f.kind == GOAWAY => return Err(format!("GOAWAY {}", f.code())),
                Some(_) => {}
                None if self.closed => return Err("connection closed".into()),
                None => return Err("timeout waiting for a SETTINGS ACK".into()),
            }
        }
    }

    /// The connection is still usable: a PING is answered.
    fn alive(&mut self) -> Result<(), String> {
        let d = *b"h2-alive";
        self.raw(PING, 0, 0, &d);
        self.ping_ack(d)
    }
}

// ---------------------------------------------------------------- cases

type Case = (&'static str, fn(&mut Conn) -> Result<(), String>);

fn hs(c: &mut Conn) -> Result<(), String> {
    c.handshake(&[])
}

/// A GET whose header block (huffman `:authority`, RFC 7541 C.4.1) uses `extra` for the last
/// field instead of a plain literal.
fn get_with_block(c: &mut Conn, stream: u32, extra: &[u8]) {
    let mut b = block(&c.req("GET", "/")[..3]);
    b.extend_from_slice(extra);
    c.raw(HEADERS, END_HEADERS | END_STREAM, stream, &b);
}

fn cases() -> Vec<Case> {
    let mut v: Vec<Case> = Vec::new();
    // ------------------------------------------------ generic
    v.push(("generic/1 starting HTTP/2: preface and SETTINGS", |c| hs(c)));
    v.push(("generic/2.1 GET on stream 1", |c| {
        hs(c)?;
        c.get(1);
        c.response(1)
    }));
    v.push(("generic/2.2 POST with a body", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(DATA, END_STREAM, 1, b"hello");
        c.response(1)
    }));
    v.push(("generic/2.3 HEADERS + CONTINUATION", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        let (a, rest) = b.split_at(b.len() / 2);
        c.raw(HEADERS, END_STREAM, 1, a);
        c.raw(CONTINUATION, END_HEADERS, 1, rest);
        c.response(1)
    }));
    v.push(("generic/2.4 POST with trailers", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(DATA, 0, 1, b"body");
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &block(&[("x-trailer", "1")]));
        c.response(1)
    }));
    v.push(("generic/2.5 padded DATA", |c| {
        hs(c)?;
        c.post_open(1);
        let mut p = vec![4u8];
        p.extend_from_slice(b"data");
        p.extend_from_slice(&[0; 4]);
        c.raw(DATA, PADDED | END_STREAM, 1, &p);
        c.response(1)
    }));
    v.push(("generic/2.6 padded HEADERS with priority", |c| {
        hs(c)?;
        let mut p = vec![3u8];
        p.extend_from_slice(&0u32.to_be_bytes());
        p.push(15);
        p.extend_from_slice(&block(&c.req("GET", "/")));
        p.extend_from_slice(&[0; 3]);
        c.raw(HEADERS, PADDED | PRIO | END_HEADERS | END_STREAM, 1, &p);
        c.response(1)
    }));
    v.push(("generic/3.1 PRIORITY frame", |c| {
        hs(c)?;
        c.raw(PRIORITY, 0, 1, &[0, 0, 0, 0, 15]);
        c.get(3);
        c.response(3)
    }));
    v.push(("generic/3.2 RST_STREAM on an open stream", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(RST_STREAM, 0, 1, &8u32.to_be_bytes());
        c.alive()
    }));
    v.push(("generic/3.3 SETTINGS with every known parameter", |c| {
        hs(c)?;
        c.send(&settings(&[(S_HEADER_TABLE_SIZE, 4096), (S_ENABLE_PUSH, 0), (S_MAX_CONCURRENT_STREAMS, 100), (S_INITIAL_WINDOW_SIZE, 65535), (S_MAX_FRAME_SIZE, 16384), (6, 65536)]));
        c.settings_ack()
    }));
    v.push(("generic/3.4 PING", |c| {
        hs(c)?;
        c.raw(PING, 0, 0, b"pingpong");
        c.ping_ack(*b"pingpong")
    }));
    v.push(("generic/3.5 WINDOW_UPDATE on the connection and a stream", |c| {
        hs(c)?;
        c.raw(WINDOW_UPDATE, 0, 0, &1u32.to_be_bytes());
        c.get(1);
        c.raw(WINDOW_UPDATE, 0, 1, &1u32.to_be_bytes());
        c.response(1)
    }));
    v.push(("generic/3.6 GOAWAY from the client", |c| {
        hs(c)?;
        c.raw(GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]);
        // The server may answer with its own GOAWAY or just close; it must not error.
        let deadline = Instant::now() + Duration::from_millis(500);
        while let Some(f) = c.next(deadline) {
            if f.kind == GOAWAY && f.code() != NO_ERROR {
                return Err(format!("GOAWAY {}", f.code()));
            }
        }
        Ok(())
    }));
    v.push(("generic/4 many streams in sequence", |c| {
        hs(c)?;
        for s in (1..40).step_by(2) {
            c.get(s);
        }
        for s in (1..40).step_by(2) {
            c.response(s)?;
        }
        Ok(())
    }));
    v.push(("generic/5.1 HPACK indexed static field", |c| {
        hs(c)?;
        // :method GET (2), :scheme from the table, :path / (4), literal :authority
        let mut b = vec![0x82, if c.scheme == "https" { 0x87 } else { 0x86 }, 0x84];
        b.push(0x01);
        hstr(&mut b, b"localhost");
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.response(1)
    }));
    v.push(("generic/5.2 HPACK literal with incremental indexing, then indexed", |c| {
        hs(c)?;
        let mut b = block(&c.req("GET", "/"));
        b.push(0x40);
        hstr(&mut b, b"x-custom");
        hstr(&mut b, b"value");
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.response(1)?;
        let mut b = block(&c.req("GET", "/"));
        b.push(0x80 | 62); // the dynamic entry just added
        c.raw(HEADERS, END_HEADERS | END_STREAM, 3, &b);
        c.response(3)
    }));
    v.push(("generic/5.3 HPACK literal never indexed", |c| {
        hs(c)?;
        let mut b = block(&c.req("GET", "/"));
        b.push(0x10);
        hstr(&mut b, b"x-secret");
        hstr(&mut b, b"s");
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.response(1)
    }));
    v.push(("generic/5.4 HPACK huffman string", |c| {
        hs(c)?;
        // literal with indexing, name :authority (1), huffman "www.example.com"
        get_with_block(c, 1, &[0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]);
        c.response(1)
    }));
    v.push(("generic/5.5 HPACK dynamic table size update to 0", |c| {
        hs(c)?;
        let mut b = vec![0x20];
        b.extend_from_slice(&block(&c.req("GET", "/")));
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.response(1)
    }));
    // ------------------------------------------------ 3.5 preface
    v.push(("3.5/1 client connection preface", |c| hs(c)));
    v.push(("3.5/2 invalid connection preface", |c| {
        c.send(b"INVALID CONNECTION PREFACE\r\n\r\n");
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ 4 frames
    v.push(("4.1/1 unknown frame type is ignored", |c| {
        hs(c)?;
        c.raw(0x16, 0, 0, b"unknown");
        c.alive()
    }));
    v.push(("4.1/2 undefined flags are ignored", |c| {
        hs(c)?;
        c.raw(PING, 0x16, 0, b"flagflag");
        c.ping_ack(*b"flagflag")
    }));
    v.push(("4.1/3 reserved bit is ignored", |c| {
        hs(c)?;
        c.raw(PING, 0, 0x8000_0000, b"reserved");
        c.ping_ack(*b"reserved")
    }));
    v.push(("4.2/1 DATA of 2^14 octets", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(DATA, END_STREAM, 1, &vec![b'x'; 16384]);
        c.response(1)
    }));
    v.push(("4.2/2 DATA over SETTINGS_MAX_FRAME_SIZE", |c| {
        hs(c)?;
        let max = c.setting(S_MAX_FRAME_SIZE).unwrap_or(16384) as usize;
        c.post_open(1);
        c.raw(DATA, END_STREAM, 1, &vec![b'x'; max + 1]);
        c.stream_error(1, &[FRAME_SIZE_ERROR])
    }));
    v.push(("4.2/3 HEADERS over SETTINGS_MAX_FRAME_SIZE", |c| {
        hs(c)?;
        let max = c.setting(S_MAX_FRAME_SIZE).unwrap_or(16384) as usize;
        let mut b = block(&c.req("GET", "/"));
        while b.len() <= max {
            lit(&mut b, "x-fill", &"y".repeat(200));
        }
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.conn_error(&[FRAME_SIZE_ERROR])
    }));
    v.push(("4.3/1 invalid header block fragment", |c| {
        hs(c)?;
        // a literal whose name length runs past the end of the block
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x00, 0x7f]);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("4.3/2 PRIORITY in the middle of a header block", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_STREAM, 1, &b);
        c.raw(PRIORITY, 0, 1, &[0, 0, 0, 0, 15]);
        c.raw(CONTINUATION, END_HEADERS, 1, &[]);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("4.3/3 frames of another stream inside a header block", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_STREAM, 1, &b);
        let b2 = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_HEADERS | END_STREAM, 3, &b2);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ 5.1 stream states
    v.push(("5.1/1 idle: DATA", |c| {
        hs(c)?;
        c.raw(DATA, END_STREAM, 1, b"x");
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("5.1/2 idle: RST_STREAM", |c| {
        hs(c)?;
        c.raw(RST_STREAM, 0, 1, &8u32.to_be_bytes());
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("5.1/3 idle: WINDOW_UPDATE", |c| {
        hs(c)?;
        c.raw(WINDOW_UPDATE, 0, 1, &100u32.to_be_bytes());
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("5.1/4 idle: CONTINUATION", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(CONTINUATION, END_HEADERS, 1, &b);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("5.1/5 half closed (remote): DATA", |c| {
        hs(c)?;
        c.get(1);
        c.raw(DATA, END_STREAM, 1, b"x");
        c.stream_error(1, &[STREAM_CLOSED])
    }));
    v.push(("5.1/6 half closed (remote): HEADERS", |c| {
        hs(c)?;
        c.get(1);
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.stream_error(1, &[STREAM_CLOSED])
    }));
    v.push(("5.1/7 half closed (remote): CONTINUATION", |c| {
        hs(c)?;
        c.get(1);
        c.raw(CONTINUATION, END_HEADERS, 1, &block(&[("x-a", "b")]));
        c.stream_error(1, &[STREAM_CLOSED, PROTOCOL_ERROR])
    }));
    v.push(("5.1/8 closed: DATA after RST_STREAM", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(RST_STREAM, 0, 1, &8u32.to_be_bytes());
        c.raw(DATA, END_STREAM, 1, b"x");
        c.stream_error(1, &[STREAM_CLOSED])
    }));
    v.push(("5.1/9 closed: HEADERS after RST_STREAM", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(RST_STREAM, 0, 1, &8u32.to_be_bytes());
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.stream_error(1, &[STREAM_CLOSED])
    }));
    v.push(("5.1/10 closed: CONTINUATION after RST_STREAM", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(RST_STREAM, 0, 1, &8u32.to_be_bytes());
        c.raw(CONTINUATION, END_HEADERS, 1, &block(&[("x-a", "b")]));
        c.stream_error(1, &[STREAM_CLOSED, PROTOCOL_ERROR])
    }));
    v.push(("5.1/11 closed: DATA after END_STREAM both ways", |c| {
        hs(c)?;
        c.get(1);
        c.response(1)?;
        c.until_end(1)?;
        c.raw(DATA, END_STREAM, 1, b"x");
        c.stream_error(1, &[STREAM_CLOSED])
    }));
    v.push(("5.1/12 closed: HEADERS after END_STREAM both ways", |c| {
        hs(c)?;
        c.get(1);
        c.response(1)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.stream_error(1, &[STREAM_CLOSED, PROTOCOL_ERROR])
    }));
    v.push(("5.1/13 closed: CONTINUATION after END_STREAM both ways", |c| {
        hs(c)?;
        c.get(1);
        c.response(1)?;
        c.raw(CONTINUATION, END_HEADERS, 1, &block(&[("x-a", "b")]));
        c.stream_error(1, &[STREAM_CLOSED, PROTOCOL_ERROR])
    }));
    v.push(("5.1.1/1 even-numbered stream identifier", |c| {
        hs(c)?;
        c.get(2);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("5.1.1/2 stream identifier smaller than a previous one", |c| {
        hs(c)?;
        c.get(5);
        c.response(5)?;
        c.get(3);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("5.1.2/1 more streams than SETTINGS_MAX_CONCURRENT_STREAMS", |c| {
        hs(c)?;
        let Some(max) = c.setting(S_MAX_CONCURRENT_STREAMS) else { return Ok(()) };
        if max > 1000 {
            return Ok(());
        }
        let mut s = 1;
        for _ in 0..=max {
            c.post_open(s);
            s += 2;
        }
        c.stream_error(s - 2, &[PROTOCOL_ERROR, REFUSED_STREAM])
    }));
    v.push(("5.3.1/1 HEADERS that depends on itself", |c| {
        hs(c)?;
        let mut p = 1u32.to_be_bytes().to_vec();
        p.push(15);
        p.extend_from_slice(&block(&c.req("GET", "/")));
        c.raw(HEADERS, PRIO | END_HEADERS | END_STREAM, 1, &p);
        c.stream_error(1, &[PROTOCOL_ERROR])
    }));
    v.push(("5.3.1/2 PRIORITY that depends on itself", |c| {
        hs(c)?;
        c.raw(PRIORITY, 0, 1, &[0, 0, 0, 1, 15]);
        c.stream_error(1, &[PROTOCOL_ERROR])
    }));
    v.push(("5.4.1/1 connection error: GOAWAY sent", |c| {
        hs(c)?;
        c.raw(PING, 0, 3, b"badstrm!");
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("5.4.1/2 connection error: connection closed after GOAWAY", |c| {
        hs(c)?;
        c.raw(PING, 0, 3, b"badstrm!");
        c.conn_error(&[PROTOCOL_ERROR])?;
        let deadline = Instant::now() + WAIT;
        while c.next(deadline).is_some() {}
        if c.closed {
            Ok(())
        } else {
            Err("connection still open after GOAWAY".into())
        }
    }));
    v.push(("5.5/1 unknown extension frame is ignored", |c| {
        hs(c)?;
        c.raw(0xff, 0, 0, b"ext");
        c.alive()
    }));
    v.push(("5.5/2 unknown extension frame inside a header block", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_STREAM, 1, &b);
        c.raw(0xff, 0, 1, b"ext");
        c.raw(CONTINUATION, END_HEADERS, 1, &[]);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ 6.1 DATA
    v.push(("6.1/1 DATA on stream 0", |c| {
        hs(c)?;
        c.raw(DATA, END_STREAM, 0, b"x");
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.1/2 DATA on a stream that is not open", |c| {
        hs(c)?;
        c.get(1);
        c.raw(DATA, END_STREAM, 1, b"x");
        c.stream_error(1, &[STREAM_CLOSED])
    }));
    v.push(("6.1/3 DATA with an invalid pad length", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(DATA, PADDED | END_STREAM, 1, &[6, b'a', b'b', b'c', b'd', b'e']);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ 6.2 HEADERS
    v.push(("6.2/1 HEADERS without END_HEADERS, then PRIORITY", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_STREAM, 1, &b);
        c.raw(PRIORITY, 0, 1, &[0, 0, 0, 0, 15]);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.2/2 HEADERS without END_HEADERS, then DATA of another stream", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_STREAM, 1, &b);
        c.raw(DATA, END_STREAM, 3, b"x");
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.2/3 HEADERS on stream 0", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_HEADERS | END_STREAM, 0, &b);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.2/4 HEADERS with an invalid pad length", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        let mut p = vec![(b.len() + 1).min(255) as u8];
        p.extend_from_slice(&b);
        c.raw(HEADERS, PADDED | END_HEADERS | END_STREAM, 1, &p);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ 6.3 PRIORITY
    v.push(("6.3/1 PRIORITY on stream 0", |c| {
        hs(c)?;
        c.raw(PRIORITY, 0, 0, &[0, 0, 0, 1, 15]);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.3/2 PRIORITY with a length other than 5", |c| {
        hs(c)?;
        c.raw(PRIORITY, 0, 1, &[0, 0, 0, 0, 15, 0]);
        c.stream_error(1, &[FRAME_SIZE_ERROR])
    }));
    // ------------------------------------------------ 6.4 RST_STREAM
    v.push(("6.4/1 RST_STREAM on stream 0", |c| {
        hs(c)?;
        c.raw(RST_STREAM, 0, 0, &8u32.to_be_bytes());
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.4/2 RST_STREAM on an idle stream", |c| {
        hs(c)?;
        c.raw(RST_STREAM, 0, 3, &8u32.to_be_bytes());
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.4/3 RST_STREAM with a length other than 4", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(RST_STREAM, 0, 1, &[0, 0, 0, 8, 0]);
        c.conn_error(&[FRAME_SIZE_ERROR])
    }));
    // ------------------------------------------------ 6.5 SETTINGS
    v.push(("6.5/1 SETTINGS ACK with a payload", |c| {
        hs(c)?;
        c.raw(SETTINGS, ACK, 0, &[0, 1, 0, 0, 0x10, 0]);
        c.conn_error(&[FRAME_SIZE_ERROR])
    }));
    v.push(("6.5/2 SETTINGS on a stream other than 0", |c| {
        hs(c)?;
        c.raw(SETTINGS, 0, 1, &[0, 3, 0, 0, 0, 100]);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.5/3 SETTINGS with a length not a multiple of 6", |c| {
        hs(c)?;
        c.raw(SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100, 0]);
        c.conn_error(&[FRAME_SIZE_ERROR])
    }));
    v.push(("6.5.2/1 SETTINGS_ENABLE_PUSH = 2", |c| {
        hs(c)?;
        c.send(&settings(&[(S_ENABLE_PUSH, 2)]));
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.5.2/2 SETTINGS_INITIAL_WINDOW_SIZE over 2^31-1", |c| {
        hs(c)?;
        c.send(&settings(&[(S_INITIAL_WINDOW_SIZE, 1 << 31)]));
        c.conn_error(&[FLOW_CONTROL_ERROR])
    }));
    v.push(("6.5.2/3 SETTINGS_MAX_FRAME_SIZE under 16384", |c| {
        hs(c)?;
        c.send(&settings(&[(S_MAX_FRAME_SIZE, 16383)]));
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.5.2/4 SETTINGS_MAX_FRAME_SIZE over 2^24-1", |c| {
        hs(c)?;
        c.send(&settings(&[(S_MAX_FRAME_SIZE, 1 << 24)]));
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.5.2/5 unknown setting is ignored", |c| {
        hs(c)?;
        c.send(&settings(&[(0xff, 1)]));
        c.settings_ack()
    }));
    v.push(("6.5.3/1 several values of one setting", |c| {
        hs(c)?;
        c.send(&settings(&[(S_INITIAL_WINDOW_SIZE, 100), (S_INITIAL_WINDOW_SIZE, 1)]));
        c.settings_ack()?;
        c.get(1);
        c.response(1)?;
        match c.data(1)? {
            1 => Ok(()),
            n => Err(format!("DATA of {n} bytes with a 1-byte window")),
        }
    }));
    v.push(("6.5.3/2 SETTINGS is acknowledged", |c| {
        hs(c)?;
        c.send(&settings(&[]));
        c.settings_ack()
    }));
    // ------------------------------------------------ 6.7 PING
    v.push(("6.7/1 PING is answered with the same payload", |c| {
        hs(c)?;
        c.raw(PING, 0, 0, b"h2spec!!");
        c.ping_ack(*b"h2spec!!")
    }));
    v.push(("6.7/2 PING ACK is not answered", |c| {
        hs(c)?;
        c.raw(PING, ACK, 0, b"invalid!");
        c.raw(PING, 0, 0, b"validpng");
        c.ping_ack(*b"validpng")
    }));
    v.push(("6.7/3 PING on a stream other than 0", |c| {
        hs(c)?;
        c.raw(PING, 0, 1, b"h2spec!!");
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.7/4 PING with a length other than 8", |c| {
        hs(c)?;
        c.raw(PING, 0, 0, b"h2spec");
        c.conn_error(&[FRAME_SIZE_ERROR])
    }));
    // ------------------------------------------------ 6.8 GOAWAY
    v.push(("6.8/1 GOAWAY on a stream other than 0", |c| {
        hs(c)?;
        c.raw(GOAWAY, 0, 1, &[0, 0, 0, 0, 0, 0, 0, 0]);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ 6.9 WINDOW_UPDATE
    v.push(("6.9/1 WINDOW_UPDATE of 0 on the connection", |c| {
        hs(c)?;
        c.raw(WINDOW_UPDATE, 0, 0, &0u32.to_be_bytes());
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.9/2 WINDOW_UPDATE of 0 on a stream", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(WINDOW_UPDATE, 0, 1, &0u32.to_be_bytes());
        c.stream_error(1, &[PROTOCOL_ERROR])
    }));
    v.push(("6.9/3 WINDOW_UPDATE with a length other than 4", |c| {
        hs(c)?;
        c.raw(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1, 0]);
        c.conn_error(&[FRAME_SIZE_ERROR])
    }));
    v.push(("6.9.1/1 SETTINGS_INITIAL_WINDOW_SIZE of 1 gives 1-byte DATA", |c| {
        c.handshake(&[(S_INITIAL_WINDOW_SIZE, 1)])?;
        c.get(1);
        c.response(1)?;
        match c.data(1)? {
            1 => Ok(()),
            n => Err(format!("DATA of {n} bytes with a 1-byte window")),
        }
    }));
    v.push(("6.9.1/2 connection window over 2^31-1", |c| {
        hs(c)?;
        c.raw(WINDOW_UPDATE, 0, 0, &0x7fff_ffffu32.to_be_bytes());
        c.raw(WINDOW_UPDATE, 0, 0, &0x7fff_ffffu32.to_be_bytes());
        c.conn_error(&[FLOW_CONTROL_ERROR])
    }));
    v.push(("6.9.1/3 stream window over 2^31-1", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(WINDOW_UPDATE, 0, 1, &0x7fff_ffffu32.to_be_bytes());
        c.raw(WINDOW_UPDATE, 0, 1, &0x7fff_ffffu32.to_be_bytes());
        c.stream_error(1, &[FLOW_CONTROL_ERROR])
    }));
    v.push(("6.9.2/1 SETTINGS_INITIAL_WINDOW_SIZE changed after HEADERS", |c| {
        c.handshake(&[(S_INITIAL_WINDOW_SIZE, 0)])?;
        c.get(1);
        c.response(1)?;
        c.send(&settings(&[(S_INITIAL_WINDOW_SIZE, 1)]));
        match c.data(1)? {
            1 => Ok(()),
            n => Err(format!("DATA of {n} bytes with a 1-byte window")),
        }
    }));
    v.push(("6.9.2/2 negative stream window after a SETTINGS change", |c| {
        c.handshake(&[(S_INITIAL_WINDOW_SIZE, 3)])?;
        c.get(1);
        c.response(1)?;
        let n = c.data(1)?;
        if n != 3 {
            return Err(format!("first DATA of {n} bytes with a 3-byte window"));
        }
        c.send(&settings(&[(S_INITIAL_WINDOW_SIZE, 2)])); // window now -1
        c.settings_ack()?;
        c.raw(WINDOW_UPDATE, 0, 1, &2u32.to_be_bytes()); // window now 1
        match c.data(1)? {
            1 => Ok(()),
            n => Err(format!("DATA of {n} bytes with a window of 1")),
        }
    }));
    v.push(("6.9.2/3 SETTINGS_INITIAL_WINDOW_SIZE of 2^31", |c| {
        hs(c)?;
        c.send(&settings(&[(S_INITIAL_WINDOW_SIZE, 1 << 31)]));
        c.conn_error(&[FLOW_CONTROL_ERROR])
    }));
    // ------------------------------------------------ 6.10 CONTINUATION
    v.push(("6.10/1 several CONTINUATION frames", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        let k = b.len() / 3;
        c.raw(HEADERS, END_STREAM, 1, &b[..k]);
        c.raw(CONTINUATION, 0, 1, &b[k..2 * k]);
        c.raw(CONTINUATION, END_HEADERS, 1, &b[2 * k..]);
        c.response(1)
    }));
    v.push(("6.10/2 CONTINUATION followed by another frame", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_STREAM, 1, &b);
        c.raw(CONTINUATION, 0, 1, &[]);
        c.raw(DATA, 0, 1, b"x");
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.10/3 CONTINUATION on stream 0", |c| {
        hs(c)?;
        let b = block(&c.req("GET", "/"));
        c.raw(HEADERS, END_STREAM, 1, &b);
        c.raw(CONTINUATION, END_HEADERS, 0, &[]);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.10/4 CONTINUATION after HEADERS with END_HEADERS", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(CONTINUATION, END_HEADERS, 1, &block(&[("x-a", "b")]));
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.10/5 CONTINUATION after CONTINUATION with END_HEADERS", |c| {
        hs(c)?;
        let b = block(&c.req("POST", "/"));
        c.raw(HEADERS, 0, 1, &b);
        c.raw(CONTINUATION, END_HEADERS, 1, &[]);
        c.raw(CONTINUATION, END_HEADERS, 1, &block(&[("x-a", "b")]));
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    v.push(("6.10/6 CONTINUATION after DATA", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(DATA, 0, 1, b"x");
        c.raw(CONTINUATION, END_HEADERS, 1, &block(&[("x-a", "b")]));
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ 8 HTTP semantics
    v.push(("8.1/1 second HEADERS without END_STREAM", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(DATA, 0, 1, b"x");
        c.raw(HEADERS, END_HEADERS, 1, &block(&[("x-trailer", "1")]));
        c.stream_error(1, &[PROTOCOL_ERROR])
    }));
    fn bad_request(c: &mut Conn, fields: &[(&str, &str)]) -> Result<(), String> {
        hs(c)?;
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &block(fields));
        c.stream_error(1, &[PROTOCOL_ERROR])
    }
    v.push(("8.1.2/1 uppercase header name", |c| {
        let mut f = c.req("GET", "/");
        f.push(("X-Upper", "1"));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.1/1 unknown pseudo-header", |c| {
        let mut f = c.req("GET", "/");
        f.push((":foo", "1"));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.1/2 response pseudo-header in a request", |c| {
        let mut f = c.req("GET", "/");
        f.push((":status", "200"));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.1/3 pseudo-header in trailers", |c| {
        hs(c)?;
        c.post_open(1);
        c.raw(DATA, 0, 1, b"x");
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &block(&[(":method", "GET")]));
        c.stream_error(1, &[PROTOCOL_ERROR])
    }));
    v.push(("8.1.2.1/4 pseudo-header after a regular header", |c| {
        let s = c.scheme;
        bad_request(c, &[(":method", "GET"), (":scheme", s), ("x-a", "b"), (":path", "/"), (":authority", "localhost")])
    }));
    v.push(("8.1.2.2/1 connection-specific header field", |c| {
        let mut f = c.req("GET", "/");
        f.push(("connection", "keep-alive"));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.2/2 TE other than trailers", |c| {
        let mut f = c.req("GET", "/");
        f.push(("te", "trailers, deflate"));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.3/1 empty :path", |c| {
        let s = c.scheme;
        bad_request(c, &[(":method", "GET"), (":scheme", s), (":path", ""), (":authority", "localhost")])
    }));
    v.push(("8.1.2.3/2 no :method", |c| {
        let s = c.scheme;
        bad_request(c, &[(":scheme", s), (":path", "/"), (":authority", "localhost")])
    }));
    v.push(("8.1.2.3/3 no :scheme", |c| bad_request(c, &[(":method", "GET"), (":path", "/"), (":authority", "localhost")])));
    v.push(("8.1.2.3/4 no :path", |c| {
        let s = c.scheme;
        bad_request(c, &[(":method", "GET"), (":scheme", s), (":authority", "localhost")])
    }));
    v.push(("8.1.2.3/5 duplicate :method", |c| {
        let mut f = c.req("GET", "/");
        f.insert(1, (":method", "GET"));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.3/6 duplicate :scheme", |c| {
        let mut f = c.req("GET", "/");
        let s = c.scheme;
        f.insert(1, (":scheme", s));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.3/7 duplicate :path", |c| {
        let mut f = c.req("GET", "/");
        f.insert(1, (":path", "/"));
        bad_request(c, &f)
    }));
    v.push(("8.1.2.6/1 content-length larger than the DATA", |c| {
        hs(c)?;
        let mut f = c.req("POST", "/");
        f.push(("content-length", "4"));
        c.raw(HEADERS, END_HEADERS, 1, &block(&f));
        c.raw(DATA, END_STREAM, 1, b"x");
        c.stream_error(1, &[PROTOCOL_ERROR])
    }));
    v.push(("8.1.2.6/2 content-length smaller than several DATA frames", |c| {
        hs(c)?;
        let mut f = c.req("POST", "/");
        f.push(("content-length", "4"));
        c.raw(HEADERS, END_HEADERS, 1, &block(&f));
        c.raw(DATA, 0, 1, b"xxx");
        c.raw(DATA, END_STREAM, 1, b"xxx");
        c.stream_error(1, &[PROTOCOL_ERROR])
    }));
    v.push(("8.2/1 PUSH_PROMISE from a client", |c| {
        hs(c)?;
        c.get(1);
        let mut p = 2u32.to_be_bytes().to_vec();
        p.extend_from_slice(&block(&c.req("GET", "/")));
        c.raw(PUSH_PROMISE, END_HEADERS, 1, &p);
        c.conn_error(&[PROTOCOL_ERROR])
    }));
    // ------------------------------------------------ HPACK (RFC 7541)
    v.push(("hpack/2.3.3/1 indexed field beyond the table", |c| {
        hs(c)?;
        get_with_block(c, 1, &[0x80 | 70]);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("hpack/2.3.3/2 literal with a name index beyond the table", |c| {
        hs(c)?;
        get_with_block(c, 1, &[0x7f, 0x07, 0x01, b'a']);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("hpack/4.2/1 table size update above SETTINGS_HEADER_TABLE_SIZE", |c| {
        hs(c)?;
        let mut b = Vec::new();
        hint(&mut b, 0x20, 5, 4097);
        b.extend_from_slice(&block(&c.req("GET", "/")));
        c.raw(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("hpack/5.2/1 huffman padding longer than 7 bits", |c| {
        hs(c)?;
        get_with_block(c, 1, &[0x41, 0x82, 0x1f, 0xff]);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("hpack/5.2/2 huffman padding that is not an EOS prefix", |c| {
        hs(c)?;
        get_with_block(c, 1, &[0x41, 0x81, 0x18]);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("hpack/5.2/3 huffman string containing EOS", |c| {
        hs(c)?;
        get_with_block(c, 1, &[0x41, 0x84, 0xff, 0xff, 0xff, 0xff]);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("hpack/6.1/1 indexed field with index 0", |c| {
        hs(c)?;
        get_with_block(c, 1, &[0x80]);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v.push(("hpack/6.3/1 table size update after a field", |c| {
        hs(c)?;
        get_with_block(c, 1, &[0x41, 0x01, b'a', 0x20]);
        c.conn_error(&[COMPRESSION_ERROR])
    }));
    v
}

/// Runs every case on a fresh connection; returns (passed, failures).
fn run(target: &Target, label: &str) -> (usize, Vec<String>) {
    let mut passed = 0;
    let mut failed = Vec::new();
    for (name, f) in cases() {
        let r = target.open().and_then(|mut c| f(&mut c));
        match r {
            Ok(()) => passed += 1,
            Err(e) => failed.push(format!("{name}: {e}")),
        }
    }
    let close_only = CLOSE_ONLY.swap(0, std::sync::atomic::Ordering::Relaxed);
    eprintln!("h2 conformance [{label}]: {passed}/{} passed ({close_only} error cases saw a close without GOAWAY/RST_STREAM)", passed + failed.len());
    for f in &failed {
        eprintln!("  FAIL {f}");
    }
    (passed, failed)
}

// ---------------------------------------------------------------- in-process server

fn service(req: &mut simoom::Request<'_>, reply: simoom::Reply<'_>) -> simoom::Outcome {
    let body = format!("ok {} {} {}\n", String::from_utf8_lossy(req.method()), req.path_str(), req.body().len());
    reply.header("content-type", "text/plain").body(body)
}

#[test]
fn h2_conformance_h2c() {
    let h = simoom::Server::builder().listen("127.0.0.1:0").threads(2).service(service).start().unwrap();
    let (_, failed) = run(&Target::H2c(h.local_addr()), "h2c, in process");
    h.stop(Duration::from_millis(100));
    h.join();
    assert!(failed.is_empty(), "{failed:#?}");
}

#[cfg(feature = "tls-client")]
#[test]
fn h2_conformance_h2_tls() {
    use simoom::tls::certgen::{self, CertParams};
    use simoom::tls::{CertifiedKey, ServerConfig};
    use simoom_tls::keys::{EcCurve, PrivateKey};
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let cfg = ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap());
    let h = simoom::Server::builder().listen_tls("127.0.0.1:0").tls(cfg).threads(2).service(service).start().unwrap();
    let mut roots = simoom_tls::x509::RootStore::empty();
    roots.add_der(&ss.cert_der).unwrap();
    let (_, failed) = run(&Target::H2(h.local_addr(), roots), "h2 over TLS, in process");
    h.stop(Duration::from_millis(100));
    h.join();
    assert!(failed.is_empty(), "{failed:#?}");
}

/// Against running servers named by `SIMOOM_H2_LIVE_H2C` and `SIMOOM_H2_LIVE_H2` (+
/// `SIMOOM_H2_LIVE_CA`, a PEM trust anchor; verification is never turned off).
#[test]
#[ignore]
fn h2_conformance_live() {
    let mut all = Vec::new();
    if let Ok(a) = std::env::var("SIMOOM_H2_LIVE_H2C") {
        let addr = a.parse().expect("SIMOOM_H2_LIVE_H2C");
        all.extend(run(&Target::H2c(addr), &format!("h2c {a}")).1);
    }
    #[cfg(feature = "tls-client")]
    if let Ok(a) = std::env::var("SIMOOM_H2_LIVE_H2") {
        let addr = a.parse().expect("SIMOOM_H2_LIVE_H2");
        let mut roots = simoom_tls::x509::RootStore::empty();
        roots.add_pem_file(std::env::var("SIMOOM_H2_LIVE_CA").expect("SIMOOM_H2_LIVE_CA")).expect("CA PEM");
        all.extend(run(&Target::H2(addr, roots), &format!("h2 {a}")).1);
    }
    assert!(all.is_empty(), "{all:#?}");
}
