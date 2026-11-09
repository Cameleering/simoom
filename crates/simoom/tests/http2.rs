//! HTTP/2 through the facade (h2c prior knowledge and `Upgrade: h2c`) with the simoom-h2 client.

#![cfg(feature = "http2")]

mod common;

use common::*;
use simoom::{blocking, Limits, Outcome, Reply, Request, Response};
use simoom_h2::{Config, Connection, Event};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[derive(Default, Debug, Clone)]
pub struct H2Resp {
    pub status: u16,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
    pub done: bool,
    pub reset: bool,
}

impl H2Resp {
    fn header(&self, n: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(k, _)| k == n.as_bytes()).map(|(_, v)| &v[..])
    }
}

pub struct H2Client {
    pub s: TcpStream,
    pub conn: Connection,
    inbuf: Vec<u8>,
    pub resps: HashMap<u32, H2Resp>,
    start: Instant,
    pub goaway: bool,
    pub eof: bool,
}

impl H2Client {
    pub fn with(s: TcpStream, conn: Connection, leftover: Vec<u8>) -> H2Client {
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut c = H2Client { s, conn, inbuf: leftover, resps: HashMap::new(), start: Instant::now(), goaway: false, eof: false };
        c.flush();
        c
    }

    pub fn prior(h: &simoom::ServerHandle) -> H2Client {
        H2Client::with(connect(h), Connection::client(Config::default()), Vec::new())
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub fn flush(&mut self) {
        let out = self.conn.output().to_vec();
        if !out.is_empty() {
            let _ = self.s.write_all(&out);
            self.conn.advance_output(out.len());
        }
    }

    /// One read and processing step.
    pub fn step(&mut self) {
        let mut tmp = vec![0u8; 65536];
        match self.s.read(&mut tmp) {
            Ok(0) => self.eof = true,
            Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => self.eof = true,
        }
        let now = self.now();
        let resps = &mut self.resps;
        let mut release = Vec::new();
        let mut goaway = false;
        let n = self.conn.recv(&self.inbuf, now, &mut |ev| match ev {
            Event::Headers { stream, headers, end_stream } => {
                let r = resps.entry(stream).or_default();
                if let Some(st) = headers.status() {
                    if st >= 200 {
                        r.status = st;
                        r.headers = headers.iter().map(|(a, b)| (a.to_vec(), b.to_vec())).collect();
                    }
                }
                r.done |= end_stream;
            }
            Event::Data { stream, data, end_stream } => {
                let r = resps.entry(stream).or_default();
                r.body.extend_from_slice(data);
                r.done |= end_stream;
                release.push((stream, data.len()));
            }
            Event::Trailers { stream, .. } => resps.entry(stream).or_default().done = true,
            Event::Reset { stream, .. } => {
                let r = resps.entry(stream).or_default();
                r.reset = true;
                r.done = true;
            }
            Event::GoAway { .. } | Event::Closed { .. } => goaway = true,
            _ => {}
        });
        self.goaway |= goaway;
        self.inbuf.drain(..n);
        for (s, n) in release {
            self.conn.release(s, n);
        }
        self.flush();
    }

    pub fn request(&mut self, method: &str, path: &str, body: &[u8]) -> u32 {
        let id = self.conn.send_request(method.as_bytes(), b"http", b"t", path.as_bytes(), &[], body.is_empty()).unwrap();
        let mut sent = 0;
        while !body.is_empty() && sent < body.len() {
            let n = self.conn.send_data(id, &body[sent..], true).unwrap();
            sent += n;
            self.flush();
            if sent < body.len() {
                self.step();
            }
        }
        self.flush();
        id
    }

    pub fn wait(&mut self, id: u32) -> H2Resp {
        let end = Instant::now() + Duration::from_secs(15);
        while !self.resps.get(&id).is_some_and(|r| r.done) {
            assert!(Instant::now() < end, "timeout waiting for stream {id}");
            assert!(!self.eof, "connection closed waiting for stream {id}");
            self.step();
        }
        self.resps.remove(&id).unwrap()
    }
}

fn echo(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let s = format!("{} {} {:?} {}", String::from_utf8_lossy(req.method()), req.path_str(), req.version(), String::from_utf8_lossy(req.body()));
    reply.header("content-type", "text/plain").header("x-host", req.host().unwrap_or(b"")).body(s)
}

#[test]
fn prior_knowledge_get_and_post() {
    let h = serve(echo);
    let mut c = H2Client::prior(&h);
    let id = c.request("GET", "/a?q=1", b"");
    let r = c.wait(id);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"GET /a H2 ");
    assert_eq!(r.header("x-host"), Some(&b"t"[..]));
    assert!(r.header("date").is_some());
    assert_eq!(r.header("content-length"), Some(&b"10"[..]));
    let id = c.request("POST", "/b", b"payload");
    assert_eq!(c.wait(id).body, b"POST /b H2 payload");
    assert!(h.stats().h2_connections >= 1);
}

#[test]
fn concurrent_streams_complete_out_of_order() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let n: u64 = req.path_str().trim_start_matches('/').parse().unwrap_or(0);
        let responder = reply.defer();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50 - n % 50));
            responder.send(Response::text(format!("r{n}")));
        });
        Outcome::Deferred
    });
    let mut c = H2Client::prior(&h);
    let ids: Vec<(u32, u64)> = (0..60).map(|i| (c.request("GET", &format!("/{i}"), b""), i)).collect();
    for (id, i) in ids {
        assert_eq!(c.wait(id).body, format!("r{i}").into_bytes());
    }
}

#[test]
fn large_bodies_with_flow_control() {
    let big: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
    let b2 = big.clone();
    let h = serve(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/down" {
            reply.body(b2.clone())
        } else {
            reply.blocking(req, |mut r| {
                let body = r.read_body().unwrap();
                Response::text(format!("{} {}", body.len(), body.iter().map(|&b| u64::from(b)).sum::<u64>()))
            })
        }
    });
    let mut c = H2Client::prior(&h);
    let id = c.request("GET", "/down", b"");
    let r = c.wait(id);
    assert_eq!(r.body.len(), big.len());
    assert!(r.body == big);
    // Upload 2 MiB: larger than the body buffer, streamed with flow control.
    let up = &big[..2 * 1024 * 1024];
    let id = c.request("POST", "/up", up);
    let sum: u64 = up.iter().map(|&b| u64::from(b)).sum();
    assert_eq!(c.wait(id).body, format!("{} {sum}", up.len()).into_bytes());
}

#[test]
fn streamed_response_over_h2() {
    let h = serve(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let mut sink = reply.sse();
        std::thread::spawn(move || {
            for i in 0..5 {
                sink.send_event(&format!("e{i}")).unwrap();
            }
        });
        Outcome::Done
    });
    let mut c = H2Client::prior(&h);
    let id = c.request("GET", "/events", b"");
    let r = c.wait(id);
    assert_eq!(r.header("content-type"), Some(&b"text/event-stream"[..]));
    assert_eq!(String::from_utf8(r.body).unwrap(), "data: e0\n\ndata: e1\n\ndata: e2\n\ndata: e3\n\ndata: e4\n\n");
}

#[test]
fn upgrade_from_http1() {
    let h = serve(echo);
    let cfg = Config::default();
    let mut s = connect(&h);
    let settings = simoom_h2::http2_settings_header(&cfg);
    s.write_all(format!("GET /up HTTP/1.1\r\nHost: t\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: {settings}\r\n\r\n").as_bytes()).unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    assert!(buf.starts_with(b"HTTP/1.1 101 "), "{}", String::from_utf8_lossy(&buf));
    let rest = buf[head_end..].to_vec();
    let mut c = H2Client::with(s, Connection::client_upgrade(cfg, false), rest);
    let r = c.wait(1);
    assert_eq!(r.body, b"GET /up H2 ");
    // The connection carries on as HTTP/2.
    let id = c.request("GET", "/next", b"");
    assert_eq!(c.wait(id).body, b"GET /next H2 ");
    assert!(h.stats().upgrades >= 1);
}

#[test]
fn panic_gives_500_and_goaway() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/panic" {
            panic!("expected by the test");
        }
        reply.body_static(b"ok")
    });
    let mut c = H2Client::prior(&h);
    let id = c.request("GET", "/panic", b"");
    assert_eq!(c.wait(id).status, 500);
    let end = Instant::now() + Duration::from_secs(5);
    while !c.goaway && Instant::now() < end {
        c.step();
    }
    assert!(c.goaway);
}

#[test]
fn graceful_stop_sends_goaway_and_finishes_streams() {
    let h = serve(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let responder = reply.defer();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            responder.send(Response::text("finished"));
        });
        Outcome::Deferred
    });
    let mut c = H2Client::prior(&h);
    let id = c.request("GET", "/", b"");
    for _ in 0..3 {
        c.step();
    }
    h.stop(Duration::from_secs(5));
    let r = c.wait(id);
    assert_eq!(r.body, b"finished");
    assert!(c.goaway);
    let end = Instant::now() + Duration::from_secs(5);
    while !c.eof && Instant::now() < end {
        c.step();
    }
    assert!(c.eof, "the connection closes after its streams");
    h.join();
}

#[test]
fn h2_and_http1_share_the_port_and_limits_apply() {
    let limits = Limits { max_body: 1000, ..Limits::default() };
    let h = serve_with(limits, blocking(|r| Response::text(format!("{}", r.body().len()))));
    assert_eq!(get(&h, "/").text(), "0");
    let mut c = H2Client::prior(&h);
    let id = c.request("POST", "/", &[1u8; 2000]);
    assert_eq!(c.wait(id).status, 413);
}

/// Sends `bytes` as the first bytes of a connection and reads until the server closes.
fn first_bytes_reply(h: &simoom::ServerHandle, bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut s = connect(h);
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(bytes).unwrap();
    let mut out = Vec::new();
    let mut tmp = [0u8; 4096];
    let closed = loop {
        match s.read(&mut tmp) {
            Ok(0) => break true,
            Ok(n) => out.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset || e.kind() == std::io::ErrorKind::ConnectionAborted => break true,
            Err(_) => break false,
        }
    };
    (out, closed)
}

/// Splits `b` into HTTP/2 frames `(type, payload)`; `None` if it is not a whole number of frames.
fn frames(mut b: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut v = Vec::new();
    while !b.is_empty() {
        if b.len() < 9 {
            return None;
        }
        let len = (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]);
        if b.len() < 9 + len {
            return None;
        }
        v.push((b[3], b[9..9 + len].to_vec()));
        b = &b[9 + len..];
    }
    Some(v)
}

/// h2spec http2/3.5/2: an invalid connection preface on the shared HTTP/1.1 + h2c port is a
/// connection error of type PROTOCOL_ERROR (RFC 9113 §3.4): whole HTTP/2 frames ending in
/// GOAWAY(PROTOCOL_ERROR), then a close, never an HTTP/1 response.
#[test]
fn invalid_preface_gets_goaway_protocol_error_and_close() {
    let h = serve(|_req: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.body("ok") });
    let cases: [&[u8]; 4] = [
        b"INVALID CONNECTION PREFACE\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\rX",
        b"PRI * HTTP/2.0\n\nSM\n\n",
    ];
    for c in cases {
        let (out, closed) = first_bytes_reply(&h, c);
        let name = String::from_utf8_lossy(c);
        assert!(closed, "{name:?}: connection not closed");
        assert!(!out.starts_with(b"HTTP/1"), "{name:?}: answered with HTTP/1: {:?}", String::from_utf8_lossy(&out));
        let f = frames(&out).unwrap_or_else(|| panic!("{name:?}: not whole HTTP/2 frames: {out:?}"));
        let (ty, payload) = f.last().unwrap_or_else(|| panic!("{name:?}: no frames"));
        assert_eq!(*ty, 7, "{name:?}: last frame is not GOAWAY: {f:?}");
        assert_eq!(&payload[4..8], &[0, 0, 0, 1], "{name:?}: GOAWAY error is not PROTOCOL_ERROR");
    }
    // HTTP/1.1 on the same port is unaffected, including a bad HTTP/1 version (400) and a
    // pipelined second request that happens to look like a broken preface.
    let (out, _) = first_bytes_reply(&h, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(out.starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&out));
    // Damaged versions (found by the HTTP Garden's mutator) are still HTTP/1 errors.
    for bad in [&b"GET / HTTP/1.x\r\nHost: x\r\n\r\n"[..], b"GET / HT\xbcP/1.1\r\nHost: x\r\n\r\n", b"GET / XTTP/1.1\r\nHost: x\r\n\r\n", b"GET /\r\n\r\n"] {
        let (out, _) = first_bytes_reply(&h, bad);
        assert!(out.starts_with(b"HTTP/1.1 400"), "{:?}: {:?}", String::from_utf8_lossy(bad), String::from_utf8_lossy(&out));
    }
    let (out, _) = first_bytes_reply(&h, b"GET / HTTP/1.1\r\nHost: x\r\n\r\nINVALID CONNECTION PREFACE\r\n\r\n");
    assert!(out.starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&out));
    assert!(out.windows(12).any(|w| w == b"HTTP/1.1 400"), "{:?}", String::from_utf8_lossy(&out));
    h.stop(Duration::from_secs(1));
}
