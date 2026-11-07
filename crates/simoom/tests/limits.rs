//! Limits audit (plan §7.1): every limit of [`simoom::Limits`] exists, is enforced through the
//! facade and is tested. Limits with tests elsewhere: request line, head, header count, body,
//! body buffer, head deadline, keep-alive, body rate, write deadline, requests per connection,
//! the stall watchdog and the offload queue (`http1.rs`); TLS handshake deadline
//! (`tls_hardening.rs`). This file covers the rest.

mod common;

use common::*;
use simoom::{Limits, Outcome, Reply, Request, Server};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn hello(_: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    reply.body_static(b"hello")
}

/// True when the server closed `s` without answering (read gives EOF or a reset).
fn refused(s: &mut TcpStream) -> bool {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
    let mut b = [0u8; 64];
    matches!(s.read(&mut b), Ok(0) | Err(_))
}

fn answers(s: &mut TcpStream) -> bool {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    if s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").is_err() {
        return false;
    }
    let mut b = [0u8; 256];
    matches!(s.read(&mut b), Ok(n) if n > 0 && b.starts_with(b"HTTP/1.1 200"))
}

/// Loop statistics are published every few milliseconds; waits for `f` to hold.
fn eventually(f: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn defaults_match_plan_7_1() {
    let l = Limits::default();
    assert_eq!(l.max_request_line, 8 * 1024);
    assert_eq!(l.max_head, 16 * 1024);
    assert_eq!(l.max_headers, 100);
    assert_eq!(l.max_header_line, 8 * 1024);
    assert_eq!(l.max_body, 10 * 1024 * 1024);
    assert_eq!(l.head_timeout, Duration::from_secs(10));
    assert_eq!(l.keep_alive_timeout, Duration::from_secs(15));
    assert_eq!(l.min_body_rate, 1024);
    assert_eq!(l.body_rate_grace, Duration::from_secs(5));
    assert_eq!(l.write_timeout, Duration::from_secs(30));
    assert_eq!(l.max_requests_per_connection, 0);
    assert_eq!(l.max_concurrent_streams, 100);
    assert_eq!(l.max_header_list, 16 * 1024);
    assert_eq!(l.header_table_size, 4096);
    assert_eq!(l.max_connections_per_ip, 0, "per-IP cap is optional (plan §7.1), off by default");
    #[cfg(feature = "http2")]
    {
        let b = simoom_h2::Budgets::default();
        assert_eq!((b.window_ms, b.rst_received, b.rst_sent), (10_000, 200, 200), "RST_STREAM 200 per 10 s, received and sent");
    }
}

#[test]
fn header_line_limit_gives_431() {
    let h = serve_with(Limits { max_header_line: 100, ..Limits::default() }, hello);
    let mut c = Client::new(&h);
    c.send(format!("GET / HTTP/1.1\r\nHost: t\r\nX-Long: {}\r\n\r\n", "a".repeat(200)).as_bytes());
    assert_eq!(c.read().status, 431);
    // Just under the limit is fine.
    let mut c = Client::new(&h);
    c.send(format!("GET / HTTP/1.1\r\nHost: t\r\nX-Long: {}\r\n\r\n", "a".repeat(60)).as_bytes());
    assert_eq!(c.read().status, 200);
    assert!(h.stats().too_large >= 1);
}

#[test]
fn total_connection_cap() {
    let h = Server::builder().listen("127.0.0.1:0").threads(2).limits(Limits { max_connections: 2, ..Limits::default() }).service(hello).start().unwrap();
    let mut a = connect(&h);
    let mut b = connect(&h);
    assert!(answers(&mut a) && answers(&mut b));
    let mut c = connect(&h);
    assert!(refused(&mut c), "a third connection over max_connections must be closed");
    assert!(eventually(|| h.stats().rejected >= 1), "rejected counter");
    drop(a);
    // The slot comes back once a connection closes.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut d = connect(&h);
        if answers(&mut d) {
            break;
        }
        assert!(Instant::now() < deadline, "slot never released");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn per_loop_connection_cap() {
    let h = Server::builder().listen("127.0.0.1:0").threads(1).limits(Limits { max_connections_per_loop: 1, ..Limits::default() }).service(hello).start().unwrap();
    let mut a = connect(&h);
    assert!(answers(&mut a));
    let mut b = connect(&h);
    assert!(refused(&mut b), "a second connection on a one-connection loop must be closed");
    assert!(eventually(|| h.stats().rejected >= 1), "rejected counter");
}

#[test]
fn per_ip_connection_cap() {
    let h = Server::builder().listen("127.0.0.1:0").threads(2).limits(Limits { max_connections_per_ip: 2, ..Limits::default() }).service(hello).start().unwrap();
    let mut a = connect(&h);
    let mut b = connect(&h);
    assert!(answers(&mut a) && answers(&mut b));
    let mut c = connect(&h);
    assert!(refused(&mut c), "a third connection from one IP must be closed");
    assert!(eventually(|| h.stats().rejected >= 1), "rejected counter");
    drop(a);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut d = connect(&h);
        if answers(&mut d) {
            break;
        }
        assert!(Instant::now() < deadline, "per-IP slot never released");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(answers(&mut b));
}

// ------------------------------------------------------------------ HTTP/2

#[cfg(feature = "http2")]
mod h2 {
    use super::*;

    const SETTINGS: u8 = 4;
    const HEADERS: u8 = 1;
    const RST_STREAM: u8 = 3;
    const GOAWAY: u8 = 7;

    fn frame(kind: u8, flags: u8, stream: u32, p: &[u8]) -> Vec<u8> {
        let mut b = (p.len() as u32).to_be_bytes()[1..].to_vec();
        b.push(kind);
        b.push(flags);
        b.extend_from_slice(&stream.to_be_bytes());
        b.extend_from_slice(p);
        b
    }

    fn lit(b: &mut Vec<u8>, n: &str, v: &str) {
        b.push(0);
        for s in [n.as_bytes(), v.as_bytes()] {
            if s.len() < 127 {
                b.push(s.len() as u8);
            } else {
                b.push(127);
                let mut x = s.len() - 127;
                while x >= 128 {
                    b.push((x % 128) as u8 | 0x80);
                    x /= 128;
                }
                b.push(x as u8);
            }
            b.extend_from_slice(s);
        }
    }

    fn req(extra: &[(&str, &str)]) -> Vec<u8> {
        let mut b = Vec::new();
        for (n, v) in [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "t")].iter().chain(extra) {
            lit(&mut b, n, v);
        }
        b
    }

    struct H2 {
        s: TcpStream,
        buf: Vec<u8>,
        settings: Vec<(u16, u32)>,
    }

    impl H2 {
        fn open(h: &simoom::ServerHandle) -> H2 {
            let mut s = connect(h);
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
            s.write_all(&frame(SETTINGS, 0, 0, &[])).unwrap();
            let mut c = H2 { s, buf: Vec::new(), settings: Vec::new() };
            let f = c.next().expect("server SETTINGS");
            assert_eq!(f.0, SETTINGS);
            for x in f.3.chunks_exact(6) {
                c.settings.push((u16::from_be_bytes([x[0], x[1]]), u32::from_be_bytes(x[2..6].try_into().unwrap())));
            }
            c.s.write_all(&frame(SETTINGS, 1, 0, &[])).unwrap();
            c
        }
        fn setting(&self, k: u16) -> Option<u32> {
            self.settings.iter().find(|x| x.0 == k).map(|x| x.1)
        }
        fn send(&mut self, b: &[u8]) {
            let _ = self.s.write_all(b);
        }
        /// (kind, flags, stream, payload), None at EOF.
        fn next(&mut self) -> Option<(u8, u8, u32, Vec<u8>)> {
            loop {
                if self.buf.len() >= 9 {
                    let len = u32::from_be_bytes([0, self.buf[0], self.buf[1], self.buf[2]]) as usize;
                    if self.buf.len() >= 9 + len {
                        let f = (self.buf[3], self.buf[4], u32::from_be_bytes(self.buf[5..9].try_into().unwrap()), self.buf[9..9 + len].to_vec());
                        self.buf.drain(..9 + len);
                        return Some(f);
                    }
                }
                let mut t = [0u8; 16384];
                match self.s.read(&mut t) {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => self.buf.extend_from_slice(&t[..n]),
                }
            }
        }
        /// The first RST_STREAM on `stream` or GOAWAY: (kind, code).
        fn error_on(&mut self, stream: u32) -> Option<(u8, u32)> {
            while let Some((k, _, s, p)) = self.next() {
                if k == GOAWAY {
                    return Some((k, u32::from_be_bytes(p[4..8].try_into().unwrap())));
                }
                if k == RST_STREAM && s == stream {
                    return Some((k, u32::from_be_bytes(p[..4].try_into().unwrap())));
                }
            }
            None
        }
        /// The `:status` of the response on `stream` (decoding only static index 8-14, which
        /// is how simoom encodes the common codes, or a literal).
        fn status_on(&mut self, stream: u32) -> Option<u16> {
            while let Some((k, _, s, p)) = self.next() {
                if k == HEADERS && s == stream {
                    return Some(match p[0] {
                        0x88 => 200,
                        0x89 => 204,
                        0x8a => 206,
                        0x8b => 304,
                        0x8c => 400,
                        0x8d => 404,
                        0x8e => 500,
                        _ => {
                            // literal with name index 8 (:status): 0x08 or 0x48, then a 3-byte string
                            let v = &p[2..5];
                            std::str::from_utf8(v).ok()?.parse().ok()?
                        }
                    });
                }
                if k == GOAWAY || (k == RST_STREAM && s == stream) {
                    return None;
                }
            }
            None
        }
    }

    #[test]
    fn concurrent_stream_limit_is_advertised_and_enforced() {
        let h = serve_with(Limits { max_concurrent_streams: 3, ..Limits::default() }, hello);
        let mut c = H2::open(&h);
        assert_eq!(c.setting(3), Some(3), "SETTINGS_MAX_CONCURRENT_STREAMS");
        // Four streams whose request bodies stay open: the fourth is refused.
        for s in [1u32, 3, 5, 7] {
            let b = req(&[]);
            c.send(&frame(HEADERS, 4, s, &b));
        }
        let e = c.error_on(7).expect("the fourth stream is refused");
        assert!(e == (RST_STREAM, 7) || e == (RST_STREAM, 1) || e == (GOAWAY, 1), "got {e:?}");
    }

    #[test]
    fn header_list_limit_is_advertised_and_enforced() {
        let h = serve_with(Limits { max_header_list: 1024, ..Limits::default() }, hello);
        let mut c = H2::open(&h);
        assert_eq!(c.setting(6), Some(1024), "SETTINGS_MAX_HEADER_LIST_SIZE");
        // Over the 1024-byte list limit, under the 2048-byte block cap: 431, not GOAWAY.
        let big = "v".repeat(1500);
        let b = req(&[("x-big", big.as_str())]);
        c.send(&frame(HEADERS, 5, 1, &b));
        match c.status_on(1) {
            Some(431) => {}
            other => panic!("expected 431 for an oversized header list, got {other:?}"),
        }
        // The connection survives and serves the next request.
        let b = req(&[]);
        c.send(&frame(HEADERS, 5, 3, &b));
        assert_eq!(c.status_on(3), Some(200));
    }

    #[test]
    fn header_table_size_is_advertised_and_enforced() {
        let h = serve_with(Limits { header_table_size: 256, ..Limits::default() }, hello);
        let mut c = H2::open(&h);
        assert_eq!(c.setting(1), Some(256), "SETTINGS_HEADER_TABLE_SIZE");
        // A dynamic table size update to 4096 exceeds what we allowed: COMPRESSION_ERROR.
        let mut b = vec![0x3f, 0xe1, 0x1f]; // size update 4096 (5-bit prefix: 31 + 4065)
        b.extend_from_slice(&req(&[]));
        c.send(&frame(HEADERS, 5, 1, &b));
        assert_eq!(c.error_on(1), Some((GOAWAY, 9)));
    }

    #[test]
    fn rst_stream_budget_gives_goaway() {
        let h = serve(hello);
        let mut c = H2::open(&h);
        // Rapid Reset: open and cancel streams far beyond 200 per 10 s.
        let mut b = Vec::new();
        for i in 0..400u32 {
            let s = 2 * i + 1;
            b.extend_from_slice(&frame(HEADERS, 4, s, &req(&[])));
            b.extend_from_slice(&frame(RST_STREAM, 0, s, &8u32.to_be_bytes()));
        }
        c.send(&b);
        let mut code = None;
        while let Some((k, _, _, p)) = c.next() {
            if k == GOAWAY {
                code = Some(u32::from_be_bytes(p[4..8].try_into().unwrap()));
                break;
            }
        }
        assert_eq!(code, Some(0xb), "ENHANCE_YOUR_CALM after the RST_STREAM budget");
    }
}

// ------------------------------------------------------------------ streaming and WebSocket

#[test]
fn stream_buffer_bounds_pending_output() {
    // 1 = second write refused with WouldBlock, 2 = accepted (limit not enforced).
    let seen = Arc::new(AtomicU8::new(0));
    let s2 = seen.clone();
    let h = serve_with(Limits { stream_buffer: 1024, ..Limits::default() }, move |_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let mut sink = reply.stream();
        // On the loop thread nothing is written until the handler returns, so the first write
        // fills the buffer and the second must be refused.
        sink.try_write(&[b'a'; 2048]).unwrap();
        let r = sink.try_write(b"more");
        s2.store(if matches!(&r, Err(e) if e.kind() == ErrorKind::WouldBlock) { 1 } else { 2 }, Ordering::SeqCst);
        Outcome::Done
    });
    let r = get(&h, "/");
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 2048);
    assert_eq!(seen.load(Ordering::SeqCst), 1, "try_write beyond stream_buffer must fail with WouldBlock");
}

#[cfg(feature = "websocket")]
#[test]
fn websocket_message_limit_closes_with_1009() {
    use simoom::{WebSocket, WebSocketHandler, WsMessage};
    struct Echo;
    impl WebSocketHandler for Echo {
        fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {
            if let WsMessage::Binary(b) = msg {
                ws.send_binary(b);
            }
        }
    }
    let h = serve_with(Limits { max_ws_message: 100, ..Limits::default() }, |_: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.websocket(Echo) });
    let mut c = Client::new(&h);
    c.send(b"GET / HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    assert_eq!(c.read().status, 101);
    let frame = |op: u8, fin: bool, p: &[u8]| {
        let mask = [7u8, 1, 2, 3];
        let mut v = vec![if fin { 0x80 } else { 0 } | op, 0x80 | p.len() as u8];
        v.extend_from_slice(&mask);
        v.extend(p.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        v
    };
    // 60 + 60 bytes across two fragments: over the 100-byte message limit.
    c.send(&frame(2, false, &[1; 60]));
    c.send(&frame(0, true, &[1; 60]));
    let mut got = Vec::new();
    let mut t = [0u8; 256];
    c.s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    while got.len() < 4 {
        match c.s.read(&mut t) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&t[..n]),
        }
    }
    got.splice(0..0, c.buf.drain(..));
    assert!(got.len() >= 4 && got[0] & 0x0f == 8, "expected a close frame, got {got:?}");
    assert_eq!(u16::from_be_bytes([got[2], got[3]]), 1009, "close code 1009 (message too big)");
}
