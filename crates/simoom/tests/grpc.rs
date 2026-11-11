//! gRPC over HTTP/2 through the facade (C9): what `cameleer-grpc` needs from HTTP/2, checked
//! with simoom-h2's client role playing a gRPC client. Unary and server-streaming calls with
//! `grpc-status` trailers, a trailers-only error, a client-streaming call read through a
//! `BodySource`, `te: trailers` and `grpc-timeout` passed to the service, per-message compression
//! (feature `compression`), cancellation by RST_STREAM, and PING keepalive.

#![cfg(feature = "http2")]

mod common;

use common::*;
use simoom::{Limits, Reply, Request, Response};
use simoom_h2::{Config, Connection, ErrorCode, Event};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// gRPC message framing: compressed flag, 4-byte big-endian length, payload.
fn frame(flag: u8, msg: &[u8]) -> Vec<u8> {
    let mut v = vec![flag];
    v.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    v.extend_from_slice(msg);
    v
}

/// Splits a body into (flag, message) pairs; panics on a partial message.
fn unframe(mut b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let len = u32::from_be_bytes(b[1..5].try_into().unwrap()) as usize;
        out.push((b[0], b[5..5 + len].to_vec()));
        b = &b[5 + len..];
    }
    out
}

fn grpc_service(req: &mut Request<'_>, reply: Reply<'_>) -> simoom::Outcome {
    let is_grpc = req.header("content-type").is_some_and(|c| c.starts_with(b"application/grpc"));
    if req.method() != b"POST" || !is_grpc {
        return reply.status(415).body("gRPC only");
    }
    let te = req.header("te").map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
    let timeout = req.header("grpc-timeout").map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
    match req.path() {
        b"/pkg.Greeter/SayHello" => {
            let msgs = unframe(req.body());
            let name = String::from_utf8_lossy(&msgs[0].1).into_owned();
            reply
                .header("content-type", "application/grpc")
                .header("x-seen-te", te)
                .header("x-seen-timeout", timeout)
                .trailer("grpc-status", "0")
                .trailer("grpc-message", "OK")
                .body(frame(0, format!("hello {name}").as_bytes()))
        }
        b"/pkg.Greeter/StreamHellos" => {
            let mut sink = reply.header("content-type", "application/grpc").stream();
            std::thread::spawn(move || {
                for i in 0..5 {
                    if sink.write(&frame(0, format!("hello #{i}").as_bytes())).is_err() {
                        return;
                    }
                }
                sink.finish_with_trailers(&[("grpc-status", "0"), ("x-count", "5")]);
            });
            simoom::Outcome::Deferred
        }
        b"/pkg.Greeter/Sum" => {
            // client streaming: the request body is read as it arrives, on the offload pool
            reply.blocking(req, |mut r| {
                let mut body = Vec::new();
                match r.take_body() {
                    Some(mut src) => {
                        src.read_to_end(&mut body).unwrap();
                    }
                    None => body.extend_from_slice(r.body()),
                }
                let sum: u64 = unframe(&body).iter().map(|(_, m)| String::from_utf8_lossy(m).parse::<u64>().unwrap()).sum();
                Response::new(200).header("content-type", "application/grpc").trailer("grpc-status", "0").body(frame(0, sum.to_string().as_bytes()))
            })
        }
        #[cfg(feature = "compression")]
        b"/pkg.Greeter/Gzip" => {
            // per-message compression: flag 1 with grpc-encoding gzip, both ways
            let enc = req.header("grpc-encoding").map(<[u8]>::to_vec);
            let (flag, msg) = unframe(req.body()).remove(0);
            assert_eq!((flag, enc.as_deref()), (1, Some(&b"gzip"[..])));
            let plain = simoom_compress::decompress(&msg, simoom_compress::Format::Gzip, 1 << 20).unwrap();
            let answer = simoom_compress::compress(&plain.repeat(2), simoom_compress::Format::Gzip, 6);
            reply.header("content-type", "application/grpc").header("grpc-encoding", "gzip").trailer("grpc-status", "0").body(frame(1, &answer))
        }
        b"/pkg.Greeter/Slow" => {
            // only the cancellation test's call reports to CANCELLED
            let mark = req.header("x-mark").is_some();
            let r = reply.header("content-type", "application/grpc").defer();
            std::thread::spawn(move || {
                let t0 = Instant::now();
                while !r.is_cancelled() && t0.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if mark {
                    CANCELLED.store(r.is_cancelled(), std::sync::atomic::Ordering::SeqCst);
                }
                r.send(Response::new(200));
            });
            simoom::Outcome::Deferred
        }
        // unknown method: a trailers-only response (one HEADERS frame with END_STREAM)
        _ => reply.header("content-type", "application/grpc").header("grpc-status", "12").header("grpc-message", "unknown method").empty(),
    }
}

static CANCELLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Default, Debug)]
struct Call {
    headers: Vec<(String, String)>,
    header_end: bool,
    data: Vec<u8>,
    trailers: Vec<(String, String)>,
    end: bool,
    reset: bool,
}

impl Call {
    fn h(&self, n: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str())
    }
    fn t(&self, n: &str) -> Option<&str> {
        self.trailers.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str())
    }
}

struct GrpcClient {
    s: TcpStream,
    c: Connection,
    inbuf: Vec<u8>,
    calls: HashMap<u32, Call>,
    t0: Instant,
}

fn own(h: &simoom_h2::Headers) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = h.iter().map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), String::from_utf8_lossy(v).into_owned())).collect();
    if let Some(s) = h.status() {
        v.insert(0, (":status".into(), s.to_string()));
    }
    v
}

impl GrpcClient {
    fn new(h: &simoom::ServerHandle) -> GrpcClient {
        let s = connect(h);
        s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        GrpcClient { s, c: Connection::client(Config::default()), inbuf: Vec::new(), calls: HashMap::new(), t0: Instant::now() }
    }

    fn start(&mut self, method: &str, extra: &[(&[u8], &[u8])], body: &[u8], end: bool) -> u32 {
        let mut fields: Vec<(&[u8], &[u8])> = vec![(b"content-type", b"application/grpc"), (b"te", b"trailers"), (b"user-agent", b"grpc-test/1.0")];
        fields.extend_from_slice(extra);
        let id = self.c.send_request(b"POST", b"http", b"localhost", method.as_bytes(), &fields, body.is_empty() && end).unwrap();
        if !body.is_empty() {
            assert_eq!(self.c.send_data(id, body, end).unwrap(), body.len());
        }
        id
    }

    fn turn(&mut self) {
        let out = self.c.output().to_vec();
        self.c.advance_output(out.len());
        if !out.is_empty() {
            self.s.write_all(&out).unwrap();
        }
        let mut buf = [0u8; 65536];
        if let Ok(n) = self.s.read(&mut buf) {
            assert!(n > 0, "server closed the connection");
            self.inbuf.extend_from_slice(&buf[..n]);
        }
        let now = self.t0.elapsed().as_millis() as u64;
        let calls = &mut self.calls;
        let mut release = Vec::new();
        let used = self.c.recv(&self.inbuf, now, &mut |e| match e {
            Event::Headers { stream, headers, end_stream } => {
                let c = calls.entry(stream).or_default();
                c.headers = own(headers);
                c.header_end = end_stream;
                c.end |= end_stream;
            }
            Event::Data { stream, data, end_stream } => {
                let c = calls.entry(stream).or_default();
                c.data.extend_from_slice(data);
                c.end |= end_stream;
                release.push((stream, data.len()));
            }
            Event::Trailers { stream, trailers } => {
                let c = calls.entry(stream).or_default();
                c.trailers = own(trailers);
                c.end = true;
            }
            Event::Reset { stream, .. } => calls.entry(stream).or_default().reset = true,
            _ => {}
        });
        self.inbuf.drain(..used);
        for (s, n) in release {
            self.c.release(s, n);
        }
    }

    fn wait(&mut self, id: u32) -> &Call {
        let end = Instant::now() + Duration::from_secs(10);
        while !self.calls.get(&id).is_some_and(|c| c.end || c.reset) {
            assert!(Instant::now() < end, "call {id} did not finish");
            self.turn();
        }
        &self.calls[&id]
    }
}

#[test]
fn unary_streaming_and_trailers_only() {
    let h = serve(grpc_service);
    let mut g = GrpcClient::new(&h);
    // unary: HEADERS, DATA (one framed message), trailing HEADERS with grpc-status
    let id = g.start("/pkg.Greeter/SayHello", &[(b"grpc-timeout", b"250m")], &frame(0, b"world"), true);
    let c = g.wait(id);
    assert_eq!(c.h(":status"), Some("200"));
    assert_eq!(c.h("content-type"), Some("application/grpc"));
    assert_eq!(c.h("x-seen-te"), Some("trailers"));
    assert_eq!(c.h("x-seen-timeout"), Some("250m"));
    assert!(!c.header_end);
    assert_eq!(unframe(&c.data), [(0, b"hello world".to_vec())]);
    assert_eq!((c.t("grpc-status"), c.t("grpc-message")), (Some("0"), Some("OK")));
    // server streaming: five messages, then trailers; no content-length on a stream
    let id = g.start("/pkg.Greeter/StreamHellos", &[], &frame(0, b""), true);
    let c = g.wait(id);
    assert_eq!(c.h(":status"), Some("200"));
    assert_eq!(c.h("content-length"), None);
    let msgs: Vec<String> = unframe(&c.data).into_iter().map(|(_, m)| String::from_utf8(m).unwrap()).collect();
    assert_eq!(msgs, ["hello #0", "hello #1", "hello #2", "hello #3", "hello #4"]);
    assert_eq!((c.t("grpc-status"), c.t("x-count")), (Some("0"), Some("5")));
    // trailers-only: grpc-status in the one and only HEADERS frame
    let id = g.start("/pkg.Greeter/Nope", &[], &frame(0, b""), true);
    let c = g.wait(id);
    assert!(c.header_end);
    assert_eq!((c.h(":status"), c.h("grpc-status"), c.h("grpc-message")), (Some("200"), Some("12"), Some("unknown method")));
    assert!(c.data.is_empty() && c.trailers.is_empty());
    // the same connection carries many concurrent calls
    let ids: Vec<u32> = (0..20).map(|i| g.start("/pkg.Greeter/SayHello", &[], &frame(0, format!("n{i}").as_bytes()), true)).collect();
    for (i, id) in ids.into_iter().enumerate() {
        let c = g.wait(id);
        assert_eq!(unframe(&c.data)[0].1, format!("hello n{i}").into_bytes());
        assert_eq!(c.t("grpc-status"), Some("0"));
    }
    h.stop(Duration::from_secs(1));
}

#[test]
fn client_streaming_with_flow_control() {
    // A small body buffer makes the request body stream through a BodySource with
    // backpressure; the client sends more than the initial windows while the call runs.
    let h = serve_with(Limits { body_buffer: 1024, ..Limits::default() }, grpc_service);
    let mut g = GrpcClient::new(&h);
    let id = g.start("/pkg.Greeter/Sum", &[], &[], false);
    let mut want = 0u64;
    let mut pending = Vec::new();
    for i in 0..20_000u64 {
        want += i;
        pending.extend_from_slice(&frame(0, i.to_string().as_bytes()));
    }
    // ~200 KB of messages: send as the windows allow
    let mut off = 0;
    let end = Instant::now() + Duration::from_secs(20);
    while off < pending.len() {
        let n = g.c.send_data(id, &pending[off..(off + 16 * 1024).min(pending.len())], false).unwrap();
        off += n;
        g.turn();
        assert!(Instant::now() < end);
    }
    g.c.send_data(id, b"", true).unwrap();
    let c = g.wait(id);
    assert_eq!(unframe(&c.data), [(0, want.to_string().into_bytes())]);
    assert_eq!(c.t("grpc-status"), Some("0"));
    h.stop(Duration::from_secs(1));
}

#[test]
fn cancellation_by_rst_stream_reaches_the_responder() {
    let h = serve(grpc_service);
    let mut g = GrpcClient::new(&h);
    let id = g.start("/pkg.Greeter/Slow", &[(b"x-mark", b"1")], &frame(0, b""), true);
    for _ in 0..5 {
        g.turn();
    }
    g.c.reset(id, ErrorCode::CANCEL);
    g.turn();
    assert!(wait_for(5, || CANCELLED.load(std::sync::atomic::Ordering::SeqCst)));
    h.stop(Duration::from_secs(1));
}

#[cfg(feature = "compression")]
#[test]
fn per_message_compression() {
    let h = serve(grpc_service);
    let mut g = GrpcClient::new(&h);
    let msg = simoom_compress::compress(b"compress me compress me", simoom_compress::Format::Gzip, 6);
    let id = g.start("/pkg.Greeter/Gzip", &[(b"grpc-encoding", b"gzip"), (b"grpc-accept-encoding", b"gzip")], &frame(1, &msg), true);
    let c = g.wait(id);
    assert_eq!(c.h("grpc-encoding"), Some("gzip"));
    let (flag, m) = unframe(&c.data).remove(0);
    assert_eq!(flag, 1);
    assert_eq!(simoom_compress::decompress(&m, simoom_compress::Format::Gzip, 1 << 20).unwrap(), b"compress me compress me".repeat(2));
    assert_eq!(c.t("grpc-status"), Some("0"));
    h.stop(Duration::from_secs(1));
}

#[cfg(feature = "h2-keepalive")]
#[test]
fn ping_keepalive_closes_dead_connections_and_keeps_live_ones() {
    let limits = Limits { h2_keepalive: Some(Duration::from_millis(100)), h2_keepalive_timeout: Duration::from_millis(200), ..Limits::default() };
    let h = simoom::Server::builder().listen("127.0.0.1:0").threads(1).limits(limits).service(grpc_service).start().unwrap();
    // A live client (its engine answers PINGs) with a long call open stays connected well past
    // several keepalive rounds.
    let mut g = GrpcClient::new(&h);
    let id = g.start("/pkg.Greeter/Slow", &[], &frame(0, b""), true);
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(800) {
        g.turn();
    }
    assert!(!g.calls.get(&id).is_some_and(|c| c.reset), "the live call survived");
    g.c.reset(id, ErrorCode::CANCEL);
    g.turn();
    // A dead client: preface and SETTINGS, then silence. The server PINGs after 100 ms, waits
    // 200 ms, then closes the connection (GOAWAY, then EOF).
    let mut s = TcpStream::connect(h.local_addr()).unwrap();
    let mut c = Connection::client(Config::default());
    let id = c.send_request(b"POST", b"http", b"localhost", b"/pkg.Greeter/Slow", &[(b"content-type", b"application/grpc")], true).unwrap();
    let _ = id;
    s.write_all(c.output()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let t0 = Instant::now();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(250) && took < Duration::from_millis(2500), "closed after {took:?}");
    // the server sent a PING and a GOAWAY
    let frames = simoom_h2::frame::split_frames(&got).into_iter().map(|(h, _)| h.kind).collect::<Vec<_>>();
    assert!(frames.contains(&simoom_h2::frame::kind::PING), "{frames:?}");
    assert!(frames.contains(&simoom_h2::frame::kind::GOAWAY), "{frames:?}");
    h.stop(Duration::from_secs(1));
}
