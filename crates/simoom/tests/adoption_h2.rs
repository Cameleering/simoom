//! The Cameleer adoption items on HTTP/2 (h2c prior knowledge, docs/BUGS.md U1, U2, U4, U5):
//! response trailers (gRPC's `grpc-status`), deferred-reply timeout, cancellation by
//! RST_STREAM, the completion hook and connection info, with the simoom-h2 client codec.

#![cfg(feature = "http2")]

mod common;

use simoom::{Completion, Limits, Outcome, Reply, Request, Response, Server, ServerHandle, Version};
use simoom_h2::{Config, Connection, ErrorCode, Event};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default, Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
    done: bool,
    reset: Option<ErrorCode>,
}

struct H2 {
    s: TcpStream,
    c: Connection,
    resps: HashMap<u32, Resp>,
    inbuf: Vec<u8>,
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl H2 {
    fn connect(h: &ServerHandle) -> H2 {
        let s = TcpStream::connect(h.local_addr()).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        s.set_nodelay(true).unwrap();
        H2 { s, c: Connection::client(Config { window_autotune: false, ..Config::default() }), resps: HashMap::new(), inbuf: Vec::new() }
    }

    fn flush(&mut self) {
        let out = self.c.output().to_vec();
        self.c.advance_output(out.len());
        if !out.is_empty() {
            self.s.write_all(&out).unwrap();
        }
    }

    fn step(&mut self) {
        self.flush();
        let mut tmp = [0u8; 65536];
        match self.s.read(&mut tmp) {
            Ok(0) => panic!("server closed"),
            Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
            Err(_) => return,
        }
        let buf = std::mem::take(&mut self.inbuf);
        let n = buf.len();
        let resps = &mut self.resps;
        let mut rel: Vec<(u32, usize)> = Vec::new();
        let mut off = 0;
        while off < n {
            let out = self.c.output().to_vec();
            self.c.advance_output(out.len());
            if !out.is_empty() {
                self.s.write_all(&out).unwrap();
            }
            let before = off;
            off += self.c.recv(&buf[off..n], 0, &mut |ev| match ev {
                Event::Headers { stream, headers, end_stream } => {
                    let r = resps.entry(stream).or_default();
                    r.status = headers.status().unwrap_or(0);
                    r.headers = headers.iter().map(|(n, v)| (s(n), s(v))).collect();
                    r.done |= end_stream;
                }
                Event::Data { stream, data, end_stream } => {
                    let r = resps.entry(stream).or_default();
                    r.body.extend_from_slice(data);
                    r.done |= end_stream;
                    rel.push((stream, data.len()));
                }
                Event::Trailers { stream, trailers } => {
                    let r = resps.entry(stream).or_default();
                    r.trailers = trailers.iter().map(|(n, v)| (s(n), s(v))).collect();
                    r.done = true;
                }
                Event::Reset { stream, code, .. } => {
                    let r = resps.entry(stream).or_default();
                    r.reset = Some(code);
                    r.done = true;
                }
                _ => {}
            });
            if off == before {
                break; // a partial frame: keep it for the next read
            }
        }
        self.inbuf = buf[off..].to_vec();
        // credit what we read so large bodies keep flowing
        for (id, n) in rel {
            self.c.release(id, n);
        }
        self.flush();
    }

    fn get(&mut self, path: &str) -> u32 {
        let id = self.c.send_request(b"GET", b"http", b"t", path.as_bytes(), &[(b"te", b"trailers")], true).unwrap();
        self.flush();
        id
    }

    fn wait(&mut self, id: u32) -> Resp {
        let end = Instant::now() + Duration::from_secs(10);
        while !self.resps.get(&id).is_some_and(|r| r.done) {
            assert!(Instant::now() < end, "timeout on stream {id}: {:?}", self.resps.get(&id));
            self.step();
        }
        self.resps.remove(&id).unwrap()
    }
}

fn start(limits: Limits, hook: Option<Arc<Mutex<Vec<Completion>>>>, svc: impl simoom::Service) -> ServerHandle {
    let mut b = Server::builder().listen("127.0.0.1:0").threads(1).limits(limits).service(svc);
    if let Some(log) = hook {
        b = b.on_complete(move |c: &Completion| log.lock().unwrap().push(c.clone()));
    }
    b.start().unwrap()
}

fn grpc(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    match req.path() {
        b"/now" => reply.header("content-type", "application/grpc").trailer("grpc-status", "0").trailer("grpc-message", "fine").body_static(b"\0\0\0\0\x02hi"),
        b"/big" => reply.trailer("grpc-status", "0").body(vec![b'b'; 300_000]),
        b"/empty" => reply.trailer("grpc-status", "5").empty(),
        b"/later" => {
            let r = reply.defer();
            std::thread::spawn(move || {
                r.send(Response::new(200).body("deferred").trailer("grpc-status", "0"));
            });
            Outcome::Deferred
        }
        b"/stream" => {
            let mut sink = reply.stream();
            std::thread::spawn(move || {
                for _ in 0..4 {
                    sink.write(&[b's'; 50_000]).unwrap();
                }
                sink.finish_with_trailers(&[("grpc-status", "13"), ("grpc-message", "late")]);
            });
            Outcome::Done
        }
        b"/info" => {
            let t = format!("{} {} {:?}", req.listener(), req.local_addr().unwrap(), req.version());
            reply.body(t)
        }
        _ => reply.status(404).empty(),
    }
}

fn tr(r: &Resp, name: &str) -> Option<String> {
    r.trailers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

#[test]
fn h2_response_trailers() {
    let h = start(Limits::default(), None, grpc);
    let mut c = H2::connect(&h);
    let a = c.get("/now");
    let b = c.get("/big");
    let e = c.get("/empty");
    let l = c.get("/later");
    let st = c.get("/stream");
    let r = c.wait(a);
    assert_eq!((r.status, r.body.as_slice()), (200, &b"\0\0\0\0\x02hi"[..]));
    assert_eq!((tr(&r, "grpc-status").as_deref(), tr(&r, "grpc-message").as_deref()), (Some("0"), Some("fine")));
    let r = c.wait(b);
    assert_eq!((r.body.len(), tr(&r, "grpc-status").as_deref()), (300_000, Some("0")), "{:?}", r.reset);
    let r = c.wait(e);
    assert_eq!((r.status, r.body.len(), tr(&r, "grpc-status").as_deref()), (200, 0, Some("5")));
    let r = c.wait(l);
    assert_eq!((r.body.as_slice(), tr(&r, "grpc-status").as_deref()), (&b"deferred"[..], Some("0")));
    let r = c.wait(st);
    assert_eq!((r.body.len(), tr(&r, "grpc-status").as_deref(), tr(&r, "grpc-message").as_deref()), (200_000, Some("13"), Some("late")));
    assert!(r.reset.is_none());
}

#[test]
fn h2_connection_info() {
    let h = start(Limits::default(), None, grpc);
    let mut c = H2::connect(&h);
    let id = c.get("/info");
    let r = c.wait(id);
    assert_eq!(s(&r.body), format!("0 {} H2", h.local_addr()));
}

#[test]
fn h2_deferred_timeout_and_cancel_by_reset() {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let limits = Limits { defer_timeout: Some(Duration::from_millis(200)), ..Limits::default() };
    let log = Arc::new(Mutex::new(Vec::new()));
    let h = start(limits, Some(log.clone()), move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/fast" {
            return reply.body_static(b"fast");
        }
        tx.lock().unwrap().send(reply.defer()).unwrap();
        Outcome::Deferred
    });
    let mut c = H2::connect(&h);
    // timed out: a 504, the responder cancelled
    let t0 = Instant::now();
    let a = c.get("/slow");
    let r = c.wait(a);
    assert_eq!(r.status, 504);
    assert!(t0.elapsed() >= Duration::from_millis(190));
    let first = rx.recv().unwrap();
    assert!(first.is_cancelled());
    // reset by the client: cancelled at once
    let b = c.get("/slow");
    let second = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (ftx, frx) = mpsc::channel();
    second.on_cancel(move || ftx.send(()).unwrap());
    c.c.reset(b, ErrorCode::CANCEL);
    c.flush();
    frx.recv_timeout(Duration::from_secs(5)).expect("reset cancels the deferred reply");
    // the connection carries on, and other streams are untouched
    let f = c.get("/fast");
    assert_eq!(c.wait(f).body, b"fast");
    drop((first, second));
    assert!(common::wait_for(5, || log.lock().unwrap().len() >= 3));
    let l = log.lock().unwrap();
    assert!(l.iter().all(|c| c.version == Version::H2), "{l:?}");
    assert!(l.iter().any(|c| c.status == 504 && !c.aborted), "{l:?}");
    assert!(l.iter().any(|c| c.aborted), "{l:?}");
    assert!(l.iter().any(|c| c.status == 200 && c.bytes_out == 4), "{l:?}");
}
