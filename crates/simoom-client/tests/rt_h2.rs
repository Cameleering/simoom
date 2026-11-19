//! HTTP/2 on simoom-rt loops (`RtClient` with `version: Http2`): h2c and ALPN, multiplexing and
//! the per-loop pool, concurrency limits and queuing, flow control both ways, GOAWAY and
//! refused streams, resets, cancellation, deadlines, streamed bodies, full-duplex calls,
//! trailers, keepalive and lost connections.

#![cfg(all(feature = "rt", feature = "client-h2", feature = "tls"))]

mod common;

use common::{plain, raw, secure, surl, url};
use simoom_client::rt::{CallHandler, CallOptions, RtCall, RtClient, RtConfig, RtRequest, RtResponse};
use simoom_client::{ErrorKind, Headers, HttpVersion, Result, Version};
use simoom_h2::{Config, Connection, ErrorCode, Event};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn h2cfg() -> RtConfig {
    let mut c = RtConfig { version: HttpVersion::Http2, timeout: Duration::from_secs(20), ..RtConfig::default() };
    c.tls.roots = common::roots();
    c
}

fn send(c: &RtClient, req: RtRequest) -> Result<RtResponse> {
    let (tx, rx) = channel();
    c.send(req, move |r| tx.send(r).unwrap());
    rx.recv_timeout(Duration::from_secs(30)).expect("callback")
}

fn get(c: &RtClient, u: &str) -> Result<RtResponse> {
    send(c, RtRequest::get(u).unwrap())
}

/// A call handler that reports everything on a channel.
#[derive(Debug)]
enum Got {
    Head(u16),
    Data(Vec<u8>),
    Writable,
    End(Result<Headers>),
}

struct Chan(Sender<Got>);

impl CallHandler for Chan {
    fn on_head(&mut self, status: u16, _: &Headers) {
        let _ = self.0.send(Got::Head(status));
    }
    fn on_data(&mut self, data: &[u8]) {
        let _ = self.0.send(Got::Data(data.to_vec()));
    }
    fn on_writable(&mut self) {
        let _ = self.0.send(Got::Writable);
    }
    fn on_end(&mut self, r: Result<Headers>) {
        let _ = self.0.send(Got::End(r));
    }
}

fn call(c: &RtClient, req: RtRequest, opts: CallOptions) -> (RtCall, Receiver<Got>) {
    let (tx, rx) = channel();
    (c.call(req, opts, Chan(tx)), rx)
}

/// Reads a call to its end: (status, body, trailers or error).
fn collect(rx: &Receiver<Got>) -> (u16, Vec<u8>, Result<Headers>) {
    let (mut status, mut body) = (0, Vec::new());
    loop {
        match rx.recv_timeout(Duration::from_secs(30)).expect("call event") {
            Got::Head(s) => status = s,
            Got::Data(d) => body.extend_from_slice(&d),
            Got::Writable => {}
            Got::End(r) => return (status, body, r),
        }
    }
}

// ------------------------------------------------------------------------ a scripted h2 server

/// What the scripted server sees. `Tick` comes every few milliseconds, for delayed answers.
#[derive(Debug)]
enum Ev {
    Headers(u32, String),
    Data(u32, Vec<u8>, bool),
    Trailers(u32, Vec<(String, String)>),
    Reset(u32, ErrorCode),
    Tick,
}

/// Per-connection state handed to the script.
#[derive(Default)]
struct St {
    /// Streams the script holds, with the time they arrived.
    held: Vec<(u32, Instant)>,
    /// Body bytes still to send per stream.
    to_send: HashMap<u32, usize>,
    /// Raw bytes written after the engine's output (frames the engine would not send).
    extra: Vec<u8>,
}

struct Srv {
    addr: SocketAddr,
    conns: Arc<AtomicUsize>,
    resets: Arc<Mutex<Vec<(u32, ErrorCode)>>>,
}

fn srv(cfg: Config, f: impl Fn(&mut Connection, &mut St, Ev) + Send + Sync + 'static) -> Srv {
    let f = Arc::new(f);
    let conns = Arc::new(AtomicUsize::new(0));
    let resets: Arc<Mutex<Vec<(u32, ErrorCode)>>> = Arc::new(Mutex::new(Vec::new()));
    let (c2, r2) = (conns.clone(), resets.clone());
    let r = raw(move |mut s: TcpStream, _| {
        c2.fetch_add(1, Ordering::SeqCst);
        let mut conn = Connection::server(cfg.clone());
        let mut st = St::default();
        let mut buf = vec![0u8; 65536];
        let mut pending: Vec<u8> = Vec::new();
        s.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let start = Instant::now();
        loop {
            let mut evs = Vec::new();
            match s.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => return,
            }
            let now = start.elapsed().as_millis() as u64;
            let used = conn.recv(&pending, now, &mut |ev| match ev {
                Event::Headers { stream, headers, end_stream } => {
                    evs.push(Ev::Headers(stream, String::from_utf8_lossy(headers.path().unwrap_or(b"")).into_owned()));
                    if end_stream {
                        evs.push(Ev::Data(stream, Vec::new(), true));
                    }
                }
                Event::Data { stream, data, end_stream } => evs.push(Ev::Data(stream, data.to_vec(), end_stream)),
                Event::Trailers { stream, trailers } => evs.push(Ev::Trailers(stream, trailers.iter().map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), String::from_utf8_lossy(v).into_owned())).collect())),
                Event::Reset { stream, code, .. } => evs.push(Ev::Reset(stream, code)),
                _ => {}
            });
            pending.drain(..used);
            evs.push(Ev::Tick);
            for ev in evs {
                match &ev {
                    Ev::Data(id, d, _) => conn.release(*id, d.len()),
                    Ev::Reset(id, code) => r2.lock().unwrap().push((*id, *code)),
                    _ => {}
                }
                f(&mut conn, &mut st, ev);
            }
            let mut out = conn.output().to_vec();
            conn.advance_output(out.len());
            out.append(&mut st.extra);
            if !out.is_empty() && s.write_all(&out).is_err() {
                return;
            }
            if conn.wants_close() {
                std::thread::sleep(Duration::from_millis(20));
                return;
            }
        }
    });
    Srv { addr: r.addr, conns, resets }
}

fn ok(conn: &mut Connection, id: u32, body: &[u8]) {
    conn.send_response(id, 200, &[], false).unwrap();
    conn.send_data(id, body, true).unwrap();
    conn.stream_finished(id);
}

/// A GOAWAY frame naming `last` as the last stream processed.
fn goaway(last: u32) -> Vec<u8> {
    let mut f = vec![0, 0, 8, 7, 0, 0, 0, 0, 0];
    f.extend_from_slice(&last.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f
}

// ------------------------------------------------------------------------ tests

#[test]
fn h2c_prior_knowledge_unary_requests_multiplexed_on_one_connection_per_loop() {
    let h = plain();
    let c = RtClient::spawn(2, RtConfig { user_agent: Some("rt-h2/1".into()), ..h2cfg() }).unwrap();
    let r = get(&c, &url(&h, "/echo?x=1")).unwrap();
    assert_eq!((r.status, r.version), (200, Version::Http2));
    let t = String::from_utf8(r.body).unwrap();
    assert!(t.starts_with("H2 GET /echo q=1") && t.contains("ua=rt-h2/1"), "{t}");
    assert_eq!(r.headers.get_all("x-multi").count(), 2);
    // a body in memory, larger than the initial stream window
    let r = send(&c, RtRequest::new("POST", &url(&h, "/upload")).unwrap().body(vec![7u8; 300_000])).unwrap();
    let sum = (0..300_000).fold(0u64, |a, _| a.wrapping_mul(31).wrapping_add(7));
    assert_eq!(String::from_utf8(r.body).unwrap(), format!("300000 {sum}"));
    // 200 at once, from another thread: answers match their requests
    let (tx, rx) = channel();
    for i in 0..200 {
        let tx = tx.clone();
        c.send(RtRequest::get(&url(&h, &format!("/echo?x={i}"))).unwrap(), move |r| tx.send((i, r)).unwrap());
    }
    for _ in 0..200 {
        let (i, r) = rx.recv_timeout(Duration::from_secs(20)).unwrap();
        let body = String::from_utf8(r.unwrap().body).unwrap();
        assert!(body.contains(&format!("q={i} ")), "{body}");
    }
    assert_eq!(c.h2_connections_on(0) + c.h2_connections_on(1), 2, "one multiplexed connection per loop");
    // slow requests overlap on the connections instead of queuing behind each other
    let t = Instant::now();
    let (tx, rx) = channel();
    for _ in 0..16 {
        let tx = tx.clone();
        c.send(RtRequest::get(&url(&h, "/slow?ms=300")).unwrap(), move |r| tx.send(r).unwrap());
    }
    for _ in 0..16 {
        assert_eq!(rx.recv_timeout(Duration::from_secs(20)).unwrap().unwrap().body, b"slow done");
    }
    assert!(t.elapsed() < Duration::from_millis(2000), "{:?}", t.elapsed());
}

#[test]
fn several_connections_per_loop_when_configured() {
    let h = plain();
    let c = RtClient::spawn(1, RtConfig { h2_connections: 4, ..h2cfg() }).unwrap();
    let (tx, rx) = channel();
    for _ in 0..64 {
        let tx = tx.clone();
        c.send(RtRequest::get(&url(&h, "/slow?ms=200")).unwrap(), move |r| tx.send(r).unwrap());
    }
    for _ in 0..64 {
        rx.recv_timeout(Duration::from_secs(20)).unwrap().unwrap();
    }
    assert_eq!(c.h2_connections_on(0), 4);
}

#[test]
fn callbacks_run_on_the_loop_and_resubmit_there() {
    let h = plain();
    let c = RtClient::spawn(2, h2cfg()).unwrap();
    let (tx, rx) = channel();
    let left = Arc::new(AtomicUsize::new(500));
    fn next(c: RtClient, u: String, left: Arc<AtomicUsize>, tx: Sender<Option<String>>) {
        let c2 = c.clone();
        c.send(RtRequest::get(&u).unwrap(), move |r| {
            let name = std::thread::current().name().map(|s| s.to_string());
            if r.is_err() || left.fetch_sub(1, Ordering::SeqCst) == 1 {
                let _ = tx.send(name.filter(|_| r.is_ok()));
                return;
            }
            next(c2, u, left, tx);
        });
    }
    next(c.clone(), url(&h, "/echo"), left.clone(), tx);
    let name = rx.recv_timeout(Duration::from_secs(30)).unwrap().expect("all requests succeeded");
    assert!(name.contains("simoom"), "callback ran on {name}");
    assert_eq!(left.load(Ordering::SeqCst), 0);
}

#[test]
fn https_with_alpn_h2_and_verification_always_on() {
    let h = secure();
    let c = RtClient::spawn(2, h2cfg()).unwrap();
    for _ in 0..3 {
        let r = get(&c, &surl(&h, "/echo")).unwrap();
        assert_eq!(r.version, Version::Http2);
        assert!(String::from_utf8(r.body).unwrap().starts_with("H2 GET /echo"));
        let r = get(&c, &surl(&h, "/big?n=500000")).unwrap();
        assert_eq!(r.body.len(), 500_000);
        assert!(r.body.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
    }
    // the system roots do not trust the test certificate
    let untrusted = RtClient::spawn(1, RtConfig { version: HttpVersion::Http2, ..RtConfig::default() }).unwrap();
    let e = get(&untrusted, &surl(&h, "/echo")).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Tls, "{e}");
}

#[test]
fn a_tls_server_without_h2_in_alpn_is_refused() {
    // a server that ignores ALPN (an HTTP/1.1-only server): no protocol is selected
    let cfg = Arc::new(common::server_config());
    let srv = raw(move |mut s, _| {
        // a TLS server handshake, then silence
        let mut t = simoom_tls::ServerConnection::new(cfg.clone());
        let mut b = vec![0u8; 16 * 1024];
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        loop {
            let out = t.tls_output().to_vec();
            if !out.is_empty() {
                t.consume_tls_output(out.len());
                if s.write_all(&out).is_err() {
                    return;
                }
            }
            let n = match s.read(&mut b) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let mut off = 0;
            while off < n {
                let k = t.read_tls(&b[off..n]);
                if k == 0 {
                    break;
                }
                off += k;
                if t.process_new_packets().is_err() {
                    return;
                }
            }
        }
    });
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let e = get(&c, &format!("https://localhost:{}/", srv.addr.port())).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unsupported, "{e}");
}

#[test]
fn stream_limit_queues_requests_on_the_loop() {
    let open = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (o2, p2) = (open.clone(), peak.clone());
    let s = srv(Config { max_concurrent_streams: 2, ..Config::default() }, move |conn, st, ev| match ev {
        Ev::Headers(id, _) => {
            let n = o2.fetch_add(1, Ordering::SeqCst) + 1;
            p2.fetch_max(n, Ordering::SeqCst);
            st.held.push((id, Instant::now()));
        }
        Ev::Tick => {
            let now = Instant::now();
            st.held.retain(|&(id, at)| {
                if now.duration_since(at) < Duration::from_millis(30) {
                    return true;
                }
                o2.fetch_sub(1, Ordering::SeqCst);
                ok(conn, id, b"done");
                false
            });
        }
        _ => {}
    });
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let u = format!("http://{}/", s.addr);
    // the first exchange brings the server's SETTINGS (a limit of 2)
    assert_eq!(get(&c, &u).unwrap().body, b"done");
    let (tx, rx) = channel();
    for _ in 0..12 {
        let tx = tx.clone();
        c.send(RtRequest::get(&u).unwrap(), move |r| tx.send(r).unwrap());
    }
    for _ in 0..12 {
        assert_eq!(rx.recv_timeout(Duration::from_secs(20)).unwrap().unwrap().body, b"done");
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2, "never more than the server's limit at once");
    assert_eq!(s.conns.load(Ordering::SeqCst), 1);
    assert!(s.resets.lock().unwrap().is_empty(), "nothing refused: {:?}", s.resets.lock().unwrap());
}

#[test]
fn large_bodies_both_ways_with_flow_control() {
    let h = plain();
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let r = get(&c, &url(&h, "/big?n=3000000")).unwrap();
    assert_eq!(r.body.len(), 3_000_000);
    assert!(r.body.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
    // a streamed upload in pieces, larger than every window
    let (sender, rx) = call(&c, RtRequest::new("POST", &url(&h, "/upload")).unwrap(), CallOptions::default());
    let mut sum = 0u64;
    for i in 0..40u8 {
        let piece = vec![i; 100_000];
        sum = piece.iter().fold(sum, |a, &b| a.wrapping_mul(31).wrapping_add(b as u64));
        assert!(sender.send(piece));
    }
    assert!(sender.finish());
    let (status, body, end) = collect(&rx);
    assert_eq!(status, 200);
    end.unwrap();
    assert_eq!(String::from_utf8(body).unwrap(), format!("4000000 {sum}"));
    assert!(!sender.send(b"late".to_vec()), "the call is over");
}

#[test]
fn manual_release_holds_the_server_back() {
    let sent = Arc::new(AtomicUsize::new(0));
    let s2 = sent.clone();
    const TOTAL: usize = 1 << 20;
    let s = srv(Config::default(), move |conn, st, ev| match ev {
        Ev::Headers(id, _) => {
            conn.send_response(id, 200, &[], false).unwrap();
            st.to_send.insert(id, TOTAL);
        }
        Ev::Tick => {
            let chunk = vec![1u8; 16 * 1024];
            for (&id, left) in st.to_send.iter_mut() {
                while *left > 0 {
                    let n = conn.send_data(id, &chunk[..chunk.len().min(*left)], *left <= chunk.len()).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    *left -= n;
                    s2.fetch_add(n, Ordering::SeqCst);
                }
            }
            st.to_send.retain(|_, l| *l > 0);
        }
        _ => {}
    });
    let mut cfg = h2cfg();
    cfg.h2.initial_window_size = 65_535;
    cfg.h2.connection_window_size = 65_535;
    cfg.h2.window_autotune = false;
    let c = RtClient::spawn(1, cfg).unwrap();
    let (call, rx) = call(&c, RtRequest::get(&format!("http://{}/", s.addr)).unwrap(), CallOptions { manual_release: true, ..CallOptions::default() });
    call.finish();
    std::thread::sleep(Duration::from_millis(300));
    let mut got = 0;
    while let Ok(ev) = rx.try_recv() {
        if let Got::Data(d) = ev {
            got += d.len();
        }
    }
    assert!(sent.load(Ordering::SeqCst) <= 65_535 && got <= 65_535, "sent {} got {got}", sent.load(Ordering::SeqCst));
    assert!(got > 0);
    // hand the credit back as the bytes are "consumed": the rest flows
    call.release(got);
    loop {
        match rx.recv_timeout(Duration::from_secs(20)).unwrap() {
            Got::Data(d) => {
                got += d.len();
                call.release(d.len());
            }
            Got::End(r) => {
                r.unwrap();
                break;
            }
            _ => {}
        }
    }
    assert_eq!(got, TOTAL);
}

#[test]
fn refused_streams_are_retried_and_goaway_moves_to_a_new_connection() {
    let refused = Arc::new(AtomicUsize::new(0));
    let rf = refused.clone();
    let s = srv(Config::default(), move |conn, _, ev| {
        if let Ev::Headers(id, _) = ev {
            if rf.fetch_add(1, Ordering::SeqCst) == 0 {
                conn.reset(id, ErrorCode::REFUSED_STREAM);
            } else {
                ok(conn, id, b"ok");
            }
        }
    });
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    assert_eq!(get(&c, &format!("http://{}/", s.addr)).unwrap().body, b"ok");
    assert_eq!(refused.load(Ordering::SeqCst), 2);

    // GOAWAY after each response: the next request needs a new connection
    let s = srv(Config::default(), |conn, _, ev| {
        if let Ev::Headers(id, _) = ev {
            ok(conn, id, b"bye");
            conn.shutdown(0);
        }
    });
    for _ in 0..3 {
        assert_eq!(get(&c, &format!("http://{}/", s.addr)).unwrap().body, b"bye");
    }
    assert_eq!(s.conns.load(Ordering::SeqCst), 3);

    // GOAWAY with requests in flight: those above the last stream are retried elsewhere
    let first = Arc::new(AtomicUsize::new(0));
    let f2 = first.clone();
    let s = srv(Config::default(), move |conn, st, ev| match ev {
        Ev::Headers(id, _) => st.held.push((id, Instant::now())),
        Ev::Tick if st.held.len() >= 4 && f2.fetch_add(1, Ordering::SeqCst) == 0 => {
            // answer the first, refuse the rest with GOAWAY(last = first)
            let (id, _) = st.held.remove(0);
            ok(conn, id, b"first");
            st.extra = goaway(id);
        }
        Ev::Tick if f2.load(Ordering::SeqCst) > 0 => {
            for (id, _) in st.held.drain(..) {
                ok(conn, id, b"later");
            }
        }
        _ => {}
    });
    let (tx, rx) = channel();
    for _ in 0..4 {
        let tx = tx.clone();
        c.send(RtRequest::get(&format!("http://{}/", s.addr)).unwrap(), move |r| tx.send(r).unwrap());
    }
    let mut bodies: Vec<Vec<u8>> = (0..4).map(|_| rx.recv_timeout(Duration::from_secs(20)).unwrap().unwrap().body).collect();
    bodies.sort();
    assert_eq!(bodies, vec![b"first".to_vec(), b"later".to_vec(), b"later".to_vec(), b"later".to_vec()]);
    assert_eq!(s.conns.load(Ordering::SeqCst), 2);
}

#[test]
fn rst_stream_fails_the_request_and_a_complete_answer_is_kept() {
    let s = srv(Config::default(), |conn, _, ev| {
        if let Ev::Headers(id, path) = ev {
            if path == "/reset" {
                conn.reset(id, ErrorCode::INTERNAL_ERROR);
            } else {
                // RFC 9113 §8.1: an answer before the request body ends, then NO_ERROR
                ok(conn, id, b"early answer");
                conn.reset(id, ErrorCode::NO_ERROR);
            }
        }
    });
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let e = get(&c, &format!("http://{}/reset", s.addr)).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Reset(2), "{e}");
    let (call, rx) = call(&c, RtRequest::new("POST", &format!("http://{}/early", s.addr)).unwrap().body(vec![1u8; 1000]), CallOptions::default());
    let (status, body, end) = collect(&rx);
    assert_eq!((status, body), (200, b"early answer".to_vec()));
    end.unwrap();
    assert!(call.is_over());
}

#[test]
fn cancelling_a_call_resets_its_stream() {
    let s = srv(Config::default(), |conn, st, ev| match ev {
        Ev::Headers(id, path) if path == "/hold" => {
            conn.send_response(id, 200, &[], false).unwrap();
            st.held.push((id, Instant::now()));
        }
        Ev::Headers(id, _) => ok(conn, id, b"ok"),
        _ => {}
    });
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let (call, rx) = call(&c, RtRequest::get(&format!("http://{}/hold", s.addr)).unwrap(), CallOptions::default());
    assert!(matches!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), Got::Head(200)));
    call.cancel();
    let (_, _, end) = collect(&rx);
    assert_eq!(end.unwrap_err().kind, ErrorKind::Cancelled);
    let t = Instant::now();
    while s.resets.lock().unwrap().is_empty() && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(s.resets.lock().unwrap().as_slice(), &[(1, ErrorCode::CANCEL)]);
    // the connection goes on serving
    let (_, rx) = call_ok(&c, s.addr);
    assert_eq!(collect(&rx).0, 200);
}

fn call_ok(c: &RtClient, addr: SocketAddr) -> (RtCall, Receiver<Got>) {
    let (call, rx) = call(c, RtRequest::get(&format!("http://{addr}/")).unwrap(), CallOptions { timeout: Some(Duration::from_millis(200)), ..CallOptions::default() });
    call.finish();
    (call, rx)
}

#[test]
fn deadlines_reset_the_stream() {
    let s = srv(Config::default(), |conn, st, ev| match ev {
        Ev::Headers(id, path) if path == "/fast" => ok(conn, id, b"fast"),
        Ev::Headers(id, _) => st.held.push((id, Instant::now())),
        _ => {}
    });
    let c = RtClient::spawn(1, RtConfig { timeout: Duration::from_millis(200), ..h2cfg() }).unwrap();
    let t = Instant::now();
    let e = get(&c, &format!("http://{}/slow", s.addr)).unwrap_err();
    assert!(e.is_timeout(), "{e}");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    // a call's own timeout
    let (_, rx) = call_ok(&c, s.addr);
    assert!(collect(&rx).2.unwrap_err().is_timeout());
    let t = Instant::now();
    while s.resets.lock().unwrap().len() < 2 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(s.resets.lock().unwrap().iter().all(|&(_, c)| c == ErrorCode::CANCEL), "{:?}", s.resets.lock().unwrap());
    assert_eq!(s.resets.lock().unwrap().len(), 2);
    assert_eq!(get(&c, &format!("http://{}/fast", s.addr)).unwrap().body, b"fast");
    assert_eq!(s.conns.load(Ordering::SeqCst), 1);
}

#[test]
fn streamed_responses_arrive_as_they_are_sent() {
    let h = plain();
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let (call, rx) = call(&c, RtRequest::get(&url(&h, "/stream?parts=5")).unwrap(), CallOptions::default());
    call.finish();
    let (mut pieces, mut body) = (0, Vec::new());
    loop {
        match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            Got::Data(d) => {
                pieces += 1;
                body.extend_from_slice(&d);
            }
            Got::End(r) => {
                r.unwrap();
                break;
            }
            _ => {}
        }
    }
    assert_eq!(body, b"part0;part1;part2;part3;part4;");
    assert!(pieces >= 2, "{pieces} pieces");
    // send_streaming takes the loop path for HTTP/2
    let (tx, rx) = channel();
    let (t1, t2, t3) = (tx.clone(), tx.clone(), tx);
    let mut req = simoom_client::Request::new("GET", simoom_client::Url::parse(&url(&h, "/trailers")).unwrap());
    req.version = Some(HttpVersion::Http2);
    c.send_streaming(req, move |s, _| t1.send(Got::Head(s)).unwrap(), move |d| t2.send(Got::Data(d.to_vec())).unwrap(), move |r| t3.send(Got::End(r)).unwrap());
    let (status, body, end) = collect(&rx);
    assert_eq!((status, body), (200, b"payload".to_vec()));
    assert_eq!(end.unwrap().get("x-checksum"), Some("abc123"));
}

#[test]
fn full_duplex_call_with_trailers_both_ways() {
    let s = srv(Config::default(), |conn, _, ev| match ev {
        Ev::Headers(id, _) => conn.send_response(id, 200, &[(b"content-type", b"application/grpc")], false).unwrap(),
        Ev::Data(id, d, end) => {
            if !d.is_empty() {
                conn.send_data(id, &d, false).unwrap();
            }
            if end {
                conn.send_trailers(id, &[(b"grpc-status", b"0")]).unwrap();
                conn.stream_finished(id);
            }
        }
        Ev::Trailers(id, t) => {
            let got = t.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join(",");
            conn.send_trailers(id, &[(b"grpc-status", b"0"), (b"x-got", got.as_bytes())]).unwrap();
            conn.stream_finished(id);
        }
        _ => {}
    });
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    for with_trailers in [false, true] {
        let (call, rx) = call(&c, RtRequest::new("POST", &format!("http://{}/svc/Echo", s.addr)).unwrap(), CallOptions::default());
        assert!(matches!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), Got::Head(200)));
        for i in 0..5 {
            let msg = format!("msg{i}");
            assert!(call.send(msg.clone()));
            let mut got = Vec::new();
            while got.len() < msg.len() {
                match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                    Got::Data(d) => got.extend_from_slice(&d),
                    other => panic!("{other:?}"),
                }
            }
            assert_eq!(got, msg.as_bytes(), "the echo arrives before the request ends");
        }
        if with_trailers {
            call.finish_with_trailers(&[("X-Sum", "10")]);
        } else {
            call.finish();
        }
        let (_, body, end) = collect(&rx);
        assert!(body.is_empty());
        let t = end.unwrap();
        assert_eq!(t.get("grpc-status"), Some("0"));
        if with_trailers {
            assert_eq!(t.get("x-got"), Some("x-sum=10"));
        }
    }
}

#[test]
fn a_full_send_buffer_reports_writable_again() {
    let s = srv(Config::default(), |conn, _, ev| match ev {
        Ev::Headers(id, _) => conn.send_response(id, 200, &[], false).unwrap(),
        Ev::Data(id, _, true) => conn.send_data(id, b"done", true).map(|_| ()).unwrap(),
        _ => {}
    });
    let mut cfg = h2cfg();
    cfg.h2.window_autotune = false;
    let c = RtClient::spawn(1, cfg).unwrap();
    let (call, rx) = call(&c, RtRequest::new("POST", &format!("http://{}/", s.addr)).unwrap(), CallOptions { high_water: 64 * 1024, ..CallOptions::default() });
    let mut sent = 0;
    while !call.is_full() && sent < (64 << 20) {
        call.send(vec![0u8; 16 * 1024]);
        sent += 16 * 1024;
    }
    assert!(sent >= 64 * 1024);
    let mut writable = false;
    let t = Instant::now();
    while !writable && t.elapsed() < Duration::from_secs(10) {
        if let Ok(Got::Writable) = rx.recv_timeout(Duration::from_millis(100)) {
            writable = true;
        }
    }
    assert!(writable && call.buffered() <= 32 * 1024, "buffered {}", call.buffered());
    call.finish();
    let (status, body, end) = collect(&rx);
    assert_eq!((status, body), (200, b"done".to_vec()));
    end.unwrap();
}

#[test]
fn keepalive_closes_a_dead_connection() {
    // answers the first request, then swallows everything (PINGs included)
    let answered = Arc::new(AtomicUsize::new(0));
    let a2 = answered.clone();
    let silent = raw(move |mut s, _| {
        let mut conn = Connection::server(Config::default());
        let mut buf = vec![0u8; 65536];
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        loop {
            let Ok(n) = s.read(&mut buf) else { return };
            if n == 0 {
                return;
            }
            if a2.load(Ordering::SeqCst) > 0 {
                continue;
            }
            let mut req = None;
            conn.recv(&buf[..n], 0, &mut |ev| {
                if let Event::Headers { stream, .. } = ev {
                    req = Some(stream);
                }
            });
            if let Some(id) = req {
                ok(&mut conn, id, b"ok");
                a2.fetch_add(1, Ordering::SeqCst);
            }
            let out = conn.output().to_vec();
            conn.advance_output(out.len());
            s.write_all(&out).unwrap();
        }
    });
    let mut cfg = h2cfg();
    cfg.h2.keepalive_interval_ms = Some(50);
    cfg.h2.keepalive_timeout_ms = 200;
    let c = RtClient::spawn(1, cfg).unwrap();
    assert_eq!(get(&c, &format!("http://{}/", silent.addr)).unwrap().body, b"ok");
    assert_eq!(c.h2_connections_on(0), 1);
    let t = Instant::now();
    while c.h2_connections_on(0) > 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(c.h2_connections_on(0), 0, "the unanswered PING closed the connection");
}

#[test]
fn a_lost_connection_fails_requests_in_flight_and_reconnects() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let s = srv(Config::default(), move |conn, st, ev| {
        if let Ev::Headers(id, _) = ev {
            if n2.fetch_add(1, Ordering::SeqCst) == 0 {
                st.held.push((id, Instant::now()));
                // drop the connection with the request in flight
                conn.close(ErrorCode::INTERNAL_ERROR, b"bye");
            } else {
                ok(conn, id, b"again");
            }
        }
    });
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let e = get(&c, &format!("http://{}/", s.addr)).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Protocol | ErrorKind::Closed | ErrorKind::Reset(_)), "{e}");
    assert_eq!(get(&c, &format!("http://{}/", s.addr)).unwrap().body, b"again");
    assert_eq!(s.conns.load(Ordering::SeqCst), 2);
    // nobody listening: the connect error reaches the callback
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let e = get(&c, &format!("http://{dead}/")).unwrap_err();
    assert!(e.is_connect() || matches!(e.kind, ErrorKind::Io(_)), "{e}");
}

#[test]
fn redirects_on_the_loop() {
    let h = plain();
    let c = RtClient::spawn(1, RtConfig { follow_redirects: true, ..h2cfg() }).unwrap();
    let r = get(&c, &url(&h, "/redirect?to=/echo%3Fx%3D9&code=302")).unwrap();
    assert_eq!(r.status, 200);
    assert!(String::from_utf8(r.body).unwrap().starts_with("H2 GET /echo q=9"));
}

#[test]
fn http2_requests_and_calls_sent_on_a_loop_thread_stay_on_that_loop() {
    let h = plain();
    let c = RtClient::spawn(1, h2cfg()).unwrap();
    let other = simoom_rt::Runtime::builder().threads(1).start().unwrap();
    let lh = other.loops()[0].clone();
    for _ in 0..3 {
        let (tx, rx) = channel();
        let (c2, u, l2) = (c.clone(), url(&h, "/echo"), lh.clone());
        lh.run(move |_| {
            let (t1, l3) = (tx.clone(), l2.clone());
            c2.send(RtRequest::get(&u).unwrap(), move |r| {
                t1.send((r.map(|r| r.version), simoom_rt::LoopHandle::current() == Some(l3))).unwrap();
            });
            struct Here(Sender<(Result<Version>, bool)>, simoom_rt::LoopHandle);
            impl CallHandler for Here {
                fn on_end(&mut self, r: Result<Headers>) {
                    let _ = self.0.send((r.map(|_| Version::Http2), simoom_rt::LoopHandle::current().as_ref() == Some(&self.1)));
                }
            }
            c2.call(RtRequest::get(&u).unwrap(), CallOptions::default(), Here(tx, l2)).finish();
        });
        for _ in 0..2 {
            let (v, same) = rx.recv_timeout(Duration::from_secs(20)).unwrap();
            assert_eq!(v.unwrap(), Version::Http2);
            assert!(same, "completed on the loop that sent");
        }
    }
    assert_eq!(c.h2_connections_on(0), 0, "nothing on the client's own loop");
    drop(c);
    other.stop(Duration::from_millis(100));
    other.join();
}
