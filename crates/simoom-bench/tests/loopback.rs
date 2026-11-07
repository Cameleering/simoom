//! The load generator against small servers on loopback: closed loop, open loop (rate and
//! sample counts), pipelining, idle connections, HTTP/2, the coordinator with agents, and a
//! stalled server (latency must count from the intended send time).

use simoom_bench::dist;
use simoom_bench::load::{self, Proto, Spec};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";

/// A thread-per-connection HTTP/1.1 server answering every request head (pipelining included).
/// `stall` makes it sleep before answering while the flag is set.
fn h1_server(stall: Arc<AtomicBool>, stall_for: Duration) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let stall = stall.clone();
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                let mut buf = vec![0u8; 65536];
                let mut have = 0;
                loop {
                    let n = match s.read(&mut buf[have..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    have += n;
                    let mut out = Vec::new();
                    let mut consumed = 0;
                    while let Some(p) = buf[consumed..have].windows(4).position(|w| w == b"\r\n\r\n") {
                        consumed += p + 4;
                        out.extend_from_slice(REPLY);
                    }
                    buf.copy_within(consumed..have, 0);
                    have -= consumed;
                    if stall.load(Ordering::Relaxed) {
                        std::thread::sleep(stall_for);
                    }
                    if !out.is_empty() && s.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// An HTTP/2 (prior knowledge) server on the simoom-h2 engine, one thread per connection.
fn h2_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                let mut c = simoom_h2::Connection::server(simoom_h2::Config::default());
                let mut input = Vec::new();
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    input.extend_from_slice(&buf[..n]);
                    let mut ended = Vec::new();
                    let used = c.recv(&input, 0, &mut |ev| match ev {
                        simoom_h2::Event::Headers { stream, end_stream: true, .. } => ended.push(stream),
                        simoom_h2::Event::Data { stream, end_stream: true, .. } => ended.push(stream),
                        _ => {}
                    });
                    input.drain(..used);
                    for st in ended {
                        let _ = c.send_response(st, 200, &[(b"content-type", b"text/plain")], false);
                        let _ = c.send_data(st, b"Hello, World!", true);
                        c.stream_finished(st);
                    }
                    let out = c.output().to_vec();
                    c.advance_output(out.len());
                    if !out.is_empty() && s.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn spec(addr: SocketAddr) -> Spec {
    Spec {
        addr,
        host: addr.to_string(),
        conns: 4,
        threads: 2,
        cpus: Some(vec![]),
        warmup: Duration::from_millis(200),
        duration: Duration::from_millis(1000),
        drain: Duration::from_millis(500),
        backend: simoom_rt::Backend::Auto,
        ..Spec::default()
    }
}

#[test]
fn closed_loop_counts_every_response() {
    let addr = h1_server(Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let r = load::run(spec(addr)).unwrap();
    assert_eq!(r.errors(), 0, "{r:?}");
    assert!(r.received > 100, "{}", r.received);
    assert_eq!(r.connected, 4);
    assert!(r.hist.percentile(50.0) > 0);
}

#[test]
fn pipelined_closed_loop() {
    let addr = h1_server(Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let r = load::run(Spec { depth: 8, ..spec(addr) }).unwrap();
    assert_eq!(r.errors(), 0);
    assert!(r.received > 100);
}

#[test]
fn open_loop_offers_the_rate() {
    let addr = h1_server(Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let r = load::run(Spec { rate: 2000.0, duration: Duration::from_secs(2), ..spec(addr) }).unwrap();
    assert_eq!(r.errors(), 0);
    // 2000 req/s for 2 s: every intended request inside the window is a sample
    let samples = r.completed as f64;
    assert!((samples - 4000.0).abs() <= 40.0, "{samples} samples");
    assert!((r.achieved() - 2000.0).abs() < 100.0, "{}", r.achieved());
    assert_eq!(r.incomplete, 0);
    assert!(r.lag.count() > 0, "the timer lag is measured");
}

#[test]
fn poisson_schedule_keeps_the_mean_rate() {
    let addr = h1_server(Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let r = load::run(Spec { rate: 2000.0, dist: load::Dist::Poisson, duration: Duration::from_secs(2), ..spec(addr) }).unwrap();
    let samples = r.completed as f64;
    assert!((samples - 4000.0).abs() < 400.0, "{samples} samples");
}

#[test]
fn a_stall_is_charged_to_every_delayed_request() {
    // the server sleeps 200 ms on every read while stalled: open-loop latency must show the
    // queueing (intended-time based), i.e. many samples near or above 100 ms, not one
    let stall = Arc::new(AtomicBool::new(false));
    let addr = h1_server(stall.clone(), Duration::from_millis(200));
    let s2 = stall.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        s2.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(400));
        s2.store(false, Ordering::Relaxed);
    });
    let r = load::run(Spec { rate: 1000.0, conns: 2, duration: Duration::from_secs(2), ..spec(addr) }).unwrap();
    // at 1000 req/s a 400 ms stall delays about 400 requests: well over 5% of 2000 samples
    assert!(r.hist.percentile(90.0) > 50_000_000, "p90 {} ns", r.hist.percentile(90.0));
}

#[test]
fn idle_connections_are_held() {
    let addr = h1_server(Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let r = load::run(Spec { idle: true, conns: 50, duration: Duration::from_millis(300), ..spec(addr) }).unwrap();
    assert_eq!(r.connected, 50);
    assert_eq!(r.errors(), 0);
}

#[test]
fn http2_streams() {
    let addr = h2_server();
    let r = load::run(Spec { proto: Proto::H2c, depth: 8, ..spec(addr) }).unwrap();
    assert_eq!(r.errors(), 0, "{r:?}");
    assert!(r.received > 100, "{}", r.received);
    let r = load::run(Spec { proto: Proto::H2c, rate: 1000.0, ..spec(addr) }).unwrap();
    assert_eq!(r.errors(), 0);
    assert!((r.completed as f64 - 1000.0).abs() <= 20.0, "{}", r.completed);
}

#[test]
fn coordinator_merges_agents() {
    let addr = h1_server(Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let mut agents = Vec::new();
    for _ in 0..2 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap().to_string();
        drop(l);
        let a2 = a.clone();
        std::thread::spawn(move || dist::agent(&a2).unwrap());
        agents.push(a);
    }
    for a in &agents {
        for _ in 0..100 {
            if TcpStream::connect(a).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let (m, nodes) = dist::run(&agents, &Spec { rate: 1000.0, conns: 4, ..spec(addr) }).unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(m.connected, 4);
    assert_eq!(m.errors(), 0);
    assert_eq!(m.hist.count(), nodes.iter().map(|n| n.hist.count()).sum::<u64>());
    assert!((m.completed as f64 - 1000.0).abs() <= 20.0, "{}", m.completed);
}
