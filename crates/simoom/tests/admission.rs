//! K5: admission control by backpressure. When a loop has `max_pending_per_loop` replies
//! outstanding, its connections stop reading new requests until the count drops (or, with
//! `pending_503`, get a fast 503).
//!
//! K6: slow attackers. A request head that outlives `head_timeout` stays open while the server
//! has connections to spare, and closes under pressure or after `slow_head_limit`; a per-IP
//! reconnect rate turns away an attacker that comes straight back. (Feature `guard`.)

#![cfg_attr(not(feature = "guard"), allow(dead_code, unused_imports))]

mod common;

use common::*;
use simoom::{Limits, Outcome, Reply, Request, Responder, Response, Server, ServerHandle};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Held = Arc<Mutex<Vec<Responder>>>;

fn deferring(limits: Limits) -> (ServerHandle, Held) {
    let held: Held = Arc::default();
    let h2 = held.clone();
    let h = Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(limits)
        .service(move |_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            h2.lock().unwrap().push(reply.defer());
            Outcome::Deferred
        })
        .start()
        .unwrap();
    (h, held)
}

fn send_get(h: &ServerHandle) -> TcpStream {
    let mut c = connect(h);
    c.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    c
}

fn status_of(c: &mut TcpStream) -> u16 {
    let mut got = Vec::new();
    let mut b = [0u8; 512];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let k = c.read(&mut b).unwrap();
        assert!(k > 0, "closed before a response");
        got.extend_from_slice(&b[..k]);
    }
    std::str::from_utf8(&got[9..12]).unwrap().parse().unwrap()
}

fn answer_all(held: &Held) {
    for r in held.lock().unwrap().drain(..) {
        r.send(Response::new(200).body(&b"ok"[..]));
    }
}

#[cfg(feature = "guard")]
#[test]
fn a_loop_with_too_many_replies_outstanding_stops_reading_new_requests() {
    let (h, held) = deferring(Limits { max_pending_per_loop: 4, ..Limits::default() });
    let mut first: Vec<TcpStream> = (0..4).map(|_| send_get(&h)).collect();
    assert!(wait_for(5, || held.lock().unwrap().len() == 4), "{:?}", h.stats());
    // A fifth request waits in the kernel: not read while four replies are outstanding.
    let mut fifth = send_get(&h);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(held.lock().unwrap().len(), 4, "the fifth request was read");
    // The replies go out: the loop reads again and the fifth request is served.
    answer_all(&held);
    for c in first.iter_mut() {
        assert_eq!(status_of(c), 200);
    }
    assert!(wait_for(5, || held.lock().unwrap().len() == 1), "the fifth request was never read");
    answer_all(&held);
    assert_eq!(status_of(&mut fifth), 200);
    assert_eq!(h.stats().shed, 0, "backpressure, not shedding");
}

#[cfg(feature = "guard")]
#[test]
fn with_pending_503_new_requests_get_a_fast_503() {
    let (h, held) = deferring(Limits { max_pending_per_loop: 2, pending_503: true, ..Limits::default() });
    let mut first: Vec<TcpStream> = (0..2).map(|_| send_get(&h)).collect();
    assert!(wait_for(5, || held.lock().unwrap().len() == 2));
    let mut third = send_get(&h);
    let t = Instant::now();
    assert_eq!(status_of(&mut third), 503);
    assert!(t.elapsed() < Duration::from_secs(1));
    assert_eq!(h.stats().shed, 1);
    answer_all(&held);
    for c in first.iter_mut() {
        assert_eq!(status_of(c), 200);
    }
}

fn slow_server(limits: Limits) -> ServerHandle {
    Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(limits)
        .service(|_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body_static(b"ok") })
        .start()
        .unwrap()
}

fn slow_head(h: &ServerHandle) -> TcpStream {
    let mut s = connect(h);
    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nX-Slow:").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    s
}

/// Open (a read times out) or closed (EOF, a 408, a reset).
fn is_open(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 64];
    match s.read(&mut b) {
        Err(e) => matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
        Ok(_) => false,
    }
}

#[cfg(feature = "guard")]
#[test]
fn a_slow_head_stays_open_until_pressure_or_its_limit() {
    let l = Limits { head_timeout: Duration::from_millis(200), slow_head_limit: Duration::from_millis(1500), ..Limits::default() };
    let h = slow_server(l);
    let mut s = slow_head(&h);
    std::thread::sleep(Duration::from_millis(700));
    assert!(is_open(&mut s), "closed with connections to spare");
    assert_eq!(h.stats().timeouts, 0);
    // Past slow_head_limit it goes.
    assert!(wait_for(3, || !is_open(&mut s)), "still open after its limit");
    assert_eq!(h.stats().timeouts, 1);
}

#[test]
fn under_connection_pressure_slow_heads_close_at_their_deadline() {
    // Four connections of a budget of four: past three quarters.
    let l = Limits { head_timeout: Duration::from_millis(200), max_connections: 4, ..Limits::default() };
    let h = slow_server(l);
    let mut conns: Vec<TcpStream> = (0..4).map(|_| slow_head(&h)).collect();
    let t = Instant::now();
    for s in conns.iter_mut() {
        assert!(wait_for(3, || !is_open(s)));
    }
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert!(h.stats().timeouts >= 4, "{:?}", h.stats());
}

#[cfg(feature = "guard")]
#[test]
fn a_reconnect_rate_turns_away_a_client_that_comes_straight_back() {
    let h = slow_server(Limits { reconnect_rate: 5, ..Limits::default() });
    let mut served = 0;
    for _ in 0..20 {
        let mut c = connect(&h);
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        if c.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").is_err() {
            continue;
        }
        let mut b = Vec::new();
        let _ = c.read_to_end(&mut b);
        if b.starts_with(b"HTTP/1.1 200") {
            served += 1;
        }
    }
    assert!((5..=8).contains(&served), "served {served} of 20 at 5 per second");
    assert!(h.stats().rejected >= 12, "{:?}", h.stats());
    // A second later the bucket has refilled.
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(get(&h, "/").status, 200);
}

/// Connections accepted while loop 0 starts the lazy loops are parked; with nothing to start
/// (one loop) they used to wait for the loop's next event, a timer away (seen on Windows: the
/// fourth of four connections opened at once was served after its head timeout).
#[test]
fn connections_accepted_while_the_loops_start_are_served_at_once() {
    let h = slow_server(Limits::default());
    let mut conns: Vec<TcpStream> = (0..6).map(|_| send_get(&h)).collect();
    let t = Instant::now();
    for c in conns.iter_mut() {
        assert_eq!(status_of(c), 200);
    }
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}
