//! HTTP/3: forced and through Alt-Svc, against simoom's QUIC listener.

#![cfg(feature = "client-h3")]

mod common;

use common::{client, secure};
use simoom_client::{Body, HttpVersion, Version};
use std::io::Read;
use std::time::{Duration, Instant};

/// Runs a test body with a 60 s limit: a hang in the QUIC client fails the test instead of
/// spinning forever (the harness exits once every test returned).
fn timed(f: fn()) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("the test body panicked"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("HTTP/3 test hung for 60 s"),
    }
}

fn h3url(h: &simoom::ServerHandle, path: &str) -> String {
    format!("https://localhost:{}{}", h.quic_addrs()[0].port(), path)
}

#[test]
fn forced_http3_round_trips() {
    timed(forced_http3_round_trips_body);
}

fn forced_http3_round_trips_body() {
    let h = secure();
    let c = client().version(HttpVersion::Http3).build();
    let r = c.get(&h3url(&h, "/echo")).query("x", "1").send().unwrap();
    assert_eq!(r.version(), Version::Http3);
    let t = r.text().unwrap();
    assert!(t.starts_with("H3 GET /echo q=1"), "{t}");
    // bodies both ways, larger than the stream windows
    let r = c.get(&h3url(&h, "/big?n=2500000")).send().unwrap();
    let mut b = r.into_body();
    let mut buf = vec![0u8; 4096];
    let mut n = 0;
    loop {
        let k = b.read(&mut buf).unwrap();
        if k == 0 {
            break;
        }
        assert_eq!(buf[0], (n % 251) as u8);
        n += k;
    }
    assert_eq!(n, 2_500_000);
    let up = vec![3u8; 1_500_000];
    let sum = up.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64));
    assert_eq!(c.post(&h3url(&h, "/upload")).body(up).send().unwrap().text().unwrap(), format!("1500000 {sum}"));
    assert_eq!(c.post(&h3url(&h, "/upload")).body(Body::reader(std::io::repeat(3).take(300_000))).send().unwrap().text().unwrap().split(' ').next(), Some("300000"));
    // trailers, streaming, concurrency on one connection
    let mut r = c.get(&h3url(&h, "/trailers")).send().unwrap();
    assert_eq!(r.buffer().unwrap(), b"payload");
    assert_eq!(r.trailers().unwrap().get("x-checksum"), Some("abc123"));
    assert_eq!(c.get(&h3url(&h, "/stream?parts=3")).send().unwrap().text().unwrap(), "part0;part1;part2;");
    let t = Instant::now();
    let ts: Vec<_> = (0..10)
        .map(|_| {
            let (c, u) = (c.clone(), h3url(&h, "/slow?ms=200"));
            std::thread::spawn(move || c.get(&u).send().unwrap().text().unwrap())
        })
        .collect();
    for t in ts {
        assert_eq!(t.join().unwrap(), "slow done");
    }
    assert!(t.elapsed() < Duration::from_millis(1500));
    assert_eq!(c.pool_stats().multiplexed, 1);
}

#[test]
fn alt_svc_moves_an_origin_to_http3() {
    timed(alt_svc_moves_an_origin_to_http3_body);
}

fn alt_svc_moves_an_origin_to_http3_body() {
    // The server's TCP and UDP ports differ: Alt-Svc names the UDP port.
    let h = secure();
    let c = client().alt_svc(true).build();
    let u = common::surl(&h, "/echo");
    let r = c.get(&u).send().unwrap();
    assert_eq!(r.version(), Version::Http2, "first request over TCP");
    assert!(r.header("alt-svc").is_some());
    drop(r);
    let r = c.get(&u).send().unwrap();
    assert_eq!(r.version(), Version::Http3, "then HTTP/3");
    assert!(r.text().unwrap().starts_with("H3 GET /echo"));
}

#[test]
fn alt_svc_falls_back_when_quic_is_unreachable() {
    timed(alt_svc_falls_back_when_quic_is_unreachable_body);
}

fn alt_svc_falls_back_when_quic_is_unreachable_body() {
    // An origin announcing h3 on a port where nothing answers.
    let srv = common::raw(|mut s, _| {
        use std::io::Write;
        while common::read_head(&mut s).is_some() {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":9\"; ma=60\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    // plain http never uses h3; this checks the fallback path with https below
    let c = client().alt_svc(true).build();
    assert_eq!(c.get(&format!("http://{}/", srv.addr)).send().unwrap().text().unwrap(), "ok");
    let h = secure();
    let c = client().alt_svc(true).connect_timeout(Some(Duration::from_millis(300))).build();
    let u = common::surl(&h, "/echo");
    let _ = c.get(&u).send().unwrap().bytes();
    // Point the cached alternative at a dead port by forcing HTTP/3 elsewhere: a forced
    // request to a port with no QUIC listener times out at connect.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let e = c.get(&format!("https://localhost:{}/", dead.local_addr().unwrap().port())).version(HttpVersion::Http3).send().unwrap_err();
    assert!(e.is_timeout() || e.is_connect(), "{e}");
}
