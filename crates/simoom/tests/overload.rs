//! Admission control: when the loop falls behind, new requests get a fast 503 and the requests
//! already admitted keep their latency.

mod common;

use common::*;
use simoom::{Limits, Outcome, Reply, Request};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn spin(d: Duration) {
    let t = Instant::now();
    while t.elapsed() < d {
        std::hint::spin_loop();
    }
}

/// Sends one request on each of `n` connections at once, then reads every answer; returns
/// (status, latency) per connection.
fn burst(h: &simoom::ServerHandle, n: usize) -> Vec<(u16, Duration)> {
    let mut conns: Vec<_> = (0..n).map(|_| connect(h)).collect();
    // Connected and accepted before the burst, so the requests arrive together.
    std::thread::sleep(Duration::from_millis(100));
    let t0 = Instant::now();
    for c in conns.iter_mut() {
        c.write_all(b"GET /work HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    }
    let mut out = Vec::new();
    for c in conns.iter_mut() {
        let mut buf = [0u8; 512];
        let mut got = Vec::new();
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let k = c.read(&mut buf).unwrap();
            assert!(k > 0, "closed before a response");
            got.extend_from_slice(&buf[..k]);
        }
        let status = std::str::from_utf8(&got[9..12]).unwrap().parse().unwrap();
        out.push((status, t0.elapsed()));
    }
    out
}

#[test]
fn an_overloaded_loop_sheds_new_requests_and_keeps_admitted_latency() {
    let work = Duration::from_millis(4);
    let limits = Limits { shed_lag: Some(Duration::from_millis(12)), inline_budget: None, ..Limits::default() };
    let h = simoom::Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(limits)
        .service(move |_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            spin(work);
            r.body_static(b"done")
        })
        .start()
        .unwrap();
    // 40 requests of 4 ms each on one loop: 160 ms of work arriving at once.
    let res = burst(&h, 40);
    let ok: Vec<Duration> = res.iter().filter(|r| r.0 == 200).map(|r| r.1).collect();
    let shed = res.iter().filter(|r| r.0 == 503).count();
    assert_eq!(ok.len() + shed, res.len(), "only 200 and 503: {res:?}");
    assert!(!ok.is_empty() && shed >= 10, "admitted {} shed {shed}: {res:?}", ok.len());
    // Without shedding the last answers would wait about 160 ms.
    let worst = ok.iter().max().unwrap();
    assert!(*worst < Duration::from_millis(100), "admitted requests kept their latency: worst {worst:?}");
    assert_eq!(h.stats().shed as usize, shed);
}

#[test]
fn without_admission_control_every_request_is_served() {
    let limits = Limits { shed_lag: None, inline_budget: None, ..Limits::default() };
    let h = simoom::Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(limits)
        .service(|_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            spin(Duration::from_millis(2));
            r.body_static(b"done")
        })
        .start()
        .unwrap();
    let res = burst(&h, 20);
    assert!(res.iter().all(|r| r.0 == 200), "{res:?}");
    assert_eq!(h.stats().shed, 0);
}
