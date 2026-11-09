//! A wave of slowloris connections timing out together is closed in paced batches (most reset
//! without a 408) while legitimate requests keep being served.

mod common;

use common::*;
use simoom::{Limits, Outcome, Reply, Request};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[test]
fn a_slowloris_wave_is_closed_in_paced_batches() {
    let limits = Limits { head_timeout: Duration::from_millis(300), ..Limits::default() };
    let h = simoom::Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(limits)
        .service(|_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body_static(b"ok") })
        .start()
        .unwrap();
    let n = 300;
    let mut loris: Vec<_> = (0..n)
        .map(|_| {
            let mut s = connect(&h);
            s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nX-Slow:").unwrap();
            s
        })
        .collect();
    // A legitimate client keeps working through the wave.
    let mut c = Client::new(&h);
    let t0 = Instant::now();
    let mut worst = Duration::ZERO;
    while t0.elapsed() < Duration::from_millis(1800) {
        let t = Instant::now();
        assert_eq!(c.get("/").status, 200);
        worst = worst.max(t.elapsed());
        std::thread::sleep(Duration::from_millis(5));
    }
    // Every attacker is gone: a few got a 408, the rest were reset.
    let (mut answered, mut reset) = (0, 0);
    for s in loris.iter_mut() {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 256];
        match s.read(&mut buf) {
            Ok(k) if k > 0 => {
                assert!(buf[..k].starts_with(b"HTTP/1.1 408"));
                answered += 1;
            }
            Ok(_) | Err(_) => reset += 1,
        }
    }
    assert_eq!(answered + reset, n);
    // How many fall in one 10 ms window (and so are reset) depends on how fast the client
    // opened them; the pacing itself is checked by the unit test in util.rs.
    assert!(h.stats().timeouts as usize >= n, "{:?}", h.stats());
    eprintln!("worst legitimate request during the wave: {worst:?}; {answered} answered 408, {reset} reset");
    assert!(worst < Duration::from_secs(1), "worst {worst:?}");
}
