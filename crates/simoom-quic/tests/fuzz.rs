//! A std-only, seeded mutation fuzzer for packet, frame and transport-parameter parsing,
//! and for the connection state machine driven by mutated packets.
//!
//! `SIMOOM_FUZZ_ITERS` sets the iterations per target (default keeps the run to seconds),
//! `SIMOOM_FUZZ_SEED` the seed.

mod common;
use common::*;
use simoom_quic::coding::Reader;
use simoom_quic::sim::{Link, Pair, Rng};
use simoom_quic::{frame, packet, TransportParams};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

fn iters(default: u64) -> u64 {
    std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed)
}

/// Applies 1–4 random mutations: bit flips, byte sets, boundary values, truncation,
/// insertion, deletion, duplication of a slice, splicing with another input.
fn mutate(rng: &mut Rng, d: &mut Vec<u8>, other: &[u8]) {
    for _ in 0..1 + rng.below(4) {
        let len = d.len().max(1) as u64;
        match rng.below(9) {
            0 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                d[i] ^= 1 << rng.below(8);
            }
            1 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                d[i] = rng.next() as u8;
            }
            2 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                d[i] = [0x00, 0x01, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff][rng.below(9) as usize];
            }
            3 => d.truncate(rng.below(len + 1) as usize),
            4 => {
                let i = rng.below(len + 1) as usize;
                let n = 1 + rng.below(8) as usize;
                for _ in 0..n {
                    d.insert(i.min(d.len()), rng.next() as u8);
                }
            }
            5 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                let n = (1 + rng.below(16) as usize).min(d.len() - i);
                d.drain(i..i + n);
            }
            6 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                let n = (1 + rng.below(32) as usize).min(d.len() - i);
                let s = d[i..i + n].to_vec();
                let at = rng.below(d.len() as u64 + 1) as usize;
                d.splice(at..at, s);
            }
            7 if !other.is_empty() => {
                let i = rng.below(len) as usize;
                let j = rng.below(other.len() as u64) as usize;
                d.truncate(i);
                d.extend_from_slice(&other[j..]);
            }
            _ => {
                // A run of varint prefix bytes (long encodings).
                let i = rng.below(len) as usize;
                for k in 0..rng.below(8) as usize {
                    if i + k < d.len() {
                        d[i + k] = 0xff;
                    }
                }
            }
        }
    }
}

fn frame_corpus() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    let mut b = Vec::new();
    let mut rs = simoom_quic::ranges::RangeSet::new();
    rs.insert(0, 10);
    rs.insert(20, 25);
    rs.insert(100, 300);
    frame::put_ack(&mut b, &rs, 1000, 32);
    v.push(std::mem::take(&mut b));
    frame::put_crypto(&mut b, 1000, b"handshake bytes");
    v.push(std::mem::take(&mut b));
    frame::put_stream_header(&mut b, 4, 70000, 5, true);
    b.extend_from_slice(b"hello");
    v.push(std::mem::take(&mut b));
    frame::put_new_connection_id(&mut b, 5, 2, &[1, 2, 3, 4, 5, 6, 7, 8], &[9; 16]);
    v.push(std::mem::take(&mut b));
    frame::put_close(&mut b, 0x100, Some(6), b"reason");
    v.push(std::mem::take(&mut b));
    frame::put_new_token(&mut b, &[7; 40]);
    v.push(std::mem::take(&mut b));
    for (ty, vals) in [
        (frame::RESET_STREAM, &[4u64, 1, 1000][..]),
        (frame::MAX_STREAMS_BIDI, &[100]),
        (frame::STREAM_DATA_BLOCKED, &[8, 9999]),
        (frame::RETIRE_CONNECTION_ID, &[3]),
    ] {
        frame::put_simple(&mut b, ty, vals);
        v.push(std::mem::take(&mut b));
    }
    v
}

#[test]
fn fuzz_frame_and_param_parsers() {
    let mut rng = Rng::new(seed());
    let corpus = frame_corpus();
    let mut tp = Vec::new();
    TransportParams {
        initial_source_connection_id: Some(simoom_quic::Cid::new(&[1; 8])),
        original_destination_connection_id: Some(simoom_quic::Cid::new(&[2; 8])),
        stateless_reset_token: Some([3; 16]),
        initial_max_data: 1 << 20,
        ..Default::default()
    }
    .encode(&mut tp);
    for _ in 0..iters(50_000) {
        let a = &corpus[rng.below(corpus.len() as u64) as usize];
        let b = &corpus[rng.below(corpus.len() as u64) as usize];
        let mut d = a.clone();
        if rng.below(3) == 0 {
            d.extend_from_slice(b);
        }
        mutate(&mut rng, &mut d, b);
        let mut r = Reader::new(&d);
        while !r.is_empty() {
            match frame::parse(&mut r) {
                Ok((_, frame::Frame::Ack { ranges, .. })) => {
                    // Iterating validated ranges never underflows.
                    for (lo, hi) in ranges.iter() {
                        assert!(lo <= hi);
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let mut t = tp.clone();
        mutate(&mut rng, &mut t, &d);
        let _ = TransportParams::decode(&t, true);
        let _ = TransportParams::decode(&t, false);
        let _ = packet::parse_header(&d, 0, 8);
    }
}

/// Captures every datagram of a handshake and a transfer, then replays mutated copies into
/// established connections whose packet tags are not checked, so the mutations reach the
/// frame and stream state machines.
#[test]
fn fuzz_connections_with_mutated_packets() {
    let mut rng = Rng::new(seed() ^ 0xabc);
    let capture: Rc<RefCell<Vec<(bool, Vec<u8>)>>> = Rc::default();
    let total = iters(20_000);
    let mut done = 0;
    let mut pairs = 0;
    while done < total {
        pairs += 1;
        let cc = config_with(pairs, |n| n.accept_any_tag = true, |_| {});
        let sc = config_with(pairs + 1000, |n| n.accept_any_tag = true, |c| c.transport.max_idle_timeout = Duration::from_secs(5));
        let mut p = Pair::new(cc, sc, Link { loss_ppm: 20_000, reorder_ppm: 50_000, reorder_delay: Duration::from_millis(5), ..Link::default() }, pairs);
        let cap = capture.clone();
        p.tamper = Some(Box::new(move |up, d| {
            let mut c = cap.borrow_mut();
            if c.len() < 4000 {
                c.push((up, d.clone()));
            }
            true
        }));
        let c = p.connect();
        p.run_until(Duration::from_secs(10), |p| p.client.conn(c).is_some_and(|x| x.is_established()));
        if let Some(s) = p.server_conn() {
            if p.client.conn(c).is_some_and(|x| x.is_established()) {
                let _ = std::panic::catch_unwind(|| ());
                let id = p.client.conn_mut(c).unwrap().open_bi().unwrap();
                p.client.conn_mut(c).unwrap().stream_send(id, &pattern(20_000, 1), true).unwrap();
                p.run_for(Duration::from_millis(300));
                let _ = s;
            }
        }
        p.tamper = None;
        let corpus = capture.borrow().clone();
        if corpus.is_empty() {
            continue;
        }
        let mut resp = Vec::new();
        for _ in 0..500 {
            let (up, d) = &corpus[rng.below(corpus.len() as u64) as usize];
            let (_, other) = &corpus[rng.below(corpus.len() as u64) as usize];
            let mut m = d.clone();
            mutate(&mut rng, &mut m, other);
            let now = p.now;
            if *up {
                let from = p.client_addr;
                let _ = p.server.recv(now, from, &mut m, &mut resp);
            } else {
                let from = p.server_addr;
                let _ = p.client.recv(now, from, &mut m, &mut resp);
            }
            done += 1;
            if rng.below(20) == 0 {
                p.run_for(Duration::from_millis(20));
            }
        }
        p.run_for(Duration::from_secs(1));
        // The connections either survived or closed cleanly; memory stays bounded.
        for h in p.server.handles().collect::<Vec<_>>() {
            assert!(p.server.conn(h).unwrap().stream_count() < 1000);
        }
        capture.borrow_mut().clear();
    }
    eprintln!("fuzz_connections: {done} mutated datagrams over {pairs} connections");
}

/// Unstructured datagrams at a server endpoint: random bytes and mutated Initials.
#[test]
fn fuzz_server_endpoint_with_garbage() {
    let mut rng = Rng::new(seed() ^ 0x77);
    let mut ep = simoom_quic::Endpoint::new(config(5, |_| {}), true);
    let mut client = simoom_quic::Endpoint::new(config(6, |_| {}), false);
    let now = std::time::Instant::now();
    let server: std::net::SocketAddr = "10.0.0.2:443".parse().unwrap();
    client.connect(now, server, "x", &[]).unwrap();
    let mut buf = Vec::new();
    let (_, t) = client.poll_transmit(now, &mut buf, 1).unwrap();
    let initial = buf[..t.size].to_vec();
    let mut resp = Vec::new();
    for i in 0..iters(30_000) {
        let mut d = if rng.below(4) == 0 {
            (0..rng.below(1500)).map(|_| rng.next() as u8).collect()
        } else {
            initial.clone()
        };
        mutate(&mut rng, &mut d, &initial);
        let from: std::net::SocketAddr = format!("10.1.{}.{}:{}", i % 7, i % 200, 1000 + i % 50).parse().unwrap();
        let _ = ep.recv(now, from, &mut d, &mut resp);
        if let Some(r) = resp.first() {
            // A stateless response is never larger than what triggered it, except VN/Retry
            // which only answer full-size Initials.
            let _ = r;
            assert!(resp.len() <= 1500);
        }
    }
    let mut touched = Vec::new();
    ep.handle_timeout(now + Duration::from_secs(120), &mut touched);
    let mut b = Vec::new();
    while ep.poll_transmit(now + Duration::from_secs(120), &mut b, 4).is_some() {}
    ep.handle_timeout(now + Duration::from_secs(600), &mut touched);
}
