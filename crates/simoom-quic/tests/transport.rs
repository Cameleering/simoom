//! End-to-end transport tests over the deterministic in-memory network.

mod common;
use common::*;
use simoom_quic::sim::{Link, Pair};
use simoom_quic::{ConnectionError, Event, StreamError, VERSION_2};
use std::time::Duration;

const MIN: Duration = Duration::from_secs(60);

fn lossy() -> Link {
    Link {
        delay: Duration::from_millis(15),
        jitter: Duration::from_millis(5),
        loss_ppm: 50_000,
        duplicate_ppm: 20_000,
        reorder_ppm: 100_000,
        reorder_delay: Duration::from_millis(30),
        ..Link::default()
    }
}

fn closed_event(p: &mut simoom_quic::Endpoint, h: simoom_quic::ConnHandle, out: &mut Option<ConnectionError>) {
    while let Some(e) = p.poll_event(h) {
        if let Event::Closed(err) = e {
            *out = Some(err);
        }
    }
}

#[test]
fn handshake_completes_and_negotiates_alpn() {
    let mut p = pair(Link::default(), 1);
    let t0 = p.now;
    let (c, s) = handshake(&mut p);
    // One round trip (20 ms) and a half: well under a second.
    assert!(p.now - t0 < Duration::from_millis(100), "{:?}", p.now - t0);
    let (ce, se) = events(&mut p, c, s);
    assert!(ce.contains(&Event::Connected), "{ce:?}");
    assert!(se.contains(&Event::Connected), "{se:?}");
    assert_eq!(p.client.conn(c).unwrap().alpn(), Some(&b"h3"[..]));
    assert_eq!(p.server.conn(s).unwrap().alpn(), Some(&b"h3"[..]));
    assert!(p.server.conn(s).unwrap().path_validated());
    assert_eq!(p.client.conn(c).unwrap().peer_params().unwrap().initial_max_streams_bidi, 100);
}

#[test]
fn echo_small_and_large() {
    for (seed, size) in [(2, 10), (3, 3 << 20)] {
        let mut p = pair(Link::default(), seed);
        let (c, s) = handshake(&mut p);
        echo_on(&mut p, c, s, size, MIN);
        let st = p.client.conn(c).unwrap().stats();
        assert_eq!(st.lost_packets, 0);
        if size > 1 << 20 {
            assert_eq!(st.mtu, 1452, "PMTU probing reached the configured size");
        }
    }
}

#[test]
fn reliable_delivery_under_loss_duplication_and_reordering() {
    for seed in 10..16 {
        let mut p = pair(lossy(), seed);
        let (c, s) = handshake(&mut p);
        echo_on(&mut p, c, s, 400_000, MIN * 5);
        let lost = p.client.conn(c).unwrap().stats().lost_packets + p.server.conn(s).unwrap().stats().lost_packets;
        assert!(lost > 0, "seed {seed}: the link dropped packets, so some must be declared lost");
        assert!(p.to_server_stats.duplicated + p.to_client_stats.duplicated > 0);
    }
}

#[test]
fn handshake_survives_heavy_loss_with_multi_packet_flights() {
    for seed in 20..30 {
        let link = Link { loss_ppm: 250_000, ..Link::default() };
        let cc = config_with(seed, |n| n.hello_padding = 3000, |_| {});
        let sc = config_with(seed + 100, |n| n.server_flight = 5000, |_| {});
        let mut p = Pair::new(cc, sc, link, seed);
        let (c, s) = handshake(&mut p);
        echo_on(&mut p, c, s, 20_000, MIN * 5);
    }
}

#[test]
fn many_concurrent_streams() {
    let mut p = pair(lossy(), 40);
    let (c, s) = handshake(&mut p);
    let n = 40;
    let ids: Vec<u64> = (0..n).map(|_| p.client.conn_mut(c).unwrap().open_bi().unwrap()).collect();
    let datas: Vec<Vec<u8>> = (0..n).map(|i| pattern(5000 + i * 300, i as u8)).collect();
    let mut offs = vec![0usize; n];
    let mut got: Vec<Vec<u8>> = vec![Vec::new(); n];
    let mut done = vec![false; n];
    let ok = p.run_until(MIN * 5, |p| {
        for i in 0..n {
            write_some(&mut p.client, c, ids[i], &datas[i], &mut offs[i]);
            if !done[i] {
                done[i] = read_all(&mut p.server, s, ids[i], &mut got[i]);
            }
        }
        done.iter().all(|d| *d)
    });
    assert!(ok);
    assert_eq!(got, datas);
}

#[test]
fn congestion_control_backs_off_at_a_bottleneck() {
    // 1 MB/s bottleneck with a 30 KB queue and 20 ms RTT: NewReno must see losses, back
    // off, and still use most of the link.
    let link = Link { delay: Duration::from_millis(10), bandwidth: Some(1_000_000), queue: 30_000, ..Link::default() };
    let mut p = pair(link, 50);
    let (c, s) = handshake(&mut p);
    let start = p.now;
    let size = 3_000_000;
    let data = pattern(size, 1);
    let id = p.client.conn_mut(c).unwrap().open_uni().unwrap();
    let mut off = 0;
    let mut got = Vec::new();
    let mut max_cwnd = 0;
    let ok = p.run_until(MIN * 5, |p| {
        write_some(&mut p.client, c, id, &data, &mut off);
        max_cwnd = max_cwnd.max(p.client.conn(c).unwrap().stats().cwnd);
        read_all(&mut p.server, s, id, &mut got)
    });
    assert!(ok);
    assert_eq!(got, data);
    let secs = (p.now - start).as_secs_f64();
    let st = p.client.conn(c).unwrap().stats();
    assert!(st.lost_packets > 0, "the queue overflowed, so packets were lost");
    let goodput = size as f64 / secs;
    assert!(goodput > 600_000.0, "goodput {goodput:.0} B/s on a 1 MB/s link");
    assert!(max_cwnd < 400_000, "cwnd grew to {max_cwnd}");
}

#[test]
fn amplification_limit_before_address_validation() {
    // The server's flight is large; the client goes silent after its first Initial. The
    // server may send at most 3x what it received until the address is validated.
    let cc = config_with(60, |_| {}, |_| {});
    let sc = config_with(61, |n| n.server_flight = 20_000, |_| {});
    let mut p = Pair::new(cc, sc, Link::default(), 60);
    let mut to_server = 0;
    p.tamper = Some(Box::new(move |up, _d| {
        if up {
            to_server += 1;
            return to_server == 1;
        }
        true
    }));
    let _c = p.connect();
    p.run_for(Duration::from_secs(5));
    let received = 1200u64;
    let sent = p.to_client_stats.bytes;
    assert!(sent > 0);
    assert!(sent <= 3 * received, "server sent {sent} bytes for {received} received");
    p.tamper = None;
    let ok = p.run_until(MIN, |p| p.server_conn().and_then(|s| p.server.conn(s)).is_some_and(|x| x.is_established()));
    assert!(ok);
}

#[test]
fn retry_validates_the_address() {
    let cc = config(70, |_| {});
    let sc = config(71, |c| c.retry = true);
    let mut p = Pair::new(cc, sc, Link::default(), 70);
    let (c, s) = handshake(&mut p);
    assert!(p.server.conn(s).unwrap().path_validated());
    echo_on(&mut p, c, s, 10_000, MIN);
    assert_eq!(p.accepted.len(), 1);
}

#[test]
fn retry_with_a_forged_token_is_dropped() {
    let cc = config(72, |_| {});
    let sc = config(73, |c| c.retry = true);
    let mut p = Pair::new(cc, sc, Link::default(), 72);
    let mut seen_retry = false;
    p.tamper = Some(Box::new(move |up, d| {
        if !up && d[0] & 0xf0 == 0xf0 {
            seen_retry = true;
        } else if up && seen_retry && d[0] & 0xf0 == 0xc0 {
            // 1 + 4 + 1 + dcid + 1 + scid, then the token length (one byte for < 64).
            let dl = d[5] as usize;
            let sl = d[6 + dl] as usize;
            let tl_at = 7 + dl + sl;
            if d[tl_at] > 0 && d[tl_at] < 64 {
                let tl = d[tl_at] as usize;
                d[tl_at + tl] ^= 1;
            }
        }
        true
    }));
    let c = p.connect();
    p.run_for(Duration::from_secs(3));
    assert!(p.accepted.is_empty(), "no connection for a forged token");
    assert!(!p.client.conn(c).unwrap().is_established());
}

#[test]
fn stateless_reset_after_server_state_loss() {
    let cc = config(80, |_| {});
    let sc = config(81, |c| c.reset_key = [7; 32]);
    let mut p = Pair::new(cc, sc.clone(), Link::default(), 80);
    let (c, _s) = handshake(&mut p);
    p.run_for(Duration::from_millis(200));
    p.server = simoom_quic::Endpoint::new(sc, true);
    let id = p.client.conn_mut(c).unwrap().open_bi().unwrap();
    p.client.conn_mut(c).unwrap().stream_send(id, b"hello", true).unwrap();
    let mut closed = None;
    p.run_until(MIN, |p| {
        closed_event(&mut p.client, c, &mut closed);
        closed.is_some()
    });
    assert_eq!(closed, Some(ConnectionError::StatelessReset));
}

#[test]
fn nat_rebinding_migrates_with_path_validation() {
    let mut p = pair(Link::default(), 90);
    let (c, s) = handshake(&mut p);
    echo_on(&mut p, c, s, 50_000, MIN);
    let new_addr = "10.0.0.9:6000".parse().unwrap();
    p.rebind_client(new_addr);
    echo_on(&mut p, c, s, 200_000, MIN);
    let sc = p.server.conn(s).unwrap();
    assert_eq!(sc.remote_address(), new_addr);
    assert!(sc.path_validated());
    let (_, se) = events(&mut p, c, s);
    assert!(se.contains(&Event::PathMigrated(new_addr)), "{se:?}");
}

#[test]
fn connection_id_rotation_and_retirement() {
    let mut p = pair(Link::default(), 100);
    let (c, s) = handshake(&mut p);
    p.run_for(Duration::from_millis(200));
    assert_eq!(p.server.conn(s).unwrap().local_cids().count(), 4, "server issued up to the limit");
    let first = p.client.conn(c).unwrap().remote_cid();
    for _ in 0..6 {
        assert!(p.client.conn_mut(c).unwrap().rotate_remote_cid());
        echo_on(&mut p, c, s, 2_000, MIN);
        p.run_for(Duration::from_millis(100));
    }
    assert_ne!(p.client.conn(c).unwrap().remote_cid(), first);
    assert_eq!(p.server.conn(s).unwrap().local_cids().count(), 4);
}

#[test]
fn stream_limits_and_streams_available() {
    let sc = config(110, |c| c.transport.max_streams_bidi = 4);
    let mut p = Pair::new(config(111, |_| {}), sc, Link::default(), 110);
    let (c, s) = handshake(&mut p);
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(p.client.conn_mut(c).unwrap().open_bi().unwrap());
    }
    assert_eq!(p.client.conn_mut(c).unwrap().open_bi(), Err(StreamError::LimitReached));
    for &id in &ids {
        p.client.conn_mut(c).unwrap().stream_send(id, b"x", true).unwrap();
    }
    let mut available = false;
    let mut answered = [false; 4];
    p.run_until(MIN, |p| {
        for (i, &id) in ids.iter().enumerate() {
            let mut v = Vec::new();
            if !answered[i] && read_all(&mut p.server, s, id, &mut v) {
                answered[i] = true;
                let _ = p.server.conn_mut(s).unwrap().stream_finish(id);
            }
            let mut w = Vec::new();
            read_all(&mut p.client, c, id, &mut w);
        }
        while let Some(e) = p.client.poll_event(c) {
            available |= e == Event::StreamsAvailable(true);
        }
        available
    });
    assert!(available);
    assert!(p.client.conn_mut(c).unwrap().open_bi().is_ok());
}

#[test]
fn flow_control_backpressure_and_window_updates() {
    let sc = config(120, |c| {
        c.transport.max_data = 64 * 1024;
        c.transport.stream_window_bidi_remote = 16 * 1024;
    });
    let mut p = Pair::new(config(121, |_| {}), sc, Link::default(), 120);
    let (c, s) = handshake(&mut p);
    let id = p.client.conn_mut(c).unwrap().open_bi().unwrap();
    let big = pattern(100_000, 3);
    let n = p.client.conn_mut(c).unwrap().stream_send(id, &big, false).unwrap();
    assert_eq!(n, 16 * 1024, "accepted only up to the peer's stream window");
    assert_eq!(p.client.conn_mut(c).unwrap().stream_send(id, &big[n..], false), Err(StreamError::Blocked));
    echo_on(&mut p, c, s, 300_000, MIN);
}

#[test]
fn stop_sending_and_reset_stream() {
    let mut p = pair(Link::default(), 130);
    let (c, s) = handshake(&mut p);
    let a = p.client.conn_mut(c).unwrap().open_bi().unwrap();
    p.client.conn_mut(c).unwrap().stream_send(a, b"some data", false).unwrap();
    p.run_for(Duration::from_millis(100));
    p.server.conn_mut(s).unwrap().stream_stop(a, 7).unwrap();
    let mut stopped = false;
    p.run_until(MIN, |p| {
        while let Some(e) = p.client.poll_event(c) {
            stopped |= e == Event::StreamStopped { id: a, code: 7 };
        }
        stopped
    });
    assert!(stopped);
    assert_eq!(p.client.conn_mut(c).unwrap().stream_send(a, b"more", false), Err(StreamError::Stopped(7)));
    let b = p.client.conn_mut(c).unwrap().open_uni().unwrap();
    p.client.conn_mut(c).unwrap().stream_send(b, b"partial", false).unwrap();
    p.run_for(Duration::from_millis(100));
    p.client.conn_mut(c).unwrap().stream_reset(b, 9).unwrap();
    let mut reset_seen = false;
    p.run_until(MIN, |p| {
        while let Some(e) = p.server.poll_event(s) {
            reset_seen |= e == Event::StreamReset { id: b, code: 9 };
        }
        reset_seen
    });
    assert!(reset_seen);
    let mut buf = [0u8; 64];
    assert_eq!(p.server.conn_mut(s).unwrap().stream_recv(b, &mut buf), Err(StreamError::Reset(9)));
}

#[test]
fn application_close_reaches_the_peer_and_both_drain() {
    let mut p = pair(Link::default(), 140);
    let (c, s) = handshake(&mut p);
    let now = p.now;
    p.client.conn_mut(c).unwrap().close(now, 42, b"bye");
    let mut peer_err = None;
    p.run_until(MIN, |p| {
        closed_event(&mut p.server, s, &mut peer_err);
        peer_err.is_some()
    });
    assert_eq!(peer_err, Some(ConnectionError::PeerApplication { code: 42, reason: b"bye".to_vec() }));
    p.run_until(MIN, |p| {
        let _ = events(p, c, s);
        p.client.is_empty() && p.server.is_empty()
    });
    assert!(p.client.is_empty() && p.server.is_empty(), "both connections drained and were removed");
}

#[test]
fn idle_timeout_closes_silently() {
    let cc = config(150, |c| c.transport.max_idle_timeout = Duration::from_secs(5));
    let mut p = Pair::new(cc, config(151, |_| {}), Link::default(), 150);
    let (c, s) = handshake(&mut p);
    let t0 = p.now;
    let (mut a, mut b) = (None, None);
    p.run_until(MIN, |p| {
        closed_event(&mut p.client, c, &mut a);
        closed_event(&mut p.server, s, &mut b);
        a.is_some() && b.is_some()
    });
    assert_eq!(a, Some(ConnectionError::IdleTimeout));
    assert_eq!(b, Some(ConnectionError::IdleTimeout));
    let took = p.now - t0;
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(7), "{took:?}");
}

#[test]
fn key_updates_during_transfer() {
    let cc = config(160, |c| c.transport.key_update_interval = Some(100));
    let mut p = Pair::new(cc, config(161, |_| {}), lossy(), 160);
    let (c, s) = handshake(&mut p);
    echo_on(&mut p, c, s, 1_000_000, MIN * 5);
    let ck = p.client.conn(c).unwrap().stats().key_updates;
    let sk = p.server.conn(s).unwrap().stats().key_updates;
    assert!(ck >= 5, "client updated keys {ck} times");
    assert!(sk >= 5, "server followed {sk} updates");
}

#[test]
fn version_negotiation_for_an_unknown_version() {
    let cc = config(170, |c| c.versions = vec![0x5a5a_5a5a]);
    let mut p = Pair::new(cc, config(171, |_| {}), Link::default(), 170);
    let c = p.connect();
    let mut err = None;
    p.run_until(MIN, |p| {
        closed_event(&mut p.client, c, &mut err);
        err.is_some()
    });
    assert_eq!(err, Some(ConnectionError::VersionMismatch));
}

#[test]
fn quic_version_2_handshake_and_transfer() {
    let cc = config(180, |c| c.versions = vec![VERSION_2]);
    let sc = config(181, |c| c.versions = vec![simoom_quic::VERSION_1, VERSION_2]);
    let mut p = Pair::new(cc, sc, Link::default(), 180);
    let (c, s) = handshake(&mut p);
    assert_eq!(p.server.conn(s).unwrap().version(), VERSION_2);
    echo_on(&mut p, c, s, 100_000, MIN);
}

#[test]
fn new_token_skips_retry_on_the_next_connection() {
    let sc = config(190, |c| {
        c.retry = true;
        c.new_token_lifetime = Some(Duration::from_secs(3600));
    });
    let mut p = Pair::new(config(191, |_| {}), sc, Link::default(), 190);
    let (c, _s) = handshake(&mut p);
    let ok = p.run_until(MIN, |p| p.client.conn(c).unwrap().new_token().is_some());
    assert!(ok, "client received NEW_TOKEN");
    let token = p.client.conn(c).unwrap().new_token().unwrap().to_vec();
    let counter = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let c2 = counter.clone();
    p.tamper = Some(Box::new(move |up, d| {
        if !up && d[0] & 0xf0 == 0xf0 {
            c2.set(c2.get() + 1);
        }
        true
    }));
    let (addr, now) = (p.server_addr, p.now);
    let h2 = p.client.connect(now, addr, "localhost", &token).unwrap();
    let ok = p.run_until(MIN, |p| p.client.conn(h2).unwrap().is_established());
    assert!(ok);
    assert_eq!(counter.get(), 0, "a valid NEW_TOKEN skips the Retry");
}

#[test]
fn transmit_batches_for_gso() {
    let mut p = pair(Link::default(), 200);
    let (c, _s) = handshake(&mut p);
    p.run_for(Duration::from_millis(300));
    let id = p.client.conn_mut(c).unwrap().open_uni().unwrap();
    p.client.conn_mut(c).unwrap().stream_send(id, &pattern(50_000, 1), true).unwrap();
    let mut buf = Vec::new();
    let now = p.now;
    let (_, t) = p.client.poll_transmit(now, &mut buf, 8).unwrap();
    let seg = t.segment_size.expect("several datagrams in one batch");
    assert!(t.size > seg && t.size <= 8 * seg);
    assert_eq!(seg, p.client.conn(c).unwrap().stats().mtu);
}

#[test]
fn rfc9001_appendix_a2_unprotected_client_initial_header() {
    let hdr = [
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e,
        0x00, 0x00, 0x00, 0x02,
    ];
    let mut d = hdr.to_vec();
    d.resize(18 + 0x049e, 0);
    let h = simoom_quic::packet::parse_header(&d, 0, 8).unwrap();
    assert_eq!(h.ty, simoom_quic::packet::PacketType::Initial);
    assert_eq!(&d[h.dcid.clone()], &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
    assert!(h.scid.is_empty() && h.token.is_empty());
    assert_eq!(h.pn_offset, 18);
    assert_eq!(h.end, 18 + 0x049e);
    assert_eq!(u32::from_be_bytes(d[18..22].try_into().unwrap()), 2);
}

/// The QUIC Interop Runner's `blackhole` case: a 10 MB download at 10 Mbit/s with a 25-packet
/// queue while the link goes dark in both directions for 2 s after every 5 s. The transfer must
/// recover after each blackout (PTO probes, then normal sending) and finish.
#[test]
fn transfer_survives_repeated_blackouts() {
    use std::cell::Cell;
    use std::rc::Rc;
    let link = Link { delay: Duration::from_millis(15), bandwidth: Some(10_000_000 / 8), queue: 25 * 1500, ..Link::default() };
    for seed in [90, 91] {
        let mut p = Pair::new(
            config(seed, |c| c.transport.max_idle_timeout = Duration::from_secs(30)),
            config(seed + 1, |c| c.transport.max_idle_timeout = Duration::from_secs(30)),
            link.clone(),
            seed,
        );
        let (c, s) = handshake(&mut p);
        let dark = Rc::new(Cell::new(false));
        let d2 = dark.clone();
        p.tamper = Some(Box::new(move |_, _| !d2.get()));
        let data = pattern(10 << 20, 7);
        let id = p.client.conn_mut(c).unwrap().open_bi().unwrap();
        p.client.conn_mut(c).unwrap().stream_finish(id).unwrap();
        let t0 = p.now;
        let mut off = 0;
        let mut got = Vec::new();
        let mut opened = false;
        let ok = p.run_until(Duration::from_secs(120), |p| {
            let t = (p.now - t0).as_millis() % 7000;
            dark.set(t >= 5000);
            if !opened {
                let mut buf = [0u8; 16];
                opened = matches!(p.server.conn_mut(s).unwrap().stream_recv(id, &mut buf), Ok((_, true)));
            }
            if opened {
                write_some(&mut p.server, s, id, &data, &mut off);
            }
            let mut closed = None;
            let fin = read_all(&mut p.client, c, id, &mut got);
            closed_event(&mut p.client, c, &mut closed);
            assert!(closed.is_none(), "seed {seed}: client connection closed after {} bytes: {closed:?}", got.len());
            fin
        });
        assert!(ok, "seed {seed}: download stalled at {} of {} bytes after {:?}", got.len(), data.len(), p.now - t0);
        assert!(got == data, "seed {seed}: corrupted download");
    }
}
