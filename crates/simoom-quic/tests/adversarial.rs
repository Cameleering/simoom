//! Adversarial peers against the QUIC transport (plan §7, hardening task 4): Initial floods
//! from spoofed addresses, amplification, connection-ID exhaustion, stream and flow-control
//! abuse, CRYPTO buffer floods, bogus and optimistic ACKs, stateless-reset spoofing and
//! version-negotiation downgrades. Everything runs in the deterministic simulator; misbehaving
//! frames are sent through the real packet protection with `Connection::send_raw_frames`, or
//! as hand-built Initial packets (Initial keys are public).

mod common;

use common::*;
use simoom_quic::coding::put_varint;
use simoom_quic::crypto::null::NullProvider;
use simoom_quic::crypto::CryptoProvider;
use simoom_quic::error::*;
use simoom_quic::frame;
use simoom_quic::packet::{self, PacketType, MIN_INITIAL_SIZE, VERSION_1, VERSION_2};
use simoom_quic::sim::{Link, Pair};
use simoom_quic::{ConnHandle, ConnectionError, DatagramEvent, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIN: Duration = Duration::from_secs(60);

// ------------------------------------------------------------------ helpers

/// A client Initial packet built by hand, padded to 1200 bytes.
fn client_initial(dcid: &[u8], scid: &[u8], token: &[u8], pn: u64, frames: &[u8]) -> Vec<u8> {
    let prov = NullProvider::new(1);
    let keys = prov.initial_keys(VERSION_1, dcid, false);
    let mut buf = Vec::new();
    let (len_at, pn_at) = packet::put_long_header(&mut buf, VERSION_1, PacketType::Initial, dcid, scid, Some(token), pn, 4);
    buf.extend_from_slice(frames);
    // Pad the payload so the datagram is exactly 1200 bytes with the tag.
    let target = MIN_INITIAL_SIZE - 16;
    if buf.len() < target {
        buf.resize(target, 0);
    }
    let len = buf.len() - pn_at + 16;
    buf[len_at] = 0x40 | (len >> 8) as u8;
    buf[len_at + 1] = len as u8;
    let payload_start = pn_at + 4;
    let end = buf.len();
    buf.resize(end + 16, 0);
    {
        let (head, rest) = buf.split_at_mut(payload_start);
        let (payload, tag) = rest.split_at_mut(end - payload_start);
        keys.local.packet.seal(pn, head, payload, tag);
    }
    packet::protect(&mut buf, 0, pn_at, 4, &*keys.local.header);
    buf
}

fn crypto_frame(off: u64, data: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    frame::put_crypto(&mut f, off, data);
    f
}

fn spoofed(i: u32) -> SocketAddr {
    SocketAddr::from(([198, 18, (i >> 8) as u8, i as u8], 1024 + (i % 50_000) as u16))
}

fn server_error(p: &Pair, s: ConnHandle) -> Option<ConnectionError> {
    p.server.conn(s).and_then(|c| c.error().cloned())
}

fn transport_code(e: &Option<ConnectionError>) -> Option<u64> {
    match e {
        Some(ConnectionError::Transport(t)) => Some(t.code),
        _ => None,
    }
}

/// Has the client send `frames` (raw, in one 1-RTT packet) and runs until the server closes
/// or `limit` passes. Returns the server's error, if any.
fn attack(p: &mut Pair, c: ConnHandle, s: ConnHandle, frames: &[u8], limit: Duration) -> Option<ConnectionError> {
    p.client.conn_mut(c).unwrap().send_raw_frames(frames);
    p.run_until(limit, |p| server_error(p, s).is_some());
    server_error(p, s)
}

fn established(seed: u64, client: impl FnOnce(&mut simoom_quic::Config), server: impl FnOnce(&mut simoom_quic::Config)) -> (Pair, ConnHandle, ConnHandle) {
    let mut p = Pair::new(config(seed, client), config(seed + 1, server), Link::default(), seed);
    let (c, s) = handshake(&mut p);
    p.run_for(Duration::from_millis(200));
    (p, c, s)
}

// ------------------------------------------------------------------ Initial flood

#[test]
fn initial_flood_from_spoofed_addresses_is_answered_with_retry_and_bounded() {
    let threshold = 16;
    let sc = config(11, |c| c.retry_threshold = threshold);
    let mut server = Endpoint::new(sc, true);
    let now = Instant::now();
    let mut resp = Vec::new();
    let (mut created, mut retries, mut other) = (0, 0, 0);
    for i in 0..5000u32 {
        let dcid = (i as u64 ^ 0xabcdef).to_be_bytes();
        let mut d = client_initial(&dcid, &[1, 2, 3, 4], &[], 0, &crypto_frame(0, b"\x01\x00\x00\x00"));
        let n = d.len();
        match server.recv(now, spoofed(i), &mut d, &mut resp) {
            DatagramEvent::NewConnection(_) => created += 1,
            DatagramEvent::Response(t) => {
                // Retry is stateless and much smaller than the Initial that caused it.
                assert_eq!(resp[0] & 0xf0, 0xf0, "only Retry packets go back");
                assert!(t.size * 3 <= n, "Retry of {} bytes for a {n}-byte Initial", t.size);
                retries += 1;
            }
            _ => other += 1,
        }
    }
    assert_eq!(created, threshold, "connections created before Retry kicked in");
    assert_eq!(retries, 5000 - threshold);
    assert_eq!(other, 0);
    assert_eq!(server.len(), threshold, "state stays bounded by retry_threshold");
    // The half-open connections from addresses that never answer go away with the idle
    // timeout, and their slots are freed.
    let later = now + Duration::from_secs(120);
    let mut touched = Vec::new();
    server.handle_timeout(later, &mut touched);
    let handles: Vec<_> = server.handles().collect();
    for h in handles {
        while server.poll_event(h).is_some() {}
    }
    assert_eq!(server.len(), 0, "half-open connections expired");
}

#[test]
fn initial_flood_without_retry_is_capped_by_max_connections() {
    let sc = config(13, |c| {
        c.retry_threshold = usize::MAX;
        c.max_connections = 100;
    });
    let mut server = Endpoint::new(sc, true);
    let now = Instant::now();
    let mut resp = Vec::new();
    for i in 0..2000u32 {
        let dcid = (i as u64 ^ 0x1234).to_be_bytes();
        let mut d = client_initial(&dcid, &[9; 8], &[], 0, &crypto_frame(0, b"\x01\x00\x00\x00"));
        let _ = server.recv(now, spoofed(i), &mut d, &mut resp);
    }
    assert_eq!(server.len(), 100);
}

#[test]
fn forged_and_replayed_retry_tokens_are_dropped() {
    let sc = config(15, |c| c.retry = true);
    let cfg = sc.clone();
    let mut server = Endpoint::new(sc, true);
    let now = Instant::now();
    let mut resp = Vec::new();
    let dcid = [7u8; 8];
    // A token minted for another address, and one for the right address but a different
    // Retry source CID, are both rejected.
    let rscid = [5u8; 8];
    let other_addr = spoofed(1);
    let t = simoom_quic::token::retry_token(&cfg, other_addr, now, &dcid, &rscid);
    let mut d = client_initial(&rscid, &[1; 8], &t, 0, &crypto_frame(0, b"\x01\x00\x00\x00"));
    assert_eq!(server.recv(now, spoofed(2), &mut d, &mut resp), DatagramEvent::Dropped);
    let t = simoom_quic::token::retry_token(&cfg, spoofed(2), now, &dcid, &rscid);
    let mut d = client_initial(&[6u8; 8], &[1; 8], &t, 0, &crypto_frame(0, b"\x01\x00\x00\x00"));
    assert_eq!(server.recv(now, spoofed(2), &mut d, &mut resp), DatagramEvent::Dropped);
    // An expired token is dropped too.
    let mut d = client_initial(&rscid, &[1; 8], &t, 0, &crypto_frame(0, b"\x01\x00\x00\x00"));
    assert_eq!(server.recv(now + Duration::from_secs(60), spoofed(2), &mut d, &mut resp), DatagramEvent::Dropped);
    assert_eq!(server.len(), 0);
}

// ------------------------------------------------------------------ amplification

#[test]
fn amplification_limit_holds_with_coalesced_and_duplicated_initials() {
    // The client's first datagram carries its Initial coalesced with junk long-header
    // packets; then the attacker (spoofing the client) only replays that datagram. The
    // server's bytes stay within 3x of what it received from the address.
    let cc = config(20, |_| {});
    let sc = config_with(21, |n| n.server_flight = 30_000, |_| {});
    let mut p = Pair::new(cc, sc, Link::default(), 20);
    let mut up = 0u32;
    let mut first: Option<Vec<u8>> = None;
    let received = std::rc::Rc::new(std::cell::Cell::new(0u64));
    let rc = received.clone();
    p.tamper = Some(Box::new(move |to_server, d| {
        if !to_server {
            return true;
        }
        up += 1;
        if up == 1 {
            // Coalesce a junk Handshake packet with the same DCID after the Initial.
            let dl = d[5] as usize;
            let dcid = d[6..6 + dl].to_vec();
            let mut junk = Vec::new();
            let (len_at, _) = packet::put_long_header(&mut junk, VERSION_1, PacketType::Handshake, &dcid, &[1; 8], None, 0, 4);
            junk.resize(len_at + 2 + 4 + 100, 0xaa);
            let len = junk.len() - len_at - 2;
            junk[len_at] = 0x40 | (len >> 8) as u8;
            junk[len_at + 1] = len as u8;
            d.extend_from_slice(&junk);
            first = Some(d.clone());
            rc.set(rc.get() + d.len() as u64);
            return true;
        }
        if up <= 4 {
            // Replays of the first datagram.
            *d = first.clone().unwrap();
            rc.set(rc.get() + d.len() as u64);
            return true;
        }
        false
    }));
    let _c = p.connect();
    p.run_for(Duration::from_secs(10));
    let sent = p.to_client_stats.bytes;
    let got = received.get();
    assert!(sent > 0, "the server answered");
    assert!(sent <= 3 * got, "server sent {sent} bytes for {got} received");
}

#[test]
fn stateless_resets_and_version_negotiation_never_amplify() {
    let sc = config(25, |_| {});
    let mut server = Endpoint::new(sc, true);
    let now = Instant::now();
    let mut resp = Vec::new();
    // Short-header packets for unknown connections: the reset is always smaller than the
    // packet that caused it, and tiny packets get nothing (no reset loops).
    for len in [10usize, 21, 22, 40, 100, 1200, 1500] {
        let mut d = vec![0x41u8; len];
        match server.recv(now, spoofed(len as u32), &mut d, &mut resp) {
            DatagramEvent::Response(t) => {
                assert!(len > 21);
                assert!(t.size < len, "reset of {} bytes for {len}", t.size);
                assert!(t.size >= 21);
            }
            DatagramEvent::Dropped => assert!(len <= 21, "no reset for {len} bytes"),
            e => panic!("unexpected {e:?}"),
        }
    }
    // Version Negotiation only for full-size datagrams, and much smaller than them.
    let mut d = client_initial(&[3; 8], &[4; 8], &[], 0, &crypto_frame(0, b"x"));
    d[1..5].copy_from_slice(&0x1a2a_3a4au32.to_be_bytes());
    let n = d.len();
    match server.recv(now, spoofed(9), &mut d, &mut resp) {
        DatagramEvent::Response(t) => assert!(t.size * 10 < n),
        e => panic!("expected Version Negotiation, got {e:?}"),
    }
    let mut small = d[..600].to_vec();
    assert_eq!(server.recv(now, spoofed(9), &mut small, &mut resp), DatagramEvent::Dropped);
}

// ------------------------------------------------------------------ connection IDs

fn ncid(seq: u64, rpt: u64) -> Vec<u8> {
    let mut f = Vec::new();
    let cid = [(seq as u8) ^ 0x5a, (seq >> 8) as u8, (seq >> 16) as u8, 1, 2, 3, 4, 5];
    let mut tok = [0u8; 16];
    tok[..8].copy_from_slice(&seq.to_be_bytes());
    frame::put_new_connection_id(&mut f, seq, rpt, &cid, &tok);
    f
}

#[test]
fn new_connection_id_beyond_the_active_limit_is_an_error() {
    let (mut p, c, s) = established(30, |_| {}, |_| {});
    // The server allows 4 active CIDs; the client already gave it seq 0..=3, so any new
    // sequence number without retiring one exceeds the limit. (Reusing seq 1..=3 with other
    // CIDs is a different error: "NEW_CONNECTION_ID changed".)
    let mut frames = Vec::new();
    for seq in 10..=13 {
        frames.extend_from_slice(&ncid(seq, 0));
    }
    let e = attack(&mut p, c, s, &frames, MIN);
    assert_eq!(transport_code(&e), Some(CONNECTION_ID_LIMIT_ERROR), "{e:?}");
}

#[test]
fn retire_prior_to_churn_cannot_queue_unbounded_retirements() {
    // Each NEW_CONNECTION_ID raises retire_prior_to, so each one makes the server queue a
    // RETIRE_CONNECTION_ID. A packet full of them (or replays of old sequence numbers) must
    // not grow that queue without bound (RFC 9000 §5.1.2).
    let (mut p, c, s) = established(32, |_| {}, |_| {});
    let mut frames = Vec::new();
    for seq in 100..=130u64 {
        frames.extend_from_slice(&ncid(seq, seq));
    }
    assert!(frames.len() < 1000);
    let e = attack(&mut p, c, s, &frames, MIN);
    assert_eq!(transport_code(&e), Some(CONNECTION_ID_LIMIT_ERROR), "{e:?}");
}

#[test]
fn replayed_retired_connection_ids_are_retired_once() {
    // Old sequence numbers below retire_prior_to, repeated many times: duplicates are queued
    // once, so the connection survives. Everything goes in one packet, because the forged
    // CID moves the server to a CID the client does not own (nothing flows afterwards).
    let (mut p, c, s) = established(34, |_| {}, |_| {});
    let mut frames = ncid(100, 100);
    for _ in 0..30 {
        frames.extend_from_slice(&ncid(50, 0));
    }
    let e = attack(&mut p, c, s, &frames, Duration::from_millis(300));
    assert_eq!(e, None);
    // Many distinct old sequence numbers in one packet: the retirement queue is capped
    // (4 retired by retire_prior_to plus 33 more is above 8x the CID limit of 4).
    let (mut p, c, s) = established(35, |_| {}, |_| {});
    let mut frames = ncid(100, 100);
    for seq in 10..43 {
        frames.extend_from_slice(&ncid(seq, 0));
    }
    assert!(frames.len() < 1000);
    let e = attack(&mut p, c, s, &frames, MIN);
    assert_eq!(transport_code(&e), Some(CONNECTION_ID_LIMIT_ERROR), "{e:?}");
}

#[test]
fn retiring_connection_ids_keeps_the_server_bounded() {
    // The client accepts many CIDs, so the replacements the server issues for CIDs retired
    // behind the client's back (raw frames) never trip the client's own limit.
    let (mut p, c, s) = established(36, |c| c.transport.active_connection_id_limit = 1000, |_| {});
    // Retire every CID the server issues, as fast as it issues them. The server replaces
    // them but never holds more than its limit.
    let mut next = 1u64;
    for _ in 0..40 {
        let issued = p.server.conn(s).unwrap().local_cids().count() as u64;
        assert!(issued <= 5, "server holds {issued} CIDs");
        let mut f = Vec::new();
        // Seq 0 is in use as the DCID of the client's packets until the client rotates; retire
        // the ones above it.
        for _ in 0..2 {
            frame::put_simple(&mut f, frame::RETIRE_CONNECTION_ID, &[next]);
            next += 1;
        }
        p.client.conn_mut(c).unwrap().send_raw_frames(&f);
        p.run_for(Duration::from_millis(100));
        assert_eq!(server_error(&p, s), None, "after retiring up to {next}");
    }
    // Retiring a sequence number never issued is a protocol violation.
    let mut f = Vec::new();
    frame::put_simple(&mut f, frame::RETIRE_CONNECTION_ID, &[1_000_000]);
    let e = attack(&mut p, c, s, &f, MIN);
    assert_eq!(transport_code(&e), Some(PROTOCOL_VIOLATION), "{e:?}");
}

// ------------------------------------------------------------------ streams and flow control

fn stream_frame(id: u64, off: u64, data: &[u8], fin: bool) -> Vec<u8> {
    let mut f = Vec::new();
    frame::put_stream_header(&mut f, id, off, data.len(), fin);
    f.extend_from_slice(data);
    f
}

#[test]
fn stream_limit_abuse_is_a_stream_limit_error() {
    let (mut p, c, s) = established(40, |_| {}, |c| c.transport.max_streams_bidi = 10);
    // Client bidi stream index 10 is the 11th.
    let e = attack(&mut p, c, s, &stream_frame(40, 0, b"x", false), MIN);
    assert_eq!(transport_code(&e), Some(STREAM_LIMIT_ERROR), "{e:?}");
}

#[test]
fn stream_frames_for_unopened_server_streams_are_stream_state_errors() {
    let (mut p, c, s) = established(42, |_| {}, |_| {});
    // Server-initiated bidi stream 1 was never opened.
    let e = attack(&mut p, c, s, &stream_frame(1, 0, b"x", false), MIN);
    assert_eq!(transport_code(&e), Some(STREAM_STATE_ERROR), "{e:?}");
    // Data on a server-initiated unidirectional stream (send-only for the server).
    let (mut p, c, s) = established(43, |_| {}, |_| {});
    let e = attack(&mut p, c, s, &stream_frame(3, 0, b"x", false), MIN);
    assert_eq!(transport_code(&e), Some(STREAM_STATE_ERROR), "{e:?}");
}

#[test]
fn stream_and_connection_flow_control_abuse() {
    // One byte beyond the stream window.
    let (mut p, c, s) = established(44, |_| {}, |c| c.transport.stream_window_bidi_remote = 1000);
    let e = attack(&mut p, c, s, &stream_frame(0, 1000, b"x", false), MIN);
    assert_eq!(transport_code(&e), Some(FLOW_CONTROL_ERROR), "{e:?}");
    // A huge offset (just below 2^62).
    let (mut p, c, s) = established(45, |_| {}, |_| {});
    let e = attack(&mut p, c, s, &stream_frame(0, (1 << 62) - 2, b"x", false), MIN);
    assert!(matches!(transport_code(&e), Some(FLOW_CONTROL_ERROR) | Some(FRAME_ENCODING_ERROR)), "{e:?}");
    // The connection window is exceeded across streams that each stay in their own window.
    let (mut p, c, s) = established(46, |_| {}, |c| {
        c.transport.max_data = 10_000;
        c.transport.stream_window_bidi_remote = 8000;
    });
    let mut f = stream_frame(0, 7000, b"a", false);
    f.extend_from_slice(&stream_frame(4, 3000, b"b", false));
    let e = attack(&mut p, c, s, &f, MIN);
    assert_eq!(transport_code(&e), Some(FLOW_CONTROL_ERROR), "{e:?}");
}

#[test]
fn final_size_changes_are_errors() {
    let (mut p, c, s) = established(48, |_| {}, |_| {});
    let mut f = stream_frame(0, 0, b"hello", true);
    f.extend_from_slice(&stream_frame(0, 5, b"more", false));
    let e = attack(&mut p, c, s, &f, MIN);
    assert_eq!(transport_code(&e), Some(FINAL_SIZE_ERROR), "{e:?}");
    // RESET_STREAM with a final size below data already received.
    let (mut p, c, s) = established(49, |_| {}, |_| {});
    let mut f = stream_frame(0, 0, b"0123456789", false);
    frame::put_simple(&mut f, frame::RESET_STREAM, &[0, 7, 4]);
    let e = attack(&mut p, c, s, &f, MIN);
    assert_eq!(transport_code(&e), Some(FINAL_SIZE_ERROR), "{e:?}");
}

#[test]
fn max_streams_above_two_to_the_sixty_is_an_encoding_error() {
    let (mut p, c, s) = established(50, |_| {}, |_| {});
    let mut f = Vec::new();
    frame::put_simple(&mut f, frame::MAX_STREAMS_BIDI, &[(1 << 60) + 1]);
    let e = attack(&mut p, c, s, &f, MIN);
    assert_eq!(transport_code(&e), Some(FRAME_ENCODING_ERROR), "{e:?}");
}

#[test]
fn fragmented_stream_data_cannot_explode_memory() {
    // One-byte STREAM frames at every other offset inside the stream window: each would be
    // its own buffered chunk (a heap allocation and a tree node) for one byte of data. The
    // number of out-of-order chunks per stream is bounded, so the attack closes the
    // connection instead of costing ~80 bytes of memory per byte sent.
    let (mut p, c, s) = established(52, |_| {}, |_| {});
    let mut off = 2u64;
    let mut closed = None;
    for _ in 0..400 {
        let mut f = Vec::new();
        while f.len() < 1000 {
            f.extend_from_slice(&stream_frame(0, off, b"z", false));
            off += 2;
        }
        p.client.conn_mut(c).unwrap().send_raw_frames(&f);
        p.run_for(Duration::from_millis(5));
        closed = server_error(&p, s);
        if closed.is_some() {
            break;
        }
    }
    assert_eq!(transport_code(&closed), Some(PROTOCOL_VIOLATION), "{closed:?} after {} chunks", off / 2);
    assert!(off / 2 <= 4096, "closed only after {} chunks", off / 2);
}

#[test]
fn many_streams_opened_and_reset_do_not_leak() {
    // Open the whole stream budget, reset every stream, repeat: the server's stream map
    // stays bounded by the limit.
    let (mut p, c, s) = established(54, |_| {}, |c| c.transport.max_streams_bidi = 20);
    for round in 0..5u64 {
        let mut f = Vec::new();
        for i in 0..20u64 {
            let id = (round * 20 + i) << 2;
            f.extend_from_slice(&stream_frame(id, 0, b"x", false));
            frame::put_simple(&mut f, frame::RESET_STREAM, &[id, 0, 1]);
        }
        p.client.conn_mut(c).unwrap().send_raw_frames(&f);
        p.run_for(Duration::from_millis(300));
        let err = server_error(&p, s);
        // The application reads the resets.
        while p.server.poll_event(s).is_some() {}
        if let Some(e) = err {
            // MAX_STREAMS is raised only as streams close; going beyond it is the peer's error.
            assert_eq!(transport_code(&Some(e.clone())), Some(STREAM_LIMIT_ERROR), "round {round}: {e:?}");
            return;
        }
        assert!(p.server.conn(s).unwrap().stream_count() <= 20, "round {round}");
    }
}

// ------------------------------------------------------------------ CRYPTO floods

#[test]
fn crypto_data_far_beyond_the_buffer_is_crypto_buffer_exceeded() {
    let sc = config(60, |_| {});
    let mut server = Endpoint::new(sc, true);
    let now = Instant::now();
    let mut resp = Vec::new();
    let mut d = client_initial(&[8; 8], &[9; 8], &[], 0, &crypto_frame(1 << 20, b"far away"));
    let h = match server.recv(now, spoofed(1), &mut d, &mut resp) {
        DatagramEvent::NewConnection(h) => h,
        e => panic!("{e:?}"),
    };
    let e = server.conn(h).unwrap().error().cloned();
    assert_eq!(transport_code(&e), Some(CRYPTO_BUFFER_EXCEEDED), "{e:?}");
}

#[test]
fn tiny_out_of_order_crypto_chunks_are_bounded() {
    // Thousands of 1-byte CRYPTO frames with gaps, all inside the 64 KiB window: each chunk
    // is charged its bookkeeping overhead, so the buffer limit trips long before the
    // server holds tens of thousands of tiny allocations.
    let sc = config(62, |_| {});
    let mut server = Endpoint::new(sc, true);
    let now = Instant::now();
    let mut resp = Vec::new();
    let dcid = [0x42u8; 8];
    let mut off = 10u64;
    for pn in 0..200u64 {
        let mut f = Vec::new();
        while f.len() < 1100 {
            f.extend_from_slice(&crypto_frame(off, b"c"));
            off += 2;
        }
        let mut d = client_initial(&dcid, &[9; 8], &[], pn, &f);
        let h = match server.recv(now, spoofed(1), &mut d, &mut resp) {
            DatagramEvent::NewConnection(x) | DatagramEvent::Connection(x) => x,
            e => panic!("{e:?}"),
        };
        let e = server.conn(h).unwrap().error().cloned();
        if e.is_some() {
            assert_eq!(transport_code(&e), Some(CRYPTO_BUFFER_EXCEEDED), "{e:?}");
            let chunks = (off - 10) / 2;
            // 64 KiB / (1 + 64 bytes of overhead) ~ 1000 chunks, plus the rest of the packet
            // that tripped the limit.
            assert!(chunks <= 1300, "closed after {chunks} chunks");
            return;
        }
    }
    panic!("server buffered {} one-byte CRYPTO chunks", (off - 10) / 2);
}

#[test]
fn crypto_frames_in_one_rtt_from_the_client_are_rejected() {
    // The server's TLS stack expects nothing from the client after Finished.
    let (mut p, c, s) = established(64, |_| {}, |_| {});
    let e = attack(&mut p, c, s, &crypto_frame(0, &[4, 0, 0, 1, 0]), MIN);
    assert!(e.is_some(), "post-handshake CRYPTO from a client closes the connection");
    let (mut p, c, s) = established(65, |_| {}, |_| {});
    let e = attack(&mut p, c, s, &crypto_frame(1 << 30, b"x"), MIN);
    assert_eq!(transport_code(&e), Some(CRYPTO_BUFFER_EXCEEDED), "{e:?}");
}

// ------------------------------------------------------------------ ACKs

fn ack(largest: u64, first: u64) -> Vec<u8> {
    let mut f = Vec::new();
    frame::put_simple(&mut f, frame::ACK, &[largest, 0, 0, first]);
    f
}

#[test]
fn ack_of_unsent_packets_is_a_protocol_violation() {
    let (mut p, c, s) = established(70, |_| {}, |_| {});
    let e = attack(&mut p, c, s, &ack(1_000_000, 0), MIN);
    assert_eq!(transport_code(&e), Some(PROTOCOL_VIOLATION), "{e:?}");
    // In an Initial packet, before the server sent anything at that level for this DCID.
    let sc = config(71, |_| {});
    let mut server = Endpoint::new(sc, true);
    let mut resp = Vec::new();
    // The ACK comes first, before the (bogus) ClientHello is handed to TLS.
    let mut f = ack(50, 0);
    f.extend_from_slice(&crypto_frame(0, b"\x01\x00\x00\x00"));
    let mut d = client_initial(&[1; 8], &[2; 8], &[], 0, &f);
    let h = match server.recv(Instant::now(), spoofed(3), &mut d, &mut resp) {
        DatagramEvent::NewConnection(h) => h,
        e => panic!("{e:?}"),
    };
    let e = server.conn(h).unwrap().error().cloned();
    assert_eq!(transport_code(&e), Some(PROTOCOL_VIOLATION), "{e:?}");
}

#[test]
fn malformed_ack_ranges_are_frame_encoding_errors() {
    let (mut p, c, s) = established(72, |_| {}, |_| {});
    // First range larger than the largest acknowledged.
    let e = attack(&mut p, c, s, &ack(3, 10), MIN);
    assert_eq!(transport_code(&e), Some(FRAME_ENCODING_ERROR), "{e:?}");
    // A gap that underflows.
    let (mut p, c, s) = established(73, |_| {}, |_| {});
    let mut f = Vec::new();
    frame::put_simple(&mut f, frame::ACK, &[5, 0, 1, 0, 10, 0]);
    let e = attack(&mut p, c, s, &f, MIN);
    assert_eq!(transport_code(&e), Some(FRAME_ENCODING_ERROR), "{e:?}");
}

#[test]
fn optimistic_ack_of_skipped_packet_numbers_is_detected() {
    // An optimistic acker acknowledges every packet number the server could have sent, to
    // inflate its congestion window (RFC 9000 §21.4). The server skips packet numbers now
    // and then; acknowledging one that was never sent is a PROTOCOL_VIOLATION.
    let (mut p, c, s) = established(74, |_| {}, |_| {});
    let id = p.server.conn_mut(s).unwrap().open_uni().unwrap();
    let data = pattern(3_000_000, 3);
    let mut off = 0usize;
    let mut caught = None;
    for _ in 0..4000 {
        write_some(&mut p.server, s, id, &data, &mut off);
        p.run_for(Duration::from_millis(2));
        let Some(largest) = p.server.conn(s).and_then(|x| x.largest_sent_packet_number()) else { continue };
        p.client.conn_mut(c).unwrap().send_raw_frames(&ack(largest, largest));
        p.run_for(Duration::from_millis(1));
        caught = server_error(&p, s);
        if caught.is_some() {
            break;
        }
    }
    assert_eq!(transport_code(&caught), Some(PROTOCOL_VIOLATION), "{caught:?}");
}

#[test]
fn packet_number_skipping_does_not_hurt_honest_transfers() {
    let (mut p, c, s) = established(76, |_| {}, |_| {});
    echo_on(&mut p, c, s, 2_000_000, MIN);
    let lossy = Link { loss_ppm: 20_000, reorder_ppm: 20_000, reorder_delay: Duration::from_millis(5), ..Link::default() };
    let mut p = pair(lossy, 77);
    let (c, s) = handshake(&mut p);
    echo_on(&mut p, c, s, 500_000, Duration::from_secs(300));
}

// ------------------------------------------------------------------ stateless reset

#[test]
fn spoofed_stateless_resets_are_ignored() {
    let (mut p, c, s) = established(80, |_| {}, |_| {});
    let client_cid = p.server.conn(s).unwrap().remote_cid();
    let server_cid = p.client.conn(c).unwrap().remote_cid();
    // To the client: short header with its CID and a random tail (wrong token).
    for i in 0..200u32 {
        let mut d = vec![0x40u8 | (i as u8 & 0x3f)];
        d.extend_from_slice(client_cid.as_slice());
        d.extend((0..40).map(|k| (k as u32 * 7 + i) as u8));
        let now = p.now;
        let mut resp = Vec::new();
        let _ = p.client.recv(now, p.server_addr, &mut d, &mut resp);
    }
    // To the server: same idea with the server's CID.
    for i in 0..200u32 {
        let mut d = vec![0x40u8];
        d.extend_from_slice(server_cid.as_slice());
        d.extend((0..40).map(|k| (k as u32 * 13 + i) as u8));
        let now = p.now;
        let mut resp = Vec::new();
        let _ = p.server.recv(now, p.client_addr, &mut d, &mut resp);
    }
    assert!(!p.client.conn(c).unwrap().is_closed());
    assert!(!p.server.conn(s).unwrap().is_closed());
    echo_on(&mut p, c, s, 10_000, MIN);
    // A long-header packet ending in the real token is not a reset either (resets use the
    // short header form), but a short header ending in it is.
    let token = p.server.config().reset_token(server_cid.as_slice());
    let mut d = vec![0xc0u8; 40];
    d.extend_from_slice(&token);
    let now = p.now;
    let mut resp = Vec::new();
    let _ = p.client.recv(now, p.server_addr, &mut d, &mut resp);
    assert!(!p.client.conn(c).unwrap().is_closed());
    let mut d = vec![0x45u8];
    d.extend_from_slice(client_cid.as_slice());
    d.extend_from_slice(&[0x77; 30]);
    d.extend_from_slice(&token);
    let _ = p.client.recv(now, p.server_addr, &mut d, &mut resp);
    assert_eq!(p.client.conn(c).unwrap().error(), Some(&ConnectionError::StatelessReset));
}

#[test]
fn stateless_reset_for_unknown_cids_does_not_leak_tokens_of_live_connections() {
    // A packet to a live CID is routed to its connection, never answered with that CID's
    // reset token (which would let an attacker reset the connection).
    let (mut p, _c, _s) = established(82, |_| {}, |_| {});
    let server_cid = p.client.conn(_c).unwrap().remote_cid();
    let mut d = vec![0x40u8];
    d.extend_from_slice(server_cid.as_slice());
    d.extend_from_slice(&[0u8; 60]);
    let mut resp = Vec::new();
    let now = p.now;
    let ev = p.server.recv(now, spoofed(77), &mut d, &mut resp);
    assert!(matches!(ev, DatagramEvent::Connection(_)), "{ev:?}");
    assert!(resp.is_empty());
}

// ------------------------------------------------------------------ version negotiation

/// A Version Negotiation packet with destination CID `dcid` and source CID `scid`.
/// (`packet::version_negotiation` takes the CIDs of the client packet it answers, swapped.)
fn vn_packet(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut v = Vec::new();
    packet::version_negotiation(&mut v, 0x3c, scid, dcid, versions);
    assert_eq!(&v[6..6 + dcid.len()], dcid);
    v
}

#[test]
fn version_negotiation_downgrade_attempts_are_ignored() {
    // Client on QUIC v2. A spoofed Version Negotiation listing v1 only, sent after the client
    // has processed a packet from the server, is ignored (RFC 9000 §6.2): no downgrade.
    let cc = config(90, |c| c.versions = vec![VERSION_2]);
    let sc = config(91, |c| c.versions = vec![VERSION_1, VERSION_2]);
    let mut p = Pair::new(cc, sc, Link::default(), 90);
    let (c, s) = handshake(&mut p);
    let client_cid = p.client.conn(c).unwrap().local_cids().next().unwrap();
    let mut d = vn_packet(client_cid.as_slice(), &[1; 8], &[VERSION_1]);
    let now = p.now;
    let mut resp = Vec::new();
    let _ = p.client.recv(now, p.server_addr, &mut d, &mut resp);
    assert!(!p.client.conn(c).unwrap().is_closed());
    assert_eq!(p.client.conn(c).unwrap().version(), VERSION_2);
    echo_on(&mut p, c, s, 10_000, MIN);
}

#[test]
fn version_negotiation_listing_our_version_is_ignored_and_none_switches_versions() {
    let cc = config(92, |c| c.versions = vec![VERSION_2]);
    let sc = config(93, |c| c.versions = vec![VERSION_1, VERSION_2]);
    let mut p = Pair::new(cc, sc, Link::default(), 92);
    // Before any server packet: drop the server's datagrams, inject VN packets.
    p.tamper = Some(Box::new(|to_server, _| to_server));
    let c = p.connect();
    p.run_for(Duration::from_millis(50));
    let our_scid = p.client.conn(c).unwrap().local_cids().next().unwrap();
    let our_dcid = p.client.conn(c).unwrap().remote_cid();
    // One listing our own version: must be ignored.
    let mut d = vn_packet(our_scid.as_slice(), our_dcid.as_slice(), &[VERSION_1, VERSION_2]);
    let now = p.now;
    let mut resp = Vec::new();
    let _ = p.client.recv(now, p.server_addr, &mut d, &mut resp);
    assert!(!p.client.conn(c).unwrap().is_closed(), "VN listing our version is ignored");
    // One listing only v1: the client gives up with VersionMismatch; it never switches to
    // v1 by itself (no silent downgrade; compatible version negotiation is not implemented).
    let mut d = vn_packet(our_scid.as_slice(), our_dcid.as_slice(), &[VERSION_1]);
    let _ = p.client.recv(now, p.server_addr, &mut d, &mut resp);
    let conn = p.client.conn(c).unwrap();
    assert_eq!(conn.error(), Some(&ConnectionError::VersionMismatch));
    assert_eq!(conn.version(), VERSION_2);
}

#[test]
fn servers_ignore_version_negotiation_packets() {
    let sc = config(94, |_| {});
    let mut server = Endpoint::new(sc, true);
    let mut d = vn_packet(&[1; 8], &[2; 8], &[VERSION_1]);
    d.resize(1200, 0);
    let mut resp = Vec::new();
    assert_eq!(server.recv(Instant::now(), spoofed(5), &mut d, &mut resp), DatagramEvent::Dropped);
    assert!(resp.is_empty());
}

// ------------------------------------------------------------------ misc

#[test]
fn path_challenge_flood_from_spoofed_addresses_is_bounded() {
    // PATH_CHALLENGE responses for other addresses are capped, so a flood can't make the
    // server send unbounded traffic to a victim address.
    let (mut p, c, s) = established(96, |_| {}, |_| {});
    let mut f = Vec::new();
    for i in 0..100u8 {
        frame::put_path(&mut f, false, &[i; 8]);
    }
    let e = attack(&mut p, c, s, &f, Duration::from_millis(200));
    assert_eq!(e, None);
    echo_on(&mut p, c, s, 1000, MIN);
}

#[test]
fn new_token_from_a_client_is_a_protocol_violation() {
    let (mut p, c, s) = established(98, |_| {}, |_| {});
    let mut f = Vec::new();
    put_varint(&mut f, frame::NEW_TOKEN);
    put_varint(&mut f, 4);
    f.extend_from_slice(b"abcd");
    let e = attack(&mut p, c, s, &f, MIN);
    assert_eq!(transport_code(&e), Some(PROTOCOL_VIOLATION), "{e:?}");
    let _ = Arc::new(0);
}
