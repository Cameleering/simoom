//! Reproducers for the HTTP/2 DoS family (research.md §5): each attack must end with bounded
//! work and GOAWAY(ENHANCE_YOUR_CALM), or be absorbed by a hard cap.

mod common;

use common::*;
use simoom_h2::frame::{flag, kind, setting};
use simoom_h2::{Budgets, Config, Connection, ErrorCode};

fn count(frames: &[Frame], k: u8) -> usize {
    frames.iter().filter(|f| f.h.kind == k).count()
}

fn headers_events(evs: &[Ev]) -> usize {
    evs.iter().filter(|e| matches!(e, Ev::Headers { .. })).count()
}

/// Feeds an attack and checks it ends with ENHANCE_YOUR_CALM.
fn calm(srv: &mut Connection, bytes: &[u8]) -> (Vec<Ev>, Vec<Frame>) {
    let (evs, frames) = feed(srv, bytes, 1);
    assert_eq!(goaway(&frames), Some(ErrorCode::ENHANCE_YOUR_CALM), "{:?}", frames.iter().map(|f| f.h.kind).collect::<Vec<_>>());
    assert!(srv.wants_close());
    assert!(evs.contains(&Ev::Closed(ErrorCode::ENHANCE_YOUR_CALM)));
    (evs, frames)
}

#[test]
fn cve_2019_9511_data_dribble() {
    // the peer asks for a large body with a zero window, then opens it a byte at a time
    let (mut srv, mut raw) = server(quiet());
    raw.settings(&[(setting::INITIAL_WINDOW_SIZE, 0)]).get(1);
    feed(&mut srv, &raw.take(), 1);
    srv.send_response(1, 200, &[], false).unwrap();
    assert_eq!(srv.send_data(1, &[0u8; 100_000], true), Ok(0));
    drain(&mut srv);
    let mut data_frames = 0;
    let mut closed = false;
    for _ in 0..2000 {
        raw.window_update(1, 1);
        let (_, frames) = feed(&mut srv, &raw.take(), 1);
        if goaway(&frames) == Some(ErrorCode::ENHANCE_YOUR_CALM) {
            closed = true;
            break;
        }
        while let Some(id) = srv.poll_writable() {
            srv.send_data(id, &[0u8; 1000], false).unwrap();
        }
        data_frames += count(&drain(&mut srv), kind::DATA);
    }
    assert!(closed);
    assert!(data_frames <= Budgets::default().small_window_updates as usize, "{data_frames}");
}

#[test]
fn cve_2019_9512_ping_flood() {
    let (mut srv, mut raw) = server(quiet());
    for i in 0..10_000u64 {
        raw.ping(i.to_be_bytes());
    }
    let (_, frames) = calm(&mut srv, &raw.take());
    assert!(count(&frames, kind::PING) <= Budgets::default().ping as usize);
}

#[test]
fn cve_2019_9512_9517_peer_that_does_not_read_is_paused() {
    // with the budgets off, replies still cannot pile up: input processing pauses
    let cfg = Config { budgets: Budgets { ping: u32::MAX, ..Budgets::default() }, ..quiet() };
    let (mut srv, mut raw) = server(cfg.clone());
    for i in 0..200_000u64 {
        raw.ping(i.to_be_bytes());
    }
    let bytes = raw.take();
    let used = srv.recv(&bytes, 1, &mut |_| {});
    assert!(used < bytes.len());
    assert!(srv.output().len() <= 2 * cfg.max_send_buffer + 17, "{}", srv.output().len());
    // once the peer reads, processing resumes
    let before = used;
    let out = srv.output().len();
    srv.advance_output(out);
    let used2 = srv.recv(&bytes[before..], 2, &mut |_| {});
    assert!(used2 > 0);
}

#[test]
fn cve_2019_9513_priority_flood() {
    let (mut srv, mut raw) = server(quiet());
    for i in 0..5_000u32 {
        raw.priority(2 * (i % 50) + 1, 2 * ((i + 7) % 50) + 1);
    }
    calm(&mut srv, &raw.take());
}

#[test]
fn cve_2019_9514_reset_flood() {
    // malformed requests make the server reset each stream
    let (mut srv, mut raw) = server(quiet());
    for i in 0..1000u32 {
        raw.headers(2 * i + 1, &[GET[0], GET[1], GET[2], GET[3], ("Bad-Case", "x")], true);
    }
    let (evs, frames) = calm(&mut srv, &raw.take());
    assert_eq!(headers_events(&evs), 0, "no handler ever starts");
    assert!(count(&frames, kind::RST_STREAM) <= Budgets::default().rst_sent as usize + 1);
}

#[test]
fn cve_2019_9515_settings_flood() {
    let (mut srv, mut raw) = server(quiet());
    for _ in 0..10_000 {
        raw.settings(&[(setting::HEADER_TABLE_SIZE, 4096)]);
    }
    let (_, frames) = calm(&mut srv, &raw.take());
    assert!(count(&frames, kind::SETTINGS) <= Budgets::default().settings as usize);
}

#[test]
fn cve_2019_9516_zero_length_headers() {
    // empty header names are malformed: each request is reset, and the flood ends in GOAWAY
    let (mut srv, mut raw) = server(quiet());
    for i in 0..1000u32 {
        let mut b = raw.block(&GET);
        for _ in 0..100 {
            b.extend_from_slice(&[0x00, 0x00, 0x00]); // literal, empty name, empty value
        }
        raw.raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 2 * i + 1, &b);
    }
    let (evs, _) = calm(&mut srv, &raw.take());
    assert_eq!(headers_events(&evs), 0);
    assert_eq!(srv.tracked_streams(), 0, "nothing is retained");
}

#[test]
fn cve_2019_9517_internal_data_buffering() {
    // the peer opens huge windows but never reads: accepted DATA is capped by the output buffer
    let cfg = quiet();
    let (mut srv, mut raw) = server(cfg.clone());
    raw.settings(&[(setting::INITIAL_WINDOW_SIZE, 0x7fff_ffff)]).window_update(0, 0x7fff_0000);
    for i in 0..50u32 {
        raw.get(2 * i + 1);
    }
    feed(&mut srv, &raw.take(), 1);
    let mut accepted = 0;
    for i in 0..50u32 {
        srv.send_response(2 * i + 1, 200, &[], false).unwrap();
        accepted += srv.send_data(2 * i + 1, &[0u8; 1 << 20], false).unwrap();
    }
    assert!(accepted <= cfg.max_send_buffer, "{accepted}");
    assert!(srv.output().len() <= cfg.max_send_buffer + 50 * 64 + 16 * 1024);
    assert_eq!(srv.poll_writable(), None, "nothing is writable until the output drains");
    let n = srv.output().len();
    srv.advance_output(n);
    assert!(srv.poll_writable().is_some());
}

#[test]
fn cve_2019_9518_empty_frames_flood() {
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false);
    for _ in 0..10_000 {
        raw.data(1, b"", false);
    }
    let (evs, _) = calm(&mut srv, &raw.take());
    let empties = evs.iter().filter(|e| matches!(e, Ev::Data { data, .. } if data.is_empty())).count();
    assert!(empties <= Budgets::default().empty_frames as usize);
}

#[test]
fn cve_2023_44487_rapid_reset() {
    let cfg = quiet();
    let (mut srv, mut raw) = server(cfg.clone());
    for i in 0..10_000u32 {
        raw.get(2 * i + 1).rst(2 * i + 1, ErrorCode::CANCEL);
    }
    let (evs, _) = calm(&mut srv, &raw.take());
    // handlers never finished, so at most max_concurrent_streams requests ever started work
    let started = headers_events(&evs);
    assert!(started <= cfg.max_concurrent_streams as usize, "{started}");
    assert!(srv.active_handlers() <= cfg.max_concurrent_streams);
}

#[test]
fn cve_2023_44487_rapid_reset_with_a_prompt_application() {
    // even when the application stops work at once, the RST_STREAM budget ends the attack
    let (mut srv, mut raw) = server(quiet());
    let mut started = 0;
    let mut closed = false;
    for i in 0..10_000u32 {
        raw.get(2 * i + 1).rst(2 * i + 1, ErrorCode::CANCEL);
        let (evs, frames) = feed(&mut srv, &raw.take(), 1);
        for e in &evs {
            if let Ev::Reset { stream, .. } = e {
                srv.stream_finished(*stream);
            }
        }
        started += headers_events(&evs);
        if goaway(&frames).is_some() {
            assert_eq!(goaway(&frames), Some(ErrorCode::ENHANCE_YOUR_CALM));
            closed = true;
            break;
        }
    }
    assert!(closed);
    assert!(started <= Budgets::default().rst_received as usize + 1, "{started}");
}

#[test]
fn legitimate_resets_within_budget_are_fine() {
    // 150 cancelled requests per 10 seconds, spread out, for a minute
    let (mut srv, mut raw) = server(quiet());
    let mut id = 1;
    for _ in 0..6u64 {
        for _ in 0..150 {
            raw.get(id).rst(id, ErrorCode::CANCEL);
            let now = id as u64 * 10_000 / 300; // 150 per 10 s
            let (evs, frames) = feed(&mut srv, &raw.take(), now);
            assert_eq!(goaway(&frames), None);
            for e in &evs {
                if let Ev::Reset { stream, .. } = e {
                    srv.stream_finished(*stream);
                }
            }
            id += 2;
        }
    }
    assert_eq!(srv.active_handlers(), 0);
    assert_eq!(srv.tracked_streams(), 0);
}

#[test]
fn continuation_flood() {
    // non-empty fragments: the header block byte cap ends it
    let (mut srv, mut raw) = server(Config { max_continuation_frames: 10_000, ..quiet() });
    raw.raw(kind::HEADERS, flag::END_STREAM, 1, &[0x82]);
    for _ in 0..100_000 {
        raw.raw(kind::CONTINUATION, 0, 1, &[0x40, 0x01, b'a', 0x01, b'b'][..]);
    }
    calm(&mut srv, &raw.take());
    // empty fragments: the frame count cap ends it
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::HEADERS, flag::END_STREAM, 1, &[0x82]);
    for _ in 0..100_000 {
        raw.raw(kind::CONTINUATION, 0, 1, &[]);
    }
    calm(&mut srv, &raw.take());
    // one HEADERS with a fragment above the block cap (twice the list limit)
    let (mut srv, mut raw) = server(Config { max_header_list_size: 1000, ..quiet() });
    raw.raw(kind::HEADERS, 0, 1, &[0u8; 2001]);
    calm(&mut srv, &raw.take());
}

#[test]
fn header_block_over_the_list_limit_gets_431_not_goaway() {
    // A plain literal larger than SETTINGS_MAX_HEADER_LIST_SIZE (advisory, RFC 9113 §10.5.1):
    // the stream gets 431 (plan §7.1) and the connection, with its other streams, survives.
    let (mut srv, mut raw) = server(Config { max_header_list_size: 1024, ..quiet() });
    let big = "v".repeat(1500);
    let mut fields = GET.to_vec();
    fields.push(("x-big", big.as_str()));
    raw.headers(1, &fields, true);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(headers_events(&evs), 0);
    assert_eq!(goaway(&frames), None);
    let h: Vec<_> = frames.iter().filter(|f| f.h.kind == kind::HEADERS && f.h.stream == 1).collect();
    assert_eq!(h.len(), 1);
    let mut d = simoom_hpack::Decoder::new(4096, 1 << 20);
    let mut status = Vec::new();
    d.decode(&h[0].p, &mut |n: &[u8], v: &[u8]| {
        if n == b":status" {
            status = v.to_vec()
        }
    })
    .unwrap();
    assert_eq!(status, b"431");
    raw.get(3);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert_eq!(headers_events(&evs), 1);
}

#[test]
fn hpack_bomb_gets_431_and_the_connection_survives() {
    let (mut srv, mut raw) = server(quiet());
    // one 4000-byte entry, referenced 20 times: 80 KB decoded from a 4 KB block
    let mut b = raw.block(&GET);
    b.extend_from_slice(&[0x40, 0x01, b'x']);
    simoom_hpack::encode_integer(4000, 7, 0, &mut b);
    b.extend(std::iter::repeat_n(b'y', 4000));
    for _ in 0..20 {
        b.push(0xbe);
    }
    raw.raw(kind::HEADERS, flag::END_HEADERS, 1, &b);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(headers_events(&evs), 0);
    assert_eq!(goaway(&frames), None);
    let h: Vec<_> = frames.iter().filter(|f| f.h.kind == kind::HEADERS && f.h.stream == 1).collect();
    assert_eq!(h.len(), 1);
    assert!(h[0].h.has(flag::END_STREAM));
    let mut d = simoom_hpack::Decoder::new(4096, 1 << 20);
    let mut status = Vec::new();
    d.decode(&h[0].p, &mut |n: &[u8], v: &[u8]| {
        if n == b":status" {
            status = v.to_vec()
        }
    })
    .unwrap();
    assert_eq!(status, b"431");
    assert_eq!(rst(&frames, 1), Some(ErrorCode::NO_ERROR));
    // the HPACK context is intact: the next request refers to the big entry and is answered
    raw.get(3);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert_eq!(headers_events(&evs), 1);
}

#[test]
fn cve_2025_8671_made_you_reset() {
    // each primitive makes the *server* reset a stream while its handler keeps running
    let primitives: [fn(&mut Raw, u32); 5] = [
        |r, id| {
            r.headers(id, &POST, false).window_update(id, 0);
        },
        |r, id| {
            r.headers(id, &POST, false).raw(kind::PRIORITY, 0, id, &[0, 0, 0, 1]);
        },
        |r, id| {
            r.get(id).data(id, b"x", true);
        },
        |r, id| {
            r.headers(id, &POST, false).window_update(id, 0x7fff_ffff);
        },
        |r, id| {
            let f = [POST[0], POST[1], POST[2], POST[3], ("content-length", "1")];
            r.headers(id, &f, false).data(id, b"xyz", true);
        },
    ];
    for (n, attack) in primitives.iter().enumerate() {
        let cfg = quiet();
        let (mut srv, mut raw) = server(cfg.clone());
        for i in 0..5_000u32 {
            attack(&mut raw, 2 * i + 1);
        }
        let (evs, frames) = calm(&mut srv, &raw.take());
        let started = headers_events(&evs);
        assert!(started <= cfg.max_concurrent_streams as usize, "primitive {n}: {started} handlers");
        assert!(srv.active_handlers() <= cfg.max_concurrent_streams);
        assert!(count(&frames, kind::RST_STREAM) <= Budgets::default().rst_sent as usize + 1, "primitive {n}");
        // the application was told to stop each reset stream
        assert!(evs.iter().any(|e| matches!(e, Ev::Reset { remote: false, .. })), "primitive {n}");
    }
}

#[test]
fn made_you_reset_slots_free_only_when_work_finishes() {
    let cfg = Config { max_concurrent_streams: 2, ..quiet() };
    let (mut srv, mut raw) = server(cfg);
    raw.headers(1, &POST, false).window_update(1, 0);
    raw.headers(3, &POST, false).window_update(3, 0);
    raw.get(5);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(headers_events(&evs), 2);
    assert_eq!(srv.open_streams(), 0, "both streams are closed");
    assert_eq!(srv.active_handlers(), 2, "but their work is still running");
    assert_eq!(rst(&frames, 5), Some(ErrorCode::REFUSED_STREAM));
    srv.stream_finished(1);
    raw.get(7);
    let (evs, _) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(headers_events(&evs), 1);
}

#[test]
fn small_budgets_are_configurable() {
    let b = Budgets { window_ms: 1000, ping: 3, ..Budgets::default() };
    let (mut srv, mut raw) = server(Config { budgets: b, ..quiet() });
    for i in 0..3u64 {
        raw.ping(i.to_be_bytes());
    }
    let (_, frames) = feed(&mut srv, &raw.take(), 100);
    assert_eq!(goaway(&frames), None);
    // a second later the window has moved on
    raw.ping([9; 8]);
    let (_, frames) = feed(&mut srv, &raw.take(), 2200);
    assert_eq!(goaway(&frames), None);
    for i in 0..3u64 {
        raw.ping(i.to_be_bytes());
    }
    calm(&mut srv, &raw.take());
}
