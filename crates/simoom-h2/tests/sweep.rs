//! Regression tests for the 2026-11-09 bug sweep (docs/BUGS.md items 9, 10 and 15).

mod common;

use common::*;
use simoom_h2::frame::{kind, setting};
use simoom_h2::{Budgets, Config, Connection, Error, ErrorCode};

/// Item 10: a late frame on a stream we reset long ago (far more resets ago than any fixed
/// window) is ignored, not a connection error.
#[test]
fn late_frames_on_long_reset_streams_are_ignored() {
    let (mut srv, mut raw) = server(Config { max_concurrent_streams: 1000, ..quiet() });
    // 300 requests with bodies; the server answers each at once and stops reading its body,
    // which resets the stream (RST_STREAM NO_ERROR after the response)
    for i in 0..300u32 {
        raw.headers(1 + 2 * i, &[(":method", "POST"), (":scheme", "http"), (":path", "/"), (":authority", "a")], false);
    }
    feed(&mut srv, &raw.take(), 1);
    for i in 0..300u32 {
        let id = 1 + 2 * i;
        srv.send_response(id, 200, &[], true).unwrap();
        srv.stream_finished(id);
    }
    let frames = drain(&mut srv);
    assert_eq!(rst(&frames, 1), Some(ErrorCode::NO_ERROR));
    assert_eq!(srv.tracked_streams(), 0);
    // the client's body and trailers for the first stream arrive late
    raw.data(1, b"late body", false).headers(1, &[("x-checksum", "1")], true).window_update(1, 100);
    let (evs, frames) = feed(&mut srv, &raw.take(), 2);
    assert!(evs.is_empty(), "{evs:?}");
    assert!(goaway(&frames).is_none() && rst(&frames, 1).is_none(), "{frames:?}");
    assert!(!srv.wants_close());
    // a stream that closed normally is still the peer's error
    raw.get(1001);
    feed(&mut srv, &raw.take(), 3);
    srv.send_response(1001, 200, &[], true).unwrap();
    srv.stream_finished(1001);
    drain(&mut srv);
    raw.data(1001, b"x", true);
    let (_, frames) = feed(&mut srv, &raw.take(), 4);
    assert_eq!(rst(&frames, 1001), Some(ErrorCode::STREAM_CLOSED));
    // and an id below the highest seen that never was a stream gets no stream state
    raw.get(1003);
    let (evs, _) = feed(&mut srv, &raw.take(), 5);
    assert!(evs.iter().any(|e| matches!(e, Ev::Headers { stream: 1003, .. })));
}

/// Item 9: header blocks larger than the peer's SETTINGS_MAX_HEADER_LIST_SIZE are refused
/// before anything is sent.
#[test]
fn outgoing_header_blocks_respect_the_peer_limit() {
    let (mut srv, mut raw) = server(quiet());
    raw.settings(&[(setting::MAX_HEADER_LIST_SIZE, 200)]).get(1).get(3);
    feed(&mut srv, &raw.take(), 1);
    drain(&mut srv);
    assert_eq!(srv.peer_max_header_list_size(), 200);
    let big = vec![b'v'; 150];
    // ":status" (7) + "200" (3) + 32 + "x-big" (5) + 150 + 32 = 229 > 200
    assert_eq!(srv.send_response(1, 200, &[(b"x-big", &big)], true), Err(Error::HeaderListTooLarge));
    assert!(drain(&mut srv).iter().all(|f| f.h.kind != kind::HEADERS), "nothing sent");
    // the stream is untouched: a smaller response still works
    srv.send_response(1, 200, &[(b"x-small", b"1")], false).unwrap();
    // trailers are checked too (fields only, no pseudo-fields)
    assert_eq!(srv.send_trailers(1, &[(b"x-big", &big), (b"x-more", b"1")]), Err(Error::HeaderListTooLarge));
    srv.send_trailers(1, &[(b"x-t", b"1")]).unwrap();
    // exactly at the limit is allowed: 7 + 3 + 32 + 5 + v + 32 = 200 -> v = 121
    let fit = vec![b'v'; 121];
    srv.send_response(3, 200, &[(b"x-big", &fit)], true).unwrap();

    // the client side checks requests against the server's limit
    let mut cli = Connection::client(Config::default());
    let mut s = Connection::server(Config { max_header_list_size: 300, ..Config::default() });
    let (mut ce, mut se) = (Vec::new(), Vec::new());
    pump(&mut cli, &mut s, 1, &mut ce, &mut se);
    assert_eq!(cli.peer_max_header_list_size(), 300);
    // pseudo-fields 42 + 44 + 53 + 38 = 177, plus 6 + 100 + 32 = 315
    assert_eq!(cli.send_request(b"GET", b"https", b"example.com", b"/", &[(b"x-long", &[b'a'; 100])], true), Err(Error::HeaderListTooLarge));
    assert!(cli.send_request(b"GET", b"https", b"example.com", b"/", &[], true).is_ok());
}

/// Item 15: the frame budgets come from `Config::budgets` (the facade sets them from
/// `Limits::h2_budgets`).
#[test]
fn frame_budgets_are_configurable() {
    let (mut srv, mut raw) = server(Config { budgets: Budgets { ping: 3, ..Budgets::default() }, ..quiet() });
    for _ in 0..4 {
        raw.ping(*b"pingping");
    }
    let (_, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), Some(ErrorCode::ENHANCE_YOUR_CALM));
    let (mut srv, mut raw) = server(Config { budgets: Budgets { ping: u32::MAX, ..Budgets::default() }, ..quiet() });
    for _ in 0..1000 {
        raw.ping(*b"pingping");
    }
    let (_, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
}
