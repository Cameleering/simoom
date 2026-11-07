//! h2spec-style server conformance cases (RFC 9113 and RFC 7541), as hermetic tests. Section
//! numbers follow h2spec's `http2` and `hpack` groups.

mod common;

use common::*;
use simoom_h2::frame::{flag, kind, setting};
use simoom_h2::{Config, Connection, ErrorCode, Event};

/// Expects a connection error: GOAWAY with `code`, and the engine closed.
fn conn_err(srv: &mut Connection, bytes: &[u8], code: ErrorCode) {
    let (evs, frames) = feed(srv, bytes, 1);
    assert_eq!(goaway(&frames), Some(code), "frames: {frames:?}");
    assert!(srv.wants_close());
    assert_eq!(srv.close_code(), Some(code));
    assert!(evs.contains(&Ev::Closed(code)));
    // later input is ignored
    let mut more = Raw::new();
    more.ping(*b"12345678");
    let (_, frames) = feed(srv, &more.take(), 2);
    assert!(frames.is_empty());
}

/// Expects a stream error: RST_STREAM on `stream` with `code`, and the connection still open.
fn stream_err(srv: &mut Connection, bytes: &[u8], stream: u32, code: ErrorCode) -> Vec<Ev> {
    let (evs, frames) = feed(srv, bytes, 1);
    assert_eq!(goaway(&frames), None, "unexpected GOAWAY: {frames:?}");
    assert_eq!(rst(&frames, stream), Some(code), "frames: {frames:?}");
    assert!(!srv.wants_close());
    evs
}

/// The connection still works: a PING is answered.
fn alive(srv: &mut Connection) {
    let mut r = Raw::new();
    r.ping(*b"alive!!!");
    let (_, frames) = feed(srv, &r.take(), 3);
    assert!(frames.iter().any(|f| f.h.kind == kind::PING && f.h.has(flag::ACK) && f.p == b"alive!!!"), "{frames:?}");
}

// ---------------------------------------------------------------- 3.5 preface

#[test]
fn s3_5_invalid_preface() {
    let mut srv = Connection::server(Config::default());
    drain(&mut srv);
    conn_err(&mut srv, b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n", ErrorCode::PROTOCOL_ERROR);
    // an HTTP/1.1 request is rejected as soon as the first byte differs
    let mut srv = Connection::server(Config::default());
    drain(&mut srv);
    conn_err(&mut srv, b"GET", ErrorCode::PROTOCOL_ERROR);
}

#[test]
fn s3_5_preface_split_and_first_frame_must_be_settings() {
    let mut srv = Connection::server(Config::default());
    let first = drain(&mut srv);
    assert_eq!(first[0].h.kind, kind::SETTINGS, "server preface is SETTINGS");
    // the preface arrives a byte at a time: nothing is consumed until it is complete
    let pre = simoom_h2::PREFACE;
    let mut ev = Vec::new();
    for i in 1..24 {
        assert_eq!(srv.recv(&pre[..i], 0, &mut |e| ev.push(own(e))), 0);
    }
    assert_eq!(srv.recv(pre, 0, &mut |_| {}), 24);
    let mut r = Raw::new();
    r.ping(*b"pingping");
    conn_err(&mut srv, &r.take(), ErrorCode::PROTOCOL_ERROR);
    // a SETTINGS ACK is not a valid first frame either
    let mut srv = Connection::server(Config::default());
    let mut r = Raw::new();
    r.buf.extend_from_slice(pre);
    r.settings_ack();
    conn_err(&mut srv, &r.take(), ErrorCode::PROTOCOL_ERROR);
}

#[test]
fn partial_frames_are_left_for_the_caller() {
    let (mut srv, mut raw) = server(quiet());
    raw.get(1);
    let bytes = raw.take();
    for cut in 0..bytes.len() {
        let mut ev = Vec::new();
        let n = srv.recv(&bytes[..cut], 1, &mut |e| ev.push(own(e)));
        assert_eq!(n, 0);
        assert!(ev.is_empty());
    }
    let (evs, _) = feed(&mut srv, &bytes, 1);
    assert!(matches!(evs[0], Ev::Headers { stream: 1, end: true, .. }));
}

// ---------------------------------------------------------------- 4 frames

#[test]
fn s4_1_unknown_types_flags_and_reserved_bit_are_ignored() {
    let (mut srv, mut raw) = server(quiet());
    raw.raw(0x20, 0xff, 0, b"whatever");
    raw.raw(kind::PING, 0x16, 0, b"flags!!!"); // undefined flags on PING
    let mut b = raw.take();
    // set the reserved bit on a PING's stream id
    let at = b.len();
    let mut r = Raw::new();
    r.ping(*b"reserved");
    b.extend_from_slice(&r.take());
    b[at + 5] |= 0x80;
    let (_, frames) = feed(&mut srv, &b, 1);
    let pongs: Vec<_> = frames.iter().filter(|f| f.h.kind == kind::PING && f.h.has(flag::ACK)).collect();
    assert_eq!(pongs.len(), 2);
    assert_eq!(goaway(&frames), None);
}

#[test]
fn s4_2_frame_size() {
    // DATA of exactly 16384 bytes is fine
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).data(1, &[7u8; 16384], true);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert!(evs.iter().any(|e| matches!(e, Ev::Data { stream: 1, data, end: true } if data.len() == 16384)));
    // one byte more is a connection error
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).data(1, &[7u8; 16385], true);
    conn_err(&mut srv, &raw.take(), ErrorCode::FRAME_SIZE_ERROR);
    // the error comes from the header alone, before the payload arrives
    let (mut srv, _) = server(quiet());
    let mut hdr = Vec::new();
    simoom_h2::frame::write_header(&mut hdr, 1 << 20, kind::HEADERS, flag::END_HEADERS, 1);
    conn_err(&mut srv, &hdr, ErrorCode::FRAME_SIZE_ERROR);
    // a larger SETTINGS_MAX_FRAME_SIZE is honoured
    let (mut srv, mut raw) = server(Config { max_frame_size: 32768, ..quiet() });
    raw.headers(1, &POST, false).data(1, &[7u8; 30000], true);
    let (_, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
}

#[test]
fn s4_3_header_compression_errors() {
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &[0x80]); // index 0
    conn_err(&mut srv, &raw.take(), ErrorCode::COMPRESSION_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &[0xff, 0x7f]); // index 188
    conn_err(&mut srv, &raw.take(), ErrorCode::COMPRESSION_ERROR);
}

#[test]
fn s4_3_header_block_interrupted() {
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&GET);
    raw.raw(kind::HEADERS, flag::END_STREAM, 1, &b[..2]).priority(1, 0);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&GET);
    raw.raw(kind::HEADERS, flag::END_STREAM, 1, &b[..2]).raw(kind::CONTINUATION, flag::END_HEADERS, 3, &b[2..]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------- 5.1 stream states

#[test]
fn s5_1_idle_stream_frames() {
    for case in 0..4 {
        let (mut srv, mut raw) = server(quiet());
        match case {
            0 => raw.data(1, b"x", false),
            1 => raw.rst(1, ErrorCode::CANCEL),
            2 => raw.window_update(1, 100),
            _ => raw.raw(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x82]),
        };
        conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    }
    // PRIORITY on an idle stream is allowed and does not open it
    let (mut srv, mut raw) = server(quiet());
    raw.priority(5, 0).get(1);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert!(matches!(evs[0], Ev::Headers { stream: 1, .. }));
}

#[test]
fn s5_1_half_closed_remote() {
    let (mut srv, mut raw) = server(quiet());
    raw.get(1);
    feed(&mut srv, &raw.take(), 1);
    raw.data(1, b"x", false);
    let evs = stream_err(&mut srv, &raw.take(), 1, ErrorCode::STREAM_CLOSED);
    assert!(evs.contains(&Ev::Reset { stream: 1, code: ErrorCode::STREAM_CLOSED, remote: false }));
    alive(&mut srv);

    let (mut srv, mut raw) = server(quiet());
    raw.get(1);
    feed(&mut srv, &raw.take(), 1);
    raw.headers(1, &[("x-trailer", "1")], true);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::STREAM_CLOSED);

    let (mut srv, mut raw) = server(quiet());
    raw.get(1);
    feed(&mut srv, &raw.take(), 1);
    raw.raw(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x82]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
}

#[test]
fn s5_1_closed_stream() {
    // DATA after the client's own RST_STREAM
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).rst(1, ErrorCode::CANCEL).data(1, b"x", true);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert!(evs.contains(&Ev::Reset { stream: 1, code: ErrorCode::CANCEL, remote: true }));
    assert_eq!(rst(&frames, 1), Some(ErrorCode::STREAM_CLOSED));
    // HEADERS after the client's RST_STREAM
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).rst(1, ErrorCode::CANCEL).headers(1, &[("x", "y")], true);
    let (_, frames) = feed(&mut srv, &raw.take(), 1);
    assert!(rst(&frames, 1) == Some(ErrorCode::STREAM_CLOSED) || goaway(&frames) == Some(ErrorCode::STREAM_CLOSED));
    // DATA and HEADERS on a stream closed by END_STREAM in both directions
    let (mut srv, mut raw) = server(quiet());
    raw.get(1);
    feed(&mut srv, &raw.take(), 1);
    srv.send_response(1, 200, &[], true).unwrap();
    srv.stream_finished(1);
    assert_eq!(srv.tracked_streams(), 0);
    drain(&mut srv);
    raw.data(1, b"x", true);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::STREAM_CLOSED);
    raw.get(1);
    conn_err(&mut srv, &raw.take(), ErrorCode::STREAM_CLOSED);
}

#[test]
fn frames_after_our_reset_are_ignored() {
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false);
    feed(&mut srv, &raw.take(), 1);
    srv.reset(1, ErrorCode::CANCEL);
    let frames = drain(&mut srv);
    assert_eq!(rst(&frames, 1), Some(ErrorCode::CANCEL));
    // in-flight frames from the client are discarded without another RST
    raw.data(1, b"late", false).window_update(1, 10).data(1, b"", true);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert!(evs.is_empty(), "{evs:?}");
    assert!(frames.is_empty(), "{frames:?}");
}

#[test]
fn s5_1_1_stream_identifiers() {
    let (mut srv, mut raw) = server(quiet());
    raw.get(2);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.get(5).get(3);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
}

#[test]
fn s5_1_2_concurrency_limit() {
    let (mut srv, mut raw) = server(Config { max_concurrent_streams: 3, ..quiet() });
    for id in [1, 3, 5, 7] {
        raw.get(id);
    }
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(evs.iter().filter(|e| matches!(e, Ev::Headers { .. })).count(), 3);
    assert_eq!(rst(&frames, 7), Some(ErrorCode::REFUSED_STREAM));
    // the server advertised the limit
    let srv2 = Connection::server(Config { max_concurrent_streams: 3, ..quiet() });
    let mut s = srv2;
    let f = drain(&mut s);
    let p = &f[0].p;
    assert!(p.chunks(6).any(|c| u16::from_be_bytes([c[0], c[1]]) == setting::MAX_CONCURRENT_STREAMS && c[5] == 3));
}

// ---------------------------------------------------------------- 5.3 priority, 5.5 extensions

#[test]
fn s5_3_self_dependency() {
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&GET);
    let mut p = 1u32.to_be_bytes().to_vec();
    p.push(16);
    p.extend_from_slice(&b);
    raw.raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM | flag::PRIORITY, 1, &p);
    let evs = stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
    assert!(evs.is_empty(), "no request reaches the application");
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).priority(1, 1);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
}

#[test]
fn s5_5_unknown_frame_inside_header_block() {
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&GET);
    raw.raw(kind::HEADERS, flag::END_STREAM, 1, &b[..1]).raw(0x77, 0, 1, b"x");
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------- 6.1 DATA

#[test]
fn s6_1_data() {
    let (mut srv, mut raw) = server(quiet());
    raw.data(0, b"x", false);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    // pad length equal to the payload length
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).raw(kind::DATA, flag::PADDED, 1, &[4, 1, 2, 3]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    // padding is stripped and counted for flow control
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).raw(kind::DATA, flag::PADDED | flag::END_STREAM, 1, &[3, b'h', b'i', 0, 0, 0]);
    let (evs, _) = feed(&mut srv, &raw.take(), 1);
    assert!(evs.contains(&Ev::Data { stream: 1, data: b"hi".to_vec(), end: true }));
}

// ---------------------------------------------------------------- 6.2 HEADERS

#[test]
fn s6_2_headers() {
    let (mut srv, mut raw) = server(quiet());
    raw.headers(0, &GET, true);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&GET);
    let mut p = vec![200u8];
    p.extend_from_slice(&b);
    raw.raw(kind::HEADERS, flag::END_HEADERS | flag::PADDED, 1, &p);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    // padded + priority, valid
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&GET);
    let mut p = vec![2u8, 0, 0, 0, 3, 7];
    p.extend_from_slice(&b);
    p.extend_from_slice(&[0, 0]);
    raw.raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM | flag::PADDED | flag::PRIORITY, 1, &p);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert!(matches!(&evs[0], Ev::Headers { stream: 1, path: Some(p), .. } if p == "/"));
}

// ---------------------------------------------------------------- 6.3 PRIORITY

#[test]
fn s6_3_priority() {
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::PRIORITY, 0, 0, &[0, 0, 0, 1, 1]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).raw(kind::PRIORITY, 0, 1, &[0, 0, 0, 3]);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::FRAME_SIZE_ERROR);
}

// ---------------------------------------------------------------- 6.4 RST_STREAM

#[test]
fn s6_4_rst_stream() {
    let (mut srv, mut raw) = server(quiet());
    raw.rst(0, ErrorCode::CANCEL);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).raw(kind::RST_STREAM, 0, 1, &[0, 0, 8]);
    conn_err(&mut srv, &raw.take(), ErrorCode::FRAME_SIZE_ERROR);
    // unknown error codes are accepted (section 7)
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).rst(1, ErrorCode(0xdead));
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert!(evs.contains(&Ev::Reset { stream: 1, code: ErrorCode(0xdead), remote: true }));
}

// ---------------------------------------------------------------- 6.5 SETTINGS

#[test]
fn s6_5_settings() {
    let cases: [(Vec<u8>, ErrorCode); 7] = [
        ({ let mut r = Raw::new(); r.raw(kind::SETTINGS, flag::ACK, 0, &[0; 6]); r.take() }, ErrorCode::FRAME_SIZE_ERROR),
        ({ let mut r = Raw::new(); r.raw(kind::SETTINGS, 0, 1, &[]); r.take() }, ErrorCode::PROTOCOL_ERROR),
        ({ let mut r = Raw::new(); r.raw(kind::SETTINGS, 0, 0, &[0, 3, 0]); r.take() }, ErrorCode::FRAME_SIZE_ERROR),
        ({ let mut r = Raw::new(); r.settings(&[(setting::ENABLE_PUSH, 2)]); r.take() }, ErrorCode::PROTOCOL_ERROR),
        ({ let mut r = Raw::new(); r.settings(&[(setting::INITIAL_WINDOW_SIZE, 1 << 31)]); r.take() }, ErrorCode::FLOW_CONTROL_ERROR),
        ({ let mut r = Raw::new(); r.settings(&[(setting::MAX_FRAME_SIZE, 16383)]); r.take() }, ErrorCode::PROTOCOL_ERROR),
        ({ let mut r = Raw::new(); r.settings(&[(setting::MAX_FRAME_SIZE, 1 << 24)]); r.take() }, ErrorCode::PROTOCOL_ERROR),
    ];
    for (bytes, code) in cases {
        let (mut srv, _) = server(quiet());
        conn_err(&mut srv, &bytes, code);
    }
    // unknown identifiers are ignored; every SETTINGS is acknowledged
    let (mut srv, mut raw) = server(quiet());
    raw.settings(&[(0x99, 1), (setting::INITIAL_WINDOW_SIZE, 100), (setting::INITIAL_WINDOW_SIZE, 10)]);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(evs, [Ev::Settings]);
    assert!(frames.iter().any(|f| f.h.kind == kind::SETTINGS && f.h.has(flag::ACK)));
    // the last value wins: a response can send 10 bytes
    raw.get(1);
    feed(&mut srv, &raw.take(), 1);
    srv.send_response(1, 200, &[], false).unwrap();
    assert_eq!(srv.send_data(1, &[1u8; 50], true), Ok(10));
}

#[test]
fn settings_ack_timeout() {
    let mut srv = Connection::server(quiet());
    let mut raw = Raw::new();
    raw.preface();
    feed(&mut srv, &raw.take(), 1000);
    assert_eq!(srv.poll_timeout(), Some(11_000));
    let mut evs = Vec::new();
    srv.handle_timeout(10_999, &mut |e| evs.push(own(e)));
    assert!(evs.is_empty());
    srv.handle_timeout(11_000, &mut |e| evs.push(own(e)));
    assert_eq!(evs, [Ev::Closed(ErrorCode::SETTINGS_TIMEOUT)]);
    assert_eq!(goaway(&drain(&mut srv)), Some(ErrorCode::SETTINGS_TIMEOUT));
    // acknowledged in time: no deadline
    let (srv, _) = server(quiet());
    assert_eq!(srv.poll_timeout(), None);
}

// ---------------------------------------------------------------- 6.7 PING, 6.8 GOAWAY

#[test]
fn s6_7_ping() {
    let (mut srv, mut raw) = server(quiet());
    raw.ping(*b"h2spec!!");
    raw.raw(kind::PING, flag::ACK, 0, b"unsolici");
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    let acks: Vec<_> = frames.iter().filter(|f| f.h.kind == kind::PING).collect();
    assert_eq!(acks.len(), 1, "an ACK is never answered");
    assert!(acks[0].h.has(flag::ACK) && acks[0].p == b"h2spec!!");
    assert_eq!(evs, [Ev::Pong(*b"unsolici")]);
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::PING, 0, 1, b"12345678");
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::PING, 0, 0, b"123456");
    conn_err(&mut srv, &raw.take(), ErrorCode::FRAME_SIZE_ERROR);
}

#[test]
fn s6_8_goaway() {
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::GOAWAY, 0, 1, &[0, 0, 0, 0, 0, 0, 0, 0]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0]);
    conn_err(&mut srv, &raw.take(), ErrorCode::FRAME_SIZE_ERROR);
    // a client GOAWAY with an unknown code: in-flight streams finish, then the server closes
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).raw(kind::GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0x12, 0x34]);
    let (evs, _) = feed(&mut srv, &raw.take(), 1);
    assert!(evs.contains(&Ev::GoAway { last: 0, code: ErrorCode(0x1234) }));
    assert!(!srv.wants_close());
    srv.send_response(1, 204, &[], true).unwrap();
    srv.stream_finished(1);
    assert!(srv.wants_close());
}

// ---------------------------------------------------------------- 6.9 WINDOW_UPDATE

#[test]
fn s6_9_window_update() {
    let (mut srv, mut raw) = server(quiet());
    raw.window_update(0, 0);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).window_update(1, 0);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::WINDOW_UPDATE, 0, 0, &[0, 0, 1]);
    conn_err(&mut srv, &raw.take(), ErrorCode::FRAME_SIZE_ERROR);
    // overflow
    let (mut srv, mut raw) = server(quiet());
    raw.window_update(0, 0x7fff_ffff);
    conn_err(&mut srv, &raw.take(), ErrorCode::FLOW_CONTROL_ERROR);
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).window_update(1, 0x7fff_ffff);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::FLOW_CONTROL_ERROR);
}

#[test]
fn s6_9_1_send_side_flow_control() {
    // SETTINGS_INITIAL_WINDOW_SIZE = 1: a response gets 1 byte, then more as windows open
    let (mut srv, mut raw) = server(quiet());
    raw.settings(&[(setting::INITIAL_WINDOW_SIZE, 1)]).get(1);
    feed(&mut srv, &raw.take(), 1);
    srv.send_response(1, 200, &[], false).unwrap();
    assert_eq!(srv.send_data(1, b"hello world!!", true), Ok(1));
    assert_eq!(srv.send_capacity(1), 0);
    assert_eq!(srv.poll_writable(), None);
    let frames = drain(&mut srv);
    let data: Vec<_> = frames.iter().filter(|f| f.h.kind == kind::DATA).collect();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].p, b"h");
    assert!(!data[0].h.has(flag::END_STREAM));
    raw.window_update(1, 1100);
    feed(&mut srv, &raw.take(), 1);
    assert_eq!(srv.poll_writable(), Some(1));
    assert_eq!(srv.poll_writable(), None);
    assert_eq!(srv.send_data(1, b"ello world!!", true), Ok(12));
    // the connection window limits too: 65535 minus what was sent
    let (mut srv, mut raw) = server(quiet());
    raw.settings(&[(setting::INITIAL_WINDOW_SIZE, 1 << 20)]).get(1);
    feed(&mut srv, &raw.take(), 1);
    srv.send_response(1, 200, &[], false).unwrap();
    let big = vec![0u8; 100_000];
    assert_eq!(srv.send_data(1, &big, false), Ok(65_535));
    // DATA frames respect the peer's max frame size
    let frames = drain(&mut srv);
    assert!(frames.iter().filter(|f| f.h.kind == kind::DATA).all(|f| f.p.len() <= 16_384));
}

#[test]
fn s6_9_2_initial_window_changes() {
    // a reduction can make a window negative; it then needs a larger update to recover
    let (mut srv, mut raw) = server(quiet());
    raw.get(1);
    feed(&mut srv, &raw.take(), 1);
    srv.send_response(1, 200, &[], false).unwrap();
    assert_eq!(srv.send_data(1, &[0u8; 1000], false), Ok(1000));
    raw.settings(&[(setting::INITIAL_WINDOW_SIZE, 100)]);
    feed(&mut srv, &raw.take(), 1);
    assert_eq!(srv.send_capacity(1), 0);
    raw.window_update(1, 1000);
    feed(&mut srv, &raw.take(), 1);
    assert_eq!(srv.send_capacity(1), 100);
    // raising the initial window above 2^31-1 for an open stream overflows
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).window_update(1, 0x7fff_0000);
    feed(&mut srv, &raw.take(), 1);
    raw.settings(&[(setting::INITIAL_WINDOW_SIZE, 0x10_0000)]);
    conn_err(&mut srv, &raw.take(), ErrorCode::FLOW_CONTROL_ERROR);
}

#[test]
fn receive_window_is_enforced() {
    let cfg = Config { initial_window_size: 1000, connection_window_size: 65_535, ..quiet() };
    // stream level: a stream error
    let (mut srv, mut raw) = server(cfg.clone());
    raw.headers(1, &POST, false).data(1, &[1u8; 1001], false);
    // before our SETTINGS were acknowledged the peer may use 65535: the server's handshake
    // helper acknowledged them, so 1000 applies
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::FLOW_CONTROL_ERROR);
    // connection level: a connection error
    let (mut srv, mut raw) = server(Config { initial_window_size: 65_535, ..cfg });
    for id in [1, 3] {
        raw.headers(id, &POST, false);
    }
    raw.data(1, &[1u8; 16_000], false).data(1, &[1u8; 16_000], false).data(1, &[1u8; 16_000], false);
    raw.data(3, &[1u8; 16_000], false).data(3, &[1u8; 2_000], false);
    conn_err(&mut srv, &raw.take(), ErrorCode::FLOW_CONTROL_ERROR);
}

#[test]
fn released_data_reopens_windows() {
    let cfg = Config { initial_window_size: 1000, connection_window_size: 65_535, ..quiet() };
    let (mut srv, mut raw) = server(cfg);
    raw.headers(1, &POST, false).data(1, &[1u8; 1000], false);
    let (_, frames) = feed(&mut srv, &raw.take(), 1);
    assert!(!frames.iter().any(|f| f.h.kind == kind::WINDOW_UPDATE), "nothing released yet");
    srv.release(1, 400);
    let frames = drain(&mut srv);
    assert!(frames.is_empty(), "under half the window: no update yet");
    srv.release(1, 10_000); // clamped to what was delivered
    let frames = drain(&mut srv);
    let wu: Vec<_> = frames.iter().filter(|f| f.h.kind == kind::WINDOW_UPDATE && f.h.stream == 1).collect();
    assert_eq!(wu.len(), 1);
    assert_eq!(u32::from_be_bytes(wu[0].p[..4].try_into().unwrap()), 1000);
    raw.data(1, &[1u8; 1000], true);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert!(evs.iter().any(|e| matches!(e, Ev::Data { end: true, .. })));
}

// ---------------------------------------------------------------- 6.10 CONTINUATION

#[test]
fn s6_10_continuation() {
    // several CONTINUATION frames are reassembled
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&[GET[0], GET[1], GET[2], GET[3], ("x-long", "abcdefghijklmnopqrstuvwxyz")]);
    raw.raw(kind::HEADERS, flag::END_STREAM, 1, &b[..3]);
    let mut at = 3;
    while at < b.len() {
        let end = (at + 4).min(b.len());
        raw.raw(kind::CONTINUATION, if end == b.len() { flag::END_HEADERS } else { 0 }, 1, &b[at..end]);
        at = end;
    }
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert!(matches!(&evs[0], Ev::Headers { fields, .. } if fields[0].0 == "x-long"));
    // CONTINUATION after a block that ended
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).raw(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x82]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    // CONTINUATION on stream 0
    let (mut srv, mut raw) = server(quiet());
    raw.raw(kind::CONTINUATION, flag::END_HEADERS, 0, &[0x82]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
    // a DATA frame in the middle of a block
    let (mut srv, mut raw) = server(quiet());
    let b = raw.block(&POST);
    raw.raw(kind::HEADERS, 0, 1, &b[..2]).data(1, b"x", false);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------- 8.1 HTTP messages

#[test]
fn s8_1_trailers_and_second_headers() {
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).data(1, b"abc", false).headers(1, &[("grpc-status", "0")], true);
    let (evs, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(goaway(&frames), None);
    assert!(evs.contains(&Ev::Trailers { stream: 1, fields: vec![("grpc-status".into(), "0".into())] }));
    // second HEADERS without END_STREAM
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).headers(1, &[("x", "y")], false);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
    // pseudo-header in trailers
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &POST, false).headers(1, &[(":status", "200")], true);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
}

#[test]
fn s8_1_2_malformed_requests() {
    let g = GET;
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![g[0], g[1], g[2], g[3], ("UPPER", "x")],
        vec![g[0], g[1], g[2], g[3], (":unknown", "x")],
        vec![g[0], g[1], g[2], g[3], (":status", "200")],
        vec![g[0], g[1], ("x", "y"), g[2], g[3]],
        vec![g[0], g[0], g[1], g[2], g[3]],
        vec![g[0], g[1], g[2], g[2], g[3]],
        vec![g[0], g[1], g[2], g[3], ("connection", "keep-alive")],
        vec![g[0], g[1], g[2], g[3], ("te", "trailers, deflate")],
        vec![g[1], g[2], g[3]],
        vec![g[0], g[2], g[3]],
        vec![g[0], g[1], g[3]],
        vec![g[0], g[1], (":path", ""), g[3]],
        vec![g[0], g[1], g[2], g[3], ("x-bad", "a\nb")],
    ];
    for (i, fields) in cases.iter().enumerate() {
        let (mut srv, mut raw) = server(quiet());
        raw.headers(1, fields, true);
        let evs = stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
        assert!(evs.is_empty(), "case {i}: the application never sees a malformed request");
        alive(&mut srv);
    }
}

#[test]
fn s8_1_2_6_content_length() {
    let post_cl = |n: &'static str| vec![POST[0], POST[1], POST[2], POST[3], ("content-length", n)];
    // DATA total below content-length
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &post_cl("10"), false).data(1, b"abc", true);
    let evs = stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
    assert!(evs.contains(&Ev::Reset { stream: 1, code: ErrorCode::PROTOCOL_ERROR, remote: false }));
    // above
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &post_cl("2"), false).data(1, b"abc", false);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
    // END_STREAM on HEADERS with a non-zero length
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &post_cl("1"), true);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
    // trailers ending a short body
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &post_cl("5"), false).data(1, b"abc", false).headers(1, &[("x", "y")], true);
    stream_err(&mut srv, &raw.take(), 1, ErrorCode::PROTOCOL_ERROR);
    // exact
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &post_cl("3"), false).data(1, b"ab", false).data(1, b"c", true);
    let (_, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(rst(&frames, 1), None);
}

#[test]
fn s8_4_push_promise_from_client() {
    let (mut srv, mut raw) = server(quiet());
    raw.get(1).raw(kind::PUSH_PROMISE, flag::END_HEADERS, 1, &[0, 0, 0, 2, 0x82]);
    conn_err(&mut srv, &raw.take(), ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------- hpack

#[test]
fn hpack_errors_are_compression_errors() {
    let cases: [&[u8]; 5] = [
        &[0x20, 0x82, 0x3f, 0xe1, 0x1f], // size update after a field
        &[0x3f, 0xe2, 0x1f],             // size update above SETTINGS_HEADER_TABLE_SIZE
        &[0x00, 0x81, 0xff, 0x82],       // huffman: padding longer than 7 bits... and garbage
        &[0x00, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00], // EOS
        &[0x40, 0x0a, b'x'],             // truncated literal
    ];
    for block in cases {
        let (mut srv, mut raw) = server(quiet());
        raw.raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, block);
        conn_err(&mut srv, &raw.take(), ErrorCode::COMPRESSION_ERROR);
    }
}

#[test]
fn hpack_state_survives_refused_streams() {
    // stream 3 is refused, but its block adds a dynamic entry that stream 5 then refers to
    let (mut srv, mut raw) = server(Config { max_concurrent_streams: 1, ..quiet() });
    raw.headers(1, &POST, false);
    raw.headers(3, &[GET[0], GET[1], GET[2], GET[3], ("x-custom", "kept")], true);
    let (_, frames) = feed(&mut srv, &raw.take(), 1);
    assert_eq!(rst(&frames, 3), Some(ErrorCode::REFUSED_STREAM));
    srv.reset(1, ErrorCode::CANCEL);
    srv.stream_finished(1);
    raw.headers(5, &[GET[0], GET[1], GET[2], GET[3], ("x-custom", "kept")], true);
    let b = raw.take();
    assert!(b.len() < 20, "the second block is all indexed fields");
    let (evs, _) = feed(&mut srv, &b, 1);
    assert!(matches!(&evs[0], Ev::Headers { stream: 5, fields, .. } if fields[0] == ("x-custom".to_string(), "kept".to_string())));
}

#[test]
fn events_borrow_without_copies() {
    // the Headers view exposes pseudo-headers and regular fields
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &[GET[0], GET[1], GET[2], GET[3], ("accept", "*/*"), ("host", "example.com")], true);
    let mut seen = false;
    srv.recv(&raw.take(), 1, &mut |e| {
        if let Event::Headers { headers, .. } = e {
            assert_eq!(headers.method(), Some(&b"GET"[..]));
            assert_eq!(headers.scheme(), Some(&b"https"[..]));
            assert_eq!(headers.authority(), Some(&b"example.com"[..]));
            assert_eq!(headers.get(b"accept"), Some(&b"*/*"[..]));
            assert_eq!(headers.len(), 2);
            seen = true;
        }
    });
    assert!(seen);
}
