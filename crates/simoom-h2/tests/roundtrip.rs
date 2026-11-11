//! Client ↔ server round trips through the two sans-io engines.

mod common;

use common::*;
use simoom_h2::frame::{self, kind};
use simoom_h2::{http2_settings_header, Config, Connection, Error, ErrorCode};

/// Runs both engines until quiet; the closures act on events. Returns all events.
fn exchange(
    client: &mut Connection,
    server: &mut Connection,
    mut on_server: impl FnMut(&mut Connection, &Ev),
    mut on_client: impl FnMut(&mut Connection, &Ev),
) -> (Vec<Ev>, Vec<Ev>) {
    let (mut all_c, mut all_s) = (Vec::new(), Vec::new());
    for round in 0..1000u64 {
        let (mut cev, mut sev) = (Vec::new(), Vec::new());
        pump(client, server, round, &mut cev, &mut sev);
        if cev.is_empty() && sev.is_empty() {
            return (all_c, all_s);
        }
        for e in &sev {
            on_server(server, e);
        }
        for e in &cev {
            on_client(client, e);
        }
        all_c.extend(cev);
        all_s.extend(sev);
    }
    panic!("no quiescence");
}

fn respond_hello(srv: &mut Connection, e: &Ev) {
    if let Ev::Headers { stream, end: true, .. } = e {
        srv.send_response(*stream, 200, &[(b"content-type", b"text/plain")], false).unwrap();
        assert_eq!(srv.send_data(*stream, b"Hello, world!", true), Ok(13));
        srv.stream_finished(*stream);
    }
}

#[test]
fn simple_get() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    let id = c.send_request(b"GET", b"https", b"example.com", b"/hello", &[(b"accept", b"*/*")], true).unwrap();
    assert_eq!(id, 1);
    let (cev, sev) = exchange(&mut c, &mut s, respond_hello, |_, _| {});
    assert!(sev.iter().any(|e| matches!(e, Ev::Headers { stream: 1, method: Some(m), path: Some(p), fields, end: true, .. }
        if m == "GET" && p == "/hello" && fields == &[("accept".to_string(), "*/*".to_string())])));
    assert!(cev.iter().any(|e| matches!(e, Ev::Headers { stream: 1, status: Some(200), end: false, .. })));
    assert!(cev.contains(&Ev::Data { stream: 1, data: b"Hello, world!".to_vec(), end: true }));
    assert_eq!((c.tracked_streams(), s.tracked_streams()), (0, 0));
    assert_eq!((c.open_streams(), s.active_handlers()), (0, 0));
}

#[test]
fn hundred_concurrent_streams() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    // learn the server's limit first
    exchange(&mut c, &mut s, |_, _| {}, |_, _| {});
    assert_eq!(c.peer_max_concurrent_streams(), 100);
    let ids: Vec<u32> = (0..100).map(|i| c.send_request(b"GET", b"https", b"h", format!("/{i}").as_bytes(), &[], true).unwrap()).collect();
    assert_eq!(c.send_request(b"GET", b"https", b"h", b"/x", &[], true), Err(Error::StreamLimit));
    assert!(!c.can_open_stream());
    let (cev, _) = exchange(&mut c, &mut s, respond_hello, |_, _| {});
    for id in ids {
        assert!(cev.contains(&Ev::Data { stream: id, data: b"Hello, world!".to_vec(), end: true }));
    }
    assert!(c.can_open_stream());
    assert_eq!((c.tracked_streams(), s.tracked_streams()), (0, 0));
}

fn checksum(d: &[u8], acc: &mut u64) {
    for &b in d {
        *acc = acc.wrapping_mul(31).wrapping_add(b as u64);
    }
}

#[test]
fn large_upload_with_flow_control_and_window_tuning() {
    let total = 8 << 20;
    let body: Vec<u8> = (0..total).map(|i| (i * 7 % 251) as u8).collect();
    let mut want = 0u64;
    checksum(&body, &mut want);
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    let initial = s.receive_windows();
    let id = c.send_request(b"POST", b"https", b"h", b"/upload", &[], false).unwrap();
    let mut sent = 0;
    let mut got = 0u64;
    let mut sum = 0u64;
    let mut done = false;
    let mut delayed = std::collections::VecDeque::new();
    for round in 0..100_000u64 {
        if sent < total {
            sent += c.send_data(id, &body[sent..], true).unwrap();
        }
        let c2s = c.output().to_vec();
        c.advance_output(c2s.len());
        let mut evs = Vec::new();
        let now = round * 50; // 50 ms per round
        let n = s.recv(&c2s, now, &mut |e| evs.push(own(e)));
        assert_eq!(n, c2s.len());
        for e in evs {
            match e {
                Ev::Data { stream, data, end } => {
                    got += data.len() as u64;
                    checksum(&data, &mut sum);
                    s.release(stream, data.len());
                    if end {
                        s.send_response(stream, 204, &[], true).unwrap();
                        s.stream_finished(stream);
                        done = true;
                    }
                }
                Ev::Headers { .. } | Ev::Settings => {}
                other => panic!("{other:?}"),
            }
        }
        // the server-to-client path has two rounds of latency, so data is in flight while a
        // window-tuning PING travels
        delayed.push_back(s.output().to_vec());
        let n = s.output().len();
        s.advance_output(n);
        if delayed.len() > 2 {
            let s2c = delayed.pop_front().unwrap();
            assert_eq!(c.recv(&s2c, now, &mut |_| {}), s2c.len());
        }
        if done {
            break;
        }
    }
    assert!(done);
    assert_eq!(got, total as u64);
    assert_eq!(sum, want);
    let tuned = s.receive_windows();
    // the single stream was the bottleneck: its window grew (the connection's may too)
    assert!(tuned.1 > initial.1 && tuned.0 >= initial.0, "{initial:?} -> {tuned:?}");
}

#[test]
fn large_download_with_backpressure() {
    let total = 3 << 20;
    let body: Vec<u8> = (0..total).map(|i| (i % 253) as u8).collect();
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    let id = c.send_request(b"GET", b"https", b"h", b"/big", &[], true).unwrap();
    let mut sent = 0usize;
    let mut stream = None;
    let mut got = Vec::with_capacity(total);
    let mut finished = false;
    for round in 0..100_000u64 {
        let c2s = c.output().to_vec();
        c.advance_output(c2s.len());
        s.recv(&c2s, round, &mut |e| {
            if let simoom_h2::Event::Headers { stream: sid, .. } = e {
                stream = Some(sid);
            }
        });
        if let Some(sid) = stream.take() {
            s.send_response(sid, 200, &[(b"content-length", total.to_string().as_bytes())], false).unwrap();
            sent += s.send_data(sid, &body[sent..], true).unwrap();
        }
        while let Some(sid) = s.poll_writable() {
            sent += s.send_data(sid, &body[sent..], true).unwrap();
            if sent == total {
                s.stream_finished(sid);
            }
        }
        // the transport takes at most 64 KiB per round
        let n = s.output().len().min(64 * 1024);
        let s2c = s.output()[..n].to_vec();
        s.advance_output(n);
        while let Some(sid) = s.poll_writable() {
            sent += s.send_data(sid, &body[sent..], true).unwrap();
            if sent == total {
                s.stream_finished(sid);
            }
        }
        let mut off = 0;
        while off < s2c.len() {
            let mut evs = Vec::new();
            let used = c.recv(&s2c[off..], round, &mut |e| evs.push(own(e)));
            if used == 0 {
                break; // partial frame: kept for the next round
            }
            off += used;
            for e in evs {
                if let Ev::Data { stream, data, end } = e {
                    got.extend_from_slice(&data);
                    c.release(stream, data.len());
                    finished |= end;
                }
            }
        }
        // put back a partial frame
        if off < s2c.len() {
            let rest = s2c[off..].to_vec();
            let mut evs = Vec::new();
            let mut buf = rest;
            buf.extend_from_slice(s.output());
            let n2 = s.output().len();
            s.advance_output(n2);
            let used = c.recv(&buf, round, &mut |e| evs.push(own(e)));
            assert_eq!(used, buf.len());
            for e in evs {
                if let Ev::Data { stream, data, end } = e {
                    got.extend_from_slice(&data);
                    c.release(stream, data.len());
                    finished |= end;
                }
            }
        }
        if finished {
            break;
        }
    }
    assert!(finished);
    assert_eq!(got.len(), total);
    assert!(got == body);
    assert_eq!(id, 1);
}

#[test]
fn grpc_style_trailers() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    let id = c.send_request(b"POST", b"http", b"h", b"/pkg.Svc/Call", &[(b"content-type", b"application/grpc"), (b"te", b"trailers")], false).unwrap();
    assert_eq!(c.send_data(id, b"\0\0\0\0\x03abc", false), Ok(8));
    c.send_trailers(id, &[(b"x-client-trailer", b"1")]).unwrap();
    let (cev, sev) = exchange(
        &mut c,
        &mut s,
        |srv, e| {
            if let Ev::Trailers { stream, .. } = e {
                srv.send_response(*stream, 200, &[(b"content-type", b"application/grpc")], false).unwrap();
                srv.send_data(*stream, b"\0\0\0\0\x01z", false).unwrap();
                srv.send_trailers(*stream, &[(b"grpc-status", b"0"), (b"grpc-message", b"OK")]).unwrap();
                srv.stream_finished(*stream);
            }
        },
        |_, _| {},
    );
    assert!(sev.contains(&Ev::Trailers { stream: 1, fields: vec![("x-client-trailer".into(), "1".into())] }));
    assert!(cev.contains(&Ev::Trailers { stream: 1, fields: vec![("grpc-status".into(), "0".into()), ("grpc-message".into(), "OK".into())] }));
    assert_eq!(c.tracked_streams(), 0);
}

#[test]
fn large_header_blocks_use_continuation() {
    let cfg = Config { max_header_list_size: 128 * 1024, ..Config::default() };
    let mut c = Connection::client(cfg.clone());
    let mut s = Connection::server(cfg);
    exchange(&mut c, &mut s, |_, _| {}, |_, _| {});
    // ~40 KB of a value Huffman cannot shrink much
    let value: Vec<u8> = (0..40_000).map(|i| b"!#$%&'*+^|~"[i % 11]).collect();
    c.send_request(b"GET", b"https", b"h", b"/", &[(b"x-big", &value)], true).unwrap();
    let out = c.output().to_vec();
    let frames = frame::split_frames(&out);
    assert!(frames.iter().filter(|(h, _)| h.kind == kind::CONTINUATION).count() >= 2);
    let (_, sev) = exchange(&mut c, &mut s, respond_hello, |_, _| {});
    assert!(sev.iter().any(|e| matches!(e, Ev::Headers { fields, .. } if fields[0].1.len() == 40_000)));
}

#[test]
fn graceful_shutdown() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    let id = c.send_request(b"POST", b"https", b"h", b"/slow", &[], false).unwrap();
    exchange(&mut c, &mut s, |_, _| {}, |_, _| {});
    assert_eq!(s.active_handlers(), 1);
    s.shutdown(5);
    let (cev, _) = exchange(&mut c, &mut s, |_, _| {}, |_, _| {});
    assert_eq!(
        cev.iter().filter(|e| matches!(e, Ev::GoAway { .. })).cloned().collect::<Vec<_>>(),
        [Ev::GoAway { last: 0x7fff_ffff, code: ErrorCode::NO_ERROR }, Ev::GoAway { last: 1, code: ErrorCode::NO_ERROR }]
    );
    assert_eq!(c.send_request(b"GET", b"https", b"h", b"/", &[], true), Err(Error::GoingAway));
    assert!(!s.wants_close(), "stream 1 is still running");
    // the in-flight request completes
    c.send_data(id, b"body", true).unwrap();
    let (cev, _) = exchange(&mut c, &mut s, |srv, e| {
        if let Ev::Data { stream, end: true, .. } = e {
            srv.send_response(*stream, 200, &[], true).unwrap();
            srv.stream_finished(*stream);
        }
    }, |_, _| {});
    assert!(cev.iter().any(|e| matches!(e, Ev::Headers { stream: 1, status: Some(200), .. })));
    assert!(s.wants_close());
    assert!(c.wants_close());
}

#[test]
fn graceful_shutdown_times_out_without_ping_ack() {
    let (mut s, mut raw) = server(quiet());
    raw.get(1);
    feed(&mut s, &raw.take(), 0);
    s.shutdown(100);
    let frames = drain(&mut s);
    assert_eq!(frames.iter().filter(|f| f.h.kind == kind::GOAWAY).count(), 1);
    assert_eq!(s.poll_timeout(), Some(1100));
    // a new stream during phase one is still accepted
    raw.get(3);
    let (evs, _) = feed(&mut s, &raw.take(), 200);
    assert!(matches!(evs[0], Ev::Headers { stream: 3, .. }));
    s.handle_timeout(1100, &mut |_| {});
    let frames = drain(&mut s);
    let g: Vec<_> = frames.iter().filter(|f| f.h.kind == kind::GOAWAY).collect();
    assert_eq!(g.len(), 1);
    assert_eq!(u32::from_be_bytes(g[0].p[..4].try_into().unwrap()), 3);
    // streams above the last one are ignored now
    raw.get(5);
    let (evs, frames) = feed(&mut s, &raw.take(), 1200);
    assert!(evs.is_empty() && frames.is_empty());
    for id in [1, 3] {
        s.send_response(id, 204, &[], true).unwrap();
        s.stream_finished(id);
    }
    assert!(s.wants_close());
}

#[test]
fn client_streams_above_goaway_are_refused() {
    let mut c = Connection::client(quiet());
    drain(&mut c);
    for _ in 0..3 {
        c.send_request(b"GET", b"https", b"h", b"/", &[], true).unwrap();
    }
    let mut raw = Raw::new();
    raw.settings(&[]);
    frame::write_goaway(&mut raw.buf, 1, ErrorCode::NO_ERROR, b"bye");
    let (evs, _) = feed(&mut c, &raw.take(), 0);
    assert!(evs.contains(&Ev::GoAway { last: 1, code: ErrorCode::NO_ERROR }));
    assert!(evs.contains(&Ev::Reset { stream: 3, code: ErrorCode::REFUSED_STREAM, remote: true }));
    assert!(evs.contains(&Ev::Reset { stream: 5, code: ErrorCode::REFUSED_STREAM, remote: true }));
    assert!(!evs.iter().any(|e| matches!(e, Ev::Reset { stream: 1, .. })));
    assert_eq!(c.tracked_streams(), 1);
}

#[test]
fn h2c_upgrade() {
    let cfg = Config { initial_window_size: 100_000, ..Config::default() };
    let header = http2_settings_header(&cfg);
    assert!(!header.contains('='));
    let mut s = Connection::server_upgrade(Config::default(), header.as_bytes()).unwrap();
    let mut c = Connection::client_upgrade(cfg, false);
    assert_eq!(s.active_handlers(), 1);
    // the server answers the upgraded request on stream 1
    s.send_response(1, 200, &[(b"x-upgraded", b"yes")], false).unwrap();
    assert_eq!(s.send_data(1, b"over h2", true), Ok(7));
    s.stream_finished(1);
    let (cev, _) = exchange(&mut c, &mut s, respond_hello, |_, _| {});
    assert!(cev.iter().any(|e| matches!(e, Ev::Headers { stream: 1, status: Some(200), .. })));
    assert!(cev.contains(&Ev::Data { stream: 1, data: b"over h2".to_vec(), end: true }));
    // and the connection carries further requests
    assert_eq!(c.send_request(b"GET", b"http", b"h", b"/next", &[], true), Ok(3));
    let (cev, _) = exchange(&mut c, &mut s, respond_hello, |_, _| {});
    assert!(cev.contains(&Ev::Data { stream: 3, data: b"Hello, world!".to_vec(), end: true }));
    // bad settings values
    assert_eq!(Connection::server_upgrade(Config::default(), b"!!!").err(), Some(Error::InvalidUpgradeSettings));
    assert_eq!(Connection::server_upgrade(Config::default(), b"AAUAAA").err(), Some(Error::InvalidUpgradeSettings)); // MAX_FRAME_SIZE 0
    assert_eq!(Connection::server_upgrade(Config::default(), b"AAUA").err(), Some(Error::InvalidUpgradeSettings)); // 3 bytes
}

#[test]
fn informational_responses_and_ping() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    c.send_request(b"POST", b"https", b"h", b"/", &[(b"expect", b"100-continue")], false).unwrap();
    c.ping(*b"rtt-test");
    let (cev, _) = exchange(
        &mut c,
        &mut s,
        |srv, e| {
            if let Ev::Headers { stream, .. } = e {
                srv.send_response(*stream, 100, &[], false).unwrap();
                srv.send_response(*stream, 200, &[], true).unwrap();
                assert_eq!(srv.send_response(*stream, 200, &[], true), Err(Error::StreamClosed));
                srv.stream_finished(*stream);
            }
        },
        |_, _| {},
    );
    let statuses: Vec<u16> = cev.iter().filter_map(|e| if let Ev::Headers { status, .. } = e { *status } else { None }).collect();
    assert_eq!(statuses, [100, 200]);
    assert!(cev.contains(&Ev::Pong(*b"rtt-test")));
    // the server reset CANCEL'd the unread request body
    assert!(!cev.iter().any(|e| matches!(e, Ev::Reset { code, .. } if *code != ErrorCode::NO_ERROR)));
}

#[test]
fn resets_reach_the_other_side() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    c.send_request(b"GET", b"https", b"h", b"/a", &[], true).unwrap();
    c.send_request(b"GET", b"https", b"h", b"/b", &[], true).unwrap();
    let (cev, _) = exchange(
        &mut c,
        &mut s,
        |srv, e| match e {
            Ev::Headers { stream: 1, .. } => srv.reset(1, ErrorCode::REFUSED_STREAM),
            Ev::Headers { stream: 3, .. } => srv.stream_finished(3), // no response at all
            _ => {}
        },
        |_, _| {},
    );
    assert!(cev.contains(&Ev::Reset { stream: 1, code: ErrorCode::REFUSED_STREAM, remote: true }));
    assert!(cev.contains(&Ev::Reset { stream: 3, code: ErrorCode::CANCEL, remote: true }));
    assert_eq!(s.active_handlers(), 1, "stream 1's handler was never finished");
    s.stream_finished(1);
    assert_eq!((s.tracked_streams(), c.tracked_streams()), (0, 0));
}

#[test]
fn client_cancel_reaches_the_server_handler() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    let id = c.send_request(b"GET", b"https", b"h", b"/slow", &[], true).unwrap();
    exchange(&mut c, &mut s, |_, _| {}, |_, _| {});
    c.reset(id, ErrorCode::CANCEL);
    let (_, sev) = exchange(&mut c, &mut s, |srv, e| {
        if let Ev::Reset { stream, .. } = e {
            assert_eq!(srv.send_response(*stream, 200, &[], true), Err(Error::StreamReset));
            srv.stream_finished(*stream);
        }
    }, |_, _| {});
    assert!(sev.contains(&Ev::Reset { stream: 1, code: ErrorCode::CANCEL, remote: true }));
    assert_eq!(s.tracked_streams(), 0);
}

#[test]
fn sending_api_validation() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    assert_eq!(c.send_request(b"GET", b"https", b"h", b"/", &[(b"Upper", b"x")], true), Err(Error::InvalidHeader));
    assert_eq!(c.send_request(b"GET", b"https", b"h", b"/", &[(b"connection", b"close")], true), Err(Error::InvalidHeader));
    assert_eq!(c.send_request(b"GET", b"https", b"h", b"/", &[(b"x", b"a\r\nb: c")], true), Err(Error::InvalidHeader));
    assert_eq!(c.send_request(b"G T", b"https", b"h", b"/", &[], true), Err(Error::InvalidHeader));
    assert_eq!(c.send_request(b"GET", b"https", b"h", b"", &[], true), Err(Error::InvalidHeader));
    assert_eq!(c.send_response(1, 200, &[], true), Err(Error::WrongRole));
    assert_eq!(s.send_request(b"GET", b"https", b"h", b"/", &[], true), Err(Error::WrongRole));
    assert_eq!(s.send_response(1, 200, &[], true), Err(Error::UnknownStream));
    let id = c.send_request(b"HEAD", b"https", b"h", b"/", &[], true).unwrap();
    assert_eq!(c.send_data(id, b"x", true), Err(Error::StreamClosed));
    let (cev, _) = exchange(
        &mut c,
        &mut s,
        |srv, e| {
            if let Ev::Headers { stream, .. } = e {
                assert_eq!(srv.send_data(*stream, b"x", false), Err(Error::HeadersNotSent));
                assert_eq!(srv.send_response(*stream, 101, &[], false), Err(Error::InvalidHeader));
                assert_eq!(srv.send_response(*stream, 100, &[], true), Err(Error::InvalidHeader));
                assert_eq!(srv.send_response(*stream, 200, &[(b"transfer-encoding", b"chunked")], true), Err(Error::InvalidHeader));
                // HEAD: a content-length without a body
                srv.send_response(*stream, 200, &[(b"content-length", b"1234")], true).unwrap();
                srv.stream_finished(*stream);
            }
        },
        |_, _| {},
    );
    assert!(cev.iter().any(|e| matches!(e, Ev::Headers { status: Some(200), end: true, .. })));
    assert!(!cev.iter().any(|e| matches!(e, Ev::Reset { .. })));
    // after close nothing can be sent
    s.close(ErrorCode::NO_ERROR, b"");
    assert!(s.wants_close());
    assert_eq!(s.send_response(99, 200, &[], true), Err(Error::ConnectionClosed));
}

#[test]
fn server_response_without_reading_body_cuts_it_off() {
    let mut c = Connection::client(Config::default());
    let mut s = Connection::server(Config::default());
    let id = c.send_request(b"POST", b"https", b"h", b"/", &[], false).unwrap();
    c.send_data(id, &[1u8; 1000], false).unwrap();
    let (cev, _) = exchange(
        &mut c,
        &mut s,
        |srv, e| {
            if let Ev::Headers { stream, .. } = e {
                srv.send_response(*stream, 413, &[], true).unwrap();
                srv.stream_finished(*stream);
            }
        },
        |_, _| {},
    );
    assert!(cev.iter().any(|e| matches!(e, Ev::Headers { status: Some(413), .. })));
    assert!(cev.contains(&Ev::Reset { stream: 1, code: ErrorCode::NO_ERROR, remote: true }));
    assert_eq!((c.tracked_streams(), s.tracked_streams()), (0, 0));
}

/// RFC 9113 §8.1: a server may send a complete response before the request is complete and
/// then RST_STREAM(NO_ERROR); the client must not discard the response. (Cameleer's
/// `a_complete_response_survives_rst_stream_no_error`, INTEROP bug 20, for the client role.)
#[test]
fn client_keeps_a_complete_response_followed_by_rst_stream_no_error() {
    let mut c = Connection::client(quiet());
    let mut s = Connection::server(quiet());
    // a POST whose body is still coming
    let id = c.send_request(b"POST", b"https", b"h", b"/early", &[], false).unwrap();
    let (cev, _) = exchange(
        &mut c,
        &mut s,
        |srv, e| {
            if let Ev::Headers { stream, end: false, .. } = e {
                // answer at once, then finish the handler: the engine resets the unread request
                // side with RST_STREAM(NO_ERROR)
                srv.send_response(*stream, 200, &[], false).unwrap();
                assert_eq!(srv.send_data(*stream, b"early answer", true), Ok(12));
                srv.stream_finished(*stream);
            }
        },
        |_, _| {},
    );
    assert!(cev.iter().any(|e| matches!(e, Ev::Headers { stream, status: Some(200), .. } if *stream == id)), "{cev:?}");
    let body: Vec<u8> = cev.iter().filter_map(|e| match e { Ev::Data { stream, data, .. } if *stream == id => Some(data.clone()), _ => None }).flatten().collect();
    assert_eq!(body, b"early answer");
    assert!(cev.contains(&Ev::Data { stream: id, data: b"early answer".to_vec(), end: true }), "{cev:?}");
    // the reset, if reported at all, is NO_ERROR and comes after the end of the response
    let end_at = cev.iter().position(|e| matches!(e, Ev::Data { end: true, .. })).unwrap();
    for (i, e) in cev.iter().enumerate() {
        if let Ev::Reset { code, .. } = e {
            assert_eq!(*code, ErrorCode::NO_ERROR);
            assert!(i > end_at);
        }
        assert!(!matches!(e, Ev::GoAway { .. } | Ev::Closed(_)), "{cev:?}");
    }
    // the rest of the request body is dropped without a connection error
    let _ = c.send_data(id, b"late request body", true);
    let (cev2, _) = exchange(&mut c, &mut s, |_, _| {}, |_, _| {});
    assert!(!cev2.iter().any(|e| matches!(e, Ev::GoAway { .. } | Ev::Closed(_))), "{cev2:?}");
    assert!(!c.wants_close() && !s.wants_close());
    // and the connection carries on
    let id2 = c.send_request(b"GET", b"https", b"h", b"/next", &[], true).unwrap();
    let (cev3, _) = exchange(&mut c, &mut s, respond_hello, |_, _| {});
    assert!(cev3.contains(&Ev::Data { stream: id2, data: b"Hello, world!".to_vec(), end: true }), "{cev3:?}");
}

/// The same with the response and the RST_STREAM(NO_ERROR) in one read, as a raw server sends
/// them.
#[test]
fn client_keeps_a_response_and_rst_stream_no_error_in_one_read() {
    let mut c = Connection::client(quiet());
    let id = c.send_request(b"POST", b"https", b"h", b"/early", &[], false).unwrap();
    drain(&mut c);
    let mut raw = Raw::new();
    raw.settings(&[]).settings_ack();
    raw.headers(id, &[(":status", "200"), ("content-type", "text/plain")], false);
    raw.data(id, b"early answer", true);
    raw.rst(id, ErrorCode::NO_ERROR);
    let (evs, frames) = feed(&mut c, &raw.take(), 0);
    assert!(evs.iter().any(|e| matches!(e, Ev::Headers { stream, status: Some(200), end: false, .. } if *stream == id)), "{evs:?}");
    assert!(evs.contains(&Ev::Data { stream: id, data: b"early answer".to_vec(), end: true }), "{evs:?}");
    assert!(evs.iter().all(|e| !matches!(e, Ev::Reset { code, .. } if *code != ErrorCode::NO_ERROR)), "{evs:?}");
    assert_eq!(goaway(&frames), None);
    assert_eq!(rst(&frames, id), None, "the client must not answer the reset");
    let _ = c.send_data(id, b"late", true);
    let frames = drain(&mut c);
    assert_eq!(goaway(&frames), None);
    assert!(frames.iter().all(|f| !(f.h.kind == kind::DATA && f.h.stream == id)), "nothing more is sent on a reset stream");
    assert!(!c.wants_close());
}
