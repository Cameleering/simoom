//! RFC 8441 extended CONNECT (WebSocket over HTTP/2) and PING keepalive.

#![cfg(all(feature = "connect-protocol", feature = "keepalive"))]

mod common;

use common::*;
use simoom_h2::frame::{flag, kind, setting};
use simoom_h2::{Config, Connection, Error, ErrorCode, Event};

fn ws_server() -> Config {
    Config { enable_connect_protocol: true, ..quiet() }
}

#[test]
fn server_announces_and_accepts_extended_connect() {
    let mut srv = Connection::server(ws_server());
    let frames = drain(&mut srv);
    let s = frames.iter().find(|f| f.h.kind == kind::SETTINGS).unwrap();
    let has = s.p.chunks(6).any(|c| u16::from_be_bytes([c[0], c[1]]) == setting::ENABLE_CONNECT_PROTOCOL && c[5] == 1);
    assert!(has, "SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 announced");
    // A client never announces it, and a server without the option doesn't either.
    let mut cl = Connection::client(Config { enable_connect_protocol: true, ..quiet() });
    let mut plain = Connection::server(quiet());
    for c in [&mut cl, &mut plain] {
        for f in drain(c).iter().filter(|f| f.h.kind == kind::SETTINGS) {
            assert!(!f.p.chunks(6).any(|c| u16::from_be_bytes([c[0], c[1]]) == setting::ENABLE_CONNECT_PROTOCOL));
        }
    }
}

#[test]
fn websocket_tunnel_end_to_end() {
    let mut cl = Connection::client(quiet());
    let mut srv = Connection::server(ws_server());
    let (mut cev, mut sev) = (Vec::new(), Vec::new());
    // Before the server's SETTINGS arrive, extended CONNECT is refused locally.
    assert_eq!(cl.send_extended_connect(b"websocket", b"https", b"example.com", b"/chat", &[]), Err(Error::ConnectProtocolDisabled));
    pump(&mut cl, &mut srv, 0, &mut cev, &mut sev);
    assert!(cl.peer_connect_protocol());
    let id = cl.send_extended_connect(b"websocket", b"https", b"example.com", b"/chat", &[(b"sec-websocket-version", b"13"), (b"sec-websocket-protocol", b"chat")]).unwrap();
    pump(&mut cl, &mut srv, 0, &mut cev, &mut sev);
    // The server sees CONNECT with :protocol, :path and the stream left open.
    let mut seen = None;
    for e in &sev {
        if let Ev::Headers { stream, method, path, fields, end, .. } = e {
            seen = Some((*stream, method.clone(), path.clone(), fields.clone(), *end));
        }
    }
    let (sid, method, path, fields, end) = seen.expect("request headers");
    assert_eq!((sid, method.as_deref(), path.as_deref(), end), (id, Some("CONNECT"), Some("/chat"), false));
    assert!(fields.contains(&("sec-websocket-protocol".into(), "chat".into())));
    // 200 accepts; then frames both ways as DATA.
    srv.send_response(id, 200, &[(b"sec-websocket-protocol", b"chat")], false).unwrap();
    srv.send_data(id, b"\x81\x05hello", false).unwrap();
    cev.clear();
    sev.clear();
    pump(&mut cl, &mut srv, 0, &mut cev, &mut sev);
    assert!(cev.iter().any(|e| matches!(e, Ev::Headers { status: Some(200), end: false, .. })));
    assert!(cev.contains(&Ev::Data { stream: id, data: b"\x81\x05hello".to_vec(), end: false }));
    cl.send_data(id, b"\x82\x80abcd", false).unwrap();
    pump(&mut cl, &mut srv, 0, &mut cev, &mut sev);
    assert!(sev.contains(&Ev::Data { stream: id, data: b"\x82\x80abcd".to_vec(), end: false }));
    // Closing: both ends finish the stream.
    cl.send_data(id, b"", true).unwrap();
    srv.send_data(id, b"", true).unwrap();
    pump(&mut cl, &mut srv, 0, &mut cev, &mut sev);
    assert!(sev.contains(&Ev::Data { stream: id, data: Vec::new(), end: true }));
    assert!(cev.contains(&Ev::Data { stream: id, data: Vec::new(), end: true }));
}

#[test]
fn protocol_pseudo_header_needs_the_setting() {
    // A server without the option treats :protocol as malformed (RFC 8441 §3): stream error.
    let (mut srv, mut raw) = server(quiet());
    raw.headers(1, &[(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/"), (":authority", "a")], false);
    let (evs, frames) = feed(&mut srv, &raw.take(), 0);
    assert!(evs.is_empty(), "{evs:?}");
    assert_eq!(rst(&frames, 1), Some(ErrorCode::PROTOCOL_ERROR));
    // With the option, a malformed extended CONNECT (no :path) is a stream error too.
    let (mut srv, mut raw) = server(ws_server());
    raw.headers(1, &[(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":authority", "a")], false);
    let (evs, frames) = feed(&mut srv, &raw.take(), 0);
    assert!(evs.is_empty());
    assert_eq!(rst(&frames, 1), Some(ErrorCode::PROTOCOL_ERROR));
}

#[test]
fn enable_connect_protocol_values_are_checked() {
    for (vals, ok) in [(&[1u32][..], true), (&[0, 1][..], true), (&[2][..], false), (&[1, 0][..], false)] {
        let mut cl = Connection::client(quiet());
        drain(&mut cl);
        let mut raw = Raw::new();
        for &v in vals {
            raw.settings(&[(setting::ENABLE_CONNECT_PROTOCOL, v)]);
        }
        let mut evs = Vec::new();
        cl.recv(&raw.take(), 0, &mut |e| evs.push(own(e)));
        let frames = drain(&mut cl);
        assert_eq!(goaway(&frames).is_none(), ok, "{vals:?}");
        if ok {
            assert_eq!(cl.peer_connect_protocol(), *vals.last().unwrap() == 1);
        }
    }
}

fn pings(frames: &[Frame]) -> Vec<(bool, [u8; 8])> {
    frames.iter().filter(|f| f.h.kind == kind::PING).map(|f| (f.h.has(flag::ACK), f.p[..8].try_into().unwrap())).collect()
}

#[test]
fn keepalive_pings_a_quiet_peer_and_closes_a_dead_one() {
    let cfg = Config { keepalive_interval_ms: Some(1000), keepalive_timeout_ms: 500, ..quiet() };
    let (mut srv, mut raw) = server(cfg);
    // The handshake at t=0 counts as activity: next PING due at 1000.
    assert_eq!(srv.poll_timeout(), Some(1000));
    srv.handle_timeout(999, &mut |_| {});
    assert!(pings(&drain(&mut srv)).is_empty());
    srv.handle_timeout(1000, &mut |_| {});
    let p = pings(&drain(&mut srv));
    assert_eq!(p.len(), 1);
    assert!(!p[0].0);
    // Waiting for the answer: deadline at 1500.
    assert_eq!(srv.poll_timeout(), Some(1500));
    // The ACK clears it; the next PING is due an interval after that activity.
    raw.raw(kind::PING, flag::ACK, 0, &p[0].1);
    let (evs, _) = feed(&mut srv, &raw.take(), 1200);
    assert!(evs.is_empty(), "our own keepalive ACK is not reported: {evs:?}");
    assert_eq!(srv.poll_timeout(), Some(2200));
    // Activity of any kind postpones it.
    raw.ping(*b"12345678");
    let (_, frames) = feed(&mut srv, &raw.take(), 2000);
    assert_eq!(pings(&frames), [(true, *b"12345678")]);
    assert_eq!(srv.poll_timeout(), Some(3000));
    // A dead peer: PING at 3000, nothing back by 3500 → GOAWAY and Closed.
    srv.handle_timeout(3000, &mut |_| {});
    assert_eq!(pings(&drain(&mut srv)).len(), 1);
    let mut closed = None;
    srv.handle_timeout(3499, &mut |e| {
        if let Event::Closed { code } = e {
            closed = Some(code)
        }
    });
    assert_eq!(closed, None);
    srv.handle_timeout(3500, &mut |e| {
        if let Event::Closed { code } = e {
            closed = Some(code)
        }
    });
    assert_eq!(closed, Some(ErrorCode::NO_ERROR));
    assert_eq!(goaway(&drain(&mut srv)), Some(ErrorCode::NO_ERROR));
    assert!(srv.wants_close());
    assert_eq!(srv.poll_timeout(), None);
}

#[test]
fn keepalive_is_off_by_default_and_works_on_clients() {
    let (srv, _) = server(quiet());
    assert_eq!(srv.poll_timeout(), None);
    let mut cl = Connection::client(Config { keepalive_interval_ms: Some(100), ..quiet() });
    let mut srv = Connection::server(quiet());
    let (mut cev, mut sev) = (Vec::new(), Vec::new());
    pump(&mut cl, &mut srv, 0, &mut cev, &mut sev);
    // The client's own PING is answered by the server; the client reports nothing and stays up.
    cl.handle_timeout(100, &mut |_| {});
    pump(&mut cl, &mut srv, 150, &mut cev, &mut sev);
    assert!(!cev.iter().any(|e| matches!(e, Ev::Pong(_) | Ev::Closed(_))), "{cev:?}");
    cl.handle_timeout(10_000, &mut |_| {});
    assert!(!cl.wants_close());
}
