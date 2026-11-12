//! HTTP/3 request/response tests over the in-memory QUIC network.

mod common;
use common::*;
use simoom_h3::{code, pseudo, Config as H3Config, Field, H3Event, SendError};
use simoom_quic::coding::put_varint;
use simoom_quic::sim::Link;
use std::collections::HashMap;
use std::time::Duration;

const LIMIT: Duration = Duration::from_secs(120);

#[derive(Default)]
struct Msg {
    headers: Vec<Field>,
    body: Vec<u8>,
    trailers: Vec<Field>,
    finished: bool,
    reset: Option<u64>,
    // Response being sent (server) with its progress.
    reply: Vec<u8>,
    sent: usize,
    replying: bool,
}

/// A server that echoes request bodies (or "hello <path>" for empty bodies) with trailers.
#[derive(Default)]
struct EchoServer {
    reqs: HashMap<u64, Msg>,
    served: usize,
}

impl EchoServer {
    fn step(&mut self, h: &mut H3Pair) {
        let now = h.p.now;
        let events: Vec<H3Event> = h.sev.drain(..).collect();
        let (h3, conn) = h.server_mut();
        let mut buf = vec![0u8; 8192];
        for e in events {
            match e {
                H3Event::Headers { stream, fields } => self.reqs.entry(stream).or_default().headers = fields,
                H3Event::Data { stream } => {
                    let m = self.reqs.entry(stream).or_default();
                    while let Ok((n, fin)) = h3.recv_body(now, conn, stream, &mut buf) {
                        m.body.extend_from_slice(&buf[..n]);
                        if fin || n == 0 {
                            break;
                        }
                    }
                }
                H3Event::Trailers { stream, fields } => self.reqs.entry(stream).or_default().trailers = fields,
                H3Event::Finished { stream } => self.reqs.entry(stream).or_default().finished = true,
                H3Event::Reset { stream, code } => self.reqs.entry(stream).or_default().reset = Some(code),
                _ => {}
            }
        }
        for (&id, m) in self.reqs.iter_mut() {
            if m.finished && !m.replying && m.reset.is_none() {
                m.replying = true;
                m.reply = if m.body.is_empty() {
                    let mut r = b"hello ".to_vec();
                    r.extend_from_slice(pseudo(&m.headers, b":path").unwrap_or(b"?"));
                    r
                } else {
                    m.body.clone()
                };
                let len = m.reply.len().to_string();
                h3.send_headers(conn, id, &[(b":status", b"200"), (b"content-length", len.as_bytes())], false).unwrap();
            }
            if m.replying && m.sent < m.reply.len() {
                match h3.send_body(conn, id, &m.reply[m.sent..], false) {
                    Ok(n) => m.sent += n,
                    Err(e) => panic!("send_body: {e:?}"),
                }
                if m.sent == m.reply.len() {
                    h3.send_trailers(conn, id, &[(b"x-checksum", m.reply.len().to_string().as_bytes())]).unwrap();
                    self.served += 1;
                }
            }
        }
    }
}

#[derive(Default)]
struct Client {
    resp: HashMap<u64, Msg>,
}

impl Client {
    fn step(&mut self, h: &mut H3Pair) {
        let now = h.p.now;
        let events: Vec<H3Event> = h.cev.drain(..).collect();
        let (h3, conn) = h.client_mut();
        let mut buf = vec![0u8; 8192];
        for e in events {
            match e {
                H3Event::Headers { stream, fields } => self.resp.entry(stream).or_default().headers = fields,
                H3Event::Data { stream } => {
                    let m = self.resp.entry(stream).or_default();
                    while let Ok((n, fin)) = h3.recv_body(now, conn, stream, &mut buf) {
                        m.body.extend_from_slice(&buf[..n]);
                        if fin || n == 0 {
                            break;
                        }
                    }
                }
                H3Event::Trailers { stream, fields } => self.resp.entry(stream).or_default().trailers = fields,
                H3Event::Finished { stream } => self.resp.entry(stream).or_default().finished = true,
                H3Event::Reset { stream, code } => self.resp.entry(stream).or_default().reset = Some(code),
                _ => {}
            }
        }
    }
}

fn post(path: &str, len: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut h = get(path);
    h[0].1 = b"POST".to_vec();
    h.push((b"content-length".to_vec(), len.to_string().into_bytes()));
    h
}

#[test]
fn get_request_response_round_trip() {
    let mut h = H3Pair::new(Link::default(), 1, Some(H3Config::default()), H3Config::default());
    let req = get("/hello");
    let (h3, conn) = h.client_mut();
    let id = h3.send_request(conn, &refs(&req), true).unwrap();
    let mut srv = EchoServer::default();
    let mut cl = Client::default();
    let ok = h.run(LIMIT, |h| {
        srv.step(h);
        cl.step(h);
        cl.resp.get(&id).is_some_and(|m| m.finished)
    });
    assert!(ok);
    let m = &cl.resp[&id];
    assert_eq!(pseudo(&m.headers, b":status"), Some(&b"200"[..]));
    assert_eq!(m.body, b"hello /hello");
    assert_eq!(pseudo(&m.trailers, b"x-checksum"), Some(&b"12"[..]));
    let sreq = &srv.reqs[&id];
    assert_eq!(pseudo(&sreq.headers, b"user-agent"), Some(&b"simoom-test"[..]));
    // Both sides exchanged SETTINGS.
    assert_eq!(h.client.as_ref().unwrap().peer_settings().unwrap().max_field_section_size, Some(16384));
}

#[test]
fn large_bodies_with_backpressure_and_trailers_over_a_lossy_link() {
    let link = Link { loss_ppm: 30_000, reorder_ppm: 50_000, reorder_delay: Duration::from_millis(20), ..Link::default() };
    let small = H3Config { body_buffer: 4096, ..H3Config::default() };
    let mut h = H3Pair::new(link, 2, Some(small.clone()), small);
    let body = pattern(1_000_000, 9);
    let req = post("/upload", body.len());
    let (h3, conn) = h.client_mut();
    let id = h3.send_request(conn, &refs(&req), false).unwrap();
    let mut off = 0;
    let mut srv = EchoServer::default();
    let mut cl = Client::default();
    let mut trailers_sent = false;
    let ok = h.run(LIMIT * 5, |h| {
        let (h3, conn) = h.client_mut();
        if off < body.len() {
            off += h3.send_body(conn, id, &body[off..], false).unwrap();
        } else if !trailers_sent {
            h3.send_trailers(conn, id, &[(b"x-req-trailer", b"yes")]).unwrap();
            trailers_sent = true;
        }
        srv.step(h);
        cl.step(h);
        cl.resp.get(&id).is_some_and(|m| m.finished)
    });
    assert!(ok, "sent {off}, server has {}", srv.reqs.get(&id).map_or(0, |m| m.body.len()));
    assert!(srv.reqs[&id].body == body);
    assert_eq!(pseudo(&srv.reqs[&id].trailers, b"x-req-trailer"), Some(&b"yes"[..]));
    assert!(cl.resp[&id].body == body);
}

#[test]
fn many_concurrent_requests_with_dynamic_qpack_and_reordering() {
    let link = Link { reorder_ppm: 200_000, reorder_delay: Duration::from_millis(30), loss_ppm: 10_000, ..Link::default() };
    let dynamic = H3Config { qpack_encoder_capacity: 4096, ..H3Config::default() };
    let mut h = H3Pair::new(link, 3, Some(dynamic.clone()), dynamic);
    let mut ids = Vec::new();
    for i in 0..60 {
        let mut req = get(&format!("/item/{}", i % 7));
        req.push((b"x-tenant".to_vec(), b"acme-corporation".to_vec()));
        req.push((b"cookie".to_vec(), format!("session=abcdef{}", i % 3).into_bytes()));
        let (h3, conn) = h.client_mut();
        match h3.send_request(conn, &refs(&req), true) {
            Ok(id) => ids.push((id, i)),
            Err(SendError::Stream(_)) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(ids.len() >= 50);
    let mut srv = EchoServer::default();
    let mut cl = Client::default();
    let ok = h.run(LIMIT, |h| {
        srv.step(h);
        cl.step(h);
        ids.iter().all(|(id, _)| cl.resp.get(id).is_some_and(|m| m.finished))
    });
    assert!(ok, "{} of {} finished", cl.resp.values().filter(|m| m.finished).count(), ids.len());
    for (id, i) in &ids {
        assert_eq!(cl.resp[id].body, format!("hello /item/{}", i % 7).into_bytes());
        assert_eq!(pseudo(&srv.reqs[id].headers, b"cookie").unwrap(), format!("session=abcdef{}", i % 3).as_bytes());
    }
}

#[test]
fn malformed_requests_get_stream_errors() {
    let mut h = H3Pair::new(Link::default(), 4, Some(H3Config::default()), H3Config::default());
    // Missing :path.
    let bad = vec![(b":method".to_vec(), b"GET".to_vec()), (b":scheme".to_vec(), b"https".to_vec())];
    let (h3, conn) = h.client_mut();
    let a = h3.send_request(conn, &refs(&bad), true).unwrap();
    // Content-length that does not match the body.
    let req = post("/x", 10);
    let b = h3.send_request(conn, &refs(&req), false).unwrap();
    h3.send_body(conn, b, b"short", true).unwrap();
    let mut cl = Client::default();
    let mut srv = EchoServer::default();
    let ok = h.run(LIMIT, |h| {
        srv.step(h);
        cl.step(h);
        cl.resp.get(&a).is_some_and(|m| m.reset.is_some()) && cl.resp.get(&b).is_some_and(|m| m.reset.is_some())
    });
    assert!(ok);
    assert_eq!(cl.resp[&a].reset, Some(code::MESSAGE_ERROR));
    assert_eq!(cl.resp[&b].reset, Some(code::MESSAGE_ERROR));
    // The connection is still usable.
    let (h3, conn) = h.client_mut();
    let c = h3.send_request(conn, &refs(&get("/ok")), true).unwrap();
    let ok = h.run(LIMIT, |h| {
        srv.step(h);
        cl.step(h);
        cl.resp.get(&c).is_some_and(|m| m.finished)
    });
    assert!(ok);
}

#[test]
fn field_section_size_limit() {
    let server = H3Config { max_field_section_size: 1000, ..H3Config::default() };
    let mut h = H3Pair::new(Link::default(), 5, Some(H3Config::default()), server);
    let mut req = get("/");
    req.push((b"x-big".to_vec(), vec![b'a'; 2000]));
    // The client honours the server's SETTINGS.
    let (h3, conn) = h.client_mut();
    assert_eq!(h3.send_request(conn, &refs(&req), true), Err(SendError::HeadersTooLarge));
}

#[test]
fn field_section_size_limit_enforced_on_receive() {
    let server = H3Config { max_field_section_size: 1000, ..H3Config::default() };
    let mut h = H3Pair::new(Link::default(), 6, None, server);
    let mut req = get("/");
    req.push((b"x-big".to_vec(), vec![b'a'; 2000]));
    let id = raw_request(&mut h, &req, true);
    let ok = h.run(LIMIT, |h| h.raw_cev.iter().any(|e| matches!(e, simoom_quic::Event::StreamReset { id: i, .. } if *i == id)));
    assert!(ok);
    assert!(h.raw_cev.contains(&simoom_quic::Event::StreamReset { id, code: code::EXCESSIVE_LOAD }));
}

#[test]
fn goaway_rejects_new_requests_and_finishes_old_ones() {
    let mut h = H3Pair::new(Link::default(), 7, Some(H3Config::default()), H3Config::default());
    let (h3, conn) = h.client_mut();
    let first = h3.send_request(conn, &refs(&get("/a")), true).unwrap();
    h.run_for(Duration::from_millis(50));
    let (h3, conn) = h.server_mut();
    let gid = h3.goaway(conn);
    assert_eq!(gid, first + 4);
    let mut srv = EchoServer::default();
    let mut cl = Client::default();
    let ok = h.run(LIMIT, |h| {
        srv.step(h);
        cl.step(h);
        cl.resp.get(&first).is_some_and(|m| m.finished) && h.cev.is_empty()
    });
    assert!(ok);
    let (h3, conn) = h.client_mut();
    assert_eq!(h3.send_request(conn, &refs(&get("/b")), true), Err(SendError::GoingAway));
    assert!(h.server.as_ref().unwrap().is_idle_after_goaway());
}

// ---------------------------------------------------------------- raw protocol errors

/// Sends a client control stream with SETTINGS, so the server accepts requests.
fn raw_settings(h: &mut H3Pair) -> u64 {
    let conn = h.cconn();
    let id = conn.open_uni().unwrap();
    let mut b = vec![0x00];
    simoom_h3::Settings::default().encode(&mut b);
    conn.stream_send(id, &b, false).unwrap();
    id
}

fn raw_request(h: &mut H3Pair, fields: &[(Vec<u8>, Vec<u8>)], fin: bool) -> u64 {
    raw_settings(h);
    let mut enc = simoom_qpack::Encoder::new();
    let conn = h.cconn();
    let id = conn.open_bi().unwrap();
    let mut block = Vec::new();
    enc.encode(id, &refs(fields), &mut block);
    let mut b = Vec::new();
    put_varint(&mut b, 0x01);
    put_varint(&mut b, block.len() as u64);
    b.extend_from_slice(&block);
    conn.stream_send(id, &b, fin).unwrap();
    id
}

fn expect_close(h: &mut H3Pair, code_: u64) {
    let ok = h.run(LIMIT, |h| h.server_error().is_some());
    assert!(ok, "server did not close the connection");
    assert_eq!(h.server_error(), Some(code_));
}

#[test]
fn control_stream_must_start_with_settings() {
    let mut h = H3Pair::new(Link::default(), 10, None, H3Config::default());
    let conn = h.cconn();
    let id = conn.open_uni().unwrap();
    conn.stream_send(id, &[0x00, 0x07, 0x01, 0x00], false).unwrap(); // GOAWAY first
    expect_close(&mut h, code::MISSING_SETTINGS);
}

#[test]
fn duplicate_control_stream_is_an_error() {
    let mut h = H3Pair::new(Link::default(), 11, None, H3Config::default());
    raw_settings(&mut h);
    raw_settings(&mut h);
    expect_close(&mut h, code::STREAM_CREATION_ERROR);
}

#[test]
fn closing_the_control_stream_is_an_error() {
    let mut h = H3Pair::new(Link::default(), 12, None, H3Config::default());
    let id = raw_settings(&mut h);
    h.run_for(Duration::from_millis(50));
    h.cconn().stream_finish(id).unwrap();
    expect_close(&mut h, code::CLOSED_CRITICAL_STREAM);
}

#[test]
fn data_before_headers_is_frame_unexpected() {
    let mut h = H3Pair::new(Link::default(), 13, None, H3Config::default());
    raw_settings(&mut h);
    let conn = h.cconn();
    let id = conn.open_bi().unwrap();
    conn.stream_send(id, &[0x00, 0x02, b'h', b'i'], true).unwrap();
    expect_close(&mut h, code::FRAME_UNEXPECTED);
}

#[test]
fn http2_frame_types_and_settings_are_rejected() {
    let mut h = H3Pair::new(Link::default(), 14, None, H3Config::default());
    let conn = h.cconn();
    let id = conn.open_uni().unwrap();
    conn.stream_send(id, &[0x00, 0x04, 0x02, 0x02, 0x01], false).unwrap(); // SETTINGS_ENABLE_PUSH
    expect_close(&mut h, code::SETTINGS_ERROR);
    let mut h = H3Pair::new(Link::default(), 15, None, H3Config::default());
    raw_settings(&mut h);
    let conn = h.cconn();
    let id = conn.open_bi().unwrap();
    conn.stream_send(id, &[0x06, 0x00], false).unwrap(); // HTTP/2 PING type
    expect_close(&mut h, code::FRAME_UNEXPECTED);
}

#[test]
fn unknown_stream_types_and_frames_are_ignored() {
    let mut h = H3Pair::new(Link::default(), 16, None, H3Config::default());
    raw_settings(&mut h);
    let conn = h.cconn();
    let u = conn.open_uni().unwrap();
    conn.stream_send(u, &[0x21, 1, 2, 3], false).unwrap(); // reserved stream type
    // A request with an unknown frame (type 0x21) before HEADERS.
    let mut enc = simoom_qpack::Encoder::new();
    let id = conn.open_bi().unwrap();
    let mut b = vec![0x21, 0x03, 9, 9, 9];
    let mut block = Vec::new();
    enc.encode(id, &refs(&get("/u")), &mut block);
    put_varint(&mut b, 0x01);
    put_varint(&mut b, block.len() as u64);
    b.extend_from_slice(&block);
    conn.stream_send(id, &b, true).unwrap();
    let mut srv = EchoServer::default();
    let ok = h.run(LIMIT, |h| {
        srv.step(h);
        srv.served == 1
    });
    assert!(ok);
    h.run_for(Duration::from_millis(100));
    assert_eq!(h.server_error(), None);
    // The unknown uni stream got STOP_SENDING with H3_STREAM_CREATION_ERROR.
    assert!(h.raw_cev.contains(&simoom_quic::Event::StreamStopped { id: u, code: code::STREAM_CREATION_ERROR }));
}

#[test]
fn push_streams_from_a_client_are_rejected() {
    let mut h = H3Pair::new(Link::default(), 17, None, H3Config::default());
    let conn = h.cconn();
    let u = conn.open_uni().unwrap();
    conn.stream_send(u, &[0x01, 0x00], false).unwrap();
    expect_close(&mut h, code::STREAM_CREATION_ERROR);
}

#[test]
fn truncated_request_is_request_incomplete() {
    let mut h = H3Pair::new(Link::default(), 18, None, H3Config::default());
    raw_settings(&mut h);
    let conn = h.cconn();
    let id = conn.open_bi().unwrap();
    conn.stream_send(id, &[0x21, 0x00], true).unwrap(); // only an unknown frame, then fin
    let ok = h.run(LIMIT, |h| h.raw_cev.iter().any(|e| matches!(e, simoom_quic::Event::StreamReset { .. })));
    assert!(ok);
    assert!(h.raw_cev.contains(&simoom_quic::Event::StreamReset { id, code: code::REQUEST_INCOMPLETE }));
}

#[test]
fn requests_over_real_tls() {
    use simoom_quic::tls::TlsProvider;
    use simoom_tls::certgen::{self, CertParams};
    use simoom_tls::keys::{EcCurve, PrivateKey};
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let ck = simoom_tls::CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap();
    let sp = TlsProvider::server(std::sync::Arc::new(simoom_tls::ServerConfig::new(ck).with_alpn(&[b"h3"])));
    let mut roots = simoom_tls::x509::RootStore::empty();
    roots.add_der(&ss.cert_der).unwrap();
    let cp = TlsProvider::client(std::sync::Arc::new(simoom_tls::ClientConfig::new(roots).with_alpn(&[b"h3"])));
    let cq = std::sync::Arc::new(simoom_quic::Config::new(std::sync::Arc::new(cp)));
    let sq = std::sync::Arc::new(simoom_quic::Config::new(std::sync::Arc::new(sp)));
    let dynamic = H3Config { qpack_encoder_capacity: 4096, ..H3Config::default() };
    let mut h = H3Pair::with_quic(cq, sq, Link::default(), 30, Some(dynamic.clone()), dynamic);
    let mut ids = Vec::new();
    for i in 0..20 {
        let (h3, conn) = h.client_mut();
        ids.push(h3.send_request(conn, &refs(&get(&format!("/tls/{i}"))), true).unwrap());
    }
    let mut srv = EchoServer::default();
    let mut cl = Client::default();
    let ok = h.run(LIMIT, |h| {
        srv.step(h);
        cl.step(h);
        ids.iter().all(|id| cl.resp.get(id).is_some_and(|m| m.finished))
    });
    assert!(ok);
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(cl.resp[id].body, format!("hello /tls/{i}").into_bytes());
    }
}

/// A server that writes only when told to (on `H3Event::Writable`), as an event loop does, must
/// still finish a response larger than the peer's stream window: a frame that fills the window
/// exactly used to leave the stream unregistered in QUIC, so MAX_STREAM_DATA never woke it.
#[test]
fn event_driven_response_larger_than_the_stream_window_finishes() {
    let mut h = H3Pair::new(Link::default(), 21, Some(H3Config::default()), H3Config::default());
    let req = get("/big");
    let (h3, conn) = h.client_mut();
    let id = h3.send_request(conn, &refs(&req), true).unwrap();
    let body = pattern(3 << 20, 4);
    let mut sent = 0usize;
    let mut started = false;
    let mut cl = Client::default();
    let ok = h.run(LIMIT, |h| {
        let events: Vec<H3Event> = h.sev.drain(..).collect();
        let (h3, conn) = h.server_mut();
        let mut write = false;
        for e in events {
            match e {
                H3Event::Finished { stream } if stream == id => {
                    h3.send_headers(conn, id, &[(b":status", b"200")], false).unwrap();
                    started = true;
                    write = true;
                }
                H3Event::Writable { stream } if stream == id => write = true,
                _ => {}
            }
        }
        if started && write {
            // Write until blocked, then wait for the next Writable event.
            while sent < body.len() {
                let n = h3.send_body(conn, id, &body[sent..], true).unwrap();
                if n == 0 {
                    break;
                }
                sent += n;
            }
        }
        cl.step(h);
        cl.resp.get(&id).is_some_and(|m| m.finished)
    });
    assert!(ok, "server sent {sent} of {}; client got {}", body.len(), cl.resp.get(&id).map_or(0, |m| m.body.len()));
    assert!(cl.resp[&id].body == body);
}

/// A server that has the request it needs stops reading and answers. RFC 9114 §4.1.1: the client
/// must not discard the response. A GET whose FIN was already sent, stopped with H3_NO_ERROR and
/// with code 0 (what quinn sends for every request stream it drops unread), and a POST still
/// uploading, stopped with H3_NO_ERROR.
#[test]
fn stop_sending_after_the_request_keeps_the_response() {
    for (req, fin, stop) in [(get("/stop"), true, code::NO_ERROR), (get("/quinn"), true, 0), (post("/upload", 100_000), false, code::NO_ERROR)] {
        let mut h = H3Pair::new(Link::default(), 41, Some(H3Config::default()), H3Config::default());
        let (h3, conn) = h.client_mut();
        let id = h3.send_request(conn, &refs(&req), fin).unwrap();
        if !fin {
            let chunk = vec![7u8; 4096];
            h3.send_body(conn, id, &chunk, false).unwrap();
        }
        let mut answered = false;
        let mut cl = Client::default();
        let ok = h.run(LIMIT, |h| {
            let events: Vec<H3Event> = h.sev.drain(..).collect();
            if !answered && events.iter().any(|e| matches!(e, H3Event::Headers { stream, .. } if *stream == id)) {
                answered = true;
                h.sconn().stream_stop(id, stop).unwrap();
                let (h3, conn) = h.server_mut();
                h3.send_headers(conn, id, &[(b":status", b"200"), (b"content-length", b"4")], false).unwrap();
                h3.send_body(conn, id, b"done", true).unwrap();
            }
            cl.step(h);
            cl.resp.get(&id).is_some_and(|m| m.finished || m.reset.is_some())
        });
        assert!(ok, "no outcome (fin={fin})");
        let m = &cl.resp[&id];
        assert_eq!(m.reset, None, "the response was discarded (fin={fin})");
        assert_eq!(pseudo(&m.headers, b":status"), Some(&b"200"[..]));
        assert_eq!(m.body, b"done");
    }
}

/// STOP_SENDING with an error code still abandons the request.
#[test]
fn stop_sending_with_an_error_resets_the_request() {
    let mut h = H3Pair::new(Link::default(), 43, Some(H3Config::default()), H3Config::default());
    let req = post("/upload", 100_000);
    let (h3, conn) = h.client_mut();
    let id = h3.send_request(conn, &refs(&req), false).unwrap();
    let mut stopped = false;
    let mut cl = Client::default();
    let ok = h.run(LIMIT, |h| {
        let events: Vec<H3Event> = h.sev.drain(..).collect();
        if !stopped && events.iter().any(|e| matches!(e, H3Event::Headers { stream, .. } if *stream == id)) {
            stopped = true;
            h.sconn().stream_stop(id, code::REQUEST_REJECTED).unwrap();
        }
        cl.step(h);
        cl.resp.get(&id).is_some_and(|m| m.reset.is_some())
    });
    assert!(ok);
    assert_eq!(cl.resp[&id].reset, Some(code::REQUEST_REJECTED));
}
