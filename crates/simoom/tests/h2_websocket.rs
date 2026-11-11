//! WebSocket over HTTP/2 (RFC 8441) through the facade, driven by simoom-h2's client role:
//! the setting, the extended CONNECT, frames both ways on one stream, `WsHandle` from another
//! thread, the closing handshake, other streams alongside, and refusals.

#![cfg(feature = "websocket-h2")]

mod common;

use common::*;
use simoom::{Reply, Request, WebSocket, WebSocketHandler, WsMessage};
use simoom_h2::{Config, Connection, Error, Event};
use simoom_http1::ws::{write_close, write_frame, FrameDecoder, Opcode, Role, WsEvent, WsLimits};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Echo {
    closed: mpsc::Sender<u16>,
}

impl WebSocketHandler for Echo {
    fn on_open(&mut self, ws: &mut WebSocket<'_>) {
        ws.send_text("welcome");
        // a message from another thread, through the handle
        let h = ws.handle();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            h.send_text("from a thread");
        });
    }
    fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {
        match msg {
            WsMessage::Text("bye") => ws.close(1000, "done"),
            WsMessage::Text(t) => ws.send_text(&format!("echo {t}")),
            WsMessage::Binary(b) => ws.send_binary(b),
        }
    }
    fn on_close(&mut self, code: u16, _reason: &str) {
        let _ = self.closed.send(code);
    }
}

fn server(closed: mpsc::Sender<u16>) -> simoom::ServerHandle {
    let closed = std::sync::Mutex::new(closed);
    serve(move |req: &mut Request<'_>, reply: Reply<'_>| {
        if req.path() == b"/chat" && req.is_websocket_upgrade() {
            let tx = closed.lock().unwrap().clone();
            let proto = req.header("sec-websocket-protocol").map(|_| "chat");
            reply.websocket_with_protocol(proto, Echo { closed: tx })
        } else if req.path() == b"/ws-anyway" {
            // not an upgrade: Reply::websocket answers 400
            reply.websocket(Echo { closed: closed.lock().unwrap().clone() })
        } else {
            reply.header("content-type", "text/plain").body("plain")
        }
    })
}

struct Client {
    s: TcpStream,
    c: Connection,
    inbuf: Vec<u8>,
    t0: Instant,
}

#[derive(Default)]
struct StreamState {
    status: u16,
    proto: Option<Vec<u8>>,
    data: Vec<u8>,
    end: bool,
    reset: bool,
}

impl Client {
    fn new(h: &simoom::ServerHandle) -> Client {
        let s = connect(h);
        s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        Client { s, c: Connection::client(Config::default()), inbuf: Vec::new(), t0: Instant::now() }
    }

    /// Writes our output, reads what is there, and feeds it to the engine.
    fn turn(&mut self, streams: &mut std::collections::HashMap<u32, StreamState>) -> bool {
        let out = self.c.output().to_vec();
        self.c.advance_output(out.len());
        if !out.is_empty() {
            self.s.write_all(&out).unwrap();
        }
        let mut buf = [0u8; 65536];
        let mut settings = false;
        match self.s.read(&mut buf) {
            Ok(0) => return false,
            Ok(n) => self.inbuf.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
        let now = self.t0.elapsed().as_millis() as u64;
        let mut release = Vec::new();
        let used = self.c.recv(&self.inbuf, now, &mut |e| match e {
            Event::Headers { stream, headers, end_stream } => {
                let st = streams.entry(stream).or_default();
                st.status = headers.status().unwrap_or(0);
                st.proto = headers.get(b"sec-websocket-protocol").map(<[u8]>::to_vec);
                st.end |= end_stream;
            }
            Event::Data { stream, data, end_stream } => {
                let st = streams.entry(stream).or_default();
                st.data.extend_from_slice(data);
                st.end |= end_stream;
                release.push((stream, data.len()));
            }
            Event::Reset { stream, .. } => streams.entry(stream).or_default().reset = true,
            Event::Settings => settings = true,
            _ => {}
        });
        self.inbuf.drain(..used);
        for (s, n) in release {
            self.c.release(s, n);
        }
        let _ = settings;
        true
    }

    fn until(&mut self, streams: &mut std::collections::HashMap<u32, StreamState>, mut f: impl FnMut(&mut Connection, &std::collections::HashMap<u32, StreamState>) -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !f(&mut self.c, streams) {
            assert!(Instant::now() < end, "timed out");
            assert!(self.turn(streams), "connection closed");
        }
    }
}

/// Decodes server frames (unmasked) from `bytes`: text and binary messages, and close codes.
fn frames(bytes: &[u8]) -> Vec<String> {
    let mut d = FrameDecoder::new(Role::Client, WsLimits { max_frame: 1 << 20, max_message: 1 << 20 });
    let mut buf = bytes.to_vec();
    let mut pos = 0;
    let mut out = Vec::new();
    while pos < buf.len() {
        let (n, ev) = d.decode(&mut buf[pos..]).expect("valid frames");
        match ev {
            WsEvent::NeedMore => break,
            WsEvent::Data { text: true, payload, .. } => out.push(String::from_utf8_lossy(payload).into_owned()),
            WsEvent::Data { text: false, payload, .. } => out.push(format!("bin {}", payload.len())),
            WsEvent::Close { code, .. } => out.push(format!("close {}", code.unwrap_or(0))),
            _ => {}
        }
        pos += n;
    }
    out
}

fn masked(op: Opcode, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    write_frame(&mut f, true, op, payload, Some([1, 2, 3, 4]));
    f
}

#[test]
fn websocket_over_http2() {
    let (tx, rx) = mpsc::channel();
    let h = server(tx);
    let mut cl = Client::new(&h);
    let mut streams = std::collections::HashMap::new();
    // the server's SETTINGS enable extended CONNECT
    cl.until(&mut streams, |c, _| c.peer_connect_protocol());
    let id = cl.c.send_extended_connect(b"websocket", b"http", b"t", b"/chat", &[(b"sec-websocket-version", b"13"), (b"sec-websocket-protocol", b"chat, other")]).unwrap();
    // a plain request on another stream at the same time
    let plain = cl.c.send_request(b"GET", b"http", b"t", b"/", &[], true).unwrap();
    cl.until(&mut streams, |_, s| s.get(&id).is_some_and(|x| frames(&x.data).len() >= 2) && s.get(&plain).is_some_and(|x| x.end));
    let ws = &streams[&id];
    assert_eq!(ws.status, 200);
    assert_eq!(ws.proto.as_deref(), Some(&b"chat"[..]));
    assert!(!ws.end);
    assert_eq!(frames(&ws.data), ["welcome", "from a thread"]);
    assert_eq!(streams[&plain].data, b"plain");
    // echo, text and binary, the second split across two DATA frames
    cl.c.send_data(id, &masked(Opcode::Text, b"hello"), false).unwrap();
    let big = masked(Opcode::Binary, &vec![7u8; 40_000]);
    cl.c.send_data(id, &big[..1000], false).unwrap();
    cl.turn(&mut streams);
    cl.c.send_data(id, &big[1000..], false).unwrap();
    cl.until(&mut streams, |_, s| frames(&s[&id].data).len() >= 4);
    assert_eq!(frames(&streams[&id].data)[2..], ["echo hello", "bin 40000"]);
    // a ping is answered with a pong (not reported as a message)
    cl.c.send_data(id, &masked(Opcode::Ping, b"p"), false).unwrap();
    // closing handshake: the server closes, we answer, the stream ends
    cl.c.send_data(id, &masked(Opcode::Text, b"bye"), false).unwrap();
    cl.until(&mut streams, |_, s| frames(&s[&id].data).last().is_some_and(|l| l.starts_with("close")));
    assert_eq!(frames(&streams[&id].data).last().unwrap(), "close 1000");
    let mut c = Vec::new();
    write_close(&mut c, 1000, "", Some([9, 9, 9, 9]));
    cl.c.send_data(id, &c, true).unwrap();
    cl.until(&mut streams, |_, s| s[&id].end || s[&id].reset);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1000);
    h.stop(Duration::from_secs(1));
}

#[test]
fn http2_websocket_refusals_and_lost_peers() {
    let (tx, rx) = mpsc::channel();
    let h = server(tx);
    let mut cl = Client::new(&h);
    let mut streams = std::collections::HashMap::new();
    cl.until(&mut streams, |c, _| c.peer_connect_protocol());
    // an extended CONNECT for another protocol is a normal request to the service (not a
    // WebSocket upgrade)
    let other = cl.c.send_extended_connect(b"something-else", b"http", b"t", b"/chat", &[]).unwrap();
    cl.until(&mut streams, |_, s| s.get(&other).is_some_and(|x| x.status != 0));
    assert_eq!(streams[&other].status, 200);
    assert_eq!(streams[&other].data, b"plain");
    // Reply::websocket on a request that isn't an extended CONNECT: 400 (with `close`, which
    // ends this HTTP/2 connection gracefully, so on a connection of its own)
    let mut cl2 = Client::new(&h);
    let mut streams2 = std::collections::HashMap::new();
    let get = cl2.c.send_request(b"GET", b"http", b"t", b"/ws-anyway", &[], true).unwrap();
    cl2.until(&mut streams2, |_, s| s.get(&get).is_some_and(|x| x.end));
    assert_eq!(streams2[&get].status, 400);
    // a client that resets its WebSocket stream: the handler hears 1006
    let id = cl.c.send_extended_connect(b"websocket", b"http", b"t", b"/chat", &[]).unwrap();
    cl.until(&mut streams, |_, s| s.get(&id).is_some_and(|x| x.status == 200));
    cl.c.reset(id, simoom_h2::ErrorCode::CANCEL);
    cl.turn(&mut streams);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1006);
    // a client that ends its side without a close frame: 1006 too, and the stream ends
    let id = cl.c.send_extended_connect(b"websocket", b"http", b"t", b"/chat", &[]).unwrap();
    cl.until(&mut streams, |_, s| s.get(&id).is_some_and(|x| x.status == 200));
    cl.c.send_data(id, b"", true).unwrap();
    cl.until(&mut streams, |_, s| s[&id].end || s[&id].reset);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1006);
    // stopping the server closes open WebSockets with 1001
    let id = cl.c.send_extended_connect(b"websocket", b"http", b"t", b"/chat", &[]).unwrap();
    cl.until(&mut streams, |_, s| s.get(&id).is_some_and(|x| x.status == 200));
    h.stop(Duration::from_secs(2));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1001);
}

#[test]
fn a_server_without_websocket_routes_does_not_need_the_client_to_care() {
    // The client API refuses extended CONNECT until the server's SETTINGS allow it.
    let mut c = Connection::client(Config::default());
    assert_eq!(c.send_extended_connect(b"websocket", b"http", b"t", b"/", &[]), Err(Error::ConnectProtocolDisabled));
}
