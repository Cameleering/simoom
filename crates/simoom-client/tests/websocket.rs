//! The WebSocket client against simoom's WebSocket server, plain, over TLS and through a
//! proxy, plus scripted servers for the edge cases.

#![cfg(feature = "client-ws")]

mod common;

use simoom::{Outcome, Reply, Request, Server, ServerHandle, WebSocket as SrvWs, WebSocketHandler, WsMessage};
use simoom_client::{Client, ErrorKind, Message, ProxyAddr, ProxyConfig};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

struct Echo;

impl WebSocketHandler for Echo {
    fn on_message(&mut self, ws: &mut SrvWs<'_>, msg: WsMessage<'_>) {
        match msg {
            WsMessage::Text(t) if t == "ping-me" => ws.ping(b"srv"),
            WsMessage::Text(t) if t == "bye" => ws.close(4000, "server bye"),
            WsMessage::Text(t) => ws.send_text(&format!("echo:{t}")),
            WsMessage::Binary(b) => ws.send_binary(b),
        }
    }
}

fn ws_service(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    if req.is_websocket_upgrade() {
        let proto = req.header("sec-websocket-protocol").map(|p| String::from_utf8_lossy(p).into_owned());
        if proto.as_deref().is_some_and(|p| p.contains("chat")) {
            return reply.websocket_with_protocol(Some("chat"), Echo);
        }
        return reply.websocket(Echo);
    }
    common::service(req, reply)
}

fn server() -> ServerHandle {
    server_with(simoom::Limits::default())
}

fn server_with(limits: simoom::Limits) -> ServerHandle {
    Server::builder().listen("127.0.0.1:0").listen_tls("127.0.0.1:0").tls(common::server_config()).threads(2).limits(limits).service(ws_service).start().unwrap()
}

#[test]
fn echo_text_binary_fragmented_ping_close() {
    let h = server();
    let c = Client::new();
    let ws = c.websocket(&format!("ws://127.0.0.1:{}/ws", h.local_addrs()[0].port())).read_timeout(Some(Duration::from_secs(10))).connect().unwrap();
    assert_eq!(ws.protocol(), None);
    ws.send_text("hello").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("echo:hello".into()));
    ws.send_binary(&[0, 1, 2, 255]).unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Binary(vec![0, 1, 2, 255]));
    // a message larger than the frame size goes out in fragments and comes back whole
    let big: Vec<u8> = (0..300_000).map(|i| (i % 256) as u8).collect();
    ws.send_binary(&big).unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Binary(big));
    // our ping, their pong
    ws.ping(b"p1").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Pong(b"p1".to_vec()));
    // their ping: answered automatically and reported
    ws.send_text("ping-me").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Ping(b"srv".to_vec()));
    ws.send_text("after ping").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("echo:after ping".into()));
    // the server closes: we answer and report the code
    ws.send_text("bye").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Close(Some(4000), "server bye".into()));
    assert!(ws.is_closed());
    assert_eq!(ws.recv().unwrap_err().kind, ErrorKind::Closed);
}

#[test]
fn client_close_handshake_and_subprotocol() {
    let h = server();
    let c = Client::new();
    let ws = c.websocket(&format!("ws://127.0.0.1:{}/ws", h.local_addrs()[0].port())).protocol("v2").protocol("chat").connect().unwrap();
    assert_eq!(ws.protocol(), Some("chat"));
    ws.send_text("x").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("echo:x".into()));
    ws.close(1000, "done", Duration::from_secs(2)).unwrap();
    assert!(ws.is_closed());
    assert!(ws.send_text("late").is_err());
}

#[test]
fn concurrent_sender_and_receiver() {
    let h = server();
    let ws = Arc::new(Client::new().websocket(&format!("ws://127.0.0.1:{}/ws", h.local_addrs()[0].port())).connect().unwrap());
    let w2 = ws.clone();
    let t = std::thread::spawn(move || {
        for i in 0..200 {
            w2.send_text(&format!("m{i}")).unwrap();
        }
    });
    for i in 0..200 {
        assert_eq!(ws.recv().unwrap(), Message::Text(format!("echo:m{i}")));
    }
    t.join().unwrap();
}

#[test]
fn wss_and_proxy_tunnel() {
    let h = server();
    let c = common::client().build();
    let ws = c.websocket(&format!("wss://localhost:{}/ws", h.local_addrs()[1].port())).connect().unwrap();
    ws.send_text("secure").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("echo:secure".into()));
    let p = common::proxy(Some("u:p"));
    let c = common::client().proxy(Some(ProxyConfig::new(ProxyAddr::new("127.0.0.1", p.addr.port()).with_credentials("u", "p")))).build();
    let ws = c.websocket(&format!("ws://127.0.0.1:{}/ws", h.local_addrs()[0].port())).connect().unwrap();
    ws.send_text("via proxy").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("echo:via proxy".into()));
    assert!(p.seen.lock().unwrap().iter().any(|l| l.starts_with("CONNECT 127.0.0.1:")));
    let ws = c.websocket(&format!("wss://localhost:{}/ws", h.local_addrs()[1].port())).connect().unwrap();
    ws.send_text("wss via proxy").unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("echo:wss via proxy".into()));
}

#[test]
fn refused_and_broken_handshakes() {
    let h = server();
    // not a WebSocket endpoint... simoom answers the upgrade on every path here, so use a
    // scripted server instead
    let _ = h;
    let srv = common::raw(|mut s, n| {
        let head = common::read_head(&mut s).unwrap();
        match n {
            0 => {
                let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            }
            1 => {
                let _ = s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n");
            }
            _ => {
                // valid handshake, then a masked frame from the server (forbidden) and a
                // frame with reserved bits
                let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap().trim().to_string();
                let acc = simoom_http1::ws::accept_key(key.as_bytes());
                let resp = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", String::from_utf8_lossy(&acc));
                let mut out = resp.into_bytes();
                out.extend_from_slice(&[0x81, 0x85, 1, 2, 3, 4, b'h' ^ 1, b'e' ^ 2, b'l' ^ 3, b'l' ^ 4, b'o' ^ 1]);
                let _ = s.write_all(&out);
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    });
    let c = Client::new();
    let e = c.websocket(&format!("ws://{}/", srv.addr)).connect().unwrap_err();
    assert!(e.kind == ErrorKind::WebSocket && e.message.contains("403"), "{e}");
    let e = c.websocket(&format!("ws://{}/", srv.addr)).connect().unwrap_err();
    assert_eq!(e.kind, ErrorKind::WebSocket, "{e}");
    let ws = c.websocket(&format!("ws://{}/", srv.addr)).connect().unwrap();
    let e = ws.recv().unwrap_err();
    assert!(e.message.contains("Masked"), "{e}");
}

#[cfg(feature = "client-h2")]
#[test]
fn websocket_over_http2() {
    let h = server();
    for (url, c) in [
        (format!("ws://127.0.0.1:{}/ws", h.local_addrs()[0].port()), Client::new()),
        (format!("wss://localhost:{}/ws", h.local_addrs()[1].port()), common::client().build()),
    ] {
        let ws = c.websocket(&url).http2(true).protocol("chat").read_timeout(Some(Duration::from_secs(10))).connect().unwrap();
        assert_eq!(ws.protocol(), Some("chat"));
        ws.send_text("over h2").unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Text("echo:over h2".into()));
        let big: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
        ws.send_binary(&big).unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Binary(big));
        ws.ping(b"x").unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Pong(b"x".to_vec()));
        // a second WebSocket and a plain request share the HTTP/2 connection
        let ws2 = c.websocket(&url).http2(true).connect().unwrap();
        ws2.send_text("second").unwrap();
        assert_eq!(ws2.recv().unwrap(), Message::Text("echo:second".into()));
        let plain = url.replace("ws://", "http://").replace("wss://", "https://").replace("/ws", "/echo");
        let r = c.get(&plain).version(simoom_client::HttpVersion::Http2).send().unwrap();
        assert_eq!(r.version(), simoom_client::Version::Http2);
        drop(r);
        assert_eq!(c.pool_stats().multiplexed, 1);
        ws.send_text("bye").unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Close(Some(4000), "server bye".into()));
        ws2.close(1000, "", Duration::from_secs(2)).unwrap();
    }
    // an HTTP/2 server that does not announce SETTINGS_ENABLE_CONNECT_PROTOCOL: refused
    let srv = common::raw(|mut s, _| {
        use std::io::Read;
        let mut conn = simoom_h2::Connection::server(simoom_h2::Config::default());
        let mut buf = vec![0u8; 65536];
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        loop {
            let Ok(n) = s.read(&mut buf) else { return };
            if n == 0 {
                return;
            }
            conn.recv(&buf[..n], 0, &mut |_| {});
            let out = conn.output().to_vec();
            conn.advance_output(out.len());
            if s.write_all(&out).is_err() {
                return;
            }
        }
    });
    let e = Client::new().websocket(&format!("ws://{}/", srv.addr)).http2(true).connect().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unsupported, "{e}");
}
