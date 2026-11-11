//! WebSocket permessage-deflate (RFC 7692) through the server (feature `ws-deflate`): the
//! negotiation, compressed messages both ways with context takeover, uncompressed messages
//! alongside, a client that offers nothing, and an inflation bomb.

#![cfg(feature = "ws-deflate")]

mod common;

use common::*;
use simoom::{Limits, Reply, Request, Server, WebSocket, WebSocketHandler, WsDeflate, WsMessage};
use simoom_http1::ws::deflate::{accept_response, offer, DeflateConfig, PerMessage, Side};
use simoom_http1::ws::{write_close, write_frame, write_frame_compressed, FrameDecoder, Opcode, Role, WsEvent, WsLimits};
use std::io::{Read, Write};
use std::time::Duration;

struct Echo;
impl WebSocketHandler for Echo {
    fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {
        match msg {
            WsMessage::Text(t) => ws.send_text(&format!("echo: {t}")),
            WsMessage::Binary(b) => ws.send_binary(b),
        }
    }
}

fn server(cfg: WsDeflate, max_ws: u64) -> simoom::ServerHandle {
    Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(Limits { max_ws_message: max_ws, ..Limits::default() })
        .websocket_deflate(cfg)
        .service(|_r: &mut Request<'_>, reply: Reply<'_>| reply.websocket(Echo))
        .start()
        .unwrap()
}

fn masked(op: Opcode, payload: &[u8], compressed: bool) -> Vec<u8> {
    let mut f = Vec::new();
    let p = payload; // write_frame masks with the key
    if compressed {
        write_frame_compressed(&mut f, true, op, p, Some([7, 1, 9, 3]));
    } else {
        write_frame(&mut f, true, op, p, Some([7, 1, 9, 3]));
    }
    f
}

/// Reads one message: (text, compressed, payload as sent).
fn read_msg(s: &mut std::net::TcpStream, dec: &mut FrameDecoder, buf: &mut Vec<u8>) -> Option<(bool, bool, Vec<u8>)> {
    let mut msg = Vec::new();
    loop {
        let mut b = std::mem::take(buf);
        match dec.decode(&mut b) {
            Ok((n, WsEvent::Data { text, payload, fin })) => {
                msg.extend_from_slice(payload);
                let c = dec.message_compressed();
                b.drain(..n);
                *buf = b;
                if fin {
                    return Some((text, c, msg));
                }
                continue;
            }
            Ok((n, WsEvent::Close { code, .. })) => {
                b.drain(..n);
                *buf = b;
                return Some((false, false, format!("close {}", code.unwrap_or(0)).into_bytes()));
            }
            Ok((0, WsEvent::NeedMore)) => {
                *buf = b;
                let mut t = [0u8; 65536];
                let n = s.read(&mut t).ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&t[..n]);
            }
            Ok((n, _)) => {
                b.drain(..n);
                *buf = b;
            }
            Err(e) => panic!("{e:?}"),
        }
    }
}

fn handshake(h: &simoom::ServerHandle, ext: Option<&str>) -> (std::net::TcpStream, Option<String>, Vec<u8>) {
    let mut s = connect(h);
    let e = ext.map(|e| format!("Sec-WebSocket-Extensions: {e}\r\n")).unwrap_or_default();
    s.write_all(format!("GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{e}\r\n").as_bytes()).unwrap();
    let mut got = Vec::new();
    let mut t = [0u8; 4096];
    let end = loop {
        let n = s.read(&mut t).unwrap();
        got.extend_from_slice(&t[..n]);
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&got[..end]).into_owned();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let ext = head.lines().find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-extensions:")).map(|l| l.split_once(':').unwrap().1.trim().to_string());
    (s, ext, got[end..].to_vec())
}

#[test]
fn compressed_messages_both_ways() {
    let h = server(WsDeflate::default(), 1 << 20);
    let cfg = DeflateConfig::default();
    let (mut s, ext, mut buf) = handshake(&h, Some(&offer(&cfg)));
    assert_eq!(ext.as_deref(), Some("permessage-deflate"));
    let p = accept_response(ext.as_deref().map(str::as_bytes), &cfg).unwrap().unwrap();
    let mut pm = PerMessage::new(Side::Client, &p, &cfg);
    let mut dec = FrameDecoder::new(Role::Client, WsLimits::default());
    dec.set_permessage_deflate(true);
    let mut sizes = Vec::new();
    for i in 0..5 {
        let text = format!("message {i}: {}", "compressible text, compressible text, ".repeat(20));
        let c = pm.compress(text.as_bytes());
        s.write_all(&masked(Opcode::Text, &c, true)).unwrap();
        let (is_text, compressed, payload) = read_msg(&mut s, &mut dec, &mut buf).unwrap();
        assert!(is_text && compressed);
        sizes.push(payload.len());
        let mut plain = Vec::new();
        pm.decompress(&payload, &mut plain).unwrap();
        assert_eq!(plain, format!("echo: {text}").into_bytes());
    }
    assert!(sizes[4] < sizes[0], "context takeover shrinks later messages: {sizes:?}");
    // an uncompressed message from the client is fine; small replies go out uncompressed
    s.write_all(&masked(Opcode::Text, b"hi", false)).unwrap();
    let (_, compressed, payload) = read_msg(&mut s, &mut dec, &mut buf).unwrap();
    assert_eq!((compressed, &payload[..]), (false, &b"echo: hi"[..]));
    let mut c = Vec::new();
    write_close(&mut c, 1000, "", Some([1, 2, 3, 4]));
    s.write_all(&c).unwrap();
    h.stop(Duration::from_secs(1));
}

#[test]
fn no_offer_no_extension_and_rsv1_refused() {
    let h = server(WsDeflate::default(), 1 << 20);
    let (mut s, ext, mut buf) = handshake(&h, None);
    assert_eq!(ext, None);
    // RSV1 without the extension: protocol error 1002
    s.write_all(&masked(Opcode::Text, b"x", true)).unwrap();
    let mut dec = FrameDecoder::new(Role::Client, WsLimits::default());
    let (_, _, payload) = read_msg(&mut s, &mut dec, &mut buf).unwrap();
    assert_eq!(payload, b"close 1002");
    h.stop(Duration::from_secs(1));
}

#[test]
fn inflation_bomb_is_closed_with_1009() {
    let h = server(WsDeflate::default(), 64 * 1024);
    let cfg = DeflateConfig::default();
    let (mut s, ext, mut buf) = handshake(&h, Some("permessage-deflate"));
    let p = accept_response(ext.as_deref().map(str::as_bytes), &cfg).unwrap().unwrap();
    let mut pm = PerMessage::new(Side::Client, &p, &cfg);
    let c = pm.compress(&vec![0u8; 4 << 20]);
    assert!(c.len() < 16 * 1024);
    s.write_all(&masked(Opcode::Binary, &c, true)).unwrap();
    let mut dec = FrameDecoder::new(Role::Client, WsLimits::default());
    dec.set_permessage_deflate(true);
    let (_, _, payload) = read_msg(&mut s, &mut dec, &mut buf).unwrap();
    assert_eq!(payload, b"close 1009");
    h.stop(Duration::from_secs(1));
}
