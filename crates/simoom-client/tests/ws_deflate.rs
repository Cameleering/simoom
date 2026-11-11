//! permessage-deflate (RFC 7692) between simoom-client and the simoom server, on HTTP/1.1 and
//! on an HTTP/2 stream (RFC 8441).

#![cfg(feature = "client-ws-deflate")]

use simoom::{Reply, Request, Server, WebSocket as SrvWs, WebSocketHandler, WsDeflate, WsMessage};
use simoom_client::{Client, Message};
use simoom_http1::ws::deflate::DeflateConfig;
use std::time::Duration;

struct Echo;
impl WebSocketHandler for Echo {
    fn on_message(&mut self, ws: &mut SrvWs<'_>, msg: WsMessage<'_>) {
        match msg {
            WsMessage::Text(t) => ws.send_text(t),
            WsMessage::Binary(b) => ws.send_binary(b),
        }
    }
}

#[test]
fn compressed_echo_over_http1_and_http2() {
    let h = Server::builder().listen("127.0.0.1:0").threads(1).websocket_deflate(WsDeflate::default()).service(|_r: &mut Request<'_>, reply: Reply<'_>| reply.websocket(Echo)).start().unwrap();
    let port = h.local_addr().port();
    for http2 in [false, true] {
        let ws = Client::new().websocket(&format!("ws://127.0.0.1:{port}/ws")).http2(http2).permessage_deflate(DeflateConfig::default()).read_timeout(Some(Duration::from_secs(10))).connect().unwrap();
        for i in 0..5 {
            let text = format!("{i}: {}", "the same phrase over and over ".repeat(50));
            ws.send_text(&text).unwrap();
            assert_eq!(ws.recv().unwrap(), Message::Text(text), "http2 {http2}");
        }
        ws.send_binary(&[1, 2, 3]).unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Binary(vec![1, 2, 3]));
        ws.close(1000, "", Duration::from_secs(2)).unwrap();
    }
    // a server without the option: the client goes on uncompressed
    let h2 = Server::builder().listen("127.0.0.1:0").threads(1).service(|_r: &mut Request<'_>, reply: Reply<'_>| reply.websocket(Echo)).start().unwrap();
    let ws = Client::new().websocket(&format!("ws://127.0.0.1:{}/ws", h2.local_addr().port())).permessage_deflate(DeflateConfig::default()).connect().unwrap();
    ws.send_text(&"x".repeat(1000)).unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("x".repeat(1000)));
    for h in [h, h2] {
        h.stop(Duration::from_secs(1));
    }
}
