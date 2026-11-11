//! WebSocket over HTTP/3 (RFC 9220) between simoom-client and the simoom server, plain and
//! with permessage-deflate.

#![cfg(all(feature = "client-h3", feature = "client-h2", feature = "client-ws"))]

mod common;

use common::{client, server_config};
use simoom::{Reply, Request, Server, WebSocket as SrvWs, WebSocketHandler, WsMessage};
use simoom_client::Message;
use std::time::Duration;

struct Echo;
impl WebSocketHandler for Echo {
    fn on_open(&mut self, ws: &mut SrvWs<'_>) {
        let h = ws.handle();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            h.send_text("pushed");
        });
    }
    fn on_message(&mut self, ws: &mut SrvWs<'_>, msg: WsMessage<'_>) {
        match msg {
            WsMessage::Text(t) => ws.send_text(&format!("echo {t}")),
            WsMessage::Binary(b) => ws.send_binary(b),
        }
    }
}

#[test]
fn websocket_over_http3() {
    let b = Server::builder().listen_quic("127.0.0.1:0").quic_tls(server_config()).threads(1);
    #[cfg(feature = "client-ws-deflate")]
    let b = b.websocket_deflate(simoom::WsDeflate::default());
    let h = b
        .service(|req: &mut Request<'_>, reply: Reply<'_>| {
            assert!(req.is_websocket_upgrade());
            reply.websocket(Echo)
        })
        .start()
        .unwrap();
    let url = format!("wss://localhost:{}/ws", h.quic_addrs()[0].port());
    let ws = client().build().websocket(&url).http3(true).connect().unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Text("pushed".into()));
    for i in 0..3 {
        ws.send_text(&format!("m{i} {}", "x".repeat(i * 1000))).unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Text(format!("echo m{i} {}", "x".repeat(i * 1000))));
    }
    ws.send_binary(&vec![9u8; 200_000]).unwrap();
    assert_eq!(ws.recv().unwrap(), Message::Binary(vec![9u8; 200_000]));
    ws.close(1000, "", Duration::from_secs(2)).unwrap();
    #[cfg(feature = "client-ws-deflate")]
    {
        let ws = client().build().websocket(&url).http3(true).permessage_deflate(simoom_http1::ws::deflate::DeflateConfig::default()).connect().unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Text("pushed".into()));
        let t = "compress me ".repeat(500);
        ws.send_text(&t).unwrap();
        assert_eq!(ws.recv().unwrap(), Message::Text(format!("echo {t}")));
        ws.close(1000, "", Duration::from_secs(2)).unwrap();
    }
    h.stop(Duration::from_secs(1));
}
