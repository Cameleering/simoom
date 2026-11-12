# How do I accept WebSocket connections with simoom?

> Implement `WebSocketHandler` and answer with `reply.websocket(handler)`; the handler runs on the loop thread, and a `WsHandle` sends from other threads.

WebSocket is on by default (feature `websocket`) for HTTP/1.1. The same handler also serves
WebSocket over HTTP/2 with the `websocket-h2` feature and over HTTP/3 with `websocket-h3`.

## An echo server

```rust
use simoom::{Reply, Request, Router, Server, WebSocket, WebSocketHandler, WsMessage};

struct Echo;

impl WebSocketHandler for Echo {
    fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {
        match msg {
            WsMessage::Text(text) => ws.send_text(text),
            WsMessage::Binary(bytes) => ws.send_binary(bytes),
        }
    }
}

fn main() {
    let router = Router::new().get("/ws", |_: &mut Request<'_>, r: Reply<'_>| r.websocket(Echo));
    let server = Server::builder().listen("127.0.0.1:8080").service(router).start().unwrap();
    server.join();
}
```

`reply.websocket(handler)` sends the `101 Switching Protocols` and hands the connection to the
handler. A request that isn't a valid WebSocket handshake gets `400`.

## The handler

`WebSocketHandler` has three callbacks:

| callback | when |
|---|---|
| `on_open(&mut self, ws)` | the upgrade completed (optional) |
| `on_message(&mut self, ws, msg)` | a whole message arrived; fragments are joined for you |
| `on_close(&mut self, code, reason)` | the connection is closing: the peer's code, 1005 if it sent none, 1006 if the connection was lost (optional) |

Inside a callback, `ws` sends with `send_text`, `send_binary` and `ping`, closes with
`close(code, reason)`, and gives you a `WsHandle` with `handle()`. Pings from the client are
answered automatically.

The handler runs on the loop thread, like a service, so the same rule applies: **no blocking in
callbacks**. Hand slow work to a thread and answer through a `WsHandle`. A panic in a callback
closes that WebSocket with code 1011.

Messages are limited to `Limits::max_ws_message` (1 MiB by default); a larger one closes the
connection with 1009.

## Sending from other threads: a chat room

A `WsHandle` is cheap to clone and can be sent to any thread. `send_text` returns `false` once
the connection is closed, which makes cleanup easy:

```rust
use simoom::{Reply, Request, Router, WebSocket, WebSocketHandler, WsHandle, WsMessage};
use std::sync::{Arc, Mutex};

type Room = Arc<Mutex<Vec<WsHandle>>>;

struct Member {
    room: Room,
}

impl WebSocketHandler for Member {
    fn on_open(&mut self, ws: &mut WebSocket<'_>) {
        ws.send_text("welcome");
        self.room.lock().unwrap().push(ws.handle());
    }

    fn on_message(&mut self, _ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {
        if let WsMessage::Text(text) = msg {
            // send_text returns false for a closed connection: drop those handles
            self.room.lock().unwrap().retain(|h| h.send_text(text));
        }
    }

    fn on_close(&mut self, code: u16, _reason: &str) {
        println!("a member left with code {code}");
    }
}

fn router() -> Router {
    let room: Room = Arc::default();
    Router::new().get("/chat", move |_: &mut Request<'_>, r: Reply<'_>| r.websocket(Member { room: room.clone() }))
}
```

A background thread can push to a client the same way:

```rust
use simoom::WsHandle;
use std::time::Duration;

fn push_clock(handle: WsHandle) {
    std::thread::spawn(move || {
        let mut n = 0u64;
        while handle.send_text(format!("tick {n}")) {
            n += 1;
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}
```

`WsHandle` has `send_text`, `send_binary`, `ping` and `close`.

## Subprotocols

When the client offers subprotocols in `Sec-WebSocket-Protocol`, pick one with
`websocket_with_protocol`:

```rust
use simoom::{Outcome, Reply, Request, WebSocket, WebSocketHandler, WsMessage};

struct Graphql;
impl WebSocketHandler for Graphql {
    fn on_message(&mut self, _ws: &mut WebSocket<'_>, _msg: WsMessage<'_>) {}
}

fn handler(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    if !req.is_websocket_upgrade() {
        return reply.status(426).header("upgrade", "websocket").empty();
    }
    let offered = req.header("sec-websocket-protocol").unwrap_or(b"");
    let wants = offered.split(|&b| b == b',').any(|p| p.trim_ascii() == b"graphql-transport-ws");
    let protocol = if wants { Some("graphql-transport-ws") } else { None };
    reply.websocket_with_protocol(protocol, Graphql)
}
```

Check `Origin`, cookies or a token in the request before you accept: the upgrade request is an
ordinary request until you call `websocket`.

## Compression and other protocols

| feature | adds |
|---|---|
| `websocket` (default), alias `ws` | WebSocket over HTTP/1.1 (RFC 6455) |
| `ws-deflate` | permessage-deflate compression (RFC 7692), offered with `Builder::websocket_deflate` |
| `websocket-h2` | WebSocket over HTTP/2 (RFC 8441), many sockets on one connection |
| `websocket-h3` | WebSocket over HTTP/3 (RFC 9220) |

None of the last three is in `default` or `full`, to keep those builds within their size
budgets. With `ws-deflate`:

```rust
use simoom::{Server, WsDeflate};

fn build() -> simoom::Builder {
    Server::builder().listen("127.0.0.1:8080").websocket_deflate(WsDeflate::default())
}
```

Each compressing WebSocket holds about 330 KiB of codec state, so offer deflate only when the
messages compress well and the number of connections is moderate.

## Common questions

### Can I use simoom for a WebSocket server in a CLI or desktop app?

Yes. That's a good fit: a command-line tool or desktop app can start a server on `127.0.0.1:0`,
open the browser on the printed port, and push updates over WebSocket or SSE, without pulling an
async runtime into a program that never needed one.

### Is there a WebSocket client?

Yes, in the separate `simoom-client` crate: `client.websocket("ws://...").connect()`. See
[The client](client.md).

### How many WebSocket connections can one server hold?

Idle connections cost little: in benchmark campaign 4 (2026-11-12), an idle HTTP connection took
573 bytes with 10,000 open and 532 bytes with 100,000 open (see the
[benchmarks](https://cameleer.ing/simoom/benchmarks/)). Real limits come
from your handler's state, compression, and `Limits::max_connections`.

### Do I need to answer pings?

No. Pings are answered automatically, and `ws.ping(...)` sends your own.
