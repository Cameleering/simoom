# How do I read requests and send responses in simoom?

> A service gets a borrowed `Request` and a `Reply`; read the request, then finish the reply once with a body, a stream, a deferred answer or an upgrade.

Everything in simoom is built on one trait, `Service`. This page shows the three ways to write a
service, what you can read from a `Request`, and every way to finish a `Reply`.

## Three ways to write a service

**A closure.** Any `Fn(&mut Request<'_>, Reply<'_>) -> Outcome + Send + Sync + 'static` is a
service. This is what most examples use.

**A function.** The same signature as a named `fn`:

```rust
use simoom::{Outcome, Reply, Request, Server};

fn hello(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    if req.method() != b"GET" {
        return reply.status(405).header("allow", "GET").empty();
    }
    reply.header("content-type", "text/plain").body_static(b"hello")
}

fn main() {
    let server = Server::builder().listen("127.0.0.1:8080").service(hello).start().unwrap();
    server.join();
}
```

**A struct.** Implement `Service` when the handler carries state. The service is shared by every
loop thread, so its state must be `Send + Sync`: atomics, `Mutex`, `RwLock` or read-only data.

```rust
use simoom::{Outcome, Reply, Request, Service};
use std::sync::atomic::{AtomicU64, Ordering};

struct Counter {
    hits: AtomicU64,
}

impl Service for Counter {
    fn call(&self, _req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        let n = self.hits.fetch_add(1, Ordering::Relaxed) + 1;
        reply.body(format!("request number {n}"))
    }
}

fn build() -> simoom::Builder {
    simoom::Server::builder().listen("127.0.0.1:8080").service(Counter { hits: AtomicU64::new(0) })
}
```

Closures can capture shared state too. Clone an `Arc` for each closure that needs it:

```rust
use simoom::{Outcome, Reply, Request, Router};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

fn router() -> Router {
    let store: Arc<RwLock<HashMap<String, String>>> = Arc::default();
    let reader = store.clone();
    Router::new()
        .put("/kv/:key", move |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let key = req.param_str("key").unwrap_or("").to_string();
            let value = String::from_utf8_lossy(req.body()).into_owned();
            store.write().unwrap().insert(key, value);
            r.status(204).empty()
        })
        .get("/kv/:key", move |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            match reader.read().unwrap().get(req.param_str("key").unwrap_or("")) {
                Some(v) => r.body(v.clone()),
                None => r.status(404).body_static(b"not found"),
            }
        })
}
```

A lock held for a few microseconds is fine on the loop thread. A lock that waits on slow work is
not; see [Slow work](slow-work.md).

## Reading the request

A `Request` borrows from the connection's receive buffer, so reading it costs nothing. Most
accessors return bytes (`&[u8]`), because HTTP allows bytes that aren't UTF-8; the `_str`
variants return text.

```rust
use simoom::{Outcome, Reply, Request};

fn inspect(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let method = String::from_utf8_lossy(req.method()).into_owned();
    let path = req.path_str();
    let page = req.query_param("page").and_then(|v| std::str::from_utf8(v).ok()).unwrap_or("1");
    let agent = req.header("user-agent").map(String::from_utf8_lossy).unwrap_or_default();
    let peer = req.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let body_len = req.body().len();
    reply.body(format!("{method} {path} page={page} agent={agent} peer={peer} body={body_len} bytes ({:?})", req.version()))
}
```

| method | returns |
|---|---|
| `method()`, `target()`, `path()`, `path_str()` | the method, the full target, the path before `?` (not percent-decoded) |
| `query()`, `query_param(name)` | the raw query string, one raw parameter |
| `header(name)`, `headers()` | the first header with that name (case-insensitive), all headers in order |
| `host()` | `Host` on HTTP/1.1, `:authority` on HTTP/2 and HTTP/3 |
| `version()` | `Version::Http10`, `Http11`, `H2` or `H3` |
| `body()`, `is_streamed()`, `take_body()` | the buffered body, or the streaming body source ([Streaming](streaming-and-sse.md)) |
| `trailers()`, `trailer(name)` | trailer fields of a buffered body |
| `param(name)`, `param_str(name)` | a value captured by the [router](routing.md) |
| `peer_addr()`, `local_addr()`, `listener()` | the client's address, the address it connected to, which listener accepted it |
| `is_secure()`, `tls()` | TLS or not, and the TLS session details ([TLS](tls.md)) |
| `is_websocket_upgrade()` | a valid WebSocket handshake ([WebSocket](websocket.md)) |
| `to_owned_request()` | an `OwnedRequest` copy that can move to another thread |

Bodies up to `Limits::body_buffer` (64 KiB by default) arrive whole before your service is
called, so `req.body()` has them. Larger bodies stream; `req.body()` is then empty and
`req.is_streamed()` is true. Percent-decoding is up to you: `simoom::percent_decode` does it.

## Finishing the reply

Set the status (default 200) and headers, then finish the reply with exactly one of these:

```rust
use simoom::{Outcome, Reply, Request, Response, StaticReply};
use std::sync::Arc;

fn finishers() {
    let _a = |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body(String::from("owned text")) };
    let _b = |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body(vec![1u8, 2, 3]) };
    let _c = |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body_static(b"no copy") };
    let _d = |req: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body_copy(req.body()) };
    let _e = |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.status(204).empty() };
    let _f = |_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
        r.send(Response::new(201).header("content-type", "application/json").body(r#"{"ok":true}"#))
    };
    let not_found = Arc::new(StaticReply::new(404, &[("content-type", "text/plain")], b"not found"));
    let _g = move |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.fixed(&not_found) };
}
```

| finisher | use it for |
|---|---|
| `body(x)` | a `String`, `Vec<u8>` or static bytes, moved without a copy |
| `body_static(b"...")` | constant bytes; large ones go out without a copy on plain HTTP/1.1 |
| `body_copy(&[u8])` | bytes you only borrow |
| `empty()` | no body (`content-length: 0`) |
| `send(Response)` | an owned `Response` built elsewhere; its status and headers replace the reply's |
| `fixed(&StaticReply)` | a response serialized once at start-up, the fastest path |
| `defer()` | a `Responder` to answer later from any thread ([Slow work](slow-work.md)) |
| `blocking(req, f)`, `offload(req, f)` | run the work on the offload pool ([Slow work](slow-work.md)) |
| `stream()`, `sse()` | a `BodySink` for a streamed body ([Streaming](streaming-and-sse.md)) |
| `websocket(handler)` | accept a WebSocket upgrade ([WebSocket](websocket.md)) |

The type system keeps you honest: each finisher takes the reply by value, so you can't answer
twice. If a reply is dropped without being finished, the client gets a `500`.

Some details the server handles for you:

- **Framing headers** (`content-length`, `transfer-encoding`) are written by the server; setting
  them is ignored. `connection: close` closes the connection after the response.
- **Header names** go out in lower case. An invalid name or value (CR, LF, NUL) turns the
  response into a `500` instead of reaching the wire.
- **`HEAD`** requests get the headers of the `GET` response without the body.
- **Trailers** after the body: `.trailer("grpc-status", "0")` on the reply, or
  `Response::trailer`. HTTP/1.1 then uses chunked framing.

## The Outcome value

`Outcome` is informational: `Outcome::Done` when the reply was sent (or a stream or upgrade
started), `Outcome::Deferred` when the answer comes later. Finishers return the right one, so you
normally just return what they return. After `reply.defer()` you return `Outcome::Deferred`
yourself.

## Panics

A panic in a service is caught. The client gets a `500`, its connection closes, the panic is
counted in `ServerHandle::stats().panics`, and the loop goes on serving everyone else.

## Optional helpers

Small helpers live behind their own cargo features, so you only compile what you use:

| feature | module | what it does |
|---|---|---|
| `cors` | `simoom::cors` | answers preflights and adds CORS headers around a service |
| `auth` | `simoom::auth` | Basic, Digest and Bearer authentication around a service |
| `cookies` | `simoom::cookie` | reads `Cookie`, writes `Set-Cookie` |
| `multipart` | `simoom::multipart` | parses `multipart/form-data` bodies |
| `conditional` | `simoom::conditional` | ETag, `If-None-Match`, `Last-Modified` and range requests |
| `compression` | `simoom::Compression` | gzip and deflate responses (`brotli`, `zstd` add those) |

A helper wraps your service. With the `cors` feature:

```rust
use simoom::cors::Cors;
use simoom::{Reply, Request, Server};

fn build() -> simoom::Builder {
    let api = |_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"{}");
    Server::builder().listen("127.0.0.1:8080").service(Cors::new().allow_any_origin().wrap(api))
}
```

The [API reference](https://docs.rs/simoom) documents each helper.

## Common questions

### How do I return JSON?

Set the content type and send the text: `r.header("content-type", "application/json").body(json)`.
simoom has no JSON library, since it has no dependencies; use the serializer you already have
(for example serde_json in your own crate) and pass the resulting `String`.

### How do I read a path parameter or a query parameter?

`req.param_str("id")` for a `:id` route segment, `req.query_param("page")` for `?page=2`. Both
return the raw value; decode it with `simoom::percent_decode` when it can contain `%XX` escapes.

### Can a handler be async?

No. A service is a plain function that returns before the loop moves on. For work that waits,
use `Reply::defer` and answer from any thread, or the offload pool; see [Slow work](slow-work.md).

### Why does my response come back as a 500?

Three causes: the reply was dropped without a finisher, a header name or value was invalid, or
the status was outside 200 to 999. A panic in the handler gives a 500 too.
