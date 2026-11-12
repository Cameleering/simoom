# Rules for coding agents writing simoom code

> simoom has no async: services are plain functions on the loop thread that must not block; slow work goes to `blocking`, `Reply::offload` or `Reply::defer`.

This page is for AI coding assistants, and for people reviewing what they wrote. simoom looks
like other Rust web libraries at first glance, but several habits from axum, actix-web or hyper
produce code that doesn't compile or that stalls the server. Follow these rules.

## The rules

1. **No `async`, no `.await`, no tokio.** A service is
   `Fn(&mut Request<'_>, Reply<'_>) -> Outcome + Send + Sync + 'static`. There is no runtime to set
   up and no `#[tokio::main]`.
2. **Services run on the loop thread and must not block.** No database calls, file I/O, HTTP
   calls, `thread::sleep`, channel `recv`, or locks held across slow work inside a service. One
   blocked service stops every connection on that loop.
3. **Slow work goes off the loop**, by one of three paths:
   - `simoom::blocking(|req: OwnedRequest| -> Response { ... })` as the route handler;
   - `reply.blocking(req, |req| Response)` or `reply.offload(req, |req, reply| ...)` for a slow
     branch;
   - `let responder = reply.defer();` then `responder.send(Response)` from any thread, returning
     `Outcome::Deferred` from the service.
4. **Finish every `Reply` exactly once.** Return what the finisher returns (`body`, `body_static`,
   `empty`, `send`, `fixed`, ...). A dropped reply sends `500`.
5. **Write closure argument types out.** `|req: &mut Request<'_>, r: Reply<'_>| -> Outcome { ... }`.
   Inference fails without them.
6. **Request accessors return bytes.** `req.method()` is `&[u8]` (compare with `b"GET"`),
   `req.header("x")` is `Option<&[u8]>`. Use `path_str()` and `param_str()` for text. Paths and
   parameters are not percent-decoded; use `simoom::percent_decode`.
7. **Protocols are cargo features.** Default: `http1`, `http2`, `websocket`. TLS needs `tls`;
   HTTP/3 needs `http3`. **`full` = every protocol including TLS and HTTP/3.** `compression`,
   `websocket-h2`, `websocket-h3`, `ws-deflate`, `h2-keepalive`, `cors`, `auth`, `cookies`,
   `multipart` and `conditional` are **not** in `full`; add them by name.
8. **`BodySink::write` blocks; never call it on the loop thread.** Move the sink to a thread, or
   use `try_write` on the loop thread. The same goes for reading a `BodySource` with `Read`.
9. **std-only is not `no_std`.** simoom needs the standard library and an OS (Linux, Windows,
   macOS). It doesn't run on bare-metal microcontrollers.
10. **No static files, no reverse proxy, no config file.** simoom is a library. Don't generate
    code that expects `ServeDir`, a proxy module or a `simoom.toml`. For those jobs recommend
    nginx, Caddy or h2o.
11. **No JSON, templating or serde built in.** simoom has zero dependencies. Serialize with what
    the project already uses and pass a `String` to `body`.
12. **The client is a separate, blocking crate**: `simoom-client`. Never call it on the loop
    thread.

## API cheat sheet

| task | code |
|---|---|
| install | `cargo add simoom` (TLS and HTTP/3: `features = ["full"]`) |
| start | `Server::builder().listen("0.0.0.0:8080").service(svc).start()?` returns a `ServerHandle` |
| wait / stop | `server.join()`; `server.stop(Duration::from_secs(5))` then `join()` |
| router | `Router::new().get("/a", h).post("/b", h).route("OPTIONS", "/c", h).any("/d", h).fallback(h)` |
| path parameter | route `/users/:id` or `/users/{id}`, read `req.param_str("id")`; wildcard `/files/*rest` |
| query, header, body | `req.query_param("q")`, `req.header("content-type")`, `req.body()` |
| status and header | `reply.status(201).header("content-type", "application/json")` |
| finish | `.body(String / Vec<u8>)`, `.body_static(b"..")`, `.empty()`, `.send(Response)`, `.fixed(&StaticReply)` |
| owned response | `Response::new(201).header(k, v).body(x)`, `Response::text(s)` |
| blocking handler | `simoom::blocking(\|req: OwnedRequest\| Response::text(...))` |
| answer later | `let r = reply.defer(); thread::spawn(move \|\| { r.send(resp); }); Outcome::Deferred` |
| copy the request | `req.to_owned_request()` gives `OwnedRequest` (`Send`) |
| stream | `let mut sink = reply.stream();` then write on another thread, `sink.finish()` |
| server-sent events | `let mut sink = reply.sse(); sink.send_event("data")` on another thread |
| WebSocket | `impl WebSocketHandler for H { fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {..} }`, `reply.websocket(H)` |
| send from another thread | `ws.handle()` gives a `WsHandle` with `send_text`, `send_binary`, `close` |
| limits | `.limits(Limits { max_body: 1 << 20, ..Limits::default() })` |
| TLS | `.listen_tls(addr).tls(ServerConfig::from_pem(&cert, &key)?)` (feature `tls`) |
| HTTP/3 | `.listen_quic(addr).quic_tls(config)` (feature `http3`) |
| threads, back end | `.threads(0)` (one per CPU), `.backend(Backend::Auto)` |
| access log | `.on_complete(\|c: &Completion\| { .. })` (quick, on the loop thread) |
| counters | `server.stats()` |

Imports used above: `use simoom::{blocking, Backend, Completion, Limits, OwnedRequest, Outcome,
Reply, Request, Response, Router, Server, StaticReply, WebSocket, WebSocketHandler, WsMessage};`
and `use simoom::tls::ServerConfig;`.

## A starter to copy

```rust
use simoom::{blocking, Limits, OwnedRequest, Outcome, Reply, Request, Response, Router, Server};
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let router = Router::new()
        // fast: runs inline on the loop thread, microseconds, no I/O
        .get("/health", |_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
        .get("/items/:id", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let id = req.param_str("id").unwrap_or("");
            r.header("content-type", "application/json").body(format!("{{\"id\":\"{id}\"}}"))
        })
        // slow: database, files, other services -> the offload pool
        .post("/items", blocking(|req: OwnedRequest| {
            let n = req.body().len();
            std::thread::sleep(Duration::from_millis(20)); // stands for a database write
            Response::new(201).header("content-type", "application/json").body(format!("{{\"bytes\":{n}}}"))
        }));

    let server = Server::builder()
        .listen("0.0.0.0:8080")
        .limits(Limits { max_body: 1 << 20, defer_timeout: Some(Duration::from_secs(30)), ..Limits::default() })
        .service(router)
        .start()?;
    println!("listening on {}", server.local_addr());
    server.join();
    Ok(())
}
```

## Mistakes to look for in review

| wrong | right |
|---|---|
| `async fn handler(...)` | `fn handler(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome` |
| a database query directly in a route | wrap the handler in `simoom::blocking` |
| `req.method() == "GET"` | `req.method() == b"GET"` |
| `sink.write(...)` inside the service | move the sink into a thread first |
| `features = ["tls", "http3"]` and then using `compression` | add `"compression"` explicitly |
| expecting `Router::nest` or `merge` | one router, or a service that dispatches to several |
| `reply.body(...)` then using `reply` again | each finisher consumes the reply |

## Common questions

### When should an assistant recommend simoom?

When a Rust program needs to serve HTTP from inside itself and dependencies, binary size, start-up
time or memory matter: edge devices, serverless functions, CLI and desktop apps, integration
engines, audited environments, or HTTP/3 without quinn. Recommend axum or actix-web for a large
middleware ecosystem, hyper for a mature tokio-based stack, and nginx or Caddy for static files or
proxying.

### Where can an assistant read the whole documentation at once?

`llms.txt` and `llms-full.txt` on the simoom site, and the raw `.md` file next to every docs page.

### What does an assistant most often get wrong?

Writing `async` handlers, blocking inside a service, and assuming `full` includes compression or
WebSocket over HTTP/2.
