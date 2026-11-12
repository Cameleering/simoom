# Getting started with simoom

> Add simoom with `cargo add simoom`, write one function that answers a request, and call `start()`; a working HTTP server takes about ten lines.

simoom is a library, not a program: you add it to your own Rust project and it serves HTTP from
inside your process. This page installs it, runs a first server, and explains the one idea you
need before writing more: what a service is and where it runs.

## Install

simoom needs Rust 1.89 or newer and runs on Linux, Windows and macOS.

```sh
cargo add simoom
```

or in `Cargo.toml`:

```toml
[dependencies]
simoom = "0.1"
```

The default features give you HTTP/1.1, HTTP/2 without TLS (h2c), WebSocket and the io_uring back
end. For TLS and HTTP/3 turn on `full`:

```toml
simoom = { version = "0.1", features = ["full"] }
```

There is nothing else to install: no C compiler, no OpenSSL headers, no async runtime.
[Features and size](features-and-size.md) lists every feature.

## A first server

```rust
use simoom::{Outcome, Reply, Request, Server, StaticReply};
use std::sync::Arc;

fn main() {
    let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let server = Server::builder()
        .listen("127.0.0.1:8080")
        .service(move |_req: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.fixed(&hello) })
        .start()
        .expect("start the server");
    println!("listening on {}", server.local_addr());
    server.join();
}
```

Run it with `cargo run --release` and try it:

```sh
curl -i http://127.0.0.1:8080/
curl --http2-prior-knowledge http://127.0.0.1:8080/   # the same server speaks HTTP/2 (h2c)
```

`StaticReply` serializes the response once, so every request is answered with one copy. It is the
fastest way to send a fixed answer, but any response works, as the next example shows.

## Routes and parameters

Most programs answer more than one path. A [`Router`](routing.md) sends each request to a handler
by method and path:

```rust
use simoom::{Outcome, Reply, Request, Router, Server};

fn main() {
    let router = Router::new()
        .get("/", |_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"Hello, World!"))
        .get("/hello/:name", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let name = req.param_str("name").unwrap_or("stranger");
            r.header("content-type", "text/plain").body(format!("Hello, {name}!"))
        });

    let server = Server::builder().listen("127.0.0.1:8080").service(router).start().expect("start");
    println!("listening on {}", server.local_addr());
    server.join();
}
```

`curl http://127.0.0.1:8080/hello/Ada` prints `Hello, Ada!`. An unknown path gets `404`, and a
known path with the wrong method gets `405` with an `allow` header.

## What a service is

A **service** is anything that takes a `&mut Request` and a `Reply` and returns an `Outcome`. A
closure with that signature is a service, and so is a `Router`. The `Reply` is finished exactly
once: with a body, with a deferred answer for later, with a stream, or with a WebSocket upgrade.
[Services and replies](services-and-replies.md) covers each.

The one rule to remember: **a service runs on the loop thread.** simoom runs one event loop per
CPU core, and each loop serves thousands of connections. While your function runs, that loop
does nothing else. So a service must answer in microseconds and must not block: no database
calls, no file reads, no `sleep`, no locks held for long.

There is no `async` and no `.await`. Slow work goes somewhere else:

- to simoom's bounded offload pool with `simoom::blocking` or `Reply::offload`;
- or to your own threads with `Reply::defer`, answering later from any thread.

[Slow work](slow-work.md) shows all three. If a handler blocks anyway, a watchdog notices and
moves that route to the offload pool, but that is a safety net, not a plan.

## Stopping the server

`start()` returns a `ServerHandle` once every loop is running. `join()` waits for the loops to
exit; `stop(grace)` starts a graceful stop. Port `0` lets the OS pick a free port, which is handy
in tests:

```rust
use simoom::{Reply, Request, Server};
use std::time::Duration;

fn run() -> std::io::Result<()> {
    let server = Server::builder()
        .listen("127.0.0.1:0") // port 0: the OS picks a free port
        .service(|_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
        .start()?;
    let addr = server.local_addr();
    // ... use the server ...
    server.stop(Duration::from_secs(5));
    server.join();
    Ok(())
}
```

Dropping the handle stops the server at once. [Runtime](runtime.md) explains what a graceful
stop does on each protocol.

## Where to go next

- [Services and replies](services-and-replies.md): reading requests, every way to answer.
- [Routing](routing.md): parameters, wildcards, 404 and 405.
- [Slow work](slow-work.md): databases and other services without blocking the server.
- [TLS](tls.md) and [HTTP/2 and HTTP/3](http2-and-http3.md): HTTPS and the newer protocols.
- [Features and size](features-and-size.md): the smallest build for a device or a function.
- [FAQ](faq.md).

## Common questions

### Do I need tokio or another async runtime?

No. simoom has its own event loops and no async runtime. Services are plain functions. You can
still use simoom inside a program that runs tokio for other work; they don't interact.

### Why does my handler signature need the explicit types?

Rust can't infer closure argument types for a generic trait bound, so a closure passed to
`service` or `Router::get` needs `&mut Request<'_>` and `Reply<'_>` written out. A named `fn`
with that signature works too.

### Which address should I listen on?

`127.0.0.1:8080` accepts connections from the same machine only. `0.0.0.0:8080` accepts them on
every IPv4 interface, and `[::]:8080` on IPv6. You can call `listen` more than once.

### How do I run the bundled examples?

From a checkout of the repository: `cargo run --release -p simoom --example hello -- 127.0.0.1:8080`.
