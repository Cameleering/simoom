<p align="center"><img src="assets/simoom-logo-1200.png" alt="simoom, the HTTP server engine" width="600"></p>

<h1 align="center">simoom</h1>

<p align="center"><b>A small, fast HTTP server you build into your Rust program.</b><br>
HTTP/1.1, HTTP/2 and HTTP/3, TLS 1.3, WebSocket and a client, with zero dependencies outside the Rust standard library.</p>

<p align="center"><i>Carry more on less.</i></p>

<p align="center">
<a href="https://crates.io/crates/simoom"><img src="https://img.shields.io/crates/v/simoom.svg" alt="crates.io"></a>
<a href="https://docs.rs/simoom"><img src="https://img.shields.io/docsrs/simoom" alt="docs.rs"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
<img src="https://img.shields.io/badge/dependencies-0-success" alt="dependencies: 0">
<img src="https://img.shields.io/badge/HTTP%2F3-QUIC%20v1-informational" alt="HTTP/3">
<img src="https://img.shields.io/badge/rust-1.89%2B-orange" alt="Rust 1.89+">
</p>

---

Most programs that speak HTTP don't want a web server. They want a door: a place where requests
come in and answers go out. A sensor reports its readings. A function wakes up, answers one
call and goes back to sleep. A desktop app shows a dashboard in the browser. An integration
engine takes webhooks all day.

In Rust, that door usually comes with a house attached: an async runtime, a few dozen crates,
and a megabyte or more of code you didn't write and can't easily audit.

**simoom is just the door.** You add one crate, write a function that answers a request, and
call `start()`. Underneath, it serves HTTP/1.1, HTTP/2 and HTTP/3, does its own TLS 1.3, and
runs one event loop per CPU core on epoll, io_uring, IOCP or kqueue. There is nothing in it
but the Rust standard library and code in this repository.

```rust
use simoom::{Outcome, Reply, Request, Server, StaticReply};
use std::sync::Arc;

fn main() {
    let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let server = Server::builder()
        .listen("127.0.0.1:8080")
        .service(move |_req: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.fixed(&hello) })
        .start()
        .unwrap();
    println!("listening on {}", server.local_addr());
    server.join();
}
```

In benchmark campaign 4 (2026-11-12), simoom's default build answered its first request 0.94 ms
after the process started, the fastest of 21 servers, and used 901 KB of memory at rest. An
HTTP/1.1-only build adds about 215 KB to your binary.

## Contents

- [Why simoom exists](#why-simoom-exists)
- [What you get, in numbers](#what-you-get-in-numbers)
- [Where simoom fits](#where-simoom-fits)
- [When to use something else](#when-to-use-something-else)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Pay only for what you use](#pay-only-for-what-you-use)
- [The benchmarks, and how they were run](#the-benchmarks-and-how-they-were-run)
- [Where simoom is behind](#where-simoom-is-behind)
- [How it is tested](#how-it-is-tested)
- [Status and limits](#status-and-limits)
- [FAQ](#faq)
- [Documentation](#documentation)
- [Contributing, security and licence](#contributing-security-and-licence)

## Why simoom exists

simoom was built for [Cameleer](https://github.com/Cameleering/cameleer), which runs Apache
Camel integration routes in Rust using only the standard library. Cameleer's first HTTP server
gave every connection its own thread. That is simple and it works, but threads are heavy: with
1,000 idle connections open it used 7.7 MB, and with the server on 4 CPU cores it topped out at
about 173,000 requests per second.

Cameleer needed something better, with rules that ruled out the usual answers:

- **No external crates.** Cameleer uses nothing outside std, so tokio, hyper, rustls and
  OpenSSL were all off the table.
- **Small enough for edge devices and serverless functions**, where every kilobyte and every
  millisecond of start-up counts.
- **Every protocol**, HTTP/3 included, in the first release.
- **Faster than what it replaces**, and never more than 5% worse on start-up time or memory,
  measured on the same machine.

So simoom was written from the ground up: the HTTP parsers, HTTP/2, QUIC and HTTP/3, the TLS
1.3 stack and its cryptography, the compression codecs and the event loops for four operating
systems. On a workstation, against Cameleer's old server, simoom serves 1.7 to 1.8 times as
many requests, with a p99 latency of 0.32 to 0.44 ms instead of 0.87 to 0.91 ms, and holds 1,000
idle connections in 2.7 MB instead of 7.7 MB.

**The name.** A simoom is a hot, fast wind that crosses the desert. It belongs to the same
caravan as Cameleer and Cameleering.

**The rule.** simoom is a [Cameleering](https://cameleer.ing/cameleering/) project. Cameleering
means making software carry the same load on less, and proving it against the original. No claim
without a number: every figure in this README comes from results committed in this repository,
and the scenarios where simoom loses are published next to the ones where it wins.

## What you get, in numbers

Every comparison below is from benchmark campaign 4 (2026-11-12): simoom and 20 other servers on
DigitalOcean `c-4` droplets, with simoom on the same droplet in the same round as each of them, and
each figure the median of rounds. The method is under
[The benchmarks](#the-benchmarks-and-how-they-were-run).

| | simoom | compared with |
|---|---|---|
| Start-up to the first answer, default build (HTTP/1.1, HTTP/2, WebSocket) | **0.94 ms**, 1st of 21 | hyper 1.48 ms; the median of the 20 others 6.4x slower |
| Start-up, full server with TLS 1.3 and HTTP/3 | 1.49 ms | hyper 1.48 ms (level) |
| Memory per idle connection, 10,000 open | **573 bytes**, 2nd of 19 | nginx 538 bytes (6% less); hyper 17,790 bytes |
| CPU time per request at 50,000 requests per second | **23.6 µs**, 1st of 19 | hyper 32.6 µs |
| Status endpoint, 256 clients, requests per second with 99% within 1 ms | 137,889, 2nd of 19 | may-minihttp 6% more; hyper 110,931 |
| HTTPS API, 256 clients, requests per second with 99% within 1 ms | **134,004**, 1st of 8 | axum + rustls 88,990; simoom also 30% ahead of H2O |
| HTTP/3, 64 clients, requests per second with 99% within 1 ms | 2nd of 4 | H2O 43% more; simoom 1.65x quinn + h3 |
| Program size, stripped, default build | 735 KB | hyper 2,069 KB; may-minihttp 515 KB |
| Code added to your binary, HTTP/1.1 only | **215 KB** | budget 250 KB |
| Code added to your binary, everything including HTTP/3 | **935 KB** | budget 1 MB |

Not every row is a win. may-minihttp leads plain throughput, axum + rustls leads full TLS
handshakes, H2O leads HTTP/2 and HTTP/3, and several servers do better during traffic spikes and
under slow attackers; all of it is listed under [Where simoom is behind](#where-simoom-is-behind).
The last two rows come from `scripts/size.sh`, not from the campaign.

## Where simoom fits

**On a device at the edge.** A gateway on a factory floor has an ARM chip, 256 MB of RAM and a
firmware image that has to stay small. It needs to accept readings over HTTP and offer a small
status page. With only the `http1` feature, simoom adds about 215 KB to the binary, and in
campaign 4 it held idle connections in 532 to 573 bytes each. Even with TLS, the build needs no C compiler, no
cmake and no OpenSSL headers for the target. (The ARM code paths compile but have not been
benchmarked yet.)

**In a serverless function.** A function that scales to zero pays for its start-up on every cold
request. In campaign 4, simoom's default build gave its first answer 0.94 ms after the process
started (hyper: 1.48 ms), the full server with TLS 1.3 and HTTP/3 1.49 ms, and the default build
used 901 KB at rest, so the time and memory go to your code instead of the HTTP layer.

**Inside a CLI or desktop app.** A command-line tool needs a local callback for an OAuth login. A
desktop app wants to show a live dashboard in the browser and push updates over WebSocket or
server-sent events. simoom runs on Windows, Linux and macOS, starts in a millisecond and pulls no
async runtime into a program that never needed one.

**In an integration engine.** Webhooks, REST and MCP endpoints, streaming responses, and calls that
block on a database or a slow partner system. simoom answers fast work on the loop thread, sends
slow work to a bounded pool that says `503` instead of piling up, and lets a host with its own
threads answer later from any of them. This is how [Cameleer](https://github.com/Cameleering/cameleer)
uses it.

**Where every line of code has to be accounted for.** A bank, a medical device maker or a defence
supplier has to review every third-party dependency and track it for vulnerabilities. simoom has
none: no crates.io dependencies at all, not even for tests. Every line, from the TLS handshake to
the QUIC congestion control, is in this repository under one licence. `unsafe` code lives in one
crate, `simoom-sys`, where each block explains why it is sound.

**For a service that wants HTTP/3.** Mobile clients on flaky networks benefit from HTTP/3 over
QUIC. With simoom, HTTP/3 is a cargo feature on the same server: TCP and QUIC listen on the same
port number, and browsers are told about HTTP/3 with `alt-svc`. It passes 54 of 58 supported
pairs in the QUIC Interop Runner, and the four failures are features it does not offer (0-RTT and
ECN).

## When to use something else

simoom is new, small and focused. Pick the alternative when it fits better:

| If you need | Use | Why |
|---|---|---|
| A web server that runs from a config file, serves static files or proxies to other servers | nginx, Caddy or h2o | simoom is a library you build into a program; it has no config file, no static-file server and no reverse proxy. |
| A large ecosystem of middleware, extractors and integrations, and many people who already know the API | axum or actix-web | simoom's API is small and young. It has a router and optional helpers, not an ecosystem. |
| A low-level HTTP library inside the tokio world, or one with years of production use | hyper | hyper is mature and battle-tested. simoom is at version 0.1.0. |
| The very simplest blocking server for a tool or a test | tiny_http | It is tiny and easy. simoom gives you more protocols and more throughput, at more API surface. |
| A general-purpose QUIC transport, raw QUIC streams, or 0-RTT | quinn or s2n-quic | simoom's QUIC exists to carry HTTP/3. It refuses 0-RTT by design and has no ECN yet. |
| An independent security audit of the TLS stack | rustls with ring or aws-lc | simoom's TLS and crypto have been tested hard but not independently audited yet. |

## Quick start

simoom needs Rust 1.89 or newer.

```sh
cargo add simoom
```

or in `Cargo.toml`:

```toml
[dependencies]
simoom = "0.1"
```

The client is a separate crate: `cargo add simoom-client`. The API documentation is on
[docs.rs](https://docs.rs/simoom).

To run the bundled hello-world server from a checkout:

```bash
cargo run --release -p simoom --example hello -- 127.0.0.1:8080
```

A **service** is a plain function that takes a request and a reply and returns an `Outcome`. It
runs on the loop thread, so it must not block: there is no `async` and no runtime to set up.
Work that blocks goes to the offload pool or to your own threads, as the examples show.

## Examples

These examples compile against the current API with `--features full`.

### Routing, JSON, request bodies and limits

```rust
use simoom::{Limits, Outcome, Reply, Request, Router, Server};
use std::time::Duration;

let router = Router::new()
    .get("/health", |_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
    .get("/users/:id", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
        let id = req.param_str("id").unwrap_or("").to_string();
        r.header("content-type", "application/json").body(format!("{{\"id\":\"{id}\"}}"))
    })
    .route("POST", "/orders", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
        let n = req.body().len();
        r.status(201).body(format!("received {n} bytes"))
    });

let server = Server::builder()
    .listen("0.0.0.0:8080")
    .limits(Limits { max_body: 1 << 20, keep_alive_timeout: Duration::from_secs(30), ..Limits::default() })
    .service(router)
    .start()
    .expect("start");
```

### Slow work: the offload pool, or your own threads

Work that takes a while, such as a database query or a call to another service, goes to the
bounded offload pool. When the pool is full, the client gets a fast `503` with `Retry-After`
instead of waiting in an endless queue:

```rust
use simoom::{blocking, OwnedRequest, Response, Router};

let router = Router::new().get("/report", blocking(|req: OwnedRequest| {
    // runs on an offload worker, never on a loop thread
    Response::text(format!("report for {}", req.path_str()))
}));
```

A host that already has its own threads can defer the reply and answer from any of them. This is
how Cameleer embeds simoom:

```rust
use simoom::{Outcome, Reply, Request, Response, Server};

let server = Server::builder()
    .listen("127.0.0.1:8080")
    .service(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let owned = req.to_owned_request();
        let responder = reply.defer();
        std::thread::spawn(move || {
            responder.send(Response::text(format!("done: {}", owned.path_str())));
        });
        Outcome::Done
    })
    .start()
    .unwrap();
```

### TLS, HTTP/2 and HTTP/3 on one port

Build with `--features full`, or with `tls` and `http3`. Over TCP, the client and server agree on
HTTP/2 or HTTP/1.1 during the TLS handshake. The QUIC listener serves HTTP/3 on the same port
number:

```rust
use simoom::tls::{certgen, CertifiedKey, ServerConfig};
use simoom::{Reply, Request, Server};

// a self-signed certificate for local testing; load your own PEM files in production
let cert = certgen::self_signed("localhost");
let key = CertifiedKey::from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("certificate and key");
let tls = ServerConfig::new(key);

let server = Server::builder()
    .listen_tls("0.0.0.0:8443")
    .tls(tls.clone())
    .listen_quic("0.0.0.0:8443") // HTTP/3, announced with alt-svc
    .quic_tls(tls)
    .service(|_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"Hello over TLS"))
    .start()
    .expect("start");
```

### Live updates: server-sent events and WebSocket

```rust
use simoom::{Outcome, Reply, Request, Router, WebSocket, WebSocketHandler, WsMessage};
use std::time::Duration;

struct Echo;
impl WebSocketHandler for Echo {
    fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {
        match msg {
            WsMessage::Text(t) => ws.send_text(t),
            WsMessage::Binary(b) => ws.send_binary(b),
        }
    }
}

let router = Router::new()
    .get("/events", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
        let mut sink = r.sse();
        std::thread::spawn(move || {
            for i in 0..3 {
                if sink.send_event(&format!("tick {i}")).is_err() { return; }
                std::thread::sleep(Duration::from_secs(1));
            }
            sink.finish();
        });
        Outcome::Done
    })
    .get("/ws", |_: &mut Request<'_>, r: Reply<'_>| r.websocket(Echo));
```

### Threads, io_uring and a graceful stop

```rust
use simoom::{Backend, Reply, Request, Server};
use std::time::Duration;

let server = Server::builder()
    .listen("0.0.0.0:8080")
    .threads(2)               // 0 = one loop per core (the default)
    .backend(Backend::IoUring) // Linux 6.1+, falls back to epoll; the default `Auto` is epoll on Linux
    .service(|_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
    .start()
    .unwrap();
// ...
server.stop(Duration::from_secs(5)); // tells clients to finish, then waits up to 5 s
server.join();
```

### The HTTP client

```rust
use simoom_client::{Client, HttpVersion};
use std::time::Duration;

let client = Client::builder()
    .connect_timeout(Some(Duration::from_secs(5)))
    .follow_redirects(true)
    .build();

let resp = client.get("https://example.com/").send()?; // HTTP/2 or HTTP/1.1, agreed in the handshake
println!("{} {} bytes", resp.status(), resp.bytes()?.len());

let resp = client
    .post("http://127.0.0.1:8080/orders")
    .header("Content-Type", "application/json")
    .body(r#"{"sku":"A-1","qty":2}"#)
    .version(HttpVersion::Http2) // h2c with prior knowledge
    .timeout(Duration::from_secs(10))
    .send()?;
```

The client speaks HTTP/1.1, HTTP/2 and HTTP/3, pools connections per origin, moves to HTTP/3 when
a server offers it, and handles proxies, redirects, decompression, cookies and WebSocket.
Certificate verification is always on.

### The smallest build, for a device or a function

Turn off everything but HTTP/1.1:

```toml
simoom = { version = "0.1", default-features = false, features = ["http1"] }
```

## Pay only for what you use

Every protocol is a cargo feature, and a build script fails when a size budget is exceeded.

| feature | adds |
|---|---|
| `http1` (default) | HTTP/1.1 |
| `http2` (default) | HTTP/2: h2c, `Upgrade: h2c`, h2 over TLS |
| `websocket` (default), alias `ws` | WebSocket on HTTP/1.1 |
| `io-uring` (default) | the Linux io_uring back end (`Backend::IoUring` or `SIMOOM_BACKEND=io_uring`); without it, epoll |
| `watchdog`, `guard`, `idle-trim` (default) | moves slow handlers off the loop; guards against overload and slow clients; returns memory after bursts |
| `tls` | TLS 1.3 listeners: X25519, P-256, RSA, AES-GCM |
| `tls-extra` | P-384 and Ed25519 certificates, ChaCha20-Poly1305 |
| `http3` | HTTP/3 over QUIC (needs `tls`) |
| `full` | HTTP/1.1, HTTP/2, HTTP/3, TLS with `tls-extra`, WebSocket, io_uring, the default safety nets and the TLS client; not compression, `websocket-h2`/`h3`, `ws-deflate`, `h2-keepalive` or the helpers below |
| `compression`, `brotli`, `zstd` | response compression and request decoding |
| `websocket-h2`, `websocket-h3`, `ws-deflate` | WebSocket over HTTP/2 and HTTP/3; permessage-deflate |
| `h2-keepalive` | HTTP/2 PING keepalive |
| `multipart`, `cookies`, `conditional`, `cors`, `auth` | helpers for forms, cookies, caching, CORS and Basic, Digest and Bearer auth |

What each build adds to a binary, measured as the bytes added to
[`examples/hello.rs`](crates/simoom/examples/hello.rs) over an empty `fn main`, stripped, on
x86-64 Linux with the `dist` profile ([`scripts/size.sh`](scripts/size.sh)):

| build | size | budget |
|---|---:|---:|
| HTTP/1.1 only (`--no-default-features --features http1`) | 214,568 B | 256,000 B |
| HTTP/1.1, HTTP/2, TLS, io_uring | 583,680 B | 614,400 B |
| everything: HTTP/1.1, HTTP/2, HTTP/3, TLS, WebSocket, io_uring | 935,064 B | 1,048,576 B |

The HTTP/1.1 and full rows are from 2026-11-11 and the TLS row from 2026-11-12
([BUGS.md](docs/BUGS.md) U9). As whole programs in benchmark campaign 4, simoom's default build
was 735 KB stripped, against may-minihttp's 515 KB and hyper's 2,069 KB.

### What is inside

| crate | what it is |
|---|---|
| [`simoom`](crates/simoom) | the public API: `Server`, `Service`, `Reply`, `Responder`, `Router`, `Limits` |
| [`simoom-client`](crates/simoom-client) | HTTP/1.1, HTTP/2 and HTTP/3 client and WebSocket client |
| [`simoom-rt`](crates/simoom-rt) | one event loop per core, timers, buffer pools, wakeups, the offload pool |
| [`simoom-sys`](crates/simoom-sys) | epoll, io_uring, kqueue, IOCP, sockets, SIMD; the only crate with `unsafe` |
| [`simoom-http1`](crates/simoom-http1) | strict HTTP/1.1 parser and serializer (RFC 9112) |
| [`simoom-h2`](crates/simoom-h2), [`simoom-hpack`](crates/simoom-hpack) | HTTP/2 (RFC 9113) with flood protection, HPACK (RFC 7541) |
| [`simoom-quic`](crates/simoom-quic) | QUIC v1 transport (RFC 9000, 9002) |
| [`simoom-h3`](crates/simoom-h3), [`simoom-qpack`](crates/simoom-qpack) | HTTP/3 (RFC 9114), QPACK (RFC 9204) |
| [`simoom-tls`](crates/simoom-tls) | TLS 1.3, server and client, and the QUIC interface (RFC 9001); the crate also has TLS 1.2 as its own `tls12` feature, which the `simoom` server does not expose |
| [`simoom-compress`](crates/simoom-compress) | DEFLATE, zlib, gzip, Brotli and zstd, streaming and bounded |

The protocol crates are sans-io: they take bytes and time and return bytes and events, and never
open sockets, start threads or read clocks. You can drive them from your own I/O loop. The
cryptography is planned to move into **ksar**, a shared crypto family for Cameleering projects.

## The benchmarks, and how they were run

Campaign 4, 2026-11-12. Charts for every measure and every server:
[cameleer.ing/simoom/benchmarks](https://cameleer.ing/simoom/benchmarks/); the tables:
[report.md](bench/results/2026-11-12-campaign4/report.md); why the campaign was run this way:
[docs/benchmark-review.md](docs/benchmark-review.md).

- **Machines:** DigitalOcean `c-4` droplets: 4 dedicated vCPUs, Xeon Platinum 8280, Bangalore,
  Ubuntu 24.04, a network card with one receive queue. Three lanes, each with its own server
  droplet and two load droplets; the server droplets rotate between rounds.
- **Same droplet only:** simoom ran in every lane and every round, so every server is compared
  with simoom on the same droplet, with the same load machines, in the same round. The published
  ratio is the median of the per-round ratios.
- **Load:** open loop, so a slow server can't slow the load down and hide its own latency.
- **Throughput figure:** the highest steady rate at which 99% of answers arrive within 1 ms (5 ms
  for new connections, downloads and HTTP/2), with no errors.
- **Rounds:** round 1 ran every scenario for every server; rounds 2 and 3 repeated the status
  endpoint at 256 clients, the JSON API, new connections, TLS and CPU.
- **Everything is published:** the raw records, the scripts and the competitor programs are
  committed under [`bench/`](bench).

### Use case by use case

| use case and measure | simoom's place | against the best other | against the median server |
|---|---|---|---|
| Status endpoint, 256 clients: requests/s with 99% within 1 ms | 2nd of 19 | may-minihttp: 6% more than simoom | simoom 50% more |
| JSON API, 1 KB in and out, 256 clients | 2nd of 12 | may-minihttp: 5% more than simoom | simoom 27% more |
| HTTPS API, 256 clients | 1st of 8 | axum + rustls: simoom 30% more | simoom 2.1x more |
| A new connection per request, 192 clients (99% within 5 ms) | 5th of 19 | xitca-web: 29% more than simoom | simoom 10% more |
| HTTP/2, 64 connections x 100 streams (99% within 5 ms) | 2nd of 12 | H2O: 11% more than simoom | simoom 74% more |
| HTTP/3, 64 clients | 2nd of 4 | H2O: 43% more than simoom | simoom 65% more |
| 64 KB downloads, 64 clients (99% within 5 ms) | joint 1st of 8 | actix-web: level | level |
| 10,000 idle connections: memory per connection | 2nd of 19 | nginx: 6% less than simoom | simoom 20x less |
| Traffic spike at 195,000 requests/s offered: answers within 1 ms | 10th of 19 | actix-web: 22x more than simoom | 26% more than simoom |
| Under 11,000 slow attackers: p99 of real requests | 6th of 19 | Go net/http: 44% lower than simoom | simoom 32% lower |
| Start-up to first answer, default build | 1st of 21 | hyper: simoom 57% faster | simoom 6.4x faster |
| CPU per request at a fixed 50,000 requests/s | 1st of 19 | may-minihttp: simoom 15% lower | simoom 1.5x lower |

Earlier campaigns (1 to 3) measured fewer servers, not always on the same droplet as simoom; their
records stay in [`bench/results/`](bench/results) but their figures are no longer quoted.

### Against the server it replaced

Cameleer's old thread-per-connection server (`cameleer-http`) and simoom, both returning the same
13-byte answer on a workstation (WSL2). These figures compare simoom only with the server it
replaced, on that machine; for every other server see campaign 4 above. Start-up and idle memory, 10 alternating rounds,
2026-11-11:

| build | start-up to first answer | idle memory (PSS) |
|---|---:|---:|
| simoom, plain | **0.73 ms** | 1,018 KB |
| cameleer-http, plain | 0.77 ms | 1,017 KB |
| simoom, TLS (P-256) | **0.87 ms** | 1,360 KB (after the K11 fix, 2026-11-12) |
| cameleer-http, TLS | 1.37 ms | 1,317 KB |

Under load (server on 4 CPUs, 64 connections, closed loop, 2026-11-09):

| | simoom | cameleer-http |
|---|---:|---:|
| throughput | 293,000–311,000 req/s | 172,000–173,000 req/s |
| p99 latency | 0.32–0.44 ms | 0.87–0.91 ms |
| server CPU per request | about 13 µs | about 23 µs |
| memory with 1,000 idle connections | 2.7 MB | 7.7 MB |

## Where simoom is behind

Losses are part of the result. All figures are from campaign 4 (2026-11-12), each server against
simoom on the same droplet:

- **Plain throughput.** may-minihttp answered 15%, 6% and 16% more status-endpoint requests at 64,
  256 and 1,024 clients, and 5% more on the 1 KB JSON API. At 64 clients Vert.x (50%), fasthttp
  (25%), Netty (20%) and uWebSockets.js (13%) also answered more than simoom on their droplet.
- **A new connection for every request.** xitca-web handled 29% more, Cameleer's old server 9%,
  actix-web 5% and may-minihttp 4%.
- **Full TLS handshakes.** axum with rustls completed 24% more full handshakes per second (11,633
  against 9,530) and 9% more resumed ones.
- **HTTP/2 and HTTP/3.** H2O answered 11% more HTTP/2 and 43% more HTTP/3 requests, and used 43%
  less peak memory serving HTTP/3.
- **Traffic spikes.** At 195,000 requests per second offered, simoom was 10th of 19 on answers
  within 1 ms: actix-web answered 22x as many, nginx 4.7x and xitca-web 3.2x. In total answers
  simoom was level with most servers.
- **Slow attackers.** Under 11,000 slow attackers simoom was 6th of 19 on p99 of real requests:
  Go net/http (44% lower), HAProxy (34%), Vert.x (27%), Netty (20%) and H2O (19%) did better.
- **Memory.** nginx used 6% less per idle connection with 10,000 open (level at 100,000). hyper,
  axum, xitca-web and Cameleer's old server used less memory at rest than simoom's full server
  (1,844 KB; the default build used 901 KB).
- **Program size.** may-minihttp's program is 515 KB against 735 KB for simoom's default build.
  The full server, at 1,550 KB, is larger than may-minihttp, xitca-web, nginx, Cameleer's old
  server and H2O.
- **Against the server it replaced, on a workstation:** idle memory with TLS was 3.3% above
  Cameleer's old server (1,360 KB against 1,317 KB).

The raw results are in [`bench/results/`](bench/results). To rerun the benchmarks, use
[`bench/cloud/`](bench/cloud) and [`scripts/size.sh`](scripts/size.sh). If you measure something
differently and get a different number, please open an issue with your method.

## How it is tested

simoom follows RFC 9110, 9112, 9113, 9114 and 9204 strictly: any request whose framing is
ambiguous is refused, every limit has a default, and certificate verification can't be turned off.
Every crate except `simoom-sys` is `#![forbid(unsafe_code)]`. Versions, commands and details are
in [docs/SECURITY.md](docs/SECURITY.md).

| check | result |
|---|---|
| h2spec 2.6.0 | **146/146**, in 30 consecutive runs |
| QUIC Interop Runner, server role, against the ngtcp2, quiche and quic-go clients | **54 of 58** supported pairs; the 4 failures are 0-RTT (refused by design) and ECN (not implemented) |
| HTTP Garden, as an origin next to nginx, Apache httpd, h2o, hyper, gunicorn and Go | **0 desyncs**, 0 dangerous discrepancies |
| Request-smuggling test behind nginx 1.24 and haproxy 2.8 | 165 streams, **0 desyncs**; accepted **0** requests that both refused |
| testssl.sh 3.2.1 | no vulnerabilities found |
| TLS interop: OpenSSL `s_client`; curl with OpenSSL, Python `ssl` and gnutls-cli; curl with Schannel | 28/28, 31/31, 3/3 |
| nghttp and h2load | 14/14 |
| Fuzzing | std-only mutation fuzzing of every parser for 2 h 40 min, and coverage-guided fuzzing of HTTP/1.1 |
| Test suite, `cargo test --workspace` | 777 passed on Windows, 791 on Linux (WSL2), zero warnings |

## Status and limits

- **Version 0.1.0.** The API can still change.
- **No independent security audit yet.** The testing above was done by the project itself.
- **QUIC:** no 0-RTT (refused by design), no ECN, no migration to a preferred address.
- **Platforms:** the test suite runs on Windows and Linux. macOS (kqueue) and the ARM SIMD and
  crypto paths are compile-checked only.
- **Benchmarks:** every cloud figure comes from 4-vCPU droplets with a single-queue network card.
  Larger machines have not been measured.
- **A library, not a product:** no static-file server, reverse proxy or configuration file.

The current state and open items are in [docs/STATUS.md](docs/STATUS.md) and
[docs/BUGS.md](docs/BUGS.md).

## FAQ

### Is there a Rust HTTP server without tokio?

Yes. simoom has no async runtime at all. A service is a plain function that runs on the loop
thread; slow work goes to a bounded offload pool (`simoom::blocking`) or to your own threads
(`Reply::defer`). Streaming, server-sent events and WebSocket all work without `async`.

### Is there a Rust web server with zero dependencies?

Yes. simoom's workspace has no crates.io dependencies, not even dev-dependencies. Calls into the
operating system go through `extern` declarations in `simoom-sys`, and SIMD goes through
`core::arch`. The only exceptions are the competitor programs under `bench/competitors/`, which are
separate projects that exist only to be benchmarked against.

simoom is std-only, not `no_std`: it uses the Rust standard library, so it needs an operating
system (Linux, Windows or macOS). It does not run on bare-metal microcontrollers.

### Can I serve HTTP/3 from Rust without quinn, rustls or OpenSSL?

Yes. simoom implements QUIC v1, HTTP/3, QPACK and TLS 1.3 itself, and HTTP/3 is a cargo feature
of the same server that serves HTTP/1.1 and HTTP/2. It passes 54 of 58 supported
pairs in the QUIC Interop Runner against the ngtcp2, quiche and quic-go clients. In benchmark
campaign 4 (2026-11-12) it answered 1.65 times as many HTTP/3 requests as quinn with h3 on the same
droplet; H2O answered 43% more than simoom.

### What is the smallest Rust HTTP server for AWS Lambda or other serverless platforms?

An HTTP/1.1-only simoom build adds about 215 KB to a binary. In benchmark campaign 4 (2026-11-12),
the default build gave its first answer 0.94 ms after the process started, the fastest of 21
servers, and used 901 KB at rest. Turn off the default features and keep `http1`.

### How do I embed an HTTP or WebSocket server in a Rust app?

Add `simoom`, build a `Server` with `Server::builder()`, give it a service or a `Router`, and call
`start()`. It runs on its own threads and returns a handle you can `stop()` and `join()`. See
[Quick start](#quick-start) and the [WebSocket example](#live-updates-server-sent-events-and-websocket).

### How does simoom compare with hyper and axum?

In benchmark campaign 4 (2026-11-12), on the same 4-vCPU droplet, simoom answered 137,889 status
requests per second with 99% within 1 ms at 256 clients, against hyper's 110,931 (24% more), and
used 26% less CPU per request at a fixed 50,000 req/s; hyper used less memory at rest.
hyper (which axum is built on) is far more mature and has a large ecosystem; simoom has no
dependencies and a much smaller footprint. Choose by what matters more to you.

### Can it run on a Raspberry Pi or another ARM board?

It is built for small devices, and the ARM SIMD and crypto paths compile. They are compile-checked
only so far, and the benchmarks ran on x86-64. Reports from ARM hardware are welcome.

### Can I use it as a reverse proxy or a static-file server?

No. simoom is an engine you build into a program. For those jobs, use nginx, Caddy or h2o.

### Which platforms does it run on?

Linux (epoll and io_uring), Windows (IOCP) and macOS (kqueue). The test suite runs on Windows and
Linux; macOS is compile-checked only.

### Is it safe to put on the internet?

It was built for it: strict parsing, a limit on everything, protection against HTTP/2 floods,
slowloris and reconnect storms, and a panic in a handler becomes a `500` instead of a crash. It
has not had an independent security audit yet; see [docs/SECURITY.md](docs/SECURITY.md).

## Documentation

| | |
|---|---|
| [docs/STATUS.md](docs/STATUS.md) | the current state and latest measurements |
| [docs/design/plan.md](docs/design/plan.md) | design, scope and size budgets |
| [docs/design/research.md](docs/design/research.md) | the research behind the design |
| [docs/SECURITY.md](docs/SECURITY.md) | security model, limits, test results, reporting a vulnerability |
| [docs/BUGS.md](docs/BUGS.md) | bugs found and fixed, open items |
| [docs/parity/](docs/parity) | parity with Cameleer's client, server and TLS |
| [bench/results/](bench/results) | benchmark campaigns: raw data and analyses |
| [llms.txt](llms.txt) | a summary for AI assistants |
| API docs | [docs.rs/simoom](https://docs.rs/simoom), or `cargo doc -p simoom --features full --open` |

## Contributing, security and licence

- **Contributing:** issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security:** report vulnerabilities privately through
  [GitHub security advisories](https://github.com/Cameleering/simoom/security/advisories/new).
  Details are in [docs/SECURITY.md](docs/SECURITY.md).
- **Licence:** [Apache License 2.0](LICENSE).

simoom is a [Cameleering](https://cameleer.ing/cameleering/) project, alongside
[Cameleer](https://github.com/Cameleering/cameleer), which runs Apache Camel routes in Rust.
simoom is independent of the Apache Software Foundation. Apache and Apache Camel are trademarks
of the ASF.
