<p align="center"><img src="assets/simoom-logo-1200.png" alt="simoom: HTTP Server Engine" width="600"></p>

# simoom: an embeddable HTTP/1.1, HTTP/2 and HTTP/3 server engine in std-only Rust

**simoom** is a small, fast, secure HTTP server engine that you embed in a Rust program. It
covers:

- HTTP/1.1, HTTP/2 and HTTP/3 over QUIC;
- TLS 1.3, with TLS 1.2 as an option;
- WebSocket;
- an HTTP client.

It depends on nothing but the Rust standard library: no tokio, no hyper, no rustls and no OpenSSL.
It runs one event loop per core, on epoll or io_uring on Linux, IOCP on Windows or kqueue on
macOS. It is built for edge devices and serverless functions as well as servers, and it is the
HTTP engine behind [Cameleer](https://github.com/Cameleering/cameleer).

*A [Cameleering](https://cameleer.ing/cameleering/) project: make software carry the same load on
less, and prove it against the original. No claim without a number.*

[![crates.io](https://img.shields.io/crates/v/simoom.svg)](https://crates.io/crates/simoom)
[![docs.rs](https://img.shields.io/docsrs/simoom)](https://docs.rs/simoom)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![dependencies: std only](https://img.shields.io/badge/dependencies-std%20only-success)
![unsafe: one crate](https://img.shields.io/badge/unsafe-simoom--sys%20only-informational)
![MSRV 1.89](https://img.shields.io/badge/rust-1.89%2B-orange)
![HTTP/3](https://img.shields.io/badge/HTTP%2F3-QUIC%20v1-informational)

## At a glance

All figures are measured. The method and the raw data are under [Benchmarks](#benchmarks).

| | simoom | compared with |
|---|---|---|
| plaintext requests/s at p99 ≤ 1 ms, 256 connections, same 4-vCPU droplet | **172,638** | hyper 144,443 · may-minihttp 150,673 |
| TLS 1.3 full / resumed handshakes per second, same droplet | **10.1k / 11.2k** | h2o 7.7k / 7.8k |
| requests/s over TLS at p99 ≤ 1 ms, 256 connections, same droplet | **160,441** | h2o 97,219 |
| HTTP/3 requests/s at p99 ≤ 1 ms, same droplet | **106,947** | h2o 94,507 |
| CPU per request at 50k req/s | **25.1 µs** | hyper 28.1 µs |
| cold start to first response | **0.73 ms** plain, **0.87 ms** TLS | Cameleer's previous HTTP server 0.77 / 1.37 ms (same machine) |
| memory per idle keep-alive connection, 100k open | **520–533 B** | nginx 532 B |
| full server build (HTTP/1.1, HTTP/2, HTTP/3, TLS, WebSocket, io_uring), stripped | **935 KB** of added code | budget 1 MB |
| HTTP/1.1-only build, stripped | **215 KB** of added code | budget 250 KB |

simoom also loses in some scenarios. They are listed under [Where simoom is behind](#where-simoom-is-behind).

## Contents

- [Why simoom](#why-simoom)
- [Features](#features)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Cargo features and binary size](#cargo-features-and-binary-size)
- [Benchmarks](#benchmarks)
- [Conformance, interop and security testing](#conformance-interop-and-security-testing)
- [Status and limits](#status-and-limits)
- [FAQ](#faq)
- [Documentation](#documentation)
- [Contributing, security and licence](#contributing-security-and-licence)

## Why simoom

- **Nothing outside std.** There are no crates.io dependencies at all, not even dev-dependencies.
  The whole stack is in this repository, where you can read and audit it in one place: TLS and
  the crypto primitives, QUIC, QPACK, HPACK, the event loops and the compression codecs.
- **Small, and you pay only for what you use.** Every protocol is a cargo feature.
  - An HTTP/1.1-only server adds about 215 KB to a binary.
  - The full server with HTTP/3 adds about 935 KB.
  - A script fails the build when a size budget is exceeded.
- **Fast start, little memory.** The first response arrives 0.73 ms after the process spawns, and
  an idle server uses about 1 MB of PSS. That suits serverless functions, scale-to-zero and small
  devices.
- **Throughput per core.**
  - Loops share nothing, one per core, with no locks on the request path.
  - Headers are scanned with SIMD through `core::arch`, with runtime detection and a scalar
    fallback.
  - On Linux you can choose epoll or io_uring.
- **Strict and bounded.**
  - Parsing follows RFC 9110, 9112, 9113, 9114 and 9204.
  - Every limit has a default and is enforced.
  - In a differential test, simoom accepted none of the requests that both nginx and haproxy
    refused.
  - Certificate verification can't be turned off.
- **Safe by construction.** Every crate except `simoom-sys` starts with
  `#![forbid(unsafe_code)]`, and every `unsafe` block in `simoom-sys` carries a `SAFETY` comment.
- **No async runtime needed.** A `Service` is a plain function that runs on the loop thread.
  Blocking work goes to a bounded offload pool, or to your own threads through a `Responder`.

**When not to use it.** simoom is an engine, not a web-server product. It has no static-file
server, no reverse proxy and no configuration-file web server. Use nginx, Caddy or h2o for those.

## Features

**Protocols**

- **HTTP/1.1:** keep-alive, pipelining, chunked bodies and trailers, `100-continue`.
- **HTTP/2:** h2c with prior knowledge and `Upgrade: h2c`, and h2 over TLS through ALPN.
  Work-based DoS accounting covers RST_STREAM, PING, SETTINGS and CONTINUATION floods.
- **HTTP/3 over QUIC v1** (RFC 9000, 9001, 9002, 9114, 9204):
  - announced with `alt-svc`;
  - Retry, resumption, key update, address rebinding and IPv6;
  - 0-RTT is refused by design.
- **TLS 1.3:**
  - X25519, P-256 and RSA with AES-GCM; P-384, Ed25519 and ChaCha20-Poly1305 with `tls-extra`;
  - session resumption and client certificates (mTLS);
  - self-signed certificates for tests (`simoom::tls::certgen`);
  - TLS 1.2 with the `simoom-tls` feature `tls12`.
- **WebSocket** (RFC 6455), also over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220), with permessage-deflate.

**Server**

- **Router:**
  - exact paths in a hash map;
  - `:param`, `{param}` and `*rest` templates;
  - `405` with `allow`;
  - `HEAD` served by `GET` routes.
- **Ways to answer:**
  - an immediate reply;
  - a deferred reply from any thread (`Reply::defer`);
  - a streamed body with backpressure (`Reply::stream`);
  - server-sent events (`Reply::sse`);
  - work on the offload pool (`blocking`, `Reply::offload`);
  - a WebSocket.
- **Request bodies** are buffered up to a limit, then streamed with pull-based backpressure.
- **Optional helpers:** response compression (gzip, deflate, Brotli, zstd), `multipart/form-data`,
  cookies, conditional and range requests, CORS, and Basic, Digest and Bearer authentication.

**Runtime and safety nets**

- **Loops:** one per core, started lazily, kept off the CPU that takes the NIC's receive
  interrupts.
- **Offload pool:** bounded, with CoDel admission. It answers a fast `503` instead of queueing
  without bound.
- **Stall watchdog:** moves a route whose inline handler turns out slow to the offload pool, and
  back once it is fast again.
- **Limits:** head and body size, timeouts, minimum body rate, write deadline, connections per IP.
- **Guards:** against overload and slow clients, such as slowloris and reconnect storms.
- **Failure handling:** a handler panic becomes a `500`. A graceful stop sends GOAWAY on HTTP/2 and
  HTTP/3, and `Connection: close` on HTTP/1.1.

**Client** ([`simoom-client`](crates/simoom-client))

- HTTP/1.1, HTTP/2 and HTTP/3, with a connection pool per origin. It moves to HTTP/3 when the
  server announces it in `Alt-Svc`, and falls back to TCP.
- TLS with verification always on, custom roots and client certificates.
- Proxies (`CONNECT`, SOCKS5, `NO_PROXY`) and streaming in both directions.
- Every timeout, redirects and decompression.
- A cookie jar, Digest and NTLM authentication, and a WebSocket client.

### Crates

| crate | what it is |
|---|---|
| [`simoom`](crates/simoom) | the public API: `Server`, `Service`, `Reply`, `Responder`, `Router`, `Limits` |
| [`simoom-client`](crates/simoom-client) | HTTP/1.1, HTTP/2 and HTTP/3 client and WebSocket client |
| [`simoom-rt`](crates/simoom-rt) | one event loop per core, timer wheel, buffer pools, cross-thread wakeups, offload pool |
| [`simoom-sys`](crates/simoom-sys) | epoll, io_uring, kqueue, IOCP, sockets, SIMD scan; the only crate with `unsafe` |
| [`simoom-http1`](crates/simoom-http1) | sans-io, strict HTTP/1.1 parser and serializer (RFC 9112) |
| [`simoom-h2`](crates/simoom-h2), [`simoom-hpack`](crates/simoom-hpack) | sans-io HTTP/2 (RFC 9113) with DoS accounting, HPACK (RFC 7541) |
| [`simoom-quic`](crates/simoom-quic) | sans-io QUIC v1 transport (RFC 9000, 9002) |
| [`simoom-h3`](crates/simoom-h3), [`simoom-qpack`](crates/simoom-qpack) | sans-io HTTP/3 (RFC 9114), QPACK (RFC 9204) |
| [`simoom-tls`](crates/simoom-tls) | sans-io TLS 1.3 (and optional 1.2), server and client, with the QUIC interface (RFC 9001) |
| [`simoom-compress`](crates/simoom-compress) | DEFLATE, zlib and gzip, plus Brotli and zstd, streaming and bounded |
| [`simoom-bench`](crates/simoom-bench) | open-loop load generator, raw responders and size checks (not published) |

The protocol crates are sans-io: they take bytes and time and return bytes and events. They never
open sockets, spawn threads or read clocks, so you can drive them from your own I/O loop.

## Quick start

simoom is on [crates.io](https://crates.io/crates/simoom) (Rust 1.89 or newer):

```sh
cargo add simoom
```

or in `Cargo.toml`:

```toml
[dependencies]
simoom = "0.1"
```

The client is a separate crate: `cargo add simoom-client`. API documentation is on
[docs.rs](https://docs.rs/simoom).

A server that answers every request:

```rust
use simoom::{Outcome, Reply, Request, Server, StaticReply};
use std::sync::Arc;

fn main() {
    let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let server = Server::builder()
        .listen("127.0.0.1:8080")
        .threads(0) // one loop per core
        .service(move |_req: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.fixed(&hello) })
        .start()
        .unwrap();
    println!("listening on {}", server.local_addr());
    server.join();
}
```

Or run the bundled example:

```bash
cargo run --release -p simoom --example hello -- 127.0.0.1:8080
```

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

### Blocking work: the offload pool, or your own threads

A service must never block its loop thread. Work that takes up to seconds, such as database or
HTTP calls, goes to the bounded offload pool. When the pool is over capacity, the client gets a
fast `503` with `Retry-After`:

```rust
use simoom::{blocking, OwnedRequest, Response, Router};

let router = Router::new().get("/report", blocking(|req: OwnedRequest| {
    // runs on an offload worker, never on a loop thread
    Response::text(format!("report for {}", req.path_str()))
}));
```

A host that already has its own worker pool can defer the reply and answer from any thread. This
is how Cameleer embeds simoom:

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

Build with `--features full`, or with `tls` and `http3`. On TCP, ALPN chooses h2 or http/1.1.
The QUIC listener serves HTTP/3 on the same port number:

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

### Server-sent events and WebSocket

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

### Runtime configuration and graceful stop

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
server.stop(Duration::from_secs(5)); // GOAWAY or Connection: close, then wait up to 5 s
server.join();
```

### HTTP client

```rust
use simoom_client::{Client, HttpVersion};
use std::time::Duration;

let client = Client::builder()
    .connect_timeout(Some(Duration::from_secs(5)))
    .follow_redirects(true)
    .build();

let resp = client.get("https://example.com/").send()?; // ALPN chooses h2 or http/1.1
println!("{} {} bytes", resp.status(), resp.bytes()?.len());

let resp = client
    .post("http://127.0.0.1:8080/orders")
    .header("Content-Type", "application/json")
    .body(r#"{"sku":"A-1","qty":2}"#)
    .version(HttpVersion::Http2) // h2c with prior knowledge
    .timeout(Duration::from_secs(10))
    .send()?;
```

### An edge build

For a device or a function that needs only HTTP/1.1, turn everything else off:

```toml
simoom = { version = "0.1", default-features = false, features = ["http1"] }
```

## Cargo features and binary size

| feature | adds |
|---|---|
| `http1` (default) | HTTP/1.1 |
| `http2` (default) | HTTP/2: h2c, `Upgrade: h2c`, h2 over TLS |
| `websocket` (default), alias `ws` | WebSocket upgrades on HTTP/1.1 |
| `io-uring` (default) | the Linux io_uring back end (`Backend::IoUring` or `SIMOOM_BACKEND=io_uring`); without it, epoll |
| `watchdog`, `guard`, `idle-trim` (default) | stall watchdog; overload and slow-client guards; memory returned after bursts |
| `tls` | TLS listeners: X25519, P-256, RSA, AES-GCM |
| `tls-extra` | P-384 and Ed25519 certificates, ChaCha20-Poly1305 |
| `http3` | HTTP/3 over QUIC (needs `tls`) |
| `full` | every protocol above, plus the TLS client |
| `compression`, `brotli`, `zstd` | response compression and request decoding |
| `websocket-h2`, `websocket-h3`, `ws-deflate` | WebSocket over HTTP/2 and HTTP/3; permessage-deflate |
| `h2-keepalive` | HTTP/2 PING keepalive |
| `multipart`, `cookies`, `conditional`, `cors`, `auth` | server helpers |

**How size is measured.**

- **What:** the bytes added to [`examples/hello.rs`](crates/simoom/examples/hello.rs) over an empty
  `fn main`.
- **Build:** stripped, x86-64 Linux, `dist` profile.
- **Check:** [`scripts/size.sh`](scripts/size.sh) fails when a budget is exceeded.

| build | size | budget |
|---|---:|---:|
| HTTP/1.1 only (`--no-default-features --features http1`) | 214,568 B | 256,000 B |
| HTTP/1.1, HTTP/2, TLS, io_uring | 583,680 B | 614,400 B |
| full server: HTTP/1.1, HTTP/2, HTTP/3, TLS, WebSocket, io_uring | 935,064 B | 1,048,576 B |

The HTTP/1.1 and full-server rows are from 2026-11-11; the TLS row is from 2026-11-12 (see
[BUGS.md](docs/BUGS.md) U9).

As a whole executable, the HTTP/1.1-only server is 536 KB stripped against may-minihttp's 515 KB.
About 181 KB of either is the standard library's backtrace symbolizer.

## Benchmarks

**Method.**

- **Machines:** DigitalOcean `c-4` droplets (4 dedicated vCPUs, Xeon Platinum 8280, Bangalore
  region).
- **Load:** generated from two separate load nodes, open loop, with no coordinated omission.
- **Headline metric:** **SLO throughput**, the highest sustained rate whose p99 stays at or under
  1 ms.
- **S1:** a GET with a 13-byte reply, with one request in flight per connection.
- **Same droplet only:** every comparison below is between servers measured on the same droplet.
  Droplets of the same type differed by up to 7x for every server, so figures from different
  droplets are not compared.
- **Published:** the raw HDR logs, the scripts and the analyses are committed.

### Plaintext throughput, same droplet (2026-11-12)

S1, requests per second at p99 ≤ 1 ms. Each figure is the median of three rounds on one droplet.
The individual rounds are in [the analysis](bench/results/2026-11-12-epoll/analysis.md).

| server | 64 connections | 256 connections | 1024 connections |
|---|---:|---:|---:|
| **simoom (epoll)** | **170,648** | **172,638** | 138,644 |
| simoom (io_uring) | 152,714 | 172,331 | **148,429** |
| may-minihttp | 158,598 | 150,673 | 120,610 |
| hyper | 122,240 | 144,443 | 115,102 |

TLS 1.3 handshakes per second on the same droplet, closed loop with 192 connections, over four
runs:

| back end | full handshakes | resumed handshakes |
|---|---:|---:|
| epoll | 8.7k | 9.8k |
| io_uring | 8.9k–9.4k | 9.9k–10.6k |

CPU per request at 50k req/s: 25.47 µs with epoll, 25.26 µs with io_uring.

### Against nginx, h2o, hyper, haproxy and others (campaign 3, 2026-11-11)

Each row compares servers that ran on the same droplet. [The analysis](bench/results/2026-11-11-campaign3/analysis.md)
names the droplet for each figure.

| scenario | simoom | best other on the same droplet |
|---|---:|---:|
| TLS 1.3 full / resumed handshakes per second | **10,083 / 11,213** | h2o 7,711 / 7,758 (simoom +31% / +45%) |
| S1 over TLS, 256 connections (req/s at p99 ≤ 1 ms) | **160,441** | h2o 97,219 (simoom +65%) |
| HTTP/3 S1 (req/s at p99 ≤ 1 ms) | **106,947** | h2o 94,507 (simoom +13%) |
| CPU per request at 50k req/s | **25.05 µs** | hyper 28.10 µs (simoom 11% less) |
| 1 KB JSON echo (req/s at p99 ≤ 1 ms) | 153,526 | hyper 152,822 (tie) |
| HTTP/2 h2c, 100 streams (p99 ≤ 5 ms) | 152.5k | h2o 152.6k (tie at the NIC) |
| 1 MB responses, plain and TLS | 1.95 Gbit/s | nginx 1.95 Gbit/s (tie at the NIC) |
| peak PSS during S1 at 256 connections | **2.5 MB** | xitca 4.1 MB |
| memory per idle connection, 10k / 100k open | 594 / 533 B (default build 520 B at 100k) | nginx 522 / 532 B |
| 100 ms blocking handler, 500 clients | 4,925 req/s, 0 errors | Cameleer's previous HTTP server 4,925 |

Full tables: [summary.md](bench/results/2026-11-11-campaign3/summary.md) and
[compare.md](bench/results/2026-11-11-campaign3/compare.md).

### Start-up and memory against Cameleer's previous HTTP server

simoom replaces Cameleer's thread-per-connection HTTP server (`cameleer-http`). Both servers
return the same 13-byte reply. Start-up and idle memory were measured on the same machine (WSL2,
10 alternating rounds, 2026-11-11):

| build | cold start to first 2xx | idle PSS |
|---|---:|---:|
| simoom, plain | **0.73 ms** | 1,018 KB |
| cameleer-http, plain | 0.77 ms | 1,017 KB |
| simoom, TLS (P-256) | **0.87 ms** | 1,360 KB (after the K11 fix, 2026-11-12) |
| cameleer-http, TLS | 1.37 ms | 1,317 KB |

Under load (WSL2, server on 4 CPUs, 64 connections, closed loop, 2026-11-09):

| measure | simoom | cameleer-http |
|---|---:|---:|
| throughput | 293,000–311,000 req/s | 172,000–173,000 req/s |
| p99 latency | 0.32–0.44 ms | 0.87–0.91 ms |
| server CPU per request | about 13 µs | about 23 µs |
| memory with 1,000 idle connections | 2.7 MB | 7.7 MB |

### Where simoom is behind

Losses are part of the result:

- **Overload:** at 195k req/s offered, 1.17x the droplet's 165k NIC ceiling, simoom answers the
  most requests in total (160.3k). nginx answers fewer (145.5k), but 52.4k of them within 1 ms,
  against simoom's 6.4k.
  - nginx's figure comes from a worker pinned to the interrupt CPU, and it changed by 20x between
    droplets.
  - This is recorded as a limit of the benchmark at that rate ([BUGS.md](docs/BUGS.md) K13).
- **Degraded network paths:** on a droplet with a slow network path, may-minihttp kept 114.7k
  req/s while simoom and the other servers fell to 17–62k (campaign 3). The receive-interrupt fix
  (K12) has not been rerun on a degraded droplet.
- **A new connection per request:** on one droplet simoom handled 19.3k connections per second
  against xitca's 24.3k (−21%). On another droplet simoom was ahead: 22.1k against hyper's 19.3k.
- **Slow attackers:** with 10,000 slowloris and 1,000 slow-read attackers, simoom's p99 for
  legitimate requests was 8% above haproxy's on the same droplet (784 µs against 724 µs).
- **TLS idle memory:** 3.3% above Cameleer's previous server (1,360 KB against 1,317 KB).
- **Binary size:** the HTTP/1.1-only executable is 4% larger than may-minihttp's.

The raw results are in [`bench/results/`](bench/results). To rerun the benchmarks, use
[`bench/cloud/`](bench/cloud) and [`scripts/size.sh`](scripts/size.sh).

## Conformance, interop and security testing

Versions, commands and details are in [docs/SECURITY.md](docs/SECURITY.md).

| check | result |
|---|---|
| h2spec 2.6.0 | **146/146** in 30 consecutive runs |
| h2spec's server list, written from the RFCs, in `cargo test` | 120/120 h2c, 120/120 h2 |
| QUIC Interop Runner, server role, against the ngtcp2, quiche and quic-go clients | **54 of 58** supported pairs; the 4 failures are 0-RTT (refused by design) and ECN (not implemented) |
| HTTP Garden, as an origin next to nginx, Apache httpd, h2o, hyper, gunicorn and Go | **0 desyncs**, 0 dangerous discrepancies |
| Request-smuggling differential behind nginx 1.24 and haproxy 2.8 | 165 streams, **0 desyncs**; accepted **0** requests that both refused |
| testssl.sh 3.2.1 | no vulnerabilities found |
| TLS interop: OpenSSL `s_client`; curl with OpenSSL, Python `ssl` and gnutls-cli; curl with Schannel | 28/28, 31/31, 3/3 |
| nghttp and h2load | 14/14 |
| Fuzzing | std-only mutation fuzzing of every parser for 2 h 40 min, and coverage-guided fuzzing of HTTP/1.1 |
| Hermetic suite, `cargo test --workspace` | 777 passed on Windows, 791 on Linux (WSL2), zero warnings |

## Status and limits

- **Release:** version 0.1.0, before the first release. The API can still change.
- **QUIC gaps:** no 0-RTT, no ECN, and no migration to a preferred address.
- **Platforms tested:** the test suite runs on Windows and Linux. macOS (kqueue) and the ARM SIMD
  and crypto paths are compile-checked only.
- **Benchmark coverage:** every cloud figure above comes from 4-vCPU droplets with a single-queue
  NIC. Larger machines and multi-queue NICs have not been measured.
- **Security review:** there is no independent security audit yet. The testing above was done by
  the project itself.
- **Embedded only:** there is no static-file server, reverse proxy or configuration file.

The current state and the open items are in [docs/STATUS.md](docs/STATUS.md) and
[docs/BUGS.md](docs/BUGS.md).

## FAQ

### Is there a Rust HTTP/3 server without tokio or external crates?

Yes. simoom implements HTTP/3, QUIC v1, QPACK and TLS 1.3 itself, with only the standard library.
In the QUIC Interop Runner it passes 54 of 58 supported pairs against the ngtcp2, quiche and
quic-go clients.

### How does simoom compare with hyper?

On the same 4-vCPU droplet, simoom served 172,638 plaintext requests per second at p99 ≤ 1 ms with
256 connections, against hyper's 144,443. At a fixed 50k req/s it used 11% less CPU per request.
hyper is the more mature library and has a large ecosystem. simoom has no dependencies and adds
about 215 KB to a binary for HTTP/1.1.

### Do I need an async runtime?

No. A service is a function that runs on the loop thread and returns an `Outcome`. Blocking work
goes to the offload pool (`simoom::blocking`) or to your own threads (`Reply::defer`). Streams,
server-sent events and WebSockets work without `async`.

### Is simoom suitable for serverless functions and edge devices?

It is designed for them:

- the first response arrives 0.73 ms after the process spawns;
- an idle server uses about 1 MB of PSS;
- the HTTP/1.1-only build adds about 215 KB.

For the smallest build, turn off the default features and keep only `http1`.

### Can I use it as a reverse proxy or a static file server?

No. simoom is an engine you embed in a program. It does not ship a server that runs from a
configuration file.

### Which platforms does it run on?

Linux (epoll and io_uring), Windows (IOCP) and macOS (kqueue). The test suite runs on Windows and
Linux; macOS is compile-checked only. The cloud benchmarks ran on Linux.

### What does "std-only" mean here?

The workspace has no crates.io dependencies, including dev-dependencies. Operating-system calls go
through `extern` declarations in `simoom-sys`, and SIMD goes through `core::arch`. The only
exceptions are the competitor programs under `bench/competitors/`: separate projects that exist
only to be benchmarked against.

## Documentation

| | |
|---|---|
| [docs/STATUS.md](docs/STATUS.md) | current state and latest measurements |
| [docs/design/plan.md](docs/design/plan.md) | design, scope and budgets (section 0 is the owner's scope) |
| [docs/design/research.md](docs/design/research.md) | the research behind the design |
| [docs/SECURITY.md](docs/SECURITY.md) | security model, limits, test results, how to report a vulnerability |
| [docs/BUGS.md](docs/BUGS.md) | bugs found and fixed, open items |
| [docs/parity/](docs/parity) | parity with Cameleer's client, server extras and TLS |
| [bench/results/](bench/results) | benchmark campaigns: raw data and analyses |
| [llms.txt](llms.txt) | a summary for AI assistants |
| API docs | `cargo doc -p simoom --features full --open` |

## Contributing, security and licence

- **Contributing:** issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
  If you measured something differently and got a different number, open an issue with your
  method.
- **Security:** report vulnerabilities privately through
  [GitHub security advisories](https://github.com/Cameleering/simoom/security/advisories/new).
  Details are in [docs/SECURITY.md](docs/SECURITY.md).
- **Licence:** [Apache License 2.0](LICENSE).

simoom is a [Cameleering](https://cameleer.ing/cameleering/) project in the
[Cameleering](https://github.com/Cameleering) organization, alongside
[Cameleer](https://github.com/Cameleering/cameleer), which runs Apache Camel routes in Rust.
simoom is independent of the Apache Software Foundation. Apache and Apache Camel are trademarks
of the ASF.
