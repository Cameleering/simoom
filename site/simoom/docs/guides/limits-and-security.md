# What does simoom limit and refuse, and how do I change it?

> Every resource has a limit in `simoom::Limits` with a safe default; ambiguous requests are refused, and a panicking handler becomes a 500, not a crash.

simoom is built to face the internet directly. This page lists the limits you are most likely to
change, what the server refuses on its own, and how to see what happened. The full security
model, every default and the test results are in [SECURITY.md](../SECURITY.md).

## Changing limits

`Limits` is a plain struct. Change the fields you care about and keep the defaults for the rest:

```rust
use simoom::{Limits, Server};
use std::time::Duration;

fn build() -> simoom::Builder {
    Server::builder().listen("0.0.0.0:8080").limits(Limits {
        max_body: 1 << 20,                       // 1 MiB uploads, 413 beyond
        max_headers: 50,                         // 431 beyond
        head_timeout: Duration::from_secs(5),    // slowloris
        keep_alive_timeout: Duration::from_secs(30),
        max_connections_per_ip: 256,             // only when clients are not behind one NAT
        reconnect_rate: 50,                      // new connections per second per IP
        ..Limits::default()
    })
}
```

## The limits you'll most often touch

| field | default | when exceeded |
|---|---|---|
| `max_request_line` | 8 KiB | `414` |
| `max_head` / `max_headers` / `max_header_line` | 16 KiB / 100 / 8 KiB | `431` |
| `max_body` | 10 MiB, checked against `Content-Length` before any body byte is read | `413` |
| `body_buffer` | 64 KiB; larger bodies stream | — |
| `head_timeout` | 10 s for the whole request head (also the TLS handshake) | close |
| `keep_alive_timeout` | 15 s idle between requests | close |
| `min_body_rate` / `body_rate_grace` | 1 KiB/s after 5 s | close |
| `write_timeout` | 30 s without the client reading | close |
| `defer_timeout` | off | `504` for a deferred or offloaded reply |
| `max_connections` / `max_connections_per_loop` | about a million each | accepted and closed at once |
| `max_connections_per_ip` / `reconnect_rate` | off | accepted and closed at once |
| `max_concurrent_streams` | 100 per HTTP/2 or HTTP/3 connection | `REFUSED_STREAM` |
| `max_ws_message` | 1 MiB | WebSocket close 1009 |
| `offload_threads` / `offload_queue` | 32 per CPU (512 to 1024) / 4096 | `503` with `Retry-After` |

The per-IP limits are off by default because, behind a proxy or a NAT, every client shares one
address. Turn them on only when clients connect to simoom directly.

## What simoom refuses on its own

Parsing follows RFC 9110, 9112, 9113, 9114 and 9204 strictly. Requests whose framing could be
read two ways are refused, and the connection closes, so a proxy in front can't be tricked into
seeing different request boundaries (request smuggling). Among others:

- both `Transfer-Encoding` and `Content-Length`, duplicate or malformed `Content-Length`, any
  transfer coding other than a single final `chunked`;
- bare CR or LF line endings, folded headers, control bytes, whitespace before a colon;
- a request target with user information (`http://user@host/`).

`CONNECT` is answered by your service and then the connection closes: simoom is never a tunnel.
In tests behind nginx and haproxy, and in the HTTP Garden next to nginx, Apache httpd, h2o,
hyper, gunicorn and Go, simoom showed no desyncs ([SECURITY.md](../SECURITY.md)).

## Attacks it defends against

- **Slowloris** (heads sent byte by byte): `head_timeout`. A slow head holds no buffer, so while
  the server has connections to spare it stays open up to `slow_head_limit` (300 s), because
  closing it early only makes the attacker reconnect.
- **Slow POST and slow read**: `min_body_rate` and `write_timeout`.
- **HTTP/2 floods** (Rapid Reset, MadeYouReset, PING, SETTINGS and empty-frame floods): frame
  budgets per connection; going over one closes the connection with `ENHANCE_YOUR_CALM`.
- **Reconnect storms**: `reconnect_rate` per IP.
- **Overload**: the offload pool answers `503` early instead of queueing. Opt-in admission control
  (`shed_lag`, `max_pending_per_loop` with `pending_503`) can shed new requests when a loop falls
  behind.
- **QUIC**: Retry under handshake load, the 3x amplification limit, bounded buffers.

The `guard` feature (on by default) carries the overload and slow-client guards; an edge build
that leaves it out also ignores those limits.

## Panics

A panic in a service becomes a `500`, the connection closes, and the server keeps running. A
panic in a WebSocket callback closes that WebSocket with 1011. Both are counted in
`stats().panics`.

## Seeing what happened

`Builder::on_complete` is called once for every finished request, including requests the parser
refused, with the status, byte counts, duration, protocol and peer. It runs on the loop thread, so
keep it quick; send the record to a channel for real logging:

```rust
use simoom::{Completion, Server};

fn build() -> simoom::Builder {
    Server::builder()
        .listen("0.0.0.0:8080")
        .on_complete(|c: &Completion| {
            // runs on the loop thread: keep it quick (push to a channel for real logging)
            if c.status >= 500 {
                eprintln!("{:?} {} {} µs peer={:?}", c.version, c.status, c.duration.as_micros(), c.peer);
            }
        })
        .log(|line| eprintln!("simoom: {line}"))
}
```

`Builder::log` decides where simoom's own log lines (stall warnings) go; the default is standard
error. Counters for every limit are in `ServerHandle::stats()`:

```rust
use simoom::ServerHandle;

fn report(server: &ServerHandle) {
    let s = server.stats();
    println!(
        "open {} requests {} bad {} too large {} timeouts {} panics {} stalls {} 503s {}",
        s.active, s.requests, s.bad_requests, s.too_large, s.timeouts, s.panics, s.stalls, s.overloaded
    );
}
```

## Honest limits

- simoom 0.1.0 has **not had an independent security audit**. The testing listed in
  [SECURITY.md](../SECURITY.md) (h2spec, the QUIC Interop Runner, HTTP Garden, testssl.sh,
  fuzzing) was done by the project.
- simoom is an origin server. It is not a reverse proxy, a forward proxy or a static-file server,
  so the protections of those roles are not its job.

## Common questions

### Is simoom safe to put on the internet?

It was built for that: strict parsing, a limit on everything, flood and slow-client defences,
and panics contained. It has no outside audit yet, so weigh that for high-risk deployments; see
[SECURITY.md](../SECURITY.md).

### Does simoom use unsafe code?

Only in one crate, `simoom-sys`, which holds the operating-system calls, SIMD and crypto
intrinsics; each `unsafe` block there documents why it is sound. Every other crate is
`#![forbid(unsafe_code)]`. There are no third-party crates at all.

### How do I report a vulnerability?

Privately, through [GitHub security advisories](https://github.com/Cameleering/simoom/security/advisories/new),
as described in [SECURITY.md](../SECURITY.md).

### Can I turn off certificate verification in the client?

No. To trust a self-signed server, add its certificate to the client's root store
([The client](client.md)).
