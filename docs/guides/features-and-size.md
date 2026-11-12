# Which simoom features do I need, and how big is the build?

> Every protocol is a cargo feature: defaults give HTTP/1.1, HTTP/2 and WebSocket, `full` adds TLS and HTTP/3; HTTP/1.1 alone adds about 215 KB.

simoom only compiles what you ask for. Each build has a size budget, and the project's size script
(`scripts/size.sh`) fails when a build goes over it.

## Common choices

```toml
# the default: HTTP/1.1, HTTP/2 (h2c), WebSocket, io_uring, watchdog, guards
simoom = "0.1"

# everything: adds TLS 1.3, HTTP/3 over QUIC and the TLS client
simoom = { version = "0.1", features = ["full"] }

# the smallest: HTTP/1.1 only, for a device or a serverless function
simoom = { version = "0.1", default-features = false, features = ["http1"] }

# HTTPS without HTTP/3
simoom = { version = "0.1", features = ["tls"] }
```

## Every feature

| feature | adds |
|---|---|
| `http1` (default) | HTTP/1.1: keep-alive, pipelining, chunked bodies, `100-continue` |
| `http2` (default) | HTTP/2: h2c with prior knowledge, `Upgrade: h2c`, h2 over TLS |
| `websocket` (default), alias `ws` | WebSocket on HTTP/1.1 |
| `io-uring` (default) | the Linux io_uring back end; without it `Backend::IoUring` falls back to epoll |
| `watchdog` (default) | moves handlers that block the loop thread to the offload pool |
| `guard` (default) | overload and slow-client guards: backpressure admission, slow heads, per-IP reconnect rate |
| `idle-trim` (default) | an idle loop frees cached buffers and returns memory to the OS after bursts |
| `tls` | TLS 1.3 listeners: X25519, P-256, RSA, AES-GCM |
| `tls-extra` | P-384 and Ed25519 certificates, ChaCha20-Poly1305 |
| `http3` | HTTP/3 over QUIC (turns on `tls`) |
| `tls-client` | the TLS and QUIC client side (used by tests; a server doesn't need it) |
| `full` | `http1`, `http2`, `http3`, `tls`, `tls-extra`, `tls-client`, `websocket` and the default runtime features |
| `compression`, `brotli`, `zstd` | response compression and request body decoding |
| `websocket-h2`, `websocket-h3` | WebSocket over HTTP/2 and HTTP/3 |
| `ws-deflate` | WebSocket permessage-deflate |
| `h2-keepalive` | HTTP/2 PING keepalive |
| `multipart`, `cookies`, `conditional`, `cors`, `auth` | helpers for forms, cookies, caching and ranges, CORS, and Basic, Digest and Bearer auth |

`full` doesn't include the last six rows, which keeps it within its size budget. Add them by
name: `features = ["full", "compression", "websocket-h2"]`.

## What each build adds

Bytes added to the bundled `hello` example over an empty `fn main`, stripped, on x86-64 Linux
with the `dist` profile:

| build | size | budget |
|---|---:|---:|
| HTTP/1.1 only (`--no-default-features --features http1`) | 214,568 B | 256,000 B |
| HTTP/1.1, HTTP/2, TLS, io_uring | 583,680 B | 614,400 B |
| everything: HTTP/1.1, HTTP/2, HTTP/3, TLS, WebSocket, io_uring | 935,064 B | 1,048,576 B |

As a whole executable, the HTTP/1.1-only server is 536 KB stripped; about 181 KB of that is the
standard library's backtrace code. The measurement script is `scripts/size.sh` in the repository,
and the dates of each figure are in the [README](https://github.com/Cameleering/simoom#pay-only-for-what-you-use).

## Building small

For the smallest binary, combine the minimal features with a size-oriented release profile in
your own `Cargo.toml`:

```toml
[profile.release]
opt-level = "s"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

With `panic = "abort"`, a panic in a handler ends the process instead of becoming a `500`, so
choose it only where a restart is acceptable.

An edge build without `watchdog` or `guard` saves their code, and the related limits are then
ignored: a blocking handler stays inline, and slow request heads close at `head_timeout`.

## Cross-compiling

simoom has no C code and no build-time dependencies, so cross-compiling needs only the Rust
target (`rustup target add aarch64-unknown-linux-gnu`) and a linker for it. TLS needs nothing extra.
The ARM SIMD and crypto paths compile but have not been benchmarked yet.

## Common questions

### What is the smallest Rust HTTP server for AWS Lambda or other serverless platforms?

An HTTP/1.1-only simoom build adds about 215 KB, gives the first answer 0.73 ms after the process
starts, and idles at about 1 MB ([benchmarks](https://cameleer.ing/simoom/benchmarks/)). Use
`default-features = false, features = ["http1"]`.

### Does `full` include compression and WebSocket over HTTP/2?

No. `full` is every protocol plus TLS; compression, `websocket-h2`, `websocket-h3`, `ws-deflate`,
`h2-keepalive` and the helpers are added by name.

### Can I have HTTP/2 without HTTP/1.1?

Yes: `default-features = false, features = ["http2"]` serves h2c only, or add `tls` for h2 over
TLS. Most clients expect HTTP/1.1 as well, so this is for internal traffic.

### Does simoom work with `no_std`?

No. simoom is std-only, which is different: it uses the Rust standard library and nothing else, so
it needs an operating system (Linux, Windows or macOS).
