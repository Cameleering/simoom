# simoom FAQ

> Short answers about simoom: no async runtime, zero dependencies, HTTP/3 without quinn, small builds, what it doesn't do, and how ready it is.

## Common questions

### Is there a Rust HTTP server without tokio?

Yes. simoom has no async runtime at all. It runs its own event loop per CPU core on epoll,
io_uring, IOCP or kqueue, and a service is a plain function. Slow work goes to a bounded offload
pool (`simoom::blocking`) or to your own threads (`Reply::defer`). Streaming, server-sent events
and WebSocket all work without `async`. See [Slow work](slow-work.md).

### Is there a Rust web server with zero dependencies?

Yes. simoom's crates have no crates.io dependencies, not even for tests. Calls into the operating
system go through `extern` declarations in one crate, `simoom-sys`, and SIMD goes through
`core::arch`. TLS, QUIC, HTTP/2, HTTP/3 and the compression codecs are all written in the
repository.

### Is simoom std-only or no_std?

std-only. It uses the Rust standard library and nothing else, so it needs an operating system:
Linux, Windows or macOS. It doesn't run on bare-metal microcontrollers without an OS.

### Can I serve HTTP/3 from Rust without quinn, rustls or OpenSSL?

Yes. simoom implements QUIC v1, HTTP/3, QPACK and TLS 1.3 itself, and HTTP/3 is a cargo feature
of the same server that serves HTTP/1.1 and HTTP/2. It passes 54 of 58 supported pairs in the QUIC
Interop Runner; the four failures are 0-RTT (refused by design) and ECN (not implemented). See
[HTTP/2 and HTTP/3](http2-and-http3.md).

### What is the smallest Rust HTTP server for AWS Lambda or serverless?

An HTTP/1.1-only simoom build adds about 215 KB to the binary, gives the first answer 0.73 ms after
the process starts and idles at about 1 MB. Build with `default-features = false, features =
["http1"]`. See [Features and size](features-and-size.md).

### How do I embed an HTTP server in a Rust app?

Add `simoom`, build a server with `Server::builder()`, give it a service or a `Router`, and call
`start()`. It runs on its own threads and returns a handle you can `stop()` and `join()`, so the
rest of your program carries on. See [Getting started](getting-started.md).

### Can I run a WebSocket server in a Rust CLI or desktop app?

Yes. Start the server on `127.0.0.1:0`, print or open the chosen port, and push updates with a
`WebSocketHandler` or server-sent events. The server starts in about a millisecond and adds no
async runtime to your program. See [WebSocket](websocket.md).

### Does simoom run on a Raspberry Pi or other ARM boards?

It is built for small devices, and the ARM SIMD and crypto code paths compile. They are
compile-checked only so far: the test suite runs on Windows and Linux on x86-64, and the
benchmarks ran on x86-64. Reports from ARM hardware are welcome.

### How does simoom compare with hyper?

On the same 4-vCPU cloud machine, simoom served more plain HTTP requests per second with p99 under
1 ms and used less CPU per request than hyper; the numbers and the method are on the
[benchmarks page](https://cameleer.ing/simoom/benchmarks/). hyper is far more mature, has years of
production use and a large ecosystem (axum is built on it). simoom has no dependencies, a smaller
footprint, its own TLS and HTTP/3. Choose by what matters more to you.

### Should I use simoom or axum?

axum gives you extractors, middleware and a large ecosystem on top of tokio. simoom gives you a
small synchronous API, a router and optional helpers, with no runtime and no dependencies. If you
want the ecosystem, use axum; if size, start-up, dependencies or HTTP/3 matter more, try simoom.

### Can simoom serve static files or act as a reverse proxy?

No. simoom is an engine you build into a program; it has no static-file server, no reverse proxy
and no configuration file. Use nginx, Caddy or h2o for those jobs. You can still send a file from
a handler yourself ([Streaming](streaming-and-sse.md)).

### Is simoom production ready?

It is version 0.1.0, the first release, and the API can still change. It has been tested hard:
h2spec 146/146, the QUIC Interop Runner, HTTP Garden with no desyncs, testssl.sh, fuzzing of every
parser, and a test suite of several hundred tests on Windows and Linux. It has not had an
independent security audit, macOS and ARM are compile-checked only, and the benchmarks ran on
4-vCPU machines. It is the HTTP server of [Cameleer](https://github.com/Cameleering/cameleer).
Decide with those facts; [SECURITY.md](../SECURITY.md) has the details.

### Which platforms does simoom support?

Linux (epoll and io_uring), Windows (IOCP) and macOS (kqueue). The test suite runs on Windows and
Linux; macOS is compile-checked only. Rust 1.89 or newer.

### Does simoom support async handlers?

No, on purpose. A handler that needs to wait takes a `Responder` with `reply.defer()` and answers
from any thread, which also works with a tokio task if your program has one. See
[Slow work](slow-work.md).

### Does simoom have an HTTP client?

Yes, the separate `simoom-client` crate: HTTP/1.1, HTTP/2, HTTP/3 and WebSocket, blocking, with
pooling, TLS and redirects. See [The client](client.md).

### Does simoom support TLS 1.2?

Not on simoom servers: they speak TLS 1.3 only. The `simoom-tls` crate has TLS 1.2 behind a
feature for other uses. See [TLS](tls.md).

### Why is it called simoom?

A simoom is a hot, fast wind that crosses the desert. It belongs to the same caravan as Cameleer
and the Cameleering projects.

### What licence is simoom under?

Apache License 2.0.
