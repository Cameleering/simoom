# simoom documentation

> simoom is an HTTP server you build into a Rust program; these guides show how to write services, add TLS, HTTP/2 and HTTP/3, and keep the build small.

simoom serves HTTP/1.1, HTTP/2 and HTTP/3, does its own TLS 1.3, and runs one event loop per CPU
core on epoll, io_uring, IOCP or kqueue. It uses nothing outside the Rust standard library and
needs no async runtime. If you have used a Rust web framework before, the main difference is
this: a service is a plain function that runs on the loop thread, so it answers fast work at
once and hands slow work to a pool or to your own threads.

## Where to find what

Read the guides in this order the first time; after that, jump to the one you need.

| you want to | go to |
|---|---|
| install simoom, run a first server and learn what a service is | [Getting started](guides/getting-started.md) |
| read requests and build responses | [Services and replies](guides/services-and-replies.md) |
| send requests to handlers by method and path | [Routing](guides/routing.md) |
| call a database or another service without blocking the server | [Slow work](guides/slow-work.md) |
| stream request and response bodies, push server-sent events | [Streaming and SSE](guides/streaming-and-sse.md) |
| accept WebSocket connections | [WebSocket](guides/websocket.md) |
| serve HTTPS with your certificates, mutual TLS, certificate rotation | [TLS](guides/tls.md) |
| turn on HTTP/2 and HTTP/3 and tune them | [HTTP/2 and HTTP/3](guides/http2-and-http3.md) |
| set limits, see what is refused, log requests | [Limits and security](guides/limits-and-security.md) |
| choose threads and the I/O back end, stop gracefully, read counters | [Runtime](guides/runtime.md) |
| make HTTP and WebSocket requests from Rust | [The client](guides/client.md) |
| pick cargo features and see what each adds to the binary | [Features and size](guides/features-and-size.md) |
| drive the HTTP/1.1, HTTP/2, QUIC or TLS crates from your own I/O loop | [Sans-io crates](guides/sans-io-crates.md) |
| give a coding agent the rules it needs to write simoom code | [For coding agents](guides/coding-agents.md) |
| find quick answers to common questions | [FAQ](guides/faq.md) |

The security model, every limit with its default, and the test results are in
[SECURITY.md](SECURITY.md). Measured numbers and how they were taken are on the
[benchmarks page](https://cameleer.ing/simoom/benchmarks/). The API reference is on
[docs.rs/simoom](https://docs.rs/simoom).

## How the pages are organized

Every guide starts with a short answer under its title, then shows code you can copy. Every Rust
example was compiled against simoom 0.1.0 with `--features full`; examples that need another
feature say so. Each guide ends with common questions.

## Common questions

### Which version do these docs describe?

simoom 0.1.0, the first release. The API can still change before 1.0; breaking changes will be
listed in the release notes.

### Is there a version of these docs for coding assistants?

Yes. The site publishes `llms.txt` (a summary with links) and `llms-full.txt` (every page as plain
markdown), and every HTML page has its markdown source next to it. The
[coding agents guide](guides/coding-agents.md) lists the rules an assistant most often gets wrong.

### Where do I report a mistake in the docs?

Open an issue or a pull request on [GitHub](https://github.com/Cameleering/simoom). Security
problems go through a private advisory, as described in [SECURITY.md](SECURITY.md).
