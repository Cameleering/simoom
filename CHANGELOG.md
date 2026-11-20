# Changelog

All twelve library crates share one version. Releases are git tags (`vX.Y.Z`) and crates.io
versions.

## 0.2.0 (2026-11-20)

HTTP/2 in `simoom-client` runs on event loops, and a request proxied from a server handler stays
on that handler's loop. Design and measurements: [docs/design/rt-h2-client.md](docs/design/rt-h2-client.md).

### Breaking

- `simoom_client::Config` has a new public field `h2_loops` (feature `client-h2`), and
  `simoom_client::rt::RtConfig` has two, `h2` and `h2_connections`. Code that builds either struct
  with every field listed and no `..Default::default()` must add them; code that uses
  `..Default::default()` or the builders compiles unchanged. This is why the version is 0.2.0 and
  not 0.1.1.
- With default features the client is larger: 1,099,128 → 1,425,288 bytes (stripped, x86-64
  Linux, `scripts/size-client.sh`), because `client-h2` now brings in `simoom-rt`. A build with
  `default-features = false, features = ["client-h1", "client-h2-engine", "tls", ...]` stays at
  the old size (1,099,560 bytes with ws and compress).

### Added

- **HTTP/2 on the loops in `RtClient`** (`version: Http2`): a connection lives on a loop, requests
  are queued to it from any thread, and each response is completed by callback on the loop that
  read it. `RtClient::call` (`CallHandler`, `CallOptions`, `RtCall`) gives streamed request and
  response bodies and full-duplex calls with trailers both ways. Stream limits, flow control in
  both directions, GOAWAY with retry, RST_STREAM and cancellation, deadlines, TLS with ALPN
  (certificate verification cannot be turned off) and h2c prior knowledge all work as in the
  blocking client. `RtClient::h2_connections_on`, `idle_on_loop`.
- **Proxying on the server's own loop:** `LoopHandle::current`, `LoopHandle::is_current` and
  `PartialEq`/`Eq` for `LoopHandle` (simoom-rt); `ServerHandle::loops` and a re-export of
  `LoopHandle` (simoom); `RtClient::send` called on a loop thread dispatches there without a
  hand-off. What a loop queues for itself is delivered in the same turn.
- **`client-h2-engine`**: HTTP/2 driven by the requesting threads, without simoom-rt, for small
  builds. `client-h2` and `client-h2-engine` sit on an internal `h2` feature; with both enabled the
  loops are used.
- `Client::call_with_body` sends a call's head, first bytes and end of stream in one write;
  `ClientBuilder::h2_loops`.

### Changed

- **The blocking `Client`'s HTTP/2 connections run on event loops.** The connection is still
  opened on the calling thread (resolution, Happy Eyeballs, proxies, TLS with ALPN), then handed to
  a loop; a waiter is woken once per response. HTTP/3 and HTTP/2 after an h2c `Upgrade` stay on
  the engine. Measured in WSL2 with 64 requests in flight: one connection 89k → 94k requests/s and
  34.8 → 22.4 µs of CPU per request; four connections 161k–203k → 236k–243k requests/s.
- simoom-client: a request body in memory leaves with the HTTP/2 head in one write; a waiting
  thread is woken once per batch of news for its stream, after the connection lock is released.
- simoom-rt: with few connections per loop, a connection goes to the least loaded loop instead of
  wherever the `SO_REUSEPORT` hash put it; the early flush writes a connection's output after its
  last message of a batch, so replies of HTTP/2 streams finished on other threads leave in one
  write.

### Fixed

- simoom-h3 client: `STOP_SENDING` after the request was fully sent no longer discards the
  response, whatever its code (RFC 9114 4.1.1; h3 over quinn stops every request stream it drops
  unread).

### Docs

- README rewritten, `llms.txt`, `context7.json`, the cameleer.ing/simoom microsite and the
  benchmark campaign 4 results (these came after the 0.1.0 tag and reach crates.io with this
  release).

## 0.1.0 (2026-11-12)

First release: the twelve library crates on crates.io.
