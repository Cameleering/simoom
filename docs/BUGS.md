# Bugs and gaps found before the second DigitalOcean campaign

**All 22 items are closed (2026-11-09).**

_2026-11-09._ Gathered from:
- the campaign analysis (`bench/results/2026-11-07-campaign/analysis.md`);
- the security pass (`docs/SECURITY.md`);
- the QUIC Interop Runner and HTTP Garden runs;
- the agents' "not done" lists.

Each item gets a regression test when it is fixed. Owner key: **C** is the conformance agent,
**S** is the bug-sweep agent.

## Bugs

| # | area | bug | owner | status |
|---|---|---|---|---|
| 1 | QUIC | interop `multiplexing` fails against the quiche client | C | fixed (a266da1): client open-file limit in the runner; passes 3/3 |
| 2 | QUIC | interop `blackhole` fails against the quic-go client | C | fixed (a266da1): blackout send-buffer stall |
| 3 | QUIC | interop `handshakeloss` fails against the quic-go client | C | fixed (a266da1): handshake flight resend |
| 4 | QUIC | interop `handshakecorruption` fails against the quic-go client | C | fixed (a266da1): handshake flight resend |
| 5 | HTTP/1.1 | HTTP Garden: 53 stream discrepancies in 14,993 payloads, to triage; fix every one that can desync a front proxy | C | done: 0 desyncs in 709 forwarded fuzz streams and 39 curated vectors; all discrepancies benign (simoom stricter) |
| 6 | HTTP/2 | h2spec §3.5/2 (invalid preface) needs re-verifying at 146/146 | C | fixed: 146/146 ×30 (h2 GOAWAY change lands with the bug-sweep commit) |
| 7 | QUIC | the cap on out-of-order gaps is per stream, not per connection (many streams × gaps) | C | fixed (a266da1) |
| 8 | HTTP/2 | `Upgrade: h2c` passes an absolute-form target through unchanged; it should use the target's authority, as HTTP/1.1 now does | S | fixed: authority and :path from the target |
| 9 | HTTP/2 | outgoing header blocks are not checked against the peer's `SETTINGS_MAX_HEADER_LIST_SIZE` | S | fixed: Error::HeaderListTooLarge, 500 in the facade |
| 10 | HTTP/2 | only the last 16 reset or closed stream ids are remembered, so a late frame on an older stream gets a connection error instead of being ignored | S | fixed: forgotten ids at or below the highest seen are treated as reset |
| 11 | runtime | timers of a closed connection stay in the wheel until they fire | S | fixed: timers cancelled on close |
| 12 | facade | each loop's QUIC endpoint (`H3Ep`) is built eagerly: cold start and base memory | S | fixed: LazyEp built on first datagram |
| 13 | TLS | the server certificate is parsed twice (`ServerConfig::new` → `names()`), and `simoom-server` builds two configs | S | fixed: leaf parsed once, ServerConfig Clone |
| 14 | facade | request trailers are ignored on every protocol; they should reach the service | S | fixed: Request/BodySource trailers on h1, h2, h3 |
| 15 | facade | HTTP/2 frame budgets (RST/PING/SETTINGS/...) cannot be configured through `Limits` | S | fixed: Limits::h2_frame_budgets |
| 16 | facade | admission control (`shed_lag`) is off by default and unvalidated; decide a safe default from measurement | S | decided: kept None; every tested value shed falsely at normal load and none helped overload (measurements in limits.rs docs) |
| 17 | facade | slowloris: idle half-requests still hold a buffer; hold partial heads without one | S | fixed: partial heads up to 512 B copied out, buffer returned |
| 19 | cold start | the full server with TLS and HTTP/3 measured 27–30 ms and 5.3 MB to its first response, against 2.5 ms without TLS. It must not slow Cameleer's start-up (Cameleer's HTTP route is ready in about 1–8 ms depending on build and OS). **Owner requirement (2026-11-09): start-up time and memory must be within 5% of Cameleer's current HTTP server (`cameleer-http`, plain and with `cameleer-tls`), measured the same way; anything above 5% needs a specific, measured advantage in real use cases.** Target: TLS + HTTP/3 ready in ≤ 3 ms and ≤ 3 MB; find out where the time goes (PEM/key parsing, `ServerConfig` set-up, ticket keys, P-256 comb table or other tables built on first use, the first handshake, QUIC endpoints) and fix it | S | fixed: 26.9 → 2.4 ms with TLS + HTTP/3 (fd-table growth during start); within 5% of cameleer-http on start-up; TLS memory +8–9% documented with measured advantage in STATUS.md |
| 20 | runtime | no lingering close: when simoom closes with unread input, the peer can get a TCP reset instead of the last response | S | fixed: lingering close (Config::linger) |
| 21 | QUIC | after switching a connection to v2, the client's retransmitted v1 Initial packets are dropped | C | fixed: v1 Initial keys kept until Initial keys are discarded; ngtcp2 v2 3/3 |
| 22 | size | size gate fails after the fixes: http1 271,488 B (budget 256,000), http1+http2+tls+io-uring 646,776 (614,400), full 1,077,616 (1,048,576) | size | fixed: every size.sh row under budget (http1 218,264; full 1,040,024); new features simoom/watchdog and simoom-sys/udp; throughput unchanged |
| 18 | docs | `SECURITY.md` and `plan.md` list the old watchdog defaults; `stall_window`, `stall_recovery` and `shed_lag` are missing | S | fixed: SECURITY.md and plan.md updated |

## Known gaps (features not built; not bugs, listed so nothing is forgotten)

- QUIC: ECN, 0-RTT (refused on purpose for replay safety), CUBIC congestion control, active
  client migration, the `preferred_address` transport parameter, DATAGRAM frames.
- HTTP/2: extended CONNECT (RFC 8441, WebSocket over HTTP/2); priorities.
- TLS: TLS 1.2 (`tls12` feature), kTLS, OCSP/CRL, P-384 as a key-exchange group.
- Facade: an access-log hook; HTTP/2 PING keepalive.
- Platforms: macOS and kqueue are compile-checked only; the ARM SIMD and crypto paths have
  never run on ARM hardware.

## Cameleer adoption backlog (from Cameleer's integration study, 2026-11-09)

Source: `E:\Work\DataHQ\Code\Rust-camel\docs\design\simoom-integration\` (simoom-embedding-study.md,
duplicate-code-map.md, plan.md §3). Cameleer starts embedding simoom only after the second
campaign.

| # | item | when | status |
|---|---|---|---|
| U1 | Connection info on the request: peer and local address, listener index, TLS version, cipher, SNI, ALPN, verified client certificate chain | before release | open |
| U2 | Timeout for deferred replies, and cancellation (a signal to the `Responder` holder) when the client disconnects | before release | open |
| U3 | Benchmark the deferred path (`defer()` → foreign thread → `Responder::send`/`stream`, `BodySource`), plus a 100 ms blocking handler with 500 clients against cameleer-http | in the second campaign | in progress |
| U4 | A per-request completion hook (status, bytes in and out, duration, protocol) for access logs and metrics, with zero cost when unset | before release | open |
| U5 | Response trailers on HTTP/2 and HTTP/3 (gRPC `grpc-status`), and on chunked HTTP/1.1 | before release | open |
| U6 | Certificate reload without a restart (swap the `ServerConfig` atomically for new connections) | before release | open |
| U7 | macOS and arm64 actually run in CI | owner decision (CI minutes on a private repository) | open |
| U8 | API freeze and a 0.1 release | at release | open |
| U9 | Size headroom: the full build has 8.5 KB left, http1 + io-uring 4.8 KB; get at least 5% headroom on every row | before release | open |
| U10 | Blocking integration routes: the offload-pool and watchdog defaults produce 503s at about 160 req/s on 8 CPUs with 100 ms handlers, and a route blocking ≥ 250 ms per call may never trip the watchdog. Fix the defaults or add an explicit blocking mode, and document it | before release | open |
| U11 | Missing test: a complete HTTP/2 response followed by RST_STREAM(NO_ERROR) must not be discarded by the client (RFC 9113 §8.1; Cameleer's `a_complete_response_survives_rst_stream_no_error`) | before release | open |

Not planned for the first release (owner decision pending): TLS 1.2, PKCS#12/JKS keystores
(Cameleer can bridge to `CertifiedKey::from_der`), CRL/OCSP, RSA-OAEP, SHA-1, WebSocket over
HTTP/2, HTTP/2 PING keepalive, compression.

Shared code: about 3,480 lines of simoom-tls and simoom-hpack are copies of Cameleer code (X.509,
ASN.1, PEM, keys, certgen, RSA, the HPACK Huffman table). Until they share one home, a fix to
those files must land in both repositories.
