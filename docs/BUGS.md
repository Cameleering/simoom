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
- HTTP/2: priorities. (Extended CONNECT is done: C6, feature `websocket-h2`.)
- TLS: TLS 1.2 (`tls12` feature), kTLS, OCSP/CRL, P-384 as a key-exchange group.
- Facade: an access-log hook. (HTTP/2 PING keepalive is done: C7, feature `h2-keepalive`.)
- Platforms: macOS and kqueue are compile-checked only; the ARM SIMD and crypto paths have
  never run on ARM hardware.

## Cameleer adoption backlog (from Cameleer's integration study, 2026-11-09)

Source: `E:\Work\DataHQ\Code\Rust-camel\docs\design\simoom-integration\` (simoom-embedding-study.md,
duplicate-code-map.md, plan.md §3). Cameleer starts embedding simoom only after the second
campaign.

| # | item | when | status |
|---|---|---|---|
| U1 | Connection info on the request: peer and local address, listener index, TLS version, cipher, SNI, ALPN, verified client certificate chain | before release | fixed: `Request::local_addr`, `listener`, `tls()` → `TlsInfo` (version, cipher suite and name, SNI, ALPN, verified client chain as DER), also on `OwnedRequest`; HTTP/1.1, h2, h3; peer address now also on io_uring; tests `adoption_h1`, `adoption_h2`, `adoption_tls`, `adoption_h3` |
| U2 | Timeout for deferred replies, and cancellation (a signal to the `Responder` holder) when the client disconnects | before release | fixed: `Limits::defer_timeout` (504 and cancellation when it expires; off by default), `Responder::is_cancelled` and `on_cancel` (client close, reset, HTTP/1.1 half-close, timeout) on h1, h2 and h3; an HTTP/1.1 connection keeps reading up to 16 KiB while a reply is deferred so it sees the client leave |
| U3 | Benchmark the deferred path (`defer()` → foreign thread → `Responder::send`/`stream`, `BodySource`), plus a 100 ms blocking handler with 500 clients against cameleer-http | in the second campaign | in progress |
| U4 | A per-request completion hook (status, bytes in and out, duration, protocol) for access logs and metrics, with zero cost when unset | before release | fixed: `Builder::on_complete(Fn(&Completion))` (status, bytes in and out, duration, version, peer, listener, aborted), parser refusals and aborted requests included; without a hook one branch per request |
| U5 | Response trailers on HTTP/2 and HTTP/3 (gRPC `grpc-status`), and on chunked HTTP/1.1 | before release | fixed: `Reply::trailer`, `Response::trailer`, `BodySink::finish_with_trailers` on h2, h3 and chunked HTTP/1.1 (an immediate HTTP/1.1 reply with trailers goes chunked; HTTP/1.0 and HEAD drop them) |
| U6 | Certificate reload without a restart (swap the `ServerConfig` atomically for new connections) | before release | fixed: `ServerHandle::set_tls` and `set_quic_tls` swap the configuration for new connections (`RwLock<Arc<ServerConfig>>`, a provider that reads it per QUIC handshake) |
| U7 | macOS and arm64 actually run in CI | deferred by the owner (2026-11-09: "not yet") | deferred |
| U8 | API freeze and a 0.1 release | at release | open |
| U9 | Size headroom: the full build has 8.5 KB left, http1 + io-uring 4.8 KB; get at least 5% headroom on every row | before release | partly done (2026-11-09): simoom-quic's TLS client is now a feature (`client`, on by default; simoom turns it on only with `tls-client`) and simoom-quic and simoom-h3 depend on simoom-tls without its default features, so `http3` no longer links the TLS client, P-384, Ed25519 and ChaCha20: http3 826,008 → 750,736 B, full-server 1,021,256 → 956,224 (8.8% headroom). Rows still under 5% headroom on the shared tree (with the other agents' work in progress): http1,io-uring 255,696 (under budget by 304 B; needs 243,200), http1,http2,tls 573,624 and http1,http2,tls,io-uring 606,016 (need 583,680; simoom-tls work in progress adds about 12 KB to the TLS rows), full 1,072,088 (over the 1 MB budget by 23.5 KB: simoom-tls work about 12 KB, the U-items and h2/WebSocket work about 22 KB; it was 1,040,024). The U-items cost about 3.4 KB of symbols in http1,io-uring after trimming (rolled chunk-header writer, out-of-line completion reporting). Closing the rest needs a decision: budget `full` without `tls-client`/`tls-extra` (the server never links them), or cuts in simoom-sys/simoom-rt start-up code and in simoom-tls |
| U10 | Blocking integration routes: the offload-pool and watchdog defaults produce 503s at about 160 req/s on 8 CPUs with 100 ms handlers, and a route blocking ≥ 250 ms per call may never trip the watchdog. Fix the defaults or add an explicit blocking mode, and document it | before release | fixed: offload pool default 32 threads per CPU (64 to 512, on demand), CoDel target raised to the jobs' mean run time; the watchdog window counts time outside the stalls (a route blocking ≥ 250 ms per call now moves); "which path" table in the crate docs; tests: 64 clients × 100 ms calls, no 503; a 300 ms route moves |
| U11 | Missing test: a complete HTTP/2 response followed by RST_STREAM(NO_ERROR) must not be discarded by the client (RFC 9113 §8.1; Cameleer's `a_complete_response_survives_rst_stream_no_error`) | before release | fixed: `client_keeps_a_complete_response_followed_by_rst_stream_no_error` and `..._in_one_read` in simoom-h2 `tests/roundtrip.rs` |

Shared code: about 3,480 lines of simoom-tls and simoom-hpack are copies of Cameleer code (X.509,
ASN.1, PEM, keys, certgen, RSA, the HPACK Huffman table). Until they share one home, a fix to
those files must land in both repositories.

## Complete HTTP stack for Cameleer (owner, 2026-11-09: all in the first release)

Goal: Cameleer can delete `cameleer-http`'s server and client, `cameleer-grpc`'s HTTP/2, its
WebSocket code and (for HTTP) `cameleer-tls`, once simoom passes parity tests, verification and
benchmarks. Each item is a cargo feature.

| # | item | status |
|---|---|---|
| C1 | TLS 1.2, client and server: ECDHE with AES-GCM and ChaCha20-Poly1305, RSA and ECDSA certificates, extended master secret, session resumption, secure renegotiation refused; also used by Cameleer's non-HTTP protocols | done: simoom-tls feature `tls12` (`tls/tls12.rs`, `server12.rs`, `client12.rs`): the six ECDHE GCM/ChaCha suites Cameleer offers, X25519/P-256/P-384, RSA/ECDSA/Ed25519 certificates, EMS required, tickets and session IDs, renegotiation refused with a warning, downgrade sentinel and FALLBACK_SCSV, RFC 5705 exporter; 1.3 chosen when both sides support it, QUIC stays 1.3-only. Tests `tests/tls12.rs`, `fuzzing_tls12.rs`, interop `tests/interop12.rs` (openssl s_client/s_server `-tls1_2`, curl, Python `ssl`, Windows and WSL). Rows in `docs/parity/tls.md` |
| C2 | Keystores: PKCS#12 (PBES2 and the legacy PBE schemes), JKS and JCEKS, PEM bundles; a configuration type equivalent to Camel's `SSLContextParameters` | done: features `keystore`, `pkcs12`, `jks` (`pki/keystore/`, ported from Cameleer with its tests and keytool fixtures; PKCS#12 PBES2 and legacy PBE read/write, JKS and JCEKS read/write, PEM bundles and encrypted PKCS#8) and `params::SslContextParameters` (Cameleer's fields, builders and `camel.ssl.*` keys; `insecureSkipVerify`/`hostnameVerification=false` refused). Tests `tests/keystores.rs`, `fuzzing_keystore.rs`, `params` unit tests. JDK keytool not installed here: keytool fixtures come from Cameleer |
| C3 | Revocation: CRL checking, OCSP client checking, OCSP stapling on the server | done: feature `revocation` (`pki/revocation/`: CRLs, OCSP, `check_path`, fetch hook, `StapleSource`), wired into both versions: `ClientConfig::revocation` (staple validation for TLS 1.3 and 1.2, CRLs, online OCSP), `ServerConfig::ocsp_staple` and `client_revocation`. Tests `tests/revocation.rs`, `fuzzing_revocation.rs`, `tls_revocation.rs` (incl. `openssl s_client -status`, `s_server -status_file`) |
| C4 | The crypto these need: SHA-1 (certificates and OCSP), RSA-OAEP if any keystore or Cameleer use requires it | done: features `sha1` (SHA-1, `crypto::md` HMAC/PBKDF2/PKCS#12 KDF, SHA-1 certificate/CRL/OCSP signatures, never in a handshake) and `legacy` (`crypto/legacy/`: MD5, DES/3DES, RC2, bitsliced AES-CBC, for key stores only). RSA-OAEP not needed (only Cameleer's XML Encryption uses it) |
| C5 | HTTP client: HTTP/1.1, HTTP/2 and HTTP/3, connection pooling, TLS, HTTP CONNECT proxies, streaming bodies both ways, timeouts, response decompression, Cameleer `http`/`netty-http`/REST producer parity | done: crate `simoom-client` (features `client-h1`, `client-h2`, `client-h3`, `client-ws`, `tls`, `compress`, `rt`): blocking `Client` (pool per origin, h2/h3 multiplexed, a reader thread only while several streams are in flight), non-blocking `rt::RtClient` on simoom-rt loops, duplex `Client::call` for gRPC, CONNECT proxies, every timeout, redirects, Camel status semantics, gzip/deflate; every row of `docs/parity/client.md` has a test (hermetic, plus nginx and Python `http.server` interop with `SIMOOM_INTEROP=1`, and a fuzz harness). Not done: h2c `Upgrade`, TLS 1.2 (waits for C1), keystores (C2) |
| C6 | WebSocket client (RFC 6455), and WebSocket over HTTP/2 (RFC 8441) for server and client | server half done: simoom-h2 `connect-protocol` (setting, `:protocol`, `send_extended_connect` for the client role), facade feature `websocket-h2` (`Reply::websocket` on extended CONNECT streams, `WsCore` shared with HTTP/1.1); tests `simoom-h2/tests/extended.rs`, `simoom/tests/h2_websocket.rs`. Client half done: `Client::websocket` (RFC 6455 over HTTP/1.1, `ws`/`wss`, CONNECT proxies, subprotocols, masking, fragmentation, pings, close handshake) and `WsBuilder::http2(true)` (RFC 8441 over a shared HTTP/2 connection, h2c and h2); tests `simoom-client/tests/websocket.rs` |
| C7 | HTTP/2 PING keepalive (server and client) | server done: simoom-h2 `keepalive` (`Config::keepalive_interval_ms`/`keepalive_timeout_ms`, either role), facade feature `h2-keepalive` (`Limits::h2_keepalive`, `h2_keepalive_timeout`); tests `extended.rs`, `grpc.rs`. Client done: simoom-client `Config::keepalive_interval`/`keepalive_timeout` (PINGs on idle pooled connections, an unanswered PING closes the connection); tests `simoom-client/tests/http2.rs` `keepalive_pings_idle_connections`, `keepalive_closes_a_dead_connection`, and nginx interop |
| C8 | Content compression: gzip and deflate, encode and decode, `Accept-Encoding` negotiation, size thresholds; plus Brotli (RFC 7932) and zstd (RFC 8878), encode and decode, for users outside Cameleer (owner, 2026-11-09) | done (server and codec): crate `simoom-compress` (streaming `Decoder`/`Encoder`, one-shot `compress`/`decompress`, bomb limit, fuzzed; zlib's ratio, 13-27% smaller than Cameleer's at levels 6-9, decoding 2.3-4.7x and level-1 encoding 1.3-2.3x Cameleer's speed), facade feature `compression` (`Builder::compression`, `Request::decoded_body`). Brotli and zstd done too (features `brotli`, `zstd` in simoom-compress and the facade): full decoders checked against brotli 8.0.4 and libzstd 1.5.7 streams, encoders whose output those decode, window caps, fuzzed; `br`/`zstd` negotiated with q-values and a server preference (default zstd, br, gzip, deflate). Client-side decoding is C5 (API in `docs/parity/server-extras.md`) |
| C9 | gRPC parity: everything `cameleer-grpc` needs from HTTP/2, client and server (trailers, `grpc-timeout`, flow control) | server done: every need mapped and tested (`docs/parity/server-extras.md`, `simoom/tests/grpc.rs`: unary, server and client streaming, trailers-only, cancellation, per-message gzip, keepalive). Client role is C5 |
| C10 | Parity audit: a checklist of every feature of `cameleer-http`, `cameleer-tls` (HTTP use) and `cameleer-grpc` (HTTP/2) mapped to simoom, with a test for each row | open; rows for C6 (server), C7, C8 and C9 in `docs/parity/server-extras.md`; client rows (C5, C6 client, C7 client, C9 client: `cameleer-http` client and producer, `cameleer-grpc` h2 and gRPC clients, the WebSocket client) in `docs/parity/client.md`; TLS rows (`cameleer-tls`: C1-C4, C11) in `docs/parity/tls.md` |
| C11 | A blocking `Read`/`Write` TLS stream adapter, so Cameleer's non-HTTP protocols (SMTP, AMQP, ...) can move to simoom-tls later | done: feature `blocking` (`blocking::TlsStream`, `connect`/`client`/`accept`, timeouts, `lingering_close` after fatal alerts, `split` into reader and writer); tests in `blocking.rs` (both versions, full duplex, late reader gets the alert, retryable timeouts) |

| C12 | Shared crypto family **saltire** (owner decision D2, 2026-11-09): crates `saltire` (primitives, hardware paths in its own confined unsafe module) and `saltire-pki` (ASN.1, PEM, X.509, CRL, OCSP, PKCS#12, JKS/JCEKS), in its own repository `<family-org>/saltire`. After the second campaign: move simoom-tls's `crypto/` and PKI modules plus simoom-sys `arch.rs` crypto kernels and `os_random` there first, then Cameleer's breadth, then both products depend on it. Nothing published on crates.io before a working release | after campaign 2 |

Still out of scope: a static-file server and a reverse proxy.

## Independent-library completeness (owner, 2026-11-09)

Principle: simoom is for third parties too, so a feature that a good standalone HTTP library is
expected to have belongs in the first release even when Cameleer doesn't use it. Each is a cargo
feature.

| # | item | status |
|---|---|---|
| L1 | Client cookies: an RFC 6265 cookie jar (domain/path matching, Secure, HttpOnly, SameSite, expiry, public-suffix-safe defaults), opt-in per client | done (2026-11-09): `cookie::CookieJar`, feature `cookies`; docs/parity/client.md "Beyond Cameleer" |
| L2 | Client authentication: Digest (RFC 7616, SHA-256 and MD5), NTLMv2 (needs MD4 and HMAC-MD5 in the legacy crypto module), Bearer helpers; server-side Basic/Digest helpers | client side done (2026-11-09): `auth::Auth` with Basic, Bearer providers, Digest (`auth-digest`) and NTLMv2 (`auth-ntlm`), proxies included; server-side Basic/Digest helpers open |
| L3 | Client HTTP/1.1 pipelining (opt-in, idempotent requests only) | done (2026-11-09): `Client::pipeline` (idempotent methods, in-memory bodies, one origin; unanswered requests resent on a new connection); test `simoom-client/tests/http1.rs` `pipelining` |
| L4 | `RtClient` (event-loop client) at parity with the blocking client: HTTP/2, HTTP/3, proxies, redirects, streamed bodies, decompression | done (2026-11-09): on the loops: HTTP/1.1 plain and TLS, redirects, `gzip`/`deflate` decoding, HTTP proxies (absolute form) and `CONNECT`/SOCKS5 tunnels (set up on the connector thread); on the client's worker threads through the blocking engine: HTTP/2, HTTP/3, streamed request bodies (`send_request`), streamed responses (`send_streaming`); tests `simoom-client/tests/rt.rs` |
| L5 | Client connection quality: happy eyeballs (RFC 8305), DNS timeout, background eviction of idle sockets, h2c via `Upgrade`, SOCKS5 proxies, retries with backoff for idempotent requests | done (2026-11-09): `Config::happy_eyeballs_delay` (250 ms, families interleaved), `dns_timeout` (10 s, resolver on a helper thread), an evictor thread per pool (also for thread-cached connections), `h2c_upgrade`, `ProxyAddr::socks5` / `socks5://` / `socks5h://` (RFC 1928/1929), `retries` with exponential backoff, jitter and `Retry-After` (`retry_statuses`); tests in `simoom-client/tests/http1.rs`, `http2.rs` and `src/dns.rs` |
| L6 | Client request helpers: multipart/form-data and form-urlencoded builders, request-body compression | done (2026-11-09): `multipart::Multipart` (feature `multipart`), `RequestBuilder::form`, `RequestBuilder::compress` (gzip, deflate, br, zstd) |
| L7 | Server helpers commonly expected from an HTTP library: multipart/form-data parsing, cookies (parse and `Set-Cookie`), conditional requests and range requests for handler-provided content, CORS helper | done: facade features `multipart` (streaming `MultipartParser` with limits, `Request::multipart`), `cookies` (`Request::cookie`, `SetCookie`, `Reply::cookie`), `conditional` (`Request::preconditions`, `Request::ranges`, `Reply::content`: 304/412/206/multipart byteranges/416), `cors` (`Cors::wrap`, preflight); tests `simoom/tests/server_helpers.rs` and unit tests |
| L8 | WebSocket over HTTP/3 (RFC 9220), and permessage-deflate (RFC 7692) for WebSocket | done: simoom-h3 `enable_connect_protocol`, facade `websocket-h3`, simoom-client `WsBuilder::http3`; permessage-deflate codec in simoom-http1 `permessage-deflate` (shared), facade `ws-deflate` (HTTP/1.1, HTTP/2, HTTP/3), simoom-client `client-ws-deflate`; tests `simoom/tests/ws_deflate.rs`, simoom-client `tests/ws_deflate.rs`, `tests/ws_h3.rs` |

## Campaign 2 findings (2026-11-09, pinned 1e50579; `bench/results/2026-11-09-campaign2/`)

| # | item | status |
|---|---|---|
| K1 | **Bug:** the stall watchdog moves a route that returns `Outcome::Deferred` to the offload pool, so every deferred request is handed off twice (p99 86 ms vs 7 ms with `--no-watchdog`). Never count a deferred return as a stall | open |
| K2 | **Bug:** 1 MiB responses over TLS hold about 2.9 MiB per connection (PSS 188 MB under load with 64 connections, 46 MB afterwards; plain HTTP 3.1 MB) | open |
| K3 | Deferred path costs 49.6 µs CPU per request against 24.9 inline and cameleer-http-min's 34.0: an MPSC queue into the loop for `Responder::send`, no futex per reply, no extra syscalls (6.8 per request) | open |
| K4 | S1 at 256 connections is 14% behind may-minihttp: heavier tail (p99 just over 1 ms, spikes) at the NIC packet limit. Send responses as soon as ready, cap connections per turn, measure retransmits | open |
| K5 | Overload (S9): admission control; stop reading new requests on a loop when its pending responses pass a bound. Re-measure at the same absolute offered rate for every server | open |
| K6 | Slow attackers (S10) 21% behind haproxy: close half-requests only under budget pressure, plus a per-source reconnect limit | open |
| K7 | Idle memory 2.0 MB against cameleer-http-min's 1.1 MB (outside the 5% rule): lazy per-loop pools and timer wheel, no pre-touching the fd table, io_uring rings sized to need | open |
| K8 | Memory per idle connection 913/737 B at 10k/100k against nginx's 538/528 B, a regression since campaign 1 (677 B): move linger and partial-head state into a side slab used only when needed | open |
| K9 | Size: `min_server` 722 KB against may-minihttp's 515 KB; measure and cut the http1-only build | open |
| K10 | Offload pool at its old defaults shed almost every 100 ms request as 503 (fixed in U10 after the pinned commit; verify in the next run) | verify |
