# Open bugs and gaps (must be fixed before the next DigitalOcean campaign)

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
| 1 | QUIC | interop `multiplexing` fails against the quiche client | C | open |
| 2 | QUIC | interop `blackhole` fails against the quic-go client | C | open |
| 3 | QUIC | interop `handshakeloss` fails against the quic-go client | C | open |
| 4 | QUIC | interop `handshakecorruption` fails against the quic-go client | C | open |
| 5 | HTTP/1.1 | HTTP Garden: 53 stream discrepancies in 14,993 payloads, to triage; fix every one that can desync a front proxy | C | open |
| 6 | HTTP/2 | h2spec §3.5/2 (invalid preface) needs re-verifying at 146/146 | C | open |
| 7 | QUIC | the cap on out-of-order gaps is per stream, not per connection (many streams × gaps) | C | open |
| 8 | HTTP/2 | `Upgrade: h2c` passes an absolute-form target through unchanged; it should use the target's authority, as HTTP/1.1 now does | S | open |
| 9 | HTTP/2 | outgoing header blocks are not checked against the peer's `SETTINGS_MAX_HEADER_LIST_SIZE` | S | open |
| 10 | HTTP/2 | only the last 16 reset or closed stream ids are remembered, so a late frame on an older stream gets a connection error instead of being ignored | S | open |
| 11 | runtime | timers of a closed connection stay in the wheel until they fire | S | open |
| 12 | facade | each loop's QUIC endpoint (`H3Ep`) is built eagerly: cold start and base memory | S | open |
| 13 | TLS | the server certificate is parsed twice (`ServerConfig::new` → `names()`), and `simoom-server` builds two configs | S | open |
| 14 | facade | request trailers are ignored on every protocol; they should reach the service | S | open |
| 15 | facade | HTTP/2 frame budgets (RST/PING/SETTINGS/...) cannot be configured through `Limits` | S | open |
| 16 | facade | admission control (`shed_lag`) is off by default and unvalidated; decide a safe default from measurement | S | open |
| 17 | facade | slowloris: idle half-requests still hold a buffer; hold partial heads without one | S | open |
| 18 | docs | `SECURITY.md` and `plan.md` list the old watchdog defaults; `stall_window`, `stall_recovery` and `shed_lag` are missing | S | open |

## Known gaps (features not built; not bugs, listed so nothing is forgotten)

- QUIC: ECN, 0-RTT (refused on purpose for replay safety), CUBIC congestion control, active
  client migration, the `preferred_address` transport parameter, DATAGRAM frames.
- HTTP/2: extended CONNECT (RFC 8441, WebSocket over HTTP/2); priorities.
- TLS: TLS 1.2 (`tls12` feature), kTLS, OCSP/CRL, P-384 as a key-exchange group.
- Facade: an access-log hook; HTTP/2 PING keepalive.
- Platforms: macOS and kqueue are compile-checked only; the ARM SIMD and crypto paths have
  never run on ARM hardware.
