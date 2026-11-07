# Security

This page covers simoom's security model, its limits and defaults, what was tested and with
what results, the known gaps, and how to report a vulnerability.

_Last hardening pass: 2026-11-07, against head `33ee716` plus the fixes listed below._

## Reporting a vulnerability

Please report vulnerabilities privately through **GitHub security advisories**:
<https://github.com/pmsudhi/simoom/security/advisories/new>. Don't open a public issue,
pull request or discussion for a suspected vulnerability.

- Include the version or commit, the feature set (`http1`, `http2`, `tls`, `http3`...), the
  operating system and back end, and a reproducer: bytes on the wire are ideal.
- We aim to acknowledge a report within 3 working days and to agree a fix and disclosure date
  with you within 14 days. The default embargo is 90 days or the release of a fix, whichever
  comes first.
- Fixes ship as a patch release with a GitHub advisory (and a RustSec advisory once the crates
  are on crates.io). Reporters are credited unless they ask not to be.
- Hardening ideas that aren't vulnerabilities (a stricter default, a new limit) are welcome as
  normal issues.

## Security model

simoom is an embeddable HTTP/1.1, HTTP/2 and HTTP/3 **origin server** engine. It isn't a
reverse proxy, a forward proxy, a tunnel or a static-file server. The service (the embedding
application) is trusted. Everything that arrives from the network is untrusted, including the
bytes forwarded by a front proxy.

What simoom guarantees to the service:

- **Memory safety.** Every crate except `simoom-sys` is `#![forbid(unsafe_code)]`. `simoom-sys`
  holds the operating-system calls, SIMD scanning and crypto intrinsics, and every `unsafe`
  block there has a `SAFETY:` comment. There are no external crates, so there is no third-party
  code in the dependency tree.
- **Strict parsing** per RFC 9110, 9112, 9113, 7541, 9114 and 9204. Any message whose framing
  is ambiguous is refused, and the connection is closed after a framing error, so request
  boundaries can't be shifted (no request smuggling).
- **Bounded resources.** Every per-connection and per-stream structure has a limit, and
  exceeding it gives a specific status code or a connection close plus a counter in
  `ServerHandle::stats()`.
- **Constant-time crypto.** TLS 1.3 only, with hardware AES-GCM or a bitsliced fallback, and
  `ct_eq` for every secret comparison. Certificate verification can't be turned off, and 0-RTT
  is off.

### HTTP/1.1 framing decisions

- A request with both `Transfer-Encoding` and `Content-Length` is refused (400), as is any
  `Transfer-Encoding` other than a single final `chunked`. So are duplicate or differing
  `Content-Length` values and a `Content-Length` with a sign, a list, spaces or hex.
- Bare CR, bare LF line endings, obs-fold, NUL and other control bytes, whitespace before a
  colon, and invalid chunk sizes are refused. Chunk extensions are parsed to the grammar,
  including BWS before `;`.
- `Expect: 100-continue` follows RFC 9110 §10.1.1, and any other expectation gets 417. An
  `Upgrade: h2c` that carries a body is ignored (served as HTTP/1.1).
- **CONNECT** is answered by the service, and then the connection is closed. simoom is not a
  tunnel, and a front proxy that sees a 2xx switches to tunnelling, so nothing after a CONNECT
  head is ever parsed as another request (fixed in this pass).
- **Absolute-form targets** (`GET http://host/path`): the authority comes from the target and
  `Host` is ignored (RFC 9112 §3.2.2). `Request::host()` returns the target's authority and
  `Request::target()`/`path()` return the path and query. A target with userinfo
  (`http://user@host/`) is refused (RFC 9110 §4.2.4). Both were fixed in this pass.
- For internal traffic, the recommended upstream protocol is HTTP/2 (h2c with prior knowledge),
  which avoids HTTP/1.1 framing ambiguity altogether.

## Limits and defaults

Every limit is a field of `simoom::Limits` (plan §7.1), and `crates/simoom/tests/limits.rs`
checks the defaults.

| limit | default | when exceeded |
|---|---|---|
| `max_request_line` | 8 KiB | 414 |
| `max_head` | 16 KiB | 431 |
| `max_headers` | 100 | 431 |
| `max_header_line` | 8 KiB | 431 |
| `max_body` | 10 MiB (checked against `Content-Length` before any body byte is read) | 413 |
| `body_buffer` | 64 KiB (larger bodies stream with backpressure) | — |
| `head_timeout` | 10 s for the whole head (slowloris); also the TLS handshake deadline | close |
| `keep_alive_timeout` | 15 s | close |
| `min_body_rate` / `body_rate_grace` | 1 KiB/s after 5 s (slow POST) | close |
| `write_timeout` | 30 s without write progress (slow read) | close |
| `max_requests_per_connection` | unlimited | `connection: close` |
| `max_connections` / `max_connections_per_loop` | 1 Mi / 1 Mi | accept and close, `rejected` |
| `max_connections_per_ip` | off (0); new in this pass | accept and close, `rejected` |
| `max_concurrent_streams` (HTTP/2, HTTP/3) | 100 streams with handler work running | REFUSED_STREAM |
| `max_header_list` (HTTP/2, HTTP/3) | 16 KiB, CONTINUATION included | 431; an encoded block over twice the limit gives GOAWAY |
| `header_table_size` (HPACK, QPACK) | 4096 | COMPRESSION_ERROR |
| `stream_buffer` | 64 KiB of streamed response output pending | writers wait (`WouldBlock`) |
| `max_ws_message` | 1 MiB | close 1009 |
| `inline_budget` / `stalls_before_offload` | 1 ms / 3 | handler moves to the offload pool |
| `offload_queue` | 4096 jobs (CoDel 5 ms / 100 ms) | 503 |

HTTP/2 frame budgets (`simoom_h2::Budgets`, per 10 s sliding window per connection; GOAWAY
ENHANCE_YOUR_CALM beyond them):

- RST_STREAM received 200 and caused 200 (Rapid Reset, MadeYouReset);
- PING 100;
- SETTINGS 100;
- empty frames 200;
- PRIORITY;
- WINDOW_UPDATE frames under 1 KiB;
- at most `max_continuation_frames` CONTINUATION frames per block.

These budgets aren't exposed through `Limits` yet (see the gaps).

TLS: TLS 1.3 only. Groups X25519 and P-256. Suites AES-128-GCM, AES-256-GCM and
ChaCha20-Poly1305. More than 32 records in a row that carry no application data (empty
records, warning alerts, KeyUpdates) is fatal. Rejected 0-RTT data is skipped only up to
64 KiB.

QUIC:

- Retry is used once the handshaking connections pass a threshold, and connections are capped
  in total.
- The 3x amplification limit is enforced.
- The connection-ID retirement queue and the out-of-order CRYPTO and STREAM buffers are all
  bounded.
- Packet numbers are skipped at random to detect optimistic ACKs.

## What was tested (2026-11-07)

Third-party code was limited to tools already on the machine and Ubuntu 24.04 archive
packages. The archive packages were extracted without root from `apt-get download`: nginx
1.24.0, haproxy 2.8.30, nghttp2-client 1.59.0 (`nghttp`, `h2load`) and gnutls-bin 3.8.3.

| check | tool / version | result |
|---|---|---|
| HTTP/2 conformance, h2spec's server list written from the RFCs (generic, RFC 9113 §3.5, 4, 5, 6, 8, RFC 7541) | `crates/simoom/tests/h2_live.rs` | **120/120 h2c, 120/120 h2 over TLS**: in process (part of `cargo test`) and against a live `conformance_server` |
| HTTP/2 interop and load | nghttp, h2load (nghttp2 1.59.0) | **14/14** (h2c prior knowledge, `Upgrade: h2c`, h2 ALPN, 1 MB bodies, 100 concurrent streams, `-m 1000` over a 100-stream limit, 100k requests over h2c, 50k over h2, 1 MB × 200, HTTP/1.1), 0 failed requests |
| Request-smuggling differential, simoom behind a proxy | `scripts/desync/desync.py`, nginx 1.24.0 and haproxy 2.8.30 | **165 streams, 0 desyncs** after the fixes below |
| Accept/reject compared with nginx and haproxy as origins | same | simoom accepted 49, all three refused 75, simoom stricter than one of them in 41, **simoom accepted 0 that both refused** |
| TLS interop | openssl s_client 3.0.13 (WSL) and 3.5.9 (Windows) | **28/28 each** |
| TLS interop | curl 8.5.0, python3 3.12 `ssl` (OpenSSL 3.0.13), gnutls-cli 3.8.3 | **31/31** |
| TLS interop | curl 8.23.0 Schannel (Windows) | **3/3** |
| TLS hand-written checks | `crates/simoom-tls/tests/hardening.rs`, `crates/simoom/tests/tls_hardening.rs`, unit tests in `tls/conn.rs` | all pass |
| QUIC adversarial peers | `crates/simoom-quic/tests/adversarial.rs` | **30/30** |
| Limits audit | `crates/simoom/tests/limits.rs` | 11/11; every `Limits` field is tested in the facade |
| Mutation fuzzing (std-only, seeded) | `tests/fuzz.rs` of http1, h2/hpack, h3, qpack, quic, tls; release, 4 threads each | **2 h 40 min**, 10 rounds × 6 harnesses, a fresh seed per round: h2 2×10⁸, h3 1.5×10⁸, http1 5×10⁸, qpack 3×10⁸, quic 2×10⁹ iterations, tls ×4000 base. Findings: 1 engine bug (QUIC ACK-only spin) and 1 harness bug (http1 test held every input in memory), both fixed; http1 then re-run 3 × 5×10⁷ clean |
| Coverage-guided fuzzing (std-only SanitizerCoverage) | `simoom_sys::sancov` + `coverage_guided` in `simoom-http1/tests/fuzz.rs` (Linux) | see "Coverage-guided fuzzing" below |

nghttp notes, both by design:

- A 1 MB POST without `Content-Length` streams through a `BodySource`. A service that answers
  without reading it gets an early 200 and an RST_STREAM(NO_ERROR), as RFC 9113 §8.1 allows.
- `nghttp -w 1 -W 1` (2-byte windows) trips the small WINDOW_UPDATE budget (data dribble,
  CVE-2019-9511), so the connection gets GOAWAY ENHANCE_YOUR_CALM.

TLS interop covered:

- the TLS 1.3 handshake with chain verification;
- `-tls1_2` and `-tls1_1` refused with a `protocol_version` alert;
- bad SNI (default certificate), no SNI, no ALPN, ALPN h2 and http/1.1, and an unknown ALPN
  (`no_application_protocol`);
- X25519 and P-256 work. P-384, P-521, X448 and ffdhe get a clean `handshake_failure`, and
  X448 then X25519 goes through HelloRetryRequest. On OpenSSL 3.5, the X25519MLKEM768 hybrid
  falls back to X25519;
- all three suites;
- client certificates: good, rogue (`unknown_ca`), and missing (`certificate_required`);
- KeyUpdate both ways, PSK resumption, and 0-RTT offered and rejected.

### Coverage-guided fuzzing

Plan §7.3 option F2 is implemented and works on stable Rust on Linux. The callbacks are in
`simoom-sys/src/sancov.rs`, behind the test-only feature `sancov`; there are no dependencies.
LLVM's `sancov-module` pass, run through `-C passes`, calls `__sanitizer_cov_trace_pc_guard`.
`coverage_guided` keeps a corpus of inputs that reach new edges, using AFL-style hit-count
buckets. Its mutator is the harness's own byte mutations plus corpus splicing. Every input is
checked for split invariance and against the reference RFC 9112 parser.

- First run: 171k executions per minute, 1,140 of 3,036 instrumented edges in 60 s.
- Longer runs: 3 seeds × 10 min, recorded under "Results" below.
- Windows: the MSVC back end refuses the instrumented COMDATs ("Associative COMDAT symbol does
  not exist"), so it runs only on Linux.
- Not done yet: corpus minimisation, the HTTP/2, QUIC and TLS targets (they need only a driver
  like the http1 one), and persisting the corpus between runs.

```text
RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 \
  -C llvm-args=-sanitizer-coverage-trace-pc-guard" SIMOOM_FUZZ_SECS=600 \
  cargo test --release -p simoom-http1 --features sancov --test fuzz coverage_guided -- --nocapture
```

### Results

Three 10-minute runs (seeds 11, 22, 33; WSL2 Ubuntu 24.04, release, one thread): 1.37M, 1.67M
and 1.81M executions, corpora of 1,858 to 1,895 inputs, **1,220 to 1,232 of 3,036 instrumented
edges** (the remainder is mostly response parsing, WebSocket and the serializer, which this
driver doesn't exercise). No split-invariance or differential failure, no panic. Coverage
plateaus after about 5 minutes, so longer runs need new targets more than more time.

## Bugs found and fixed in this pass

| # | area | bug | fix | regression test |
|---|---|---|---|---|
| 1 | HTTP/1.1 | After a 2xx to `CONNECT`, simoom kept parsing the connection as HTTP. A front proxy (haproxy) switches to tunnelling, so tunnelled bytes would run as requests the proxy never saw (desync). | `crates/simoom/src/h1.rs`: close after the CONNECT response | `tests/desync.rs` `connect_closes_the_connection_after_its_response` |
| 2 | HTTP/1.1 | Absolute-form targets: the service got the raw URI as the path and the `Host` header as the host, so a request addressed to `y` looked like one for `x` (RFC 9112 §3.2.2 says the target wins) | `h1.rs` `split_absolute`: authority from the target, target becomes path and query | `absolute_form_uses_the_target_authority` |
| 3 | HTTP/1.1 | Userinfo in absolute-form (`http://trusted@evil/`) was accepted (RFC 9110 §4.2.4: treat as an error) | `crates/simoom-http1/src/parse.rs` `valid_absolute`, and the reference parser | `absolute_form_with_userinfo_is_refused`; `simoom-http1/tests/request.rs` `target_rules` |
| 4 | HTTP/2 | A header block larger than `max_header_list` but otherwise sane closed the whole connection with GOAWAY, instead of answering that stream with 431 (plan §7.1) | `crates/simoom-h2/src/conn.rs` `block_cap` (twice the list limit; beyond that, still GOAWAY) | `simoom-h2/tests/dos.rs` `header_block_over_the_list_limit_gets_431_not_goaway`; `tests/limits.rs` `header_list_limit_is_advertised_and_enforced` |
| 5 | limits | No per-IP connection cap (plan §7.1, optional) | `Limits::max_connections_per_ip` (`limits.rs`, `server.rs` `IpSlot`, `conn.rs`) | `tests/limits.rs` `per_ip_connection_cap` |
| 6 | QUIC | ACK-only packet spin: with no RTT sample and a pending PMTU probe, `poll_transmit` sent ACK-only packets forever, without limit (found by fuzzing, seed 7000098) | `crates/simoom-quic/src/connection.rs` (`space_has_data` follows the probe writer; ACK-only packets only when an ACK is due) | `connection::tests::unbuildable_mtu_probe_does_not_spin_ack_only_packets` |
| 7 | QUIC | Out-of-order STREAM fragments had no bound (one allocation per byte of window) | `src/stream.rs`: merge adjacent chunks; more than 1024 gaps gives PROTOCOL_VIOLATION | `fragmented_stream_data_cannot_explode_memory`, `too_many_out_of_order_gaps_is_an_error` |
| 8 | QUIC | No defence against optimistic ACKs | `connection.rs`, `recovery.rs`: random skipped packet numbers; an ACK of one is PROTOCOL_VIOLATION | `optimistic_ack_of_skipped_packet_numbers_is_detected` |
| 9 | QUIC | Tiny out-of-order CRYPTO chunks held far more memory than the buffer size | `connection.rs`: per-chunk overhead charged | `tiny_out_of_order_crypto_chunks_are_bounded` |
| 10 | QUIC | The RETIRE_CONNECTION_ID queue grew without limit under `retire_prior_to` churn | `connection.rs` `queue_retire`: deduplicated, capped, then CONNECTION_ID_LIMIT_ERROR | `retire_prior_to_churn_cannot_queue_unbounded_retirements` |
| 11 | QUIC | Retry never triggered under a spoofed flood of bad ClientHellos, because failed handshakes stopped counting | `src/endpoint.rs` | `initial_flood_from_spoofed_addresses_is_answered_with_retry_and_bounded` |
| 12 | TLS | A client whose certificate was refused saw `bad_record_mac` instead of the alert (the server wrote the alert under the wrong key) | `crates/simoom-tls/src/tls/conn.rs` | `simoom-tls/tests/hardening.rs` `client_certificate_with_a_bad_chain_is_refused_with_a_readable_alert` |
| 13 | TLS | No bound on records that deliver nothing (empty records, warning alerts, KeyUpdate floods) | `tls/conn.rs` `idle_record` (32 in a row) | `empty_record_flood_is_bounded`, `warning_alert_flood_is_bounded`, `key_update_flood_is_bounded` |
| 14 | TLS | The client ignored the downgrade sentinels (it refused with `protocol_version` rather than `illegal_parameter`) | `tls/client.rs` | `client_rejects_the_downgrade_sentinels` |
| 15 | fuzz harness | `simd_and_scalar_agree_on_fuzz_inputs` collected every input, so a long run aborted out of memory | `simoom-http1/tests/fuzz.rs`: compare in batches | (the harness itself) |

Smuggling divergences reviewed and judged benign:

- **Requests simoom refuses but nginx or haproxy accept (41 streams).** Each is a refusal on a
  stricter rule: bare LF, obs-fold, a `Transfer-Encoding` list, `HTTP/1.0` with
  `Transfer-Encoding`, a high byte in a field, a lowercase method, and so on. Behind a proxy that
  forwards such a request, simoom answers 400 and closes. The proxy then sends the next request
  on a new connection, so the boundaries still agree.
- **BWS before a chunk extension (`5 ;ext`).** It is valid per RFC 9112 §7.1.1, and all three
  accept it the same way.
- **`Upgrade: h2c` with a body.** simoom serves it as HTTP/1.1, the same as the proxies.
- **`OPTIONS *` and absolute-form.** simoom accepts these, as RFC 9112 requires. haproxy refuses
  absolute-form whose authority differs from `Host`. That is its own policy, and safe either way
  since bug 2 was fixed.
- **0.CL with `Expect: 100-continue`.** All three treat the body as a body: one request each.

## Known gaps

- **Third-party suites weren't run.** These are HTTP Garden, h2spec, the QUIC Interop Runner
  and testssl.sh. They need code from GitHub or container images. The owner approved them during
  this pass, but the agent permission system blocked running external code, so they are still
  open. Run them in WSL or Docker from a pinned release, outside the repository. The hand-written
  runners here (the h2spec list, the desync harness, the TLS and QUIC adversarial tests) are a
  substitute, not an equivalent.
- No external audit yet (plan §7.5). No Miri, ASan or TSan runs were part of this pass.
- HTTP/3 was tested only with simoom's own QUIC client and simulator. No curl/ngtcp2, quiche or
  quic-go client has been run against it.
- TLS groups are X25519 and P-256 only (no P-384, no ML-KEM hybrid), and there is no TLS 1.2.
  Clients that offer only those get `handshake_failure`, by design.
- The HTTP/2 frame budgets are fixed defaults and aren't configurable through `Limits`.
- The QUIC out-of-order gap cap applies per stream, so the worst case per connection is
  streams × 1024 chunks. Compatible version negotiation (RFC 9368) isn't implemented.
- The coverage-guided fuzzer runs on Linux only, covers only the HTTP/1 target, and has no corpus
  minimisation.
- The `h2c` upgrade path (`Upgrade: h2c`) passes an absolute-form target through unchanged.
  simoom only serves it, and the upgraded stream has the `:authority` from `Host`.

## Reproducing

```text
# hermetic: everything above that runs in cargo test
cargo test --workspace --features simoom/full

# live HTTP/2 conformance against a running server
cargo run --release -p simoom --features full --example conformance_server -- \
    --addr 127.0.0.1:18080 --tls-addr 127.0.0.1:18443 --out /tmp/cs
SIMOOM_H2_LIVE_H2C=127.0.0.1:18080 SIMOOM_H2_LIVE_H2=127.0.0.1:18443 SIMOOM_H2_LIVE_CA=/tmp/cs/ca.pem \
    cargo test --release -p simoom --features full --test h2_live -- --ignored --nocapture

# request smuggling differential (WSL / Linux; nginx and haproxy from the Ubuntu archive)
python3 scripts/desync/desync.py --server target/release/examples/conformance_server \
    --nginx /usr/sbin/nginx --haproxy /usr/sbin/haproxy

# long fuzzing, per harness
SIMOOM_FUZZ_ITERS=20000000 SIMOOM_FUZZ_SEED=7 cargo test --release -p simoom-h2 --test fuzz
```
