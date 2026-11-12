# Security

This page covers simoom's security model, its limits and defaults, what was tested and with
what results, the known gaps, and how to report a vulnerability.

_Last hardening pass: 2026-11-07, against head `33ee716` plus the fixes listed below. Third-party
suites: 2026-11-09, against head `bf24f89` plus bugs 16 to 22 below._

## Reporting a vulnerability

Please report vulnerabilities privately through **GitHub security advisories**:
<https://github.com/Cameleering/simoom/security/advisories/new>. Don't open a public issue,
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
| `inline_budget` | 1 ms; a call over it on the wall clock makes its route suspect, and the route's next calls are timed with the thread's CPU clock: a stall is a call over the budget in CPU time, or one that blocked | stall counted, logged once per route |
| `stalls_before_offload` / `stall_window` | 5 stalls within 1 s | the route (alone) moves to the offload pool |
| `stall_recovery` | 64 consecutive fast calls on the pool (twice as many after each further move) | the route comes back inline |
| `shed_lag` | off; measured 2026-11-09: 1 ms shed falsely at 50% load and no value from 0.5 to 5 ms improved goodput or p99 under 120-150% overload, so it stays opt-in | fast `503` with `retry-after` for new requests and streams |
| `h2_frame_budgets` (HTTP/2) | the budgets below (`simoom::FrameBudgets`) | GOAWAY(ENHANCE_YOUR_CALM) |
| `offload_queue` | 4096 jobs (CoDel 5 ms / 100 ms) | 503 |

HTTP/2 frame budgets (`Limits::h2_frame_budgets`, per 10 s sliding window per connection; GOAWAY
ENHANCE_YOUR_CALM beyond them):

- RST_STREAM received 200 and caused 200 (Rapid Reset, MadeYouReset);
- PING 100;
- SETTINGS 100;
- empty frames 200;
- PRIORITY;
- WINDOW_UPDATE frames under 1 KiB;
- at most `max_continuation_frames` CONTINUATION frames per block.

Each is configurable (`u32::MAX` turns one off).

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

## Third-party suites (2026-11-09)

Approved by the owner on 2026-11-08 ("Yes, allow them"). Every suite ran in WSL2 (Ubuntu 24.04)
or in Docker (Docker Desktop 29.9.2 through the WSL integration), from scratch directories
under `~/simoom-sec-tools/` outside the repository, at pinned versions. None is a dependency of
any simoom crate. The simoom servers were built from the working tree in pinned images:
`rust:1.99.1-slim-trixie@sha256:7eab7ce1…3cd5` for the build, `debian:trixie-slim@sha256:a72b4433…b6b2`
(HTTP Garden) and the runner's endpoint image (QUIC) for the run.

| suite | version | target | result |
|---|---|---|---|
| h2spec | 2.6.0 (release tarball, sha256 `157ee0de…9318`) | `conformance_server`, h2c on the shared HTTP/1.1 + h2c port | **146/146 in 30 consecutive runs** on the final tree (was 145/146: §3.5/2, fixed as bug 16; then generic §3.8/1 flaked about 1 run in 5, fixed as bug 22; §3.8/1 alone then passed 50/50). TLS mode can't run: h2spec offers only TLS 1.2 and simoom is TLS 1.3-only |
| testssl.sh | v3.2.1 (commit `b6a951d4`) | `conformance_server --tls-addr` | TLS 1.3 only, no vulnerabilities found. Notes only: the certificate is from a private test CA, and it has no CRL or OCSP URI |
| HTTP Garden | commit `b417e806c1b15e8ea0b9312f81a91fbdcbc7a83e` | `conformance_server --garden` as an origin, next to nginx, apache_httpd, h2o, hyper, gunicorn and go_stdlib; transducers haproxy, nginx_proxy, apache_httpd_proxy, h2o_proxy | **0 desyncs, 0 dangerous discrepancies**: see below |
| QUIC Interop Runner | commit `19016767e70789d70416442a1118ad82b5b5fc2e` | `interop_server` (server role) against the ngtcp2, quiche and quic-go clients | see the matrix below; engine bugs found and fixed: 17, 18, 20 and 21, and compatible version negotiation added (19) |

### h2spec

h2spec §3.5/2 sends `INVALID CONNECTION PREFACE\r\n\r\n` and expects a connection close
(GOAWAY allowed). On the shared HTTP/1.1 + h2c port simoom read it as an HTTP/1 request and
answered `400`, which h2spec reads as a malformed frame. Now (bug 16), on an h2c-enabled
listener, the first bytes of a connection go to the HTTP/2 codec, which answers SETTINGS and
GOAWAY(PROTOCOL_ERROR) and closes (RFC 9113 §3.4), when either:

- they start with the preface's request line `PRI * HTTP/2.0` but the rest of the preface is
  wrong; or
- the first request line fails with an invalid version and its last word has no `HT` prefix and
  no `/`: nothing in it is HTTP/1 in any form.

HTTP/1 clients with a damaged version (`HTTP/1.x`, `HT?P/1.1`, `XTTP/1.1`, HTTP/0.9's `GET /`)
still get a 400, and later requests on a connection are never treated as a preface. The HTTP
Garden's mutator found the first, too broad version of the rule (any line without `HTTP/`), which
answered `HT\xbcP/1.1` with GOAWAY, and the narrower rule replaced it.

Repeated runs then showed generic §3.8/1 ("Sends a GOAWAY frame", GOAWAY then PING) failing
with "connection reset by peer" in about 1 run in 5: the server closed as soon as it read the
peer's GOAWAY, and when the PING came in a later read it hit a closed socket. Fixed as bug 22
(the server answers a GOAWAY with its own graceful shutdown); results after it are in the
matrix section below.

### HTTP Garden

simoom joined the Garden as an origin (`conformance_server --garden` answers with the Garden's
echo format: base64 JSON of the method, version, target, headers and body; image
`images/simoom/Dockerfile` in the Garden checkout). Its probed quirk is `allows-http-2: true`.
The Garden removed its fuzzing driver upstream (commit `5e260b6`), so a small driver
(`tools/simoom_fuzz.py`, adapted from the removed `fuzz.py`) runs the Garden's own mutator
(`mutations.py`) and classifier (`diff.categorize_discrepancy`), fans every mutated stream out to
all origins, and replays every kept result through each transducer.

- **Differential fuzzing:** two complete runs of 40 minutes (seed 2: 16,354 mutated streams, 42
  kept results; seed 3: 14,993 streams, 53 results), after a shorter first run that a WSL
  restart cut off (13 results). Every kept result was then replayed 3 times through each
  transducer, comparing the proxy's own view of what it forwarded with simoom's reading
  (`tools/simoom_recheck.py`): **709 forwarded streams (321 and 388), 0 flagged**. Results that involve simoom, triaged
  by hand:
  - **simoom stricter** (simoom refuses or closes, another origin accepts): bare LF in the head
    or in chunked framing, whitespace or a high byte in `Host`, `Host` with a bad port, a
    duplicate `Transfer-Encoding: chunked`, `Content-Length` with `Transfer-Encoding`, a non-ASCII
    byte in the target, `Connection: close` plus `keep-alive` with a body and no length. Benign:
    simoom answers 400 and closes, so a proxy's next request goes on a new connection.
  - **simoom accepts with the same boundaries but a different header set** (13 in run 2, 20 in
    run 3): apache,
    gunicorn and nginx drop or rewrite headers with `_` or odd names (CGI environments), nginx adds
    empty `content-length`/`content-type`, apache's CGI echo loses chunked bodies split across
    reads. Every one of these is a difference between the other origins and simoom's reading,
    which matches the majority. Benign.
  - **Stream discrepancies after a transducer** (run 3: a payload split into pieces, sent
    through apache_httpd_proxy or nginx_proxy): another origin returned nothing within the
    Garden's 50 ms origin timeout while simoom answered, or the proxy forwarded nothing on a
    retry. None reproduced in the replay above. Timing, benign.
  - **Garbage first lines** (`os t: whatever`) get GOAWAY instead of 400 because of bug 16; the
    Garden counts that as no response, which it treats as agreeing with a rejection. Benign.
  - **No result where simoom read a different number of requests, a different body, or a
    different method or target than a proxy forwarded.**
- **Curated smuggling vectors** (`tools/simoom_curated.py`, 39 streams: CL.TE, TE.CL, TE
  obfuscations, duplicate or listed `Content-Length`, chunk-size overflow and `0x`, chunk
  extensions with LF or quoted CRLF, trailers that smuggle `Content-Length`, bare CR and LF, NUL,
  HTTP/1.0 with TE, `GET` with a body, `Expect`, `CONNECT`, `Upgrade: h2c` with a body,
  absolute-form, pipelining). Each was sent through haproxy, nginx_proxy, apache_httpd_proxy and
  h2o_proxy, and the proxy's own view of what it forwarded was compared with simoom's reading of
  the forwarded bytes: **0 of 156 proxy paths flagged**. simoom refused 28 of the 39 directly.

### QUIC Interop Runner

`crates/simoom/examples/interop_server.rs` follows the runner's endpoint contract: `TESTCASE`
selects the case (unknown cases exit 127), files come from `/www`, the key and chain from
`/certs/priv.key` and `/certs/cert.pem`, port 443 on `[::]` (IPv4 and IPv6). `http3` goes through
the `simoom` facade (`Server::listen_quic`, the production HTTP/3 path); every other case speaks
`hq-interop` over a `simoom_quic::Endpoint` on a std UDP socket. The image builds it on the
runner's endpoint image (`martenseemann/quic-network-simulator-endpoint@sha256:3b2b9e6f…71a`).
Clients, pinned by digest: ngtcp2 `ghcr.io/ngtcp2/ngtcp2-interop@sha256:4333a236…37e0`, quiche
`cloudflare/quiche-qns@sha256:d8480e44…3f63df`, quic-go
`martenseemann/quic-go-interop@sha256:fc8fc56c…4ea4e`; simulator
`martenseemann/quic-network-simulator@sha256:c23d82a5…b6c9`. The runner itself ran in a
container with Python 3.12.12 and tshark 4.6.9, one runner call per case, a case retried only
when tshark crashed.

Final full run (on the final tree, after bugs 17 to 21; ✓ passed, ✕ failed, – the client doesn't support the case
or the server exits 127):

| case | ngtcp2 | quiche | quic-go |
|---|---|---|---|
| handshake | ✓ | ✓ | ✓ |
| transfer | ✓ | ✓ | ✓ |
| longrtt | ✓ | ✓ | ✓ |
| chacha20 | ✓ | – | ✓ |
| multiplexing | ✓ | ✓ | ✓ |
| retry | ✓ | ✓ | ✓ |
| resumption | ✓ | ✓ | ✓ |
| zerortt | ✕ (0-RTT refused by design) | ✕ (same) | ✕ (same) |
| http3 | ✓ | ✓ | ✓ |
| blackhole | ✓ | ✓ | ✓ |
| keyupdate | ✓ | – | ✓ |
| ecn | ✕ (no ECN) | – | – |
| amplificationlimit | ✓ | ✓ | ✓ |
| handshakeloss | ✓ | ✓ | ✓ |
| transferloss | ✓ | ✓ | ✓ |
| handshakecorruption | ✓ | ✓ | ✓ |
| transfercorruption | ✓ | ✓ | ✓ |
| ipv6 | ✓ | ✓ | ✓ |
| v2 | ✓ | – | – |
| rebind-port | ✓ | ✓ | ✓ |
| rebind-addr | ✓ | ✓ | ✓ |
| connectionmigration | – (no preferred address) | – | – |

**Totals:** 54 of the 58 supported pairs pass. The 4 failures are `zerortt` against every client
(0-RTT is refused by design, so the client's 0-RTT data is never accepted) and `ecn` against
ngtcp2 (not implemented). The runner crashed in tshark on a few cases (it reads its pcaps
through pyshark); those were run again and passed.

How it got there (earlier full runs on the same day):

- The first run had `blackhole` failing (bug 17: the send buffer stuck after a blackout),
  `rebind-port` and `rebind-addr` failing against quic-go (bug 18: no PATH_CHALLENGE in the first
  packet on the new path) and `v2` failing against ngtcp2 (bug 19).
- quiche `multiplexing` failed with "Too many open files" in the quiche client: it keeps one
  file open per request and Docker Desktop's default soft limit is 1024 descriptors. An
  environment limit, not a simoom bug: the runner's compose file now gives the endpoints a
  `nofile` limit of 65536, and it passes 3 out of 3.
- `handshakeloss` and `handshakecorruption` failed now and then (quic-go: "handshake did not
  complete in time"; quiche: one of the 50 connections timed out). The traces showed the server
  resending a lost flight only on its own PTO, which heavy handshake loss had stretched to
  seconds. Bug 20 resends it as soon as the client's ClientHello comes again.
- `blackhole` against quic-go once ran past the runner's time limit before bug 20 and the final
  image; it passes in the final run and in the reruns below.

Reruns of the cases that had been intermittent, on the final image, 3 times each: quic-go
`handshakeloss` 3/3, quic-go `handshakecorruption` 3/3, quic-go `blackhole` 3/3, quiche
`handshakeloss` 3/3; quiche `multiplexing` 3/3 with the raised descriptor limit; ngtcp2
`handshakeloss` 3/3 (on the image before bug 21).

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
| 16 | HTTP/2 | An invalid connection preface on the shared HTTP/1.1 + h2c port got an HTTP/1 `400` instead of GOAWAY(PROTOCOL_ERROR) and a close (RFC 9113 §3.4; h2spec §3.5/2) | `crates/simoom-http1/src/h2c.rs` `Preface::Invalid`; `crates/simoom/src/h1.rs` (first request only, `looks_like_http`) | `simoom/tests/http2.rs` `invalid_preface_gets_goaway_protocol_error_and_close`; `simoom-http1/tests/response.rs` `h2_preface_detection` |
| 17 | QUIC | A stalled transfer after packet loss: an acknowledgement of bytes already released (the original packet and its retransmission both acknowledged) was recorded below the send buffer's base, stayed first in the acknowledged set forever, and blocked every later release, so the 1 MiB send buffer stayed full and the stream never sent again (found by the interop runner's `blackhole` case) | `crates/simoom-quic/src/stream.rs` `on_stream_acked`: record only the part above `base` | `simoom-quic/tests/transport.rs` `transfer_survives_repeated_blackouts`; `stream::tests::send_side_credit_and_limits` |
| 18 | QUIC | After a NAT rebinding the PATH_CHALLENGE waited for congestion window: the bytes in flight on the old path filled the reset window, so the first packet on the new path was ACK-only (interop `rebind-port`, `rebind-addr`) | `crates/simoom-quic/src/connection.rs`: the challenge is written first and is not held back by congestion control | `connection::tests::first_packet_on_a_new_path_carries_the_challenge_when_cwnd_is_full` |
| 19 | QUIC | No compatible version negotiation (RFC 9368): a client that started in v1 and offered v2 stayed in v1 (interop `v2`) | `crates/simoom-quic/src/vn.rs` (new), `params.rs` (`version_information`), `connection.rs`: a server with more than one version starts TLS after the whole ClientHello, picks its preferred version from the client's list and switches its Initial keys; a client follows a server Initial in another compatible version | `simoom-quic/tests/tls.rs` `compatible_version_negotiation_v1_to_v2` (with Retry and with loss); `vn::tests`; `params::tests` |
| 20 | QUIC | Under heavy handshake loss the server waited for its own PTO, backed off to seconds by RTT samples it can't correct in the handshake spaces, before resending a lost flight; clients gave up (interop `handshakeloss`, `handshakecorruption`, intermittent) | `connection.rs` `on_crypto`, `resend_handshake_flight`: a repeated ClientHello means the client's PTO fired, so the server queues its unacknowledged Initial and Handshake data again at once (still under the anti-amplification limit and congestion control) | `connection::tests::duplicate_client_hello_resends_the_server_flight` |
| 21 | QUIC | The cap on out-of-order STREAM fragments (1024) applied per stream, so a peer could hold streams × 1024 fragments per connection | `crates/simoom-quic/src/stream.rs`: `recv_gaps` counts holes over all streams; a reset or stopped stream gives its holes back | `stream::tests::out_of_order_gap_cap_is_per_connection`, `too_many_out_of_order_gaps_is_an_error` |
| 22 | HTTP/2 | After the peer's GOAWAY with no streams open the server closed at once, so a frame the peer sent after its GOAWAY (h2spec generic 3.8/1 sends a PING) hit a closed socket and the peer saw a TCP reset instead of the PING ACK (h2spec flaked about 1 run in 5) | `crates/simoom-h2/src/conn.rs`: a server answers the peer's GOAWAY with its own graceful shutdown (GOAWAY, PING round trip or timeout, final GOAWAY) and closes after it | `simoom-h2/tests/conformance.rs` `s6_8_ping_after_goaway_is_answered`, `s6_8_goaway` |

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

- **QUIC:** no ECN (packets are not marked ECT and ACK frames carry no ECN counts: interop
  `ecn` fails), no preferred address and so no server-side active migration (`connectionmigration`
  unsupported), and 0-RTT is refused by design (`zerortt` fails). Handshake-space RTT samples
  can't be corrected by the peer's ACK delay (RFC 9002 §5.3), so heavy handshake loss inflates
  the RTT estimate and the PTO; bug 20 resends the flight when the client's ClientHello comes
  again, but a lost server flight with a client that probes only with PING still waits for the
  server's PTO.
- No external audit yet (plan §7.5). No Miri, ASan or TSan runs were part of this pass.
- HTTP/2 over TLS has not been run through h2spec (h2spec offers only TLS 1.2); the in-repo
  h2spec list (`h2_live.rs`) covers it.
- HTTP Garden ran only its HTTP/1.1 paths against simoom; its HTTP/2 fan-out (`h2fanout`) was not
  run.
- TLS groups are X25519 and P-256 only (no P-384, no ML-KEM hybrid), and there is no TLS 1.2.
  Clients that offer only those get `handshake_failure`, by design.
- Compatible version negotiation (RFC 9368) covers v1 and v2 only. After a switch to v2 the
  server keeps processing the client's v1 Initial packets until the Initial keys are discarded
  (fixed 2026-11-09, BUGS.md item 21).
- The coverage-guided fuzzer runs on Linux only, covers only the HTTP/1 target, and has no corpus
  minimisation.

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

# third-party suites (WSL, outside the repository; versions in the table above)
h2spec -h 127.0.0.1 -p 18080 -o 3                    # against conformance_server --addr
conformance_server --garden --addr 0.0.0.0:80        # the HTTP Garden origin (in its Docker image)
TESTCASE=transfer interop_server --addr [::]:443 --www /www --certs /certs   # QUIC Interop Runner endpoint
python3 run.py -s simoom -c ngtcp2,quiche,quic-go    # in the runner checkout, simoom added to implementations_quic.json
```

Notes for the QUIC Interop Runner on Docker 28 or later: the runner's two bridge networks need
`com.docker.network.bridge.gateway_mode_ipv4: nat-unprotected` (and `_ipv6`), otherwise Docker's
direct-routing protection (raw-table `PREROUTING` drops) discards the bridged frames between the
client and the simulator and every test fails, the runner's reference pairs included. The runner
needs Python 3.12 (pyshark fails on 3.14) and tshark 4.5 or later.
