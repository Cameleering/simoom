# Plan: a new std-only Rust HTTP server

_Internal design note, 2026-11-07. Evidence and sources are in [research.md](research.md)._

## 0. Scope set by the owner (2026-11-07)

These decisions take precedence over anything later in this note that disagrees with them.

1. **Not a full web-server replacement.** simoom is an embeddable HTTP engine. It does what
   Cameleer needs as a whole, and it is also usable by other services:
   - serve routes, REST and MCP, including streaming (SSE and chunked) and WebSocket upgrades;
   - run on edge devices and in FaaS environments, where start-up, memory and size dominate.

   No static-file server, reverse proxy or config-file web server in the first release.
2. **HTTP/1.1, HTTP/2 and HTTP/3 (QUIC) are all in the first release.** HTTP/3 is no longer a
   later decision. §2.9 and §8 are updated.
3. **Efficiency comes before everything; time and effort are secondary.** Every feature must
   measure better than the alternatives in §6.3 on throughput, tail latency, memory and size.
4. **Size is a hard budget.** Cameleer's `core` build is 5.82 MB, and simoom must not be a
   major part of any Cameleer build. Budgets (stripped, x86-64 Linux, release):

   | build | budget |
   |---|---|
   | HTTP/1.1 only | at most 250 KB of added code |
   | HTTP/1.1, HTTP/2 and TLS 1.3 | at most 600 KB |
   | everything, HTTP/3 included | at most 1 MB |

   Each protocol is a cargo feature, so a build pays only for what it uses. CI measures the
   size of every feature combination and fails when a budget is exceeded.
5. **TLS is owned by simoom.** QUIC needs TLS 1.3 handshake messages without records (RFC 9001),
   header protection, and a sans-io API. So `simoom-tls` is a server-first TLS 1.3
   implementation that ports the constant-time primitives from `cameleer-tls` (same owner,
   same licence) and adds AES-NI/PCLMULQDQ and ARMv8 AES paths. This replaces the adapter
   described in §2.8. TLS 1.2 is optional and off by default.
6. **Std-only, like Cameleer.** Fuzzing uses option F2 (§7.3): std-only harnesses, no
   `libfuzzer-sys`.
7. **Start-up and memory (owner, 2026-11-09).** simoom's cold start and memory must be within
   5% of Cameleer's current HTTP server (`cameleer-http`, plain and with TLS), measured the same
   way on the same machine. Anything above that needs a specific, measured advantage in real use
   cases, documented alongside the numbers.
8. The repository is `github.com/pmsudhi/simoom` (private), licensed Apache-2.0 like Cameleer.
   Releases are git tags. Cameleer depends on simoom by tag until the owner decides to publish
   it on crates.io.

## 1. Decision

**Recommendation:** build a new server, std-only, in its own repository. Gate the build behind
a two-week measurement spike (Milestone 0) that has to show the gain on the real machines before
the main work starts.

The server is named **simoom** (a hot, fast desert wind). On 2026-11-07 the name and the
sub-crate names in §4 were free on crates.io, and `pmsudhi/simoom` was free on GitHub. No
trademark search has been done.

### The options

| option | what it means | verdict |
|---|---|---|
| A. Tune the existing `cameleer-http` server | keep a thread per connection; cut allocation and parsing cost | caps at the do-nothing threaded ceiling: 166k req/s on c-4, so at most about 1.5x today's 113k. **Not several times.** Still worth doing for the classic engine's 32% overhead if Milestone 0 says no. |
| B. Adopt hyper/tokio, actix, may-minihttp or xitca | add crates | **breaks hard rule 1 (std-only)**; would also add 1–5 MB of binary and give up control over strictness. Only if the owner lifts the rule. |
| C. Port designs into an event loop inside `cameleer-http` | a new engine in the monorepo | works technically, but ties a general-purpose server to Cameleer's release cycle and to its 2,800-test suite. That makes it harder to use in other services. |
| **D. New std-only repository, used by Cameleer** | sans-io protocol crates, event loop per core, cross-OS back ends | **Recommended.** The owner asked for a separate, reusable server; protocol crates can be fuzzed and audited on their own; Cameleer pins a version. |

**"Build versus adapt", answered:** adapt **designs**, build **code**. The designs come from:

- H2O and nginx: per-thread loops, lazy buffers, a cached `Date` header;
- picohttpparser and httparse: SIMD scanning;
- compio and monoio: a completion model across operating systems, and owned ("rent") buffers;
- HAProxy: strict parsing;
- the CVE record: HTTP/2 work accounting.

There is no std-only code to adapt.

### What Milestone 0 must show before the build goes ahead

A raw event-loop responder must reach at least **2.0x the threaded responder** (at least
330k req/s, against 166k) on c-4 droplets, at an open-loop **p99 at or under 1 ms**.
Alternatively, nginx or H2O must show that much headroom on the same droplets.

If neither holds, the VM network is the ceiling. In that case, stop and do option A instead.

The reasoning: the earlier IOCP experiment that showed no gain
(`benchmarks/analysis.md`) ran on Windows over loopback, with the load generator on the same
machine. So it doesn't settle the Linux VM case. The CPU budget (24 µs per request today,
against about 8 µs for an event-loop server) says the gain should be there. Closed-loop
measurement at 64 connections would hide it (Little's law, research.md §1).

## 2. Architecture

### 2.1 Layers

```
Service API (embedding)         simoom          Service, Reply, Responder, Blocking adapter, router
protocol, sans-io, safe code    simoom-http1    parser and serializer, chunked, limits
                                simoom-h2       frames, streams, flow control, DoS accounting
                                simoom-hpack
TLS, sans-io trait              simoom-tls      adapter to cameleer-tls (optional feature); kTLS hand-off
runtime                         simoom-rt       loop per core, timer wheel, buffer pools, wake, offload pool
OS (the only unsafe code)       simoom-sys      epoll, io_uring, kqueue, IOCP, eventfd, mmap, SIMD scan
```

The protocol crates have no I/O. They take bytes and emit events and bytes, as rustls and
quinn-proto do. That is what makes them easy to fuzz, testable under Miri, and usable over any
back end.

### 2.2 Threading: hybrid thread per core

- **N loop threads**, one per core by default (the CPU set from `sched_getaffinity` on Linux).
  Each loop owns its connections, buffers and timers. Nothing is shared on the hot path.
- **Accepting connections.**
  - Linux: one `SO_REUSEPORT` listener per loop. A CBPF steering program by CPU is optional,
    used only if Milestone 1 measures a gain.
  - macOS: one listener per loop; the OS spreads connections only roughly, so check the balance.
  - Windows: one `AcceptEx` queue shared by all loops through IOCP.
  - Optional power-of-two-choices hand-off when loops become imbalanced.
- **Handlers run in one of two modes, chosen per service or per route:**
  - **Inline**, on the loop thread. For fixed replies, in-memory routes and anything that
    finishes in microseconds. This is the partitioned M/M/1 regime, fine when the service time
    S is tiny.
  - **Offload**, on a shared, bounded worker pool (the M/M/c regime: about 3x better p99 than
    partitioned queues at 80% load, research.md §3). For blocking work: Cameleer routes with
    I/O, databases, `to("http:...")`. The reply comes back through a `Responder` and a wakeup
    across threads (eventfd, `PostQueuedCompletionStatus` or `EVFILT_USER`).
- **Stall watchdog.** An inline call over `inline_budget` (default 1 ms) on the wall clock makes
  its route suspect; the route's next calls are timed with the thread's CPU clock, and a call is
  a stall only if it used more CPU than the budget or blocked (a preempted loop thread is not a
  slow handler). Stalls are logged once per route. `stalls_before_offload` (default 5) stalls
  within `stall_window` (default 1 s) move the route, alone, to the offload pool; after
  `stall_recovery` (default 64) consecutive fast calls there it comes back inline, and each
  further move needs twice as many. This protects the tail from a handler that was wrongly
  marked inline.
- **Admission control.** `shed_lag`: when a loop reaches a connection's input this long after
  the turn's events were ready, new requests and streams get a fast `503` with `retry-after`
  without calling the service. Off by default (`None`): measured on 2026-11-09 (4 loops, open-loop HTTP/1.1 load from 8 other
  cores, 256 connections), 1 ms already shed requests falsely at 50% load and 0.5 ms at 90%, while
  under overload (120% and 150%) no value from 0.5 to 5 ms improved goodput or the p99, because
  the queue builds in the client and the kernel, not in the loop. Lag also grows when a loop
  thread is preempted. Opt in with a value that matches a latency SLO.

### 2.3 I/O back ends per operating system

The internal abstraction is **completion-style**: "receive into a buffer you own, send these
owned buffers, tell me when done". It maps natively to io_uring and IOCP. epoll and kqueue
emulate it with readiness events plus non-blocking calls, inside the loop, at no extra syscall
cost. This is compio's approach. The loop never exposes readiness to the protocol layer.

| OS | default back end | details |
|---|---|---|
| Linux | **epoll**, edge-triggered, one epoll per loop | `recv` into a pooled buffer, `writev`; `accept4(SOCK_NONBLOCK)`; `TCP_NODELAY`; batched writes flushed once per loop turn. Optional busy polling (`EPIOCSPARAMS` on 6.9+) after measurement. Works on 3.9+ kernels; tested on 5.10+. |
| Linux, opt-in | **io_uring** on 6.1+ | `SINGLE_ISSUER` plus `DEFER_TASKRUN`; multishot accept; multishot recv with a provided-buffer ring (no buffer pinned while idle); registered (direct) file descriptors; `SEND_ZC` only for sends of 16 KB or more; no SQPOLL by default (it burns a core, a bad trade on 4 vCPUs). **Probed at start**: falls back to epoll on `ENOSYS`/`EPERM`, under seccomp and with `io_uring_disabled`. Must beat epoll by 10% or more in Milestone 2 to be recommended. |
| Windows | **IOCP** | overlapped `WSARecv`/`WSASend`, `AcceptEx`, `SetFileCompletionNotificationModes(SKIP_COMPLETION_PORT_ON_SUCCESS)`, one completion port per loop. RIO (Registered I/O) is a later experiment, not 1.0. |
| macOS / BSD | **kqueue** | `EV_CLEAR`, `EVFILT_USER` for wakeups. A development platform; correctness first, performance second. |

All of it uses std plus `extern "C"`/`extern "system"` declarations, as `cameleer-tls/src/net.rs`
and `cameleer-bench/src/rawiocp.rs` already do. io_uring is reached through `syscall(2)` and
`mmap` from libc, which std already links. No crates.

### 2.4 Memory

- **Per-loop slab pools** in size classes (2 KB, 16 KB, 64 KB). An idle keep-alive connection
  holds **no** buffer: its state is a struct of about 200–400 bytes. A buffer is borrowed when
  data arrives and returned when the request has been parsed and the response sent.
- Response heads for fixed routes are pre-serialized and cached. The `Date` header is
  refreshed once a second per loop.
- Hard caps on pool size per loop. When a pool is empty, reading pauses (backpressure); the
  server doesn't allocate without bound.

### 2.5 Timers

A hierarchical timing wheel per loop (Varghese and Lauck, SOSP 1987): O(1) insert and cancel,
one tick per loop turn. It drives:

- the deadline for the whole request head (defeats slowloris);
- the idle keep-alive timeout;
- the minimum body rate;
- the write deadline;
- HTTP/2 ping and settings timeouts.

### 2.6 HTTP/1.1

- **A strict parser** per RFC 9112, with the rejection list in research.md §5:
  - `Transfer-Encoding` together with `Content-Length` is a 400, followed by a close;
  - duplicate or differing `Content-Length` values are rejected;
  - only a final `chunked` encoding is accepted;
  - no obs-fold, no bare CR, no whitespace before the colon;
  - strict tchar set, strict chunk grammar with a capped chunk-extension length.
- SIMD delimiter scan (SSE4.2, AVX2, NEON) with runtime detection and a scalar fallback. A
  test checks that both give the same answer on every fuzz input.
- Zero copy: headers are `&[u8]` slices into the receive buffer. A header map is built lazily
  and only if the service asks for one.
- Pipelining works: requests parsed in one turn are answered in order, and the replies go out
  in one write.
- `Expect: 100-continue` per RFC 9110 §10.1.1.
- Any framing error closes the connection after the response.
- A connection whose body wasn't fully read or rejected is never reused.
- Upgrades (WebSocket, h2c) hand the connection to another codec on the same loop.

### 2.7 HTTP/2

- **A sans-io rewrite of `cameleer-grpc`'s h2 engine.** The frame codec and HPACK are reused.
  The reader and writer threads and the condition variables are replaced by a state machine the
  loop drives.
- **h2 over TLS through ALPN, and h2c with prior knowledge.** h2c is the recommended protocol
  for internal upstream traffic, per Kettle 2025.
- **DoS accounting** (research.md §5):
  - concurrency counts streams whose **handler work** is still running, not streams in the
    open state (the MadeYouReset fix);
  - sliding-window budgets per connection for RST_STREAM (received and sent), PING, SETTINGS,
    empty DATA, PRIORITY and WINDOW_UPDATE frames;
  - total header-block bytes across CONTINUATION frames capped at `max_header_list_size`;
  - an HPACK dynamic table cap;
  - `GOAWAY(ENHANCE_YOUR_CALM)` and a close when a budget is exceeded.
- Flow control: window auto-tuning (bandwidth times delay estimate), and a cap on data buffered
  per stream and per connection.

### 2.8 TLS

- **A trait in `simoom`:** `TlsSession` with `read_tls`, `write_tls`, `process`,
  `plaintext_reader` and `export_traffic_secrets`. Sans-io, like rustls. The `simoom-tls`
  crate implements it on **`cameleer-tls`**, using the published crate.
- **Two changes needed in `cameleer-tls`**, in the Cameleer repository, before Milestone 4:
  1. a sans-io record and handshake API (today it wraps `Read`/`Write`);
  2. an AES-NI and PCLMULQDQ AES-GCM path through `std::arch`, with the bitsliced code as the
     fallback (ARMv8 AES and PMULL on arm64). Today's AES is constant time but has no hardware
     path. That is fine for handshakes but slow for bulk data.
- **kTLS on Linux** (opt-in, then the default once measured): after the handshake, pass the
  keys to `SOL_TLS`. The kernel then encrypts with AES-NI, and `sendfile` works over TLS. Fall
  back to user space when the kernel lacks the cipher, and for key updates the kernel can't
  take.
- Session tickets with rotating keys; 0-RTT **off** (replay risk).

### 2.9 HTTP/3

**In the first release (owner decision, §0).** Crates and design:

- **`simoom-quic`:** a sans-io QUIC v1 transport (RFC 9000, 9001, 9002), with QUIC v2
  (RFC 9369) as an option. Server side first. It covers:
  - packet protection and header protection through `simoom-tls`;
  - Retry with address-validation tokens (anti-amplification, the 3x limit);
  - stateless reset;
  - connection IDs and migration (path validation);
  - loss recovery (RFC 9002), with NewReno by default and CUBIC as an option;
  - ACK frequency kept simple.
- **`simoom-h3` and `simoom-qpack`:** HTTP/3 (RFC 9114) and QPACK (RFC 9204), with the static
  table and a bounded dynamic table.
- **I/O.** On Linux, one UDP socket per loop with `SO_REUSEPORT`; `recvmmsg`/`sendmmsg`, plus
  GSO (`UDP_SEGMENT`) and GRO (`UDP_GRO`) when the kernel supports them. On Windows, IOCP with
  `WSARecvMsg`/`WSASendMsg` and USO/URO where available. On macOS, kqueue.
- **`Alt-Svc`:** the HTTP/1.1 and HTTP/2 listeners announce HTTP/3.
- **DoS limits:** amplification, connection IDs per connection, streams, and `CRYPTO`
  buffering; Retry under load.
- **Targets:** interop with curl/ngtcp2, quiche and quic-go clients (the QUIC Interop Runner
  test cases); h2load `--h3` throughput and latency against H2O, nginx and Caddy.

### 2.10 Overload behaviour

- Caps on connections (per loop and in total), requests in flight per connection, write-queue
  bytes per connection (above the high-water mark the server stops reading that connection) and
  offload-queue depth.
- When the offload queue's **sojourn time** stays above its target for an interval (CoDel,
  default target 5 ms over 100 ms), new offloaded requests get a fast 503 with `Retry-After`.
  When the connection cap is reached, new connections are accepted and closed at once, so the
  kernel's accept queue doesn't silently stretch the tail.
- The test for this is §6, scenario S9: at 2x the saturation rate, admitted p99 stays within
  2x of p99 at 80% load, and goodput stays at 90% or more of the peak.

## 3. Public API for embedding

The API is synchronous at its core, so it needs no async runtime, but it doesn't stop callers
who use one. A sketch, not final:

```rust
use simoom::{Server, Service, Request, Reply, Outcome, Limits, Backend};

/// Runs on a loop thread. Must not block. Return Outcome::Deferred to answer later.
pub trait Service: Send + Sync + 'static {
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome;
}

// Inline: a fixed reply, answered on the loop thread.
struct Hello;
impl Service for Hello {
    fn call(&self, _req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        reply.status(200).header("content-type", "text/plain").body_static(b"hello")
    }
}

// Deferred: the work is done elsewhere, and the reply comes back from any thread.
impl Service for MyAsync {
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        let owned = req.to_owned_limited()?;     // copies the head; the body is already buffered or streamed
        let responder = reply.defer();           // Responder: Send + 'static, completes exactly once
        self.pool.submit(move || responder.send(handle(owned)));
        Outcome::Deferred
    }
}

// The usual case for blocking code: the built-in adapter runs it on the shared bounded pool.
let svc = simoom::blocking(|req: OwnedRequest| -> Response { /* blocking route */ });

let server = Server::builder()
    .listen("0.0.0.0:8080")?
    .threads(0)                       // 0 = one per core
    .backend(Backend::Auto)           // Auto = io_uring if allowed and enabled, else epoll / IOCP / kqueue
    .limits(Limits::default())        // every limit in §7.1
    .tls(tls_config)                  // optional
    .http2(true)
    .service(svc)
    .start()?;                        // returns ServerHandle: local_addr(), stats(), stop(grace)
```

- **Streaming:**
  - `Reply::stream()` returns a `BodySink: Send`; its `write` reports backpressure through
    `Pending`, or blocks in the blocking form. Used for SSE and chunked responses.
  - `Request::body()` gives a `BodySource` that pulls, so a slow handler stops the reads.
- **async callers:** `Responder` and `BodySink` are plain `Send` handles, so a tokio or
  smol user can complete them from a task. `std::future::Future` adapters (`responder.send`
  returns immediately, `BodySink::ready()` is a future) come with no runtime attached.
- **A router helper:** exact paths in a hash map and templates in a trie, evaluated on the loop
  thread. A 404 or a method mismatch never reaches the pool.
- **Bring your own listener:** `Server::from_listeners(Vec<TcpListener>)` for socket
  activation and for sharing a port.
- **Observability:** `stats()` counts (accepted, active, requests, parse errors per kind,
  limits hit per kind, offload queue sojourn p99), and an optional access-log hook called off
  the hot path.

### 3.1 How Cameleer plugs in

- **`cameleer-http` keeps its public API** (`HttpServer`, `HttpHandler`, `ServerConfig`). Inside
  it, a new engine module wraps simoom:
  - `HttpHandler::handle(&mut HttpRequest) -> HttpResponse` runs through `simoom::blocking`
    (offload) by default;
  - routes known to be non-blocking run inline: the route has only in-memory steps, or the user
    sets an endpoint option such as `?inline=true`, decided at route start.
  - The engine is chosen by `camel.server.engine=simoom|classic`. The default becomes
    `simoom` only when the whole hermetic suite and the live tiers pass with it. `classic`
    stays one release as a fallback, then goes.
- **`platform-http`, `netty-http`, `rest`, `undertow`, `jetty` and the other consumers that use
  the shared server** (`camel.server.port`) register routes with the router helper, so path
  matching moves to the loop.
- **The MCP server** (`cameleer_ai::mcp::http`): the Streamable HTTP POST becomes a deferred
  reply. The SSE GET stream and the response streams use `Reply::stream()` with backpressure.
  `Mcp-Session-Id` lookups stay in Cameleer. The idle-session sweep can use the loop's timer
  wheel instead of checking once a second.
- **gRPC** (`cameleer-grpc`) moves onto `simoom-h2` in Milestone 5. Its handlers are
  offloaded.
- **Dependencies:** `cameleer-http` depends on `simoom` and `simoom-tls`; `simoom-tls`
  depends on `cameleer-tls`. There is no cycle, but the two repositories are versioned together
  through `cameleer-tls`. To decouple later, move `cameleer-tls` into its own repository; that
  is not required now.
- **Cargo features:** `cameleer-main`'s existing `http` feature pulls simoom in. The `core`
  build stays as small as it is: simoom replaces `server.rs`, it doesn't add to it.

## 4. Repository layout

```
simoom/                             github.com/pmsudhi/simoom
  Cargo.toml                        workspace; std only; edition and MSRV pinned
  crates/
    simoom-sys/                     the only crate with `unsafe`; SAFETY comment on every block
    simoom-rt/                      #![forbid(unsafe_code)]
    simoom-http1/                   #![forbid(unsafe_code)]; SIMD comes through simoom-sys::scan
    simoom-hpack/                   #![forbid(unsafe_code)]
    simoom-h2/                      #![forbid(unsafe_code)]
    simoom-tls/                     adapter to cameleer-tls (feature `tls`)
    simoom/                         the Service API, builder, router, limits
    simoom-server/                  standalone binary: static files, config file, later a reverse proxy
    simoom-bench/                   open-loop load generator, raw responders, harness (publish = false)
  fuzz/                             outside the workspace (see §7.3)
  conformance/                      h2spec runner, HTTP Garden adapter, smuggling corpus
  bench/                            competitor configs, pinned versions, checksums, cloud scripts
  docs/                             design, API guide, security model, benchmark reports
  SECURITY.md  CHANGELOG.md  LICENSE (same license as Cameleer)
```

### 4.1 CI and releases

- **CI on every PR:**
  - zero warnings and `cargo clippy` clean from the first day (a new repository has no lint
    debt);
  - tests on Linux x86-64 (Ubuntu 22.04 with kernel 5.15, and 24.04 with 6.8), Linux arm64,
    Windows Server 2022, and macOS 14 arm64;
  - a QEMU job on kernel 5.10 (epoll only) and one on the latest mainline (io_uring);
  - Miri on the sans-io crates;
  - an `unsafe` counter that fails when it grows without a `SAFETY` comment and review;
  - 10 minutes of fuzzing per target.
- **Nightly:** 8 hours of fuzzing per target with the corpus kept; HTTP Garden and h2spec; ASan
  and TSan on `simoom-sys` and `simoom-rt`.
- **Releases:**
  - semver, 0.x until Milestone 7 and 1.0 after that;
  - signed tags `vX.Y.Z`;
  - crates published in dependency order (the same pattern as `scripts/publish-crates.sh`);
  - a CHANGELOG entry and a benchmark report per minor release (§6, on droplets, results
    committed under `bench/results/`).
- **Security policy:** private reports through GitHub security advisories, a 90-day disclosure
  window, the latest minor release supported, and fixes backported to the previous minor
  release for 6 months after 1.0.
- **Cameleer** pins an exact version. A bump is its own PR that runs Cameleer's full hermetic,
  live and official-client tiers (hard rule 6).

## 5. Std-only accounting

| need | std-only approach | risk |
|---|---|---|
| epoll, kqueue, IOCP, eventfd, `accept4`, `writev` | `extern` declarations against libc and Win32, which std already links | low; the same pattern already runs in `cameleer-tls/src/net.rs` |
| io_uring | `syscall(SYS_io_uring_setup / enter / register)`, `mmap` of the SQ, CQ and SQE rings, atomics for head and tail | medium; ring memory ordering must be exact. Miri can't run it, so cover it with TSan and stress tests. |
| SIMD scan | `core::arch` intrinsics, `is_x86_feature_detected!` | low; a scalar oracle checks it in tests and fuzzing |
| AES-NI and PCLMUL | `core::arch::x86_64::_mm_aesenc_si128`, `_mm_clmulepi64_si128` | low |
| kTLS | `setsockopt(SOL_TLS)` with the kernel's `tls12_crypto_info` structures | low to medium; kernel version matrix |
| fuzzing | see §7.3: needs an owner decision | the only place where std-only costs real effort |

## 6. Benchmark method

The goal is numbers that hold up to scrutiny: open loop, no coordinated omission, competitors
set up the way their own docs recommend, and raw data published.

### 6.1 Load generation

- **A new open-loop generator** in `simoom-bench`:
  - event-driven (it runs on simoom-rt itself);
  - each connection follows a fixed-rate or Poisson schedule;
  - latency is timed from the **intended** send time, as wrk2 does;
  - HdrHistogram-format logs.
  - It must reach more than 3x the server's expected peak across the load nodes, at under 60%
    CPU on each.
- **Cross-checks** on every target: wrk2 (HTTP/1.1), h2load (HTTP/2), and oha with latency
  correction. A disagreement of more than 5% blocks publication until explained.
- **The existing closed-loop `loadgen-remote`** is also run at 64, 256 and 1024 connections,
  for continuity with `docs/BENCHMARKS.md`.

### 6.2 Machines and hygiene

- Reuse `scripts/cloud-bench`: c-4 droplets (also c-8 and c-16 for scaling), **one server and
  three load nodes**, all in the same region and VPC.
- Servers swap roles. Each run is 15 s of warmup, then 5 × 30 s, three rounds; report the
  median and the spread.
- Record the kernel, the sysctls (`somaxconn`, `tcp_max_syn_backlog`, `net.core.busy_poll` left
  at default), the CPU governor and the NIC's packets-per-second (`sar -n DEV`) for each run.
  Flag any run where a load node passed 60% CPU or the NIC neared its packets-per-second limit.
- Pinned versions and checksums for every competitor (hard rule 4). Configs live in
  `bench/competitors/` and follow each project's own production-tuning guide.

### 6.3 Competitors

| group | servers |
|---|---|
| C/C++ servers | nginx, H2O, HAProxy (`http-request return`), Envoy (`direct_response`), OpenLiteSpeed, uWebSockets; Seastar httpd if it builds reasonably |
| Rust | hyper 1.x on tokio, axum, actix-web, may-minihttp, xitca-web, ntex, monoio's HTTP example; Pingora in the proxy scenario only |
| JVM / .NET / Go / Node | Netty (raw), Vert.x, Undertow, Kestrel, Go net/http, fasthttp, Caddy |
| reference | Apache Camel 4.23 (netty-http and platform-http), Cameleer `classic`, the raw threaded responder |

### 6.4 Scenarios

| id | scenario | why |
|---|---|---|
| S1 | GET, 13 B reply, no pipelining; 64 / 256 / 1k / 4k connections | the headline; one request in flight per connection, like real clients |
| S2 | the same with 16-deep pipelining | for comparison with TFB only; never the headline |
| S3 | POST with a 1 KB JSON body, 1 KB JSON reply | parsing the body, realistic APIs |
| S4 | 64 KB and 1 MB replies (from memory and from files) | `writev`, `sendfile`, `SEND_ZC`, kTLS |
| S5 | a new connection per request | accept path, TLS handshakes |
| S6 | 10k and 100k idle keep-alive connections | memory per connection |
| S7 | TLS 1.3: full and resumed handshakes per second; S1 and S4 over TLS | TLS cost, kTLS |
| S8 | HTTP/2: h2load, 100 streams per connection, 64 connections; and gRPC unary | HPACK and flow-control cost |
| S9 | overload at 2x the saturation rate | goodput, admitted p99, shedding |
| S10 | S1 at 50% load plus 10k slowloris and 1k slow-read attackers | DoS resistance while serving |
| S11 | Cameleer: fixed-reply route, REST JSON route, MCP session `tools/call` | what users actually see |

### 6.5 Metrics

- **Main metric:** the highest sustained rate whose open-loop p99 stays at or under 1 ms
  ("SLO throughput").
- **Latency:** p50, p99, p99.9 and max at 50%, 80% and 95% of the SLO throughput.
- **Cost per request:** CPU cycles (`perf stat`), syscalls (`strace -c` or bpftrace), context
  switches.
- **Footprint:** peak RSS, RSS per idle connection, stripped binary size, cold start.
- **Publication:** raw HDR logs and the scripts are committed; the report is generated from
  them (the `summarize.py` pattern).

## 7. Security plan

### 7.1 Default limits

Every limit is configurable. Exceeding one gives a specific status code and a counter.

| limit | default |
|---|---|
| request line | 8 KB |
| request head in total | 16 KB |
| header count | 100 |
| single header line | 8 KB |
| body | 10 MB, configurable per route; `Content-Length` checked before reading |
| deadline for the whole head | 10 s |
| keep-alive idle timeout | 15 s (the current Cameleer default) |
| minimum body rate | 1 KB/s after a 5 s grace period |
| write deadline | 30 s, with a minimum client read rate |
| requests per keep-alive connection | unlimited by default (the classic server's 1000 cap existed because of threads) |
| HTTP/2 concurrent streams with handler work running | 100 |
| HTTP/2 header list | 16 KB, CONTINUATION included |
| HTTP/2 HPACK table | 4096 |
| HTTP/2 RST_STREAM (received and sent) | 200 per 10 s window per connection; more gives GOAWAY |
| HTTP/2 PING, SETTINGS, empty DATA, WINDOW_UPDATE | each with its own budget per window (`Limits::h2_frame_budgets`) |
| stall watchdog | `inline_budget` 1 ms of CPU; `stalls_before_offload` 5 within `stall_window` 1 s; back inline after `stall_recovery` 64 fast calls (doubling each time) |
| admission control (`shed_lag`) | off (`None`; no value tried, 0.5 to 5 ms, avoided false sheds at normal load and helped under overload) |
| connections | per loop, in total, and optionally per IP |

### 7.2 Unsafe budget and memory safety

- `unsafe` is allowed only in `simoom-sys`; every other crate has `#![forbid(unsafe_code)]`.
  The target is **at most 150 `unsafe` blocks at 1.0**, each with a `SAFETY:` comment. CI
  tracks the count.
- Miri on everything except `simoom-sys`.
- ASan and TSan in nightly CI on `simoom-sys` and `simoom-rt`.
- Stress tests for the io_uring ring code: millions of operations with random cancellation.

### 7.3 Fuzzing (needs an owner decision)

- **Option F1 (recommended): a dev-only exception to the std-only rule.** A `fuzz/` directory
  outside the workspace that uses `cargo-fuzz` and `libfuzzer-sys`. It is never published and
  never in a shipped crate's dependency tree. It gives the fastest start and OSS-Fuzz
  eligibility.
- **Option F2: a std-only fuzzer.** Compile the harness with SanitizerCoverage
  (`-C llvm-args=-sanitizer-coverage-trace-pc-guard` plus `-C passes=sancov-module`; some
  flags may need nightly). Implement the `__sanitizer_cov_trace_pc_guard` callbacks in Rust,
  then write a mutation engine with a corpus and minimization, about 1.5–2k lines. It has no
  dependencies but takes 2–3 weeks and will be weaker than libFuzzer.

**Targets, either way:**

1. The HTTP/1 request-stream parser, with every input split at arbitrary points: the parse must
   be the same however the bytes arrive.
2. The chunked decoder.
3. Every HTTP/2 frame decoder, the HPACK decoder (with an encoder round trip), and the
   connection state machine driven by a frame sequence.
4. The TLS record layer and handshake, through the sans-io API.
5. The whole server through a simulated socket: reads, writes, timeouts and close events, with
   the invariants checked (no panic, bounded memory, limits enforced).
6. **A differential target:** simoom's parser against a small, slow reference parser written
   straight from the RFC 9112 ABNF. Any difference in the length or the accept/reject decision
   is a failure.
7. **An external differential test** with **HTTP Garden**: simoom added as a server and as a
   proxy origin, run nightly. Every discrepancy is triaged, and one that could cause desync
   blocks a release.

**Conformance:**

- h2spec at 100%;
- reproducers for CVE-2019-9511 to 9518, CVE-2023-44487 (Rapid Reset), CONTINUATION flood
  (VU#421644) and CVE-2025-8671 (MadeYouReset), kept as hermetic tests;
- the smuggling corpus from T-Reqs and the "HTTP/1.1 Must Die" toolkit as regression tests.

### 7.4 TLS

- Constant time: hardware AES-GCM (constant time by construction), bitsliced as the fallback,
  `ct_eq` everywhere.
- dudect-style timing tests in nightly CI for the AES, GHASH, X25519 and P-256 paths.
- Never disable verification (hard rule 4).
- 0-RTT off.

### 7.5 Audit

Before 1.0: an external review of `simoom-sys`, the HTTP/1 and HTTP/2 parsers, and the
`cameleer-tls` changes. This overlaps STATUS.md todo 5, so do both in one engagement. Budget and
vendor are the owner's call; nothing is to be signed up for automatically.

## 8. Milestones and measurable targets

**Reference numbers** (c-4, 4 vCPUs): raw threaded responder 166k req/s, Cameleer 113k (p99
3.4 ms, 17 MB), Camel 67.7k. "Engineer-weeks" assumes one experienced engineer working with
agents. Targets are measured with §6 (open loop) unless marked closed loop.

| # | milestone | effort | exit targets |
|---|---|---|---|
| **M0** | **Measurement spike (go/no-go)** | 2 weeks | the open-loop load generator reaches at least 1.5M req/s over 3 load nodes. A raw epoll responder with a loop per core: **at least 330k req/s SLO throughput (2x threaded)**. Baselines measured for nginx, H2O, actix-web, hyper, may-minihttp, fasthttp and Netty on the same droplets. **Gate:** if raw epoll is below 2x, and nginx and H2O show no more headroom, stop (option A). |
| M1 | Runtime and HTTP/1.1 on Linux epoll, Service API, offload pool, limits, strict parser, fuzzing harness | 6 weeks | S1: **at least 450k req/s SLO throughput** (2.7x threaded), within 10% of the best C server on the same droplets, aiming to match or beat it. **p99 at or under 0.5 ms at 80% load.** User-space memory per idle connection **at most 1 KB**; 100k idle connections in **at most 150 MB** RSS. Stripped hello-world binary **at most 400 KB**. All fuzz targets running; zero findings open. |
| M2 | io_uring (opt-in), Windows IOCP, macOS kqueue | 4 weeks | io_uring at least 10% more SLO throughput than epoll with p99 no worse, or it stays off by default. Windows: at least 2x the classic engine with the load generator on another host. All OS back ends pass the same suite. |
| M3 | Cameleer integration (engine switch, platform-http and the other shared-server consumers, router, MCP streams) | 4 weeks | fixed-reply route **at least 340k req/s** (3x today, 5x Camel); **p99 at or under 1 ms at 80% load** (today 3.4 ms closed loop); RSS **at most 20 MB**. MCP session `tools/call` **at least 75k calls/s** (1.8x today, 3.3x Camel). Hermetic suite, live, official-client and simulator tiers green with `simoom` as the default engine. |
| M4 | TLS: sans-io API and AES-NI/PCLMUL in `cameleer-tls`, the adapter, kTLS | 5 weeks | AES-128-GCM **at least 3 GB/s per core** in user space; S1 over TLS keep-alive at least 80% of cleartext. Full handshakes per second at least 0.7x nginx with OpenSSL (OpenSSL's assembly for elliptic curves is hard to beat; stated honestly). kTLS `sendfile` S4 within 10% of cleartext. |
| M5 | HTTP/2 sans-io, h2c and h2, gRPC moved, DoS suite | 6 weeks | h2spec 100%; every HTTP/2 CVE reproducer passes. h2load S8 within 10% of H2O and nginx, and **at least 3x today's `cameleer-grpc` server**. A Rapid Reset or MadeYouReset flood at line rate leaves legitimate p99 within 2x. |
| M6 | HTTP/3 and QUIC (in the first release, §0) | 8–12 weeks | QUIC Interop Runner server cases pass against curl/ngtcp2, quiche and quic-go clients. h2load `--h3` within 10% of H2O, or better. The full build stays within the 1 MB budget. |
| M7 | Hardening and 1.0: audit, 30 CPU-days of fuzzing with no new crash, HTTP Garden clean, docs, a minimal example binary (no static files or proxy, §0) | 4 weeks | no open high or critical findings; overload test S9 passes (admitted p99 within 2x of the 80%-load p99, goodput at least 90% of peak); slowloris test S10 passes (legitimate p99 within 1.5x) |

**Total to 1.0 without HTTP/3:** about 31 engineer-weeks. The first useful result for Cameleer
(M3) comes at about week 16. Milestones M2, M4 and M5 can run in parallel worktrees after M1,
because they touch different crates.

## 9. Risks

| risk | likelihood | impact | mitigation |
|---|---|---|---|
| The VM network or packets-per-second rate, not the server, is the ceiling, so no several-times gain can be shown on c-4 | medium | high | the M0 gate; measure nginx and H2O on the same droplets; scale to c-8 and c-16; report SLO throughput, CPU per request and memory, which improve even when throughput is capped |
| The load generator becomes the bottleneck | high without action | high | 3 load nodes, an event-driven generator, cross-checks with wrk2 and h2load, a 60% CPU rule |
| io_uring unavailable (seccomp, sysctl, old kernels) or a kernel CVE | high in containers | low | epoll is the default and must win on its own; io_uring is opt-in, probed, with fallback |
| An inline handler blocks a loop and the tail suffers | medium | high | offload by default for Cameleer routes; inline only when proven; stall watchdog; per-loop stall metric |
| Strict parsing rejects real clients | medium | medium | follow RFC 9112 exactly; a compatibility corpus from curl, browsers, Java, Go, Python and .NET clients; a documented `lenient` option only for the few cases RFC 9112 allows, off by default |
| An HTTP/2 DoS variant not yet known | medium | high | work-based accounting rather than state-based; generic budgets for control frames; fuzzing of the state machine; fast patch releases |
| TLS performance gap against OpenSSL in elliptic curves | high | medium | kTLS and AES-NI cover bulk data; resumption cuts full handshakes; accept 0.7x on full handshakes and say so |
| A second repository doubles the maintenance (releases, CI, security response) | certain | medium | a small, focused scope; shared CI templates; one security contact; Cameleer as the first user, catching regressions |
| Fuzzing under the std-only rule | certain | medium | the owner decides F1 or F2 (§7.3) |
| Scope creep (proxy, HTTP/3, WebSocket compression) | medium | medium | 1.0 scope fixed to §2.6–2.8 and the standalone binary's static files; everything else after 1.0 |

## 10. The five numbers to beat

Expected, with the evidence for each. All are on c-4 droplets with the method in §6.

| # | metric | today | target | evidence |
|---|---|---:|---:|---|
| 1 | Cameleer fixed-reply route, SLO throughput | 112,910 req/s (closed loop) | **at least 340k req/s**, at least 5x Camel's 67,682 | CPU budget: 24 µs per request today against about 8 µs for event-loop servers; the gap is 64-thread scheduling, wakeups and IPIs, which perf shows as a flat, scheduler-dominated profile (research.md §1). The raw core target of at least 450k leaves room for Cameleer's per-request cost. Unproven until M0. |
| 2 | p99 at 80% load | 3.4 ms | **at most 1 ms** (route), **at most 0.5 ms** (raw) | the raw threaded responder already shows 0.47 ms; queueing math puts the per-core tail at microseconds when S is small (research.md §3); slow routes go to the M/M/c offload pool, about 3x better p99 than partitioned queues |
| 3 | memory per idle keep-alive connection | one thread each (stack, scheduler state) | **at most 1 KB user space**; 100k idle in at most 150 MB | no buffer held while idle (the nginx design; provided-buffer rings on io_uring); a connection struct of about 200–400 bytes |
| 4 | stripped HTTP/1.1 server binary | n/a (tokio, hyper and rustls is typically 1–3 MB; actix with TLS 3–6 MB; nginx 1.2 MB plus OpenSSL) | **at most 400 KB** | std-only with no dependency tree; a sans-io parser plus one back end. To be measured in M0/M1 against the competitors' own builds. |
| 5 | MCP session `tools/call` | 41,620 calls/s | **at least 75k calls/s**, at least 3.3x Camel's 22,458 | the envelope costs 3–6 µs per call (`docs/BENCHMARKS.md`), well under the HTTP cost per request it rides on; removing the threaded server's overhead and adding streaming replies is the main lever |

## 11. Owner decisions

Decided on 2026-11-07 (see §0):

1. Build. Measurements run alongside the build, not as a gate.
2. Apache-2.0; a private repository `pmsudhi/simoom`; releases by git tag.
3. Fuzzing: F2, std-only.
4. TLS is owned by simoom (`simoom-tls`); `cameleer-tls` is unchanged.
5. HTTP/3 is in the first release.

Still open: a budget for the external audit before 1.0.
