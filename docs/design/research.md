# HTTP server research

_Internal design note, 2026-11-07. Written to support the build/adapt decision in
[plan.md](plan.md). Not part of the published docs._

## How to read this note

- **[measured here]** means a number measured on Cameleer's own benchmark machines (the
  2026-11-06 DigitalOcean run, `docs/BENCHMARKS.md`, `benchmarks/analysis.md`).
- **[vendor]** means a number published by the project or company that makes the product.
  Treat it as a claim, not a measurement.
- **[third party]** means a number from an independent write-up, paper or thesis.
- **[checked 2026-11-07]** means I looked the source up during this research. Sources without
  the tag are standard references (RFCs, papers, kernel docs, well-known advisories) cited from
  prior knowledge with their canonical URL. Check those before quoting them outside this
  repository.
- Numbers from different machines, rounds or load models can't be compared directly. The
  comparison table in section 2 gives orders of magnitude, not a ranking.

## 1. Starting point: what Cameleer measures today

On DigitalOcean `c-4` droplets (4 dedicated vCPUs on a Xeon Platinum 8280, Ubuntu 24.04), with
64 keep-alive connections and a closed-loop load generator (`cameleer-bench loadgen-remote`)
running on another droplet **[measured here]**:

| side | req/s | p99 | memory |
|---|---:|---:|---:|
| do-nothing Rust responder, thread per connection (`raw-http threads`) | 166,374 | 0.47 ms | n/a |
| do-nothing Rust responder, single-threaded `poll` | 124,572 | n/a | n/a |
| Cameleer fixed-reply route (`cameleer-http`, thread pool) | 112,910 | 3.4 ms | 17 MB |
| Apache Camel 4.23 on Netty (JVM) | 67,682 | n/a | n/a |

What the profiles showed: `strace` saw one `recv` and one `send` per request, so the syscall
count is already at the floor for a readiness model. `perf` showed a flat profile, dominated by
the kernel scheduling 64 threads on 4 vCPUs.

Three facts about the current code matter for the design:

- `crates/cameleer-http/src/server.rs`: one accept thread, connections served by
  `cameleer_core::executor::ThreadPool`, blocking `std::net` I/O, keep-alive for up to 1000
  requests per connection, and a keep-alive connection closed once the pool is saturated.
- `crates/cameleer-grpc/src/h2/conn.rs`: HTTP/2 uses one reader thread and one writer thread
  per connection, and application threads block on condition variables. It is not sans-io, so
  an event loop can't drive it as it stands.
- `crates/cameleer-tls`: a TLS 1.3/1.2 implementation that wraps `Read`/`Write` streams (no
  sans-io record API). AES-GCM is constant time through a bitsliced S-box and branch-free
  GHASH (`crypto/aes.rs`), with **no AES-NI or PCLMULQDQ path**. That is safe, but slow in
  bulk: hardware AES-GCM reaches several GB/s per core.

### What these numbers already say (Little's law)

In a closed loop with N connections, throughput X and mean latency R are tied: **N = X · R**
(Little 1961). So:

- the raw responder at 166k req/s has R = 64 / 166,374 = **385 µs**;
- Cameleer at 112,910 req/s has R = **567 µs**.

The network round trip between two VMs, plus the load generator's own per-request cost, sets a
floor under R. If that floor is about 150 µs, then **64 connections can't exceed about 430k
req/s, whatever the server does.** Two consequences follow:

1. A several-times gain can't be demonstrated at 64 connections alone. The method has to sweep
   connections (64 to 4096) and use an open-loop, fixed-rate load. See section 6.
2. The load generator (one thread per connection, on one 4-vCPU droplet) may already be part of
   the ceiling. Before believing any number above about 200k req/s, check its CPU use and use
   several load nodes.

### CPU budget

Four vCPUs at 166k req/s is about **24 µs of CPU per request**, kernel included. For tiny
keep-alive requests that aren't pipelined, a Linux TCP stack typically costs 3–8 µs per
request-response in softirq and syscall work. That leaves the do-nothing threaded server about
15 µs per request of avoidable overhead: context switches, wakeups and inter-processor
interrupts (IPIs). These are much dearer in a VM, where waking an idle vCPU takes a VM exit. An
event loop per core removes most of it. The plan's estimate is **400–600k req/s on the same
4 vCPUs**, which is 8–10 µs per request. The plan makes Milestone 0 prove this before anything
else is built.

## 2. The fastest servers and stacks

### Comparison table

Key to the columns:

- **Arch:** TPC = thread per core with shared-nothing connections; WS = work-stealing
  scheduler; ELT = one event loop per thread (connections pinned); MP = multi-process; GPC =
  goroutine or green thread per connection.
- **I/O:** the readiness or completion API used.

| server / stack | lang | arch | I/O on Linux | other OS | H1 / H2 / H3 | TLS | notes on performance and size |
|---|---|---|---|---|---|---|---|
| nginx | C | MP, ELT per worker | epoll (ET), `SO_REUSEPORT` optional, thread pool for files | kqueue; Windows poor (select) | ✓ / ✓ / ✓ (1.25+) | OpenSSL family; kTLS with `sendfile` (1.21.4+) | reference for low memory per connection (about 2.5 KB idle on the event side) |
| H2O | C | ELT, multi-thread | epoll | kqueue | ✓ / ✓ / ✓ (quicly) | picotls / OpenSSL | picohttpparser (SSE4.2), fast HPACK; base of Fastly's edge |
| Envoy | C++ | ELT (worker threads pinned to connections) | libevent / epoll | kqueue, Windows | ✓ / ✓ / ✓ (QUICHE) | BoringSSL | feature-rich proxy; large binary (tens of MB); heavy filter chain per request |
| HAProxy | C | ELT with thread groups (2.7+) | epoll | kqueue | ✓ / ✓ / ✓ (2.6+) | OpenSSL / AWS-LC / quictls | strict, fast parser; best smuggling record of the C proxies |
| Caddy | Go | GPC on the netpoller | epoll | all | ✓ / ✓ / ✓ (quic-go) | Go crypto/tls | convenience over speed; Go net/http cost per request |
| LiteSpeed / OpenLiteSpeed | C | MP event-driven | epoll | kqueue | ✓ / ✓ / ✓ (LSQUIC) | BoringSSL | vendor benchmarks only **[vendor]** |
| Seastar (ScyllaDB) | C++ | TPC, shared-nothing, memory per core | epoll, linux-aio, io_uring reactors, or DPDK with its own TCP | Linux only | ✓ / partial / ✗ | GnuTLS | the canonical TPC design; futures and continuations |
| Netty / Vert.x | Java | ELT (EventLoopGroup) | native epoll; io_uring transport (core in 4.2) | kqueue, NIO | ✓ / ✓ / ✓ (incubator) | JDK / BoringSSL (tcnative) | Camel's netty-http: 67.7k req/s here **[measured here]** |
| Undertow | Java | XNIO I/O threads plus worker pool | epoll via NIO | NIO | ✓ / ✓ / ✗ | JDK | |
| ASP.NET Core Kestrel | C# | thread pool with socket engine | epoll | IOCP, kqueue | ✓ / ✓ / ✓ (msquic) | SChannel / OpenSSL | TFB R23 plaintext leader, about 27.5M req/s with pipelining **[third party, checked 2026-11-07]** |
| Go net/http | Go | GPC | netpoller (epoll) | all | ✓ / ✓ / ✗ (x/net) | crypto/tls | many HTTP/2 CVEs (see section 5) |
| fasthttp | Go | worker pool, zero-alloc | netpoller | all | ✓ / ✗ / ✗ | crypto/tls | reuses buffers and request objects |
| uWebSockets / uSockets | C++ | ELT | epoll | kqueue, libuv | ✓ / ✗ / experimental | OpenSSL | among the fastest H1 and WebSocket servers |
| hyper (+ axum) | Rust | WS (tokio multi-thread) | mio / epoll | kqueue, IOCP (AFD poll) | ✓ / ✓ (h2 crate) / ✗ (h3 separate) | rustls / native-tls | the Rust default; several smuggling and HTTP/2 advisories (section 5) |
| actix-web | Rust | TPC-ish: N single-threaded arbiters, accept thread hands off | tokio current-thread per arbiter | all | ✓ / ✓ / ✗ | rustls / OpenSSL | top-tier TFB results for a full framework |
| may-minihttp | Rust | stackful coroutines with WS | epoll | all | ✓ / ✗ / ✗ | ✗ | historically near the top of TFB plaintext; minimal, protocol-correct only for well-behaved clients **[third party, checked 2026-11-07]** |
| xitca-web | Rust | TPC; optional io_uring | epoll / io_uring | all | ✓ / ✓ / ✓ | rustls / OpenSSL | top-tier TFB; small dependency tree |
| monoio (ByteDance) | Rust | TPC | io_uring, epoll fallback | kqueue | runtime only | n/a | ownership ("rent") buffer API for completion I/O; vendor benchmarks show gains growing with core count **[vendor]** |
| glommio (Datadog) | Rust | TPC, three rings per thread (main, latency, poll) | io_uring only | ✗ | runtime only | n/a | influential design; maintenance has slowed |
| tokio-uring | Rust | io_uring runtime per thread | io_uring | ✗ | runtime only | n/a | experimental, not production-maintained |
| compio | Rust | TPC, completion-based | io_uring, polling fallback | IOCP, kqueue | runtime only | n/a | closest existing design to the cross-OS completion abstraction proposed in the plan |
| ntex | Rust | actix fork, pluggable runtime (tokio, compio, own `neon`) | epoll / io_uring | all | ✓ / ✓ / ✗ | rustls / OpenSSL | |
| Pingora (Cloudflare) | Rust | WS (tokio), threads over processes to share connection pools | epoll | Unix | ✓ / ✓ / ✗ | OpenSSL / BoringSSL / rustls / s2n | serves over 1 trillion requests a day using about a third of the CPU and memory of the nginx setup it replaced; connection reuse went from 87.1% to 99.92% **[vendor, checked 2026-11-07]** |

Sources for the table: project repositories and docs (nginx.org, h2o.examp1e.net,
envoyproxy.io, haproxy.org, caddyserver.com, seastar.io, netty.io, github.com/hyperium/hyper,
actix.rs, github.com/xudong-963/may-minihttp, github.com/HFQR/xitca-web,
github.com/bytedance/monoio, github.com/DataDog/glommio, github.com/compio-rs/compio,
github.com/ntex-rs/ntex), and Cloudflare, "How we built Pingora, the proxy that connects
Cloudflare to the Internet" (2022-09-14),
https://blog.cloudflare.com/how-we-built-pingora-the-proxy-that-connects-cloudflare-to-the-internet/
**[checked 2026-11-07]**.

### TechEmpower Framework Benchmarks

- **Round 23** (published 2025-02-24) ran on new hardware and network, and TechEmpower notes
  that network-bound results rose across the board. So R23 can't be compared directly with
  earlier rounds **[checked 2026-11-07]**: https://www.techempower.com/blog/tag/tfb/.
- The plaintext leader was ASP.NET Core at about 27.5M req/s **[third party, checked
  2026-11-07]**: https://dev.to/insight105/on-web-framework-performance-a-net-10-reality-check-4ep5.
  The official data is at https://www.techempower.com/benchmarks/#section=data-r23. Continuous
  runs are at https://tfb-status.techempower.com.
- **Caveat that matters here:** TFB plaintext uses HTTP pipelining (16 requests in flight per
  connection) and thousands of connections. That measures the parser and how writes are
  batched, not a request-response round trip. Cameleer's workload (one request in flight per
  connection, a real route behind it) is closer to TFB's JSON test without pipelining. The plan
  reports pipelined results separately and never leads with them.

### Lessons from the designs

1. **Every top performer pins a connection to one event loop on one thread**: nginx, H2O,
   HAProxy, Envoy, Seastar, actix, xitca, monoio and uWS. Work-stealing (hyper on tokio,
   Pingora) wins when the work per request is uneven and pools are shared; Pingora chose it
   explicitly for upstream connection-pool reuse. That matters for a proxy, much less for a
   route that answers.
2. **The parser and the response path are zero-copy and allocation-free** in H2O
   (picohttpparser), fasthttp and uWS. H2O and nginx refresh the `Date` header once a second
   per thread instead of formatting it per request.
3. **io_uring is used by the newest Rust runtimes** (monoio, glommio, compio, xitca's option)
   **and by Netty 4.2, but by none of the big C servers by default.** nginx and HAProxy stay on
   epoll. io_uring's advantage is real but modest for small RPCs (section 3), and it has a
   security and availability cost (section 5).
4. **Binary size:** a Rust server on tokio, hyper and rustls is typically 1–3 MB stripped, and
   actix-web with TLS around 3–6 MB. nginx is about 1.2 MB plus OpenSSL. Envoy is tens of MB.
   These are typical figures from public builds, not measured here; the plan measures them in
   Milestone 0.

## 3. Papers and mathematics

### Queueing: one shared queue against a queue per core

Take c cores, each with service rate μ (service time S = 1/μ), Poisson arrivals and
utilization ρ.

- **Partitioned (thread per core, each a separate M/M/1)**: mean response time is
  S / (1 − ρ), and the response time is exponential with rate μ(1 − ρ). So
  **p99 = ln(100) · S / (1 − ρ)**.
- **Shared queue (M/M/c)**: Erlang C gives the probability of waiting.

Worked numbers for c = 4 and ρ = 0.8, computed for this note:

| model | mean response | p99 response |
|---|---:|---:|
| 4 × M/M/1 (strict thread per core) | 5.0 S | 23.0 S |
| M/M/4 (one shared queue) | 1.75 S | 6.9 S |

For M/M/4: Erlang C = 0.596, mean wait 0.746 S, and P(T > t) = 2.982e^(−0.8t) − 1.982e^(−t)
with t in units of S.

So **a strict shared-nothing design is about 3x worse at the tail at 80% load.** But the
absolute cost depends on S:

- For a fixed reply, S ≈ 5 µs, so 23 S ≈ 115 µs, well below the network round trip.
- For a route with a 2 ms database call, the partitioned tail (46 ms) is unacceptable.

This is the main argument for a **hybrid design**: handle the HTTP framing on the per-core loop
(tiny S, which partitions well), and send slow or uneven handlers to a shared pool (the M/M/c
regime). The same conclusion appears in the systems literature:

- ZygOS (Prekas et al., SOSP 2017) adds work stealing to shared-nothing dataplanes to fix the
  tail.
- Shinjuku (Kaffes et al., NSDI 2019) adds preemption for dispersed service times.
- Shenango (Ousterhout et al., NSDI 2019) and Caladan (Fried et al., OSDI 2020) reallocate
  cores at microsecond scale.
- "The Tail at Scale" (Dean and Barroso, CACM 2013) explains why tails dominate at fan-out.
- "Tales of the Tail" (Li et al., SoCC 2014) measures the effects of interrupts, NUMA and
  scheduling on the tail.
- Balls-into-bins with **two choices** (Mitzenmacher, "The Power of Two Choices in Randomized
  Load Balancing", IEEE TPDS 2001) cuts maximum load from Θ(log n / log log n) to
  Θ(log log n). That is useful when assigning accepted connections to loops by load rather than
  by hash.

### C10K, C10M and kernel bypass

- **C10K:** Dan Kegel's "The C10K problem" (1999–2014, http://www.kegel.com/c10k.html) argues
  for event-driven servers over thread-per-connection. Banga, Mogul and Druschel, "A Scalable
  and Explicit Event Delivery Mechanism for UNIX" (USENIX ATC 1999), is the forerunner of
  epoll.
- **C10M:** Robert Graham's talk (Shmoocon 2013) argues for taking the kernel out of the data
  path. Papers in that line:
  - mTCP (Jeong et al., NSDI 2014): user-space TCP per core.
  - IX (Belay et al., OSDI 2014) and Arrakis (Peter et al., OSDI 2014): protected dataplanes.
  - MegaPipe (Han et al., OSDI 2012): batched, partitioned socket API.
  - Affinity-Accept (Pesterev et al., EuroSys 2012): keeping a connection on one core gives
    large gains from cache locality.
  - Snap (Marty et al., SOSP 2019): Google's microkernel-style network stack.
  - Demikernel (Zhang et al., SOSP 2021): a portable kernel-bypass library OS.
  - Junction (Fried et al., NSDI 2024).
- **"Understanding Host Network Stack Overheads"** (Cai et al., SIGCOMM 2021): at high
  bandwidth the data copy dominates; for small messages the cost per packet and per syscall
  dominates, and cache and NUMA misses matter.
- **When kernel bypass pays:** above roughly 1–2M small requests a second per machine, or
  when the target is single-digit microseconds. That needs dedicated NIC queues: SR-IOV for
  DPDK, or AF_XDP in native driver mode.
  - Cloud VMs like the DigitalOcean droplets expose virtio-net with no SR-IOV for customers,
    and DPDK needs its own TCP stack (Seastar's or F-Stack's). That is a very large, risky
    surface.
  - **Conclusion: kernel bypass is out of scope.** It can't be measured on the target
    machines and would not survive the std-only rule at reasonable cost.
- **io_uring zero-copy receive** (zcrx, merged in Linux 6.15, March 2025) keeps the kernel TCP
  stack but needs header/data split and flow steering on the NIC. It is again unavailable on
  virtio VMs. A demo saturated a 200G link from one core **[vendor demo, checked 2026-11-07]**:
  https://www.phoronix.com/news/Linux-6.15-IO_uring and the NetDev 0x1A talk
  https://netdevconf.info/0x1A/sessions/talk/io_uring-zcrx-progress-and-next-steps.html.
  Bulk transfer only; out of scope for 1.0.

### io_uring against epoll: what has been measured

The evidence is mixed. The gains come from batching and fewer wakeups, not from the API alone.

- Edinburgh MSc project (2023): an HTTP benchmark with io_uring up to **33% more throughput**
  than epoll across response sizes and queue depths **[third party, checked 2026-11-07]**:
  https://project-archive.inf.ed.ac.uk/msc/20236779/msc_proj.pdf.
- Netty on an 8-core box with Linux 6.6: io_uring gave **about 6.5% more throughput** at the
  same thread count, with about twice the efficiency per thread (multishot receive plus a buffer
  ring). But **epoll had up to 21% lower p99** **[third party, checked 2026-11-07]**:
  https://www.besthub.dev/articles/does-netty-s-io-uring-make-the-2-cpu-thread-rule-obsolete-3358ba3ca620.
- Single-threaded echo servers with multishot accept and recv: about equal at 256
  connections; io_uring ahead at 512 and 1024 connections, where the epoll server stalled. The
  author calls the benchmark unscientific (loopback) **[third party, checked 2026-11-07]**:
  https://github.com/joakimthun/io-uring-echo-server.
- A loopback study on kernel 6.17 found results close between the two, with the gains depending
  on the threading and continuation model **[third party, checked 2026-11-07]**:
  https://mda2av.github.io/zerg/blog/io-uring-minima-part-6.html.
- Primary references:
  - Jens Axboe, "Efficient IO with io_uring" (2019), https://kernel.dk/io_uring.pdf.
  - The `io_uring_setup(2)`, `io_uring_enter(2)` and `io_uring_register(2)` man pages
    (liburing project).
  - Feature dates by kernel version:
    - multishot accept: 5.19
    - multishot recv and ring-provided buffers: 6.0
    - `SEND_ZC` (zero-copy send): 6.0
    - `IORING_SETUP_SINGLE_ISSUER` and `DEFER_TASKRUN`: 6.1
    - `kernel.io_uring_disabled` sysctl: 6.6
    - bundles (one recv or send for many buffers): 6.10

**Conclusion for this design:** epoll is the baseline and must already deliver most of the
gain. io_uring is an optional back end worth 0–30% more throughput and fewer syscalls per batch.
Its tail can be worse, so measure it; don't assume it.

### Steering and locality

- **`SO_REUSEPORT`** (Linux 3.9): one listening socket per loop, so the kernel hashes
  connections across loops and no accept lock is needed.
- **`SO_ATTACH_REUSEPORT_CBPF` / `EBPF`**: a BPF program picks the socket. The common program
  returns the current CPU, so the loop that runs on the CPU taking the NIC interrupt accepts the
  connection.
- **`SO_INCOMING_CPU`**: reads which CPU handled the connection's packets.

Together these give receive-side affinity: the same core runs the softirq and the application.
See Affinity-Accept, the nginx "Socket Sharding" blog (2015), and the kernel
`Documentation/networking/scaling.rst` (RSS, RPS, RFS, XPS).

On a 4-vCPU VM with one virtio queue, steering matters less than on bare metal. Measure it.

- **Busy polling:** `SO_BUSY_POLL`, plus per-epoll busy-poll parameters through the
  `EPIOCSPARAMS` ioctl (Linux 6.9), trade CPU for lower latency. It is useful for the tail on
  idle VMs, where interrupt-driven wakeups cause VM exits. Off by default; measured in
  Milestone 1.

### Coordinated omission and how to measure

- Gil Tene, "How NOT to Measure Latency" (talks 2013–2016) and HdrHistogram
  (http://hdrhistogram.org). A closed-loop generator stops sending while the server stalls,
  so the stall shows up as one slow sample instead of all the requests that should have been
  sent. The fix is to send at a fixed rate and time each request from its **intended** send
  time.
  - wrk2 (https://github.com/giltene/wrk2) does this.
  - So do Vegeta, k6's constant-arrival-rate executor, and `oha --latency-correction`.
- Schroeder, Wierman and Harchol-Balter, "Open Versus Closed: A Cautionary Tale" (NSDI 2006):
  closed and open systems give very different response times at the same load, and
  scheduling-policy conclusions can flip between them.
- `cameleer-bench`'s driver and `loadgen-remote` are closed loop
  (`crates/cameleer-bench/src/driver.rs`). The histogram is HdrHistogram-like (64 sub-buckets
  per power of two). That is good, but it inherits coordinated omission. The plan adds an
  open-loop mode.

### Cache and NUMA

Keep each connection's state, buffers and the handler's working set on one core, and allocate
buffers from a pool local to that core. Seastar's per-core memory, Affinity-Accept and
"Tales of the Tail" all show cross-core cache traffic in the tail. The droplets are single
socket, so NUMA doesn't apply there, but the design shouldn't block NUMA-aware pools on larger
machines.

## 4. Techniques

- **Zero-allocation, SIMD parsing.**
  - picohttpparser (H2O) uses SSE4.2 `PCMPESTRI` to find delimiters in 16 bytes at a time:
    https://github.com/h2o/picohttpparser.
  - httparse uses SSE4.2 and AVX2 with runtime detection: https://github.com/seanmonstar/httparse.
  - simdjson (Langdale and Lemire, "Parsing Gigabytes of JSON per Second", VLDB Journal 2019)
    shows the general method: classify bytes in bulk, then walk an index.
  - **All of this is possible std-only** through `core::arch` and `is_x86_feature_detected!`
    (`std::arch::is_aarch64_feature_detected!` for NEON). The parser returns slices into the
    receive buffer, never owned strings.
- **Buffer pools.** Size-classed slabs per loop, plus a provided-buffer ring for io_uring
  multishot recv. An idle connection holds **no** receive buffer; it borrows one when data
  arrives, as nginx does with its lazy buffers. That is what keeps memory per idle connection
  in the hundreds of bytes.
- **Vectored and batched writes.**
  - `writev` / `WSASend` with several buffers: the head is a pre-serialized status line plus
    cached headers, then the body.
  - A per-loop write batch that flushes once per loop iteration. That gives pipelining for free
    and, on io_uring, one `io_uring_enter` for all sends.
  - `TCP_NODELAY` on, with corking (`TCP_CORK` / `MSG_MORE`) only for multi-part responses.
- **Response caching.** Cache serialized response heads for fixed routes: status, content
  type, content length and the `Date` slot. Refresh `Date` once a second per loop.
- **Zero-copy send.** `sendfile` and `splice` for files. `MSG_ZEROCOPY` and io_uring `SEND_ZC`
  pay only above about 10 KB per send, because completion notifications cost something (kernel
  `Documentation/networking/msg_zerocopy.rst`). Never use them for small responses.
- **kTLS** (kernel `Documentation/networking/tls.rst`): run the handshake in user space, then
  pass the traffic keys to the kernel with `setsockopt(SOL_TLS, TLS_TX/TLS_RX)`. After that,
  `send`, `sendfile` and `splice` encrypt in the kernel with AES-NI. Netflix serves about
  400 Gb/s per box with FreeBSD kTLS plus `sendfile` (Drew Gallatin, "Serving Netflix Video at
  400Gb/s on FreeBSD", EuroBSDCon 2021). nginx supports it since 1.21.4 with
  `ssl_conf_command Options KTLS`. **For Cameleer, kTLS is a way to get hardware AES-GCM
  without the TLS crate needing AES-NI**, but key updates, renegotiation and alerts still need
  care, and on Windows the user-space path must be fast anyway. Also add an AES-NI and PCLMUL
  path to `cameleer-tls` through `std::arch` (std-only, constant time by construction).
- **HTTP/2 costs.**
  - HPACK: the dynamic table, Huffman coding, and the decoder's memory limit
    (`SETTINGS_HEADER_TABLE_SIZE`).
  - Flow control (RFC 9113 §5.2): WINDOW_UPDATE traffic. The window must be large enough for
    bandwidth times delay.
  - A frame per stream. h2load (nghttp2) is the standard benchmark tool.
  - For small RPCs, HTTP/2 multiplexing reduces connection count but costs more CPU per request
    than pipelined HTTP/1.1. Most servers measure 20–50% more CPU per request; to be confirmed
    in Milestone 5.
- **HTTP/3 and QUIC** (RFC 9000, 9001, 9002, 9114; QPACK RFC 9204):
  - User-space transport over UDP with loss recovery and congestion control (CUBIC, BBR).
  - GSO/GRO (`UDP_SEGMENT`, `UDP_GRO`) is essential for throughput (Cloudflare and Fastly blogs
    on QUIC performance, 2020–2022).
  - QUIC typically costs 2–3x the CPU of TCP+TLS for bulk transfer. For an embedded service
    server it matters mostly at the edge, which is not Cameleer's main deployment.
- **Backpressure and admission control.**
  - Bound everything: connections per loop, in-flight requests per connection, pending writes
    per connection (stop reading when the write queue passes a high-water mark), and the
    offload queue depth.
  - Under overload, shed early (accept and send 503, or drop accepts) instead of queueing.
  - Use CoDel-style queue delay targets (Nichols and Jacobson, "Controlling Queue Delay",
    ACM Queue 2012). Facebook's adaptive LIFO plus CoDel for server queues is described in
    "Fail at Scale" (Maurer, ACM Queue 2015).
  - Graceful overload keeps p99 for admitted requests flat while goodput plateaus, instead of
    collapsing.

## 5. Security

### Standards and parser strictness

- HTTP semantics RFC 9110, HTTP/1.1 RFC 9112, HTTP/2 RFC 9113, HPACK RFC 7541, HTTP/3 RFC 9114,
  QPACK RFC 9204.
- RFC 9112 §6.3 is the message-length algorithm. Reject a request that has both
  `Transfer-Encoding` and `Content-Length` (§6.1 allows rejecting it; a server must not forward
  it). Reject duplicate or differing `Content-Length` values. Reject any `Transfer-Encoding`
  other than a final `chunked`.
- Other required checks:
  - Reject bare CR.
  - Reject obs-fold (RFC 9112 §5.2: reject or replace with SP; rejecting is safer).
  - Reject whitespace between the field name and the colon (§5.1: must reject with 400).
  - Validate the field-name tchar set, the request-target form, and the chunk-size and
    chunk-extension grammar.

### Request smuggling and desync

- Watchfire (Linhart et al., 2005) first described request smuggling.
- James Kettle, "HTTP Desync Attacks" (Black Hat USA 2019), then "HTTP/2: The Sequel is Always
  Worse" (2021).
- Kettle, **"HTTP/1.1 Must Die: The Desync Endgame"** (Black Hat USA and DEF CON 33, August
  2025): smuggling is a protocol-level weakness. It covers 0.CL and Expect-based desyncs, the
  latter including CVE-2025-32094 on F5. Upstream HTTP/2 is the main mitigation, and HTTP/2-to-1
  downgrades bring the ambiguity back **[checked 2026-11-07]**:
  https://portswigger.net/research/http1-must-die.
- For an embedded server this means:
  - strict parsing;
  - `Expect: 100-continue` handled exactly per RFC 9110 §10.1.1;
  - closing the connection after any framing error;
  - never reusing a connection whose body wasn't fully consumed or rejected;
  - offering HTTP/2 (h2c prior knowledge for internal traffic) as the recommended upstream
    protocol.

### The HTTP/2 DoS family

- 2019 Netflix advisories, CVE-2019-9511 to 9518: data dribble, ping flood, resource loop, reset
  flood, settings flood, 0-length headers leak, internal data buffering.
- The 2016 HPACK bomb (CVE-2016-6581, Imperva's report "HTTP/2: In-depth analysis of the top
  four flaws").
- **Rapid Reset, CVE-2023-44487** (October 2023; Google, Cloudflare and AWS saw 398M, 201M and
  155M requests per second at peak). It affected nghttp2, Go, Netty, Envoy, hyper's h2 crate,
  Tomcat, Jetty and others.
- **CONTINUATION flood** (CERT/CC VU#421644, April 2024): unbounded header blocks. It affected
  nghttp2 (CVE-2024-28182), Apache httpd (CVE-2024-27316), Envoy (CVE-2024-27919), Go
  (CVE-2023-45288), Node.js (CVE-2024-27983) and others.
- **MadeYouReset, CVE-2025-8671** (2025-08-13, CERT/CC VU#767506): the client makes the
  *server* reset streams through malformed frames, so streams leave the concurrency count while
  their work continues. It bypasses Rapid Reset mitigations. Affected: Netty (CVE-2025-55163),
  Tomcat (CVE-2025-48989), F5 (CVE-2025-54500), H2O, swift-nio-http2, gRPC, Varnish and more
  **[checked 2026-11-07]**:
  https://www.theregister.com/2025/08/14/madeyoureset_http2_flaw_lets_attackers/.
- **Common defense:** count the *work* a stream started, not its open state, until the handler
  has actually finished. Rate-limit control frames per connection with a sliding window
  (RST_STREAM, sent and received; PING; SETTINGS; empty DATA; WINDOW_UPDATE). Cap header-block
  bytes across CONTINUATION frames. Send GOAWAY and close when a limit is exceeded.

### Slow attacks

- Slowloris (RSnake, 2009), slow POST (R-U-Dead-Yet), and slow read.
- **Defense:** a deadline for the whole request head (not an idle timeout per read), a minimum
  body data rate, a write deadline and a minimum read rate on responses, caps per IP, and a
  cheap idle connection (no buffer held) so holding connections open costs the attacker more
  than the server.

### Track records worth learning from

Advisory IDs are as published by each project; check them in NVD and RustSec before quoting.

| project | advisories |
|---|---|
| hyper | CVE-2021-32715 (lenient Content-Length parsing, smuggling); CVE-2021-32714 (chunk size integer overflow); RUSTSEC-2023-0034 (h2 stream stacking); h2 Rapid Reset and CONTINUATION fixes |
| HAProxy | CVE-2021-40346 (integer overflow, smuggling); CVE-2023-25725 (empty header name, smuggling); CVE-2023-40225 (empty Content-Length) |
| Pingora | CVE-2025-4366 (request smuggling through the cache path, May 2025; Cloudflare blog "Resolving a request smuggling vulnerability in Pingora") |
| Node.js / llhttp | CVE-2022-32213, 32214, 32215 (lenient parsing, smuggling) |
| Netty | CVE-2021-21295 and CVE-2021-21409 (HTTP/2 Content-Length, smuggling); CVE-2023-44487; CVE-2025-55163 |
| Go net/http | CVE-2022-41717 (HPACK memory); CVE-2023-39325 (Rapid Reset); CVE-2023-45288 (CONTINUATION) |
| nginx | CVE-2013-2028 (chunked stack overflow); CVE-2021-23017 (resolver off-by-one) |
| Envoy | a long list, many in filters and HTTP/2 |

**Pattern:** memory-safety bugs cluster in the C servers. In the memory-safe ones (Rust, Go,
Java) the bugs are **leniency and resource accounting**: smuggling and HTTP/2 DoS. A new Rust
server inherits memory safety only where it avoids `unsafe`. Its real risk is the second
category, and that is what testing has to target.

### io_uring as an attack surface

- Google reported that 60% of the kernel exploits submitted to its kCTF VRP in 2022 used
  io_uring. It disabled io_uring on ChromeOS, on Android apps and on its production servers.
  Source: Google Security Blog, "Learnings from kCTF VRP's 42 Linux kernel exploits
  submissions" (2023-06-14).
- Docker's and containerd's default seccomp profiles block `io_uring_setup`,
  `io_uring_enter` and `io_uring_register` (moby/moby, 2023).
- Linux 6.6 added the `kernel.io_uring_disabled` sysctl.
- **So io_uring must be an opt-in back end with automatic fallback to epoll, never a
  requirement.** In Cameleer's container images (distroless, default seccomp) it will
  usually be unavailable.

### Fuzzing and differential testing

- **T-Reqs** (Jabiyev et al., "T-Reqs: HTTP Request Smuggling with Differential Fuzzing",
  ACM CCS 2021) and **Frameshifter** (Jabiyev et al., "Frameshifter: Security Implications of
  HTTP/2-to-HTTP/1 Conversion Anomalies", USENIX Security 2022).
- **HTTP Garden** (Kallus et al., "HTTP Garden: Discovering Parsing Vulnerabilities in HTTP/1.1
  Implementations by Differential Fuzzing of Request Streams", arXiv 2405.17737, 2024),
  https://github.com/narfindustries/http-garden. It runs dozens of real servers and proxies
  side by side and compares how each one interprets the same bytes. It is the best ready-made
  harness to point a new server at.
- **h2spec** (https://github.com/summerwind/h2spec) for HTTP/2 conformance. Also the
  CONTINUATION, Rapid Reset and MadeYouReset reproducers published with the advisories.
- `cargo-fuzz` / libFuzzer, AFL++ and OSS-Fuzz are the usual tooling. They need the
  `libfuzzer-sys` or `afl` crates, which **conflicts with the std-only rule**. The plan
  proposes a dev-only exception or a std-only fuzzer built on SanitizerCoverage callbacks.

### Constant-time TLS

`cameleer-tls` already avoids secret-dependent table lookups in AES and uses `ct_eq`. A
hardware AES-NI and PCLMULQDQ path is constant time by construction and 10–50x faster than
bitslicing. Keep the bitsliced path as the portable fallback. Verify constant-time behaviour
with dudect-style statistical tests (Reparaz, Balasch and Verbauwhede, "Dude, is my code
constant time?", DATE 2017). Those can be written std-only.

## 6. What this means for Cameleer

1. **The gap is the I/O and scheduling model, not syscalls.** One `recv` and one `send` per
   request is already the floor. The cost is 64 threads, their wakeups, and IPIs and VM exits.
   An event loop per core removes that. Expected on 4 vCPUs: 400–600k req/s for the raw core
   and 300–450k for a Cameleer fixed-reply route. This is an estimate, and Milestone 0 tests
   it before committing.
2. **The measurement has to change before the server does.** Closed loop at 64 connections caps
   throughput through Little's law, and a single thread-per-connection load node may be a
   ceiling too. An earlier experiment on Windows (`benchmarks/analysis.md`: IOCP "no faster
   than threads") was loopback with the load generator on the same machine. It doesn't show
   that event-driven designs bring no gain on Linux VMs.
3. **There is nothing to "adapt" without breaking the std-only rule.** hyper, tokio, monoio,
   compio, may and xitca are all crates. Adapting means porting **designs** (compio's
   cross-OS completion model, monoio's rent buffers, picohttpparser's SIMD scan, H2O's
   per-thread loops, HAProxy's strictness), not code.
4. **Security work dominates the long-term cost**: strict parsing, the HTTP/2 DoS family,
   slow attacks, and fuzzing infrastructure under the std-only rule.
5. **Two existing crates need changes for an event loop**:
   - `cameleer-tls` needs a sans-io record API and an AES-NI/PCLMUL path;
   - the HTTP/2 engine needs a sans-io rewrite (the frame codec and HPACK can be reused).
