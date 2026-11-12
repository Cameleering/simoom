# Status

_2026-11-07._ The repository was created and the workspace scaffolded. The design is in
[design/plan.md](design/plan.md) (section 0 is the owner's scope) and the research in
[design/research.md](design/research.md).

## Release 0.1.0 on crates.io

_2026-11-12._ The owner decided to publish on crates.io. The twelve library crates (`simoom`,
`simoom-client`, `simoom-sys`, `simoom-rt`, `simoom-http1`, `simoom-compress`, `simoom-hpack`,
`simoom-qpack`, `simoom-h2`, `simoom-tls`, `simoom-quic`, `simoom-h3`) are published at 0.1.0 by
`scripts/publish-crates.sh` (dependency order, skips versions already there, waits out the
new-crate rate limit); `simoom-bench` stays `publish = false`. Internal dependencies carry
`version = "0.1.0"` next to `path`; dev-dependencies stay path-only and are dropped from the
published manifests. `cargo package --workspace --exclude simoom-bench` verifies every crate from
its package (largest: simoom-compress 421 KB, simoom-tls 321 KB). Git tag `v0.1.0`.

## Work in progress

Wave 1, crates built in parallel: `simoom-sys` + `simoom-rt`, `simoom-http1`, `simoom-hpack` +
`simoom-h2`, `simoom-tls`, `simoom-quic` + `simoom-qpack` + `simoom-h3`.

## The epoll gap (K12 follow-up)

_2026-11-12._ Same-droplet A/B on DigitalOcean (`bench/cloud/ab.sh` with the new fixed-rate `FR`
and repeated-handshake `S7H` scenarios; results and analysis in `bench/results/2026-11-12-epoll/`).

- Cause: the three loops of the K12 fix were unpinned, and the scheduler kept putting a loop woken
  by the receive softirq on that interrupt CPU (sampled there more than on any other CPU). That
  loop's connections stalled: p99 in seconds at fixed rates, with no drops and a handful of
  retransmits. The readiness driver's turn was not the cause (one recv and one sendmsg per
  request, about 1.5 requests per wakeup).
- Fix: the loop threads keep off the CPU with the most softirq time in `/proc/stat`
  (`simoom_sys::cpu::keep_current_thread_off_net_rx`); the concentration test reads `/proc/stat`
  too, because the `NET_RX` counts pointed at the transmit-completion CPU.
- S1 at 64/256/1024 connections, median of three rounds on one droplet: epoll 170.6k/172.6k/138.6k
  (before 117.0k/133.8k/87.6k), io_uring 152.7k/172.3k/148.4k, hyper 122.2k/144.4k/115.1k,
  may-minihttp 158.6k/150.7k/120.6k. epoll leads at 64 and 256 in every round.
- The -14% epoll handshakes were the same effect: 8.7k full / 9.8k resumed over four runs (before
  6.3k/6.9k; four loops 7.4k/8.1k). S3, S5, S7 over TLS, S8 level or better; CPU per request -5%
  (epoll) and -7% (io_uring). Size: `http1,http2,tls,io-uring` at 583,680 of 614,400 bytes (5.0%
  headroom), `http1,io-uring` 242,568 of 256,000 (5.2%).
- Tests: `cargo test --workspace` 777 passed on Windows and 791 on WSL2, zero warnings with
  `--all-targets`. 9.4 droplet-hours, nothing left.

## K12 / K13 fix round

_2026-11-12._ Same-droplet A/B on DigitalOcean (`bench/cloud/ab.sh`, results and analysis in
`bench/results/2026-11-12-fix-k12-k13/`).

- K12's cause: the c-4 droplet's NIC has one receive queue, so its softirq takes most of one CPU,
  and the simoom loop on that CPU holds a quarter of the connections. The runtime now starts one
  loop fewer than CPUs when the receive work is concentrated (`Config::leave_cpu_for_network`).
  S1 on one droplet, 64/256/1024 connections: io_uring 152.7k/162.1k/144.0k against hyper
  122.2k/145.6k/70.5k and may-minihttp 140.8k/168.8k/42.9k (four loops: 128.9k/116.8k/88.2k).
  epoll gained 45-69% but is still behind at 64 and 256 connections.
- K13: a read-side turn budget did not help (removed); nginx's in-time goodput under overload comes
  from its worker pinned to the interrupt CPU starving, and changes by 20x between droplets.
  Recorded as a limit of the benchmark at 1.17x the NIC ceiling.

## Cloud benchmark campaign 3

_2026-11-11._ simoom pinned at `28d2a6f` (K1-K10 in), three lanes on 9 DigitalOcean c-4 droplets
against may-minihttp, hyper, xitca, h2o, nginx, haproxy, cameleer-http-min and Cameleer.
Results, tables and analysis: `bench/results/2026-11-11-campaign3/` (`analysis.md`).

- One droplet (srvC) had a degraded network path for every server, so only servers of the same
  lane compare directly in the one-round scenarios; the analysis says which droplet each figure is
  from.
- Confirmed on the droplets: TLS handshakes +31% / +45% and S1 over TLS +65% against h2o; CPU per
  request 11% below hyper; idle PSS below cameleer-http-min (K7); memory per idle connection level
  with nginx at 100k (K8); 1 MiB TLS bodies no longer balloon memory (K2); slowloris no longer
  churns (K6); the offload pool serves 100 ms handlers without 503s (K10); the http1-only build is
  536 KB against may-minihttp's 515 KB (K9).
- Still behind: S1 at 256 connections with epoll (-14%) and on degraded droplets, S1 at 1024
  against hyper (-17%), in-time goodput under overload against nginx (K12, K13).
- Start-up and memory against cameleer-http (same machine, WSL2): cold start passes plain and TLS;
  idle memory passes plain; TLS idle PSS was +11% (K11). Fixed 2026-11-12: +3.3% (1,360 against
  1,316.5 KB, 20 rounds); the gap was the P-256 table's build scratch left in the loop's malloc
  arena, not code pages (`docs/BUGS.md` K11).
- Client (workstation, not a droplet): simoom-client at parity or ahead of Cameleer's client on
  HTTP/1.1 and h2c, at 10-47% less CPU per request.
- About 77 of the 90 droplet-hours were idle after an operator restart; the safety net now also
  fires at logon and from the operator's next command (`bench/cloud/safety-net.sh due`).

## Start-up and memory against cameleer-http

_2026-11-09._ Owner requirement (plan §0 item 7): cold start and memory within 5% of Cameleer's
current HTTP server, plain and with TLS, measured the same way on the same machine.

**Baseline.** `bench/competitors/cameleer-http-min` (path dependencies on the Cameleer checkout,
read-only): `cameleer_http::server::HttpServer` with a fixed 13-byte reply, plain on `--addr`
and TLS on `--tls-addr`; it builds its TLS configuration before binding and prints `ready`. The
simoom side is `crates/simoom/examples/min_server.rs`, the same reply and arguments, built with
the default features for the plain row and `--features tls,simoom-tls/rsa` for the TLS rows
(`--features full` for the HTTP/3 rows, which have no Cameleer equivalent). Both use the system
allocator and the workspace release profile (fat LTO, one codegen unit). Same PEM files:
ECDSA P-256 and RSA-2048 from `openssl req -x509`.

**Method.** Cold start: `simoom-bench coldstart` (spawn to the first 2xx on the plain port),
20 runs per round, 6 interleaved rounds on WSL2 (Ubuntu 24.04, 12 vCPU); on Windows 11 with
`--ready ready` (a connect to a port nobody listens on yet takes about 200 ms to fail there, which
hid everything else), 15 runs, 5 rounds. Memory: `smaps_rollup` PSS on Linux (median of 3
interleaved rounds), working set and private bytes on Windows; idle is after one request, then
after 1,000 requests on one keep-alive connection, then with 1,000 idle connections open.

| | cold start WSL | Windows | PSS idle / 1k req / 1k conns (WSL) | Windows private idle / 1k conns (WS idle) |
|---|---|---|---|---|
| cameleer-http plain | 0.81 ms | 9.19 ms | 1041 / 1089 / 7580 KB | 962 / 15,180 KB (5,144) |
| simoom plain | **0.77 ms (−5%)** | **8.04 ms (−13%)** | **1023 / 1023 / 2438 KB (−2%)** | 1,100 / 5,040 KB (5,150) |
| cameleer-http TLS P-256 | 1.39 ms | 9.94 ms | 1209 / 1257 / 7744 KB | 1,060 / 15,240 KB (5,376) |
| simoom TLS P-256 | **0.88 ms (−37%)** | **8.82 ms (−11%)** | 1315 / 1315 / 2710 KB (+9%) | 1,174 / 5,130 KB (5,548) |
| cameleer-http TLS RSA-2048 | 1.77 ms | 10.74 ms | 1157 / 1205 / 7692 KB | 1,072 / 15,200 KB (5,362) |
| simoom TLS RSA-2048 | **1.70 ms (−4%)** | **9.84 ms (−8%)** | 1247 / 1247 / 2646 KB (+8%) | 1,182 / 5,110 KB (5,544) |
| simoom TLS P-256 + HTTP/3 (no Cameleer equivalent) | 1.91 ms | — | 2707 / 2711 / 3490 KB | — |
| simoom TLS RSA-2048 + HTTP/3 | 2.81 ms | — | — | — |

Cold start is within 5% or faster everywhere, plain memory on Linux is 2% lower. Above 5%:

- **TLS PSS on Linux, +8-9%** (since fixed, K11: +3.3% on 2026-11-12; the cause was the P-256 table's
  build scratch kept in the loop thread's malloc arena, not the code pages described next). The anonymous memory is the same (224-240 KB against 208-220 KB);
  the difference is file-backed pages of the binary touched at start (1,007-1,095 KB against
  937-1,097 KB, Cameleer's own figure moves by 100 KB from run to run). It is code, shared by
  every process that maps the same binary, and it does not grow with traffic: after 1,000
  requests simoom is 4-5% above Cameleer (Cameleer grows by 48 KB), and with 1,000 idle
  connections simoom uses 2.7 MB against 7.7 MB (65% less: Cameleer keeps a thread per
  connection).
- **Windows private bytes, +7-14% idle (+110-140 KB).** The working set is within 0.1% (plain)
  and 3-3.5% (TLS). The private bytes are the IOCP loop thread and its structures. With 1,000
  idle connections simoom uses 5.1 MB against 15.2 MB.
- **Measured advantage (WSL, server on 4 CPUs, closed-loop load from 8 other CPUs, 64
  connections, 13-byte reply):** cameleer-http 172,000-173,000 req/s, p99 0.87-0.91 ms, about 23
  µs of server CPU per request; simoom 293,000-311,000 req/s (1.7-1.8x), p99 0.32-0.44 ms (2-2.7x
  lower), about 13 µs of CPU per request (43% less).

**What changed to get here** (bug sweep items 12, 13 and 19, `docs/BUGS.md`):

- The descriptor table is grown at start (`simoom_rt::Config::reserve_fds`, 1,024 slots, 8 KiB of
  kernel memory). Growing it once threads run waits for an RCU grace period on the thread that
  crosses a step: that was 18-28 ms of the 27-30 ms TLS + HTTP/3 start (the 12 per-loop UDP
  sockets pushed loop 11's `epoll_create` past 64 descriptors), and it hit first accepts too.
  `simoom-server` with TLS + HTTP/3: 26.9 ms → 2.4 ms (P-256) and 3.3 ms (RSA-2048); PSS
  5.3 → 3.6 MB (1.06 MB of it is the server's own `/64k` and `/1m` bodies).
- Lazy loops (`simoom_rt::Config::lazy_loops`, on in the `simoom` server): start returns without
  waiting, with only loop 0 running; the others start in the background once loop 0 holds three
  connections at once. Connections accepted meanwhile are held and spread over every loop, and
  loop 0 hands out its accepts for a second after, so a burst does not stay on one loop
  (throughput with 64 connections opened at once: 293-311k req/s, as with every loop started at
  once). Not with HTTP/3: a socket added later to a `SO_REUSEPORT` group would take over some
  established QUIC connections, so those servers start every loop.
- The QUIC endpoint of each loop is built on its first datagram (`Stats::quic_endpoints`).
- Receive buffers on epoll/kqueue start at 8 and double when a read finds the stock empty, up to
  `recv_buffers` (64 at once cost about 130 KiB per loop).
- A P-256 key's public point is computed without the base-point table when the key is
  loaded (the first signature builds it, 32 KB since K11, about 0.34 ms); the certificate is parsed once, and a
  `ServerConfig` clone shares it (`simoom-server` builds one for TCP and QUIC).
- The cgroup CPU quota (about 40 µs of file reads) is read once per process, and with lazy loops
  only when the other loops start; the offload pool sizes itself on its first job.

Reproduce: `target-bugs/` scripts are not committed; the commands are `simoom-bench coldstart
--addr 127.0.0.1:18080 --repeat 20 [--ready ready] -- BIN --addr 127.0.0.1:18080 [--tls-addr
127.0.0.1:18443 --cert C --key K]`, and PSS from `/proc/PID/smaps_rollup`.
