# Campaign 4: simoom against the field, use case by use case

_2026-11-12, 16:10–20:12 UTC. simoom `a81c368` (epoll back end), the benchmark server with every
feature. Why this campaign exists: [docs/benchmark-review.md](../../../docs/benchmark-review.md)._

Every figure here comes from `results.txt` (merged from `raw/lane1..3/`) and `supplement.txt`,
computed by `bench/cloud/c4-report.py`:

- `report.md`: one table per measure, every server.
- `c4.json`: the same data, read by `scripts/c4-site.py` to generate the site.

Nothing below was typed in by hand except the commentary.

## Setup

- **Three lanes in parallel.** Each lane had one server droplet and two load droplets, all
  DigitalOcean `c-4` (4 dedicated vCPUs) in blr1, Ubuntu 24.04.
- **Rotation.** The server droplets srvA, srvB and srvC rotated between rounds, so each lane met
  each droplet:

  | | round 1 | round 2 | round 3 |
  |---|---|---|---|
  | lane 1 | srvA | srvB | srvC |
  | lane 2 | srvB | srvC | srvA |
  | lane 3 | srvC | srvA | srvB |

- **simoom in every lane and every round**, before that lane's other servers. Every ratio is
  simoom against that server on the same droplet, with the same load droplets, in the same round.
  The published figure is the median of those per-round ratios.
- **The field (20 other servers):**

  | lane | language | servers |
  |---|---|---|
  | 1 | Rust | hyper 1.12.0, axum 0.8.9, axum 0.8.9 + rustls 0.23.46 (aws-lc-rs), actix-web 4.18.2, ntex 2.18.0, xitca-web 0.7.1, h3 0.0.8 + quinn 0.11.12 |
  | 2 | C and C++ | may-minihttp 0.1.11 (Rust), nginx 1.24.0, H2O 2.3.0-DEV, HAProxy 2.8.30, Envoy, Caddy 2.11.9 (Go), Cameleer's old server (cameleer-http 0.5.1) |
  | 3 | Go, JVM, .NET, JS | Go net/http and fasthttp (go1.27.3), Netty 4.2.20, Vert.x 5.2.3, Kestrel (.NET 10.0.403), uWebSockets.js 20.71.0, simoom's smallest build |

- **Rounds.** Round 1 ran every scenario for every server. Rounds 2 and 3 repeated these on the
  other two droplets:
  - the status endpoint at 256 clients;
  - JSON API;
  - new connections;
  - TLS and HTTP/3;
  - CPU per request.

  The other measures have one round each. The site labels each chart with its round count.

## The result, one line per use case

The main measure of each use case. "Place" counts the servers more than 3% ahead of simoom.

| use case | measure | simoom's place | best other | median server |
|---|---|---|---|---|
| Health checks and status endpoints | `s1-256` | 2nd of 19 | may-minihttp: 6% more than simoom | simoom 50% more |
| JSON APIs | `s3` | 2nd of 12 | may-minihttp: 5% more than simoom | simoom 27% more |
| HTTPS APIs and new TLS clients | `s7-tls` | 1st of 8 | axum + rustls: simoom 30% more | simoom 2.1x more |
| Clients that connect for every request | `s5` | 5th of 19 | xitca-web: 29% more than simoom | simoom 10% more |
| Service-to-service HTTP/2 | `s8` | 2nd of 12 | H2O: 11% more than simoom | simoom 74% more |
| Mobile clients over HTTP/3 | `h3` | 2nd of 4 | H2O: 43% more than simoom | simoom 65% more |
| Downloads | `s4-64k` | joint 1st of 8 | actix-web: level | level |
| Many idle connections | `idle-10k` | 2nd of 19 | nginx: 6% less than simoom | simoom 20x less |
| Traffic spikes | `s9` | 10th of 19 | actix-web: 22x more than simoom | 26% more than simoom |
| Slow attackers | `s10` | 6th of 19 | Go net/http: 44% lower than simoom | simoom 32% lower |
| Start-up, size and memory | `cold-plain` | 1st of 21 | hyper: simoom 57% faster | simoom 6.4x faster |

Also first of 19 on CPU per request at a fixed 50,000 req/s:

- simoom used 23.6 µs per request;
- the closest servers were may-minihttp and Vert.x, at 17% and 24% more;
- hyper used 35% more.

## What it means

- **Where simoom leads:**
  - **Cost and footprint:** start-up, CPU per request, idle memory (only nginx is level) and peak
    memory under plain and TLS load (H2O uses less under HTTP/3).
  - **TLS throughput:** 1.3x the next best, both axum + rustls and H2O.

  This is the case the project was built for: functions, devices and services that pay for
  every millisecond of start-up and every megabyte.
- **Plain throughput: near the top, not first.** may-minihttp, a stackful-coroutine server,
  leads plain throughput by 5–16% at every client count and in the JSON API. simoom is ahead of
  or level with every other Rust, C, Go and JVM server here, except at 64 clients (see the
  anomalies).
- **HTTP/2 and HTTP/3: H2O leads.** H2O is 11% ahead on HTTP/2 and 43% ahead on HTTP/3.
  simoom is 1.65x quinn + h3, the Rust alternative.
- **New TLS clients: axum + rustls leads.** It does 24% more full handshakes and 9% more resumed
  ones. rustls on aws-lc-rs uses assembly-optimised P-256 and X25519. simoom's constant-time
  std-only code does not.
- **Real losses under overload:**
  - At 195,000 req/s offered, more than the network card carries, every server answers
    roughly 150–160k req/s in total.
  - How many of those answers arrive within 1 ms is the weak spot. actix-web keeps 59k,
    nginx 29k, xitca-web 8.9k; simoom keeps 2.7–6.3k.
  - simoom accepts and queues everything it can read. The servers that win shed or delay
    reading.
- **Slow attackers.** Under 10,000 slowloris and 1,000 slow-read connections, five servers keep a
  lower p99 for real requests: Go net/http, HAProxy, Vert.x, Netty and H2O. simoom is level
  with hyper, axum and fasthttp, and well ahead of ntex, xitca-web, actix-web, Envoy and Kestrel.
  Kestrel's p99 reached 160 ms; Cameleer's old server's reached 32 s.

## Anomalies and how they were handled

1. **Start-up failed for Netty, Vert.x and Kestrel.** The cause is that the campaign's start-up
   step uses the launch command printed by `run.sh --print`, which is shell-escaped:
   - the JVM classpath wildcard reached `java` as a literal `\*`;
   - Kestrel lost `DOTNET_ROOT`.

   After the lanes finished, the three were timed by hand on srvC with their `run.sh` command
   lines, next to a fresh simoom run (`coldstart-manual-srvC.txt`, recorded in `supplement.txt`
   as cell `(manual, 1)`). Results:
   - Netty 467 ms
   - Vert.x 724 ms
   - Kestrel 367 ms
   - simoom's default build 0.95 ms

   To fix in `campaign.sh`: run the start-up step through `run.sh` itself.
2. **Per-scenario peak memory.** The campaign's own SPEAK records were dropped by its record
   filter (fixed in `f570d3c`, after these lanes started). Peak memory per scenario therefore
   comes from 1-second PSS samplers on the three server droplets (`raw/lane1/pss-ts-srv*.log`),
   with each scenario's window taken from the lanes' progress logs.
   - The first version of that windowing took a lane's previous entry as the start. In rounds 2
     and 3 a lane moves to a droplet that may still be running another lane's last server, so
     simoom's first window absorbed a JVM's 1.9 GB.
   - The windows now start at the previous event on the same droplet from any lane.
   - The whole-run peak was dropped as a measure: simoom's includes HTTP/3, which most servers
     never ran.
3. **Stalls.** In S1 and S3, some search points show a p99 of hundreds of milliseconds with the
   achieved rate above the offered rate: the load generator catching up after a pause. Every
   such point counts as a miss.

   | server | stalled points (S1 and S3) |
   |---|---|
   | simoom | 8 of 57 |
   | simoom's smallest build | 6 of 19 |
   | may-minihttp | 4 of 19 |
   | hyper, axum | 3 of 19 each |
   | most others | 0–2 |

   The pauses hit servers in every lane, so part of the cause is the environment. simoom's
   higher rate is worth a look on a quiet machine. It is the likeliest reason for the next point.
4. **Status endpoint at 64 clients (one round).** In lane 3, simoom's 64-client search hit a
   stall and settled at 69k req/s, where it reached 129–137k on the other droplets. That single
   round makes Vert.x, fasthttp, Netty and uWebSockets.js read 13–50% ahead of simoom at 64
   clients. The chart shows it as measured and labels it as one round. At 256 clients, with
   three rounds, simoom is ahead of all four.
5. **Simoom's smallest build in S1.** It missed the target at 64 and 1,024 clients through
   stalls, and beat the full build at 256 clients. It is simoom itself, so the site shows it only
   in the footprint charts.
6. **Memory at rest.** HAProxy (143 MB), nginx (72 MB), Envoy, Caddy, the JVMs, .NET and Node
   reserve memory at start-up in the configuration under `bench/competitors`. These are their
   numbers as configured, not their minimums.
7. **Program size** is shown only for self-contained executables. The JVM servers, Kestrel and
   uWebSockets.js need a runtime and are left out. nginx, H2O and HAProxy link the system's
   OpenSSL, which their size does not include.
8. **Traffic spike, 1 MB downloads, HTTP/2 throughput.** At 195k req/s offered and with 1 MB
   responses, the network card is the limit. Only the share of answers within the latency target
   tells the servers apart.

## Not measured

- **Handlers with slow partners and live updates (WebSocket, SSE).** These have benchmark
  endpoints only in simoom and Cameleer, so they stay simoom-only results.
- **Larger machines and multi-queue network cards.** Every figure is from 4-vCPU droplets whose
  network card has one receive queue.
- **OpenLiteSpeed, Undertow and monoio** (from plan §6.3) have no benchmark program yet.
