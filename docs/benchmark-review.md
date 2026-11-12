# Benchmark review: what we set out to prove, what we measured, what the site showed

_2026-11-12. Written after the owner's review of the microsite: "there is no use in putting random
numbers; the very idea of benchmarking was to get comparative numbers"._

## 1. What we set out to do

The plan (docs/design/plan.md) fixed the goal on 2026-11-07:

- **§0 item 3:** "Efficiency comes before everything. Every feature must measure better than the
  alternatives in §6.3 on throughput, tail latency, memory and size."
- **§6.3, the field:** nginx, H2O, HAProxy, Envoy, OpenLiteSpeed, uWebSockets (C/C++); hyper,
  axum, actix-web, may-minihttp, xitca-web, ntex, monoio (Rust); Netty, Vert.x, Undertow,
  Kestrel, Go net/http, fasthttp, Caddy (JVM, .NET, Go); Apache Camel and Cameleer (reference).
- **§6.4, the scenarios:** S1 small GET at 64 to 4k connections, S3 1 KB JSON POST, S4 64 KB and
  1 MB replies, S5 a connection per request, S6 10k and 100k idle connections, S7 TLS handshakes
  and TLS traffic, S8 HTTP/2, S9 overload, S10 slow attackers, S11 Cameleer routes.
- **§6.5, the metrics:** SLO throughput (p99 ≤ 1 ms), p50/p99/p99.9, CPU per request, peak
  memory, memory per idle connection, binary size, cold start.

That is the same standard as Cameleer's "Apache Camel vs Cameleer" page: every scenario, every
alternative, one table, throughput, latency, memory and start-up side by side, with the ratio.

## 2. What actually ran

| campaign | simoom | field | what it was for | outcome |
|---|---|---|---|---|
| 1 (2026-11-07) | `33ee716`, before the K-fixes | 18 competitors: everything in §6.3 that built, including Kestrel, Netty, Vert.x, uWebSockets, Envoy, Caddy, Go net/http and fasthttp | the full comparison | simoom led only TLS handshakes, S1 over TLS, HTTP/3 and CPU per request; it lost S1, S3, S5, S8, S9, S10, cold start and size. Most competitors got one round |
| 2 (2026-11-09) | after K1–K3 | 13: Kestrel, Vert.x, uWebSockets, Envoy, Caddy and Go dropped | re-measure after the first fixes | narrower field |
| 3 (2026-11-11) | after K4–K11 | 8: hyper, may-minihttp, xitca, h2o, nginx, haproxy, Cameleer and its old server | check the fixes of campaign 2's losses | three lanes on three droplets that differed up to 6x; only same-lane rows compare |
| 2026-11-12 epoll | after K12 | hyper, may-minihttp | close the epoll gap | simoom first at 64 and 256 connections |

**The plot was lost after campaign 1.** Each later campaign measured simoom against the servers
that had beaten it in the previous one, to check a fix. That was the right engineering loop, but
it never produced the deliverable: the current simoom against the whole field, on one machine,
per use case. Kestrel, Netty, Vert.x, Go, fasthttp, actix, axum, ntex, uWebSockets, Envoy and
Caddy were last measured against a simoom that no longer exists.

## 3. What the site then did wrong

- It quoted the few same-droplet pairs that happened to exist: hyper and may-minihttp for plain
  HTTP, h2o for TLS and HTTP/3, Cameleer's old server for start-up, nginx for memory per
  connection. Each headline used a different rival, so the numbers read as picked, not compared.
- The commit after review (bcd7b82) made it worse: a 30x memory figure across lanes, a size
  figure against hyper, a start-up figure against Cameleer's old server, in one hero.
- No table answered the question a reader brings: "for my use case, how does simoom compare with
  what I would otherwise use?"
- Realistic Rust baselines were missing: Rust users serve TLS with rustls and HTTP/3 with quinn,
  and neither was in any campaign; the TLS and HTTP/3 comparisons were against C servers only.
- Two use cases simoom is built for, a handler that calls a slow partner and live updates, have
  benchmark endpoints only in simoom and Cameleer.

## 4. What the deliverable has to be

One table per use case, every alternative in it, the same machine for every row, the ratio
against each, and the losses in the same table. Footprint (start-up, size, idle memory, peak
memory) for every server. Then the site is generated from that table, nothing else.

## 5. Campaign 4: the final comparison

- **Field (21):** simoom, simoom-default (smallest build); hyper, axum, axum + rustls (new),
  actix-web, ntex, xitca-web, may-minihttp, quinn + h3 (new); nginx, h2o, haproxy, Envoy, Caddy;
  Go net/http, fasthttp; Netty, Vert.x; Kestrel; uWebSockets; Cameleer's old server.
- **Fairness:** three lanes, each with its own server droplet and two load droplets. **simoom
  runs in every lane, every round,** so every competitor is compared with simoom on the same
  droplet, with the same load nodes, in the same round. Droplets rotate between rounds, so every
  server meets every droplet. The published ratio is the median of the per-round same-droplet
  ratios; absolute numbers are shown with their droplet.
- **Use cases → scenarios:** status and health endpoint (S1, 64/256/1,024 connections); JSON API
  (S3); downloads (S4); clients that connect for each request, such as serverless callers and
  devices (S5); HTTPS API and new TLS clients (S7: S1 over TLS, full and resumed handshakes);
  many idle devices (S6, 10k and 100k); service-to-service HTTP/2 (S8); mobile over HTTP/3 (H3);
  traffic spike (S9, one absolute rate for everyone); under attack (S10); cost per request (CPU
  at a fixed 50k req/s); footprint (cold start, size, idle memory, peak memory per scenario).
- **Rounds:** round 1 runs every scenario for every server; rounds 2 and 3 repeat S1, S3, S5,
  S7 and CPU on the other two droplets.
- **Not in this campaign** (no competitor implementations yet): the slow-partner handler and live
  updates. They stay simoom-only results and are labelled so.

## 6. Found while preparing campaign 4

- **simoom-h3 discarded valid responses** (fixed in `c351e6d` and the commit after it). A
  server may stop reading a request it no longer needs and still answer (RFC 9114 §4.1.1). quinn
  does this for every request stream, with STOP_SENDING code 0. simoom's HTTP/3 layer reported it as a reset, so
  simoom's client, and the benchmark's HTTP/3 load generator built on it, threw the response away.
  Without the fix quinn + h3 would have been scored as failing most requests. Campaign 4 measures
  simoom with this fix.
