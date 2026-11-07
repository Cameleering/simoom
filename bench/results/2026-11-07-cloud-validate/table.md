# simoom-bench against wrk 4.1 and wrk2 (44a94c1), DigitalOcean

One load node (c-4, Xeon Platinum 8168, kernel 6.8.0-147) against nginx 1.24 (Ubuntu package,
`bench/competitors/nginx`) on another c-4 droplet in the same VPC. Raw output: `raw.txt` (first
pass, launched from an SSH shell with the default 1024 open-file limit, so 11 of 1024
connections failed in the open-loop runs) and `ticker.txt` (open loop again with the limit raised,
with and without the ticker). The kernel refuses simoom-rt's io_uring set-up (EINVAL), so every
simoom-bench run here is on epoll.

| test | wrk / wrk2 | simoom-bench | difference |
|---|---:|---:|---:|
| closed loop, 256 conns, round 1 | 168,856 req/s | 166,304 req/s | -1.5% |
| closed loop, 256 conns, round 2 | 168,114 req/s | 166,374 req/s | -1.0% |
| pipelined 16, 64 conns (`--batch`, wrk's pipeline script) | 393,798 req/s | 396,548 req/s | +0.7% |
| open loop 50k req/s, 1024 conns: achieved | 48,518 req/s | 50,001 req/s | see note 1 |
| open loop 100k req/s, 1024 conns: achieved | 97,002 req/s | 100,001 req/s | see note 1 |
| open loop 50k: p50 / p99 / p99.9 | 2.04 / 5.84 / 6.73 ms | 0.236 / 0.417 / 0.867 ms (ticker) · 0.359 / 1.40 / 1.65 ms (no ticker) | see note 2 |
| open loop 100k: p50 / p99 / p99.9 | 2.98 / 8.89 / 11.12 ms | 0.277 / 1.06 / 6.95 ms (ticker) · 0.295 / 1.25 / 2.15 ms (no ticker) | see note 2 |

Throughput agrees within 1.5% in both closed-loop modes (the bar is 5%). In both tools the
single load node was the limit of the closed-loop runs (simoom-bench reported 78% node CPU and
flagged the run), so these rows compare the generators, not nginx.

1. wrk2 divides by the whole run, including connection set-up and its 10-second calibration
   phase, so it reports 3% under the rate it was asked for. simoom-bench reports the responses
   received inside the measured window; the offered and achieved rates match to 0.01%.
2. wrk2's latency is not comparable at this precision. It schedules each connection's next
   request with a millisecond timer (`round(usec / 1000 + 0.5)` in `src/wrk.c`) and counts its own
   lateness as latency, which is right in principle but at sub-millisecond server latency the
   timer slop dominates: its p50 is 2-3 ms where the server answers in 0.2-0.3 ms. simoom-bench
   measures its own lateness (timer lag) and reports it: without the ticker its p99 timer lag is
   1.06 ms (epoll's millisecond wait), with the 20 µs ticker it is 0.12-0.27 ms, and latency drops
   accordingly. The ticker costs about 18 points of one node's CPU at 50k req/s (41% vs 24%),
   which is why the cloud runs spread the load over three nodes.

A second finding from these runs: closed-loop p99.9 near 200 ms in both tools is TCP
retransmission (the 200 ms minimum RTO) on the DigitalOcean network at this packet rate, not the
server or the generator.
