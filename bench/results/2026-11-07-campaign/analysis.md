# Campaign analysis (2026-11-07, DigitalOcean c-4, blr1)

Written from the campaign agent's final report. Raw data: `results.txt`, `summary.md`, `hdr/`,
`prof/`. Built from simoom `33ee716` plus the working tree listed in `tree.txt`.

## Coverage and caveats

- Rounds 2 and 3 ran only for the four simoom variants and nginx. A bug in choosing the top
  servers caused this; it is fixed in `campaign.sh`.
- A rerun of rounds 2 and 3 for hyper, may-minihttp, netty, axum, fasthttp and ntex was lost when
  the droplets were deleted. Those servers have one round each.
- The c-8/c-16 scaling check, the watchdog-off variant and the S3 profiles were not run.
- Cost was about 200 droplet-hours, roughly $25. About 147 of those droplet-hours were idle time
  while the agent was stopped by a rate limit.

## Shared ceiling

Every server's closed-loop probe tops out at 160–180k req/s, and every S4 run at 2.41 Gbit/s.
That is the droplet's virtual NIC: kernel and virtio work is 70–85% of cycles in every profile.
So S1 ranks tail latency below that ceiling, not raw speed.

## Summary (verified SLO)

Medians over 3 rounds for the simoom variants and nginx; single values for the rest.

| scenario | leaders | simoom (best variant) |
|---|---|---|
| S1 @64 | may-minihttp 150.7k, hyper 130.8k | 106k median (69–128k) |
| S1 @256 | hyper 137.1k, may-minihttp 135.8k, axum 118k | 124.8k (94–128k) |
| S1 @1024 | hyper 109.3k, netty 93.6k, ntex 88.6k | 76.3k (67–105k) |
| S3 1 KB echo | axum 118.3k, fasthttp 96k | 82.8k |
| S4 64 KB / 1 MB | everyone at the NIC limit | tie |
| S5 connection per request | xitca 25.0k, fasthttp 20.5k | 18.1k |
| S7 full TLS handshakes/s | h2o 6.6k, go 5.4k, nginx 4.0k | **8.6–8.7k** |
| S7 S1 over TLS | nginx 73k | **114k** |
| S8 h2c, 100 streams | h2o 162k, hyper 145k | 136.3k |
| S9 goodput within 1 ms at 2× load | xitca 141k, ntex 140k | 91k |
| S10 legitimate p99 under attack | haproxy 372 µs, nginx 392 µs | 470 µs |
| HTTP/3 S1 | h2o 45.7k | **82.3k** |
| HTTP/3 1 MB download | h2o and Caddy 227 req/s | 0 (bug 9) |
| CPU per request at 60k req/s for every server | nginx 33.6 µs, hyper 33.1 µs | **29.7 µs**, also the lowest p99 |
| cold start | hyper 1.33 ms | 3.23 ms full server; 1.42 ms `bench_server` |
| stripped size | may-minihttp 527 KB | 762 KB `bench_server`; 1,497 KB full server |
| idle memory per connection | nginx 529 B | 677 B |

## Causes and proposed fixes

1. **The stall watchdog fires falsely.** The loop thread is preempted on a busy VM, so a 13-byte
   handler measures 1.4–9.3 ms of wall time. The watchdog then moves the whole service to the
   offload pool.

   | simoom fixed/epoll | CPU per request | context switches per request | syscalls per request | S1 SLO at 1024 conns |
   |---|---:|---:|---:|---:|
   | inline (round 2) | 22.65 µs | 0.225 | 2.41 | 110.1k |
   | offloaded (rounds 1 and 3) | 34–35 µs | 1.35 | 5.4–5.6 | 71–80k |

   This is behind the S1, S3 and S8 losses, part of S9, the io_uring and builder gaps, and the
   6.4 ms p99 at 100% load.

   Fix: time handlers with the thread's CPU clock; count only consecutive stalls within a window;
   move a single route rather than the whole service, and move it back after fast calls.
2. **One `epoll_wait` per request.** simoom makes about 1.0 per request, against 0.55 for nginx
   and 0.23 for hyper; it is 17% of simoom's samples. Fix: adaptive spinning or non-blocking polls
   for 20–50 µs after a busy loop turn.
3. **io_uring is slower than epoll** (96.5k against 124.8k req/s). No io_uring profile was taken.
   Fix: one `io_uring_enter` per loop turn for both submit and wait; profile next to epoll.
4. **Builder mode is 27% behind fixed replies**, and S3 is 30% behind axum. Fix: pre-serialized
   heads, one writev for head and body, and small bodies appended to the output buffer.
5. **S5 is 28% behind xitca near saturation.** simoom makes 3.5 `epoll_wait` per connection
   against nginx's 1.8. Fix: `TCP_DEFER_ACCEPT`, read right after accept, batched accepts.
6. **S8 is 16% behind h2o at the top.** Fix: items 1 and 2, plus HEADERS and DATA frames for
   every ready stream written into one buffer per turn.
7. **S9 has 35% less goodput than xitca** because there is no admission control. Fix: shed new
   requests (503) or stop reading busy connections while loop lag is high.
8. **S10 legitimate p99 is 26–153% higher than haproxy and nginx**, from churn as slowloris
   connections are closed and reopened. Fix: cheaper closes, a reconnect rate limit per source
   address, and idle half-requests held without a buffer.
9. **Bug: HTTP/3 responses over 1 MiB never finish.** Reproduce by changing `/big` to 1,100,000
   bytes in `crates/simoom/tests/http3.rs`. It is likely a blocked stream that isn't resumed after
   MAX_STREAM_DATA.
10. **100k idle connections:** the listen backlog is 1024. Fix: default to somaxconn (capped at
    65535) and make it configurable.
11. **Cold start and base memory:** 3.23 ms and 3.6 MB, against hyper's 1.33 ms and 1.3 MB.
    Fix: lazy QUIC endpoints and pools, parallel loop start, the certificate parsed once.
12. **Size:** measure an http1-only edge build against may-minihttp's 527 KB.
