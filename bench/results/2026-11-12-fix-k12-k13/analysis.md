# K12 / K13 fix round (2026-11-12, DigitalOcean c-4, blr1)

Same-droplet A/B of simoom variants against hyper, may-minihttp and nginx, with
`bench/cloud/ab.sh` (one server droplet, two load nodes, every variant on the same server,
campaign 3's lane sweep settings: SLO search with 4% precision, p99 <= 1 ms). Tables from
`bench/cloud/ab-summary.py`.

- `raw/batch12/`: droplet set 1 (srvA), specs `spec1` (round 1) and `spec2` (round 2). Builds
  `fbdd4fe` and `857c853` (work in progress: accept balancing, a turn budget, per-loop STATS).
- `raw/batch3/`: droplet set 2 (srvA2), `spec3`, build `6d2fb3d` (the fix as committed, with the
  first version of the receive-path check; it chose three loops on this droplet like the final
  one). `srv-softirqs.txt`: the server's `/proc/softirqs` and NIC interrupts after the run.
- Droplets: set 1 from 05:24 to 07:20 UTC (3 droplets; batch 1 was cut short by an operator
  restart at 06:48, batch 2 had finished at 06:58), set 2 from 07:21 to 08:38 UTC (3 droplets).
  About 9.7 droplet-hours in all. 0 simoom-bench droplets and no simoom-bench-key left (checked
  with the API at 08:38).

## Root cause of K12: a loop on the NIC's interrupt CPU

The private NIC of a c-4 droplet is virtio-net with **one** receive queue and no RPS
(`/sys/class/net/eth1/queues/`: rx-0 only, `rps_cpus` 0, `ethtool -l`: Combined 1). Every received
packet's softirq runs on the CPU that takes its interrupt. At S1's packet rates that CPU is
mostly softirq; per-CPU `mpstat` during 256 connections at 130k req/s, four simoom loops:

| CPU | usr | sys | soft | idle |
|---|---:|---:|---:|---:|
| 0 | 9.5 | 30.3 | 0.3 | 59.6 |
| 1 | 11.1 | 35.0 | 0.2 | 53.5 |
| 2 | 7.3 | 22.8 | **65.7** | 4.1 |
| 3 | 10.9 | 31.5 | 9.6 | 47.8 |

(batch 1, `epoll-head`; hyper on the same droplet shows 59.6% softirq on CPU 2.) simoom is
thread-per-core: the loop whose thread shares CPU 2 gets about a third of a CPU, and every
connection it holds waits for it, which is the p99 tail. hyper and may-minihttp move work between
their threads (work stealing), so the other three CPUs absorb it. Campaign 3's "degraded"
droplets fit the same picture (the softirq share differs per host).

Ruled out on the same droplet (S1 at 256 connections, req/s): the K4 early flush off
(`FLUSH_EARLY_BATCH` = infinity) 116,820; campaign 2's commit `1e50579` 111,168; 512 receive
buffers per loop 111,168; accept balancing by connection count 65,948 / 128,125 (no gain;
removed); against four loops at HEAD 111,168 / 128,125. Eight loops: 139,430. **Three loops:
150,735 (epoll), 172,406 (io_uring).**

## The fix

`simoom_rt::Config::leave_cpu_for_network` (default on): with the default loop count on 4 CPUs or
more, the runtime starts one loop fewer than CPUs when the network's receive processing is
concentrated (`simoom_sys::cpu::net_rx_concentrated`: at most half of the CPUs did the `NET_RX`
work in `/proc/softirqs`, a CPU counting when it did at least half of an even share). On set 1
that was CPU 2 alone; on set 2 CPUs 2 and 3 (the private NIC's receive and transmit-completion
interrupts). An explicit `threads` or `cpus` turns it off.

## S1, same droplet (req/s at p99 <= 1 ms)

Droplet set 1 (batch 2 for the rows with three loops; where a cell has two figures they are
rounds 1 and 2):

| server | 64 | 256 | 1024 |
|---|---:|---:|---:|
| simoom epoll, 4 loops (HEAD) | 122,964 | 111,168 / 128,125 | 88,228 |
| simoom io_uring, 4 loops (HEAD) | 122,964 | 116,820 | 88,228 |
| **simoom epoll, 3 loops** | **158,663** | 150,735 | **150,354** |
| **simoom io_uring, 3 loops** | 122,964 | **172,406** | 147,479 |
| hyper | 111,910 | 143,781 / 129,972 | 102,154 |
| may-minihttp | 158,598 | 168,521 | 85,858 |

Droplet set 2 (batch 3, the committed build; one round each):

| server | 64 | 256 | 1024 |
|---|---:|---:|---:|
| simoom epoll, default (3 loops) | 97,181 | 133,778 | 127,841 |
| simoom epoll, `--threads 4` | 97,181 | 92,326 | 75,624 |
| **simoom io_uring, default (3 loops)** | **152,714** | 162,100 | **144,045** |
| simoom io_uring, `--threads 4` | 128,914 | 116,820 | 88,228 |
| hyper | 122,240 | 145,625 | 70,500 |
| may-minihttp | 140,757 | **168,819** | 42,930 |

- io_uring: on set 2 leads at 64 and 1024 connections (+8.5% and +104% over the best other) and
  is 4% behind may-minihttp at 256 (one sweep step: a tie at this precision); on set 1 it leads
  at 256 and 1024 and is behind at 64.
- epoll: +45% to +69% over four loops on the same droplet; leads at 1024 on both droplets; ties
  may-minihttp at 64 on set 1 but is 20-31% behind at 64 on set 2, and 11-21% behind
  may-minihttp at 256. **The epoll gap at 64 and 256 connections is not closed** (see "Still
  open").
- The four-loop builds were behind everyone at 256 and 1024 on both droplets: the loop count is
  the difference.

## Other scenarios, three loops against four (set 2, same droplet)

| scenario | epoll 3 loops | epoll 4 loops | io_uring 3 loops | io_uring 4 loops |
|---|---:|---:|---:|---:|
| S3 1 KB echo, 256 conns (SLO req/s) | 161,375 | 110,625 | 138,750 | 116,250 |
| S5 connection per request (SLO, 5 ms) | 22,000 | 18,700 | 21,175 | 18,700 |
| S7 full handshakes /s | 6,807 | 7,877 | 9,765 | 8,271 |
| S7 resumed handshakes /s | 7,369 | 8,613 | 11,306 | 8,916 |
| S7 S1 over TLS (SLO req/s) | 110,625 | 105,000 | 150,000 | 120,413 |
| S8 h2c, 100 streams (SLO, 5 ms) | 173,994 | 167,760 | 160,710 | 168,898 |
| CPU per request at 50k req/s (us) | **25.51** | 28.47 | **24.98** | 28.71 |

- Better or level everywhere except **S7 handshakes on epoll (-14%)**, which are CPU-bound and
  lost a loop; io_uring's handshakes went the other way (+18% / +27%), so part of it is the noise
  of a single 15 s closed-loop run, but the epoll figure is recorded as a possible regression for
  the next campaign. S8 io_uring -5% is within one sweep step.
- CPU per request fell 10-13%: the loop that shared the softirq CPU was paying for it.
- Memory: one loop fewer holds less (pools, rings); per-connection state is unchanged. Cold
  start: the default server (`lazy_loops`) starts one loop and reads `/proc/softirqs` only when
  the other loops start, so start-up is unchanged; a non-lazy runtime with the default count reads
  it once at start (one 4 KiB read). Neither was re-measured on a droplet.
- Size (`scripts/size.sh`, WSL, `dist`): every budgeted row keeps at least 5% headroom; the
  tightest are `http1,io-uring` 242,472 of 256,000 (5.3%) and `http1,http2,tls,io-uring` 583,584
  of 614,400 (5.0%; 582,760 on `origin/main`).

## K13: S9 overload (1024 connections, 195,000 req/s offered)

| server (droplet) | goodput | within 1 ms | admitted p50 us | admitted p99 us | never answered |
|---|---:|---:|---:|---:|---:|
| nginx (set 1) | 153,611 | **144,210** | 230 | 25,231 | 1,099,587 |
| simoom io_uring, 4 loops (set 1) | 159,620 | 2,912 | 3,535 | 211,157 | 743,824 |
| simoom io_uring + turn budget 300 us (set 1) | 156,301 | 2,688 | 3,645 | 211,026 | 831,462 |
| simoom io_uring + turn budget 600 us (set 1) | 151,052 | 2,762 | 540 | 211,943 | 995,117 |
| simoom epoll, 4 loops (set 1) | 159,389 | 4,474 | 3,289 | 211,026 | 740,876 |
| simoom epoll + turn budget 300 us (set 1) | 160,126 | 4,084 | 3,308 | 210,895 | 718,468 |
| hyper (set 1) | 158,787 | 4,794 | 2,112 | 211,550 | 757,687 |
| nginx (set 2) | 158,220 | 6,433 | 3,191 | 206,570 | 836,051 |
| hyper (set 2) | 154,486 | 2,913 | 1,771 | 212,206 | 887,114 |
| **simoom io_uring, default (set 2)** | **160,904** | 1,160 | 4,968 | **9,699** | 694,830 |
| simoom epoll, default (set 2) | 153,483 | 1,570 | 4,313 | 209,846 | 910,811 |
| simoom io_uring, 4 loops (set 2) | 155,434 | 1,403 | 4,395 | 208,798 | 865,066 |

- **The read-side bound does not help.** The turn budget (a loop that has spent its budget holds
  the remaining connections' input back, pauses their reading and serves connections in slot
  order) was implemented with tests and measured at 300 and 600 us: in-time goodput 2.7k against
  2.9k without it on io_uring, 4.1k against 4.5k on epoll. It was removed again (no gain, and it
  cost about 4 KB of the size budget).
- **nginx's in-time figure is a property of the droplet, not of a better queue.** nginx pins one
  worker per CPU (`worker_cpu_affinity auto`) with `reuseport`, so a quarter of the connections
  land on the worker pinned to the interrupt CPU. On set 1, where that CPU was 60-66% softirq,
  that worker answered almost nothing (1.1 M requests never answered, about 3/4 of one worker's
  1.46 M) while the other three answered their connections on time: 144k within 1 ms. On set 2,
  where the interrupt load was split over two CPUs, the same nginx answered 6.4k within 1 ms, the
  order of hyper (2.9k) and simoom (1.2-1.6k). Campaign 3's 52.4k was the same effect on another
  droplet.
- Every server sits at the NIC's packet ceiling (153-161k goodput); what is late is late because
  of TCP retransmissions after drops at the single receive queue (admitted p99 206-212 ms, the
  minimum RTO), except simoom io_uring with three loops on set 2, whose admitted p99 fell to
  9.7 ms and which has the highest goodput.
- Conclusion: at 1.17x the NIC ceiling, in-time goodput is decided by which connections the
  network drops and how the server's workers sit on the interrupt CPU, not by a server-side
  queue. K13 is recorded as a platform limit of this benchmark on c-4 droplets; the overload
  metric needs a rate below the NIC ceiling (or a multi-queue NIC) to compare servers.

## Still open

- **epoll S1 at 64 and 256 connections** on set 2: 97k and 134k against hyper's 122k and
  may-minihttp's 169k. With three loops the epoll build is not CPU-bound at 130k (CPUs 0, 1 and 3
  31-50% idle, p99 526 us) but its p99 crosses 1 ms earlier than io_uring's, which reaches 153k
  and 162k on the same droplet; so the remaining gap is in the readiness driver's turn (a `recv`
  per ready socket before any dispatch, a `sendmsg` per connection) and needs per-loop latency
  histograms to place.
- epoll S7 handshakes with three loops (-14% in one run).
- The rule is a heuristic over `/proc/softirqs` since boot; a host with several receive queues per
  NIC keeps every loop. Multi-queue droplets (larger sizes) were not measured.
