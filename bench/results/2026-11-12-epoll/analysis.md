# The epoll gap (K12 follow-up, 2026-11-12, DigitalOcean c-4, blr1)

One server droplet (srvA) and two load nodes, every variant on the same server, with
`bench/cloud/ab.sh` (campaign 3's lane settings for S1: SLO search with 4% precision,
p99 <= 1 ms). New this round:

- `FR` in `ab.sh`: fixed open-loop rates (10 s each) with a `NET` line from the server and both
  load nodes (`bench/cloud/node.sh net-begin`/`net-end`): TCP retransmits and losses, softnet and
  NIC drops, `NET_RX` softirqs and ksoftirqd time per CPU, and where the server's running threads
  were (`ps` every 0.2 s, CPU:samples).
- `S7H` in `ab.sh`: S7's full and resumed handshakes alone, repeated.
- `SIMOOM_TASKSET` (any server, `bench/competitors/lib.sh`) and `SIMOOM_BIN` (another build of the
  campaign server, `bench/competitors/simoom/run.sh`), so two builds and CPU sets run on one droplet.

Raw data: `raw/a` (batch A, build `21cbbfc`, fixed rates, three rounds), `raw/b`, `raw/b2` and
`raw/b3` (batch B, rounds 1 to 3: build `ca3d108` against `21cbbfc` kept as
`/root/simoom-server-old`), `raw/c` (batch C, the other scenarios and repeated handshakes),
`raw/spec-*` (the variant files). `srv-journal.txt` in `raw/a`, `raw/b` and `raw/c` holds the
server's per-loop `STATS` lines (a work-in-progress copy of `ab.sh` filtered them out of
`results.txt`). Build `ca3d108` is a local work-in-progress commit whose crates are the committed
fix but for one number in a comment. One droplet set, 09:11 to
12:18 UTC (three droplets, 9.4 droplet-hours); nothing left afterwards (checked with the API).

The droplet's private NIC is the same as before: virtio-net with one queue, its receive interrupt
on CPU 2 and its transmit-completion interrupt on CPU 3 (`/proc/interrupts`: `virtio2-input.0` on
CPU 2, `virtio2-output.0` on CPU 3).

## Root cause: the loops still ran on the receive-interrupt CPU

The K12 fix started three loops on four CPUs but left the threads unpinned. The scheduler's
wake-up placement prefers the waking CPU when that CPU looks idle, and a CPU that handles softirqs
from its idle loop looks idle. The loops are woken by the receive softirq on CPU 2, so they were sampled
there more than on any other CPU (batch A, build `21cbbfc`, the server's running threads summed
over 18 fixed-rate runs each):

| server | CPU 0 | CPU 1 | CPU 2 (receive IRQ) | CPU 3 |
|---|---:|---:|---:|---:|
| simoom epoll, three loops | 360 | 462 | **701** | 477 |
| simoom io_uring, three loops | 384 | 453 | **752** | 442 |
| simoom epoll, `taskset 0,1,3` | 490 | 474 | 0 | 509 |
| hyper (four threads, work stealing) | 658 | 625 | 730 | 746 |

A loop on CPU 2 gets what the softirq leaves, and every connection it holds waits for it. The open
loop keeps sending, so that loop's backlog grows for the rest of the run and the p99 goes to
hundreds of milliseconds or seconds. It is not packet loss: softnet drops, NIC drops and ksoftirqd
time were zero or nearly so in every run below 160k req/s, and the retransmits were a handful per
run (tail-loss probes). Whether a loop happened to sit on CPU 2 during a 5 s step decided pass or
fail, which is why the previous round saw epoll at 97k on one droplet and 159k on the other, and
the -14% handshakes. hyper and may-minihttp also run on CPU 2, but their other threads take the
work over.

Fixed rates, p99 in us, median of three rounds (batch A, same droplet):

| server | 64 @ 100k | 64 @ 120k | 64 @ 140k | 256 @ 120k | 256 @ 140k | 256 @ 160k |
|---|---:|---:|---:|---:|---:|---:|
| simoom epoll, three loops (as committed) | 1,314 | 23,020 | 2,392,850 | 195,690 | 1,387,266 | 2,491,417 |
| simoom io_uring, three loops (as committed) | 1,189 | 1,430 | 261,226 | 19,595 | 355,992 | 1,818,231 |
| simoom epoll, `taskset 0,1,3` (three loops) | **860** | 1,074 | 1,842 | 1,407 | 1,541 | 1,594,884 |
| simoom epoll, `taskset 0,1` (two loops) | 1,031 | **1,067** | **1,048** | **794** | **853** | 2,646,606 |
| hyper | 1,462 | 1,937 | 5,312 | 1,832 | 2,159 | 2,771 |
| may-minihttp | 1,794 | 2,144 | 2,484 | 1,598,030 | 1,804 | 2,302,673 |

This droplet's network path was slower than the previous round's (hyper over 1 ms at 100k with 64
connections in all three rounds), so fixed-rate p99s sit near 1 ms for everyone. What matters is
that the loops kept off CPU 2 no longer collapse below 160k. Two loops off both interrupt CPUs had
the lowest p99 up to 140k, but cost a third of the CPU for CPU-bound work (see "Not done").

The new build at the same rates (batch B round 1, one run each): epoll 992 / 1,788 / 1,322 us at
64 connections and 1,066 / 1,117 / 1,903 us at 256; io_uring 1,165 / 1,593 / 1,581 and
922 / 781,713 / 1,898 (the one collapse came with 726 server and 812 client retransmits, a loss
burst on the path). Its loop threads were never sampled on CPU 2.

### The epoll turn is not the problem

Per request, from the per-loop counters (batch A, fixed-rate runs at about 120-130k req/s):

| server | recv | send | epoll_wait / io_uring_enter | of them sleeps | busy-poll polls |
|---|---:|---:|---:|---:|---:|
| epoll, three loops | 1.00 | 1.00 | 0.63 | 0.54 | 0.09 |
| epoll, `taskset 0,1,3` | 1.00 | 1.00 | 0.74 | 0.63 | 0.11 |
| io_uring, three loops | completions | completions | 0.81 | 0.80 | 1.54 (in user space) |

One `recv` and one `sendmsg` per request, no reads that return `EAGAIN`, no extra writes, and
about 1.5 requests per wakeup: the readiness driver's turn wastes nothing. io_uring makes fewer
system calls (0.8 against 2.6 per request), but CPU time per request is within 1% (batch C). None
of the candidates in the brief (edge-triggered re-arm cost, `epoll_wait` batch size,
read-until-`EAGAIN`, write coalescing, the busy-poll window, the timer wheel, the fd table,
lingering close, `EPOLLEXCLUSIVE`) explains a gap that the CPU placement does not, so none was
changed.

## The fix

`simoom_sys::cpu::net_rx_concentrated` records the receive-interrupt CPU, and the loop threads keep
off it (`keep_current_thread_off_net_rx`, called when each loop thread starts and, with the lazy
start, by loop 0 once the other loops run). The CPU is the one with the most softirq **time** in
`/proc/stat`. The `NET_RX` counts of `/proc/softirqs` that the K12 check used point at the wrong
CPU here, because transmit completions are counted under `NET_RX` too: 590k on CPU 3 against 342k
on CPU 2 in one 12 s run (batch A, 256 connections at 140k), while the previous round measured CPU
2 at 65% softirq and CPU 3 at 10% (`/proc/stat` before batch A: 24,987 ticks on CPU 2, 3,922 on CPU
3, 159 and 105 on CPUs 0 and 1; at the end of the day 360,969 against 83,733, while `NET_RX`
counted 368 M on CPU 3 against 200 M on CPU 2: `raw/srv-cpu.txt`). So the concentration test moved
to `/proc/stat` as well: one CPU with at least half of all softirq time, and at least 2 s of it.
Only the default loop count does this; explicit `threads`, `cpus` or `pin_threads` keep their
meaning.

## S1, same droplet (req/s at p99 <= 1 ms)

Batch B, three rounds (rounds 2 and 3 in `raw/b2`, `raw/b3`); a cell lists the rounds, the bold
figure is the median:

| server | 64 | 256 | 1024 |
|---|---:|---:|---:|
| **simoom epoll, new** | **170,648** (170,648 / 152,714 / 171,128) | **172,638** (172,700 / 172,638 / 172,634) | 138,644 (133,242 / 138,644 / 171,309) |
| simoom io_uring, new | 152,714 (169,870 / 152,714 / 152,714) | 172,331 (92,326 / 172,331 / 172,483) | 148,429 (166,014 / 146,661 / 148,429) |
| simoom epoll, old (`21cbbfc`) | 117,014 (111,064 / 117,014 / 162,520) | 133,778 (92,326 / 133,778 / 167,583) | 87,634 (171,466 / 87,634 / 75,624) |
| simoom io_uring, old (`21cbbfc`) | 152,714 (117,014 / 169,781 / 152,714) | 167,444 (167,947 / 122,473 / 167,444) | 155,583 (169,656 / 155,583 / 144,045) |
| hyper | 122,240 (168,653 / 122,240 / 122,240) | 144,443 (144,443 / 136,191 / 157,157) | 115,102 (110,786 / 115,102 / 115,102) |
| may-minihttp | 158,598 (158,598 / 140,757 / 158,598) | 150,673 (103,242 / 155,782 / 150,673) | 120,610 (114,477 / 120,610 / 120,610) |

- **epoll leads at 64 and 256 connections in every round**: +8% and +15% over the best competitor
  at the median (may-minihttp in both), and +46% / +29% over the old
  build. At 1024 it leads hyper and may-minihttp by 10% or more in every round.
- io_uring: level with the old build at 64 and 256 (the 92k at 256 in round 1 is one collapsed
  step, a loss burst like the fixed-rate one above), 4.6% lower at 1024 at the median, about one
  sweep step at 4% precision; every round is above hyper and may-minihttp at 1024.
- epoll is 7% below io_uring at 1024 at the median: there it is closer to CPU-bound, and the
  readiness driver makes 2.6 system calls per request against 0.8. Not pursued: it leads the
  competitors there by a wide margin and the old build's 171k came with 88k and 76k in the other
  rounds.

## Other scenarios, new build against the old one (batch C, same droplet, one run each)

| scenario | epoll new | epoll old | io_uring new | io_uring old |
|---|---:|---:|---:|---:|
| S3 1 KB echo, 256 conns (SLO req/s) | 161,513 | 121,875 | 167,064 | 121,875 |
| S5 connection per request (SLO, 5 ms) | 24,652 | 18,700 | 24,660 | 25,020 |
| S7 S1 over TLS, 256 conns (SLO req/s) | 155,902 | 121,875 | 161,333 | 167,673 |
| S8 h2c, 100 streams (SLO, 5 ms) | 167,548 | 144,375 | 168,780 | 161,895 |
| CPU per request at 50k req/s (us) | **25.47** | 26.93 | **25.26** | 27.21 |

TLS handshakes per second (closed loop, 192 connections), every run:

| build | full | resumed |
|---|---|---|
| epoll, new (three loops off CPU 2) | 8,716 / 8,684 / 8,790 / 8,702 | 9,793 / 9,763 / 9,828 / 9,801 |
| epoll, old (three loops, unpinned) | 6,317 / 7,958 / 6,215 / 6,294 | 7,037 / 6,880 / 6,900 / 6,848 |
| epoll, new, `--threads 4` | 7,314 / 7,403 / 7,505 | 8,042 / 8,019 / 8,211 |
| io_uring, new | 9,024 / 8,857 / 9,382 / 9,354 | 9,957 / 10,597 / 9,967 / 9,932 |
| io_uring, old | 9,747 / 8,694 / 6,930 / 8,960 | 9,113 / 7,193 / 9,588 / 8,728 |
| io_uring, new, `--threads 4` | 7,810 / 7,702 / 7,861 | 8,594 / 8,506 / 8,535 |

- The previous round's epoll handshake figure (6.8k/7.4k with three loops against 7.9k/8.6k with
  four) was the same placement effect, not the lost loop: with the loops off CPU 2, three loops do
  8.7k/9.8k, 18% and 21% more than four loops and 38% and 42% more than the old build, steady over
  four runs. The old io_uring build varies from run to run (6.9k to 9.7k) for the same reason.
- Everything else is level or better. S7 over TLS on io_uring is one sweep step below the old build
  (161k against 168k) and S5 on io_uring 1.4% below, both within the search's 4% precision.
- CPU per request fell 5% (epoll) and 7% (io_uring).
- Memory: one static word, nothing per loop or per connection. Cold start: the default runtime
  reads `/proc/stat` instead of `/proc/softirqs` (one 4 KiB read either way; with the facade's lazy
  loops only when the other loops start) and makes two affinity calls per loop thread on a
  concentrated host. Not re-measured on a droplet.
- Size: `scripts/size.sh` (WSL, `dist`): every budgeted row keeps at least 5% headroom.
  The tightest: `http1,http2,tls,io-uring` 583,680 of 614,400 (5.0%; 583,584 before) and
  `http1,io-uring` 242,568 of 256,000 (5.2%; 242,472 before). The first version of the change cost
  3.1 KB (a CPU list in the runtime, a general affinity setter); the committed one costs 96 bytes
  in each row after merging three error prints in the runtime and one in the io_uring probe.

## Not done

- Keeping the loops off the transmit-completion CPU too (two loops on this droplet) had the lowest
  fixed-rate p99 at 64 and 256 connections up to 140k, but takes a third of the CPU from CPU-bound
  work (handshakes, S3, S8); it is left to `Config::cpus`.
- The choice uses softirq time since boot: if the traffic moved to another NIC, it can pick a CPU
  that no longer takes the receive interrupts. A multi-queue NIC spreads softirq time and keeps
  every loop, as before. Larger droplets were not measured.
- The S1 SLO search is noisy at this precision on these droplets: one bad 5 s step caps a result
  (hyper passes 168.7k at 64 connections in one round and fails 100k at a fixed rate). The fixed
  rates and the repeated handshakes are the firmer evidence.
