| test | tool | req/s | p50 us | p99 us | p99.9 us | note |
|---|---|---:|---:|---:|---:|---|
| closed-64 | wrk | 314462.15 | 105.0 | 1290000.0 | - | wrk 4.1 |
| closed-64 | simoom-bench | 530924 | 118.7 | 206.5 | 376.1 | gen cpu 34.4% |
| pipelined-16 | wrk | 3185968.67 | - | - | - | lua pipeline script (wrk counts responses) |
| pipelined-16 | simoom-bench | 5541161 | 172.8 | 350.7 | 439.3 | gen cpu 36.2% |
| open-50000 | wrk2 | 49923.95 | 920.0 | 1770000.0 | 1950000.0 | ms timers (epoll) |
| open-50000 | simoom-bench (epoll) | 49998 | 492.0 | 1197.1 | 1306.6 | timer lag p99 1028.6 us, gen cpu 5.9% |
| open-50000 | simoom-bench (io_uring) | 50000 | 82.4 | 138.2 | 694.3 | timer lag p99 47.7 us, gen cpu 12.2% |
| open-100000 | wrk2 | 99845.51 | 1440.0 | 1810000.0 | 1930000.0 | ms timers (epoll) |
| open-100000 | simoom-bench (epoll) | 99998 | 590.8 | 1256.4 | 9265.2 | timer lag p99 1067.0 us, gen cpu 10.5% |
| open-100000 | simoom-bench (io_uring) | 100000 | 93.1 | 27033.6 | 111476.7 | timer lag p99 75.8 us, gen cpu 19.7% |
| open-200000 | wrk2 | 199683.97 | 1340.0 | 1740000.0 | 1800000.0 | ms timers (epoll) |
| open-200000 | simoom-bench (epoll) | 200003 | 459.3 | 26837.0 | 73596.9 | timer lag p99 1068.0 us, gen cpu 19.6% |
| open-200000 | simoom-bench (io_uring) | 200000 | 89.8 | 441.6 | 5570.6 | timer lag p99 79.0 us, gen cpu 25.9% |
