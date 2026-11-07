| test | tool | req/s | p50 us | p99 us | p99.9 us | note |
|---|---|---:|---:|---:|---:|---|
| closed-64 | wrk | 127617.44 | 189.0 | 1280000.0 | - | wrk 4.1 |
| closed-64 | simoom-bench | 314746 | 194.6 | 437.5 | 3635.2 | gen cpu 26.8% |
| pipelined-16 | wrk | 337786.24 | - | - | - | lua pipeline script (wrk counts responses) |
| pipelined-16 | simoom-bench --batch | 357050 | 1757.2 | 5230.6 | 6623.2 | gen cpu 19.6% |
| open-50000-c1024 | wrk2 | 48441.50 | 1550.0 | 1820000.0 | 1960000.0 | ms timers (epoll) |
| open-50000-c1024 | simoom-bench (epoll) | 50001 | 565.2 | 1260.5 | 1406.0 | timer lag p99 1066.0 us, gen cpu 6.4% |
| open-50000-c1024 | simoom-bench (io_uring) | 50001 | 99.4 | 247.7 | 2711.6 | timer lag p99 60.4 us, gen cpu 13.5% |
| open-100000-c1024 | wrk2 | 94403.88 | 1460.0 | 4130.0 | 8650.0 | ms timers (epoll) |
| open-100000-c1024 | simoom-bench (epoll) | 99999 | 521.7 | 1439.7 | 4468.7 | timer lag p99 1061.9 us, gen cpu 11.5% |
| open-100000-c1024 | simoom-bench (io_uring) | 100000 | 99.3 | 5984.3 | 29179.9 | timer lag p99 87.7 us, gen cpu 19.9% |
| open-200000-c1024 | wrk2 | 194385.07 | 127170.0 | 2820000.0 | 2980000.0 | ms timers (epoll) |
| open-200000-c1024 | simoom-bench (epoll) | 199897 | 181.9 | 2656.3 | 11403.3 | timer lag p99 1035.8 us, gen cpu 20.7% |
| open-200000-c1024 | simoom-bench (io_uring) | 200623 | 271319.0 | 1072169.0 | 1296039.9 | timer lag p99 537.6 us, gen cpu 28.6% |
