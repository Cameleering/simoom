| axis | unit | campaign 2: best simoom | campaign 3: best simoom | change | campaign 2: best other | campaign 3: best other | margin 2 | margin 3 |
|---|---|---|---|---:|---|---|---:|---:|
| S1 @64 verified SLO | req/s ↑ | simoom-uring 147,520 | simoom-uring 142,797 | -3.2% | may-minihttp 152,651 | may-minihttp 158,584 | -3.4% | -10.0% |
| S1 @256 verified SLO | req/s ↑ | simoom 137,736 | simoom-uring 115,418 | -16.2% | may-minihttp 160,350 | may-minihttp 163,876 | -14.1% | -29.6% |
| S1 @1024 verified SLO | req/s ↑ | simoom-uring 143,865 | simoom-uring 138,644 | -3.6% | hyper 115,102 | hyper 166,948 | +25.0% | -17.0% |
| S3 1 KB echo verified SLO | req/s ↑ | simoom 148,400 | simoom-uring 153,526 | +3.5% | hyper 134,251 | hyper 152,822 | +10.5% | +0.5% |
| S4 64 KB verified SLO (p99 5 ms) | req/s ↑ | simoom 3,658 | simoom 3,776 | +3.2% | nginx 3,771 | nginx 3,768 | -3.0% | +0.2% |
| S4 1 MB plain | Gbit/s ↑ | simoom 1.95 | simoom 1.95 | -0.4% | nginx 1.95 | nginx 1.95 | +0.0% | +0.0% |
| S4 1 MB TLS | Gbit/s ↑ | simoom 1.95 | simoom 1.94 | -0.4% | nginx 1.95 | nginx 1.94 | +0.0% | +0.0% |
| S5 connection per request verified SLO (p99 5 ms) | req/s ↑ | simoom 23,676 | simoom-uring 22,117 | -6.6% | cameleer 24,535 | xitca 24,345 | -3.5% | -9.2% |
| S7 full TLS handshakes | per s ↑ | simoom-uring 10,213 | simoom-uring 10,083 | -1.3% | h2o 7,152 | h2o 7,711 | +42.8% | +30.8% |
| S7 resumed TLS handshakes | per s ↑ | simoom-uring 11,222 | simoom-uring 11,213 | -0.1% | h2o 7,092 | h2o 7,758 | +58.2% | +44.5% |
| S7 S1 over TLS verified SLO | req/s ↑ | simoom-uring 150,740 | simoom-uring 160,441 | +6.4% | h2o 87,387 | h2o 97,219 | +72.5% | +65.0% |
| S8 h2c 100 streams verified SLO (p99 5 ms) | req/s ↑ | simoom-default 163,874 | simoom 153,179 | -6.5% | h2o 164,149 | h2o 152,608 | -0.2% | +0.4% |
| S9 goodput within 1 ms at 2x load | req/s ↑ | simoom-builder 2,508 | simoom-uring 6,427 | +156.3% | xitca 141,393 | nginx 52,370 | -98.2% | -87.7% |
| S10 legitimate p99 under attack | µs ↓ | simoom 456 | simoom-uring 517 | -13.3% | haproxy 362 | nginx 458 | -20.8% | -11.4% |
| HTTP/3 S1 verified SLO | req/s ↑ | simoom 105,557 | simoom-uring 106,947 | +1.3% | - | h2o 94,507 | - | +13.2% |
| HTTP/3 64 KB download | Gbit/s ↑ | simoom 1.90 | simoom-uring 1.90 | +0.0% | h2o 1.90 | h2o 1.90 | +0.1% | +0.1% |
| HTTP/3 1 MB download | Gbit/s ↑ | simoom 1.90 | simoom 1.90 | +0.0% | h2o 1.90 | h2o 1.90 | +0.0% | +0.0% |
| CPU per request at 50k req/s (S1, every server, same rate) | µs ↓ | simoom 24.9 | simoom-uring 25.1 | -0.6% | xitca 29.2 | may-minihttp 27.2 | +17.4% | +8.6% |
| 100 ms blocking handler, 500 clients (no errors) | req/s ↑ | simoom-deferred 4,950 | simoom-deferred 4,926 | -0.5% | cameleer-http-min 4,950 | cameleer-http-min 4,925 | +0.0% | +0.0% |
| CPU per request at a fixed rate (profile case s1) | µs ↓ | simoom 29.7 | simoom 31.1 | -4.9% | may-minihttp 29.3 | - | -1.4% | - |
| cold start to first response | ms ↓ | simoom:min_server 0.78 | simoom:min_server 0.91 | -16.7% | cameleer-http-min:plain 0.94 | hyper 1.23 | +20.5% | +35.2% |
| stripped binary size (native executables) | KB ↓ | simoom:min_server 722 | simoom:min_server-h1 536 | +25.8% | may-minihttp 515 | may-minihttp 515 | -28.7% | -3.9% |
| idle memory (PSS) after one request | MB ↓ | simoom-default 1.99 | simoom-default 0.96 | +51.7% | cameleer-http-min 1.10 | cameleer-http-min 1.12 | -44.6% | +16.3% |
| peak memory (PSS) during S1 at 256 connections (rounds 2-3) | MB ↓ | simoom-default 3.62 | simoom-default 2.54 | +29.8% | xitca 4.06 | xitca 4.05 | +12.4% | +59.6% |
| memory per idle connection, 10k open | B ↓ | simoom 913 | simoom 594 | +34.9% | nginx 538 | nginx 522 | -41.1% | -12.1% |
| memory per idle connection, 100k open | B ↓ | simoom 737 | simoom-default 520 | +29.4% | nginx 528 | cameleer-http-min 407 | -28.4% | -21.7% |
| CPU per request at a fixed rate (profile case s3) | µs ↓ | simoom 30.5 | - | - | may-minihttp 31.7 | - | +4.0% | - |

change: improvement of simoom's best variant (positive is better on every axis); margin: simoom's best against the best other server (positive: simoom ahead).
