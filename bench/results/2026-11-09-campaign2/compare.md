| axis | unit | campaign 1: best simoom | campaign 2: best simoom | change | campaign 1: best other | campaign 2: best other | margin 1 | margin 2 |
|---|---|---|---|---:|---|---|---:|---:|
| S1 @64 verified SLO | req/s ↑ | simoom-builder 116,154 | simoom-uring 147,520 | +27.0% | may-minihttp 150,668 | may-minihttp 152,651 | -22.9% | -3.4% |
| S1 @256 verified SLO | req/s ↑ | simoom 124,835 | simoom 137,736 | +10.3% | hyper 137,058 | may-minihttp 160,350 | -8.9% | -14.1% |
| S1 @1024 verified SLO | req/s ↑ | simoom-builder 79,626 | simoom-uring 143,865 | +80.7% | hyper 109,348 | hyper 115,102 | -27.2% | +25.0% |
| S3 1 KB echo verified SLO | req/s ↑ | simoom-builder-uring 82,823 | simoom 148,400 | +79.2% | axum 118,284 | hyper 134,251 | -30.0% | +10.5% |
| S4 64 KB verified SLO (p99 5 ms) | req/s ↑ | simoom-builder 3,649 | simoom 3,658 | +0.2% | hyper 3,658 | nginx 3,771 | -0.2% | -3.0% |
| S4 1 MB plain | Gbit/s ↑ | simoom-builder-uring 1.95 | simoom 1.95 | +0.0% | go-nethttp 1.95 | nginx 1.95 | +0.0% | +0.0% |
| S4 1 MB TLS | Gbit/s ↑ | simoom 1.95 | simoom 1.95 | +0.0% | nginx 1.95 | nginx 1.95 | +0.0% | +0.0% |
| S5 connection per request verified SLO (p99 5 ms) | req/s ↑ | simoom-uring 18,065 | simoom 23,676 | +31.1% | xitca 25,004 | cameleer 24,535 | -27.8% | -3.5% |
| S7 full TLS handshakes | per s ↑ | simoom-builder 8,713 | simoom-uring 10,213 | +17.2% | h2o 6,620 | h2o 7,152 | +31.6% | +42.8% |
| S7 resumed TLS handshakes | per s ↑ | simoom-uring 9,652 | simoom-uring 11,222 | +16.3% | h2o 6,386 | h2o 7,092 | +51.1% | +58.2% |
| S7 S1 over TLS verified SLO | req/s ↑ | simoom 114,368 | simoom-uring 150,740 | +31.8% | nginx 73,012 | h2o 87,387 | +56.6% | +72.5% |
| S8 h2c 100 streams verified SLO (p99 5 ms) | req/s ↑ | simoom-builder-uring 136,264 | simoom-default 163,874 | +20.3% | h2o 162,015 | h2o 164,149 | -15.9% | -0.2% |
| S9 goodput within 1 ms at 2x load | req/s ↑ | simoom-uring 91,073 | simoom-builder 2,508 | -97.2% | xitca 140,950 | xitca 141,393 | -35.4% | -98.2% |
| S10 legitimate p99 under attack | µs ↓ | simoom-uring 470 | simoom 456 | +3.0% | haproxy 372 | haproxy 362 | -21.0% | -20.8% |
| HTTP/3 S1 verified SLO | req/s ↑ | simoom-uring 82,320 | simoom 105,557 | +28.2% | h2o 45,655 | - | +80.3% | - |
| HTTP/3 64 KB download | Gbit/s ↑ | simoom 1.90 | simoom 1.90 | +0.0% | caddy 1.91 | h2o 1.90 | -0.4% | +0.1% |
| HTTP/3 1 MB download | Gbit/s ↑ | - | simoom 1.90 | - | caddy 1.91 | h2o 1.90 | - | +0.0% |
| CPU per request at 50k req/s (S1, every server, same rate) | µs ↓ | - | simoom 24.9 | - | - | xitca 29.2 | - | +17.4% |
| 100 ms blocking handler, 500 clients (no errors) | req/s ↑ | - | simoom-deferred 4,950 | - | - | cameleer-http-min 4,950 | - | +0.0% |
| CPU per request at a fixed rate (profile case s1) | µs ↓ | simoom 29.7 | simoom 29.7 | +0.1% | hyper 33.1 | may-minihttp 29.3 | +11.3% | -1.4% |
| CPU per request at a fixed rate (profile case s3) | µs ↓ | - | simoom 30.5 | - | - | may-minihttp 31.7 | - | +4.0% |
| cold start to first response | ms ↓ | simoom-builder 2.81 | simoom:min_server 0.78 | +72.2% | hyper 1.33 | cameleer-http-min:plain 0.94 | -52.7% | +20.5% |
| stripped binary size (native executables) | KB ↓ | simoom:bench_server 744 | simoom:min_server 722 | +2.9% | may-minihttp 515 | may-minihttp 515 | -30.8% | -28.7% |
| idle memory (PSS) after one request | MB ↓ | simoom 3.57 | simoom-default 1.99 | +44.2% | hyper 1.31 | cameleer-http-min 1.10 | -63.4% | -44.6% |
| peak memory (PSS) during S1 at 256 connections (rounds 2-3) | MB ↓ | - | simoom-default 3.62 | - | - | xitca 4.06 | - | +12.4% |
| memory per idle connection, 10k open | B ↓ | simoom 677 | simoom 913 | -34.9% | nginx 539 | nginx 538 | -20.4% | -41.1% |
| memory per idle connection, 100k open | B ↓ | simoom-builder 735 | simoom 737 | -0.3% | nginx 529 | nginx 528 | -28.0% | -28.4% |
| CPU per request at 80% of own S1 SLO | µs ↓ | simoom 34.4 | - | - | may-minihttp 17.9 | - | -47.9% | - |
| CPU per request at a fixed rate (profile case s5) | µs ↓ | simoom 92.7 | - | - | nginx 95.8 | - | +3.3% | - |
| CPU per request at a fixed rate (profile case s7) | µs ↓ | simoom 401 | - | - | h2o 656 | - | +63.8% | - |
| CPU per request at a fixed rate (profile case s8) | µs ↓ | simoom 30.7 | - | - | hyper 39.7 | - | +29.6% | - |

change: improvement of simoom's best variant (positive is better on every axis); margin: simoom's best against the best other server (positive: simoom ahead).
