# Campaign 4: every competitor against simoom on the same droplet

Each ratio compares a server with the simoom run on the same droplet, with the same load nodes, in the same round;
the figure is the median over rounds. `simoom 1.30x` means simoom is 1.30 times better on that metric
(more throughput, or less latency, memory or time). Losses are marked in bold.

## Status endpoint, 64 clients: requests/s with 99% within 1 ms

`s1-64` · use case `status` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| may-minihttp | 158,598 req/s | 137,443 req/s | **1.15x ahead of simoom** | 1 |
| **simoom** | 128,914 req/s | - | reference | 3 |
| cameleer-http-min | 113,042 req/s | 137,443 req/s | simoom 1.22x | 1 |
| nginx | 108,684 req/s | 137,443 req/s | simoom 1.26x | 1 |
| vertx | 104,411 req/s | 69,415 req/s | **1.50x ahead of simoom** | 1 |
| haproxy | 103,791 req/s | 137,443 req/s | simoom 1.32x | 1 |
| actix | 99,838 req/s | 128,914 req/s | simoom 1.29x | 1 |
| ntex | 98,846 req/s | 128,914 req/s | simoom 1.30x | 1 |
| axum | 96,227 req/s | 128,914 req/s | simoom 1.34x | 1 |
| fasthttp | 86,701 req/s | 69,415 req/s | **1.25x ahead of simoom** | 1 |
| hyper | 84,364 req/s | 128,914 req/s | simoom 1.53x | 1 |
| netty | 83,229 req/s | 69,415 req/s | **1.20x ahead of simoom** | 1 |
| uws | 78,369 req/s | 69,415 req/s | **1.13x ahead of simoom** | 1 |
| xitca | 76,678 req/s | 128,914 req/s | simoom 1.68x | 1 |
| h2o | 70,543 req/s | 137,443 req/s | simoom 1.95x | 1 |
| kestrel | 38,276 req/s | 69,415 req/s | simoom 1.81x | 1 |
| envoy | 36,925 req/s | 137,443 req/s | simoom 3.72x | 1 |
| go-nethttp | 31,854 req/s | 69,415 req/s | simoom 2.18x | 1 |
| caddy | 18,937 req/s | 137,443 req/s | simoom 7.26x | 1 |
| simoom-default | 0 req/s | 69,415 req/s | only simoom met the target | 1 |

## Status endpoint, 256 clients: requests/s with 99% within 1 ms

`s1-256` · use case `status` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| may-minihttp | 154,590 req/s | 145,171 req/s | **1.06x ahead of simoom** | 3 |
| simoom-default | 147,145 req/s | 102,713 req/s | **1.43x ahead of simoom** | 3 |
| **simoom** | 137,889 req/s | - | reference | 9 |
| hyper | 110,931 req/s | 137,889 req/s | simoom 1.24x | 3 |
| ntex | 108,326 req/s | 137,890 req/s | simoom 1.27x | 3 |
| actix | 106,566 req/s | 137,890 req/s | simoom 1.29x | 3 |
| axum | 101,477 req/s | 137,890 req/s | simoom 1.36x | 3 |
| vertx | 100,036 req/s | 102,713 req/s | level (within 3%) | 3 |
| netty | 96,967 req/s | 102,713 req/s | simoom 1.06x | 3 |
| fasthttp | 95,444 req/s | 102,713 req/s | simoom 1.08x | 3 |
| xitca | 92,021 req/s | 137,890 req/s | simoom 1.50x | 3 |
| haproxy | 91,915 req/s | 145,171 req/s | simoom 1.58x | 3 |
| uws | 59,138 req/s | 92,326 req/s | simoom 1.56x | 3 |
| nginx | 57,179 req/s | 145,082 req/s | simoom 2.54x | 3 |
| h2o | 40,551 req/s | 145,082 req/s | simoom 3.58x | 3 |
| kestrel | 36,871 req/s | 102,713 req/s | simoom 2.79x | 3 |
| envoy | 24,900 req/s | 145,171 req/s | simoom 5.83x | 3 |
| go-nethttp | 24,600 req/s | 92,326 req/s | simoom 3.75x | 3 |
| caddy | 12,546 req/s | 145,082 req/s | simoom 11.56x | 3 |
| cameleer-http-min | 0 req/s | 145,082 req/s | only simoom met the target | 3 |

## Status endpoint, 1,024 clients: requests/s with 99% within 1 ms

`s1-1024` · use case `status` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| may-minihttp | 155,048 req/s | 133,243 req/s | **1.16x ahead of simoom** | 1 |
| **simoom** | 133,243 req/s | - | reference | 3 |
| nginx | 111,554 req/s | 133,243 req/s | simoom 1.19x | 1 |
| haproxy | 106,530 req/s | 133,243 req/s | simoom 1.25x | 1 |
| cameleer-http-min | 103,814 req/s | 133,243 req/s | simoom 1.28x | 1 |
| hyper | 102,154 req/s | 153,049 req/s | simoom 1.50x | 1 |
| actix | 83,023 req/s | 153,049 req/s | simoom 1.84x | 1 |
| axum | 76,953 req/s | 153,049 req/s | simoom 1.99x | 1 |
| ntex | 75,739 req/s | 153,049 req/s | simoom 2.02x | 1 |
| h2o | 67,646 req/s | 133,243 req/s | simoom 1.97x | 1 |
| xitca | 65,436 req/s | 153,049 req/s | simoom 2.34x | 1 |
| uws | 63,776 req/s | 95,611 req/s | simoom 1.50x | 1 |
| fasthttp | 57,512 req/s | 95,611 req/s | simoom 1.66x | 1 |
| vertx | 56,886 req/s | 95,611 req/s | simoom 1.68x | 1 |
| netty | 54,326 req/s | 95,611 req/s | simoom 1.76x | 1 |
| envoy | 31,869 req/s | 133,243 req/s | simoom 4.18x | 1 |
| kestrel | 30,702 req/s | 95,611 req/s | simoom 3.11x | 1 |
| go-nethttp | 19,118 req/s | 95,611 req/s | simoom 5.00x | 1 |
| caddy | 12,587 req/s | 133,243 req/s | simoom 10.59x | 1 |
| simoom-default | 0 req/s | 95,611 req/s | only simoom met the target | 1 |

## Latency at a fixed 50,000 requests/s (256 clients): p99

`p99-50k` · use case `status` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 311 µs | 325 µs | **1.04x ahead of simoom** | 3 |
| **simoom** | 355 µs | - | reference | 9 |
| vertx | 391 µs | 384 µs | level (within 3%) | 3 |
| may-minihttp | 400 µs | 356 µs | simoom 1.13x | 3 |
| axum | 404 µs | 346 µs | simoom 1.17x | 3 |
| xitca | 405 µs | 387 µs | simoom 1.05x | 3 |
| actix | 410 µs | 387 µs | simoom 1.06x | 3 |
| ntex | 416 µs | 387 µs | simoom 1.08x | 3 |
| hyper | 418 µs | 387 µs | simoom 1.08x | 3 |
| fasthttp | 431 µs | 366 µs | simoom 1.18x | 3 |
| haproxy | 441 µs | 356 µs | simoom 1.24x | 3 |
| uws | 442 µs | 366 µs | simoom 1.21x | 3 |
| netty | 480 µs | 366 µs | simoom 1.31x | 3 |
| cameleer-http-min | 608 µs | 356 µs | simoom 1.71x | 3 |
| nginx | 839 µs | 356 µs | simoom 2.36x | 3 |
| h2o | 1,451 µs | 355 µs | simoom 4.09x | 3 |
| kestrel | 1,629 µs | 384 µs | simoom 4.24x | 3 |
| go-nethttp | 3,140 µs | 384 µs | simoom 8.17x | 3 |
| caddy | 1,519,387 µs | 355 µs | simoom 4282.37x | 3 |
| envoy | 2,102,395 µs | 355 µs | simoom 5925.58x | 3 |

## CPU per request at a fixed 50,000 requests/s

`cpu-50k` · use case `status` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 20.3 µs | 21.3 µs | **1.05x ahead of simoom** | 3 |
| **simoom** | 23.6 µs | - | reference | 9 |
| may-minihttp | 28.6 µs | 24.3 µs | simoom 1.17x | 3 |
| vertx | 30.4 µs | 24.5 µs | simoom 1.24x | 3 |
| actix | 31.2 µs | 24.1 µs | simoom 1.30x | 3 |
| ntex | 32.1 µs | 24.1 µs | simoom 1.33x | 3 |
| xitca | 32.4 µs | 24.1 µs | simoom 1.35x | 3 |
| hyper | 32.6 µs | 24.1 µs | simoom 1.35x | 3 |
| nginx | 32.9 µs | 24.3 µs | simoom 1.35x | 3 |
| fasthttp | 33.2 µs | 21.3 µs | simoom 1.56x | 3 |
| uws | 34.2 µs | 24.5 µs | simoom 1.40x | 3 |
| netty | 34.6 µs | 24.5 µs | simoom 1.41x | 3 |
| axum | 35.6 µs | 23.6 µs | simoom 1.51x | 3 |
| cameleer-http-min | 36.2 µs | 24.3 µs | simoom 1.49x | 3 |
| haproxy | 36.6 µs | 24.3 µs | simoom 1.50x | 3 |
| h2o | 47.0 µs | 24.3 µs | simoom 1.93x | 3 |
| go-nethttp | 53.0 µs | 23.7 µs | simoom 2.24x | 3 |
| kestrel | 64.1 µs | 23.7 µs | simoom 2.71x | 3 |
| envoy | 68.4 µs | 21.1 µs | simoom 3.24x | 3 |
| caddy | 86.3 µs | 24.3 µs | simoom 3.55x | 3 |

## JSON API, 1 KB in and out, 256 clients: requests/s with 99% within 1 ms

`s3` · use case `api` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 138,177 req/s | 135,188 req/s | level (within 3%) | 3 |
| axum | 127,598 req/s | 161,438 req/s | simoom 1.27x | 3 |
| may-minihttp | 124,126 req/s | 118,427 req/s | **1.05x ahead of simoom** | 3 |
| **simoom** | 118,427 req/s | - | reference | 9 |
| netty | 109,736 req/s | 135,188 req/s | simoom 1.23x | 3 |
| vertx | 101,178 req/s | 135,188 req/s | simoom 1.34x | 3 |
| fasthttp | 86,456 req/s | 109,366 req/s | simoom 1.26x | 3 |
| ntex | 83,326 req/s | 95,678 req/s | simoom 1.15x | 3 |
| hyper | 71,171 req/s | 84,755 req/s | simoom 1.19x | 3 |
| uws | 57,141 req/s | 109,366 req/s | simoom 1.91x | 3 |
| actix | 54,349 req/s | 84,755 req/s | simoom 1.56x | 3 |
| kestrel | 22,515 req/s | 109,366 req/s | simoom 4.86x | 3 |
| go-nethttp | 20,755 req/s | 109,366 req/s | simoom 5.27x | 3 |

## 64 KB downloads, 64 clients: requests/s with 99% within 5 ms

`s4-64k` · use case `download` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| actix | 3,780 req/s | 3,773 req/s | level (within 3%) | 1 |
| nginx | 3,780 req/s | 3,786 req/s | level (within 3%) | 1 |
| axum | 3,779 req/s | 3,773 req/s | level (within 3%) | 1 |
| caddy | 3,779 req/s | 3,786 req/s | level (within 3%) | 1 |
| hyper | 3,776 req/s | 3,773 req/s | level (within 3%) | 1 |
| simoom-default | 3,775 req/s | 3,772 req/s | level (within 3%) | 1 |
| **simoom** | 3,773 req/s | - | reference | 3 |
| h2o | 3,773 req/s | 3,786 req/s | level (within 3%) | 1 |
| go-nethttp | 3,771 req/s | 3,772 req/s | level (within 3%) | 1 |

## A new connection per request, 192 clients: requests/s with 99% within 5 ms

`s5` · use case `newconn` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 30,274 req/s | 30,488 req/s | level (within 3%) | 3 |
| fasthttp | 23,317 req/s | 30,488 req/s | simoom 1.31x | 3 |
| may-minihttp | 23,052 req/s | 22,116 req/s | **1.04x ahead of simoom** | 3 |
| nginx | 22,618 req/s | 22,116 req/s | level (within 3%) | 3 |
| xitca | 21,149 req/s | 16,359 req/s | **1.29x ahead of simoom** | 3 |
| haproxy | 19,946 req/s | 22,116 req/s | simoom 1.11x | 3 |
| h2o | 18,847 req/s | 22,116 req/s | simoom 1.17x | 3 |
| **simoom** | 17,323 req/s | - | reference | 9 |
| actix | 17,137 req/s | 16,359 req/s | **1.05x ahead of simoom** | 3 |
| caddy | 17,055 req/s | 22,116 req/s | simoom 1.30x | 3 |
| hyper | 16,378 req/s | 16,359 req/s | level (within 3%) | 3 |
| cameleer-http-min | 15,961 req/s | 14,684 req/s | **1.09x ahead of simoom** | 3 |
| uws | 15,887 req/s | 17,323 req/s | simoom 1.09x | 3 |
| ntex | 15,388 req/s | 16,359 req/s | simoom 1.06x | 3 |
| go-nethttp | 15,226 req/s | 17,323 req/s | simoom 1.14x | 3 |
| axum | 15,009 req/s | 16,359 req/s | simoom 1.09x | 3 |
| vertx | 13,747 req/s | 17,323 req/s | simoom 1.26x | 3 |
| netty | 12,852 req/s | 17,323 req/s | simoom 1.35x | 3 |
| kestrel | 12,206 req/s | 17,323 req/s | simoom 1.42x | 3 |
| envoy | 10,848 req/s | 22,116 req/s | simoom 2.04x | 3 |

## HTTPS API, 256 clients: requests/s with 99% within 1 ms

`s7-tls` · use case `https` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| **simoom** | 134,004 req/s | - | reference | 9 |
| axum-rustls | 103,343 req/s | 134,004 req/s | simoom 1.30x | 3 |
| h2o | 79,386 req/s | 103,311 req/s | simoom 1.30x | 3 |
| haproxy | 61,431 req/s | 103,311 req/s | simoom 1.68x | 3 |
| nginx | 40,777 req/s | 103,311 req/s | simoom 2.53x | 3 |
| go-nethttp | 28,755 req/s | 167,300 req/s | simoom 5.82x | 3 |
| caddy | 11,843 req/s | 103,311 req/s | simoom 8.72x | 3 |
| cameleer-http-min | 0 req/s | 103,311 req/s | only simoom met the target | 3 |

## New TLS 1.3 clients: full handshakes per second

`s7-full` · use case `https` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| axum-rustls | 11,633 /s | 9,396 /s | **1.24x ahead of simoom** | 3 |
| **simoom** | 9,431 /s | - | reference | 9 |
| h2o | 6,464 /s | 8,973 /s | simoom 1.39x | 3 |
| go-nethttp | 5,247 /s | 9,410 /s | simoom 1.79x | 3 |
| caddy | 4,928 /s | 8,973 /s | simoom 1.82x | 3 |
| nginx | 3,695 /s | 8,973 /s | simoom 2.43x | 3 |
| haproxy | 3,483 /s | 8,973 /s | simoom 2.58x | 3 |
| cameleer-http-min | 1,517 /s | 8,973 /s | simoom 5.91x | 3 |

## Returning TLS 1.3 clients: resumed handshakes per second

`s7-resumed` · use case `https` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| axum-rustls | 13,537 /s | 12,388 /s | **1.09x ahead of simoom** | 3 |
| **simoom** | 10,565 /s | - | reference | 9 |
| go-nethttp | 6,555 /s | 12,717 /s | simoom 1.94x | 3 |
| h2o | 6,351 /s | 9,924 /s | simoom 1.56x | 3 |
| caddy | 5,163 /s | 9,924 /s | simoom 1.92x | 3 |
| cameleer-http-min | 4,487 /s | 9,924 /s | simoom 2.21x | 3 |
| nginx | 4,216 /s | 9,924 /s | simoom 2.35x | 3 |
| haproxy | 4,004 /s | 9,924 /s | simoom 2.48x | 3 |

## Service-to-service HTTP/2, 64 connections x 100 streams: requests/s with 99% within 5 ms

`s8` · use case `h2` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| h2o | 168,962 req/s | 152,445 req/s | **1.11x ahead of simoom** | 1 |
| haproxy | 154,298 req/s | 152,445 req/s | level (within 3%) | 1 |
| **simoom** | 153,230 req/s | - | reference | 3 |
| simoom-default | 149,947 req/s | 153,230 req/s | level (within 3%) | 1 |
| hyper | 143,530 req/s | 153,232 req/s | simoom 1.07x | 1 |
| axum | 124,765 req/s | 153,232 req/s | simoom 1.23x | 1 |
| vertx | 102,563 req/s | 153,230 req/s | simoom 1.49x | 1 |
| nginx | 87,443 req/s | 152,445 req/s | simoom 1.74x | 1 |
| kestrel | 82,084 req/s | 153,230 req/s | simoom 1.87x | 1 |
| actix | 72,914 req/s | 153,232 req/s | simoom 2.10x | 1 |
| envoy | 48,266 req/s | 152,445 req/s | simoom 3.16x | 1 |
| go-nethttp | 35,588 req/s | 153,230 req/s | simoom 4.31x | 1 |
| caddy | 14,206 req/s | 152,445 req/s | simoom 10.73x | 1 |

## HTTP/3, 64 clients: requests/s with 99% within 1 ms

`h3` · use case `h3` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| **simoom** | 75,916 req/s | - | reference | 9 |
| h2o | 74,961 req/s | 52,259 req/s | **1.43x ahead of simoom** | 3 |
| quinn-h3 | 42,518 req/s | 70,001 req/s | simoom 1.65x | 3 |
| caddy | 3,370 req/s | 52,259 req/s | simoom 15.51x | 3 |

## Traffic spike at 195,000 requests/s offered: answers within 1 ms per second

`s9` · use case `spike` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| actix | 59,015 req/s | 2,743 req/s | **21.51x ahead of simoom** | 1 |
| nginx | 29,135 req/s | 6,264 req/s | **4.65x ahead of simoom** | 1 |
| xitca | 8,887 req/s | 2,743 req/s | **3.24x ahead of simoom** | 1 |
| haproxy | 8,462 req/s | 6,264 req/s | **1.35x ahead of simoom** | 1 |
| may-minihttp | 4,811 req/s | 6,264 req/s | simoom 1.30x | 1 |
| uws | 4,796 req/s | 3,309 req/s | **1.45x ahead of simoom** | 1 |
| vertx | 4,724 req/s | 3,309 req/s | **1.43x ahead of simoom** | 1 |
| netty | 4,078 req/s | 3,309 req/s | **1.23x ahead of simoom** | 1 |
| fasthttp | 4,053 req/s | 3,309 req/s | **1.22x ahead of simoom** | 1 |
| simoom-default | 3,963 req/s | 3,309 req/s | **1.20x ahead of simoom** | 1 |
| cameleer-http-min | 3,724 req/s | 6,264 req/s | simoom 1.68x | 1 |
| ntex | 3,524 req/s | 2,743 req/s | **1.28x ahead of simoom** | 1 |
| **simoom** | 3,309 req/s | - | reference | 3 |
| hyper | 2,179 req/s | 2,743 req/s | simoom 1.26x | 1 |
| axum | 956 req/s | 2,743 req/s | simoom 2.87x | 1 |
| h2o | 231 req/s | 6,264 req/s | simoom 27.12x | 1 |
| envoy | 0 req/s | 6,264 req/s | only simoom met the target | 1 |
| caddy | 0 req/s | 6,264 req/s | only simoom met the target | 1 |
| go-nethttp | 0 req/s | 3,309 req/s | only simoom met the target | 1 |
| kestrel | 0 req/s | 3,309 req/s | only simoom met the target | 1 |

## Traffic spike: all answers per second

`s9-total` · use case `spike` · higher is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| axum | 160,356 req/s | 155,270 req/s | **1.03x ahead of simoom** | 1 |
| cameleer-http-min | 160,264 req/s | 159,868 req/s | level (within 3%) | 1 |
| nginx | 160,028 req/s | 159,868 req/s | level (within 3%) | 1 |
| haproxy | 160,007 req/s | 159,868 req/s | level (within 3%) | 1 |
| xitca | 159,705 req/s | 155,270 req/s | level (within 3%) | 1 |
| uws | 159,633 req/s | 150,344 req/s | **1.06x ahead of simoom** | 1 |
| vertx | 159,263 req/s | 150,344 req/s | **1.06x ahead of simoom** | 1 |
| may-minihttp | 159,107 req/s | 159,868 req/s | level (within 3%) | 1 |
| actix | 157,873 req/s | 155,270 req/s | level (within 3%) | 1 |
| hyper | 157,030 req/s | 155,270 req/s | level (within 3%) | 1 |
| ntex | 155,665 req/s | 155,270 req/s | level (within 3%) | 1 |
| fasthttp | 155,502 req/s | 150,344 req/s | **1.03x ahead of simoom** | 1 |
| **simoom** | 155,270 req/s | - | reference | 3 |
| simoom-default | 155,112 req/s | 150,344 req/s | **1.03x ahead of simoom** | 1 |
| netty | 153,384 req/s | 150,344 req/s | level (within 3%) | 1 |
| kestrel | 151,455 req/s | 150,344 req/s | level (within 3%) | 1 |
| go-nethttp | 77,379 req/s | 150,344 req/s | simoom 1.94x | 1 |
| h2o | 65,179 req/s | 159,868 req/s | simoom 2.45x | 1 |
| envoy | 54,944 req/s | 159,868 req/s | simoom 2.91x | 1 |
| caddy | 37,083 req/s | 159,868 req/s | simoom 4.31x | 1 |

## Under 11,000 slow attackers: p99 of real requests

`s10` · use case `attack` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| haproxy | 375 µs | 568 µs | **1.51x ahead of simoom** | 1 |
| go-nethttp | 445 µs | 791 µs | **1.78x ahead of simoom** | 1 |
| h2o | 462 µs | 568 µs | **1.23x ahead of simoom** | 1 |
| caddy | 561 µs | 568 µs | level (within 3%) | 1 |
| vertx | 578 µs | 791 µs | **1.37x ahead of simoom** | 1 |
| netty | 632 µs | 791 µs | **1.25x ahead of simoom** | 1 |
| **simoom** | 791 µs | - | reference | 3 |
| fasthttp | 799 µs | 791 µs | level (within 3%) | 1 |
| hyper | 1,026 µs | 1,002 µs | level (within 3%) | 1 |
| simoom-default | 1,028 µs | 791 µs | simoom 1.30x | 1 |
| axum | 1,065 µs | 1,002 µs | simoom 1.06x | 1 |
| may-minihttp | 1,073 µs | 568 µs | simoom 1.89x | 1 |
| nginx | 1,146 µs | 568 µs | simoom 2.02x | 1 |
| uws | 2,171 µs | 791 µs | simoom 2.74x | 1 |
| envoy | 4,147 µs | 568 µs | simoom 7.30x | 1 |
| actix | 4,428 µs | 1,002 µs | simoom 4.42x | 1 |
| xitca | 6,844 µs | 1,002 µs | simoom 6.83x | 1 |
| ntex | 17,285 µs | 1,002 µs | simoom 17.24x | 1 |
| kestrel | 159,777 µs | 791 µs | simoom 201.99x | 1 |
| cameleer-http-min | 31,708,938 µs | 568 µs | simoom 55845.26x | 1 |

## 10,000 idle connections: memory per connection

`idle-10k` · use case `idle` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| nginx | 538 B | 575 B | **1.07x ahead of simoom** | 1 |
| **simoom** | 573 B | - | reference | 3 |
| simoom-default | 576 B | 570 B | level (within 3%) | 1 |
| uws | 1,038 B | 570 B | simoom 1.82x | 1 |
| h2o | 1,681 B | 575 B | simoom 2.92x | 1 |
| haproxy | 1,682 B | 575 B | simoom 2.93x | 1 |
| cameleer-http-min | 3,363 B | 575 B | simoom 5.85x | 1 |
| netty | 7,207 B | 570 B | simoom 12.64x | 1 |
| xitca | 7,412 B | 573 B | simoom 12.94x | 1 |
| vertx | 9,772 B | 570 B | simoom 17.14x | 1 |
| kestrel | 10,564 B | 570 B | simoom 18.53x | 1 |
| actix | 11,892 B | 573 B | simoom 20.75x | 1 |
| fasthttp | 16,581 B | 570 B | simoom 29.09x | 1 |
| envoy | 17,544 B | 575 B | simoom 30.51x | 1 |
| hyper | 17,790 B | 573 B | simoom 31.05x | 1 |
| ntex | 18,674 B | 573 B | simoom 32.59x | 1 |
| may-minihttp | 20,293 B | 575 B | simoom 35.29x | 1 |
| go-nethttp | 21,714 B | 570 B | simoom 38.09x | 1 |
| axum | 21,888 B | 573 B | simoom 38.20x | 1 |
| caddy | 28,449 B | 575 B | simoom 49.48x | 1 |

## 100,000 idle connections: memory per connection

`idle-100k` · use case `idle` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 522 B | 531 B | level (within 3%) | 1 |
| nginx | 528 B | 532 B | level (within 3%) | 1 |
| **simoom** | 532 B | - | reference | 3 |
| haproxy | 1,311 B | 532 B | simoom 2.46x | 1 |
| h2o | 1,680 B | 532 B | simoom 3.16x | 1 |
| netty | 4,598 B | 531 B | simoom 8.66x | 1 |
| vertx | 6,839 B | 531 B | simoom 12.88x | 1 |
| kestrel | 10,162 B | 531 B | simoom 19.14x | 1 |
| actix | 10,649 B | 535 B | simoom 19.90x | 1 |
| hyper | 16,293 B | 535 B | simoom 30.45x | 1 |
| fasthttp | 16,312 B | 531 B | simoom 30.72x | 1 |
| envoy | 17,303 B | 532 B | simoom 32.52x | 1 |
| axum | 20,356 B | 535 B | simoom 38.05x | 1 |
| go-nethttp | 20,398 B | 531 B | simoom 38.41x | 1 |
| may-minihttp | 21,035 B | 532 B | simoom 39.54x | 1 |
| caddy | 36,864 B | 532 B | simoom 69.29x | 1 |

## Start-up, process start to first answer: simoom's default build (HTTP/1.1, HTTP/2, WebSocket)

`cold-plain` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| **simoom** | 0.94 ms | - | reference | 4 |
| simoom-default | 0.98 ms | 0.97 ms | level (within 3%) | 1 |
| hyper | 1.48 ms | 0.94 ms | simoom 1.57x | 1 |
| axum | 1.56 ms | 0.94 ms | simoom 1.66x | 1 |
| cameleer-http-min | 1.74 ms | 0.90 ms | simoom 1.93x | 1 |
| actix | 1.81 ms | 0.94 ms | simoom 1.93x | 1 |
| axum-rustls | 1.91 ms | 0.94 ms | simoom 2.03x | 1 |
| quinn-h3 | 1.96 ms | 0.94 ms | simoom 2.09x | 1 |
| ntex | 2.07 ms | 0.94 ms | simoom 2.20x | 1 |
| fasthttp | 3.04 ms | 0.97 ms | simoom 3.13x | 1 |
| xitca | 3.29 ms | 0.94 ms | simoom 3.50x | 1 |
| go-nethttp | 3.74 ms | 0.97 ms | simoom 3.86x | 1 |
| may-minihttp | 8.03 ms | 0.90 ms | simoom 8.92x | 1 |
| h2o | 14.34 ms | 0.90 ms | simoom 15.93x | 1 |
| nginx | 19.57 ms | 0.90 ms | simoom 21.74x | 1 |
| caddy | 33.32 ms | 0.90 ms | simoom 37.02x | 1 |
| envoy | 72.84 ms | 0.90 ms | simoom 80.93x | 1 |
| uws | 112.58 ms | 0.97 ms | simoom 116.06x | 1 |
| haproxy | 200.42 ms | 0.90 ms | simoom 222.69x | 1 |
| kestrel | 366.56 ms | 0.95 ms | simoom 385.85x | 1 |
| netty | 467.01 ms | 0.95 ms | simoom 491.59x | 1 |
| vertx | 723.57 ms | 0.95 ms | simoom 761.65x | 1 |

## Start-up, process start to first answer: simoom's full server (also TLS 1.3 and HTTP/3)

`cold` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 0.98 ms | 1.73 ms | **1.77x ahead of simoom** | 1 |
| hyper | 1.48 ms | 1.46 ms | level (within 3%) | 1 |
| **simoom** | 1.49 ms | - | reference | 4 |
| axum | 1.56 ms | 1.46 ms | simoom 1.07x | 1 |
| cameleer-http-min | 1.74 ms | 1.20 ms | simoom 1.45x | 1 |
| actix | 1.81 ms | 1.46 ms | simoom 1.24x | 1 |
| axum-rustls | 1.91 ms | 1.46 ms | simoom 1.31x | 1 |
| quinn-h3 | 1.96 ms | 1.46 ms | simoom 1.34x | 1 |
| ntex | 2.07 ms | 1.46 ms | simoom 1.42x | 1 |
| fasthttp | 3.04 ms | 1.73 ms | simoom 1.76x | 1 |
| xitca | 3.29 ms | 1.46 ms | simoom 2.25x | 1 |
| go-nethttp | 3.74 ms | 1.73 ms | simoom 2.16x | 1 |
| may-minihttp | 8.03 ms | 1.20 ms | simoom 6.69x | 1 |
| h2o | 14.34 ms | 1.20 ms | simoom 11.95x | 1 |
| nginx | 19.57 ms | 1.20 ms | simoom 16.31x | 1 |
| caddy | 33.32 ms | 1.20 ms | simoom 27.77x | 1 |
| envoy | 72.84 ms | 1.20 ms | simoom 60.70x | 1 |
| uws | 112.58 ms | 1.73 ms | simoom 65.08x | 1 |
| haproxy | 200.42 ms | 1.20 ms | simoom 167.02x | 1 |
| kestrel | 366.56 ms | 1.52 ms | simoom 241.16x | 1 |
| netty | 467.01 ms | 1.52 ms | simoom 307.24x | 1 |
| vertx | 723.57 ms | 1.52 ms | simoom 476.03x | 1 |

## Program size, stripped: simoom's default build (HTTP/1.1, HTTP/2, WebSocket)

`size-plain` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| may-minihttp | 515 KB | 735 KB | **1.43x ahead of simoom** | 1 |
| **simoom** | 735 KB | - | reference | 3 |
| simoom-default | 743 KB | 735 KB | level (within 3%) | 1 |
| xitca | 1,025 KB | 735 KB | simoom 1.39x | 1 |
| nginx | 1,283 KB | 735 KB | simoom 1.75x | 1 |
| cameleer-http-min | 1,307 KB | 735 KB | simoom 1.78x | 1 |
| h2o | 1,499 KB | 735 KB | simoom 2.04x | 1 |
| ntex | 1,831 KB | 735 KB | simoom 2.49x | 1 |
| hyper | 2,069 KB | 735 KB | simoom 2.81x | 1 |
| axum | 2,246 KB | 735 KB | simoom 3.05x | 1 |
| actix | 2,450 KB | 735 KB | simoom 3.33x | 1 |
| haproxy | 3,765 KB | 735 KB | simoom 5.12x | 1 |
| axum-rustls | 5,400 KB | 735 KB | simoom 7.34x | 1 |
| fasthttp | 5,739 KB | 735 KB | simoom 7.81x | 1 |
| quinn-h3 | 5,766 KB | 735 KB | simoom 7.84x | 1 |
| go-nethttp | 6,180 KB | 735 KB | simoom 8.41x | 1 |
| caddy | 49,697 KB | 735 KB | simoom 67.60x | 1 |
| envoy | 104,356 KB | 735 KB | simoom 141.94x | 1 |

## Program size, stripped: simoom's full server (also TLS 1.3 and HTTP/3)

`size` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| may-minihttp | 515 KB | 1,550 KB | **3.01x ahead of simoom** | 1 |
| simoom-default | 743 KB | 1,550 KB | **2.09x ahead of simoom** | 1 |
| xitca | 1,025 KB | 1,550 KB | **1.51x ahead of simoom** | 1 |
| nginx | 1,283 KB | 1,550 KB | **1.21x ahead of simoom** | 1 |
| cameleer-http-min | 1,307 KB | 1,550 KB | **1.19x ahead of simoom** | 1 |
| h2o | 1,499 KB | 1,550 KB | **1.03x ahead of simoom** | 1 |
| **simoom** | 1,550 KB | - | reference | 3 |
| ntex | 1,831 KB | 1,550 KB | simoom 1.18x | 1 |
| hyper | 2,069 KB | 1,550 KB | simoom 1.33x | 1 |
| axum | 2,246 KB | 1,550 KB | simoom 1.45x | 1 |
| actix | 2,450 KB | 1,550 KB | simoom 1.58x | 1 |
| haproxy | 3,765 KB | 1,550 KB | simoom 2.43x | 1 |
| axum-rustls | 5,400 KB | 1,550 KB | simoom 3.48x | 1 |
| fasthttp | 5,739 KB | 1,550 KB | simoom 3.70x | 1 |
| quinn-h3 | 5,766 KB | 1,550 KB | simoom 3.72x | 1 |
| go-nethttp | 6,180 KB | 1,550 KB | simoom 3.99x | 1 |
| caddy | 49,697 KB | 1,550 KB | simoom 32.06x | 1 |
| envoy | 104,356 KB | 1,550 KB | simoom 67.32x | 1 |

## Memory at rest (PSS)

`base` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 901 KB | 1,869 KB | **2.07x ahead of simoom** | 3 |
| cameleer-http-min | 1,142 KB | 1,844 KB | **1.61x ahead of simoom** | 3 |
| hyper | 1,315 KB | 1,769 KB | **1.35x ahead of simoom** | 3 |
| xitca | 1,349 KB | 1,769 KB | **1.31x ahead of simoom** | 3 |
| axum | 1,466 KB | 1,769 KB | **1.21x ahead of simoom** | 3 |
| **simoom** | 1,844 KB | - | reference | 9 |
| actix | 1,885 KB | 1,761 KB | simoom 1.07x | 3 |
| ntex | 2,069 KB | 1,761 KB | simoom 1.17x | 3 |
| axum-rustls | 3,110 KB | 1,769 KB | simoom 1.76x | 3 |
| quinn-h3 | 3,468 KB | 1,769 KB | simoom 1.96x | 3 |
| h2o | 5,028 KB | 1,844 KB | simoom 2.73x | 3 |
| fasthttp | 6,396 KB | 1,869 KB | simoom 3.42x | 3 |
| go-nethttp | 8,108 KB | 1,869 KB | simoom 4.34x | 3 |
| may-minihttp | 9,152 KB | 1,844 KB | simoom 4.96x | 3 |
| caddy | 46,932 KB | 1,873 KB | simoom 25.06x | 3 |
| envoy | 63,578 KB | 1,844 KB | simoom 34.48x | 3 |
| kestrel | 70,559 KB | 1,869 KB | simoom 37.75x | 3 |
| nginx | 72,426 KB | 1,844 KB | simoom 39.28x | 3 |
| netty | 74,330 KB | 1,869 KB | simoom 39.77x | 3 |
| uws | 81,298 KB | 1,869 KB | simoom 43.50x | 3 |
| vertx | 96,578 KB | 1,869 KB | simoom 51.67x | 3 |
| haproxy | 142,887 KB | 1,844 KB | simoom 77.49x | 3 |

## Peak memory while serving the status endpoint (PSS)

`peak-s1` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 2,099 KB | 3,010 KB | **1.43x ahead of simoom** | 3 |
| **simoom** | 2,864 KB | - | reference | 6 |
| xitca | 4,279 KB | 2,880 KB | simoom 1.49x | 3 |
| ntex | 5,352 KB | 2,880 KB | simoom 1.86x | 3 |
| h2o | 6,203 KB | 3,008 KB | simoom 2.06x | 3 |
| actix | 6,912 KB | 2,880 KB | simoom 2.40x | 3 |
| fasthttp | 12,904 KB | 3,010 KB | simoom 4.29x | 3 |
| axum | 15,233 KB | 2,848 KB | simoom 5.35x | 3 |
| hyper | 16,486 KB | 2,848 KB | simoom 5.79x | 3 |
| go-nethttp | 20,940 KB | 2,833 KB | simoom 7.39x | 3 |
| may-minihttp | 28,936 KB | 3,008 KB | simoom 9.62x | 3 |
| caddy | 66,708 KB | 2,840 KB | simoom 23.49x | 3 |
| cameleer-http-min | 70,404 KB | 3,008 KB | simoom 23.41x | 3 |
| envoy | 71,518 KB | 2,840 KB | simoom 25.18x | 3 |
| nginx | 72,964 KB | 3,008 KB | simoom 24.26x | 3 |
| uws | 94,286 KB | 3,010 KB | simoom 31.32x | 3 |
| kestrel | 125,550 KB | 3,010 KB | simoom 41.71x | 3 |
| haproxy | 146,567 KB | 3,008 KB | simoom 48.73x | 3 |
| netty | 447,819 KB | 3,010 KB | simoom 148.78x | 3 |
| vertx | 452,309 KB | 3,010 KB | simoom 150.27x | 3 |

## Peak memory while serving the JSON API (PSS)

`peak-s3` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| simoom-default | 2,209 KB | 3,058 KB | **1.38x ahead of simoom** | 3 |
| **simoom** | 2,992 KB | - | reference | 6 |
| ntex | 8,860 KB | 2,988 KB | simoom 2.97x | 3 |
| actix | 11,172 KB | 2,988 KB | simoom 3.74x | 3 |
| fasthttp | 13,592 KB | 3,058 KB | simoom 4.44x | 3 |
| axum | 16,365 KB | 2,988 KB | simoom 5.48x | 3 |
| hyper | 17,790 KB | 2,988 KB | simoom 5.95x | 3 |
| go-nethttp | 21,072 KB | 3,058 KB | simoom 6.89x | 3 |
| may-minihttp | 29,869 KB | 3,129 KB | simoom 9.55x | 3 |
| kestrel | 121,394 KB | 3,058 KB | simoom 39.70x | 3 |
| uws | 124,749 KB | 3,058 KB | simoom 40.79x | 3 |
| netty | 465,543 KB | 2,996 KB | simoom 155.39x | 3 |
| vertx | 469,130 KB | 3,058 KB | simoom 153.41x | 3 |

## Peak memory while serving HTTPS (PSS)

`peak-s7` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| **simoom** | 6,983 KB | - | reference | 6 |
| h2o | 9,701 KB | 8,089 KB | simoom 1.20x | 3 |
| axum-rustls | 16,773 KB | 7,385 KB | simoom 2.27x | 3 |
| go-nethttp | 26,488 KB | 6,997 KB | simoom 3.79x | 3 |
| cameleer-http-min | 41,285 KB | 8,089 KB | simoom 5.10x | 3 |
| caddy | 71,988 KB | 8,089 KB | simoom 8.90x | 3 |
| nginx | 88,232 KB | 8,089 KB | simoom 10.91x | 3 |
| haproxy | 168,905 KB | 8,089 KB | simoom 20.88x | 3 |

## Peak memory while serving HTTP/3 (PSS)

`peak-h3` · use case `footprint` · lower is better

| server | value | simoom on the same droplet | comparison | runs |
|---|---:|---:|---|---:|
| h2o | 24,300 KB | 43,133 KB | **1.78x ahead of simoom** | 3 |
| **simoom** | 42,129 KB | - | reference | 6 |
| quinn-h3 | 55,358 KB | 42,541 KB | simoom 1.30x | 3 |
| caddy | 100,588 KB | 43,133 KB | simoom 2.33x | 3 |

