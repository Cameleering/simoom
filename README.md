# simoom

A small, fast, secure, embeddable HTTP/1.1, HTTP/2 and HTTP/3 server engine for Rust, with no
dependencies beyond the standard library. It runs on Linux (epoll, io_uring), Windows (IOCP) and
macOS (kqueue), and it is built for edge devices, FaaS and servers alike. It is the HTTP engine
of [Cameleer](https://github.com/Cameleering/cameleer).

Status: under construction. See [docs/STATUS.md](docs/STATUS.md) and
[docs/design/plan.md](docs/design/plan.md).

Licensed under the Apache License 2.0.
