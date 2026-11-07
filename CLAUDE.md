# CLAUDE.md: project memory for simoom

simoom is a small, fast, secure, embeddable HTTP/1.1, HTTP/2 and HTTP/3 server engine in Rust.
It is the server engine for [Cameleer](https://github.com/pmsudhi/cameleer), a std-only Rust
reimplementation of Apache Camel, and it is usable on its own inside other services. It targets
edge devices and FaaS as well as servers. It is **not** a full web-server replacement: there is
no static-file server, reverse proxy or config-file web server.

Read [docs/design/plan.md](docs/design/plan.md) (section 0 overrides the rest) and
[docs/STATUS.md](docs/STATUS.md) first.

## Hard rules

1. **Std-only. No external crates**, not even dev-dependencies. OS access goes through
   `extern "C"` / `extern "system"` declarations against libc, Win32 and the syscalls that std
   already links. SIMD goes through `core::arch` with runtime detection and a scalar fallback.
2. **`unsafe` only in `simoom-sys`.** Every other crate starts with `#![forbid(unsafe_code)]`.
   Every `unsafe` block in `simoom-sys` has a `// SAFETY:` comment.
3. **Zero warnings** from `cargo build --workspace --all-targets`, and `cargo test --workspace`
   passes on Windows and on Linux (WSL2). Every feature and every bug fix gets a test. Tests are
   hermetic: loopback only, never the internet.
4. **Efficiency is the product.** No feature lands without a measurement showing it costs no
   more than the alternatives. Size budgets are in plan.md §0, and every protocol is a cargo
   feature of the `simoom` crate.
5. **Security.** Strict parsing per RFC 9110, 9112, 9113, 9114 and 9204; every limit bounded
   (plan.md §7.1); constant-time crypto; never disable certificate verification.
6. **Protocol crates are sans-io.** They take bytes and time and emit bytes and events. They
   never open sockets, spawn threads or read clocks themselves.
7. **Git.**
   - Commits are authored as `Sudheesh PM <pmsudhi@gmail.com>` (the repo's local config).
   - No AI trailers: no `Co-Authored-By: Claude`, no `Claude-Session:`, no "Generated with"
     lines. Don't put model names in commits or code.
   - The branch is `main`. Never open a PR unless asked.

## Layout

| crate | role | depends on |
|---|---|---|
| `simoom-sys` | sockets, epoll, io_uring, kqueue, IOCP, eventfd, mmap, SIMD scan, AES-NI/CLMUL intrinsics | — |
| `simoom-rt` | event loop per core, timer wheel, buffer pools, wakeups, offload pool | sys |
| `simoom-http1` | HTTP/1.1 parser and serializer | sys (SIMD scan only) |
| `simoom-hpack`, `simoom-h2` | HTTP/2 | — |
| `simoom-tls` | TLS 1.3 (records and the QUIC interface), crypto primitives | sys (intrinsics only) |
| `simoom-quic` | QUIC v1 transport | tls |
| `simoom-qpack`, `simoom-h3` | HTTP/3 | quic |
| `simoom` | public API: `Server`, `Service`, `Reply`, `Responder`, router, limits; features `http1` `http2` `http3` `tls` | all |
| `simoom-bench` | open-loop load generator, raw responders, size checks (`publish = false`) | simoom |

## Working with parallel agents

- Each agent owns one or more crates and edits only those directories, unless its brief says
  otherwise. The root `Cargo.toml` is edited by the coordinator only.
- Use your own target directory so builds don't block each other, for example
  `CARGO_TARGET_DIR=target-<crate>`, and test with `cargo test -p <crate>`.
- Linux tests: `wsl -e bash -lc 'cd /mnt/e/Work/DataHQ/Code/simoom && CARGO_TARGET_DIR=$HOME/simoom-target-<crate> cargo test -p <crate>'`.
  WSL has 5 GB of RAM, so run at most one heavy Linux build at a time.
- Agents don't commit. The coordinator reviews and commits.

## Reference code

Cameleer (`E:\Work\DataHQ\Code\Rust-camel`, same owner and licence) has std-only code to port
from: `crates/cameleer-tls` (TLS 1.3/1.2, X25519, P-256, Ed25519, RSA, AES-GCM, ChaCha20-Poly1305,
SHA-2, HKDF, X.509), `crates/cameleer-grpc/src/h2` and `hpack` (HTTP/2 and HPACK, thread-based),
`crates/cameleer-http` (the current HTTP/1.1 server), `crates/cameleer-bench` (histogram,
load generator, `rawiocp.rs`, `rawhttp.rs`), and `crates/cameleer-tls/src/net.rs` (Windows socket
FFI patterns). Read it, copy and adapt it; never edit it.
