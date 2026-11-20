# How do I set simoom's threads, I/O back end and shutdown?

> simoom runs one event loop per CPU core by default; set `threads`, pick a `Backend`, and stop with `stop(grace)` followed by `join()`.

simoom has its own runtime, not tokio. Each loop thread owns its connections from accept to close
and shares nothing with the others, so there are no locks on the request path. This page covers
the settings you can change.

## Threads and back ends

```rust
use simoom::{Backend, Reply, Request, Server};
use std::time::Duration;

fn main() {
    let server = Server::builder()
        .listen("0.0.0.0:8080")
        .threads(2) // 0 (the default) = one loop per CPU
        .backend(Backend::IoUring) // Linux 6.1+; falls back to epoll
        .service(|_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
        .start()
        .unwrap();
    println!("back end {:?}, fallback: {:?}", server.backend(), server.fallback_reason());
    // ...
    server.stop(Duration::from_secs(5));
    server.join();
}
```

**Threads.** `threads(0)`, the default, starts one loop per CPU the process may use. Only the
first loop starts at once; the others start in the background once traffic arrives, so an idle
server or a serverless instance pays for one thread (with an HTTP/3 listener every loop starts at
once). On machines with 4 or more CPUs where the network card's receive work lands on one CPU,
the default uses one loop fewer and keeps the loops off that CPU.

**Back ends.**

| `Backend` | platform |
|---|---|
| `Auto` (default) | epoll on Linux, IOCP on Windows, kqueue on macOS and BSD |
| `Epoll` | Linux, edge-triggered |
| `IoUring` | Linux 6.1 and newer, with the `io-uring` feature (on by default); falls back to epoll when the kernel refuses it |
| `Iocp` | Windows completion ports |
| `Kqueue` | macOS and BSD |

The environment variable `SIMOOM_BACKEND` (`epoll`, `io_uring`, `iocp`, `kqueue`) chooses the back
end when the code says `Auto`, which is handy for trying io_uring without a rebuild.
`server.fallback_reason()` tells you why io_uring was replaced, if it was.

Which is faster depends on the load: in the committed benchmarks epoll led at 64 and 256
connections and io_uring at 1,024 ([benchmarks](https://cameleer.ing/simoom/benchmarks/)).

## Graceful stop

`server.stop(grace)` closes the listeners, then:

- idle HTTP/1.1 connections close at once, busy ones after their response, with
  `Connection: close`;
- HTTP/2 and HTTP/3 connections get `GOAWAY` and close when their streams finish;
- whatever is still open after `grace` is aborted.

`server.join()` waits for the loops to exit. Dropping the `ServerHandle` stops at once, without a
grace period.

simoom doesn't install signal handlers. Wire your own shutdown signal to `stop`:

```rust
use simoom::{Reply, Request, Server};
use std::time::Duration;

fn run() -> std::io::Result<()> {
    let server = Server::builder()
        .listen("0.0.0.0:8080")
        .service(|_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
        .start()?;
    // block until stdin closes, a stand-in for your own shutdown signal
    let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut Vec::new());
    server.stop(Duration::from_secs(10));
    server.join();
    Ok(())
}
```

## Existing listeners

`Server::from_listeners` serves sockets you already have: socket activation by systemd, a port
handed over from a parent process, or a listener bound before dropping privileges.
`listen_on` and `listen_on_tls` add one at a time:

```rust
use simoom::{Reply, Request, Server};
use std::net::TcpListener;

fn run() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let server = Server::from_listeners(vec![listener])
        .service(|_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
        .start()?;
    server.join();
    Ok(())
}
```

## Low-level runtime settings

`Builder::runtime` gives access to the runtime configuration: CPU pinning, buffer sizes, thread
names, stack size, lingering close and more. Most programs never need it:

```rust
use simoom::Server;

fn build() -> simoom::Builder {
    Server::builder().listen("0.0.0.0:8080").runtime(|rt| {
        rt.pin_threads = true; // loop i on CPU i
        rt.thread_name = "web".into();
    })
}
```

The fields are documented on `simoom_rt::Config` at [docs.rs/simoom-rt](https://docs.rs/simoom-rt).

## Counters

`server.stats()` returns a `Stats` snapshot: connections accepted, rejected and open, requests,
refusals by kind, timeouts, panics, watchdog stalls, `503`s, upgrades, TLS errors, the offload
pool's counters and per-loop runtime counters. Each loop writes only its own counters, so they
cost nothing on the request path. Expose them however you like, for example on a `/metrics`
route.

## Common questions

### Should I use io_uring?

Try both on your workload. `Auto` uses epoll on Linux; in the committed runs epoll led at 64 and
256 connections and io_uring at 1,024. Setting `SIMOOM_BACKEND=io_uring`
lets you compare without a rebuild.

### How many threads should I use?

The default, one per CPU, suits a server. On a shared machine, or inside an app that does other
work, set fewer. A serverless function serving one request at a time effectively uses one loop,
since the others start only under load.

### Does simoom run on macOS and ARM?

macOS (kqueue) and the ARM code paths compile and are checked in the build, but the test suite
runs on Windows and Linux and the benchmarks ran on x86-64. Reports from macOS and ARM are welcome.

### Can I run two servers in one process?

Yes. Each `Server::builder().start()` creates its own loops, listeners and connections.
