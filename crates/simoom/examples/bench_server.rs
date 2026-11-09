//! The facade's throughput probe: a fixed 13-byte reply answered inline, the same work as
//! simoom-rt's `raw_http` example but through the full HTTP/1.1 stack (strict parsing, the
//! service call with panic catching and the stall watchdog, a `Date` header).
//!
//! ```text
//! cargo run --release -p simoom --example bench_server -- [--addr 127.0.0.1:8080] [--threads 4]
//!     [--secs 30] [--backend auto|epoll|io_uring|iocp] [--mode fixed|builder] [--cpus 0,2,4,6]
//!     [--no-watchdog] [--shed-us N]
//! ```
//!
//! `--addr` takes `host:port` (`0.0.0.0:8080` to serve other machines) or a bare host;
//! `--port` sets the port alone. Without `--secs` the server runs until it is killed, printing
//! its counters every 10 seconds.
//!
//! `--mode fixed` (the default) answers with a pre-serialized `StaticReply`; `--mode builder`
//! builds the reply with `status`/`header`/`body_static` on every request.
//! A `POST` (any mode) gets its body back with `body_copy`, the campaign's S3 echo.

#![forbid(unsafe_code)]

use simoom::{Backend, Limits, Outcome, Reply, Request, Server, StaticReply};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let mut host = "127.0.0.1".to_string();
    let mut port = 8080u16;
    let mut threads = 0usize;
    let mut secs: Option<u64> = None;
    let mut backend = Backend::Auto;
    let mut mode = "fixed".to_string();
    let mut cpus: Option<Vec<usize>> = None;
    let mut watchdog = true;
    let mut shed: Option<Duration> = None;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--port" => port = val.parse().expect("--port"),
            "--threads" => threads = val.parse().expect("--threads"),
            "--secs" => secs = Some(val.parse().expect("--secs")),
            "--addr" => match val.rsplit_once(':') {
                Some((h, p)) if !h.is_empty() && !h.ends_with(':') => {
                    host = h.trim_start_matches('[').trim_end_matches(']').to_string();
                    port = p.parse().expect("--addr port");
                }
                _ => host = val,
            },
            "--mode" => mode = val,
            "--backend" => {
                backend = match val.as_str() {
                    "epoll" => Backend::Epoll,
                    "io_uring" | "uring" => Backend::IoUring,
                    "iocp" => Backend::Iocp,
                    "kqueue" => Backend::Kqueue,
                    _ => Backend::Auto,
                }
            }
            "--shed-us" => shed = Some(Duration::from_micros(val.parse().expect("--shed-us"))),
            "--cpus" => cpus = Some(val.split(',').map(|s| s.trim().parse().expect("--cpus")).collect()),
            "--no-watchdog" => {
                watchdog = false;
                i += 1;
                continue;
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let limits = Limits { inline_budget: if watchdog { Some(Duration::from_millis(1)) } else { None }, shed_lag: shed, ..Limits::default() };
    let fixed = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let builder = mode == "builder";
    let svc = move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.method() == b"POST" {
            // S3: the request body back (`simoom-bench load --method POST --body-size 1024`).
            return reply.header("content-type", "application/json").body_copy(req.body());
        }
        if builder {
            reply.header("content-type", "text/plain").body_static(b"Hello, World!")
        } else {
            reply.fixed(&fixed)
        }
    };
    let server = Server::builder()
        .listen((host.as_str(), port))
        .threads(threads)
        .backend(backend)
        .limits(limits)
        .runtime(move |c| {
            if let Some(cpus) = cpus {
                c.pin_threads = true;
                c.cpus = Some(cpus);
            }
        })
        .service(svc)
        .start()
        .expect("start");
    eprintln!(
        "bench_server: {} on {}, back end {:?}{}",
        mode,
        server.local_addr(),
        server.backend(),
        server.fallback_reason().map(|r| format!(" ({r})")).unwrap_or_default()
    );
    let Some(secs) = secs else {
        loop {
            std::thread::sleep(Duration::from_secs(10));
            report(&server);
        }
    };
    std::thread::sleep(Duration::from_secs(secs));
    report(&server);
    server.stop(Duration::from_millis(100));
    server.join();
}

fn report(server: &simoom::ServerHandle) {
    let s = server.stats();
    let d = s.runtime.total().driver;
    let per = |x: u64| if s.requests == 0 { 0.0 } else { x as f64 / s.requests as f64 };
    println!("served {} requests on {} connections", s.requests, s.accepted);
    println!(
        "per request: {:.3} syscalls (waits {:.3}, recv {:.3}, send {:.3}, other {:.3}); {:.3} OS events; {} stalls; {} shed",
        per(d.syscalls()),
        per(d.waits),
        per(d.recv_calls),
        per(d.send_calls),
        per(d.other_calls),
        per(d.os_events),
        s.stalls,
        s.shed
    );
}
