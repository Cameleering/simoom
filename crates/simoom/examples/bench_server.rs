//! The facade's throughput probe: a fixed 13-byte reply answered inline, the same work as
//! simoom-rt's `raw_http` example but through the full HTTP/1.1 stack (strict parsing, the
//! service call with panic catching and the stall watchdog, a `Date` header).
//!
//! ```text
//! cargo run --release -p simoom --example bench_server -- --port 8080 --threads 4 --secs 30
//!     [--backend auto|epoll|io_uring|iocp] [--mode fixed|builder] [--cpus 0,2,4,6] [--no-watchdog]
//! ```
//!
//! `--mode fixed` (the default) answers with a pre-serialized `StaticReply`; `--mode builder`
//! builds the reply with `status`/`header`/`body_static` on every request.

#![forbid(unsafe_code)]

use simoom::{Backend, Limits, Outcome, Reply, Request, Server, StaticReply};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let mut port = 8080u16;
    let mut threads = 0usize;
    let mut secs = 30u64;
    let mut backend = Backend::Auto;
    let mut mode = "fixed".to_string();
    let mut cpus: Option<Vec<usize>> = None;
    let mut watchdog = true;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--port" => port = val.parse().expect("--port"),
            "--threads" => threads = val.parse().expect("--threads"),
            "--secs" => secs = val.parse().expect("--secs"),
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
    let limits = Limits { inline_budget: if watchdog { Some(Duration::from_millis(1)) } else { None }, ..Limits::default() };
    let fixed = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let builder = mode == "builder";
    let svc = move |_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if builder {
            reply.header("content-type", "text/plain").body_static(b"Hello, World!")
        } else {
            reply.fixed(&fixed)
        }
    };
    let server = Server::builder()
        .listen(("127.0.0.1", port))
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
    std::thread::sleep(Duration::from_secs(secs));
    let s = server.stats();
    let d = s.runtime.total().driver;
    let per = |x: u64| if s.requests == 0 { 0.0 } else { x as f64 / s.requests as f64 };
    println!("served {} requests on {} connections", s.requests, s.accepted);
    println!("per request: {:.3} syscalls (waits {:.3}, recv {:.3}, send {:.3}); {} stalls", per(d.syscalls()), per(d.waits), per(d.recv_calls), per(d.send_calls), s.stalls);
    server.stop(Duration::from_millis(100));
    server.join();
}
