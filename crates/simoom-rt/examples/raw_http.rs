//! A do-nothing HTTP/1.1 responder, to measure the runtime's ceiling.
//!
//! It finds the end of each request head (`\r\n\r\n`, searched naively) and answers every
//! request with a fixed `200 OK` and keep-alive. Pipelined requests in one read are answered in
//! one batch. `--mode threads` runs the same responder as a thread-per-connection std server,
//! the baseline.
//!
//! ```text
//! cargo run --release -p simoom-rt --example raw_http -- --port 8080 --threads 4 --secs 30
//!     [--mode rt|threads] [--backend auto|epoll|io_uring|iocp] [--cpus 0,2,4,6]
//! ```
//!
//! At exit it prints the requests served and, in `rt` mode, the system calls per request.

#![forbid(unsafe_code)]

use simoom_rt::{Backend, ConnInfo, Connection, Ctx, Runtime};
use std::cell::Cell;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\nHello, World!";

thread_local! {
    static SERVED: Cell<u64> = const { Cell::new(0) };
}

/// Counts complete request heads in `data`; returns (requests, bytes up to the last one's end).
fn heads(data: &[u8]) -> (usize, usize) {
    let mut n = 0;
    let mut end = 0;
    let mut i = 0;
    while i + 4 <= data.len() {
        if &data[i..i + 4] == b"\r\n\r\n" {
            n += 1;
            i += 4;
            end = i;
        } else {
            i += 1;
        }
    }
    (n, end)
}

struct Raw;
impl Connection for Raw {
    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let (n, end) = heads(data);
        for _ in 0..n {
            cx.send_static(RESPONSE);
        }
        SERVED.with(|c| c.set(c.get() + n as u64));
        end
    }
}

struct Args {
    port: u16,
    threads: usize,
    secs: u64,
    mode: String,
    backend: Backend,
    cpus: Option<Vec<usize>>,
    eager: bool,
}

fn args() -> Args {
    let mut a = Args { port: 8080, threads: 0, secs: 30, mode: "rt".into(), backend: Backend::Auto, cpus: None, eager: false };
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--port" => a.port = val.parse().expect("--port"),
            "--threads" => a.threads = val.parse().expect("--threads"),
            "--secs" => a.secs = val.parse().expect("--secs"),
            "--mode" => a.mode = val,
            "--backend" => {
                a.backend = match val.as_str() {
                    "epoll" => Backend::Epoll,
                    "io_uring" | "uring" => Backend::IoUring,
                    "iocp" => Backend::Iocp,
                    "kqueue" => Backend::Kqueue,
                    _ => Backend::Auto,
                }
            }
            "--eager" => {
                a.eager = true;
                i += 1;
                continue;
            }
            "--cpus" => a.cpus = Some(val.split(',').map(|s| s.trim().parse().expect("--cpus")).collect()),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    a
}

fn main() {
    let a = args();
    let addr = format!("127.0.0.1:{}", a.port);
    if a.mode == "threads" {
        threads_mode(&addr, a.secs);
        return;
    }
    let cpus = a.cpus.clone();
    let rt = Runtime::builder()
        .configure(|c| {
            c.threads = a.threads;
            c.driver.backend = a.backend;
            c.driver.iocp_eager_recv = a.eager;
            if let Some(cpus) = cpus {
                c.pin_threads = true;
                c.cpus = Some(cpus);
            }
        })
        .listen(addr.as_str(), |_: &ConnInfo| Some(Box::new(Raw) as Box<dyn Connection>))
        .start()
        .expect("start");
    eprintln!(
        "raw_http: {} loops on {:?}, back end {:?}{}",
        rt.loops().len(),
        rt.local_addrs(),
        rt.backend(),
        rt.fallback_reason().map(|r| format!(" ({r})")).unwrap_or_default()
    );
    std::thread::sleep(Duration::from_secs(a.secs));
    let (tx, rx) = mpsc::channel();
    for l in rt.loops() {
        let tx = tx.clone();
        l.run(move |_| tx.send(SERVED.with(|c| c.get())).unwrap());
    }
    drop(tx);
    let served: u64 = rx.iter().sum();
    let t = rt.stats().total();
    let d = t.driver;
    let per = |x: u64| if served == 0 { 0.0 } else { x as f64 / served as f64 };
    println!("served {served} requests on {} connections", t.accepted);
    println!(
        "per request: {:.3} syscalls (waits {:.3}, recv {:.3}, send {:.3}, other {:.3}); {:.3} io_uring SQEs; {:.3} OS events",
        per(d.syscalls()),
        per(d.waits),
        per(d.recv_calls),
        per(d.send_calls),
        per(d.accept_calls + d.other_calls),
        per(d.sqes),
        per(d.os_events)
    );
    rt.stop(Duration::from_millis(100));
    rt.join();
}

/// The baseline: a std thread per connection, blocking reads and writes.
fn threads_mode(addr: &str, secs: u64) {
    let l = std::net::TcpListener::bind(addr).expect("bind");
    eprintln!("raw_http: thread per connection on {}", l.local_addr().unwrap());
    let served = Arc::new(AtomicU64::new(0));
    let s2 = served.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let _ = s.set_nodelay(true);
            let served = s2.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 4096];
                let mut have = 0;
                let mut out = Vec::with_capacity(4096);
                let mut local = 0u64;
                loop {
                    let n = match s.read(&mut buf[have..]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    have += n;
                    let (reqs, end) = heads(&buf[..have]);
                    if reqs > 0 {
                        out.clear();
                        for _ in 0..reqs {
                            out.extend_from_slice(RESPONSE);
                        }
                        if s.write_all(&out).is_err() {
                            break;
                        }
                        buf.copy_within(end..have, 0);
                        have -= end;
                        local += reqs as u64;
                        if local >= 1024 {
                            served.fetch_add(local, Ordering::Relaxed);
                            local = 0;
                        }
                    }
                    if have == buf.len() {
                        break;
                    }
                }
                served.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    std::thread::sleep(Duration::from_secs(secs));
    println!("served {} requests (thread per connection)", served.load(Ordering::Relaxed));
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}
