//! Closed-loop client benchmark: `threads` threads each send requests back to back on one
//! shared client for `secs` seconds, then print requests per second and the client process's
//! CPU time per request (Linux: from /proc/self/stat, user and system separately).
//!
//! ```text
//! cargo run --release -p simoom-client --example client_bench -- --url http://127.0.0.1:8080/ \
//!     [--threads 4] [--secs 10] [--h2] [--post BYTES] [--conns N --streams S]
//! cargo run --release -p simoom-client --features rt --example client_bench -- --rt \
//!     --url http://127.0.0.1:8080/ [--inflight 64] [--loops 4] [--conns 1] [--facade --threads 64]
//! ```
//!
//! The same command line as bench/competitors/cameleer-client-min, for a like-for-like
//! comparison against Cameleer's client.
//!
//! `--rt` drives `rt::RtClient` over HTTP/2 on `--loops` event loops with `--conns` connections
//! per loop: `--inflight` requests are kept in flight, each callback (on the loop) sends the
//! next one. With `--facade`, `--threads` blocking callers each send a request and park until
//! its callback (on the loop) unparks them: what a blocking client built over the event-driven
//! one would cost.

use simoom_client::{Client, HttpVersion};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// (user, system) CPU time of this process in milliseconds.
fn cpu_ms() -> Option<(f64, f64)> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some((f.get(11)?.parse::<f64>().ok()? * 10.0, f.get(12)?.parse::<f64>().ok()? * 10.0))
}

fn report(kind: &str, threads: usize, n: f64, el: f64, cpu0: Option<(f64, f64)>) {
    let cpu = match (cpu0, cpu_ms()) {
        (Some(a), Some(b)) => format!("{:.2} user_us_per_req={:.2} sys_us_per_req={:.2}", ((b.0 + b.1) - (a.0 + a.1)) * 1000.0 / n, (b.0 - a.0) * 1000.0 / n, (b.1 - a.1) * 1000.0 / n),
        _ => "n/a".into(),
    };
    println!("client={kind} threads={threads} requests={n} secs={el:.2} rps={:.0} cpu_us_per_req={cpu}", n / el);
}

fn main() {
    let mut url = "http://127.0.0.1:8080/".to_string();
    let mut threads = 4usize;
    let mut secs = 10u64;
    let mut h2 = false;
    let mut post = 0usize;
    let mut conns = 1usize;
    let mut streams: Option<usize> = None;
    let mut rt = false;
    let mut facade = false;
    let mut inflight = 64usize;
    let mut loops = 4usize;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--url" => url = val,
            "--threads" => threads = val.parse().expect("--threads"),
            "--secs" => secs = val.parse().expect("--secs"),
            "--post" => post = val.parse().expect("--post"),
            "--conns" => conns = val.parse().expect("--conns"),
            "--streams" => streams = Some(val.parse().expect("--streams")),
            "--inflight" => inflight = val.parse().expect("--inflight"),
            "--loops" => loops = val.parse().expect("--loops"),
            flag @ ("--h2" | "--rt" | "--facade") => {
                match flag {
                    "--h2" => h2 = true,
                    "--rt" => rt = true,
                    _ => facade = true,
                }
                i += 1;
                continue;
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    if rt {
        #[cfg(feature = "rt")]
        {
            rt_bench::run(&url, secs, post, conns, inflight, loops, facade.then_some(threads));
            return;
        }
        #[cfg(not(feature = "rt"))]
        {
            let _ = (facade, inflight, loops);
            panic!("--rt needs the `rt` feature");
        }
    }
    let client = Client::builder().version(if h2 { HttpVersion::Http2 } else { HttpVersion::Auto }).max_multiplexed_per_origin(conns).streams_per_connection(streams).build();
    for _ in 0..100 {
        client.get(&url).send().expect("request").bytes().expect("body");
    }
    let stop = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicU64::new(0));
    let body = vec![b'x'; post];
    let cpu0 = cpu_ms();
    let t0 = Instant::now();
    let ts: Vec<_> = (0..threads)
        .map(|_| {
            let (c, u, stop, count, body) = (client.clone(), url.clone(), stop.clone(), count.clone(), body.clone());
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let r = if body.is_empty() { c.get(&u).send() } else { c.post(&u).body(body.clone()).send() };
                    let b = r.expect("request").bytes().expect("body");
                    assert!(!b.is_empty());
                    n += 1;
                }
                count.fetch_add(n, Ordering::Relaxed);
            })
        })
        .collect();
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    for t in ts {
        t.join().unwrap();
    }
    let el = t0.elapsed().as_secs_f64();
    let n = count.load(Ordering::Relaxed) as f64;
    report(&format!("simoom-client h2={h2}"), threads, n, el, cpu0);
}

#[cfg(feature = "rt")]
mod rt_bench {
    use super::{cpu_ms, report};
    use simoom_client::rt::{RtClient, RtConfig, RtRequest};
    use simoom_client::HttpVersion;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct Chain {
        c: RtClient,
        url: String,
        body: Vec<u8>,
        stop: Arc<AtomicBool>,
        count: Arc<AtomicU64>,
        live: Arc<AtomicUsize>,
    }

    fn request(url: &str, body: &[u8]) -> RtRequest {
        let r = RtRequest::new(if body.is_empty() { "GET" } else { "POST" }, url).unwrap();
        if body.is_empty() {
            r
        } else {
            r.body(body.to_vec())
        }
    }

    /// One request; its callback (on the loop) sends the next.
    fn next(ch: Arc<Chain>) {
        let req = request(&ch.url, &ch.body);
        let c = ch.c.clone();
        c.send(req, move |r| {
            let r = r.expect("request");
            assert!(!r.body.is_empty());
            ch.count.fetch_add(1, Ordering::Relaxed);
            if ch.stop.load(Ordering::Relaxed) {
                ch.live.fetch_sub(1, Ordering::AcqRel);
                return;
            }
            next(ch);
        });
    }

    pub fn run(url: &str, secs: u64, post: usize, conns: usize, inflight: usize, loops: usize, facade: Option<usize>) {
        let cfg = RtConfig { version: HttpVersion::Http2, h2_connections: conns, timeout: Duration::from_secs(30), ..RtConfig::default() };
        let c = RtClient::spawn(loops, cfg).expect("runtime");
        let body = vec![b'x'; post];
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..100 {
            let tx = tx.clone();
            c.send(request(url, &body), move |r| tx.send(r.is_ok()).unwrap());
        }
        assert!((0..100).all(|_| rx.recv().unwrap()), "warm-up failed");
        let stop = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicU64::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let cpu0 = cpu_ms();
        let t0 = Instant::now();
        let kind;
        let mut ts = Vec::new();
        match facade {
            None => {
                kind = format!("rt-h2 inflight={inflight} loops={loops} conns_per_loop={conns}");
                for _ in 0..inflight {
                    live.fetch_add(1, Ordering::AcqRel);
                    next(Arc::new(Chain { c: c.clone(), url: url.to_string(), body: body.clone(), stop: stop.clone(), count: count.clone(), live: live.clone() }));
                }
            }
            Some(threads) => {
                kind = format!("rt-h2-facade loops={loops} conns_per_loop={conns}");
                for _ in 0..threads {
                    let (c, u, stop, count, body) = (c.clone(), url.to_string(), stop.clone(), count.clone(), body.clone());
                    ts.push(std::thread::spawn(move || {
                        let me = std::thread::current();
                        while !stop.load(Ordering::Relaxed) {
                            let slot = Arc::new(Mutex::new(None));
                            let (s2, t2) = (slot.clone(), me.clone());
                            c.send(request(&u, &body), move |r| {
                                *s2.lock().unwrap() = Some(r);
                                t2.unpark();
                            });
                            let r = loop {
                                if let Some(r) = slot.lock().unwrap().take() {
                                    break r;
                                }
                                std::thread::park();
                            };
                            assert!(!r.expect("request").body.is_empty());
                            count.fetch_add(1, Ordering::Relaxed);
                        }
                    }));
                }
            }
        }
        std::thread::sleep(Duration::from_secs(secs));
        stop.store(true, Ordering::Relaxed);
        let threads = ts.len();
        for t in ts {
            t.join().unwrap();
        }
        let el = t0.elapsed().as_secs_f64();
        let n = count.load(Ordering::Relaxed) as f64;
        report(&kind, threads, n, el, cpu0);
        let end = Instant::now() + Duration::from_secs(5);
        while live.load(Ordering::Acquire) > 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
