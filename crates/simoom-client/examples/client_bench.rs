//! Closed-loop client benchmark: `threads` threads each send requests back to back on one
//! shared client for `secs` seconds, then print requests per second and the client process's
//! CPU time per request (Linux: from /proc/self/stat).
//!
//! ```text
//! cargo run --release -p simoom-client --example client_bench -- --url http://127.0.0.1:8080/ \
//!     [--threads 4] [--secs 10] [--h2] [--post BYTES] [--conns N --streams S]
//! ```
//!
//! The same command line as bench/competitors/cameleer-client-min, for a like-for-like
//! comparison against Cameleer's client.

use simoom_client::{Client, HttpVersion};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn cpu_ms() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks: f64 = f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?;
    Some(ticks * 10.0)
}

fn main() {
    let mut url = "http://127.0.0.1:8080/".to_string();
    let mut threads = 4usize;
    let mut secs = 10u64;
    let mut h2 = false;
    let mut post = 0usize;
    let mut conns = 1usize;
    let mut streams: Option<usize> = None;
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
            "--h2" => {
                h2 = true;
                i += 1;
                continue;
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
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
    let cpu = match (cpu0, cpu_ms()) {
        (Some(a), Some(b)) => format!("{:.2}", (b - a) * 1000.0 / n),
        _ => "n/a".into(),
    };
    println!("client=simoom-client h2={h2} threads={threads} requests={n} secs={el:.2} rps={:.0} cpu_us_per_req={cpu}", n / el);
}
