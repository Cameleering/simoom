//! Cameleer's HTTP client (`cameleer_http::client::HttpClient` with keep-alive pooling, and
//! cameleer-grpc's HTTP/2 client with `--h2`) in the same closed loop as simoom-client's
//! `client_bench` example: same command line, same output.
//!
//! ```text
//! cameleer-client-min --url http://127.0.0.1:8080/ [--threads 4] [--secs 10] [--h2] [--post BYTES]
//! ```

use cameleer_grpc::h2::{H2Config, H2Connection, H2Request};
use cameleer_http::client::HttpClient;
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
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--url" => url = val,
            "--threads" => threads = val.parse().expect("--threads"),
            "--secs" => secs = val.parse().expect("--secs"),
            "--post" => post = val.parse().expect("--post"),
            "--h2" => {
                h2 = true;
                i += 1;
                continue;
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let client = HttpClient::new().with_keep_alive(true);
    let rest = url.trim_start_matches("http://");
    let authority = rest.split('/').next().unwrap_or("").to_string();
    let path = format!("/{}", rest.split_once('/').map(|x| x.1).unwrap_or(""));
    let h2c = if h2 { Some(H2Connection::connect(&authority, H2Config::default()).expect("h2c connect")) } else { None };
    let body = vec![b'x'; post];
    let one = |client: &HttpClient, h2c: &Option<H2Connection>| -> usize {
        match h2c {
            Some(c) => {
                let mut req = H2Request::get(&path);
                if !body.is_empty() {
                    req.method = "POST".into();
                    req.body = body.clone();
                }
                c.request(&req, Some(Duration::from_secs(30))).expect("request").body.len()
            }
            None => {
                let r = if body.is_empty() { client.get(&url) } else { client.post(&url, "application/octet-stream", &body) };
                r.expect("request").body.len()
            }
        }
    };
    for _ in 0..100 {
        one(&client, &h2c);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicU64::new(0));
    let cpu0 = cpu_ms();
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            let (stop, count, client, h2c) = (stop.clone(), count.clone(), client.clone(), h2c.clone());
            let one = &one;
            s.spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    assert!(one(&client, &h2c) > 0);
                    n += 1;
                }
                count.fetch_add(n, Ordering::Relaxed);
            });
        }
        std::thread::sleep(Duration::from_secs(secs));
        stop.store(true, Ordering::Relaxed);
    });
    let el = t0.elapsed().as_secs_f64();
    let n = count.load(Ordering::Relaxed) as f64;
    let cpu = match (cpu0, cpu_ms()) {
        (Some(a), Some(b)) => format!("{:.2}", (b - a) * 1000.0 / n),
        _ => "n/a".into(),
    };
    println!("client=cameleer h2={h2} threads={threads} requests={n} secs={el:.2} rps={:.0} cpu_us_per_req={cpu}", n / el);
}
