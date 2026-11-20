//! A proxy for measuring where a forwarded request runs: a simoom server whose handler sends
//! each request upstream with `rt::RtClient` and answers in the client's callback.
//!
//! ```text
//! cargo run --release -p simoom-client --features rt --example rt_proxy -- \
//!     --listen 127.0.0.1:8081 --upstream http://127.0.0.1:8080/ [--threads 4] [--separate N] [--secs 30]
//! ```
//!
//! By default the client runs on the server's own loops (`RtClient::new(server.loops())`);
//! `--separate N` gives it a runtime of its own with N loops instead. Prints the process's CPU
//! time per answered request at the end (Linux).

#[cfg(feature = "rt")]
fn main() {
    use simoom_client::rt::{RtClient, RtConfig, RtRequest};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    let mut listen = "127.0.0.1:8081".to_string();
    let mut upstream = "http://127.0.0.1:8080/".to_string();
    let mut threads = 4usize;
    let mut separate: Option<usize> = None;
    let mut secs = 30u64;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i + 1 < v.len() {
        let val = v[i + 1].clone();
        match v[i].as_str() {
            "--listen" => listen = val,
            "--upstream" => upstream = val,
            "--threads" => threads = val.parse().expect("--threads"),
            "--separate" => separate = Some(val.parse().expect("--separate")),
            "--secs" => secs = val.parse().expect("--secs"),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let client: Arc<OnceLock<RtClient>> = Arc::new(OnceLock::new());
    let answered = Arc::new(AtomicU64::new(0));
    let (c2, a2, u) = (client.clone(), answered.clone(), upstream.clone());
    let server = simoom::Server::builder()
        .listen(listen.as_str())
        .threads(threads)
        .service(move |_req: &mut simoom::Request<'_>, reply: simoom::Reply<'_>| {
            let Some(c) = c2.get() else { return reply.status(503).empty() };
            let responder = reply.defer();
            let a3 = a2.clone();
            c.send(RtRequest::get(&u).unwrap(), move |r| {
                let resp = match r {
                    Ok(r) => simoom::Response::new(r.status).body(r.body),
                    Err(e) => simoom::Response::new(502).body(e.to_string()),
                };
                responder.send(resp);
                a3.fetch_add(1, Ordering::Relaxed);
            });
            simoom::Outcome::Deferred
        })
        .start()
        .expect("server");
    let cfg = RtConfig { timeout: Duration::from_secs(30), ..RtConfig::default() };
    let c = match separate {
        Some(n) => RtClient::spawn(n, cfg).expect("client runtime"),
        None => RtClient::new(server.loops(), cfg),
    };
    let _ = client.set(c);
    eprintln!("rt_proxy on {} -> {upstream} (client on {})", server.local_addr(), separate.map_or("the server's loops".to_string(), |n| format!("{n} loops of its own")));
    let cpu = || -> Option<f64> {
        let s = std::fs::read_to_string("/proc/self/stat").ok()?;
        let f: Vec<&str> = s[s.rfind(')')? + 2..].split_whitespace().collect();
        Some((f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?) * 10.0)
    };
    let (c0, n0) = (cpu(), answered.load(Ordering::Relaxed));
    std::thread::sleep(Duration::from_secs(secs));
    let (c1, n1) = (cpu(), answered.load(Ordering::Relaxed));
    let n = (n1 - n0).max(1) as f64;
    match (c0, c1) {
        (Some(a), Some(b)) => println!("rt_proxy answered={n} cpu_us_per_req={:.2}", (b - a) * 1000.0 / n),
        _ => println!("rt_proxy answered={n}"),
    }
    server.stop(Duration::from_millis(200));
}

#[cfg(not(feature = "rt"))]
fn main() {
    eprintln!("rt_proxy needs the `rt` feature");
}
