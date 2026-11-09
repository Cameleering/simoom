//! S5 (and S7's handshakes): a new connection for every request.
//!
//! Each node runs `conns` worker threads with blocking sockets. Requests follow one schedule per
//! node: in open loop the k-th request is due at `t0 + k / rate` and goes to the next idle
//! worker; a request that falls due while every worker is busy waits and is still timed from its
//! intended time (wrk2 semantics), so `conns` bounds the concurrency, not the rate. Closed loop
//! (`rate == 0`) has every worker connect again as soon as it finishes.
//!
//! A request is: connect (and, with TLS, a full or resumed TLS 1.3 handshake with certificate
//! verification), one request with `Connection: close`, read the whole response, close. Its
//! latency covers all of that. `connects` counts the connections opened.

use crate::h1;
use crate::load::{self, record, sent, Engine, LoopStats, Report, Shared, Spec, STATS};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

struct Gate {
    open: Mutex<bool>,
    cv: Condvar,
}

struct NewConn {
    spec: Spec,
    sh: Arc<Shared>,
    gate: Arc<Gate>,
    workers: Vec<std::thread::JoinHandle<LoopStats>>,
}

struct Job {
    sh: Arc<Shared>,
    next: Arc<AtomicU64>,
    interval_ns: f64,
    req: Arc<Vec<u8>>,
    tls: Option<Arc<simoom_tls::ClientConfig>>,
    sni: String,
    head: bool,
    addr: std::net::SocketAddr,
}

pub(crate) fn prepare(spec: Spec) -> Result<Box<dyn Engine>, String> {
    let sh = Arc::new(Shared::for_engine(&spec));
    let tls = if spec.tls { Some(load::tls_config(&spec, &[b"http/1.1"], load::wants_resume(&spec))?) } else { None };
    let mut headers = load::request_headers(&spec);
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
    headers.push(("Connection".into(), "close".into()));
    let req = Arc::new(h1::build_request(&spec.method, &spec.path, &spec.host, &headers, &spec.body));
    let gate = Arc::new(Gate { open: Mutex::new(false), cv: Condvar::new() });
    let next = Arc::new(AtomicU64::new(0));
    let interval_ns = if spec.rate > 0.0 { 1e9 / spec.rate } else { 0.0 };
    let n = spec.conns.max(1);
    let mut workers = Vec::with_capacity(n);
    for _ in 0..n {
        let job = Job {
            sh: sh.clone(),
            next: next.clone(),
            interval_ns,
            req: req.clone(),
            tls: tls.clone(),
            sni: load::server_name(&spec),
            head: spec.method == "HEAD",
            addr: spec.addr,
        };
        let gate = gate.clone();
        let w = std::thread::Builder::new()
            .name("newconn".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                {
                    let mut g = gate.open.lock().unwrap();
                    while !*g {
                        g = gate.cv.wait(g).unwrap();
                    }
                }
                worker(&job);
                LoopStats::take()
            })
            .map_err(|e| format!("spawn: {e}"))?;
        workers.push(w);
    }
    Ok(Box::new(NewConn { spec, sh, gate, workers }))
}

fn now_ns() -> u64 {
    simoom_sys::time::now_ns()
}

fn sleep_until(t: u64) {
    loop {
        let n = now_ns();
        if n >= t {
            return;
        }
        let d = t - n;
        if d > 200_000 {
            std::thread::sleep(Duration::from_nanos(d - 100_000));
        } else if d > 20_000 {
            std::thread::sleep(Duration::from_micros(10));
        } else {
            std::hint::spin_loop();
        }
    }
}

fn worker(job: &Job) {
    let t0 = job.sh.t0.load(Ordering::Relaxed);
    let (_, mend) = job.sh.window();
    loop {
        let t = if job.interval_ns > 0.0 {
            let k = job.next.fetch_add(1, Ordering::Relaxed);
            let t = t0 + (k as f64 * job.interval_ns) as u64;
            if t >= mend {
                return;
            }
            let before = now_ns();
            if t > before {
                sleep_until(t);
                let late = now_ns().saturating_sub(t);
                STATS.with(|s| s.borrow_mut().lag.record(late));
            }
            t
        } else {
            let n = now_ns();
            if n < t0 {
                sleep_until(t0);
                continue;
            }
            if n >= mend {
                return;
            }
            n
        };
        let t_sent = now_ns().max(t);
        sent(1);
        let r = one(job);
        let now = now_ns();
        match r {
            Ok((status, bytes)) => {
                STATS.with(|s| s.borrow_mut().bytes_in += bytes);
                record(&job.sh, t, t_sent, now, status);
            }
            Err(_) => {
                STATS.with(|s| s.borrow_mut().conn_errors += 1);
                // charged to the run like any failed request (status 0 is not 2xx)
                record(&job.sh, t, t_sent, now, 0);
            }
        }
    }
}

/// One connection, one request, one response. Returns the status and the bytes received.
fn one(job: &Job) -> Result<(u16, u64), String> {
    let s = TcpStream::connect_timeout(&job.addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    STATS.with(|st| st.borrow_mut().connects += 1);
    let _ = s.set_nodelay(true);
    s.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    let mut tls = match &job.tls {
        Some(cfg) => Some(simoom_tls::ClientConnection::new(cfg.clone(), &job.sni).map_err(|e| format!("{e:?}"))?),
        None => None,
    };
    exchange(s, tls.as_mut(), &job.req, job.head)
}

/// Sends `req` and reads one response, over TLS when `tls` is given.
pub(crate) fn exchange(mut s: TcpStream, mut tls: Option<&mut simoom_tls::ClientConnection>, req: &[u8], head: bool) -> Result<(u16, u64), String> {
    match tls.as_deref_mut() {
        None => s.write_all(req).map_err(|e| e.to_string())?,
        Some(t) => {
            // buffered until the handshake completes, then sent with the client's Finished
            t.write_plaintext(req).map_err(|e| format!("{e:?}"))?;
        }
    }
    let mut raw = vec![0u8; 64 * 1024];
    let mut buf: Vec<u8> = Vec::new();
    let mut bytes = 0u64;
    let mut body_left = 0usize;
    let mut status = 0u16;
    let mut framed = false;
    loop {
        if let Some(t) = tls.as_deref_mut() {
            if t.wants_write() {
                let mut out = Vec::new();
                t.write_tls_into(&mut out);
                s.write_all(&out).map_err(|e| e.to_string())?;
            }
        }
        let n = s.read(&mut raw).map_err(|e| e.to_string())?;
        if n == 0 {
            return if framed && body_left == 0 { Ok((status, bytes)) } else { Err("closed before the response ended".into()) };
        }
        bytes += n as u64;
        match tls.as_deref_mut() {
            None => buf.extend_from_slice(&raw[..n]),
            Some(t) => {
                let mut off = 0;
                while off < n {
                    let k = t.read_tls(&raw[off..n]);
                    off += k;
                    t.process_new_packets().map_err(|e| format!("tls: {e:?}"))?;
                    let p = t.plaintext();
                    let pl = p.len();
                    buf.extend_from_slice(p);
                    t.consume_plaintext(pl);
                    if k == 0 && pl == 0 {
                        return Err("tls input stalled".into());
                    }
                }
            }
        }
        if !framed {
            match h1::frame_partial(&buf, head) {
                Ok(Some((f, left))) => {
                    framed = true;
                    status = f.status;
                    body_left = left;
                    buf.clear();
                }
                Ok(None) => continue,
                Err(_) => return Err("malformed response".into()),
            }
        } else {
            let take = body_left.min(buf.len());
            body_left -= take;
            buf.clear();
        }
        if framed && body_left == 0 {
            return Ok((status, bytes));
        }
    }
}

impl Engine for NewConn {
    fn connected(&self) -> usize {
        self.workers.len()
    }

    fn go(self: Box<Self>, delay: Duration) -> Report {
        let t0 = now_ns() + delay.as_nanos() as u64;
        let (mstart, mend) = self.sh.set_window(t0, &self.spec);
        *self.gate.open.lock().unwrap() = true;
        self.gate.cv.notify_all();
        sleep_until(mstart);
        let c0 = crate::cpu::sample("newconn");
        sleep_until(mend);
        let c1 = crate::cpu::sample("newconn");
        let mut rep = Report {
            spec_rate: self.spec.rate,
            conns: self.spec.conns,
            connected: self.workers.len(),
            window_s: self.spec.duration.as_secs_f64(),
            cpu: crate::cpu::usage(&c0, &c1),
            backend: "threads".into(),
            nodes: 1,
            ..Report::default()
        };
        for w in self.workers {
            if let Ok(s) = w.join() {
                s.add_to(&mut rep);
            }
        }
        rep
    }
}
