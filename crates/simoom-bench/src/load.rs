//! The open-loop load generator.
//!
//! - **Open loop** (`rate > 0`): every connection follows its own schedule, fixed-interval or
//!   Poisson, of `rate / conns` requests a second. A request's latency is timed from its
//!   **intended** send time, not from when it was actually written, so a stalled server is
//!   charged for every request it delayed (wrk2 semantics; no coordinated omission). A
//!   connection keeps at most `depth` requests in flight (1 for plain HTTP/1.1); requests that
//!   fall due while it is full wait and are sent as soon as a slot frees, still timed from their
//!   intended time.
//! - **Closed loop** (`rate == 0`): each connection keeps `depth` requests outstanding and sends
//!   the next as soon as a response arrives; latency is timed from the actual send. With
//!   `depth > 1` on HTTP/1.1 this is the TechEmpower-style pipelined mode.
//! - **Idle** (`idle`): open the connections, send one request on each, then hold them.
//!
//! The generator runs on `simoom-rt` (one pinned loop per thread). It reports its own CPU use
//! and the lateness of its timers (`lag`), so a run shows when the generator, rather than the
//! server, was the limit. Requests that were due inside the measured window but never answered
//! by the end of the drain period are recorded with their latency so far and counted as
//! `incomplete` (a truncated run must not look better than it was).

use crate::cpu;
use crate::h1;
use crate::hdr::Histogram;
use simoom_rt::{Backend, CloseReason, ConnHandle, Connection, Ctx, Message, Runtime, RuntimeHandle, Socket};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Wire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    H1,
    /// HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 §3.3).
    H2c,
}

/// Inter-arrival distribution of the open-loop schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dist {
    Fixed,
    Poisson,
}

/// Everything that defines one load run.
#[derive(Clone, Debug)]
pub struct Spec {
    pub addr: SocketAddr,
    pub host: String,
    pub proto: Proto,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub conns: usize,
    pub threads: usize,
    pub cpus: Option<Vec<usize>>,
    /// Total requests per second; 0 is closed loop.
    pub rate: f64,
    pub dist: Dist,
    /// HTTP/1.1 pipelining depth or HTTP/2 streams per connection.
    pub depth: usize,
    /// Closed loop with `depth > 1`: send the next batch of `depth` requests only once the whole
    /// previous batch is answered, as wrk's pipeline script (and so TechEmpower) does. Without it
    /// `depth` requests stay outstanding at all times.
    pub batch: bool,
    pub warmup: Duration,
    pub duration: Duration,
    pub idle: bool,
    pub backend: Backend,
    pub tick: Duration,
    /// Open loop on a back end whose waits have millisecond resolution (epoll, IOCP): wake every
    /// loop this often so timers fire within about this plus the OS sleep slack (on Linux about
    /// 50 us) instead of up to a millisecond late. Zero turns it off.
    pub ticker: Duration,
    /// After the window, how long to wait for outstanding responses.
    pub drain: Duration,
    /// Interval histogram length for the HdrHistogram log (0 = none).
    pub interval: Duration,
    /// Threads opening connections in parallel.
    pub connect_threads: usize,
    pub seed: u64,
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            addr: "127.0.0.1:8080".parse().unwrap(),
            host: "127.0.0.1:8080".into(),
            proto: Proto::H1,
            method: "GET".into(),
            path: "/".into(),
            headers: Vec::new(),
            body: Vec::new(),
            conns: 64,
            threads: 0,
            cpus: None,
            rate: 0.0,
            dist: Dist::Fixed,
            depth: 1,
            batch: false,
            warmup: Duration::from_secs(5),
            duration: Duration::from_secs(30),
            idle: false,
            backend: Backend::Auto,
            tick: Duration::from_micros(20),
            ticker: Duration::from_micros(20),
            drain: Duration::from_secs(2),
            interval: Duration::from_secs(1),
            connect_threads: 32,
            seed: 0x5eed,
        }
    }
}

fn backend_name(b: Backend) -> &'static str {
    match b {
        Backend::Auto => "auto",
        Backend::Epoll => "epoll",
        Backend::IoUring => "io_uring",
        Backend::Iocp => "iocp",
        Backend::Kqueue => "kqueue",
    }
}

pub fn parse_backend(s: &str) -> Result<Backend, String> {
    Ok(match s {
        "auto" => Backend::Auto,
        "epoll" => Backend::Epoll,
        "io_uring" | "uring" => Backend::IoUring,
        "iocp" => Backend::Iocp,
        "kqueue" => Backend::Kqueue,
        _ => return Err(format!("unknown backend {s}")),
    })
}

/// Resolves `host:port` (a name is resolved once, IPv4 first).
pub fn resolve(target: &str) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = target.to_socket_addrs().map_err(|e| format!("{target}: {e}"))?.collect();
    addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied().ok_or_else(|| format!("{target}: no address"))
}

impl Spec {
    /// Serializes as `key=value` words (the agent protocol).
    pub fn to_kv(&self) -> String {
        let mut s = format!(
            "addr={} host={} proto={} method={} path={} conns={} threads={} rate={} dist={} depth={} batch={} warmup_ms={} duration_ms={} idle={} backend={} tick_us={} ticker_us={} drain_ms={} interval_ms={} connect_threads={} seed={} body={}",
            self.addr,
            self.host,
            match self.proto {
                Proto::H1 => "h1",
                Proto::H2c => "h2c",
            },
            self.method,
            self.path,
            self.conns,
            self.threads,
            self.rate,
            match self.dist {
                Dist::Fixed => "fixed",
                Dist::Poisson => "poisson",
            },
            self.depth,
            self.batch,
            self.warmup.as_millis(),
            self.duration.as_millis(),
            self.idle,
            backend_name(self.backend),
            self.tick.as_micros(),
            self.ticker.as_micros(),
            self.drain.as_millis(),
            self.interval.as_millis(),
            self.connect_threads,
            self.seed,
            crate::hdr::base64_encode(&self.body),
        );
        if let Some(c) = &self.cpus {
            s.push_str(&format!(" cpus={}", c.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")));
        }
        for (k, v) in &self.headers {
            s.push_str(&format!(" header={}", crate::hdr::base64_encode(format!("{k}: {v}").as_bytes())));
        }
        s
    }

    pub fn from_kv(line: &str) -> Result<Spec, String> {
        let mut s = Spec::default();
        for w in line.split_whitespace() {
            let Some((k, v)) = w.split_once('=') else { continue };
            let num = |v: &str| v.parse::<u64>().map_err(|_| format!("bad {k}"));
            match k {
                "addr" => s.addr = v.parse().map_err(|_| "bad addr")?,
                "host" => s.host = v.into(),
                "proto" => s.proto = if v == "h2c" { Proto::H2c } else { Proto::H1 },
                "method" => s.method = v.into(),
                "path" => s.path = v.into(),
                "conns" => s.conns = num(v)? as usize,
                "threads" => s.threads = num(v)? as usize,
                "rate" => s.rate = v.parse().map_err(|_| "bad rate")?,
                "dist" => s.dist = if v == "poisson" { Dist::Poisson } else { Dist::Fixed },
                "depth" => s.depth = num(v)? as usize,
                "batch" => s.batch = v == "true",
                "warmup_ms" => s.warmup = Duration::from_millis(num(v)?),
                "duration_ms" => s.duration = Duration::from_millis(num(v)?),
                "idle" => s.idle = v == "true",
                "backend" => s.backend = parse_backend(v)?,
                "tick_us" => s.tick = Duration::from_micros(num(v)?),
                "ticker_us" => s.ticker = Duration::from_micros(num(v)?),
                "drain_ms" => s.drain = Duration::from_millis(num(v)?),
                "interval_ms" => s.interval = Duration::from_millis(num(v)?),
                "connect_threads" => s.connect_threads = num(v)? as usize,
                "seed" => s.seed = num(v)?,
                "body" => s.body = crate::hdr::base64_decode(v)?,
                "cpus" => s.cpus = Some(v.split(',').filter_map(|x| x.parse().ok()).collect()),
                "header" => {
                    let h = String::from_utf8(crate::hdr::base64_decode(v)?).map_err(|_| "bad header")?;
                    let (a, b) = h.split_once(": ").ok_or("bad header")?;
                    s.headers.push((a.into(), b.into()));
                }
                _ => {}
            }
        }
        Ok(s)
    }
}

/// The outcome of a run (one node, or several merged).
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub spec_rate: f64,
    pub conns: usize,
    pub connected: usize,
    pub connect_failed: usize,
    pub window_s: f64,
    /// Responses received inside the window.
    pub received: u64,
    /// Latency samples (requests intended or sent inside the window).
    pub completed: u64,
    pub non2xx: u64,
    pub conn_errors: u64,
    pub reconnects: u64,
    pub incomplete: u64,
    pub bytes_in: u64,
    pub hist: Histogram,
    /// How late the generator's timers fired (its own scheduling slop).
    pub lag: Histogram,
    /// Interval histograms: (index, histogram).
    pub intervals: Vec<(u64, Histogram)>,
    pub cpu: cpu::Usage,
    pub syscalls: u64,
    pub backend: String,
    pub nodes: usize,
    /// Highest node CPU seen across merged nodes.
    pub node_pct_max: Option<f64>,
    pub gen_pct_max: Option<f64>,
    pub thread_pct_max: Option<f64>,
}

impl Report {
    pub fn achieved(&self) -> f64 {
        if self.window_s > 0.0 {
            self.received as f64 / self.window_s
        } else {
            0.0
        }
    }

    pub fn errors(&self) -> u64 {
        self.non2xx + self.conn_errors + self.connect_failed as u64
    }

    /// Merges another node's report into this one (throughput adds, histograms merge).
    pub fn merge(&mut self, o: &Report) {
        self.spec_rate += o.spec_rate;
        self.conns += o.conns;
        self.connected += o.connected;
        self.connect_failed += o.connect_failed;
        self.window_s = self.window_s.max(o.window_s);
        self.received += o.received;
        self.completed += o.completed;
        self.non2xx += o.non2xx;
        self.conn_errors += o.conn_errors;
        self.reconnects += o.reconnects;
        self.incomplete += o.incomplete;
        self.bytes_in += o.bytes_in;
        self.hist.merge(&o.hist);
        self.lag.merge(&o.lag);
        for (i, h) in &o.intervals {
            match self.intervals.iter_mut().find(|(j, _)| j == i) {
                Some((_, mine)) => mine.merge(h),
                None => self.intervals.push((*i, h.clone())),
            }
        }
        self.intervals.sort_by_key(|x| x.0);
        self.syscalls += o.syscalls;
        self.nodes += o.nodes.max(1);
        let mx = |a: Option<f64>, b: Option<f64>| match (a, b) {
            (Some(x), Some(y)) => Some(x.max(y)),
            (x, None) => x,
            (None, y) => y,
        };
        self.node_pct_max = mx(self.node_pct_max, o.node_pct_max.or(o.cpu.node_pct));
        self.gen_pct_max = mx(self.gen_pct_max, o.gen_pct_max.or(o.cpu.proc_pct));
        self.thread_pct_max = mx(self.thread_pct_max, o.thread_pct_max.or(o.cpu.max_thread_pct));
        if self.backend.is_empty() {
            self.backend = o.backend.clone();
        }
    }

    /// The machine-readable summary line.
    pub fn result_line(&self, label: &str) -> String {
        let us = |v: u64| format!("{:.1}", v as f64 / 1000.0);
        let opt = |v: Option<f64>| v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "-".into());
        let node = self.node_pct_max.or(self.cpu.node_pct);
        let gen = self.gen_pct_max.or(self.cpu.proc_pct);
        let thr = self.thread_pct_max.or(self.cpu.max_thread_pct);
        let flag = if node.is_some_and(|n| n > 60.0) { " load_node_over_60pct=1" } else { "" };
        format!(
            "RESULT {label}rate={:.0} achieved={:.0} conns={} connected={} received={} samples={} errors={} non2xx={} conn_errors={} incomplete={} \
             p50_us={} p90_us={} p99_us={} p999_us={} p9999_us={} max_us={} mean_us={:.1} lag_p99_us={} lag_max_us={} \
             gen_cpu_pct={} gen_thread_max_pct={} node_cpu_pct={} softirq_pct={} gen_syscalls_per_req={:.2} window_s={:.1} nodes={} backend={}{flag}",
            self.spec_rate,
            self.achieved(),
            self.conns,
            self.connected,
            self.received,
            self.completed,
            self.errors(),
            self.non2xx,
            self.conn_errors,
            self.incomplete,
            us(self.hist.percentile(50.0)),
            us(self.hist.percentile(90.0)),
            us(self.hist.percentile(99.0)),
            us(self.hist.percentile(99.9)),
            us(self.hist.percentile(99.99)),
            us(self.hist.max()),
            self.hist.mean() / 1000.0,
            us(self.lag.percentile(99.0)),
            us(self.lag.max()),
            opt(gen),
            opt(thr),
            opt(node),
            opt(self.cpu.softirq_pct),
            if self.received > 0 { self.syscalls as f64 / self.received as f64 } else { 0.0 },
            self.window_s,
            self.nodes.max(1),
            if self.backend.is_empty() { "-" } else { &self.backend },
        )
    }

    /// Wire form for the agent protocol: the RESULT-like counters, then the histograms.
    pub fn to_wire(&self) -> String {
        let mut s = format!(
            "REPORT spec_rate={} conns={} connected={} connect_failed={} window_s={} received={} completed={} non2xx={} conn_errors={} reconnects={} incomplete={} bytes_in={} syscalls={} backend={} gen_pct={} node_pct={} thread_pct={} softirq_pct={}\n",
            self.spec_rate,
            self.conns,
            self.connected,
            self.connect_failed,
            self.window_s,
            self.received,
            self.completed,
            self.non2xx,
            self.conn_errors,
            self.reconnects,
            self.incomplete,
            self.bytes_in,
            self.syscalls,
            if self.backend.is_empty() { "-" } else { &self.backend },
            self.cpu.proc_pct.map(|x| x.to_string()).unwrap_or("-".into()),
            self.cpu.node_pct.map(|x| x.to_string()).unwrap_or("-".into()),
            self.cpu.max_thread_pct.map(|x| x.to_string()).unwrap_or("-".into()),
            self.cpu.softirq_pct.map(|x| x.to_string()).unwrap_or("-".into()),
        );
        s.push_str(&format!("HIST {}\n", self.hist.to_base64()));
        s.push_str(&format!("LAG {}\n", self.lag.to_base64()));
        for (i, h) in &self.intervals {
            s.push_str(&format!("INTERVAL {i} {}\n", h.to_base64()));
        }
        s.push_str("END\n");
        s
    }

    /// Parses [`Report::to_wire`] from lines (up to and including `END`).
    pub fn from_wire<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Report, String> {
        let mut r = Report { nodes: 1, ..Report::default() };
        for line in lines {
            let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
            match kind {
                "REPORT" => {
                    for w in rest.split_whitespace() {
                        let Some((k, v)) = w.split_once('=') else { continue };
                        let f = || v.parse::<f64>().ok();
                        let u = || v.parse::<u64>().unwrap_or(0);
                        match k {
                            "spec_rate" => r.spec_rate = f().unwrap_or(0.0),
                            "conns" => r.conns = u() as usize,
                            "connected" => r.connected = u() as usize,
                            "connect_failed" => r.connect_failed = u() as usize,
                            "window_s" => r.window_s = f().unwrap_or(0.0),
                            "received" => r.received = u(),
                            "completed" => r.completed = u(),
                            "non2xx" => r.non2xx = u(),
                            "conn_errors" => r.conn_errors = u(),
                            "reconnects" => r.reconnects = u(),
                            "incomplete" => r.incomplete = u(),
                            "bytes_in" => r.bytes_in = u(),
                            "syscalls" => r.syscalls = u(),
                            "backend" => r.backend = v.into(),
                            "gen_pct" => r.cpu.proc_pct = f(),
                            "node_pct" => r.cpu.node_pct = f(),
                            "thread_pct" => r.cpu.max_thread_pct = f(),
                            "softirq_pct" => r.cpu.softirq_pct = f(),
                            _ => {}
                        }
                    }
                }
                "HIST" => r.hist = Histogram::from_base64(rest)?,
                "LAG" => r.lag = Histogram::from_base64(rest)?,
                "INTERVAL" => {
                    let (i, b) = rest.split_once(' ').ok_or("bad INTERVAL")?;
                    r.intervals.push((i.parse().map_err(|_| "bad interval index")?, Histogram::from_base64(b)?));
                }
                "END" => return Ok(r),
                _ => {}
            }
        }
        Err("report ended without END".into())
    }
}

// ---------------------------------------------------------------------------------------------
// Per-loop statistics
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct LoopStats {
    hist: Histogram,
    lag: Histogram,
    received: u64,
    completed: u64,
    non2xx: u64,
    conn_errors: u64,
    reconnects: u64,
    incomplete: u64,
    bytes_in: u64,
    inflight: i64,
    cur_interval: Option<(u64, Histogram)>,
    intervals: Vec<(u64, Histogram)>,
}

thread_local! {
    static STATS: RefCell<LoopStats> = RefCell::new(LoopStats::default());
}

/// Window boundaries, shared by every connection (set when the run starts).
struct Shared {
    t0: AtomicU64,
    mstart: AtomicU64,
    mend: AtomicU64,
    hard_end: AtomicU64,
    interval_ns: u64,
    open: bool,
    idle: bool,
    depth: usize,
    batch: bool,
    per_conn_rate: f64,
    dist: Dist,
    req: Vec<u8>,
    head: bool,
    h2: Option<H2Req>,
    addr: SocketAddr,
    reconnect_tx: Mutex<Option<mpsc::Sender<Reconnect>>>,
    loops: Mutex<Vec<simoom_rt::LoopHandle>>,
}

struct H2Req {
    method: Vec<u8>,
    authority: Vec<u8>,
    path: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

impl Shared {
    fn window(&self) -> (u64, u64) {
        (self.mstart.load(Ordering::Relaxed), self.mend.load(Ordering::Relaxed))
    }
}

/// Records one completed request.
fn record(sh: &Shared, t_start: u64, now: u64, status: u16) {
    let (ms, me) = sh.window();
    STATS.with(|s| {
        let mut s = s.borrow_mut();
        s.inflight -= 1;
        if !(200..300).contains(&status) {
            s.non2xx += 1;
        }
        if now >= ms && now < me {
            s.received += 1;
        }
        if t_start >= ms && t_start < me {
            let lat = now.saturating_sub(t_start);
            s.completed += 1;
            s.hist.record(lat);
            if sh.interval_ns > 0 {
                let idx = (now.saturating_sub(ms)) / sh.interval_ns;
                let rotate = !matches!(&s.cur_interval, Some((i, _)) if *i == idx);
                if rotate {
                    if let Some(prev) = s.cur_interval.take() {
                        s.intervals.push(prev);
                    }
                    s.cur_interval = Some((idx, Histogram::default()));
                }
                s.cur_interval.as_mut().unwrap().1.record(lat);
            }
        }
    });
}

fn sent(n: usize) {
    STATS.with(|s| s.borrow_mut().inflight += n as i64);
}

// ---------------------------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Sched {
    base: u64,
    k: u64,
    interval: f64,
    poisson: bool,
    next: u64,
    rng: u64,
}

impl Sched {
    fn new(rate: f64, dist: Dist, seed: u64) -> Sched {
        let interval = if rate > 0.0 { 1e9 / rate } else { f64::INFINITY };
        Sched { base: 0, k: 0, interval, poisson: dist == Dist::Poisson, next: u64::MAX, rng: seed | 1 }
    }

    fn rand(&mut self) -> f64 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        ((self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }

    /// Starts at `t0` with a random phase inside the first interval (no synchronized bursts).
    fn start(&mut self, t0: u64) {
        if !self.interval.is_finite() {
            return;
        }
        let phase = if self.poisson { -self.rand().ln() * self.interval } else { self.rand() * self.interval };
        self.base = t0 + phase as u64;
        self.k = 0;
        self.next = self.base;
    }

    fn advance(&mut self) {
        if self.poisson {
            self.next += (-self.rand().ln() * self.interval) as u64;
        } else {
            self.k += 1;
            self.next = self.base + (self.k as f64 * self.interval) as u64;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------------------------

enum Msg {
    /// Flush anything the protocol wants to send first (the HTTP/2 preface).
    Hello,
    Start,
    /// Re-adopted after a reconnect: carry on with the schedule.
    Resume,
    Finish,
}

struct Reconnect {
    loop_index: usize,
    client: Client,
}

/// Protocol state of one connection.
enum Wire {
    H1,
    H2(Box<simoom_h2::Connection>, Vec<(u32, u64, u16)>),
}

struct Client {
    sh: Arc<Shared>,
    sched: Sched,
    wire: Wire,
    /// Start times of outstanding requests (intended time in open loop, send time in closed).
    inflight: VecDeque<u64>,
    timer_armed: bool,
    timer_at: u64,
    started: bool,
    finished: bool,
    dead: bool,
}

impl Client {
    fn new(sh: Arc<Shared>, seed: u64) -> Client {
        let wire = match &sh.h2 {
            None => Wire::H1,
            Some(_) => {
                let cfg = simoom_h2::Config { max_concurrent_streams: 100, window_autotune: false, ..simoom_h2::Config::default() };
                Wire::H2(Box::new(simoom_h2::Connection::client(cfg)), Vec::new())
            }
        };
        let sched = Sched::new(sh.per_conn_rate, sh.dist, seed);
        Client { sh, sched, wire, inflight: VecDeque::new(), timer_armed: false, timer_at: 0, started: false, finished: false, dead: false }
    }

    /// Fresh protocol state for a new connection, keeping the schedule.
    fn reborn(&mut self) -> Client {
        let mut c = Client::new(self.sh.clone(), 0);
        c.sched = self.sched.clone();
        c.started = self.started;
        c
    }

    fn flush(&mut self, cx: &mut Ctx<'_>) {
        if let Wire::H2(c, _) = &mut self.wire {
            let n = c.output().len();
            if n > 0 {
                let mut b = cx.buffer(n);
                b.extend_from_slice(c.output());
                c.advance_output(n);
                cx.send(b);
            }
        }
    }

    /// Sends one request; `t` is its start time for latency. Returns false if the protocol
    /// cannot open another stream now.
    fn send_one(&mut self, cx: &mut Ctx<'_>, t: u64) -> bool {
        match &mut self.wire {
            Wire::H1 => {
                let mut b = cx.buffer(self.sh.req.len());
                b.extend_from_slice(&self.sh.req);
                cx.send(b);
                self.inflight.push_back(t);
            }
            Wire::H2(c, streams) => {
                let r = self.sh.h2.as_ref().unwrap();
                let fields: Vec<(&[u8], &[u8])> = r.headers.iter().map(|(a, b)| (&a[..], &b[..])).collect();
                match c.send_request(&r.method, b"http", &r.authority, &r.path, &fields, r.body.is_empty()) {
                    Ok(id) => {
                        if !r.body.is_empty() {
                            let _ = c.send_data(id, &r.body, true);
                        }
                        streams.push((id, t, 0));
                        self.inflight.push_back(t);
                    }
                    Err(_) => return false,
                }
            }
        }
        sent(1);
        true
    }

    fn pump(&mut self, cx: &mut Ctx<'_>) {
        if self.finished || self.dead || !self.started {
            return;
        }
        let now = cx.now_ns();
        let stop = self.sh.mend.load(Ordering::Relaxed);
        if self.sh.open {
            while self.inflight.len() < self.sh.depth {
                let due = self.sched.next;
                if due >= stop || due > now {
                    break;
                }
                if !self.send_one(cx, due) {
                    break;
                }
                self.sched.advance();
            }
            if !self.timer_armed && self.inflight.len() < self.sh.depth && self.sched.next < stop {
                let due = self.sched.next;
                self.timer_armed = true;
                self.timer_at = due;
                cx.set_timer(Duration::from_nanos(due.saturating_sub(now)), 1);
            }
        } else if !self.sh.idle && now < stop && (!self.sh.batch || self.inflight.is_empty()) {
            while self.inflight.len() < self.sh.depth {
                if !self.send_one(cx, now) {
                    break;
                }
            }
        }
        self.flush(cx);
    }

    fn finish(&mut self, now: u64) {
        if self.finished {
            return;
        }
        self.finished = true;
        let (ms, me) = self.sh.window();
        STATS.with(|s| {
            let mut s = s.borrow_mut();
            // requests sent but not answered
            for &t in &self.inflight {
                s.inflight -= 1;
                if t >= ms && t < me {
                    s.incomplete += 1;
                    if self.sh.open {
                        s.hist.record(now.saturating_sub(t));
                        s.completed += 1;
                    }
                }
            }
            // requests that fell due but were never sent (the connection was saturated)
            if self.sh.open && self.started {
                let mut guard = 0u64;
                while self.sched.next < me && guard < 100_000_000 {
                    let due = self.sched.next;
                    if due >= ms {
                        s.incomplete += 1;
                        s.completed += 1;
                        s.hist.record(now.saturating_sub(due));
                    }
                    self.sched.advance();
                    guard += 1;
                }
            }
        });
        self.inflight.clear();
    }

    fn fail(&mut self, cx: &mut Ctx<'_>) {
        STATS.with(|s| s.borrow_mut().conn_errors += 1);
        self.dead = true;
        cx.abort();
    }
}

impl Connection for Client {
    fn on_message(&mut self, cx: &mut Ctx<'_>, msg: Message) {
        let Ok(m) = msg.downcast::<Msg>() else { return };
        match *m {
            Msg::Hello => self.flush(cx),
            Msg::Start => {
                self.started = true;
                if self.sh.idle {
                    let now = cx.now_ns();
                    if self.send_one(cx, now) {
                        self.flush(cx);
                    }
                    return;
                }
                if self.sh.open {
                    self.sched.start(self.sh.t0.load(Ordering::Relaxed));
                }
                self.pump(cx);
            }
            Msg::Resume => {
                STATS.with(|s| s.borrow_mut().reconnects += 1);
                self.flush(cx);
                self.pump(cx);
            }
            Msg::Finish => {
                let now = cx.now_ns();
                self.finish(now);
                cx.close();
            }
        }
    }

    fn on_timer(&mut self, cx: &mut Ctx<'_>, _token: u64) {
        self.timer_armed = false;
        if self.finished || self.dead {
            return;
        }
        let now = cx.now_ns();
        STATS.with(|s| s.borrow_mut().lag.record(now.saturating_sub(self.timer_at)));
        self.pump(cx);
    }

    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let now = cx.now_ns();
        STATS.with(|s| s.borrow_mut().bytes_in += data.len() as u64);
        let mut pos = 0;
        let mut close = false;
        match &mut self.wire {
            Wire::H1 => loop {
                match h1::frame(&data[pos..], self.sh.head) {
                    Ok(Some(f)) => {
                        pos += f.len;
                        match self.inflight.pop_front() {
                            Some(t) => record(&self.sh, t, now, f.status),
                            None => {
                                self.fail(cx);
                                return data.len();
                            }
                        }
                        if f.close {
                            close = true;
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        self.fail(cx);
                        return data.len();
                    }
                }
            },
            Wire::H2(c, streams) => {
                let mut done: Vec<(u32, u16)> = Vec::new();
                let mut status: Vec<(u32, u16)> = Vec::new();
                let mut release: Vec<(u32, usize)> = Vec::new();
                let mut closed = false;
                pos = c.recv(data, now / 1_000_000, &mut |ev| match ev {
                    simoom_h2::Event::Headers { stream, headers, end_stream } => {
                        let st = headers.status().unwrap_or(0);
                        if st >= 200 {
                            if end_stream {
                                done.push((stream, st));
                            } else {
                                status.push((stream, st));
                            }
                        }
                    }
                    simoom_h2::Event::Data { stream, data, end_stream } => {
                        release.push((stream, data.len()));
                        if end_stream {
                            let st = status.iter().find(|x| x.0 == stream).map(|x| x.1).unwrap_or(0);
                            done.push((stream, st));
                        }
                    }
                    simoom_h2::Event::Trailers { stream, .. } => done.push((stream, 200)),
                    simoom_h2::Event::Reset { stream, .. } => done.push((stream, 0)),
                    simoom_h2::Event::Closed { .. } | simoom_h2::Event::GoAway { .. } => closed = true,
                    _ => {}
                });
                for (s, n) in release {
                    c.release(s, n);
                }
                for (s, st) in &status {
                    // a status whose stream did not end in this batch is kept on the stream
                    if let Some(e) = streams.iter_mut().find(|x| x.0 == *s) {
                        e.2 = *st;
                    }
                }
                for (s, st) in done {
                    if let Some(i) = streams.iter().position(|x| x.0 == s) {
                        let (_, t, kept) = streams.swap_remove(i);
                        let st = if st == 0 { kept } else { st };
                        if let Some(j) = self.inflight.iter().position(|&x| x == t) {
                            self.inflight.remove(j);
                        }
                        record(&self.sh, t, now, st);
                    }
                }
                if closed {
                    close = true;
                }
            }
        }
        if close {
            self.flush(cx);
            cx.close();
            return data.len();
        }
        self.pump(cx);
        self.flush(cx);
        pos
    }

    fn on_close(&mut self, reason: CloseReason) {
        let now = simoom_sys::time::now_ns();
        let lost = self.inflight.len();
        if self.finished {
            return;
        }
        if !matches!(reason, CloseReason::Closed) || lost > 0 {
            STATS.with(|s| {
                let mut s = s.borrow_mut();
                s.inflight -= lost as i64;
                if !self.dead {
                    s.conn_errors += 1;
                }
            });
        }
        self.inflight.clear();
        // reconnect while the run is on, keeping the schedule
        if self.started && now < self.sh.mend.load(Ordering::Relaxed) {
            let client = self.reborn();
            if let Some(tx) = self.sh.reconnect_tx.lock().unwrap().as_ref() {
                let li = LOOP_INDEX.with(|l| *l.borrow());
                let _ = tx.send(Reconnect { loop_index: li, client });
            }
        }
    }
}

thread_local! {
    static LOOP_INDEX: RefCell<usize> = const { RefCell::new(0) };
}

// ---------------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------------

/// A prepared run: the runtime is up and the connections are open, waiting for [`Prepared::go`].
pub struct Prepared {
    spec: Spec,
    rt: RuntimeHandle,
    sh: Arc<Shared>,
    handles: Vec<ConnHandle>,
    connect_failed: usize,
    reconnect_thread: Option<std::thread::JoinHandle<()>>,
}

fn runtime_now(rt: &RuntimeHandle) -> u64 {
    let (tx, rx) = mpsc::channel();
    rt.loops()[0].run(move |_| {
        let _ = tx.send(clock_now());
    });
    rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_| clock_now())
}

fn clock_now() -> u64 {
    simoom_sys::time::now_ns()
}

/// Opens the connections. Fails only if no connection could be opened.
pub fn prepare(spec: Spec) -> Result<Prepared, String> {
    let threads = if spec.threads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) } else { spec.threads };
    let conns = spec.conns.max(1);
    let open = spec.rate > 0.0 && !spec.idle;
    let depth = if spec.idle { 1 } else { spec.depth.max(1) };
    let h2 = match spec.proto {
        Proto::H1 => None,
        Proto::H2c => {
            let mut headers: Vec<(Vec<u8>, Vec<u8>)> = spec.headers.iter().map(|(k, v)| (k.to_ascii_lowercase().into_bytes(), v.clone().into_bytes())).collect();
            if !spec.body.is_empty() {
                headers.push((b"content-length".to_vec(), spec.body.len().to_string().into_bytes()));
            }
            Some(H2Req { method: spec.method.clone().into_bytes(), authority: spec.host.clone().into_bytes(), path: spec.path.clone().into_bytes(), headers, body: spec.body.clone() })
        }
    };
    let sh = Arc::new(Shared {
        t0: AtomicU64::new(u64::MAX),
        mstart: AtomicU64::new(u64::MAX),
        mend: AtomicU64::new(u64::MAX),
        hard_end: AtomicU64::new(u64::MAX),
        interval_ns: spec.interval.as_nanos() as u64,
        open,
        idle: spec.idle,
        depth,
        batch: spec.batch,
        per_conn_rate: if open { spec.rate / conns as f64 } else { 0.0 },
        dist: spec.dist,
        req: h1::build_request(&spec.method, &spec.path, &spec.host, &spec.headers, &spec.body),
        head: spec.method == "HEAD",
        h2,
        addr: spec.addr,
        reconnect_tx: Mutex::new(None),
        loops: Mutex::new(Vec::new()),
    });
    let mut cpus = spec.cpus.clone();
    if cpus.is_none() && cfg!(target_os = "linux") {
        cpus = Some(simoom_sys_cpus());
    }
    let backend = spec.backend;
    let tick = spec.tick;
    let rt = Runtime::builder()
        .configure(|c| {
            c.threads = threads;
            c.thread_name = "gen".into();
            c.driver.backend = backend;
            c.timer_tick = tick;
            c.max_input = 1 << 20;
            c.driver.uring_fixed_files = false;
            // an empty list means: do not pin
            if let Some(cpus) = cpus.filter(|c| !c.is_empty()) {
                c.pin_threads = true;
                c.cpus = Some(cpus);
            }
        })
        .start()
        .map_err(|e| format!("runtime: {e}"))?;
    for (i, l) in rt.loops().iter().enumerate() {
        l.run(move |_| LOOP_INDEX.with(|x| *x.borrow_mut() = i));
    }
    *sh.loops.lock().unwrap() = rt.loops().to_vec();

    // connect in parallel
    if let Some(soft) = open_file_limit() {
        if conns as u64 + 64 > soft {
            eprintln!("simoom-bench: warning: {conns} connections but the open-file limit is {soft}; raise it (ulimit -n) or connections will fail");
        }
    }
    let next = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let last_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let (htx, hrx) = mpsc::channel::<ConnHandle>();
    let workers = spec.connect_threads.clamp(1, conns);
    let mut joins = Vec::new();
    for _ in 0..workers {
        let (next, failed, htx, sh, loops, last_err) = (next.clone(), failed.clone(), htx.clone(), sh.clone(), rt.loops().to_vec(), last_err.clone());
        let seed = spec.seed;
        joins.push(std::thread::spawn(move || loop {
            let k = next.fetch_add(1, Ordering::Relaxed);
            if k >= conns {
                break;
            }
            let mut sock = None;
            for attempt in 0..8u32 {
                match Socket::tcp_connect(sh.addr) {
                    Ok(s) => {
                        sock = Some(s);
                        break;
                    }
                    Err(e) => {
                        *last_err.lock().unwrap() = Some(e.to_string());
                        std::thread::sleep(Duration::from_millis((50u64 << attempt).min(1000)));
                    }
                }
            }
            let Some(sock) = sock else {
                failed.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let client = Client::new(sh.clone(), seed ^ (k as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let htx = htx.clone();
            let failed = failed.clone();
            loops[k % loops.len()].run(move |lcx| match lcx.adopt(sock, Box::new(client)) {
                Ok(h) => {
                    h.send(Box::new(Msg::Hello));
                    let _ = htx.send(h);
                }
                Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
            });
        }));
    }
    drop(htx);
    for j in joins {
        let _ = j.join();
    }
    let connect_failed = failed.load(Ordering::Relaxed);
    if connect_failed > 0 {
        eprintln!("simoom-bench: {connect_failed} of {conns} connections failed; last error: {}", last_err.lock().unwrap().clone().unwrap_or_default());
    }
    if let Some(r) = rt.fallback_reason() {
        eprintln!("simoom-bench: back end {} ({r})", backend_name(rt.backend()));
    }
    let want = conns - connect_failed;
    let mut handles = Vec::with_capacity(want);
    let deadline = Instant::now() + Duration::from_secs(30);
    while handles.len() < want {
        match hrx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(h) => handles.push(h),
            Err(_) => break,
        }
    }
    if handles.is_empty() {
        rt.stop(Duration::ZERO);
        rt.join();
        return Err(format!("could not connect to {}", spec.addr));
    }

    // reconnector: reopens connections the server closed, on the same loop
    let (rtx, rrx) = mpsc::channel::<Reconnect>();
    *sh.reconnect_tx.lock().unwrap() = Some(rtx);
    let sh2 = sh.clone();
    let reconnect_thread = std::thread::spawn(move || {
        for r in rrx {
            let Ok(sock) = Socket::tcp_connect(sh2.addr) else {
                STATS_FAILS.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let loops = sh2.loops.lock().unwrap().clone();
            let Some(l) = loops.get(r.loop_index) else { continue };
            let client = r.client;
            l.run(move |lcx| {
                if let Ok(h) = lcx.adopt(sock, Box::new(client)) {
                    h.send(Box::new(Msg::Resume));
                }
            });
        }
    });
    Ok(Prepared { spec, rt, sh, handles, connect_failed, reconnect_thread: Some(reconnect_thread) })
}

static STATS_FAILS: AtomicU64 = AtomicU64::new(0);

/// The soft open-file limit (Linux, from /proc/self/limits).
fn open_file_limit() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = s.lines().find(|l| l.starts_with("Max open files"))?;
    line.split_whitespace().nth(3)?.parse().ok()
}

fn simoom_sys_cpus() -> Vec<usize> {
    simoom_sys::cpu::allowed_cpus()
}

impl Prepared {
    pub fn connected(&self) -> usize {
        self.handles.len()
    }

    /// Starts sending `delay` from now, runs warm-up, window and drain, and reports.
    pub fn go(mut self, delay: Duration) -> Report {
        let spec = self.spec.clone();
        let now = runtime_now(&self.rt);
        let t0 = now + delay.as_nanos() as u64;
        let mstart = t0 + spec.warmup.as_nanos() as u64;
        let mend = mstart + spec.duration.as_nanos() as u64;
        self.sh.t0.store(t0, Ordering::Relaxed);
        self.sh.mstart.store(mstart, Ordering::Relaxed);
        self.sh.mend.store(mend, Ordering::Relaxed);
        self.sh.hard_end.store(mend + spec.drain.as_nanos() as u64, Ordering::Relaxed);
        for h in &self.handles {
            h.send(Box::new(Msg::Start));
        }
        // millisecond-resolution waits: wake the loops often enough for precise open-loop timers
        let ticking = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ticker = if self.sh.open && !spec.ticker.is_zero() && self.rt.backend() != Backend::IoUring {
            let (loops, run, every) = (self.rt.loops().to_vec(), ticking.clone(), spec.ticker);
            Some(std::thread::Builder::new().name("ticker".into()).spawn(move || {
                while run.load(Ordering::Relaxed) {
                    for l in &loops {
                        l.run(|_| {});
                    }
                    std::thread::sleep(every);
                }
            }))
        } else {
            None
        };
        let sleep_until = |t: u64| {
            let n = clock_now();
            if t > n {
                std::thread::sleep(Duration::from_nanos(t - n));
            }
        };
        sleep_until(mstart);
        let c0 = cpu::sample("gen");
        let s0 = self.rt.stats().total().driver.syscalls();
        sleep_until(mend);
        let c1 = cpu::sample("gen");
        let s1 = self.rt.stats().total().driver.syscalls();
        // drain: wait until nothing is outstanding, or the drain period ends
        let hard_end = mend + spec.drain.as_nanos() as u64;
        if !spec.idle {
            // let timers due just before the end fire (their requests are still sent), then wait
            // for the outstanding responses
            sleep_until(mend + 100_000_000u64.min(spec.drain.as_nanos() as u64));
            while clock_now() < hard_end {
                if self.inflight() <= 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        ticking.store(false, Ordering::Relaxed);
        if let Some(Ok(t)) = ticker {
            let _ = t.join();
        }
        *self.sh.reconnect_tx.lock().unwrap() = None;
        for h in &self.handles {
            h.send(Box::new(Msg::Finish));
        }
        let (tx, rx) = mpsc::channel::<LoopStats>();
        for l in self.rt.loops() {
            let tx = tx.clone();
            l.run(move |_| {
                let mut s = STATS.with(|s| std::mem::take(&mut *s.borrow_mut()));
                if let Some(c) = s.cur_interval.take() {
                    s.intervals.push(c);
                }
                let _ = tx.send(s);
            });
        }
        drop(tx);
        let mut rep = Report {
            spec_rate: if self.sh.open { spec.rate } else { 0.0 },
            conns: spec.conns,
            connected: self.handles.len(),
            connect_failed: self.connect_failed,
            window_s: spec.duration.as_secs_f64(),
            cpu: cpu::usage(&c0, &c1),
            syscalls: s1.saturating_sub(s0),
            backend: backend_name(self.rt.backend()).to_string(),
            nodes: 1,
            ..Report::default()
        };
        for s in rx.iter() {
            rep.received += s.received;
            rep.completed += s.completed;
            rep.non2xx += s.non2xx;
            rep.conn_errors += s.conn_errors;
            rep.reconnects += s.reconnects;
            rep.incomplete += s.incomplete;
            rep.bytes_in += s.bytes_in;
            rep.hist.merge(&s.hist);
            rep.lag.merge(&s.lag);
            for (i, h) in s.intervals {
                match rep.intervals.iter_mut().find(|(j, _)| *j == i) {
                    Some((_, mine)) => mine.merge(&h),
                    None => rep.intervals.push((i, h)),
                }
            }
        }
        rep.intervals.sort_by_key(|x| x.0);
        rep.conn_errors += STATS_FAILS.swap(0, Ordering::Relaxed);
        self.rt.stop(Duration::from_millis(200));
        self.rt.join();
        if let Some(j) = self.reconnect_thread.take() {
            let _ = j.join();
        }
        rep
    }

    fn inflight(&self) -> i64 {
        let (tx, rx) = mpsc::channel();
        for l in self.rt.loops() {
            let tx = tx.clone();
            l.run(move |_| {
                let _ = tx.send(STATS.with(|s| s.borrow().inflight));
            });
        }
        drop(tx);
        rx.iter().sum()
    }
}

/// Prepares and runs at once.
pub fn run(spec: Spec) -> Result<Report, String> {
    Ok(prepare(spec)?.go(Duration::from_millis(50)))
}
