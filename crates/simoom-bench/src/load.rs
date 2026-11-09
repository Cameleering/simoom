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
    /// HTTP/2 over TLS 1.3 (ALPN h2).
    H2,
    /// HTTP/3 over QUIC (the `h3load` engine).
    H3,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::H1 => "h1",
            Proto::H2c => "h2c",
            Proto::H2 => "h2",
            Proto::H3 => "h3",
        }
    }

    pub fn parse(s: &str) -> Result<Proto, String> {
        Ok(match s {
            "h1" | "http1" => Proto::H1,
            "h2c" => Proto::H2c,
            "h2" => Proto::H2,
            "h3" | "http3" => Proto::H3,
            p => return Err(format!("unknown --proto {p} (h1, h2c, h2, h3)")),
        })
    }

    /// HTTP/2 framing (cleartext or TLS).
    pub fn is_h2(self) -> bool {
        matches!(self, Proto::H2c | Proto::H2)
    }
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
    /// TLS 1.3 on the TCP connections (h1 over TLS, or h2 with ALPN).
    pub tls: bool,
    /// TLS/QUIC server name (SNI and certificate check); the certificate must match it.
    pub sni: String,
    /// PEM root certificates that the server's certificate must chain to (verification is
    /// never turned off).
    pub ca: Vec<u8>,
    /// S5: a new connection for every request (`Connection: close`, connect time included).
    pub new_conn: bool,
    /// Latency bound for `goodput_slo` (requests answered within it, from the intended time).
    pub slo_us: u64,
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
            tls: false,
            sni: String::new(),
            ca: Vec::new(),
            new_conn: false,
            slo_us: 1000,
        }
    }
}

pub(crate) fn backend_label(b: Backend) -> &'static str {
    backend_name(b)
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
            "addr={} host={} proto={} method={} path={} conns={} threads={} rate={} dist={} depth={} batch={} warmup_ms={} duration_ms={} idle={} backend={} tick_us={} ticker_us={} drain_ms={} interval_ms={} connect_threads={} seed={} tls={} new_conn={} slo_us={} sni={} ca={} body={}",
            self.addr,
            self.host,
            self.proto.name(),
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
            self.tls,
            self.new_conn,
            self.slo_us,
            if self.sni.is_empty() { "-" } else { &self.sni },
            crate::hdr::base64_encode(&self.ca),
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
                "proto" => s.proto = Proto::parse(v)?,
                "tls" => s.tls = v == "true",
                "new_conn" => s.new_conn = v == "true",
                "slo_us" => s.slo_us = num(v)?,
                "sni" => s.sni = if v == "-" { String::new() } else { v.into() },
                "ca" => s.ca = crate::hdr::base64_decode(v)?,
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
    /// 2xx responses to requests intended inside the window (goodput), and those of them
    /// answered within `slo_us` of their intended time.
    pub ok: u64,
    pub ok_fast: u64,
    /// Latency of the 2xx responses timed from when the request was actually written (the
    /// "admitted" latency of S9: what the server did with the requests it took).
    pub ok_hist: Histogram,
    /// New connections opened during the run (S5).
    pub connects: u64,
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
        self.ok += o.ok;
        self.ok_fast += o.ok_fast;
        self.connects += o.connects;
        self.ok_hist.merge(&o.ok_hist);
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
             gen_cpu_pct={} gen_thread_max_pct={} node_cpu_pct={} softirq_pct={} gen_syscalls_per_req={:.2} window_s={:.1} nodes={} backend={} \
             ok={} goodput={:.0} goodput_slo={:.0} ok_p50_us={} ok_p99_us={} ok_p999_us={} connects={} mbit_in={:.1}{flag}",
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
            self.ok,
            if self.window_s > 0.0 { self.ok as f64 / self.window_s } else { 0.0 },
            if self.window_s > 0.0 { self.ok_fast as f64 / self.window_s } else { 0.0 },
            us(self.ok_hist.percentile(50.0)),
            us(self.ok_hist.percentile(99.0)),
            us(self.ok_hist.percentile(99.9)),
            self.connects,
            if self.window_s > 0.0 { self.bytes_in as f64 * 8.0 / self.window_s / 1e6 } else { 0.0 },
        )
    }

    /// Wire form for the agent protocol: the RESULT-like counters, then the histograms.
    pub fn to_wire(&self) -> String {
        let mut s = format!(
            "REPORT spec_rate={} conns={} connected={} connect_failed={} window_s={} received={} completed={} non2xx={} conn_errors={} reconnects={} incomplete={} bytes_in={} syscalls={} backend={} gen_pct={} node_pct={} thread_pct={} softirq_pct={} ok={} ok_fast={} connects={}\n",
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
            self.ok,
            self.ok_fast,
            self.connects,
        );
        s.push_str(&format!("HIST {}\n", self.hist.to_base64()));
        s.push_str(&format!("OKHIST {}\n", self.ok_hist.to_base64()));
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
                            "ok" => r.ok = u(),
                            "ok_fast" => r.ok_fast = u(),
                            "connects" => r.connects = u(),
                            _ => {}
                        }
                    }
                }
                "HIST" => r.hist = Histogram::from_base64(rest)?,
                "OKHIST" => r.ok_hist = Histogram::from_base64(rest)?,
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
pub(crate) struct LoopStats {
    ok: u64,
    ok_fast: u64,
    ok_hist: Histogram,
    pub(crate) connects: u64,
    hist: Histogram,
    pub(crate) lag: Histogram,
    received: u64,
    completed: u64,
    non2xx: u64,
    pub(crate) conn_errors: u64,
    reconnects: u64,
    pub(crate) incomplete: u64,
    pub(crate) bytes_in: u64,
    pub(crate) inflight: i64,
    cur_interval: Option<(u64, Histogram)>,
    intervals: Vec<(u64, Histogram)>,
}

thread_local! {
    pub(crate) static STATS: RefCell<LoopStats> = RefCell::new(LoopStats::default());
}

impl LoopStats {
    /// Adds this thread's statistics to a report.
    pub(crate) fn add_to(mut self, rep: &mut Report) {
        if let Some(c) = self.cur_interval.take() {
            self.intervals.push(c);
        }
        rep.received += self.received;
        rep.completed += self.completed;
        rep.non2xx += self.non2xx;
        rep.conn_errors += self.conn_errors;
        rep.reconnects += self.reconnects;
        rep.incomplete += self.incomplete;
        rep.bytes_in += self.bytes_in;
        rep.ok += self.ok;
        rep.ok_fast += self.ok_fast;
        rep.connects += self.connects;
        rep.ok_hist.merge(&self.ok_hist);
        rep.hist.merge(&self.hist);
        rep.lag.merge(&self.lag);
        for (i, h) in self.intervals {
            match rep.intervals.iter_mut().find(|(j, _)| *j == i) {
                Some((_, mine)) => mine.merge(&h),
                None => rep.intervals.push((i, h)),
            }
        }
        rep.intervals.sort_by_key(|x| x.0);
    }

    /// A request that was due in the window but never answered (open loop): charged with its
    /// latency so far.
    pub(crate) fn record_lost(&mut self, lat: u64) {
        self.completed += 1;
        self.hist.record(lat);
    }

    /// Takes the calling thread's statistics.
    pub(crate) fn take() -> LoopStats {
        STATS.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }
}

/// Window boundaries, shared by every connection (set when the run starts).
pub(crate) struct Shared {
    pub(crate) t0: AtomicU64,
    pub(crate) mstart: AtomicU64,
    pub(crate) mend: AtomicU64,
    hard_end: AtomicU64,
    pub(crate) interval_ns: u64,
    pub(crate) slo_ns: u64,
    tls: Option<Arc<simoom_tls::ClientConfig>>,
    sni: String,
    pub(crate) open: bool,
    idle: bool,
    pub(crate) depth: usize,
    batch: bool,
    per_conn_rate: f64,
    pub(crate) dist: Dist,
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
    /// A window holder for the threaded engines (S5, HTTP/3).
    pub(crate) fn for_engine(spec: &Spec) -> Shared {
        Shared {
            t0: AtomicU64::new(u64::MAX),
            mstart: AtomicU64::new(u64::MAX),
            mend: AtomicU64::new(u64::MAX),
            hard_end: AtomicU64::new(u64::MAX),
            interval_ns: spec.interval.as_nanos() as u64,
            slo_ns: spec.slo_us * 1000,
            tls: None,
            sni: String::new(),
            open: spec.rate > 0.0,
            idle: false,
            depth: spec.depth.max(1),
            batch: false,
            per_conn_rate: 0.0,
            dist: spec.dist,
            req: Vec::new(),
            head: spec.method == "HEAD",
            h2: None,
            addr: spec.addr,
            reconnect_tx: Mutex::new(None),
            loops: Mutex::new(Vec::new()),
        }
    }

    /// Sets the run's window: sending starts at `t0`, measuring at `t0 + warmup`.
    pub(crate) fn set_window(&self, t0: u64, spec: &Spec) -> (u64, u64) {
        let mstart = t0 + spec.warmup.as_nanos() as u64;
        let mend = mstart + spec.duration.as_nanos() as u64;
        self.t0.store(t0, Ordering::Relaxed);
        self.mstart.store(mstart, Ordering::Relaxed);
        self.mend.store(mend, Ordering::Relaxed);
        self.hard_end.store(mend + spec.drain.as_nanos() as u64, Ordering::Relaxed);
        (mstart, mend)
    }

    pub(crate) fn window(&self) -> (u64, u64) {
        (self.mstart.load(Ordering::Relaxed), self.mend.load(Ordering::Relaxed))
    }
}

/// Records one completed request: `t_start` is its start time for latency (intended in open
/// loop), `t_sent` when it was actually written.
pub(crate) fn record(sh: &Shared, t_start: u64, t_sent: u64, now: u64, status: u16) {
    let (ms, me) = sh.window();
    STATS.with(|s| {
        let mut s = s.borrow_mut();
        s.inflight -= 1;
        let good = (200..300).contains(&status);
        if !good {
            s.non2xx += 1;
        }
        if now >= ms && now < me {
            s.received += 1;
        }
        if t_start >= ms && t_start < me {
            let lat = now.saturating_sub(t_start);
            s.completed += 1;
            s.hist.record(lat);
            if good && now < me {
                s.ok += 1;
                if lat <= sh.slo_ns {
                    s.ok_fast += 1;
                }
                s.ok_hist.record(now.saturating_sub(t_sent));
            }
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

pub(crate) fn sent(n: usize) {
    STATS.with(|s| s.borrow_mut().inflight += n as i64);
}

// ---------------------------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) struct Sched {
    base: u64,
    k: u64,
    interval: f64,
    poisson: bool,
    pub(crate) next: u64,
    rng: u64,
}

impl Sched {
    pub(crate) fn new(rate: f64, dist: Dist, seed: u64) -> Sched {
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
    pub(crate) fn start(&mut self, t0: u64) {
        if !self.interval.is_finite() {
            return;
        }
        let phase = if self.poisson { -self.rand().ln() * self.interval } else { self.rand() * self.interval };
        self.base = t0 + phase as u64;
        self.k = 0;
        self.next = self.base;
    }

    pub(crate) fn advance(&mut self) {
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
    /// Flush anything the protocol wants to send first (the TLS ClientHello, the HTTP/2 preface).
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
    /// HTTP/2 and its open streams: (id, start time, send time, status seen so far).
    H2(Box<simoom_h2::Connection>, Vec<(u32, u64, u64, u16)>),
}

/// Builds the TLS client configuration of a run (roots from the PEM in `spec.ca`).
pub fn tls_config(spec: &Spec, alpn: &[&[u8]], resume: bool) -> Result<Arc<simoom_tls::ClientConfig>, String> {
    let mut roots = simoom_tls::x509::RootStore::empty();
    let blocks = simoom_tls::pem::parse_pem(&spec.ca).map_err(|e| format!("--cacert: {e}"))?;
    let mut n = 0;
    for b in blocks.iter().filter(|b| b.label == "CERTIFICATE") {
        roots.add_der(&b.der).map_err(|e| format!("--cacert: {e}"))?;
        n += 1;
    }
    if n == 0 {
        return Err("TLS needs --cacert FILE (PEM): the server certificate is always verified".into());
    }
    let mut cfg = simoom_tls::ClientConfig::new(roots).with_alpn(alpn);
    if !resume {
        cfg.sessions = None;
    }
    Ok(Arc::new(cfg))
}

/// Whether a run resumes TLS sessions (S7 resumed handshakes): the `X-Bench-Resume` pseudo
/// header in the spec turns it on, so the agent protocol needs no new field.
pub(crate) fn wants_resume(spec: &Spec) -> bool {
    spec.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-bench-resume") && v == "1")
}

/// The server name for TLS and QUIC: `--sni`, else the host part of the target.
pub(crate) fn server_name(spec: &Spec) -> String {
    if !spec.sni.is_empty() {
        return spec.sni.clone();
    }
    match spec.host.rsplit_once(':') {
        Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']').to_string(),
        None => spec.host.clone(),
    }
}

struct Client {
    sh: Arc<Shared>,
    sched: Sched,
    wire: Wire,
    /// Outstanding requests: (start time for latency, time actually written). The start time is
    /// the intended time in open loop and the send time in closed loop.
    inflight: VecDeque<(u64, u64)>,
    tls: Option<Box<simoom_tls::ClientConnection>>,
    /// Decrypted bytes not yet framed (TLS only).
    pt: Vec<u8>,
    /// HTTP/1.1: body bytes of the current response still to come, and its status and close
    /// flag (large bodies are counted as they stream).
    body_left: usize,
    pending: (u16, bool),
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
        let tls = sh.tls.as_ref().and_then(|cfg| simoom_tls::ClientConnection::new(cfg.clone(), &sh.sni).ok().map(Box::new));
        let sched = Sched::new(sh.per_conn_rate, sh.dist, seed);
        Client {
            sh,
            sched,
            wire,
            inflight: VecDeque::new(),
            tls,
            pt: Vec::new(),
            body_left: 0,
            pending: (0, false),
            timer_armed: false,
            timer_at: 0,
            started: false,
            finished: false,
            dead: false,
        }
    }

    /// Fresh protocol state for a new connection, keeping the schedule.
    fn reborn(&mut self) -> Client {
        let mut c = Client::new(self.sh.clone(), 0);
        c.sched = self.sched.clone();
        c.started = self.started;
        c
    }

    /// Queues plaintext for the peer (encrypted when the connection uses TLS).
    fn emit(&mut self, cx: &mut Ctx<'_>, bytes: &[u8]) {
        match &mut self.tls {
            None => {
                let mut b = cx.buffer(bytes.len());
                b.extend_from_slice(bytes);
                cx.send(b);
            }
            Some(t) => {
                if t.write_plaintext(bytes).is_err() {
                    self.dead = true;
                }
            }
        }
    }

    fn flush(&mut self, cx: &mut Ctx<'_>) {
        if let Wire::H2(c, _) = &mut self.wire {
            let n = c.output().len();
            if n > 0 {
                match &mut self.tls {
                    None => {
                        let mut b = cx.buffer(n);
                        b.extend_from_slice(c.output());
                        cx.send(b);
                    }
                    Some(t) => {
                        let _ = t.write_plaintext(c.output());
                    }
                }
                c.advance_output(n);
            }
        }
        if let Some(t) = &mut self.tls {
            if t.wants_write() {
                let mut b = cx.buffer(t.tls_output().len());
                t.write_tls_into(&mut b);
                cx.send(b);
            }
        }
    }

    /// Sends one request; `t` is its start time for latency. Returns false if the protocol
    /// cannot open another stream now.
    fn send_one(&mut self, cx: &mut Ctx<'_>, t: u64) -> bool {
        let now = cx.now_ns();
        match &mut self.wire {
            Wire::H1 => {
                let sh = self.sh.clone();
                self.emit(cx, &sh.req);
                self.inflight.push_back((t, now));
            }
            Wire::H2(c, streams) => {
                let r = self.sh.h2.as_ref().unwrap();
                let fields: Vec<(&[u8], &[u8])> = r.headers.iter().map(|(a, b)| (&a[..], &b[..])).collect();
                let scheme: &[u8] = if self.tls.is_some() { b"https" } else { b"http" };
                match c.send_request(&r.method, scheme, &r.authority, &r.path, &fields, r.body.is_empty()) {
                    Ok(id) => {
                        if !r.body.is_empty() {
                            let _ = c.send_data(id, &r.body, true);
                        }
                        streams.push((id, t, now, 0));
                        self.inflight.push_back((t, now));
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
            for &(t, _) in &self.inflight {
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

    /// Frames plaintext responses. Returns (bytes consumed, the server closes, a protocol error).
    fn on_plain(&mut self, now: u64, data: &[u8]) -> (usize, bool, bool) {
        let mut pos = 0;
        let mut close = false;
        match &mut self.wire {
            Wire::H1 => loop {
                if self.body_left > 0 {
                    let take = self.body_left.min(data.len() - pos);
                    pos += take;
                    self.body_left -= take;
                    if self.body_left > 0 {
                        break;
                    }
                    let (status, c) = self.pending;
                    match self.inflight.pop_front() {
                        Some((t, ts)) => record(&self.sh, t, ts, now, status),
                        None => return (data.len(), false, true),
                    }
                    if c {
                        close = true;
                        break;
                    }
                    continue;
                }
                if pos >= data.len() {
                    break;
                }
                match h1::frame_partial(&data[pos..], self.sh.head) {
                    Ok(Some((f, left))) => {
                        pos += f.len;
                        if left > 0 {
                            self.body_left = left;
                            self.pending = (f.status, f.close);
                            break;
                        }
                        match self.inflight.pop_front() {
                            Some((t, ts)) => record(&self.sh, t, ts, now, f.status),
                            None => return (data.len(), false, true),
                        }
                        if f.close {
                            close = true;
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return (data.len(), false, true),
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
                        e.3 = *st;
                    }
                }
                for (s, st) in done {
                    if let Some(i) = streams.iter().position(|x| x.0 == s) {
                        let (_, t, ts, kept) = streams.swap_remove(i);
                        let st = if st == 0 { kept } else { st };
                        if let Some(j) = self.inflight.iter().position(|&x| x.0 == t && x.1 == ts) {
                            self.inflight.remove(j);
                        }
                        record(&self.sh, t, ts, now, st);
                    }
                }
                if closed {
                    close = true;
                }
            }
        }
        (pos, close, false)
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
        let (consumed, close, err) = if let Some(t) = &mut self.tls {
            // decrypt everything offered, then frame the plaintext
            let mut off = 0;
            let mut bad = false;
            while off < data.len() {
                let n = t.read_tls(&data[off..]);
                off += n;
                if t.process_new_packets().is_err() {
                    bad = true;
                    break;
                }
                let p = t.plaintext();
                if !p.is_empty() {
                    self.pt.extend_from_slice(p);
                    let k = p.len();
                    t.consume_plaintext(k);
                }
                if n == 0 && t.plaintext().is_empty() {
                    break;
                }
            }
            let peer_closed = t.peer_has_closed();
            if bad {
                (data.len(), false, true)
            } else {
                let buf = std::mem::take(&mut self.pt);
                let (used, close, err) = self.on_plain(now, &buf);
                let mut buf = buf;
                buf.drain(..used.min(buf.len()));
                self.pt = buf;
                (off, close || peer_closed, err)
            }
        } else {
            self.on_plain(now, data)
        };
        // count each byte once: unconsumed input is offered again with the next read (a large
        // body that arrives in pieces was counted many times, campaign 1's 684 Tbit/s for Go)
        let counted = if err || close { data.len() } else { consumed.min(data.len()) };
        let (ms, me) = (self.sh.mstart.load(Ordering::Relaxed), self.sh.mend.load(Ordering::Relaxed));
        if now >= ms && now < me {
            // inside the measured window only, like the request counters
            STATS.with(|s| s.borrow_mut().bytes_in += counted as u64);
        }
        if err {
            self.fail(cx);
            return data.len();
        }
        if close {
            self.flush(cx);
            cx.close();
            return data.len();
        }
        self.pump(cx);
        self.flush(cx);
        consumed
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

/// The event-driven engine's prepared run: the runtime is up and the connections are open.
struct RtPrepared {
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

/// A run prepared by one of the threaded engines (S5 connection per request, HTTP/3).
pub(crate) trait Engine: Send {
    fn connected(&self) -> usize;
    fn go(self: Box<Self>, delay: Duration) -> Report;
}

/// A prepared run: the connections are open (or the workers ready), waiting for [`Prepared::go`].
pub struct Prepared {
    inner: Inner,
}

enum Inner {
    Rt(RtPrepared),
    Engine(Box<dyn Engine>),
}

impl Prepared {
    pub fn connected(&self) -> usize {
        match &self.inner {
            Inner::Rt(p) => p.connected(),
            Inner::Engine(e) => e.connected(),
        }
    }

    /// Starts sending `delay` from now, runs warm-up, window and drain, and reports.
    pub fn go(self, delay: Duration) -> Report {
        match self.inner {
            Inner::Rt(p) => p.go(delay),
            Inner::Engine(e) => e.go(delay),
        }
    }
}

/// Prepares a run on the engine its spec needs.
pub fn prepare(spec: Spec) -> Result<Prepared, String> {
    let inner = if spec.proto == Proto::H3 {
        Inner::Engine(crate::h3load::prepare(spec)?)
    } else if spec.new_conn {
        Inner::Engine(crate::newconn::prepare(spec)?)
    } else {
        Inner::Rt(prepare_rt(spec)?)
    };
    Ok(Prepared { inner })
}

/// Opens the connections. Fails only if no connection could be opened.
fn prepare_rt(spec: Spec) -> Result<RtPrepared, String> {
    let threads = if spec.threads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) } else { spec.threads };
    let conns = spec.conns.max(1);
    let open = spec.rate > 0.0 && !spec.idle;
    let depth = if spec.idle { 1 } else { spec.depth.max(1) };
    let h2 = match spec.proto {
        Proto::H1 | Proto::H3 => None,
        Proto::H2c | Proto::H2 => {
            let mut headers: Vec<(Vec<u8>, Vec<u8>)> = request_headers(&spec).iter().map(|(k, v)| (k.to_ascii_lowercase().into_bytes(), v.clone().into_bytes())).collect();
            if !spec.body.is_empty() {
                headers.push((b"content-length".to_vec(), spec.body.len().to_string().into_bytes()));
            }
            Some(H2Req { method: spec.method.clone().into_bytes(), authority: spec.host.clone().into_bytes(), path: spec.path.clone().into_bytes(), headers, body: spec.body.clone() })
        }
    };
    let use_tls = spec.tls || spec.proto == Proto::H2;
    let tls = if use_tls {
        let alpn: &[&[u8]] = if spec.proto.is_h2() { &[b"h2"] } else { &[b"http/1.1"] };
        Some(tls_config(&spec, alpn, wants_resume(&spec))?)
    } else {
        None
    };
    let sh = Arc::new(Shared {
        t0: AtomicU64::new(u64::MAX),
        mstart: AtomicU64::new(u64::MAX),
        mend: AtomicU64::new(u64::MAX),
        hard_end: AtomicU64::new(u64::MAX),
        interval_ns: spec.interval.as_nanos() as u64,
        slo_ns: spec.slo_us * 1000,
        tls,
        sni: server_name(&spec),
        open,
        idle: spec.idle,
        depth,
        batch: spec.batch,
        per_conn_rate: if open { spec.rate / conns as f64 } else { 0.0 },
        dist: spec.dist,
        req: h1::build_request(&spec.method, &spec.path, &spec.host, &request_headers(&spec), &spec.body),
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
            c.max_input = 4 << 20;
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
    Ok(RtPrepared { spec, rt, sh, handles, connect_failed, reconnect_thread: Some(reconnect_thread) })
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

/// The request headers sent on the wire (the generator's own pseudo headers removed).
pub(crate) fn request_headers(spec: &Spec) -> Vec<(String, String)> {
    spec.headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("x-bench-resume")).cloned().collect()
}

impl RtPrepared {
    fn connected(&self) -> usize {
        self.handles.len()
    }

    fn go(mut self, delay: Duration) -> Report {
        let spec = self.spec.clone();
        let now = runtime_now(&self.rt);
        let t0 = now + delay.as_nanos() as u64;
        let (mstart, mend) = self.sh.set_window(t0, &spec);
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
                let _ = tx.send(LoopStats::take());
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
            s.add_to(&mut rep);
        }
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
