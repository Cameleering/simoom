//! [`Server`], its [`Builder`] and [`ServerHandle`]; the state shared by every connection; the
//! service call with panic catching and the stall watchdog.

use crate::limits::Limits;
use crate::reply::{Reply, Target};
use crate::request::Request;
use crate::service::Service;
use simoom_rt::offload::{OffloadConfig, OffloadStats};
use simoom_rt::{Backend, ConnInfo, Connection, Runtime, RuntimeHandle};
use std::io;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::panic::{catch_unwind, AssertUnwindSafe};
use crate::watchdog::Watch;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Counters of one loop thread (each loop writes only its own, so they never contend).
#[derive(Default, Debug)]
#[repr(align(64))]
pub(crate) struct Counters {
    pub(crate) requests: AtomicU64,
    pub(crate) bad_requests: AtomicU64,
    pub(crate) too_large: AtomicU64,
    pub(crate) timeouts: AtomicU64,
    pub(crate) panics: AtomicU64,
    pub(crate) stalls: AtomicU64,
    pub(crate) stall_checks: AtomicU64,
    pub(crate) offloaded_routes: AtomicU64,
    pub(crate) overloaded: AtomicU64,
    pub(crate) shed: AtomicU64,
    pub(crate) upgrades: AtomicU64,
    pub(crate) h2_connections: AtomicU64,
    pub(crate) h3_connections: AtomicU64,
    pub(crate) quic_endpoints: AtomicU64,
    pub(crate) tls_errors: AtomicU64,
}

/// Counter slots, indexed by loop number modulo this (loops beyond it share slots).
const COUNTER_SLOTS: usize = 64;

pub(crate) fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// Everything the connections share: the service, limits, protocol settings and counters.
pub(crate) struct Shared {
    pub(crate) service: Arc<dyn Service>,
    pub(crate) limits: Limits,
    #[cfg(feature = "http1")]
    pub(crate) h1: simoom_http1::Limits,
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    pub(crate) http2: bool,
    #[cfg(feature = "http2")]
    pub(crate) h2: simoom_h2::Config,
    /// `alt-svc: ...\r\n`, set once the UDP port is known.
    pub(crate) alt_svc: OnceLock<(Vec<u8>, Vec<u8>)>,
    counters: Box<[Counters]>,
    pub(crate) watchdog: crate::watchdog::Policy,
    /// [`Limits::shed_lag`] in ns (0: off).
    pub(crate) shed_ns: u64,
    /// Watchdog state per path slot, for services without routes ([`Service::watch`] `None`).
    slots: Box<[Arc<Watch>]>,
    /// Slots that are suspect or offloaded: the path is hashed only while this is not 0.
    slots_active: Arc<AtomicU32>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    #[cfg(feature = "tls")]
    pub(crate) tls: Option<Arc<simoom_tls::ServerConfig>>,
    /// Open connections per client IP, kept only when [`Limits::max_connections_per_ip`] is set.
    per_ip: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>,
}

/// A connection's place in the per-IP count; released when the connection is dropped.
pub(crate) struct IpSlot {
    sh: Arc<Shared>,
    ip: std::net::IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut m = self.sh.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

impl Shared {
    /// Takes a per-IP slot for a new connection; `Err` when the IP is at its cap.
    pub(crate) fn take_ip_slot(self: &Arc<Self>, peer: Option<std::net::SocketAddr>) -> Result<Option<IpSlot>, ()> {
        let cap = self.limits.max_connections_per_ip;
        let Some(peer) = peer.filter(|_| cap != 0) else { return Ok(None) };
        let ip = peer.ip();
        let mut m = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(ip).or_insert(0);
        if *n as usize >= cap {
            return Err(());
        }
        *n += 1;
        Ok(Some(IpSlot { sh: self.clone(), ip }))
    }
}

impl Shared {
    pub(crate) fn counters(&self, loop_index: usize) -> &Counters {
        &self.counters[loop_index % self.counters.len()]
    }

    /// The `alt-svc` line for HTTP/1.1 responses.
    pub(crate) fn alt_svc_line(&self) -> Option<&[u8]> {
        self.alt_svc.get().map(|a| &a.0[..])
    }

    /// The `alt-svc` value for HTTP/2 responses.
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    pub(crate) fn alt_svc_value(&self) -> Option<&[u8]> {
        self.alt_svc.get().map(|a| &a.1[..])
    }

    pub(crate) fn log(&self, msg: &str) {
        (self.log)(msg)
    }

    /// The watchdog slot of a request to a service without routes: its method and path.
    fn slot(&self, req: &Request<'_>) -> &Arc<Watch> {
        use std::hash::Hasher;
        let mut h = crate::util::Fnv::default();
        h.write(req.method());
        h.write(req.path());
        &self.slots[(h.finish() as usize) % self.slots.len()]
    }

    /// The watchdog's part after a call that overran the budget or was measured.
    fn after_call(&self, req: &Request<'_>, took_ns: u64) {
        let p = &self.watchdog;
        let (w, k, name) = match self.service.watch(req) {
            Some(r) => (r.watch, r.stalls.unwrap_or(p.stalls), std::borrow::Cow::Borrowed(r.name)),
            None => (self.slot(req), p.stalls, String::from_utf8_lossy(req.path())),
        };
        let c = self.counters(req.loop_index);
        let Some(s) = req.sample else {
            if took_ns > p.budget_ns && w.wall_overrun() {
                bump(&c.stall_checks);
            }
            return;
        };
        let ev = w.measured(took_ns, s, p, k, simoom_sys::time::now_ns());
        if ev == crate::watchdog::Event::None {
            return;
        }
        bump(&c.stalls);
        if !w.logged.swap(true, Ordering::Relaxed) {
            // Microseconds as integers: `Duration`'s Debug costs 2 KB of code.
            self.log(&format!(
                "simoom: an inline handler on {name} took {} us ({} us of CPU; budget {} us); slow handlers belong on the offload pool",
                took_ns / 1000,
                s.cpu_ns / 1000,
                p.budget_ns / 1000
            ));
        }
        if ev == crate::watchdog::Event::Offloaded {
            bump(&c.offloaded_routes);
            self.log(&format!("simoom: {name} stalled {k} times within {} ms and now runs on the offload pool", p.window_ns / 1_000_000));
        }
    }
}

/// Calls the service for one request: on the offload pool when the watchdog moved the
/// request's path there, else inline, timed, with panics caught. Returns `true` if the service
/// panicked. (A [`crate::Router`] does the same per route inside its own call.)
///
/// `clock` carries the time the previous call of the same callback ended, so pipelined
/// requests cost one clock read each instead of two.
pub(crate) fn call(sh: &Shared, req: &mut Request<'_>, t: &mut dyn Target, clock: &mut Option<Instant>) -> bool {
    let budget = sh.watchdog.budget_ns;
    if budget == 0 {
        let r = catch_unwind(AssertUnwindSafe(|| {
            let _ = sh.service.call(req, Reply::new(t));
        }));
        return finish_call(sh, req, r);
    }
    let mut measure = false;
    if sh.slots_active.load(Ordering::Relaxed) != 0 {
        let w = sh.slot(req);
        if w.offloaded() {
            let w = w.clone();
            let _ = Reply::new(t).offload_watched(req, sh.service.clone(), w);
            return false;
        }
        measure = w.suspect();
    }
    let t0 = clock.take().unwrap_or_else(Instant::now);
    let r = if measure {
        let (r, s) = crate::watchdog::measured(|| {
            catch_unwind(AssertUnwindSafe(|| {
                let _ = sh.service.call(req, Reply::new(t));
            }))
        });
        req.sample = s;
        r
    } else {
        catch_unwind(AssertUnwindSafe(|| {
            let _ = sh.service.call(req, Reply::new(t));
        }))
    };
    let t1 = Instant::now();
    *clock = Some(t1);
    let took = (t1 - t0).as_nanos() as u64;
    if took > budget || req.sample.is_some() {
        sh.after_call(req, took);
    }
    finish_call(sh, req, r)
}

/// Path slots of the watchdog for services without routes.
const WATCH_SLOTS: usize = 64;

fn finish_call(sh: &Shared, req: &Request<'_>, r: std::thread::Result<()>) -> bool {
    if r.is_err() {
        bump(&sh.counters(req.loop_index).panics);
        return true;
    }
    false
}

/// Server counters.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Connections accepted.
    pub accepted: u64,
    /// Connections refused (over a cap).
    pub rejected: u64,
    /// Connections open now.
    pub active: usize,
    /// Requests started (every protocol).
    pub requests: u64,
    /// Malformed requests (400-class parse errors).
    pub bad_requests: u64,
    /// Requests over a size limit (413, 414, 431).
    pub too_large: u64,
    /// Connections closed by a timeout (head deadline, body rate, idle with a partial request,
    /// write deadline).
    pub timeouts: u64,
    /// Handlers that panicked.
    pub panics: u64,
    /// Inline handler calls the watchdog confirmed as stalls (over the CPU budget, or blocked).
    pub stalls: u64,
    /// Calls over the budget on the wall clock that made their route suspect (and measured);
    /// most are a preempted loop thread, not a slow handler.
    pub stall_checks: u64,
    /// Times a route moved to the offload pool.
    pub offloaded_routes: u64,
    /// Requests answered 503 because the offload pool was full or overloaded.
    pub overloaded: u64,
    /// Requests answered 503 by admission control ([`Limits::shed_lag`]).
    pub shed: u64,
    /// WebSocket and h2c upgrades.
    pub upgrades: u64,
    /// HTTP/2 connections.
    pub h2_connections: u64,
    /// HTTP/3 connections.
    pub h3_connections: u64,
    /// QUIC endpoints built: one per loop, on that loop's first HTTP/3 datagram (a loop that
    /// never sees HTTP/3 traffic builds none).
    pub quic_endpoints: u64,
    /// Failed TLS handshakes.
    pub tls_errors: u64,
    /// The offload pool.
    pub offload: OffloadStats,
    /// The runtime: per-loop system calls, buffers, connections.
    pub runtime: simoom_rt::Stats,
}

/// Entry point: [`Server::builder`].
#[derive(Debug)]
pub struct Server;

impl Server {
    /// A [`Builder`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// A builder serving existing listeners (socket activation, a shared port).
    pub fn from_listeners(listeners: Vec<TcpListener>) -> Builder {
        let mut b = Builder::default();
        for l in listeners {
            b = b.listen_on(l);
        }
        b
    }
}

enum Listen {
    Addr(io::Result<Vec<SocketAddr>>),
    Std(TcpListener),
}

type RtConfigure = Box<dyn FnOnce(&mut simoom_rt::Config)>;
#[cfg(feature = "http3")]
type QuicConfigure = Box<dyn FnOnce(&mut simoom_quic::Config)>;

/// Configures and starts a server. See [`Server::builder`].
pub struct Builder {
    tcp: Vec<(Listen, bool)>,
    #[cfg(feature = "http3")]
    quic: Vec<io::Result<Vec<SocketAddr>>>,
    threads: usize,
    backend: Backend,
    limits: Limits,
    http2: bool,
    alt_svc: Option<String>,
    service: Option<Arc<dyn Service>>,
    runtime: Vec<RtConfigure>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    #[cfg(feature = "tls")]
    tls: Option<simoom_tls::ServerConfig>,
    #[cfg(feature = "http3")]
    quic_tls: Option<simoom_tls::ServerConfig>,
    #[cfg(feature = "http3")]
    quic_config: Option<QuicConfigure>,
    #[cfg(feature = "http3")]
    quic_gro: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Builder {
            tcp: Vec::new(),
            #[cfg(feature = "http3")]
            quic: Vec::new(),
            threads: 0,
            backend: Backend::Auto,
            limits: Limits::default(),
            http2: true,
            alt_svc: None,
            service: None,
            runtime: Vec::new(),
            log: Arc::new(|m: &str| eprintln!("{m}")),
            #[cfg(feature = "tls")]
            tls: None,
            #[cfg(feature = "http3")]
            quic_tls: None,
            #[cfg(feature = "http3")]
            quic_config: None,
            #[cfg(feature = "http3")]
            quic_gro: true,
        }
    }
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder").field("listeners", &self.tcp.len()).field("threads", &self.threads).field("limits", &self.limits).finish()
    }
}

fn resolve(addr: impl ToSocketAddrs) -> io::Result<Vec<SocketAddr>> {
    // The runtime puts IPv4 first (`localhost` should mean 127.0.0.1).
    let v: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    if v.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no address to listen on"));
    }
    Ok(v)
}

impl Builder {
    /// Listens on `addr` (plain TCP: HTTP/1.1, and h2c when HTTP/2 is on). Address errors are
    /// reported by [`Builder::start`].
    pub fn listen(mut self, addr: impl ToSocketAddrs) -> Self {
        self.tcp.push((Listen::Addr(resolve(addr)), false));
        self
    }

    /// Listens on `addr` with TLS ([`Builder::tls`]); ALPN chooses h2 or http/1.1.
    #[cfg(feature = "tls")]
    pub fn listen_tls(mut self, addr: impl ToSocketAddrs) -> Self {
        self.tcp.push((Listen::Addr(resolve(addr)), true));
        self
    }

    /// Serves an existing listener (plain TCP).
    pub fn listen_on(mut self, listener: TcpListener) -> Self {
        self.tcp.push((Listen::Std(listener), false));
        self
    }

    /// Serves an existing listener with TLS.
    #[cfg(feature = "tls")]
    pub fn listen_on_tls(mut self, listener: TcpListener) -> Self {
        self.tcp.push((Listen::Std(listener), true));
        self
    }

    /// Serves HTTP/3 over QUIC on the UDP address `addr`, with the TLS configuration given to
    /// [`Builder::quic_tls`] (or, failing that, error at start). HTTP/1.1 and HTTP/2 responses
    /// then announce it with `alt-svc`.
    #[cfg(feature = "http3")]
    pub fn listen_quic(mut self, addr: impl ToSocketAddrs) -> Self {
        self.quic.push(resolve(addr));
        self
    }

    /// The TLS configuration for [`Builder::listen_tls`] listeners. Its ALPN list is replaced
    /// with `h2` (when HTTP/2 is on) and `http/1.1`.
    #[cfg(feature = "tls")]
    pub fn tls(mut self, config: simoom_tls::ServerConfig) -> Self {
        self.tls = Some(config);
        self
    }

    /// The TLS configuration for HTTP/3 listeners (its ALPN becomes `h3`).
    #[cfg(feature = "http3")]
    pub fn quic_tls(mut self, config: simoom_tls::ServerConfig) -> Self {
        self.quic_tls = Some(config);
        self
    }

    /// Adjusts the QUIC configuration (transport parameters, Retry) before start.
    #[cfg(feature = "http3")]
    pub fn quic_config(mut self, f: impl FnOnce(&mut simoom_quic::Config) + 'static) -> Self {
        self.quic_config = Some(Box::new(f));
        self
    }

    /// UDP generic receive offload on HTTP/3 listeners (Linux only; on by default): the kernel
    /// hands over a batch of datagrams from one peer as one 64 KiB buffer, one receive call
    /// for up to 64 packets.
    #[cfg(feature = "http3")]
    pub fn quic_gro(mut self, on: bool) -> Self {
        self.quic_gro = on;
        self
    }

    /// Loop threads: 0 (the default) means one per CPU.
    pub fn threads(mut self, n: usize) -> Self {
        self.threads = n;
        self
    }

    /// The I/O back end: `Auto` picks io_uring only when enabled, else epoll, IOCP or kqueue.
    pub fn backend(mut self, b: Backend) -> Self {
        self.backend = b;
        self
    }

    /// Every limit (plan §7.1 defaults).
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// HTTP/2 on or off (on by default with the `http2` feature): h2c prior knowledge,
    /// `Upgrade: h2c`, and ALPN `h2`.
    pub fn http2(mut self, on: bool) -> Self {
        self.http2 = on;
        self
    }

    /// Overrides the `alt-svc` value announced on HTTP/1.1 and HTTP/2 responses (by default
    /// `h3=":<port>"; ma=86400` when HTTP/3 listens).
    pub fn alt_svc(mut self, value: impl Into<String>) -> Self {
        self.alt_svc = Some(value.into());
        self
    }

    /// The service that answers every request.
    pub fn service(mut self, service: impl Service) -> Self {
        self.service = Some(Arc::new(service));
        self
    }

    /// Adjusts the runtime configuration (buffer sizes, pinning, back-end details).
    pub fn runtime(mut self, f: impl FnOnce(&mut simoom_rt::Config) + 'static) -> Self {
        self.runtime.push(Box::new(f));
        self
    }

    /// Where log lines go (stall warnings). Default: standard error.
    pub fn log(mut self, f: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.log = Arc::new(f);
        self
    }

    /// Binds every listener, starts the loops, and returns once they run.
    pub fn start(self) -> io::Result<ServerHandle> {
        let service = self.service.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no service"))?;
        let limits = self.limits;
        let http2 = self.http2 && cfg!(feature = "http2");
        #[cfg(feature = "tls")]
        let tls = match self.tls {
            Some(mut c) => {
                c.alpn = if http2 { vec![b"h2".to_vec(), b"http/1.1".to_vec()] } else { vec![b"http/1.1".to_vec()] };
                Some(Arc::new(c))
            }
            None => None,
        };
        #[cfg(feature = "tls")]
        if tls.is_none() && self.tcp.iter().any(|(_, t)| *t) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a TLS listener needs Builder::tls"));
        }
        #[cfg(feature = "http2")]
        let h2 = simoom_h2::Config {
            max_concurrent_streams: limits.max_concurrent_streams,
            max_header_list_size: limits.max_header_list,
            header_table_size: limits.header_table_size,
            budgets: limits.h2_frame_budgets.h2(),
            ..simoom_h2::Config::default()
        };
        let slots_active = Arc::new(AtomicU32::new(0));
        let shared = Arc::new(Shared {
            service,
            #[cfg(feature = "http1")]
            h1: limits.http1(),
            http2,
            #[cfg(feature = "http2")]
            h2,
            alt_svc: OnceLock::new(),
            counters: (0..COUNTER_SLOTS).map(|_| Counters::default()).collect(),
            watchdog: limits.watchdog(),
            shed_ns: limits.shed_lag.map_or(0, |d| (d.as_nanos() as u64).max(1)),
            slots: (0..WATCH_SLOTS).map(|_| Arc::new(Watch::new(Some(slots_active.clone())))).collect(),
            slots_active,
            log: self.log,
            per_ip: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(feature = "tls")]
            tls,
            limits,
        });
        if let Some(v) = &self.alt_svc {
            let _ = shared.alt_svc.set((format!("alt-svc: {v}\r\n").into_bytes(), v.clone().into_bytes()));
        }

        let lim = &shared.limits;
        let mut rt = Runtime::builder().threads(self.threads).backend(self.backend).configure(|c| {
            c.max_connections = lim.max_connections;
            c.max_connections_per_loop = lim.max_connections_per_loop;
            c.max_input = (lim.max_head * 2 + 16 * 1024).max(64 * 1024);
            c.thread_name = "simoom".into();
            // One loop until three connections are open at once: an idle server, or one that
            // serves a connection at a time (FaaS), costs one loop thread in start-up time and
            // memory. Servers with HTTP/3 start every loop (see simoom_rt::Config::lazy_loops).
            c.lazy_loops = true;
            c.offload = OffloadConfig {
                max_threads: lim.offload_threads,
                max_queue: lim.offload_queue,
                target: lim.offload_target,
                interval: lim.offload_interval,
                ..OffloadConfig::default()
            };
        });
        for f in self.runtime {
            rt = rt.configure(f);
        }
        for (src, secure) in self.tcp {
            let sh = shared.clone();
            let acceptor = move |info: &ConnInfo| {
                // Over the per-IP cap: refused (the runtime counts it in `rejected`).
                let slot = sh.take_ip_slot(info.peer).ok()?;
                Some(Box::new(crate::conn::Conn::new(sh.clone(), info, secure, slot)) as Box<dyn Connection>)
            };
            rt = match src {
                Listen::Addr(a) => rt.listen(&a?[..], acceptor),
                Listen::Std(l) => rt.listen_on(l, acceptor),
            };
        }
        #[cfg(feature = "http3")]
        let quic_cfg = if self.quic.is_empty() {
            None
        } else {
            let mut c = self.quic_tls.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "an HTTP/3 listener needs Builder::quic_tls"))?;
            c.alpn = vec![b"h3".to_vec()];
            let mut q = simoom_quic::Config::new(Arc::new(simoom_quic::tls::TlsProvider::server(Arc::new(c))));
            q.transport.max_streams_bidi = u64::from(shared.limits.max_concurrent_streams);
            q.transport.max_idle_timeout = shared.limits.keep_alive_timeout.max(Duration::from_secs(1));
            q.transport.disable_active_migration = true;
            if let Some(f) = self.quic_config {
                f(&mut q);
            }
            Some(Arc::new(q))
        };
        #[cfg(feature = "http3")]
        if let Some(q) = &quic_cfg {
            for a in self.quic {
                let a = a?;
                let sh = shared.clone();
                let q = q.clone();
                // GRO on Linux: a batch of datagrams from one peer arrives as one 64 KiB buffer
                // (one receive and one wake-up for up to 64 packets of a bulk upload).
                let opts = simoom_rt::UdpOptions { gro: self.quic_gro && cfg!(target_os = "linux"), ..simoom_rt::UdpOptions::default() };
                rt = rt.udp(&a[..], opts, move |info: &simoom_rt::UdpInfo| crate::h3::endpoint(sh.clone(), q.clone(), info));
            }
        }
        let rt = rt.start()?;
        #[cfg(feature = "http3")]
        if let Some(a) = rt.udp_addrs().first() {
            let v = format!("h3=\":{}\"; ma=86400", a.port());
            let _ = shared.alt_svc.set((format!("alt-svc: {v}\r\n").into_bytes(), v.into_bytes()));
        }
        Ok(ServerHandle { rt, shared })
    }
}

/// A running server. Dropping it stops at once; use [`ServerHandle::stop`] and
/// [`ServerHandle::join`] for a graceful stop.
pub struct ServerHandle {
    rt: RuntimeHandle,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle").field("addrs", &self.rt.local_addrs()).field("backend", &self.rt.backend()).finish()
    }
}

impl ServerHandle {
    /// The first bound TCP address.
    pub fn local_addr(&self) -> SocketAddr {
        self.rt.local_addrs().first().or(self.rt.udp_addrs().first()).copied().unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// Every bound TCP address, in the order of the `listen` calls.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        self.rt.local_addrs()
    }

    /// Every bound UDP (HTTP/3) address.
    pub fn quic_addrs(&self) -> &[SocketAddr] {
        self.rt.udp_addrs()
    }

    /// The I/O back end in use.
    pub fn backend(&self) -> Backend {
        self.rt.backend()
    }

    /// Why the requested back end was replaced, if it was (io_uring falling back to epoll).
    pub fn fallback_reason(&self) -> Option<&str> {
        self.rt.fallback_reason()
    }

    /// Current counters.
    pub fn stats(&self) -> Stats {
        let rt = self.rt.stats();
        let t = rt.total();
        let mut s = Stats { accepted: t.accepted, rejected: t.rejected, active: rt.active, offload: self.rt.offload().stats(), ..Stats::default() };
        let r = Ordering::Relaxed;
        for c in self.shared.counters.iter() {
            s.requests += c.requests.load(r);
            s.bad_requests += c.bad_requests.load(r);
            s.too_large += c.too_large.load(r);
            s.timeouts += c.timeouts.load(r);
            s.panics += c.panics.load(r);
            s.stalls += c.stalls.load(r);
            s.stall_checks += c.stall_checks.load(r);
            s.offloaded_routes += c.offloaded_routes.load(r);
            s.overloaded += c.overloaded.load(r);
            s.shed += c.shed.load(r);
            s.upgrades += c.upgrades.load(r);
            s.h2_connections += c.h2_connections.load(r);
            s.h3_connections += c.h3_connections.load(r);
            s.quic_endpoints += c.quic_endpoints.load(r);
            s.tls_errors += c.tls_errors.load(r);
        }
        s.runtime = rt;
        s
    }

    /// Starts a graceful stop: listeners close; idle HTTP/1.1 connections close at once and busy
    /// ones after their response (with `Connection: close`); HTTP/2 and HTTP/3 connections get
    /// GOAWAY and close when their streams finish. Whatever is still open after `grace` is
    /// aborted.
    pub fn stop(&self, grace: Duration) {
        self.rt.stop(grace);
    }

    /// Waits for the loops to exit (after [`ServerHandle::stop`]).
    pub fn join(self) {
        self.rt.join();
    }
}
