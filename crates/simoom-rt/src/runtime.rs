//! Starting, observing and stopping a runtime.

// Without the `udp` feature the UDP slots stay empty and their code is left out.
#![cfg_attr(not(feature = "udp"), allow(dead_code, unused_imports, unused_mut))]

use crate::event_loop::{build, ListenerSlot, LoopHandle, LoopSetup, UdpSlot};
use crate::handler::{Acceptor, UdpService};
use crate::offload::{OffloadConfig, OffloadPool};
use crate::pool::{PoolStats, DEFAULT_CLASSES};
use simoom_sys::driver::{Backend, DriverConfig, DriverStats};
use simoom_sys::net::{ListenOptions, Socket, UdpOptions};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// Runtime settings. `Config::default()` suits a server.
#[derive(Clone, Debug)]
pub struct Config {
    /// Loop threads; 0 means one per CPU this process may use.
    pub threads: usize,
    /// Pin loop `i` to CPU `cpus[i % cpus.len()]` (Linux and Windows).
    pub pin_threads: bool,
    /// The CPUs to pin to; `None` means the process affinity set.
    pub cpus: Option<Vec<usize>>,
    /// I/O driver settings, including the back end.
    pub driver: DriverConfig,
    /// Buffer class sizes; the smallest is also the receive buffer size.
    pub buffer_classes: [usize; 3],
    /// Most buffers each loop keeps cached in its smallest class.
    pub pool_cache: usize,
    /// Receive buffers each loop keeps lent to its driver (io_uring: in the provided-buffer ring).
    pub recv_buffers: usize,
    /// Most unconsumed input bytes per connection; beyond it the connection is closed.
    pub max_input: usize,
    /// Most connections in total; more are accepted and closed at once.
    pub max_connections: usize,
    /// Most connections per loop.
    pub max_connections_per_loop: usize,
    /// Above this many queued output bytes a connection stops reading.
    pub write_high_water: usize,
    /// At or below this many queued output bytes reading resumes.
    pub write_low_water: usize,
    /// Timer resolution.
    pub timer_tick: Duration,
    /// The shared offload pool.
    pub offload: OffloadConfig,
    /// Listener options (backlog, buffer sizes; `reuse_port` is set by the runtime). The
    /// default backlog is the system maximum, and `defer_accept` is `Some(1)`: on Linux a
    /// connection is handed over once its first bytes arrived, so the first request is read
    /// in the same turn as the accept. Set `defer_accept` to `None` for a protocol where the
    /// server speaks first.
    pub listen: ListenOptions,
    /// Loop thread name prefix.
    pub thread_name: String,
    /// Stack size of the loop threads; `None` keeps std's default (2 MiB, or `RUST_MIN_STACK`).
    /// Only touched pages cost memory, so this mostly matters for address space.
    pub stack_size: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            threads: 0,
            pin_threads: false,
            cpus: None,
            driver: DriverConfig::default(),
            buffer_classes: DEFAULT_CLASSES,
            pool_cache: 1024,
            recv_buffers: 64,
            max_input: 64 * 1024,
            max_connections: 1 << 20,
            max_connections_per_loop: 1 << 20,
            write_high_water: 256 * 1024,
            write_low_water: 64 * 1024,
            timer_tick: Duration::from_millis(1),
            offload: OffloadConfig::default(),
            listen: ListenOptions { defer_accept: Some(1), ..ListenOptions::default() },
            thread_name: "simoom-loop".into(),
            stack_size: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct LoopStats {
    waits: AtomicU64,
    recv_calls: AtomicU64,
    send_calls: AtomicU64,
    accept_calls: AtomicU64,
    other_calls: AtomicU64,
    sqes: AtomicU64,
    os_events: AtomicU64,
    sleeps: AtomicU64,
    spin_polls: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicU64,
    active: AtomicU64,
    pool_allocated: AtomicU64,
    pool_reused: AtomicU64,
    pool_cached: AtomicU64,
}

impl LoopStats {
    pub(crate) fn store(&self, d: DriverStats, p: PoolStats, accepted: u64, rejected: u64, closed: u64, active: u64) {
        let r = Ordering::Relaxed;
        self.waits.store(d.waits, r);
        self.recv_calls.store(d.recv_calls, r);
        self.send_calls.store(d.send_calls, r);
        self.accept_calls.store(d.accept_calls, r);
        self.other_calls.store(d.other_calls, r);
        self.sqes.store(d.sqes, r);
        self.os_events.store(d.os_events, r);
        self.sleeps.store(d.sleeps, r);
        self.spin_polls.store(d.spin_polls, r);
        self.accepted.store(accepted, r);
        self.rejected.store(rejected, r);
        self.closed.store(closed, r);
        self.active.store(active, r);
        self.pool_allocated.store(p.allocated, r);
        self.pool_reused.store(p.reused, r);
        self.pool_cached.store(p.cached as u64, r);
    }

    fn load(&self) -> LoopSnapshot {
        let r = Ordering::Relaxed;
        LoopSnapshot {
            driver: DriverStats {
                waits: self.waits.load(r),
                recv_calls: self.recv_calls.load(r),
                send_calls: self.send_calls.load(r),
                accept_calls: self.accept_calls.load(r),
                other_calls: self.other_calls.load(r),
                sqes: self.sqes.load(r),
                os_events: self.os_events.load(r),
                sleeps: self.sleeps.load(r),
                spin_polls: self.spin_polls.load(r),
            },
            accepted: self.accepted.load(r),
            rejected: self.rejected.load(r),
            closed: self.closed.load(r),
            active: self.active.load(r),
            pool_allocated: self.pool_allocated.load(r),
            pool_reused: self.pool_reused.load(r),
            pool_cached: self.pool_cached.load(r),
        }
    }
}

pub(crate) struct Shared {
    pub(crate) stop: AtomicBool,
    pub(crate) grace_ns: AtomicU64,
    pub(crate) active: AtomicUsize,
    pub(crate) loop_active: Vec<AtomicUsize>,
    pub(crate) loops: Vec<LoopStats>,
}

/// Counters of one loop, as last published by it (once per loop turn).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoopSnapshot {
    /// The loop's driver counters (system calls and OS events).
    pub driver: DriverStats,
    /// Connections accepted (and kept).
    pub accepted: u64,
    /// Connections refused: over a cap, or the acceptor said no.
    pub rejected: u64,
    /// Connections closed.
    pub closed: u64,
    /// Connections open now.
    pub active: u64,
    /// Buffers newly allocated by the loop's pool.
    pub pool_allocated: u64,
    /// Buffers reused by the loop's pool.
    pub pool_reused: u64,
    /// Buffers cached in the loop's pool now.
    pub pool_cached: u64,
}

/// Runtime counters.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Per loop.
    pub loops: Vec<LoopSnapshot>,
    /// Connections open now, across loops.
    pub active: usize,
}

impl Stats {
    /// The per-loop counters summed.
    pub fn total(&self) -> LoopSnapshot {
        let mut t = LoopSnapshot::default();
        for l in &self.loops {
            t.driver.waits += l.driver.waits;
            t.driver.recv_calls += l.driver.recv_calls;
            t.driver.send_calls += l.driver.send_calls;
            t.driver.accept_calls += l.driver.accept_calls;
            t.driver.other_calls += l.driver.other_calls;
            t.driver.sqes += l.driver.sqes;
            t.driver.os_events += l.driver.os_events;
            t.driver.sleeps += l.driver.sleeps;
            t.driver.spin_polls += l.driver.spin_polls;
            t.accepted += l.accepted;
            t.rejected += l.rejected;
            t.closed += l.closed;
            t.active += l.active;
            t.pool_allocated += l.pool_allocated;
            t.pool_reused += l.pool_reused;
            t.pool_cached += l.pool_cached;
        }
        t
    }
}

/// The start-up rendezvous between [`Builder::start`] and the loop threads: one mutex and one
/// condition variable (two channel types cost about 20 KB of code).
struct StartGate {
    st: Mutex<StartState>,
    cv: Condvar,
}

type LoopReport = io::Result<(LoopHandle, (Backend, Option<String>))>;

struct StartState {
    reports: Vec<Option<LoopReport>>,
    reported: usize,
    /// `None` until decided; `Some(None)` tells the loops to exit.
    peers: Option<Option<Arc<Vec<LoopHandle>>>>,
}

impl StartGate {
    fn lock(&self) -> MutexGuard<'_, StartState> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for the decision of [`Builder::start`]: every loop's handle, or `None` to exit.
    fn peers(&self) -> Option<Arc<Vec<LoopHandle>>> {
        let mut st = self.lock();
        loop {
            if let Some(p) = &st.peers {
                return p.clone();
            }
            st = self.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn release(&self, peers: Option<Arc<Vec<LoopHandle>>>) {
        self.lock().peers = Some(peers);
        self.cv.notify_all();
    }
}

/// A loop thread's report slot; a thread that ends without reporting counts as failed.
struct Reporter {
    gate: Arc<StartGate>,
    index: usize,
    done: bool,
}

impl Reporter {
    fn report(&mut self, r: LoopReport) {
        if !self.done {
            self.done = true;
            let mut st = self.gate.lock();
            st.reports[self.index] = Some(r);
            st.reported += 1;
            drop(st);
            self.gate.cv.notify_all();
        }
    }
}

impl Drop for Reporter {
    fn drop(&mut self) {
        if !self.done {
            self.done = true;
            let mut st = self.gate.lock();
            st.reported += 1;
            drop(st);
            self.gate.cv.notify_all();
        }
    }
}

enum ListenSource {
    Addr(io::Result<Vec<SocketAddr>>),
    Socket(Socket),
}

/// Builds and starts a runtime. See [`crate::Runtime::builder`].
pub struct Builder {
    cfg: Config,
    listeners: Vec<(ListenSource, Arc<dyn Acceptor>)>,
    udps: Vec<(io::Result<Vec<SocketAddr>>, UdpOptions, Arc<dyn UdpService>)>,
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder").field("cfg", &self.cfg).field("listeners", &self.listeners.len()).field("udps", &self.udps.len()).finish()
    }
}

impl Default for Builder {
    fn default() -> Self {
        Builder::new()
    }
}

impl Builder {
    /// A builder with the default [`Config`].
    pub fn new() -> Builder {
        Builder { cfg: Config::default(), listeners: Vec::new(), udps: Vec::new() }
    }

    /// Replaces the whole configuration.
    pub fn config(mut self, cfg: Config) -> Builder {
        self.cfg = cfg;
        self
    }

    /// Changes the configuration in place.
    pub fn configure(mut self, f: impl FnOnce(&mut Config)) -> Builder {
        f(&mut self.cfg);
        self
    }

    /// Loop threads (0 = one per CPU).
    pub fn threads(mut self, n: usize) -> Builder {
        self.cfg.threads = n;
        self
    }

    /// The I/O back end.
    pub fn backend(mut self, b: Backend) -> Builder {
        self.cfg.driver.backend = b;
        self
    }

    /// Accepts TCP connections on `addr` and runs them with `acceptor`. On Linux each loop gets
    /// its own `SO_REUSEPORT` listener; elsewhere one listener is shared and connections are
    /// handed to the less busy of two loops (on Windows, through one `AcceptEx` queue).
    /// Address errors are reported by [`Builder::start`].
    pub fn listen(self, addr: impl ToSocketAddrs, acceptor: impl Acceptor) -> Builder {
        let addrs = addr.to_socket_addrs().map(|a| a.collect());
        self.listen_addrs(addrs, Arc::new(acceptor))
    }

    fn listen_addrs(mut self, addrs: io::Result<Vec<SocketAddr>>, acceptor: Arc<dyn Acceptor>) -> Builder {
        // IPv4 first, as `localhost` should mean 127.0.0.1 (a stable partition, not a sort).
        let addrs = addrs.map(|v| {
            let (mut v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) = v.into_iter().partition(SocketAddr::is_ipv4);
            v4.extend(v6);
            v4
        });
        self.listeners.push((ListenSource::Addr(addrs), acceptor));
        self
    }

    /// Accepts on an existing listener (socket activation, a shared port). It is shared by all
    /// loops.
    pub fn listen_on(mut self, listener: std::net::TcpListener, acceptor: impl Acceptor) -> Builder {
        let _ = listener.set_nonblocking(true);
        self.listeners.push((ListenSource::Socket(Socket::from(listener)), Arc::new(acceptor)));
        self
    }

    /// Binds UDP on `addr` and creates an endpoint per loop with `service` (one `SO_REUSEPORT`
    /// socket per loop on Linux; one socket on loop 0 elsewhere). Feature `udp`.
    #[cfg(feature = "udp")]
    pub fn udp(mut self, addr: impl ToSocketAddrs, opts: UdpOptions, service: impl UdpService) -> Builder {
        let addrs = addr.to_socket_addrs().map(|a| a.collect());
        self.udps.push((addrs, opts, Arc::new(service)));
        self
    }

    /// Binds every listener, starts the loops and returns once they all run.
    pub fn start(self) -> io::Result<RuntimeHandle> {
        let mut cfg = self.cfg;
        let cpus = cfg.cpus.clone().unwrap_or_else(simoom_sys::cpu::allowed_cpus);
        let n = match (cfg.threads, &cfg.cpus) {
            (0, Some(_)) => cpus.len().max(1),
            (0, None) => simoom_sys::cpu::cpu_count(),
            (t, _) => t,
        };
        cfg.threads = n;
        if cfg.write_low_water > cfg.write_high_water {
            cfg.write_low_water = cfg.write_high_water;
        }
        let per_loop = cfg!(target_os = "linux");

        // Listener sockets per loop.
        let mut per_loop_listeners: Vec<Vec<ListenerSlot>> = (0..n).map(|_| Vec::new()).collect();
        let mut addrs = Vec::new();
        for (src, acceptor) in self.listeners {
            match src {
                ListenSource::Socket(s) => {
                    addrs.push(s.local_addr()?);
                    for slots in per_loop_listeners.iter_mut() {
                        slots.push(ListenerSlot::new(acceptor.clone(), None, true));
                    }
                    per_loop_listeners[0].last_mut().unwrap().socket = Some(s);
                }
                ListenSource::Addr(a) => {
                    let list = a?;
                    let first = *list.first().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address to listen on"))?;
                    let mut opts = cfg.listen.clone();
                    opts.reuse_port = per_loop;
                    let s0 = Socket::tcp_listen(first, &opts)?;
                    let bound = s0.local_addr()?;
                    addrs.push(bound);
                    // Loop 0 gets the socket bound here (it fixes the port); the other loops bind
                    // their SO_REUSEPORT sockets on their own threads, in parallel.
                    let mut s0 = Some(s0);
                    for (i, slots) in per_loop_listeners.iter_mut().enumerate() {
                        let mut slot = ListenerSlot::new(acceptor.clone(), s0.take(), !per_loop);
                        if per_loop && i > 0 {
                            slot.bind = Some((bound, opts.clone()));
                        }
                        slots.push(slot);
                    }
                }
            }
        }

        // UDP sockets per loop.
        let mut per_loop_udps: Vec<Vec<UdpSlot>> = (0..n).map(|_| Vec::new()).collect();
        let mut udp_addrs = Vec::new();
        #[cfg(feature = "udp")]
        for (b, (a, opts, service)) in self.udps.into_iter().enumerate() {
            let list = a?;
            let first = *list.first().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address to bind"))?;
            let mut opts = opts;
            opts.reuse_port = per_loop;
            let s0 = Socket::udp_bind(first, &opts)?;
            let bound = s0.local_addr()?;
            udp_addrs.push(bound);
            per_loop_udps[0].push(UdpSlot::new(service.clone(), b, Some(s0), opts.gro));
            if per_loop {
                for slots in per_loop_udps.iter_mut().skip(1) {
                    let mut slot = UdpSlot::new(service.clone(), b, None, opts.gro);
                    slot.bind = Some((bound, opts.clone()));
                    slots.push(slot);
                }
            }
        }

        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            grace_ns: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            loop_active: (0..n).map(|_| AtomicUsize::new(0)).collect(),
            loops: (0..n).map(|_| LoopStats::default()).collect(),
        });
        let mut ocfg = cfg.offload.clone();
        if ocfg.name.is_empty() {
            ocfg.name = "simoom-offload".into();
        }
        let offload = OffloadPool::new(ocfg);
        let cfg = Arc::new(cfg);

        // Start the loops: each creates its driver on its own thread, reports its handle, then
        // waits for the handles of all loops before serving.
        let gate = Arc::new(StartGate { st: Mutex::new(StartState { reports: (0..n).map(|_| None).collect(), reported: 0, peers: None }), cv: Condvar::new() });
        let mut threads = Vec::new();
        for (i, (listeners, udps)) in per_loop_listeners.into_iter().zip(per_loop_udps).enumerate() {
            let setup = LoopSetup { index: i, cfg: cfg.clone(), shared: shared.clone(), offload: offload.clone(), listeners, udps };
            let pin = if cfg.pin_threads && !cpus.is_empty() { Some(cpus[i % cpus.len()]) } else { None };
            let mut reporter = Reporter { gate: gate.clone(), index: i, done: false };
            let mut tb = std::thread::Builder::new().name(format!("{}-{i}", cfg.thread_name));
            if let Some(sz) = cfg.stack_size {
                tb = tb.stack_size(sz);
            }
            let spawned = tb.spawn(move || {
                if let Some(cpu) = pin {
                    let _ = simoom_sys::cpu::pin_current_thread(cpu);
                }
                let (mut core, queue) = match build(setup) {
                    Ok(x) => x,
                    Err(e) => return reporter.report(Err(e)),
                };
                let backend = core.backend();
                reporter.report(Ok((LoopHandle { index: i, queue }, backend)));
                let Some(peers) = reporter.gate.peers() else { return };
                core.set_peers(peers.to_vec());
                drop(reporter);
                if let Err(e) = core.run() {
                    eprintln!("simoom loop {i} failed: {e}");
                }
            });
            match spawned {
                Ok(t) => threads.push(t),
                Err(e) => {
                    gate.release(None);
                    for t in threads {
                        let _ = t.join();
                    }
                    return Err(e);
                }
            }
        }
        let mut backend = (Backend::Auto, None);
        let mut err = None;
        let mut loops = Vec::with_capacity(n);
        {
            let mut st = gate.lock();
            while st.reported < n {
                st = gate.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
            }
            for r in st.reports.iter_mut() {
                match r.take() {
                    Some(Ok((h, b))) => {
                        loops.push(h);
                        backend = b;
                    }
                    Some(Err(e)) => err = Some(e),
                    None => err = Some(io::Error::other("a loop thread died during start")),
                }
            }
        }
        if let Some(e) = err {
            gate.release(None);
            for t in threads {
                let _ = t.join();
            }
            return Err(e);
        }
        gate.release(Some(Arc::new(loops.clone())));
        Ok(RuntimeHandle { loops, threads, shared, addrs, udp_addrs, offload, backend: backend.0, fallback: backend.1 })
    }
}

/// A running runtime. Dropping it stops the runtime at once (no grace) and waits for its
/// threads; call [`RuntimeHandle::stop`] and [`RuntimeHandle::join`] for a graceful stop.
pub struct RuntimeHandle {
    loops: Vec<LoopHandle>,
    threads: Vec<JoinHandle<()>>,
    shared: Arc<Shared>,
    addrs: Vec<SocketAddr>,
    udp_addrs: Vec<SocketAddr>,
    offload: OffloadPool,
    backend: Backend,
    fallback: Option<String>,
}

impl std::fmt::Debug for RuntimeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeHandle").field("loops", &self.loops.len()).field("addrs", &self.addrs).field("backend", &self.backend).finish()
    }
}

impl RuntimeHandle {
    /// The bound TCP addresses, in the order of [`Builder::listen`] calls.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// The bound UDP addresses, in the order of [`Builder::udp`] calls.
    pub fn udp_addrs(&self) -> &[SocketAddr] {
        &self.udp_addrs
    }

    /// The loops, to run tasks on them.
    pub fn loops(&self) -> &[LoopHandle] {
        &self.loops
    }

    /// The back end the loops use.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Why the configured back end was replaced (io_uring falling back to epoll), if it was.
    pub fn fallback_reason(&self) -> Option<&str> {
        self.fallback.as_deref()
    }

    /// The shared offload pool.
    pub fn offload(&self) -> &OffloadPool {
        &self.offload
    }

    /// Current counters.
    pub fn stats(&self) -> Stats {
        Stats { loops: self.shared.loops.iter().map(LoopStats::load).collect(), active: self.shared.active.load(Ordering::Relaxed) }
    }

    /// Starts a graceful stop: listeners close, every connection gets
    /// [`crate::Connection::on_stop`], and connections still open after `grace` are aborted.
    pub fn stop(&self, grace: Duration) {
        self.shared.grace_ns.store(grace.as_nanos().min(u64::MAX as u128) as u64, Ordering::Release);
        self.shared.stop.store(true, Ordering::Release);
        for l in &self.loops {
            l.queue.waker.wake();
        }
    }

    /// Waits for every loop to exit (after [`RuntimeHandle::stop`]), then stops the offload
    /// pool.
    pub fn join(mut self) {
        self.join_threads();
    }

    fn join_threads(&mut self) {
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        self.offload.shutdown(Duration::from_secs(5));
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            if !self.shared.stop.load(Ordering::Acquire) {
                self.stop(Duration::ZERO);
            }
            self.join_threads();
        }
    }
}
