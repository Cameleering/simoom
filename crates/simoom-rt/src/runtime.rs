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
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
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
    /// Start only loop 0 at [`Builder::start`], without waiting for it (the listeners are bound
    /// first, so connections wait in the backlog), and the other loops in the background when
    /// loop 0 holds three connections at once. A server that is idle, or serves one connection
    /// at a time (a FaaS instance), then pays for one loop thread in start-up time and memory
    /// instead of one per core. Connections accepted while the other loops start (well under a
    /// millisecond) are held, then spread over every loop, and loop 0 hands out its accepts for
    /// a second after. A loop that fails to build its driver is logged on standard error
    /// instead of failing `start` (binding errors still fail it). Ignored when the runtime has
    /// UDP sockets ([`Builder::udp`]): every loop starts at once then, since a socket added
    /// later to a `SO_REUSEPORT` group would take over some established QUIC connections.
    /// Default `false` here (a load generator wants every loop at once); the `simoom` server
    /// turns it on.
    pub lazy_loops: bool,
    /// Lingering close: after a graceful close ([`crate::Ctx::close`]) the write side is shut
    /// down and input is read and dropped until the peer closes, for at most this long, before
    /// the socket is closed (closing over unread input resets the connection, and a reset can
    /// destroy the last response at the peer). `Duration::ZERO` closes at once. Default 2 s.
    pub linger: Duration,
    /// The most input a lingering close reads and drops before it closes anyway. Default
    /// 256 KiB.
    pub linger_bytes: usize,
    /// Linux: descriptor table slots reserved at start, before the loop threads exist (capped
    /// at the soft `RLIMIT_NOFILE`). Growing the table once threads run stalls the thread that
    /// crosses each step (64, 128, 256...) for an RCU grace period, 10-30 ms on a VM. 0 skips
    /// it. Default 1024 (8 KiB of kernel memory).
    pub reserve_fds: usize,
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
            reserve_fds: 1024,
            linger: Duration::from_secs(2),
            linger_bytes: 256 * 1024,
            lazy_loops: false,
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
    pub(crate) timers: AtomicU64,
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
            timers: self.timers.load(r),
        }
    }
}

type Grow = Box<dyn FnOnce() + Send>;

pub(crate) struct Shared {
    pub(crate) stop: AtomicBool,
    pub(crate) grace_ns: AtomicU64,
    pub(crate) active: AtomicUsize,
    pub(crate) loop_active: Vec<AtomicUsize>,
    pub(crate) loops: Vec<LoopStats>,
    /// The loops that run, by index.
    handles: Mutex<Vec<LoopHandle>>,
    /// `handles.len()`, read without the lock.
    pub(crate) started: AtomicUsize,
    /// Lazy loops that failed to start.
    failed: AtomicUsize,
    /// Every thread to join: the loops, and the one that starts lazy loops.
    threads: Mutex<Vec<JoinHandle<()>>>,
    /// Starts the loops not started yet ([`Config::lazy_loops`]); taken once.
    grow: Mutex<Option<Grow>>,
    /// The lazy loops are being started (connections accepted meanwhile are parked).
    pub(crate) growing: AtomicBool,
    /// Lazy start: loop 0's back end once it has built its driver (or failed to).
    boot: Mutex<Option<(Backend, Option<String>)>>,
    /// The first loop that failed to start: why.
    error: Mutex<Option<io::Error>>,
    boot_cv: Condvar,
}

// Out of line: the poison handling, inlined at each of its many call sites, costs about 2 KB.
#[inline(never)]
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    /// A loop runs: it can take tasks and handed-off connections. A loop that registers after
    /// a stop began is woken, so it sees the stop at once.
    pub(crate) fn register(&self, h: LoopHandle) {
        let mut v = lock(&self.handles);
        // kept sorted by index (an insertion: a sort call costs about 6 KB of code)
        let at = v.iter().position(|l| l.index > h.index).unwrap_or(v.len());
        v.insert(at, h.clone());
        self.started.store(v.len(), Ordering::Release);
        if self.stop.load(Ordering::Acquire) {
            h.queue.waker.wake();
        }
        drop(v);
        // for the thread waiting until the lazy loops are up
        drop(lock(&self.boot));
        self.boot_cv.notify_all();
    }

    /// The running loops, by index.
    pub(crate) fn handles(&self) -> Vec<LoopHandle> {
        lock(&self.handles).clone()
    }

    fn booted(&self, b: (Backend, Option<String>)) {
        *lock(&self.boot) = Some(b);
        self.boot_cv.notify_all();
    }

    /// Lazy start: waits until loop 0 has built its driver.
    fn boot(&self) -> (Backend, Option<String>) {
        let mut g = lock(&self.boot);
        loop {
            if let Some(b) = &*g {
                return b.clone();
            }
            g = self.boot_cv.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Starts the remaining loops if they were held back (first call only).
    pub(crate) fn grow(&self) {
        let f = lock(&self.grow).take();
        if let Some(f) = f {
            self.growing.store(true, Ordering::Release);
            f();
        }
    }

    /// The lazy loops are up (or failed): wake the loops so they spread parked connections.
    fn grown(&self) {
        self.growing.store(false, Ordering::Release);
        for h in lock(&self.handles).iter() {
            h.queue.waker.wake();
        }
    }
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
    /// Timers scheduled on the loop now (connections' and endpoints').
    pub timers: u64,
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
            t.timers += l.timers;
        }
        t
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
        // UDP sockets are not lazy: SO_REUSEPORT spreads datagrams by hash over the sockets
        // bound, so adding one later would send an established QUIC connection's datagrams
        // to a loop that does not know it.
        cfg.lazy_loops &= self.udps.is_empty();
        let cpus = cfg.cpus.clone().unwrap_or_else(simoom_sys::cpu::allowed_cpus);
        // Lazy loops with the default count: the affinity mask now, and the cgroup CPU quota
        // (a few file reads, about 40 us) when the other loops start.
        let quota_later = cfg.lazy_loops && cfg.threads == 0 && cfg.cpus.is_none();
        let n = match (cfg.threads, &cfg.cpus) {
            (0, Some(_)) => cpus.len().max(1),
            (0, None) if quota_later => cpus.len().max(1),
            (0, None) => simoom_sys::cpu::cpu_count(),
            (t, _) => t,
        };
        cfg.threads = n;
        if cfg.write_low_water > cfg.write_high_water {
            cfg.write_low_water = cfg.write_high_water;
        }
        let per_loop = cfg!(target_os = "linux");
        // Grow the descriptor table now, while (usually) only this thread exists: growing it
        // later stalls the loop thread that crosses a step for an RCU grace period (measured
        // 18-28 ms on WSL2 at start with 12 loops and HTTP/3, and again at the first accepts).
        simoom_sys::net::reserve_descriptors(cfg.reserve_fds);

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
            handles: Mutex::new(Vec::with_capacity(n)),
            started: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
            threads: Mutex::new(Vec::with_capacity(n + 1)),
            grow: Mutex::new(None),
            growing: AtomicBool::new(false),
            boot: Mutex::new(None),
            error: Mutex::new(None),
            boot_cv: Condvar::new(),
        });
        let mut ocfg = cfg.offload.clone();
        if ocfg.name.is_empty() {
            ocfg.name = "simoom-offload".into();
        }
        let offload = OffloadPool::new(ocfg);
        let cfg = Arc::new(cfg);
        let mut setups: Vec<LoopSetup> = per_loop_listeners
            .into_iter()
            .zip(per_loop_udps)
            .enumerate()
            .map(|(i, (listeners, udps))| LoopSetup { index: i, cfg: cfg.clone(), shared: shared.clone(), offload: offload.clone(), listeners, udps })
            .collect();
        let pin_of = {
            let cpus = cpus.clone();
            let pin = cfg.pin_threads;
            move |i: usize| if pin && !cpus.is_empty() { Some(cpus[i % cpus.len()]) } else { None }
        };
        if cfg.lazy_loops {
            // Loop 0 now, without waiting for it: its listeners are bound, so connections
            // queue in the backlog until it runs (it reports its back end through `boot`). The
            // other loops start when three connections are open at once.
            let later = setups.split_off(1);
            let setup = setups.pop().expect("loop 0");
            let t = spawn_loop(&cfg, setup, pin_of(0), shared.clone())?;
            lock(&shared.threads).push(t);
            if !later.is_empty() {
                let cfg = cfg.clone();
                let weak = Arc::downgrade(&shared);
                *lock(&shared.grow) = Some(Box::new(move || {
                    // Called on the loop thread that saw the first connection: a helper creates
                    // the threads, so that loop goes on serving.
                    let w = weak.clone();
                    let helper = crate::spawn(std::thread::Builder::new().name(format!("{}-start", cfg.thread_name)), Box::new(move || {
                        let mut later = later;
                        if quota_later {
                            later.truncate(simoom_sys::cpu::cpu_count().saturating_sub(1));
                        }
                        let mut spawned = 0;
                        for setup in later {
                            let Some(shared) = w.upgrade() else { return };
                            if shared.stop.load(Ordering::Acquire) {
                                break;
                            }
                            let i = setup.index;
                            match spawn_loop(&cfg, setup, pin_of(i), shared.clone()) {
                                Ok(t) => {
                                    lock(&shared.threads).push(t);
                                    spawned += 1;
                                }
                                Err(e) => eprintln!("simoom loop {i} failed to start: {e}"),
                            }
                        }
                        // every loop registered (or failed): parked connections can be spread
                        if let Some(shared) = w.upgrade() {
                            let mut g = lock(&shared.boot);
                            while shared.started.load(Ordering::Acquire) + shared.failed.load(Ordering::Acquire) < 1 + spawned {
                                g = shared.boot_cv.wait(g).unwrap_or_else(PoisonError::into_inner);
                            }
                            drop(g);
                            shared.grown();
                        }
                    }));
                    match (helper, weak.upgrade()) {
                        (Ok(t), Some(shared)) => lock(&shared.threads).push(t),
                        (Err(e), Some(shared)) => {
                            eprintln!("simoom: the loops could not be started: {e}");
                            shared.grown();
                        }
                        _ => {}
                    }
                }));
            }
            return Ok(RuntimeHandle { shared, addrs, udp_addrs, offload, backend: OnceLock::new(), lazy: true });
        }
        let now = setups.len();

        // Every loop at once (the same thread body as a lazy start); wait until each has built
        // its driver and registered, or failed.
        for setup in setups {
            let i = setup.index;
            match spawn_loop(&cfg, setup, pin_of(i), shared.clone()) {
                Ok(t) => lock(&shared.threads).push(t),
                Err(e) => {
                    *lock(&shared.error) = Some(e);
                    break;
                }
            }
        }
        let mut g = lock(&shared.boot);
        let spawned = lock(&shared.threads).len();
        while shared.started.load(Ordering::Acquire) + shared.failed.load(Ordering::Acquire) < spawned {
            g = shared.boot_cv.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
        drop(g);
        let mut handle = RuntimeHandle { shared, addrs, udp_addrs, offload, backend: OnceLock::new(), lazy: false };
        if spawned < now || handle.shared.failed.load(Ordering::Acquire) != 0 {
            // A loop failed: stop the others (they serve nothing yet) and report its error.
            handle.stop(Duration::ZERO);
            handle.join_threads();
            let e = lock(&handle.shared.error).take();
            return Err(e.unwrap_or_else(|| io::Error::other("a loop thread died during start")));
        }
        Ok(handle)
    }
}

/// Counts a loop thread as failed unless it registered (also when `build` panics), so a start
/// waiting for the loops never hangs.
struct Starting {
    shared: Arc<Shared>,
    done: bool,
}

impl Drop for Starting {
    fn drop(&mut self) {
        if !self.done {
            self.shared.failed.fetch_add(1, Ordering::AcqRel);
            drop(lock(&self.shared.boot));
            self.shared.boot_cv.notify_all();
        }
    }
}

/// Starts a loop thread: it builds its driver and registers itself. A failure is counted in
/// `failed` and kept in `error`; with a lazy start it is logged too (nothing waits for it).
fn spawn_loop(cfg: &Config, setup: LoopSetup, pin: Option<usize>, shared: Arc<Shared>) -> io::Result<JoinHandle<()>> {
    let i = setup.index;
    let log = cfg.lazy_loops;
    crate::spawn(loop_thread(cfg, i), Box::new(move || {
        if let Some(cpu) = pin {
            let _ = simoom_sys::cpu::pin_current_thread(cpu);
        }
        let mut starting = Starting { shared, done: false };
        let shared = &starting.shared;
        let (mut core, queue) = match build(setup) {
            Ok(x) => x,
            Err(e) => {
                if log {
                    eprintln!("simoom loop {i} failed to start: {e}");
                }
                if i == 0 {
                    shared.booted((Backend::Auto, Some(format!("loop 0 failed to start: {e}"))));
                }
                lock(&shared.error).get_or_insert(e);
                return;
            }
        };
        if i == 0 {
            shared.booted(core.backend());
        }
        shared.register(LoopHandle { index: i, queue });
        starting.done = true;
        drop(starting);
        if let Err(e) = core.run() {
            eprintln!("simoom loop {i} failed: {e}");
        }
    }))
}

fn loop_thread(cfg: &Config, i: usize) -> std::thread::Builder {
    let tb = std::thread::Builder::new().name(format!("{}-{i}", cfg.thread_name));
    match cfg.stack_size {
        Some(sz) => tb.stack_size(sz),
        None => tb,
    }
}

/// A running runtime. Dropping it stops the runtime at once (no grace) and waits for its
/// threads; call [`RuntimeHandle::stop`] and [`RuntimeHandle::join`] for a graceful stop.
pub struct RuntimeHandle {
    shared: Arc<Shared>,
    addrs: Vec<SocketAddr>,
    udp_addrs: Vec<SocketAddr>,
    offload: OffloadPool,
    /// The back end and the fallback reason; with a lazy start, filled on first ask.
    backend: OnceLock<(Backend, Option<String>)>,
    lazy: bool,
}

impl std::fmt::Debug for RuntimeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeHandle").field("loops", &self.shared.started.load(Ordering::Relaxed)).field("addrs", &self.addrs).field("lazy", &self.lazy).finish()
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

    /// The loops that run, by index, to run tasks on them. With [`Config::lazy_loops`] that is
    /// loop 0 until three connections were open at once, then each loop as it starts.
    pub fn loops(&self) -> Vec<LoopHandle> {
        self.shared.handles()
    }

    fn boot(&self) -> &(Backend, Option<String>) {
        self.backend.get_or_init(|| self.shared.boot())
    }

    /// The back end the loops use. With [`Config::lazy_loops`] it waits until loop 0 has
    /// built its driver (well under a millisecond after [`Builder::start`]).
    pub fn backend(&self) -> Backend {
        self.boot().0
    }

    /// Why the configured back end was replaced (io_uring falling back to epoll), if it was.
    pub fn fallback_reason(&self) -> Option<&str> {
        self.boot().1.as_deref()
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
    /// Loops held back by [`Config::lazy_loops`] are not started any more.
    pub fn stop(&self, grace: Duration) {
        self.shared.grace_ns.store(grace.as_nanos().min(u64::MAX as u128) as u64, Ordering::Release);
        self.shared.stop.store(true, Ordering::Release);
        // closes the sockets of loops never started
        drop(lock(&self.shared.grow).take());
        for l in lock(&self.shared.handles).iter() {
            l.queue.waker.wake();
        }
    }

    /// Waits for every loop to exit (after [`RuntimeHandle::stop`]), then stops the offload
    /// pool.
    pub fn join(mut self) {
        self.join_threads();
    }

    fn join_threads(&mut self) {
        // The helper that starts lazy loops adds their threads while it runs: pop until empty.
        loop {
            let t = lock(&self.shared.threads).pop();
            match t {
                Some(t) => {
                    let _ = t.join();
                }
                None => break,
            }
        }
        self.offload.shutdown(Duration::from_secs(5));
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        let running = !lock(&self.shared.threads).is_empty();
        if running {
            if !self.shared.stop.load(Ordering::Acquire) {
                self.stop(Duration::ZERO);
            }
            self.join_threads();
        }
    }
}
