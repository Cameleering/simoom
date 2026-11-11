//! A completion-style I/O driver, one per event-loop thread.
//!
//! The model is the one io_uring and IOCP provide natively, and that epoll and kqueue emulate
//! inside [`Driver::turn`] with readiness events plus non-blocking calls:
//!
//! - **Receive** into buffers the driver owns. The caller hands buffers to the driver with
//!   [`Driver::provide`]; the driver takes one only when data has actually arrived (io_uring's
//!   provided-buffer ring, a read after readiness on epoll and kqueue, a read after a zero-byte
//!   `WSARecv` on IOCP). So **an idle connection holds no buffer**. Data comes back as
//!   [`Event::Data`] carrying the filled `Vec<u8>`; the caller owns it from then on.
//! - **Send** owned buffers with [`Driver::send`]. Sends on one connection go out in order and
//!   are batched: everything queued during a turn is written at the start of the next
//!   [`Driver::turn`], with one vectored call (or one submission) per connection. Each buffer
//!   comes back as [`Event::Sent`] once written, so it can be reused.
//! - **Accept** on listeners registered with [`Driver::listen`]: [`Event::Accepted`] carries the
//!   new non-blocking socket, which the caller registers with [`Driver::stream`] (possibly on
//!   another loop's driver).
//! - **Close** with [`Driver::close`]: the driver cancels what is in flight, returns every
//!   buffer, closes the socket and reports [`Event::Closed`]; only then may the caller reuse the
//!   key.
//! - **Wake** a driver blocked in [`Driver::turn`] from any thread with a [`Waker`].
//!
//! The driver never calls back into user code: [`Driver::turn`] appends [`Event`]s to a vector.

use crate::net::Socket;
use crate::udp::{RecvMeta, Transmit};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios", target_os = "freebsd"))]
mod readiness;

#[cfg(target_os = "linux")]
mod epoll;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod uring;

#[cfg(windows)]
mod iocp;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
mod kqueue;

/// Which I/O back end a driver uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Pick for this OS: epoll on Linux (io_uring when `SIMOOM_BACKEND=io_uring` is set), IOCP
    /// on Windows, kqueue on macOS and BSD.
    Auto,
    /// Linux epoll, edge-triggered.
    Epoll,
    /// Linux io_uring (6.1+). Falls back to epoll when the kernel refuses it.
    IoUring,
    /// Windows I/O completion ports.
    Iocp,
    /// macOS and BSD kqueue.
    Kqueue,
}

impl Backend {
    /// The back end `Auto` resolves to on this OS, honouring `SIMOOM_BACKEND`
    /// (`epoll`, `io_uring`/`uring`, `iocp`, `kqueue`).
    pub fn resolve(self) -> Backend {
        if self != Backend::Auto {
            return self;
        }
        match env_bytes("SIMOOM_BACKEND").as_deref() {
            Some(b"epoll") => return Backend::Epoll,
            Some(b"io_uring") | Some(b"uring") => return Backend::IoUring,
            Some(b"iocp") => return Backend::Iocp,
            Some(b"kqueue") => return Backend::Kqueue,
            _ => {}
        }
        if cfg!(windows) {
            Backend::Iocp
        } else if cfg!(target_os = "linux") {
            Backend::Epoll
        } else {
            Backend::Kqueue
        }
    }

    /// A short lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            Backend::Auto => "auto",
            Backend::Epoll => "epoll",
            Backend::IoUring => "io_uring",
            Backend::Iocp => "iocp",
            Backend::Kqueue => "kqueue",
        }
    }
}

/// Driver settings. The defaults suit a server loop.
#[derive(Clone, Debug)]
pub struct DriverConfig {
    /// Which back end to use.
    pub backend: Backend,
    /// Most OS events taken per wait (epoll and kqueue events, IOCP entries). The array starts
    /// at 64 entries and doubles, up to this, whenever a wait fills it, so a busy loop drains
    /// every ready event in one call and an idle one keeps a small array.
    pub events: usize,
    /// Most receives per connection per turn before others get a go (epoll, kqueue, IOCP).
    pub recv_budget: usize,
    /// io_uring: submission queue entries (the completion queue is four times larger).
    pub uring_entries: u32,
    /// io_uring: entries of the provided-buffer ring (a power of two, at most 32768).
    pub uring_buffers: u16,
    /// io_uring: use registered (fixed) file descriptors for connections.
    pub uring_fixed_files: bool,
    /// io_uring: size of the fixed file table (connections per loop that can use it; others
    /// use plain descriptors).
    pub uring_max_files: u32,
    /// io_uring: pretend `io_uring_setup` failed with this errno, to test the fallback. The
    /// environment variable `SIMOOM_IO_URING_FAIL=<errno>` does the same.
    pub uring_simulate_failure: Option<i32>,
    /// IOCP: post receives with a buffer instead of the zero-byte idiom: one system call per
    /// receive instead of two, but every connection waiting for data holds a receive buffer.
    /// Off by default.
    pub iocp_eager_recv: bool,
    /// IOCP: `AcceptEx` calls kept outstanding per listener.
    pub accepts_outstanding: usize,
    /// UDP: receives kept outstanding per socket on IOCP.
    pub udp_recvs_outstanding: usize,
    /// Adaptive busy polling: after a turn that delivered events, the driver may poll without
    /// blocking for up to this long before it sleeps, saving a sleep and a wake-up when the next
    /// event comes within a few microseconds. It spins only while events have been arriving
    /// sooner than a quarter of this window after busy turns (measured by an occasional probe
    /// spin), so at moderate load it sleeps exactly as without busy polling and costs no CPU per
    /// request; an idle loop never spins. `Duration::ZERO` turns it off. The environment variable
    /// `SIMOOM_BUSY_POLL_US` overrides it. Default 30 µs.
    pub busy_poll: Duration,
}

impl Default for DriverConfig {
    fn default() -> Self {
        DriverConfig {
            backend: Backend::Auto,
            events: 1024,
            recv_budget: 16,
            uring_entries: 1024,
            uring_buffers: 1024,
            uring_fixed_files: true,
            uring_max_files: 16384,
            uring_simulate_failure: None,
            iocp_eager_recv: false,
            accepts_outstanding: 32,
            udp_recvs_outstanding: 4,
            busy_poll: Duration::from_micros(30),
        }
    }
}

/// A handle to a socket registered with a [`Driver`]. Stale handles (after the socket was
/// closed) are detected by a generation count and ignored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(pub(crate) u64);

impl Id {
    pub(crate) fn new(idx: u32, gen: u32) -> Id {
        Id(idx as u64 | (gen as u64) << 32)
    }
    pub(crate) fn idx(self) -> u32 {
        self.0 as u32
    }
    pub(crate) fn gen(self) -> u32 {
        (self.0 >> 32) as u32
    }
    /// The raw value (for logging).
    pub fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({}#{})", self.idx(), self.gen())
    }
}

/// A buffer to send: owned (returned by [`Event::Sent`] for reuse) or static.
#[derive(Debug)]
pub enum OutBuf {
    /// An owned buffer; all of `len()` bytes are sent.
    Owned(Vec<u8>),
    /// Static bytes, such as a fixed reply.
    Static(&'static [u8]),
}

impl OutBuf {
    /// The bytes to send.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            OutBuf::Owned(v) => v,
            OutBuf::Static(s) => s,
        }
    }
    /// Length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
    /// Whether it is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Something that happened, reported by [`Driver::turn`].
#[derive(Debug)]
pub enum Event {
    /// A listener accepted a connection. The socket is non-blocking and not yet registered.
    Accepted { key: u64, socket: Socket, peer: Option<SocketAddr> },
    /// Bytes arrived on a stream: `buf[..]` holds them (`buf.len()` > 0).
    Data { key: u64, buf: Vec<u8> },
    /// The peer closed its sending side. Receiving stops; sending may continue.
    Eof { key: u64 },
    /// A receive, send or accept failed. The connection should be closed.
    Error { key: u64, error: io::Error },
    /// A buffer was written completely (or discarded because the connection failed or closed).
    Sent { key: u64, buf: OutBuf },
    /// A datagram (or a GRO batch) arrived on a UDP socket.
    Datagram { key: u64, buf: Vec<u8>, meta: RecvMeta },
    /// A socket given to [`Driver::close`] is closed and the driver holds nothing of it.
    Closed { key: u64 },
    /// A [`Waker`] was triggered.
    Wake,
}

/// System calls and events counted by a driver (plain counters; read them on the loop thread).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverStats {
    /// Waits: `epoll_wait`, `kevent`, `io_uring_enter`, `GetQueuedCompletionStatusEx`.
    pub waits: u64,
    /// Receive calls: `recv`, `recvmmsg`, `WSARecv`/`WSARecvMsg` (io_uring: none, completions only).
    pub recv_calls: u64,
    /// Send calls: `sendmsg`/`send`, `WSASend` (io_uring: none, submissions only).
    pub send_calls: u64,
    /// Accept calls: `accept4`, `AcceptEx`.
    pub accept_calls: u64,
    /// Other system calls: registration, `epoll_ctl`, eventfd reads, `io_uring_register`, ...
    pub other_calls: u64,
    /// io_uring submission queue entries pushed (buffer hand-overs with `PROVIDE_BUFFERS` not
    /// counted).
    pub sqes: u64,
    /// Completions or readiness events taken from the OS.
    pub os_events: u64,
    /// Waits that blocked (put the thread to sleep, or could have: a non-zero timeout).
    pub sleeps: u64,
    /// Non-blocking polls made while busy polling (also counted in `waits` when they were system
    /// calls; io_uring polls its rings in user space and enters only when work is flagged).
    pub spin_polls: u64,
}

impl DriverStats {
    /// All counted system calls.
    pub fn syscalls(&self) -> u64 {
        self.waits + self.recv_calls + self.send_calls + self.accept_calls + self.other_calls
    }
}

// ---------------------------------------------------------------------------------------------
// Adaptive busy polling
// ---------------------------------------------------------------------------------------------

/// Entries of an event array before it grows (see [`DriverConfig::events`]).
pub(crate) const EVENTS_START: usize = 64;

/// Most turns in a row that report results without asking the OS for new events.
pub(crate) const MAX_SKIPS: u8 = 3;

/// Busy waits between probe spins while the loop sleeps (see [`Spin`]).
const PROBE_EVERY: u8 = 64;

/// Busy polling of one driver (see [`DriverConfig::busy_poll`]).
///
/// Spinning costs the CPU time until the next event; sleeping costs a sleep and a wake-up (a
/// few microseconds of kernel and scheduler work, more in a VM). So the driver spins only while
/// the next event comes sooner than about one sleep and wake-up: it keeps `gap`, a smoothed time
/// from the end of a busy turn to the next event, and spins while it is under a quarter of the
/// window. The gap is measured only by spinning (a sleep's length includes the wake-up delay, so
/// it would overstate it): while the loop sleeps, every [`PROBE_EVERY`]th busy wait spins once
/// for the whole window to sample it. A spin that finds nothing counts as a long gap, so when
/// load drops the loop goes back to sleeping at once. At moderate load (tens of microseconds
/// between requests per loop) it sleeps, as without busy polling; on chatty connections with
/// short round trips and near saturation it spins and saves the wake-ups. An idle loop never
/// spins.
pub(crate) struct Spin {
    max: u64,
    /// Smoothed time to the next event after a busy turn, in nanoseconds (spins only).
    gap: u64,
    /// Busy waits since the last probe spin.
    probe: u8,
    /// The last turn delivered events: the loop is busy, so spinning may be worth it.
    pub(crate) worked: bool,
}

/// An environment variable's bytes (`std::env::var` and its UTF-8 check cost more code).
#[inline(never)]
pub(crate) fn env_bytes(name: &str) -> Option<Vec<u8>> {
    std::env::var_os(name).map(|v| v.into_encoded_bytes())
}

/// An environment variable holding a decimal number; `None` if unset or not a number.
pub(crate) fn env_u64(name: &str) -> Option<u64> {
    let v = env_bytes(name)?;
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(v.iter().fold(0, |n, &d| n * 10 + u64::from(d - b'0')))
}

impl Spin {
    pub(crate) fn new(cfg: &DriverConfig) -> Spin {
        let max = env_u64("SIMOOM_BUSY_POLL_US").map_or(cfg.busy_poll.as_nanos().min(u64::MAX as u128) as u64, |us| us.saturating_mul(1000));
        Spin { max, gap: max, probe: 0, worked: false }
    }

    /// Whether events come soon enough after busy turns to spin for them.
    fn spins(&self) -> bool {
        self.worked && self.max > 0 && self.gap <= self.max / 4
    }

    /// Folds one observed time-to-event into the smoothed gap (weight 1/4).
    fn record(&mut self, ns: u64) {
        let ns = ns.min(4 * self.max);
        self.gap = self.gap - self.gap / 4 + ns / 4;
    }

    /// Waits for events with `poll`, which waits up to the given timeout (zero: does not block)
    /// and returns whether it found anything. Spins first when [`Spin::spins`] or a probe is
    /// due; `syscall_polls` paces polls that are system calls to one a microsecond.
    ///
    /// `w` is the driver's waker: work [`Waker::post`]ed meanwhile ends a spin, and the driver
    /// announces that it parks in the OS before it blocks, so that a post wakes it only then.
    // One copy for every back end (K9): `poll` is a trait object, its cost is nothing next to
    // the system call it makes.
    #[inline(never)]
    pub(crate) fn wait(&mut self, timeout: Option<Duration>, syscall_polls: bool, stats: &mut DriverStats, w: &WakerInner, poll: &mut dyn FnMut(Option<Duration>, &mut DriverStats) -> io::Result<bool>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return poll(timeout, stats).map(drop);
        }
        let mut spin = self.spins();
        if !spin && self.worked && self.max > 0 {
            self.probe += 1;
            if self.probe >= PROBE_EVERY {
                self.probe = 0;
                spin = true;
            }
        }
        let mut spun = 0;
        if spin {
            let limit = timeout.map_or(u64::MAX, |t| t.as_nanos().min(u64::MAX as u128) as u64);
            let window = self.max.min(limit);
            let t0 = crate::time::now_ns();
            let mut last = 0;
            loop {
                let now = crate::time::now_ns() - t0;
                if w.posted.load(Ordering::Relaxed) {
                    // A message for the loop (no system call on either side). Not counted as
                    // a short gap: replies from worker threads must not keep the loop
                    // spinning, or it takes the CPU those threads need (K3).
                    return Ok(());
                }
                if !syscall_polls || now - last >= 1_000 || last == 0 {
                    last = now.max(1);
                    stats.spin_polls += 1;
                    if poll(Some(Duration::ZERO), stats)? {
                        self.record(crate::time::now_ns() - t0);
                        return Ok(());
                    }
                }
                if now >= window {
                    spun = now;
                    break;
                }
                core::hint::spin_loop();
            }
            if window == self.max {
                self.record(u64::MAX); // nothing within the whole window
            }
        }
        let rest = timeout.map(|t| t.saturating_sub(Duration::from_nanos(spun)));
        // Announce the park, then look for posted work once more: with both sides sequentially
        // consistent, either this sees the post or the poster sees the park and signals.
        w.parked.store(true, Ordering::SeqCst);
        if w.posted.load(Ordering::SeqCst) {
            w.parked.store(false, Ordering::Relaxed);
            return poll(Some(Duration::ZERO), stats).map(drop);
        }
        stats.sleeps += 1;
        let r = poll(rest, stats);
        w.parked.store(false, Ordering::Relaxed);
        r.map(drop)
    }
}

// ---------------------------------------------------------------------------------------------
// Waker
// ---------------------------------------------------------------------------------------------

/// Wakes a driver blocked in [`Driver::turn`] from any thread. Cheap to clone; repeated wakes
/// before the driver runs collapse into one OS signal.
#[derive(Clone)]
pub struct Waker {
    pub(crate) inner: Arc<WakerInner>,
}

pub(crate) struct WakerInner {
    pub(crate) pending: AtomicBool,
    pub(crate) signal: Box<dyn Fn() + Send + Sync>,
    /// Work was [`Waker::post`]ed since the driver last reported it.
    pub(crate) posted: AtomicBool,
    /// The driver is blocked in the OS, or about to be (set by [`Spin::wait`]).
    pub(crate) parked: AtomicBool,
}

impl Waker {
    pub(crate) fn new(signal: Box<dyn Fn() + Send + Sync>) -> Waker {
        Waker { inner: Arc::new(WakerInner { pending: AtomicBool::new(false), signal, posted: AtomicBool::new(false), parked: AtomicBool::new(false) }) }
    }

    /// Makes the driver's current or next [`Driver::turn`] return [`Event::Wake`].
    pub fn wake(&self) {
        if !self.inner.pending.swap(true, Ordering::AcqRel) {
            (self.inner.signal)();
        }
    }

    /// Like [`Waker::wake`], for work the caller has just queued for the driver's thread (with
    /// a sequentially consistent push, such as [`crate::mpsc::Mpsc::push`]): the current or next
    /// [`Driver::turn`] returns [`Event::Wake`], but the OS is signalled only when the driver is
    /// parked in it. A driver that is running, or spinning in its busy poll, picks the work up
    /// without a system call on either side, and posts that arrive together cost one signal.
    pub fn post(&self) {
        let i = &*self.inner;
        // Sequentially consistent against the driver's park announcement and re-check in
        // `Spin::wait`: either the driver sees `posted`, or this sees `parked` and signals
        // (`wake` signals once however many posters see it).
        i.posted.store(true, Ordering::SeqCst);
        if i.parked.load(Ordering::SeqCst) {
            self.wake();
        }
    }

    /// Whether work was posted since the driver last reported it (and clears that).
    pub(crate) fn take_posted(&self) -> bool {
        self.inner.posted.load(Ordering::Relaxed) && self.inner.posted.swap(false, Ordering::AcqRel)
    }

    /// Called by the driver when it reports the wake, before the caller looks at its queues.
    pub(crate) fn clear(&self) {
        self.inner.pending.store(false, Ordering::Release);
    }
}

impl fmt::Debug for Waker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waker").field("pending", &self.inner.pending.load(Ordering::Relaxed)).finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Slab with generations
// ---------------------------------------------------------------------------------------------

pub(crate) struct Slab<T> {
    slots: Vec<(u32, Option<T>)>,
    free: Vec<u32>,
    len: usize,
}

impl<T> Slab<T> {
    pub(crate) fn new() -> Slab<T> {
        Slab { slots: Vec::new(), free: Vec::new(), len: 0 }
    }
    pub(crate) fn insert(&mut self, v: T) -> Id {
        self.len += 1;
        if let Some(i) = self.free.pop() {
            let s = &mut self.slots[i as usize];
            s.1 = Some(v);
            Id::new(i, s.0)
        } else {
            self.slots.push((0, Some(v)));
            Id::new(self.slots.len() as u32 - 1, 0)
        }
    }
    pub(crate) fn get(&self, id: Id) -> Option<&T> {
        match self.slots.get(id.idx() as usize) {
            Some((g, Some(v))) if *g == id.gen() => Some(v),
            _ => None,
        }
    }
    pub(crate) fn get_mut(&mut self, id: Id) -> Option<&mut T> {
        match self.slots.get_mut(id.idx() as usize) {
            Some((g, Some(v))) if *g == id.gen() => Some(v),
            _ => None,
        }
    }
    #[cfg_attr(not(all(target_os = "linux", feature = "io-uring")), allow(dead_code))]
    pub(crate) fn id_at(&self, idx: u32) -> Option<Id> {
        match self.slots.get(idx as usize) {
            Some((g, Some(_))) => Some(Id::new(idx, *g)),
            _ => None,
        }
    }
    pub(crate) fn remove(&mut self, id: Id) -> Option<T> {
        let s = self.slots.get_mut(id.idx() as usize)?;
        if s.0 != id.gen() || s.1.is_none() {
            return None;
        }
        s.0 = s.0.wrapping_add(1);
        self.free.push(id.idx());
        self.len -= 1;
        s.1.take()
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn ids(&self) -> Vec<Id> {
        self.slots.iter().enumerate().filter(|(_, s)| s.1.is_some()).map(|(i, s)| Id::new(i as u32, s.0)).collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Large UDP receive buffers (GRO)
// ---------------------------------------------------------------------------------------------

/// Receive buffers per batched receive call on a GRO socket. Each holds up to 64 datagrams of
/// one peer, so a batch takes up to 512 datagrams (and 512 KiB of buffers).
pub(crate) const LARGE_BATCH: usize = 8;

/// The driver's own stock of large buffers for UDP sockets registered with [`Driver::udp_large`]:
/// allocated on first use, given back through [`Driver::provide`], at most two batches kept.
#[derive(Default)]
pub(crate) struct LargeBufs {
    pub(crate) size: usize,
    free: Vec<Vec<u8>>,
}

impl LargeBufs {
    /// A cleared buffer of at least `size` bytes.
    #[inline(never)]
    pub(crate) fn take(&mut self) -> Vec<u8> {
        self.free.pop().unwrap_or_else(|| Vec::with_capacity(self.size))
    }

    /// Takes `buf` back if it is a large buffer (`None`), else hands it back. The check is
    /// inlined; keeping the buffer (GRO sockets only) is not.
    #[inline]
    pub(crate) fn keep(&mut self, buf: Vec<u8>) -> Option<Vec<u8>> {
        if !cfg!(feature = "udp") || self.size == 0 || buf.capacity() < self.size {
            return Some(buf);
        }
        self.store(buf);
        None
    }

    #[inline(never)]
    fn store(&mut self, mut buf: Vec<u8>) {
        if self.free.len() < 2 * LARGE_BATCH {
            buf.clear();
            self.free.push(buf);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------------------------

enum Imp {
    #[cfg(target_os = "linux")]
    Epoll(readiness::Driver<epoll::Poller>),
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    Uring(uring::Driver),
    #[cfg(windows)]
    Iocp(iocp::Driver),
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    Kqueue(readiness::Driver<kqueue::Poller>),
}

macro_rules! dispatch {
    ($self:expr, $d:ident => $e:expr) => {
        match &mut $self.imp {
            #[cfg(target_os = "linux")]
            Imp::Epoll($d) => $e,
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Imp::Uring($d) => $e,
            #[cfg(windows)]
            Imp::Iocp($d) => $e,
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            Imp::Kqueue($d) => $e,
        }
    };
}

macro_rules! dispatch_ref {
    ($self:expr, $d:ident => $e:expr) => {
        match &$self.imp {
            #[cfg(target_os = "linux")]
            Imp::Epoll($d) => $e,
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Imp::Uring($d) => $e,
            #[cfg(windows)]
            Imp::Iocp($d) => $e,
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            Imp::Kqueue($d) => $e,
        }
    };
}

/// A completion-style I/O driver for one thread. See the [module docs](self).
///
/// A driver is not `Send`: create it on the thread that runs it (io_uring's single-issuer mode
/// requires that). Its [`Waker`] is `Send + Sync`.
pub struct Driver {
    imp: Imp,
    kind: Backend,
    fallback: Option<String>,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl fmt::Debug for Driver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Driver").field("backend", &self.kind).field("fallback", &self.fallback).finish()
    }
}

impl Driver {
    /// Creates a driver. With [`Backend::IoUring`] it probes the kernel and falls back to epoll
    /// when io_uring is missing, disabled or too old ([`Driver::fallback_reason`] says why).
    /// Asking for a back end this OS doesn't have is an `Unsupported` error.
    pub fn new(cfg: &DriverConfig) -> io::Result<Driver> {
        let want = cfg.backend.resolve();
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut fallback = None;
        // io_uring, or why it fell back to epoll: the epoll driver is built in one place below
        // (it is inlined into the loop thread's start, so a second copy would cost its code twice).
        #[cfg(target_os = "linux")]
        if want == Backend::IoUring {
            #[cfg(feature = "io-uring")]
            match uring::Driver::new(cfg) {
                Ok(d) => {
                    let fallback = d.degraded();
                    return Ok(Driver { imp: Imp::Uring(d), kind: Backend::IoUring, fallback, _not_send: core::marker::PhantomData });
                }
                Err(e) => fallback = Some(uring_unavailable(&e)),
            }
            #[cfg(not(feature = "io-uring"))]
            {
                fallback = Some("io_uring unavailable (built without the `io-uring` feature); using epoll".into());
            }
        }
        let (imp, kind) = match want {
            #[cfg(target_os = "linux")]
            Backend::Epoll | Backend::IoUring => (Imp::Epoll(readiness::Driver::new(cfg)?), Backend::Epoll),
            #[cfg(windows)]
            Backend::Iocp => (Imp::Iocp(iocp::Driver::new(cfg)?), Backend::Iocp),
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            Backend::Kqueue => (Imp::Kqueue(readiness::Driver::new(cfg)?), Backend::Kqueue),
            other => return Err(unsupported_backend(other)),
        };
        Ok(Driver { imp, kind, fallback, _not_send: core::marker::PhantomData })
    }

    /// The back end in use.
    pub fn backend(&self) -> Backend {
        self.kind
    }

    /// Why the requested back end was replaced, if it was, or which of its optional features
    /// the kernel lacks (io_uring set-up flags or registered files, each dropped on its own).
    pub fn fallback_reason(&self) -> Option<&str> {
        self.fallback.as_deref()
    }

    /// A handle that wakes this driver from any thread.
    pub fn waker(&self) -> Waker {
        dispatch_ref!(self, d => d.waker())
    }

    /// Registers a listening socket and starts accepting on it. Accepted connections arrive as
    /// [`Event::Accepted`] with `key`.
    pub fn listen(&mut self, socket: Socket, key: u64) -> io::Result<Id> {
        dispatch!(self, d => d.listen(socket, key))
    }

    /// Registers a connected, non-blocking stream socket. Nothing is received until
    /// [`Driver::recv`] turns receiving on.
    pub fn stream(&mut self, socket: Socket, key: u64) -> io::Result<Id> {
        dispatch!(self, d => d.stream(socket, key))
    }

    /// Registers a bound UDP socket. Datagrams arrive as [`Event::Datagram`] once
    /// [`Driver::recv`] turns receiving on.
    pub fn udp(&mut self, socket: Socket, key: u64) -> io::Result<Id> {
        dispatch!(self, d => d.udp(socket, key))
    }

    /// Registers a bound UDP socket that receives into `buf_size`-byte buffers of the driver's own
    /// (instead of the stock given with [`Driver::provide`]), for a socket with GRO on: a buffer
    /// then takes a whole batch of datagrams (up to 64 KiB, cut by
    /// [`RecvMeta::segment_size`]). Give the buffers of its [`Event::Datagram`]s back with
    /// [`Driver::provide`]; the driver keeps a few for reuse.
    pub fn udp_large(&mut self, socket: Socket, key: u64, buf_size: usize) -> io::Result<Id> {
        dispatch!(self, d => d.udp_large(socket, key, buf_size))
    }

    /// Turns receiving on or off for a stream or UDP socket. Turning it off is backpressure: the
    /// driver stops taking data, so the kernel's receive window closes. A few `Data` events
    /// already under way may still arrive after it is turned off.
    pub fn recv(&mut self, id: Id, on: bool) {
        dispatch!(self, d => d.recv(id, on))
    }

    /// Queues a buffer to send on a stream. It is written at the start of the next turn, after
    /// everything queued before it.
    pub fn send(&mut self, id: Id, buf: OutBuf) {
        dispatch!(self, d => d.send(id, buf))
    }

    /// Sends datagrams on a UDP socket at once, without queueing. Returns how many were handed
    /// to the kernel; `WouldBlock` means the socket buffer is full and nothing was sent.
    pub fn send_to(&mut self, id: Id, msgs: &[Transmit<'_>]) -> io::Result<usize> {
        dispatch!(self, d => d.send_to(id, msgs))
    }

    /// Closes a socket. Queued and in-flight sends are discarded (their buffers come back as
    /// [`Event::Sent`]), then [`Event::Closed`] is reported. Flush first for a graceful close.
    pub fn close(&mut self, id: Id) {
        dispatch!(self, d => d.close(id))
    }

    /// The socket behind `id`, for addresses and options.
    pub fn socket(&self, id: Id) -> Option<&Socket> {
        dispatch_ref!(self, d => d.socket(id))
    }

    /// Gives the driver a receive buffer (an empty `Vec` with spare capacity). The driver keeps
    /// it until data arrives and then hands it back in an event. A buffer of the size given to
    /// [`Driver::udp_large`] goes back to the large stock.
    pub fn provide(&mut self, buf: Vec<u8>) {
        dispatch!(self, d => d.provide(buf))
    }

    /// How many more receive buffers the driver would like (to reach its target stock).
    pub fn buffers_wanted(&self) -> usize {
        dispatch_ref!(self, d => d.buffers_wanted())
    }

    /// Sets how many receive buffers the driver keeps in stock (io_uring: at most the ring size).
    pub fn set_buffer_target(&mut self, n: usize) {
        dispatch!(self, d => d.set_buffer_target(n))
    }

    /// Writes a stream's queued output now, where that costs no extra system call (epoll and
    /// kqueue write each socket with its own call anyway; io_uring batches its submissions and
    /// IOCP posts them, so there this does nothing). The results come with the next turn (K4).
    pub fn flush_now(&mut self, id: Id) {
        match &mut self.imp {
            #[cfg(target_os = "linux")]
            Imp::Epoll(d) => d.flush_now(id),
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            Imp::Kqueue(d) => d.flush_now(id),
            #[allow(unreachable_patterns)]
            _ => {
                let _ = id;
            }
        }
    }

    /// Frees spare receive buffers down to `keep` and lets the stock grow again from small
    /// (an idle loop after a burst; buffers lent to an io_uring ring stay).
    pub fn trim_buffers(&mut self, keep: usize) {
        dispatch!(self, d => d.trim_buffers(keep))
    }

    /// Flushes queued sends, waits for I/O up to `timeout` (`None` waits until something happens
    /// or a [`Waker`] fires; zero only polls) and appends what happened to `out`. Returns at once
    /// when events are already pending.
    pub fn turn(&mut self, timeout: Option<Duration>, out: &mut Vec<Event>) -> io::Result<()> {
        dispatch!(self, d => d.turn(timeout, out))?;
        if dispatch_ref!(self, d => d.waker.take_posted()) {
            out.push(Event::Wake);
        }
        Ok(())
    }

    /// System call and event counters.
    pub fn stats(&self) -> DriverStats {
        dispatch_ref!(self, d => d.stats())
    }

    /// Registered sockets (listeners, streams and UDP sockets, including ones closing).
    pub fn len(&self) -> usize {
        dispatch_ref!(self, d => d.len())
    }

    /// Whether no socket is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[cold]
#[inline(never)]
fn uring_unavailable(e: &io::Error) -> String {
    format!("io_uring unavailable ({e}); using epoll")
}

#[cold]
#[inline(never)]
fn unsupported_backend(b: Backend) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("the {} back end is not available on this OS", b.name()))
}

/// Converts an optional timeout to milliseconds for epoll and IOCP, rounding up so a timer
/// never fires early (`-1` / `INFINITE` for none).
#[allow(dead_code)]
pub(crate) fn timeout_ms(t: Option<Duration>) -> i32 {
    match t {
        None => -1,
        Some(d) => {
            let ms = d.as_nanos().div_ceil(1_000_000);
            ms.min(i32::MAX as u128) as i32
        }
    }
}

#[cfg(test)]
mod tests;
