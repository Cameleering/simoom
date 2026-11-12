//! One event loop: its driver, buffer pool, timer wheel, connections and task queue, and the
//! contexts handed to handlers.

// Without the `udp` feature the UDP slots stay empty and their code is left out.
#![cfg_attr(not(feature = "udp"), allow(dead_code, unused_imports, unused_mut))]

use crate::handler::{Acceptor, CloseReason, ConnInfo, Connection, Endpoint, Message, UdpInfo, UdpService};
use crate::offload::{OffloadPool, Rejected};
use crate::pool::BufPool;
use crate::runtime::{Config, Shared};
use crate::timer::{TimerId, TimerWheel};
use simoom_sys::driver::{Driver, Event, Id, OutBuf, Waker};
use simoom_sys::net::Socket;
use simoom_sys::udp::Transmit;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const LISTENER_BIT: u64 = 1 << 63;
/// Receive buffers lent to the driver before the loop's first connection.
const INITIAL_RECV_BUFFERS: usize = 8;
/// Unconsumed input up to this size is kept in its own exact-size allocation rather than in a
/// pooled receive buffer ([`Core::call_data`]).
const COMPACT_INPUT: usize = 512;
/// How long loop 0 balances its accepts after the lazy loops started.
const BALANCE_AFTER_GROWTH_NS: u64 = 1_000_000_000;
/// A loop that saw no I/O for this long after a burst gives the buffers its pool cached back to
/// the allocator, keeping [`IDLE_POOL_KEEP`] per size class, and asks the allocator to return
/// free memory to the OS (K2, K8).
#[cfg_attr(not(feature = "idle-trim"), allow(dead_code))]
const IDLE_TRIM_NS: u64 = 1_000_000_000;
#[cfg_attr(not(feature = "idle-trim"), allow(dead_code))]
const IDLE_POOL_KEEP: usize = 4;
/// Events left in a turn from which a connection's response is written as soon as its callback
/// returns (K4).
const FLUSH_EARLY_BATCH: usize = 16;
/// I/O events since the last trim that make a burst worth trimming after.
#[cfg_attr(not(feature = "idle-trim"), allow(dead_code))]
const BURST_EVENTS: u64 = 4096;
const UDP_BIT: u64 = 1 << 62;

/// A task run on a loop thread.
pub(crate) type Task = Box<dyn FnOnce(&mut LoopCtx<'_>) + Send>;

/// What other threads queue for a loop. Messages to a connection or endpoint are their own
/// variants, so a reply costs no closure allocation.
pub(crate) enum Item {
    Task(Task),
    Conn(u64, Message),
    Udp(usize, Message),
}

/// A loop's inbox: a lock-free MPSC queue (K3: `Responder::send` from a worker thread takes
/// no lock and, while the loop is running or spinning, makes no system call; a parked loop is
/// signalled once per batch through [`Waker::post`]).
pub(crate) struct Queue {
    items: simoom_sys::mpsc::Mpsc<Item>,
    pub(crate) waker: Waker,
    closed: AtomicBool,
}

impl Queue {
    pub(crate) fn new(waker: Waker) -> Queue {
        Queue { items: simoom_sys::mpsc::Mpsc::new(), waker, closed: AtomicBool::new(false) }
    }

    fn push(&self, t: Item) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        self.items.push(t);
        self.waker.post();
        // Closed meanwhile: the item is dropped with the queue (or by `close`).
        !self.closed.load(Ordering::Acquire)
    }

    fn take(&self, into: &mut Vec<Item>) {
        self.items.take(into);
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let mut v = Vec::new();
        self.items.take(&mut v);
    }
}

/// A handle to one loop, usable from any thread: run closures on the loop thread.
#[derive(Clone)]
pub struct LoopHandle {
    pub(crate) index: usize,
    pub(crate) queue: Arc<Queue>,
}

impl std::fmt::Debug for LoopHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopHandle").field("index", &self.index).finish()
    }
}

impl LoopHandle {
    /// The loop's index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Runs `f` on the loop thread at its next turn. Returns `false` if the loop has exited.
    pub fn run(&self, f: impl FnOnce(&mut LoopCtx<'_>) + Send + 'static) -> bool {
        self.queue.push(Item::Task(Box::new(f)))
    }
}

/// A handle to one connection, usable from any thread. Messages to a closed connection are
/// dropped.
#[derive(Clone)]
pub struct ConnHandle {
    queue: Arc<Queue>,
    key: u64,
    loop_index: usize,
}

impl std::fmt::Debug for ConnHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnHandle").field("loop", &self.loop_index).field("key", &self.key).finish()
    }
}

impl ConnHandle {
    /// Delivers `msg` to the connection's [`Connection::on_message`] on its loop. Returns
    /// `false` if the loop has exited (the message is dropped).
    pub fn send(&self, msg: Message) -> bool {
        let key = self.key;
        self.queue.push(Item::Conn(key, msg))
    }

    /// The loop running the connection.
    pub fn loop_index(&self) -> usize {
        self.loop_index
    }
}

/// A handle to a UDP endpoint, usable from any thread.
#[derive(Clone)]
pub struct EndpointHandle {
    queue: Arc<Queue>,
    idx: usize,
}

impl std::fmt::Debug for EndpointHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointHandle").field("idx", &self.idx).finish()
    }
}

impl EndpointHandle {
    /// Delivers `msg` to the endpoint's [`Endpoint::on_message`]. Returns `false` if the loop
    /// has exited.
    pub fn send(&self, msg: Message) -> bool {
        let idx = self.idx;
        self.queue.push(Item::Udp(idx, msg))
    }
}

// ---------------------------------------------------------------------------------------------
// Slab
// ---------------------------------------------------------------------------------------------

struct Slab<T> {
    slots: Vec<(u32, Option<T>)>,
    free: Vec<u32>,
    len: usize,
}

impl<T> Slab<T> {
    fn new() -> Self {
        Slab { slots: Vec::new(), free: Vec::new(), len: 0 }
    }
    fn next_key(&self) -> u64 {
        match self.free.last() {
            Some(&i) => i as u64 | (self.slots[i as usize].0 as u64) << 32,
            None => self.slots.len() as u64,
        }
    }
    fn insert(&mut self, v: T) -> u64 {
        self.len += 1;
        match self.free.pop() {
            Some(i) => {
                self.slots[i as usize].1 = Some(v);
                i as u64 | (self.slots[i as usize].0 as u64) << 32
            }
            None => {
                self.slots.push((0, Some(v)));
                self.slots.len() as u64 - 1
            }
        }
    }
    fn get_mut(&mut self, key: u64) -> Option<&mut T> {
        match self.slots.get_mut((key & 0xFFFF_FFFF) as usize) {
            Some((g, Some(v))) if *g == (key >> 32) as u32 => Some(v),
            _ => None,
        }
    }
    fn remove(&mut self, key: u64) -> Option<T> {
        let s = self.slots.get_mut((key & 0xFFFF_FFFF) as usize)?;
        if s.0 != (key >> 32) as u32 || s.1.is_none() {
            return None;
        }
        s.0 = s.0.wrapping_add(1) & 0x3FFF_FFFF; // keep the top two key bits free
        self.free.push((key & 0xFFFF_FFFF) as u32);
        self.len -= 1;
        s.1.take()
    }
    fn keys(&self) -> Vec<u64> {
        self.slots.iter().enumerate().filter(|(_, s)| s.1.is_some()).map(|(i, s)| i as u64 | (s.0 as u64) << 32).collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Loop state
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) enum TimerTarget {
    Conn(u64, u64),
    Udp(usize, u64),
    /// The end of a connection's lingering close ([`Core::linger`]).
    Linger(u64),
}

struct Conn {
    id: Id,
    handler: Option<Box<dyn Connection>>,
    input: Option<Vec<u8>>,
    queued: usize,
    reason: Option<CloseReason>,
    user_paused: bool,
    hw_paused: bool,
    want_drain: bool,
    closing: bool,
    closed: bool,
    /// Timers this connection set that may still be pending: cancelled when it is removed, so
    /// a closed connection leaves nothing in the wheel. Fired ones are pruned as it grows.
    timers: ConnTimers,
    /// In a lingering close: the write side is shut down and input is read and dropped until
    /// the peer closes, `linger_left` bytes were dropped, or the linger timer fires.
    lingering: bool,
    linger_left: u32,
}

/// One shared panic site for [`Core::conn`] (inlined into every `Ctx` method, an `expect`
/// carried its own message and location into each, K9).
#[cold]
#[inline(never)]
fn no_connection() -> ! {
    panic!("connection exists during its callback")
}

/// The timers a connection set that may still be pending. Connections almost always have at
/// most one (the facade re-arms a single timer), so it lives inline; more go to a side vector
/// made only when needed (K8: no allocation per idle connection).
#[derive(Default)]
struct ConnTimers {
    one: Option<TimerId>,
    more: Option<Box<Vec<TimerId>>>,
}

impl ConnTimers {
    fn push(&mut self, id: TimerId, wheel: &TimerWheel<TimerTarget>) {
        if self.one.is_none_or(|t| !wheel.is_pending(t)) {
            self.one = Some(id);
            return;
        }
        let v = self.more.get_or_insert_with(Default::default);
        if v.len() >= 4 {
            v.retain(|t| wheel.is_pending(*t));
        }
        v.push(id);
    }

    fn remove(&mut self, id: TimerId) {
        if self.one == Some(id) {
            self.one = None;
        } else if let Some(v) = self.more.as_mut() {
            if let Some(i) = v.iter().position(|t| *t == id) {
                v.swap_remove(i);
            }
        }
    }

    fn cancel_all(&mut self, wheel: &mut TimerWheel<TimerTarget>) {
        if let Some(t) = self.one.take() {
            wheel.cancel(t);
        }
        for t in self.more.take().into_iter().flat_map(|v| *v) {
            wheel.cancel(t);
        }
    }
}

pub(crate) struct ListenerSlot {
    pub(crate) acceptor: Arc<dyn Acceptor>,
    /// The socket this loop accepts on, if it has one (all loops on Linux; loop 0 elsewhere).
    pub(crate) socket: Option<Socket>,
    /// One socket shared by all loops (accepted connections are handed out), rather than one
    /// `SO_REUSEPORT` socket per loop.
    handoff: bool,
    id: Option<Id>,
    /// Bind this loop's own `SO_REUSEPORT` socket on the loop thread at start.
    pub(crate) bind: Option<(SocketAddr, simoom_sys::net::ListenOptions)>,
}

impl ListenerSlot {
    pub(crate) fn new(acceptor: Arc<dyn Acceptor>, socket: Option<Socket>, handoff: bool) -> ListenerSlot {
        ListenerSlot { acceptor, socket, handoff, id: None, bind: None }
    }
}

pub(crate) struct UdpSlot {
    pub(crate) service: Arc<dyn UdpService>,
    pub(crate) binding: usize,
    pub(crate) socket: Option<Socket>,
    /// GRO is on: receive into 64 KiB buffers of the driver's own.
    gro: bool,
    id: Option<Id>,
    local: Option<SocketAddr>,
    /// Bind this loop's own `SO_REUSEPORT` socket on the loop thread at start.
    pub(crate) bind: Option<(SocketAddr, simoom_sys::net::UdpOptions)>,
}

/// Receive buffer size for a UDP socket with GRO: a whole coalesced batch (at most 64 KiB).
#[cfg_attr(not(feature = "udp"), allow(dead_code))]
pub(crate) const GRO_BUFFER: usize = 64 * 1024;

impl UdpSlot {
    #[cfg_attr(not(feature = "udp"), allow(dead_code))]
    pub(crate) fn new(service: Arc<dyn UdpService>, binding: usize, socket: Option<Socket>, gro: bool) -> UdpSlot {
        UdpSlot { service, binding, socket, gro, id: None, local: None, bind: None }
    }
}

/// Everything a handler's context reaches.
pub(crate) struct Core {
    pub(crate) index: usize,
    driver: Driver,
    pool: BufPool,
    timers: TimerWheel<TimerTarget>,
    conns: Slab<Conn>,
    now_ns: u64,
    tick_ns: u64,
    queue: Arc<Queue>,
    peers: Vec<LoopHandle>,
    offload: OffloadPool,
    cfg: Arc<Config>,
    shared: Arc<Shared>,
    listeners: Vec<ListenerSlot>,
    udps: Vec<UdpSlot>,
    endpoints: Vec<Option<Box<dyn Endpoint>>>,
    redeliver: Vec<u64>,
    drains: Vec<u64>,
    rr: usize,
    /// A third connection at once arrived this turn: start lazy loops after it.
    want_grow: bool,
    /// Start them after the next turn, which flushes this turn's output.
    grow_next: bool,
    grown: bool,
    /// Connections accepted while the lazy loops start ([`Core::spread_parked`]).
    parked: Vec<(Socket, Option<SocketAddr>, usize)>,
    /// Until then (loop clock), connections accepted here are handed to the less busy of two
    /// loops, as on a shared listener: set when the lazy loops are up.
    handoff_until: u64,
    accepted: u64,
    rejected: u64,
    closed: u64,
    /// The loop clock when the driver last reported I/O ([`IDLE_TRIM_NS`]).
    #[cfg_attr(not(feature = "idle-trim"), allow(dead_code))]
    last_io: u64,
    /// I/O events since the last idle trim.
    #[cfg_attr(not(feature = "idle-trim"), allow(dead_code))]
    io_since_trim: u64,
    /// Events (or messages) of this turn not dispatched yet, the current one included.
    batch_left: usize,
}

impl Core {
    fn conn(&mut self, key: u64) -> &mut Conn {
        match self.conns.get_mut(key) {
            Some(c) => c,
            None => no_connection(),
        }
    }

    fn deadline_tick(&self, after: Duration) -> u64 {
        let at = self.now_ns.saturating_add(after.as_nanos().min(u64::MAX as u128) as u64);
        at.div_ceil(self.tick_ns)
    }

    /// Calls `f` with the connection's handler and a context; puts the handler back after.
    fn with_conn(&mut self, key: u64, f: impl FnOnce(&mut dyn Connection, &mut Ctx<'_>)) {
        let mut f = Some(f);
        self.with_conn_dyn(key, &mut |h, cx| {
            if let Some(f) = f.take() {
                f(h, cx)
            }
        });
    }

    /// The body of [`Core::with_conn`], once for every callback (none of them is on the data
    /// path, which goes through `call_data`).
    #[inline(never)]
    fn with_conn_dyn(&mut self, key: u64, f: &mut dyn FnMut(&mut dyn Connection, &mut Ctx<'_>)) {
        let Some(c) = self.conns.get_mut(key) else { return };
        if c.closed {
            return;
        }
        let Some(mut h) = c.handler.take() else { return };
        {
            let mut cx = Ctx { core: self, key };
            f(&mut *h, &mut cx);
        }
        if let Some(c) = self.conns.get_mut(key) {
            c.handler = Some(h);
        }
    }

    fn with_udp(&mut self, idx: usize, f: impl FnOnce(&mut dyn Endpoint, &mut UdpCtx<'_>)) {
        // Without the `udp` feature there are no UDP slots: leave every caller's code out.
        if !cfg!(feature = "udp") {
            return;
        }
        let Some(slot) = self.endpoints.get_mut(idx) else { return };
        let Some(mut ep) = slot.take() else { return };
        {
            let mut cx = UdpCtx { core: self, idx };
            f(&mut *ep, &mut cx);
        }
        self.endpoints[idx] = Some(ep);
    }

    #[inline(never)]
    pub(crate) fn deliver(&mut self, key: u64, msg: Message) {
        self.with_conn(key, |h, cx| h.on_message(cx, msg));
        self.flush_conn(key);
    }

    pub(crate) fn deliver_udp(&mut self, idx: usize, msg: Message) {
        self.with_udp(idx, |h, cx| h.on_message(cx, msg));
    }

    /// Creates the endpoint of UDP slot `idx` (at start, once its socket is registered).
    fn ensure_endpoint(&mut self, idx: usize) {
        let Some(slot) = self.udps.get(idx) else { return };
        if slot.id.is_none() || self.endpoints[idx].is_some() {
            return;
        }
        let info = UdpInfo { binding: slot.binding, loop_index: self.index, local_addr: slot.local.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))) };
        self.endpoints[idx] = Some(slot.service.endpoint(&info));
    }

    fn close_now(&mut self, key: u64, reason: CloseReason) {
        let Some(c) = self.conns.get_mut(key) else { return };
        if c.closed {
            return;
        }
        c.closed = true;
        if c.reason.is_none() {
            c.reason = Some(reason);
        }
        let id = c.id;
        self.driver.close(id);
    }

    /// A graceful close once the output is flushed: shut down the write side (the peer reads
    /// our last bytes and a FIN), then read and drop input until the peer closes, the linger
    /// time passes or `linger_bytes` were dropped, and only then close. Closing a socket with
    /// unread input makes the kernel send a reset, which can destroy the response at the peer
    /// before it reads it (RFC 9112 §9.6). Holds no buffer: what arrives goes straight back to
    /// the pool.
    fn linger(&mut self, key: u64) {
        let linger = self.cfg.linger;
        let id = match self.conns.get_mut(key) {
            Some(c) if !c.closed && !c.lingering => c.id,
            _ => return,
        };
        let shut = !linger.is_zero() && self.driver.socket(id).is_some_and(|s| s.shutdown(std::net::Shutdown::Write).is_ok());
        if !shut {
            self.close_now(key, CloseReason::Closed);
            return;
        }
        let Some(c) = self.conns.get_mut(key) else { return };
        c.lingering = true;
        c.linger_left = self.cfg.linger_bytes.min(u32::MAX as usize) as u32;
        if let Some(i) = c.input.take() {
            self.pool.put(i);
        }
        let at = self.deadline_tick(linger);
        let t = self.timers.insert(at, TimerTarget::Linger(key));
        if let Some(c) = self.conns.get_mut(key) {
            c.timers.push(t, &self.timers);
        }
        self.driver.recv(id, true);
    }

    /// A connection accepted here or handed over by another loop.
    pub(crate) fn adopt(&mut self, socket: Socket, peer: Option<SocketAddr>, listener: usize) {
        let total = self.shared.active.fetch_add(1, Ordering::AcqRel) + 1;
        let here = self.conns.len + 1;
        if total > self.cfg.max_connections || here > self.cfg.max_connections_per_loop {
            // Accept and close at once, so the kernel's queue doesn't stretch the tail.
            self.shared.active.fetch_sub(1, Ordering::AcqRel);
            self.rejected += 1;
            drop(socket);
            return;
        }
        let info = ConnInfo { listener, peer, loop_index: self.index };
        let Some(handler) = self.listeners.get(listener).and_then(|l| l.acceptor.accept(&info)) else {
            self.shared.active.fetch_sub(1, Ordering::AcqRel);
            self.rejected += 1;
            return;
        };
        if self.register(socket, handler).is_err() {
            self.shared.active.fetch_sub(1, Ordering::AcqRel);
            self.rejected += 1;
            return;
        }
        if self.accepted == 0 {
            self.driver.set_buffer_target(self.cfg.recv_buffers);
        }
        // A third connection at once on loop 0: more loops can help now (lazy_loops). One
        // connection at a time (a FaaS instance) never needs them; the threshold is three, not
        // two, because a client's next connection often arrives before its last one is reaped.
        if self.cfg.lazy_loops && self.index == 0 && self.conns.len >= 3 {
            self.want_grow |= !self.grown;
        }
        self.accepted += 1;
    }

    fn register(&mut self, socket: Socket, handler: Box<dyn Connection>) -> io::Result<u64> {
        let key = self.conns.next_key();
        let id = self.driver.stream(socket, key)?;
        let k = self.conns.insert(Conn {
            id,
            handler: Some(handler),
            input: None,
            queued: 0,
            reason: None,
            user_paused: false,
            hw_paused: false,
            want_drain: false,
            closing: false,
            closed: false,
            timers: ConnTimers::default(),
            lingering: false,
            linger_left: 0,
        });
        debug_assert_eq!(k, key);
        self.driver.recv(id, true);
        self.with_conn(key, |h, cx| h.on_open(cx));
        Ok(key)
    }

}

// ---------------------------------------------------------------------------------------------
// Contexts
// ---------------------------------------------------------------------------------------------

/// What a [`Connection`] callback can do: send, close, pause, set timers, reach other threads.
pub struct Ctx<'a> {
    core: &'a mut Core,
    key: u64,
}

impl std::fmt::Debug for Ctx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx").field("loop", &self.core.index).field("key", &self.key).finish()
    }
}

impl Ctx<'_> {
    /// Queues bytes to send. Output queued in one loop turn goes out together, in order, at the
    /// end of the turn. The buffer returns to the loop's pool once written.
    pub fn send(&mut self, buf: Vec<u8>) {
        self.send_buf(OutBuf::Owned(buf));
    }

    /// Queues static bytes to send (a fixed reply costs no copy).
    pub fn send_static(&mut self, bytes: &'static [u8]) {
        self.send_buf(OutBuf::Static(bytes));
    }

    /// Queues an [`OutBuf`].
    pub fn send_buf(&mut self, buf: OutBuf) {
        let high = self.core.cfg.write_high_water;
        let c = self.core.conn(self.key);
        if c.closed || buf.is_empty() {
            if let OutBuf::Owned(v) = buf {
                self.core.pool.put(v);
            }
            return;
        }
        c.queued += buf.len();
        let id = c.id;
        let pause = c.queued > high && !c.hw_paused;
        if pause {
            c.hw_paused = true;
        }
        let user_paused = c.user_paused;
        self.core.driver.send(id, buf);
        if pause && !user_paused {
            self.core.driver.recv(id, false);
        }
    }

    /// An empty buffer from the loop's pool with room for at least `min` bytes, to build output
    /// in. Hand it to [`Ctx::send`] or back with [`Ctx::recycle`].
    pub fn buffer(&mut self, min: usize) -> Vec<u8> {
        self.core.pool.get(min)
    }

    /// Returns a buffer to the loop's pool.
    pub fn recycle(&mut self, buf: Vec<u8>) {
        self.core.pool.put(buf);
    }

    /// Bytes queued and not yet written.
    pub fn queued(&mut self) -> usize {
        self.core.conn(self.key).queued
    }

    /// Stops calling [`Connection::on_data`] and stops reading from the socket (backpressure,
    /// for example while a request is processed elsewhere).
    pub fn pause_reading(&mut self) {
        let c = self.core.conn(self.key);
        if c.user_paused || c.closed {
            return;
        }
        c.user_paused = true;
        let (id, hw) = (c.id, c.hw_paused);
        if !hw {
            self.core.driver.recv(id, false);
        }
    }

    /// Undoes [`Ctx::pause_reading`]. Input that arrived meanwhile is offered to
    /// [`Connection::on_data`] right after the current callback.
    pub fn resume_reading(&mut self) {
        let c = self.core.conn(self.key);
        if !c.user_paused || c.closed {
            return;
        }
        c.user_paused = false;
        let (id, hw, has_input) = (c.id, c.hw_paused, c.input.as_ref().is_some_and(|i| !i.is_empty()));
        if !hw {
            self.core.driver.recv(id, true);
        }
        if has_input {
            self.core.redeliver.push(self.key);
        }
    }

    /// Offers input that is still unconsumed to [`Connection::on_data`] again right after the
    /// current callback, for a connection that left input unconsumed without pausing (it was
    /// busy) and can take it now.
    pub fn redeliver(&mut self) {
        let c = self.core.conn(self.key);
        if c.user_paused || c.closed || !c.input.as_ref().is_some_and(|i| !i.is_empty()) {
            return;
        }
        self.core.redeliver.push(self.key);
    }

    /// Asks for [`Connection::on_drain`] once the queued output is at or below the low-water
    /// mark (right after this callback if it already is).
    pub fn notify_drain(&mut self) {
        let low = self.core.cfg.write_low_water;
        let c = self.core.conn(self.key);
        if c.queued <= low {
            self.core.drains.push(self.key);
        } else {
            c.want_drain = true;
        }
    }

    /// Closes gracefully: queued output is written first, then the socket is closed. Nothing
    /// more is delivered except [`Connection::on_close`].
    pub fn close(&mut self) {
        let c = self.core.conn(self.key);
        if c.closed || c.closing {
            return;
        }
        c.closing = true;
        if c.queued == 0 {
            self.core.linger(self.key);
        }
    }

    /// Closes at once, discarding queued output.
    pub fn abort(&mut self) {
        self.core.close_now(self.key, CloseReason::Aborted);
    }

    /// Whether [`Ctx::close`] or [`Ctx::abort`] was called.
    pub fn is_closing(&mut self) -> bool {
        let c = self.core.conn(self.key);
        c.closing || c.closed
    }

    /// Calls [`Connection::on_timer`] with `token` after `after` (rounded up to the loop's
    /// timer tick). The timers of a connection are cancelled when it is closed.
    pub fn set_timer(&mut self, after: Duration, token: u64) -> TimerId {
        let at = self.core.deadline_tick(after);
        let id = self.core.timers.insert(at, TimerTarget::Conn(self.key, token));
        let core = &mut *self.core;
        if let Some(c) = core.conns.get_mut(self.key) {
            c.timers.push(id, &core.timers);
        }
        id
    }

    /// Cancels a timer. Returns whether it was still pending.
    pub fn cancel_timer(&mut self, id: TimerId) -> bool {
        if let Some(c) = self.core.conns.get_mut(self.key) {
            c.timers.remove(id);
        }
        self.core.timers.cancel(id).is_some()
    }

    /// A handle for reaching this connection from other threads.
    pub fn handle(&mut self) -> ConnHandle {
        ConnHandle { queue: self.core.queue.clone(), key: self.key, loop_index: self.core.index }
    }

    /// Runs `job` on the shared offload pool and delivers its result to
    /// [`Connection::on_message`]. Fails at once when the pool is full or overloaded.
    pub fn offload<F>(&mut self, job: F) -> Result<(), Rejected>
    where
        F: FnOnce() -> Message + Send + 'static,
    {
        let h = self.handle();
        self.core.offload.try_submit(Box::new(move || {
            h.send(job());
        }))
    }

    /// The offload pool, for callers that manage their own completion.
    pub fn offload_pool(&mut self) -> &OffloadPool {
        &self.core.offload
    }

    /// The loop's clock in nanoseconds (read once per loop turn).
    pub fn now_ns(&mut self) -> u64 {
        self.core.now_ns
    }

    /// The peer's address.
    pub fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        let id = self.core.conn(self.key).id;
        self.core.driver.socket(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "closed"))?.peer_addr()
    }

    /// The local address.
    pub fn local_addr(&mut self) -> io::Result<SocketAddr> {
        let id = self.core.conn(self.key).id;
        self.core.driver.socket(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "closed"))?.local_addr()
    }

    /// The socket, for options the runtime doesn't wrap.
    pub fn socket(&mut self) -> Option<&Socket> {
        let id = self.core.conn(self.key).id;
        self.core.driver.socket(id)
    }

    /// The index of the loop running this connection.
    pub fn loop_index(&mut self) -> usize {
        self.core.index
    }

    /// Whether open connections passed three quarters of what the server can hold (its
    /// `max_connections`, and on Linux its file descriptor limit): time to shed connections
    /// that hold a slot without doing anything useful (K6).
    /// Asked only when a slow request head reaches its deadline, so the descriptor limit is
    /// read then (one `getrlimit`), not kept per loop.
    #[inline(never)]
    pub fn connection_pressure(&mut self) -> bool {
        let max = self.core.cfg.max_connections;
        let budget = simoom_sys::net::descriptor_limit().map_or(max, |fds| max.min(fds.saturating_sub(32).max(1)));
        let open = self.core.shared.active.load(Ordering::Relaxed);
        open.saturating_mul(4) > budget.saturating_mul(3)
    }
}

/// What an [`Endpoint`] callback can do.
pub struct UdpCtx<'a> {
    core: &'a mut Core,
    idx: usize,
}

impl std::fmt::Debug for UdpCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpCtx").field("loop", &self.core.index).field("idx", &self.idx).finish()
    }
}

impl UdpCtx<'_> {
    /// Sends datagrams at once (batched, with GSO where the kernel has it). Returns how many
    /// transmits were handed to the kernel; `WouldBlock` means none was (socket buffer full).
    pub fn send(&mut self, msgs: &[Transmit<'_>]) -> io::Result<usize> {
        let id = self.core.udps[self.idx].id.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "closed"))?;
        self.core.driver.send_to(id, msgs)
    }

    /// The bound address.
    pub fn local_addr(&mut self) -> Option<SocketAddr> {
        self.core.udps[self.idx].local
    }

    /// Calls [`Endpoint::on_timer`] with `token` after `after`.
    pub fn set_timer(&mut self, after: Duration, token: u64) -> TimerId {
        let at = self.core.deadline_tick(after);
        self.core.timers.insert(at, TimerTarget::Udp(self.idx, token))
    }

    /// Cancels a timer.
    pub fn cancel_timer(&mut self, id: TimerId) -> bool {
        self.core.timers.cancel(id).is_some()
    }

    /// A handle for reaching this endpoint from other threads.
    pub fn handle(&mut self) -> EndpointHandle {
        EndpointHandle { queue: self.core.queue.clone(), idx: self.idx }
    }

    /// An empty pooled buffer with room for `min` bytes.
    pub fn buffer(&mut self, min: usize) -> Vec<u8> {
        self.core.pool.get(min)
    }

    /// Returns a buffer to the pool.
    pub fn recycle(&mut self, buf: Vec<u8>) {
        self.core.pool.put(buf);
    }

    /// The offload pool.
    pub fn offload_pool(&mut self) -> &OffloadPool {
        &self.core.offload
    }

    /// The loop's clock in nanoseconds.
    pub fn now_ns(&mut self) -> u64 {
        self.core.now_ns
    }

    /// The loop index.
    pub fn loop_index(&mut self) -> usize {
        self.core.index
    }
}

/// Access to a loop from a task run with [`LoopHandle::run`].
pub struct LoopCtx<'a> {
    pub(crate) core: &'a mut Core,
}

impl std::fmt::Debug for LoopCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopCtx").field("loop", &self.core.index).finish()
    }
}

impl LoopCtx<'_> {
    /// The loop index.
    pub fn index(&self) -> usize {
        self.core.index
    }

    /// Runs a connected, non-blocking socket (an outbound connection, or one accepted
    /// elsewhere) on this loop with `handler`. It does not count against the connection caps.
    pub fn adopt(&mut self, socket: Socket, handler: Box<dyn Connection>) -> io::Result<ConnHandle> {
        self.core.shared.active.fetch_add(1, Ordering::AcqRel);
        match self.core.register(socket, handler) {
            Ok(key) => Ok(ConnHandle { queue: self.core.queue.clone(), key, loop_index: self.core.index }),
            Err(e) => {
                self.core.shared.active.fetch_sub(1, Ordering::AcqRel);
                Err(e)
            }
        }
    }

    /// Connections on this loop.
    pub fn connections(&self) -> usize {
        self.core.conns.len
    }

    /// The loop's clock in nanoseconds.
    pub fn now_ns(&self) -> u64 {
        self.core.now_ns
    }

    /// Driver counters of this loop.
    pub fn driver_stats(&self) -> simoom_sys::driver::DriverStats {
        self.core.driver.stats()
    }

    /// Buffer pool counters of this loop.
    pub fn pool_stats(&self) -> crate::pool::PoolStats {
        self.core.pool.stats()
    }
}

// ---------------------------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------------------------

pub(crate) struct LoopSetup {
    pub(crate) index: usize,
    pub(crate) cfg: Arc<Config>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) offload: OffloadPool,
    pub(crate) listeners: Vec<ListenerSlot>,
    pub(crate) udps: Vec<UdpSlot>,
}

/// Creates the driver on this thread and returns the loop, ready to run.
pub(crate) fn build(mut setup: LoopSetup) -> io::Result<(Core, Arc<Queue>)> {
    let cfg = setup.cfg;
    for l in setup.listeners.iter_mut() {
        if let Some((addr, opts)) = l.bind.take() {
            l.socket = Some(Socket::tcp_listen(addr, &opts)?);
        }
    }
    #[cfg(feature = "udp")]
    for u in setup.udps.iter_mut() {
        if let Some((addr, opts)) = u.bind.take() {
            u.socket = Some(Socket::udp_bind(addr, &opts)?);
        }
    }
    let mut driver = Driver::new(&cfg.driver)?;
    // A small stock until the loop has work: an idle loop holds few receive buffers.
    driver.set_buffer_target(if setup.udps.is_empty() { cfg.recv_buffers.min(INITIAL_RECV_BUFFERS) } else { cfg.recv_buffers });
    let queue = Arc::new(Queue::new(driver.waker()));
    let tick_ns = (cfg.timer_tick.as_nanos() as u64).max(1);
    let now_ns = simoom_sys::time::now_ns();
    let core = Core {
        index: setup.index,
        driver,
        pool: BufPool::new(cfg.buffer_classes, cfg.pool_cache),
        timers: TimerWheel::new(now_ns / tick_ns),
        conns: Slab::new(),
        now_ns,
        tick_ns,
        queue: queue.clone(),
        peers: Vec::new(),
        offload: setup.offload,
        shared: setup.shared,
        listeners: setup.listeners,
        endpoints: if cfg!(feature = "udp") { setup.udps.iter().map(|_| None).collect() } else { Vec::new() },
        udps: setup.udps,
        redeliver: Vec::new(),
        drains: Vec::new(),
        rr: setup.index,
        want_grow: false,
        grow_next: false,
        grown: false,
        parked: Vec::new(),
        handoff_until: 0,
        accepted: 0,
        rejected: 0,
        closed: 0,
        last_io: now_ns,
        io_since_trim: 0,
        batch_left: 0,
        cfg,
    };
    Ok((core, queue))
}

impl Core {
    pub(crate) fn backend(&self) -> (simoom_sys::driver::Backend, Option<String>) {
        (self.driver.backend(), self.driver.fallback_reason().map(str::to_string))
    }

    fn start_io(&mut self) -> io::Result<()> {
        for i in 0..self.listeners.len() {
            if let Some(s) = self.listeners[i].socket.take() {
                self.listeners[i].id = Some(self.driver.listen(s, LISTENER_BIT | i as u64)?);
            }
        }
        #[cfg(feature = "udp")]
        for i in 0..self.udps.len() {
            if let Some(s) = self.udps[i].socket.take() {
                let local = s.local_addr().ok();
                let key = UDP_BIT | i as u64;
                let id = if self.udps[i].gro { self.driver.udp_large(s, key, GRO_BUFFER)? } else { self.driver.udp(s, key)? };
                self.driver.recv(id, true);
                let slot = &mut self.udps[i];
                slot.id = Some(id);
                slot.local = local;
                self.ensure_endpoint(i);
            }
        }
        Ok(())
    }

    /// Hands the connections accepted while the lazy loops started to every loop in turn.
    fn spread_parked(&mut self) {
        self.peers = self.shared.handles();
        let n = self.peers.len().max(1);
        for (j, (socket, peer, li)) in std::mem::take(&mut self.parked).into_iter().enumerate() {
            let p = (self.rr + j) % n;
            match self.peers.get(p) {
                Some(h) if h.index != self.index => {
                    if !h.run(move |lcx| lcx.core.adopt(socket, peer, li)) {
                        self.rejected += 1;
                    }
                }
                _ => self.adopt(socket, peer, li),
            }
        }
    }

    /// Picks the loop for a connection accepted on a shared listener: the less busy of two
    /// (power of two choices), starting from a rotating position. Returns a position in
    /// `peers` (the running loops, by index), or `None` for this loop.
    fn pick_loop(&mut self) -> Option<usize> {
        if self.shared.started.load(Ordering::Acquire) != self.peers.len() {
            // lazy loops started since: refresh the copy
            self.peers = self.shared.handles();
        }
        let n = self.peers.len();
        if n <= 1 {
            return None;
        }
        self.rr = (self.rr + 1) % n;
        let a = self.rr;
        let b = (a + 1 + self.rr * 7 % (n - 1).max(1)) % n;
        let la = self.shared.loop_active[self.peers[a].index].load(Ordering::Relaxed);
        let lb = self.shared.loop_active[self.peers[b].index].load(Ordering::Relaxed);
        let p = if lb < la { b } else { a };
        (self.peers[p].index != self.index).then_some(p)
    }

    fn dispatch(&mut self, ev: Event) {
        match ev {
            Event::Accepted { key, socket, peer } => {
                let li = (key & !LISTENER_BIT) as usize;
                if self.want_grow || self.grow_next || (self.grown && self.shared.growing.load(Ordering::Acquire)) {
                    // The other loops are about to start or starting: hold the connection until
                    // they all run, then spread what arrived meanwhile over every loop (else a
                    // burst of new connections, accepted in one batch, would all stay here).
                    self.parked.push((socket, peer, li));
                    return;
                }
                let handoff = self.listeners.get(li).is_some_and(|l| l.handoff) || self.now_ns < self.handoff_until;
                match if handoff { self.pick_loop() } else { None } {
                    None => self.adopt(socket, peer, li),
                    Some(p) => {
                        let ok = self.peers[p].run(move |lcx| lcx.core.adopt(socket, peer, li));
                        if !ok {
                            self.rejected += 1;
                        }
                    }
                }
            }
            Event::Data { key, buf } => self.on_data(key, buf),
            Event::Eof { key } => {
                if self.conns.get_mut(key).is_some_and(|c| c.lingering) {
                    // the peer closed its side: the lingering close is over
                    self.close_now(key, CloseReason::Closed);
                    return;
                }
                self.with_conn(key, |h, cx| {
                    if !cx.is_closing() {
                        h.on_eof(cx)
                    }
                })
            }
            Event::Error { key, error } => {
                if key & (LISTENER_BIT | UDP_BIT) != 0 {
                    return; // accept errors (EMFILE...) and UDP noise: keep serving
                }
                self.close_now(key, CloseReason::Error(error));
            }
            Event::Sent { key, buf } => self.on_sent(key, buf),
            Event::Closed { key } => self.on_closed(key),
            #[cfg(not(feature = "udp"))]
            Event::Datagram { buf, .. } => self.pool.put(buf),
            #[cfg(feature = "udp")]
            Event::Datagram { key, buf, meta } => {
                let idx = (key & !UDP_BIT) as usize;
                let data = buf;
                self.with_udp(idx, |h, cx| h.on_datagram(cx, &data, &meta));
                if self.udps.get(idx).is_some_and(|u| u.gro) {
                    self.driver.provide(data); // back to the driver's large stock
                } else {
                    self.pool.put(data);
                }
            }
            Event::Wake => {}
        }
    }

    fn on_data(&mut self, key: u64, buf: Vec<u8>) {
        let max_input = self.cfg.max_input;
        let Some(c) = self.conns.get_mut(key) else {
            self.pool.put(buf);
            return;
        };
        if c.closed || c.closing {
            let n = buf.len();
            self.pool.put(buf);
            if c.lingering {
                if n > c.linger_left as usize {
                    self.close_now(key, CloseReason::Closed);
                } else {
                    c.linger_left -= n as u32;
                }
            }
            return;
        }
        match c.input.as_mut() {
            None => c.input = Some(buf),
            Some(cur) => {
                if cur.capacity() - cur.len() < buf.len() {
                    let mut bigger = self.pool.get(cur.len() + buf.len());
                    bigger.extend_from_slice(cur);
                    let old = std::mem::replace(cur, bigger);
                    self.pool.put(old);
                }
                cur.extend_from_slice(&buf);
                self.pool.put(buf);
            }
        }
        let c = self.conns.get_mut(key).unwrap();
        // While reading is paused the driver reads nothing more, so what arrives is the rest of
        // the turn's reads (at most the receive budget) and is kept: the handler paused
        // because it can't take more yet (a full body source), not because the peer misbehaves.
        if !c.user_paused && c.input.as_ref().map_or(0, |i| i.len()) > max_input {
            self.close_now(key, CloseReason::InputLimit);
            return;
        }
        if c.user_paused {
            return;
        }
        self.call_data(key);
        self.flush_conn(key);
    }

    /// Hands a connection's output to the socket now (K4), where the driver can do so without an
    /// extra system call, when enough of the turn's work is left that waiting for it would delay
    /// this response (a small batch flushes at the end of the turn as before, at no cost).
    #[inline]
    fn flush_conn(&mut self, key: u64) {
        if self.batch_left < FLUSH_EARLY_BATCH {
            return;
        }
        if let Some(c) = self.conns.get_mut(key) {
            if !c.closed {
                let id = c.id;
                self.driver.flush_now(id);
            }
        }
    }

    fn call_data(&mut self, key: u64) {
        let Some(c) = self.conns.get_mut(key) else { return };
        if c.closed || c.closing || c.user_paused {
            return;
        }
        let Some(input) = c.input.take() else { return };
        let Some(mut h) = c.handler.take() else {
            c.input = Some(input);
            return;
        };
        let n = {
            let mut cx = Ctx { core: self, key };
            h.on_data(&mut cx, &input)
        };
        let Some(c) = self.conns.get_mut(key) else {
            self.pool.put(input);
            return;
        };
        c.handler = Some(h);
        let mut input = input;
        if n >= input.len() {
            // Everything consumed: the buffer goes back, the connection holds none.
            self.pool.put(input);
        } else {
            let rest = input.len() - n;
            if rest <= COMPACT_INPUT && input.capacity() >= 4 * rest {
                // A small unconsumed tail (a partial head, as a slowloris client keeps sending):
                // move it to an allocation of its own size and give the pooled buffer back, so
                // an idle half-request holds tens of bytes instead of a receive buffer.
                let tail = input[n..].to_vec();
                self.pool.put(input);
                if c.input.is_none() {
                    c.input = Some(tail);
                }
                return;
            }
            if n > 0 {
                let len = input.len();
                input.copy_within(n..len, 0);
                input.truncate(len - n);
            }
            if c.input.is_none() {
                c.input = Some(input);
            } else {
                self.pool.put(input);
            }
        }
    }

    fn on_sent(&mut self, key: u64, buf: OutBuf) {
        let len = buf.len();
        if let OutBuf::Owned(v) = buf {
            self.pool.put(v);
        }
        let low = self.cfg.write_low_water;
        let Some(c) = self.conns.get_mut(key) else { return };
        c.queued = c.queued.saturating_sub(len);
        if c.closed {
            return;
        }
        if c.closing {
            if c.queued == 0 {
                self.linger(key);
            }
            return;
        }
        let mut drain = false;
        if c.hw_paused && c.queued <= low {
            c.hw_paused = false;
            drain = true;
            if !c.user_paused {
                let id = c.id;
                let has_input = c.input.as_ref().is_some_and(|i| !i.is_empty());
                self.driver.recv(id, true);
                if has_input {
                    self.redeliver.push(key);
                }
            }
        }
        let c = self.conns.get_mut(key).unwrap();
        if c.want_drain && c.queued <= low {
            c.want_drain = false;
            drain = true;
        }
        if drain {
            self.with_conn(key, |h, cx| h.on_drain(cx));
        }
    }

    fn on_closed(&mut self, key: u64) {
        if key & LISTENER_BIT != 0 {
            let i = (key & !LISTENER_BIT) as usize;
            if let Some(l) = self.listeners.get_mut(i) {
                l.id = None;
            }
            return;
        }
        if cfg!(feature = "udp") && key & UDP_BIT != 0 {
            let i = (key & !UDP_BIT) as usize;
            if let Some(u) = self.udps.get_mut(i) {
                u.id = None;
                self.endpoints[i] = None;
            }
            return;
        }
        let Some(mut c) = self.conns.remove(key) else { return };
        c.timers.cancel_all(&mut self.timers);
        if let Some(i) = c.input.take() {
            self.pool.put(i);
        }
        self.shared.active.fetch_sub(1, Ordering::AcqRel);
        self.closed += 1;
        let reason = c.reason.take().unwrap_or(CloseReason::Closed);
        if let Some(mut h) = c.handler.take() {
            h.on_close(reason);
        }
    }

    fn fire_timers(&mut self) {
        let now_tick = self.now_ns / self.tick_ns;
        self.timers.collect(now_tick);
        while let Some(t) = self.timers.pop_ready() {
            match t {
                TimerTarget::Conn(key, token) => self.with_conn(key, |h, cx| h.on_timer(cx, token)),
                TimerTarget::Udp(idx, token) => self.with_udp(idx, |h, cx| h.on_timer(cx, token)),
                TimerTarget::Linger(key) => self.close_now(key, CloseReason::Closed),
            }
        }
    }

    /// After a burst: frees what it left once the loop has been idle a while; else shortens
    /// the wait to that moment.
    #[cfg(feature = "idle-trim")]
    #[cold]
    #[inline(never)]
    fn idle_trim(&mut self, timeout: Option<Duration>) -> Option<Duration> {
        let at = self.last_io.saturating_add(IDLE_TRIM_NS);
        if self.now_ns >= at {
            self.pool.trim(IDLE_POOL_KEEP);
            self.driver.trim_buffers(INITIAL_RECV_BUFFERS);
            self.io_since_trim = 0;
            simoom_sys::alloc::release_free_memory();
            return timeout;
        }
        let left = Duration::from_nanos(at - self.now_ns);
        Some(timeout.map_or(left, |t| t.min(left)))
    }

    fn after_callbacks(&mut self) {
        while !self.redeliver.is_empty() || !self.drains.is_empty() {
            for key in std::mem::take(&mut self.redeliver) {
                self.call_data(key);
            }
            for key in std::mem::take(&mut self.drains) {
                self.with_conn(key, |h, cx| h.on_drain(cx));
            }
        }
    }

    fn publish(&self) {
        let s = &self.shared.loops[self.index];
        let d = self.driver.stats();
        s.store(d, self.pool.stats(), self.accepted, self.rejected, self.closed, self.conns.len as u64);
        s.timers.store(self.timers.len() as u64, Ordering::Relaxed);
        self.shared.loop_active[self.index].store(self.conns.len, Ordering::Relaxed);
    }

    /// During a stop: every connection is gone, the listeners are closed and no UDP endpoint is
    /// busy (or the deadline passed).
    fn stop_done(&self, aborted: bool) -> bool {
        self.conns.len == 0 && !self.listeners.iter().any(|l| l.id.is_some()) && (aborted || !(0..self.udp_count()).any(|i| self.endpoint_busy(i)))
    }

    /// UDP slots (endpoints have the same count); none without the `udp` feature, so the
    /// loops over them are left out.
    fn udp_count(&self) -> usize {
        if cfg!(feature = "udp") {
            self.udps.len()
        } else {
            0
        }
    }

    fn endpoint_busy(&self, i: usize) -> bool {
        self.endpoints[i].as_ref().is_some_and(|e| e.is_busy())
    }

    fn begin_stop(&mut self) {
        for i in 0..self.listeners.len() {
            if let Some(id) = self.listeners[i].id {
                self.driver.close(id);
            }
        }
        for key in self.conns.keys() {
            self.with_conn(key, |h, cx| {
                if !cx.is_closing() {
                    h.on_stop(cx)
                }
            });
        }
        for i in 0..self.udp_count() {
            self.with_udp(i, |h, cx| h.on_stop(cx));
        }
    }

    /// Runs the loop until the runtime stops and every connection is gone.
    pub(crate) fn run(&mut self) -> io::Result<()> {
        self.start_io()?;
        let mut events = Vec::with_capacity(256);
        let mut tasks: Vec<Item> = Vec::new();
        let mut stop_at: Option<u64> = None;
        let mut aborted = false;
        let recv_size = self.cfg.buffer_classes[0];
        loop {
            self.now_ns = simoom_sys::time::now_ns();
            self.fire_timers();
            self.after_callbacks();
            // A timer may have finished the last piece of work of a stop (a QUIC endpoint
            // that went idle): check before blocking.
            if stop_at.is_some() && self.stop_done(aborted) {
                break;
            }
            for _ in 0..self.driver.buffers_wanted() {
                let b = self.pool.get(recv_size);
                self.driver.provide(b);
            }
            let mut timeout = self.timers.next_deadline().map(|t| Duration::from_nanos((t * self.tick_ns).saturating_sub(self.now_ns)));
            if let Some(at) = stop_at {
                let left = Duration::from_nanos(at.saturating_sub(self.now_ns));
                timeout = Some(timeout.map_or(left, |t| t.min(left)));
                if aborted {
                    timeout = Some(timeout.unwrap().min(Duration::from_millis(10)));
                }
            }
            if self.grow_next || (!self.parked.is_empty() && self.grown && !self.shared.growing.load(Ordering::Acquire)) {
                // Also: connections parked while the lazy loops started, and the start is over
                // (or had nothing to start: one loop): spread them now, not at the next event
                // (they waited for it, up to a timer away, before).
                timeout = Some(Duration::ZERO);
            }
            #[cfg(feature = "idle-trim")]
            if self.pool.stats().cached > 3 * IDLE_POOL_KEEP || self.io_since_trim >= BURST_EVENTS {
                timeout = self.idle_trim(timeout);
            }
            self.driver.turn(timeout, &mut events)?;
            self.now_ns = simoom_sys::time::now_ns();
            #[cfg(feature = "idle-trim")]
            if !events.is_empty() {
                self.last_io = self.now_ns;
                self.io_since_trim += events.len() as u64;
            }
            let mut woke = false;
            let n = events.len();
            for (i, ev) in events.drain(..).enumerate() {
                if matches!(ev, Event::Wake) {
                    woke = true;
                }
                self.batch_left = n - i;
                self.dispatch(ev);
            }
            if woke {
                self.queue.take(&mut tasks);
                let n = tasks.len();
                for (i, t) in tasks.drain(..).enumerate() {
                    self.batch_left = n - i;
                    match t {
                        Item::Task(t) => t(&mut LoopCtx { core: self }),
                        Item::Conn(key, msg) => self.deliver(key, msg),
                        Item::Udp(idx, msg) => self.deliver_udp(idx, msg),
                    }
                }
            }
            self.batch_left = 0;
            if self.grown && self.handoff_until == 0 && !self.shared.growing.load(Ordering::Acquire) {
                // The lazy loops run. Connections already queued on this loop's listener (a
                // burst that arrived before theirs existed) are handed out for a while too.
                self.handoff_until = self.now_ns.saturating_add(BALANCE_AFTER_GROWTH_NS).max(1);
                self.spread_parked();
                // loop 0 started before the loop count was chosen: off a CPU left to the
                // network too
                simoom_sys::cpu::keep_current_thread_off_net_rx();
            }
            if self.grow_next {
                // a third connection at once, served and flushed by the turn
                // above: start the loops held back (lazy_loops)
                self.grow_next = false;
                self.grown = true;
                self.shared.grow();
            } else if self.want_grow {
                // one more (non-blocking) turn first, which writes this turn's replies
                self.want_grow = false;
                self.grow_next = true;
            }
            self.after_callbacks();
            self.publish();

            if stop_at.is_none() && self.shared.stop.load(Ordering::Acquire) {
                let grace = self.shared.grace_ns.load(Ordering::Acquire);
                stop_at = Some(self.now_ns.saturating_add(grace));
                self.begin_stop();
            }
            if let Some(at) = stop_at {
                if !aborted && self.now_ns >= at {
                    aborted = true;
                    for key in self.conns.keys() {
                        self.close_now(key, CloseReason::Stopped);
                    }
                    for i in 0..self.udp_count() {
                        if self.endpoint_busy(i) {
                            self.with_udp(i, |h, cx| h.on_abort(cx));
                        }
                    }
                }
                if self.stop_done(aborted) {
                    break;
                }
            }
        }
        for i in 0..self.udp_count() {
            if let Some(id) = self.udps[i].id.take() {
                self.driver.close(id);
            }
        }
        // Let the UDP closes and any last sends complete, then shut the queue.
        let end = simoom_sys::time::now_ns() + 200_000_000;
        while !self.driver.is_empty() && simoom_sys::time::now_ns() < end {
            self.driver.turn(Some(Duration::from_millis(10)), &mut events)?;
            for ev in events.drain(..) {
                if let Event::Sent { buf: OutBuf::Owned(v), .. } = ev {
                    self.pool.put(v);
                }
            }
        }
        self.queue.close();
        self.publish();
        Ok(())
    }
}
