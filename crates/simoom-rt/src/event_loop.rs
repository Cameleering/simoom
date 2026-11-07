//! One event loop: its driver, buffer pool, timer wheel, connections and task queue, and the
//! contexts handed to handlers.

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
use std::sync::{Arc, Mutex};
use std::time::Duration;

const LISTENER_BIT: u64 = 1 << 63;
const UDP_BIT: u64 = 1 << 62;

/// A task run on a loop thread.
pub(crate) type Task = Box<dyn FnOnce(&mut LoopCtx<'_>) + Send>;

pub(crate) struct Queue {
    tasks: Mutex<Vec<Task>>,
    pub(crate) waker: Waker,
    closed: AtomicBool,
}

impl Queue {
    pub(crate) fn new(waker: Waker) -> Queue {
        Queue { tasks: Mutex::new(Vec::new()), waker, closed: AtomicBool::new(false) }
    }

    fn push(&self, t: Task) -> bool {
        {
            let mut q = self.tasks.lock().unwrap();
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            q.push(t);
        }
        self.waker.wake();
        true
    }

    fn take(&self, into: &mut Vec<Task>) {
        let mut q = self.tasks.lock().unwrap();
        std::mem::swap(&mut *q, into);
    }

    fn close(&self) {
        let mut q = self.tasks.lock().unwrap();
        self.closed.store(true, Ordering::Release);
        q.clear();
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
        self.queue.push(Box::new(f))
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
        self.queue.push(Box::new(move |lcx: &mut LoopCtx<'_>| lcx.core.deliver(key, msg)))
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
        self.queue.push(Box::new(move |lcx: &mut LoopCtx<'_>| lcx.core.deliver_udp(idx, msg)))
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
}

pub(crate) struct ListenerSlot {
    pub(crate) acceptor: Arc<dyn Acceptor>,
    /// The socket this loop accepts on, if it has one (all loops on Linux; loop 0 elsewhere).
    pub(crate) socket: Option<Socket>,
    /// One socket shared by all loops (accepted connections are handed out), rather than one
    /// `SO_REUSEPORT` socket per loop.
    handoff: bool,
    id: Option<Id>,
}

impl ListenerSlot {
    pub(crate) fn new(acceptor: Arc<dyn Acceptor>, socket: Option<Socket>, handoff: bool) -> ListenerSlot {
        ListenerSlot { acceptor, socket, handoff, id: None }
    }
}

pub(crate) struct UdpSlot {
    pub(crate) service: Arc<dyn UdpService>,
    pub(crate) binding: usize,
    pub(crate) socket: Option<Socket>,
    id: Option<Id>,
    local: Option<SocketAddr>,
}

impl UdpSlot {
    pub(crate) fn new(service: Arc<dyn UdpService>, binding: usize, socket: Socket) -> UdpSlot {
        UdpSlot { service, binding, socket: Some(socket), id: None, local: None }
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
    accepted: u64,
    rejected: u64,
    closed: u64,
}

impl Core {
    fn conn(&mut self, key: u64) -> &mut Conn {
        self.conns.get_mut(key).expect("connection exists during its callback")
    }

    fn deadline_tick(&self, after: Duration) -> u64 {
        let at = self.now_ns.saturating_add(after.as_nanos().min(u64::MAX as u128) as u64);
        at.div_ceil(self.tick_ns)
    }

    /// Calls `f` with the connection's handler and a context; puts the handler back after.
    fn with_conn(&mut self, key: u64, f: impl FnOnce(&mut dyn Connection, &mut Ctx<'_>)) {
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
        let Some(slot) = self.endpoints.get_mut(idx) else { return };
        let Some(mut ep) = slot.take() else { return };
        {
            let mut cx = UdpCtx { core: self, idx };
            f(&mut *ep, &mut cx);
        }
        self.endpoints[idx] = Some(ep);
    }

    pub(crate) fn deliver(&mut self, key: u64, msg: Message) {
        self.with_conn(key, |h, cx| h.on_message(cx, msg));
    }

    pub(crate) fn deliver_udp(&mut self, idx: usize, msg: Message) {
        self.with_udp(idx, |h, cx| h.on_message(cx, msg));
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
        });
        debug_assert_eq!(k, key);
        self.driver.recv(id, true);
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
            self.core.close_now(self.key, CloseReason::Closed);
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
    /// timer tick). Timers of a closed connection are ignored when they fire.
    pub fn set_timer(&mut self, after: Duration, token: u64) -> TimerId {
        let at = self.core.deadline_tick(after);
        self.core.timers.insert(at, TimerTarget::Conn(self.key, token))
    }

    /// Cancels a timer. Returns whether it was still pending.
    pub fn cancel_timer(&mut self, id: TimerId) -> bool {
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
pub(crate) fn build(setup: LoopSetup) -> io::Result<(Core, Arc<Queue>)> {
    let cfg = setup.cfg;
    let mut driver = Driver::new(&cfg.driver)?;
    driver.set_buffer_target(cfg.recv_buffers);
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
        endpoints: setup.udps.iter().map(|_| None).collect(),
        udps: setup.udps,
        redeliver: Vec::new(),
        drains: Vec::new(),
        rr: setup.index,
        accepted: 0,
        rejected: 0,
        closed: 0,
        cfg,
    };
    Ok((core, queue))
}

impl Core {
    pub(crate) fn set_peers(&mut self, peers: Vec<LoopHandle>) {
        self.peers = peers;
    }

    pub(crate) fn backend(&self) -> (simoom_sys::driver::Backend, Option<String>) {
        (self.driver.backend(), self.driver.fallback_reason().map(str::to_string))
    }

    fn start_io(&mut self) -> io::Result<()> {
        for i in 0..self.listeners.len() {
            if let Some(s) = self.listeners[i].socket.take() {
                self.listeners[i].id = Some(self.driver.listen(s, LISTENER_BIT | i as u64)?);
            }
        }
        for i in 0..self.udps.len() {
            if let Some(s) = self.udps[i].socket.take() {
                let local = s.local_addr().ok();
                let id = self.driver.udp(s, UDP_BIT | i as u64)?;
                self.driver.recv(id, true);
                let info = UdpInfo { binding: self.udps[i].binding, loop_index: self.index, local_addr: local.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()) };
                let ep = self.udps[i].service.endpoint(&info);
                let slot = &mut self.udps[i];
                slot.id = Some(id);
                slot.local = local;
                self.endpoints[i] = Some(ep);
            }
        }
        Ok(())
    }

    /// Picks the loop for a connection accepted on a shared listener: the less busy of two
    /// (power of two choices), starting from a rotating position.
    fn pick_loop(&mut self) -> usize {
        let n = self.peers.len();
        if n <= 1 {
            return self.index;
        }
        self.rr = (self.rr + 1) % n;
        let a = self.rr;
        let b = (a + 1 + self.rr * 7 % (n - 1).max(1)) % n;
        let la = self.shared.loop_active[a].load(Ordering::Relaxed);
        let lb = self.shared.loop_active[b].load(Ordering::Relaxed);
        if lb < la {
            b
        } else {
            a
        }
    }

    fn dispatch(&mut self, ev: Event) {
        match ev {
            Event::Accepted { key, socket, peer } => {
                let li = (key & !LISTENER_BIT) as usize;
                let handoff = self.listeners.get(li).is_some_and(|l| l.handoff);
                let target = if handoff { self.pick_loop() } else { self.index };
                if target == self.index {
                    self.adopt(socket, peer, li);
                } else {
                    let ok = self.peers[target].run(move |lcx| lcx.core.adopt(socket, peer, li));
                    if !ok {
                        self.rejected += 1;
                    }
                }
            }
            Event::Data { key, buf } => self.on_data(key, buf),
            Event::Eof { key } => self.with_conn(key, |h, cx| {
                if !cx.is_closing() {
                    h.on_eof(cx)
                }
            }),
            Event::Error { key, error } => {
                if key & (LISTENER_BIT | UDP_BIT) != 0 {
                    return; // accept errors (EMFILE...) and UDP noise: keep serving
                }
                self.close_now(key, CloseReason::Error(error));
            }
            Event::Sent { key, buf } => self.on_sent(key, buf),
            Event::Closed { key } => self.on_closed(key),
            Event::Datagram { key, buf, meta } => {
                let idx = (key & !UDP_BIT) as usize;
                let data = buf;
                self.with_udp(idx, |h, cx| h.on_datagram(cx, &data, &meta));
                self.pool.put(data);
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
            self.pool.put(buf);
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
        if c.input.as_ref().map_or(0, |i| i.len()) > max_input {
            self.close_now(key, CloseReason::InputLimit);
            return;
        }
        if c.user_paused {
            return;
        }
        self.call_data(key);
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
                self.close_now(key, CloseReason::Closed);
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
        if key & UDP_BIT != 0 {
            let i = (key & !UDP_BIT) as usize;
            if let Some(u) = self.udps.get_mut(i) {
                u.id = None;
                self.endpoints[i] = None;
            }
            return;
        }
        let Some(mut c) = self.conns.remove(key) else { return };
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
            }
        }
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
        self.shared.loop_active[self.index].store(self.conns.len, Ordering::Relaxed);
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
        for i in 0..self.udps.len() {
            self.with_udp(i, |h, cx| h.on_stop(cx));
        }
    }

    /// Runs the loop until the runtime stops and every connection is gone.
    pub(crate) fn run(&mut self) -> io::Result<()> {
        self.start_io()?;
        let mut events = Vec::with_capacity(256);
        let mut tasks: Vec<Task> = Vec::new();
        let mut stop_at: Option<u64> = None;
        let mut aborted = false;
        let recv_size = self.cfg.buffer_classes[0];
        loop {
            self.now_ns = simoom_sys::time::now_ns();
            self.fire_timers();
            self.after_callbacks();
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
            self.driver.turn(timeout, &mut events)?;
            self.now_ns = simoom_sys::time::now_ns();
            let mut woke = false;
            for ev in events.drain(..) {
                if matches!(ev, Event::Wake) {
                    woke = true;
                }
                self.dispatch(ev);
            }
            if woke {
                self.queue.take(&mut tasks);
                for t in tasks.drain(..) {
                    let mut lcx = LoopCtx { core: self };
                    t(&mut lcx);
                }
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
                }
                let listeners_open = self.listeners.iter().any(|l| l.id.is_some());
                if self.conns.len == 0 && !listeners_open {
                    for i in 0..self.udps.len() {
                        if let Some(id) = self.udps[i].id.take() {
                            self.driver.close(id);
                        }
                    }
                    break;
                }
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
