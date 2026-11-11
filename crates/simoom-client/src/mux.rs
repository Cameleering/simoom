//! A multiplexed connection (HTTP/2 or HTTP/3) shared by many threads.
//!
//! The protocol state (a sans-io engine behind [`Proto`]) lives under the connection lock, taken
//! for short sections: opening a stream, feeding received bytes, handing back flow-control
//! credit. Each stream has a slot with its own lock and condition variable; received headers,
//! body bytes and trailers are moved into it, and the requesting thread reads and waits there.
//!
//! With one stream in flight the waiting thread reads the socket itself (no hand-off). With two
//! or more, a pump thread reads for all of them and wakes only the threads whose streams
//! changed; it exits once fewer than two streams are open, so an idle connection has no thread.
//! Output is queued under the lock and written after it is released by whichever thread holds
//! the write lock; others leave their bytes for it (`Guard`), so frames ready together go out
//! in one write.

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::transport::{earliest, is_timeout};
use crate::types::{Headers, Version};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

/// What a protocol engine reports.
#[derive(Debug)]
pub(crate) enum MuxEvent {
    Head { id: u64, status: u16, headers: Headers },
    Readable(u64),
    Trailers { id: u64, trailers: Headers },
    End(u64),
    Reset { id: u64, code: u64 },
    Writable(u64),
    #[cfg_attr(not(feature = "client-h2"), allow(dead_code))]
    Pong,
    GoAway,
    Closed(Error),
}

/// A request head for [`Proto::open`]: pseudo-fields and lower-case regular fields.
pub(crate) struct ReqHead<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A sans-io protocol engine driven by [`Mux`].
pub(crate) trait Proto: Send {
    fn version(&self) -> Version;
    /// Opens a stream with a request head.
    fn open(&mut self, head: &ReqHead<'_>, end: bool) -> Result<u64>;
    /// Opens an extended CONNECT stream (RFC 8441) for `protocol`.
    #[cfg_attr(not(feature = "client-ws"), allow(dead_code))]
    fn open_extended(&mut self, protocol: &str, head: &ReqHead<'_>) -> Result<u64> {
        let _ = (protocol, head);
        Err(Error::new(ErrorKind::Unsupported, "extended CONNECT is not available on this protocol"))
    }
    /// Whether the peer allows extended CONNECT: `None` until its SETTINGS arrived.
    #[cfg_attr(not(feature = "client-ws"), allow(dead_code))]
    fn extended_connect(&self) -> Option<bool> {
        Some(false)
    }
    /// Sends body bytes; returns how many were accepted (flow control).
    fn send_data(&mut self, id: u64, data: &[u8], end: bool) -> Result<usize>;
    /// Bytes `id` could send now.
    fn capacity(&self, id: u64) -> usize;
    fn send_trailers(&mut self, id: u64, trailers: &[(Vec<u8>, Vec<u8>)]) -> Result<()>;
    /// Abandons a stream (RST_STREAM / STOP_SENDING).
    fn cancel(&mut self, id: u64);
    /// Drops what is kept for a finished stream.
    fn forget(&mut self, id: u64);
    /// Appends up to `max` received body bytes of `id` to `out` without returning
    /// flow-control credit (see [`Proto::release`]); may produce events (end of stream).
    fn take_body(&mut self, id: u64, out: &mut Vec<u8>, max: usize, now: Instant, ev: &mut Vec<MuxEvent>) -> usize;
    /// The application consumed `n` body bytes of `id`: the peer may send more.
    fn release(&mut self, id: u64, n: usize) {
        let _ = (id, n);
    }
    /// Feeds received bytes or a datagram.
    fn input(&mut self, data: &mut [u8], from: Option<SocketAddr>, now: Instant, io: &MuxIo, ev: &mut Vec<MuxEvent>);
    /// Writes pending output to the transport.
    fn flush(&mut self, io: &MuxIo, now: Instant) -> io::Result<()>;
    /// Received body bytes of `id` not yet read, when the engine knows (`None`: unknown).
    fn buffered(&self, id: u64) -> Option<usize> {
        let _ = id;
        None
    }
    /// Moves pending output to `out` (stream transports: the connection writes it after
    /// releasing its lock).
    fn take_output(&mut self, out: &mut Vec<u8>) {
        let _ = out;
    }
    /// When [`Proto::timeout`] must run.
    fn deadline(&mut self) -> Option<Instant>;
    fn timeout(&mut self, now: Instant, ev: &mut Vec<MuxEvent>);
    /// Sends a PING; true when a [`MuxEvent::Pong`] will answer it (HTTP/2). QUIC PINGs are
    /// answered by ACKs the transport handles, and the QUIC idle timeout closes a dead path.
    fn ping(&mut self) -> bool;
    /// Whether another stream may be opened now.
    fn can_open(&self) -> bool;
    /// The peer's limit on concurrent streams, as far as known.
    fn max_streams(&self) -> usize {
        100
    }
    /// Whether the connection accepts no more streams ever (closed or going away).
    fn is_done(&self) -> bool;
    /// Whether the handshake (TLS/QUIC and SETTINGS) is complete enough to send requests.
    fn ready(&self) -> bool {
        true
    }
    fn close(&mut self, now: Instant);
}

/// The transport of a multiplexed connection.
pub(crate) enum MuxIo {
    #[cfg_attr(not(feature = "client-h2"), allow(dead_code))]
    Tcp(crate::transport::Duplex),
    #[cfg(feature = "client-h3")]
    Udp(std::net::UdpSocket),
}

impl MuxIo {
    fn read(&self, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<(usize, Option<SocketAddr>)> {
        match self {
            MuxIo::Tcp(d) => d.read(buf, timeout).map(|n| (n, None)),
            #[cfg(feature = "client-h3")]
            MuxIo::Udp(s) => {
                let _ = s.set_read_timeout(Some(timeout.unwrap_or(Duration::from_secs(3600)).max(Duration::from_millis(1))));
                s.recv_from(buf).map(|(n, a)| (n, Some(a)))
            }
        }
    }

    fn is_stream(&self) -> bool {
        matches!(self, MuxIo::Tcp(_))
    }

    pub(crate) fn duplex(&self) -> Option<&crate::transport::Duplex> {
        match self {
            MuxIo::Tcp(d) => Some(d),
            #[cfg(feature = "client-h3")]
            MuxIo::Udp(_) => None,
        }
    }
}

/// Body bytes kept per stream before the rest is left in the engine (flow control then holds
/// the sender back).
const SLOT_CAP: usize = 256 * 1024;
/// Longest single wait on a condition variable; wake-ups are targeted, this only bounds a
/// missed hand-off.
const MAX_WAIT: Duration = Duration::from_millis(20);

/// What one stream has received. Its own lock and condition variable: the requesting thread
/// waits here without touching the connection lock.
#[derive(Default)]
pub(crate) struct Slot {
    st: Mutex<SlotSt>,
    cv: Condvar,
}

#[derive(Default)]
struct SlotSt {
    status: u16,
    headers: Option<Headers>,
    data: Vec<u8>,
    pos: usize,
    /// The engine may hold more body bytes than were moved here.
    more: bool,
    /// The engine reported the end of the response.
    end: bool,
    trailers: Option<Headers>,
    error: Option<Error>,
    writable: bool,
    waiting: bool,
}

impl Slot {
    fn lock(&self) -> MutexGuard<'_, SlotSt> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }
}

pub(crate) struct State {
    proto: Box<dyn Proto>,
    reading: bool,
    dead: Option<Error>,
    pongs: u64,
    pub(crate) requests: u64,
    evs: Vec<MuxEvent>,
    /// Threads waiting on [`Mux::cv`] (no stream of their own: open, ping, handshake).
    any_waiting: u32,
    /// Output waiting to be written once the lock is released (stream transports).
    wbuf: Vec<u8>,
}

type SlotMap = HashMap<u64, Arc<Slot>, std::hash::BuildHasherDefault<crate::pool::FxHasher>>;

/// A multiplexed connection.
pub(crate) struct Mux {
    io: MuxIo,
    state: Mutex<State>,
    cv: Condvar,
    slots: RwLock<SlotMap>,
    /// Streams open (opened and not finished).
    active: AtomicUsize,
    /// The pump thread is running.
    pump: AtomicBool,
    dead: AtomicBool,
    /// The engine accepts no new streams (GOAWAY, closed); kept outside the lock for the pool.
    going_away: AtomicBool,
    /// The peer's concurrent-stream limit, as last seen.
    limit: AtomicUsize,
    /// Mirror of `State::any_waiting`, to skip a lock when nobody waits.
    any_hint: AtomicUsize,
    /// Finished streams whose engine state is dropped at the next connection-lock section.
    retire: Mutex<Vec<u64>>,
    idle_since: Mutex<Instant>,
    rbuf: Mutex<Vec<u8>>,
    /// Held by the thread writing; others leave their bytes for it (batched writes).
    wlock: Mutex<()>,
    version: Version,
    what: String,
    /// A weak reference to the `Arc` this connection lives in, for the pump thread.
    me: std::sync::OnceLock<std::sync::Weak<Mux>>,
}

impl std::fmt::Debug for Mux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mux").field("what", &self.what).finish()
    }
}

impl Mux {
    pub(crate) fn new(io: MuxIo, proto: Box<dyn Proto>, what: String) -> Mux {
        let now = Instant::now();
        let rlen = if io.is_stream() { 64 * 1024 } else { 65536 };
        let version = proto.version();
        Mux {
            io,
            version,
            state: Mutex::new(State { proto, reading: false, dead: None, pongs: 0, requests: 0, evs: Vec::new(), any_waiting: 0, wbuf: Vec::new() }),
            cv: Condvar::new(),
            slots: RwLock::new(SlotMap::default()),
            active: AtomicUsize::new(0),
            pump: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            going_away: AtomicBool::new(false),
            limit: AtomicUsize::new(100),
            any_hint: AtomicUsize::new(0),
            retire: Mutex::new(Vec::new()),
            idle_since: Mutex::new(now),
            rbuf: Mutex::new(vec![0u8; rlen]),
            wlock: Mutex::new(()),
            what,
            me: std::sync::OnceLock::new(),
        }
    }

    /// The connection in an `Arc`, able to start its pump thread.
    pub(crate) fn into_arc(self) -> Arc<Mux> {
        let a = Arc::new(self);
        let _ = a.me.set(Arc::downgrade(&a));
        a
    }

    fn lock(&self) -> Guard<'_> {
        Guard { g: Some(self.state.lock().unwrap_or_else(|p| p.into_inner())), mux: self }
    }

    fn slot(&self, id: u64) -> Option<Arc<Slot>> {
        self.slots.read().unwrap_or_else(|p| p.into_inner()).get(&id).cloned()
    }

    pub(crate) fn version(&self) -> Version {
        self.version
    }

    /// For the pool: (finished for good or idle past `idle_limit`, can open a stream now).
    pub(crate) fn usable(&self, idle_limit: Duration) -> (bool, bool) {
        if self.dead.load(Ordering::Acquire) || self.going_away.load(Ordering::Acquire) {
            return (true, false);
        }
        let active = self.active.load(Ordering::Acquire);
        let idle = active == 0 && self.idle_since.lock().unwrap_or_else(|p| p.into_inner()).elapsed() >= idle_limit;
        (idle, !idle && active < self.limit.load(Ordering::Acquire))
    }

    /// Whether the connection is finished for good.
    pub(crate) fn is_dead(&self) -> bool {
        if self.dead.load(Ordering::Acquire) {
            return true;
        }
        let st = self.lock();
        st.dead.is_some() || st.proto.is_done()
    }

    /// Streams open on this connection.
    pub(crate) fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn idle_for(&self) -> Option<Duration> {
        if self.active.load(Ordering::Acquire) == 0 {
            Some(self.idle_since.lock().unwrap_or_else(|p| p.into_inner()).elapsed())
        } else {
            None
        }
    }

    /// Moves the engine's output into the write buffer (stream transports) or sends it (UDP).
    fn flush(&self, st: &mut State) {
        if st.dead.is_some() {
            return;
        }
        if self.io.is_stream() {
            let mut out = std::mem::take(&mut st.wbuf);
            st.proto.take_output(&mut out);
            st.wbuf = out;
            return;
        }
        if let Err(e) = st.proto.flush(&self.io, Instant::now()) {
            st.dead = Some(Error::io(&e, &self.what));
            self.fail_all(st);
        }
    }

    fn fail_all(&self, st: &mut State) {
        let e = st.dead.clone().unwrap_or_else(|| Error::new(ErrorKind::Closed, format!("connection closed: {}", self.what)));
        self.dead.store(true, Ordering::Release);
        for s in self.slots.read().unwrap_or_else(|p| p.into_inner()).values() {
            let mut g = s.lock();
            if !g.end && g.error.is_none() {
                g.error = Some(e.clone());
            }
            drop(g);
            s.cv.notify_all();
        }
        if st.any_waiting > 0 {
            self.cv.notify_all();
        }
    }

    /// Drops the engine state of finished streams (deferred from `finish`).
    fn retire(&self, st: &mut State) {
        let ids = std::mem::take(&mut *self.retire.lock().unwrap_or_else(|p| p.into_inner()));
        for id in ids {
            st.proto.forget(id);
        }
    }

    /// Moves body bytes of `id` from the engine into its slot (up to the slot cap).
    fn pull(&self, st: &mut State, id: u64, s: &mut SlotSt, now: Instant) {
        if s.pos > 0 && s.pos == s.data.len() {
            s.data.clear();
            s.pos = 0;
        }
        let room = SLOT_CAP.saturating_sub(s.data.len() - s.pos);
        if room == 0 {
            s.more = true;
            return;
        }
        let mut evs = std::mem::take(&mut st.evs);
        let n = st.proto.take_body(id, &mut s.data, room, now, &mut evs);
        // bytes in the slot count as delivered: the slot cap bounds them, and the credit goes
        // back now (holding it until the application reads starves other streams)
        if n > 0 {
            st.proto.release(id, n);
        }
        // events produced while reading (HTTP/3 end of stream) are handled by the caller
        st.evs.append(&mut evs);
        s.more = n == room || st.proto.buffered(id).is_some_and(|b| b > 0);
    }

    fn dispatch(&self, st: &mut State, now: Instant) {
        let mut wake_any = false;
        while !st.evs.is_empty() {
            let evs = std::mem::take(&mut st.evs);
            for ev in evs {
                let id = match &ev {
                    MuxEvent::Head { id, .. } | MuxEvent::Trailers { id, .. } | MuxEvent::Reset { id, .. } => Some(*id),
                    MuxEvent::Readable(id) | MuxEvent::End(id) | MuxEvent::Writable(id) => Some(*id),
                    _ => None,
                };
                let Some(id) = id else {
                    match ev {
                        MuxEvent::Pong => {
                            st.pongs += 1;
                            wake_any = true;
                        }
                        MuxEvent::GoAway => wake_any = true,
                        MuxEvent::Closed(e) => {
                            if st.dead.is_none() {
                                st.dead = Some(e);
                            }
                            self.fail_all(st);
                        }
                        _ => {}
                    }
                    continue;
                };
                let Some(slot) = self.slot(id) else { continue };
                let mut s = slot.lock();
                match ev {
                    MuxEvent::Head { status, headers, .. } => {
                        if s.headers.is_none() {
                            s.status = status;
                            s.headers = Some(headers);
                        }
                    }
                    MuxEvent::Readable(_) => self.pull(st, id, &mut s, now),
                    MuxEvent::Trailers { trailers, .. } => s.trailers = Some(trailers),
                    MuxEvent::End(_) => s.end = true,
                    MuxEvent::Reset { code, .. } => {
                        // a complete response followed by a reset (RFC 9113 §8.1) is kept
                        if !s.end {
                            s.error = Some(Error::new(ErrorKind::Reset(code), format!("stream reset by the peer (code {code:#x}): {}", self.what)));
                        }
                    }
                    MuxEvent::Writable(_) => s.writable = true,
                    _ => {}
                }
                let wake = s.waiting;
                drop(s);
                if wake {
                    slot.cv.notify_all();
                }
            }
        }
        if wake_any && st.any_waiting > 0 {
            self.cv.notify_all();
        }
    }

    /// Reads the transport once (until `deadline` or the engine's next timer), feeds the
    /// engine and wakes the threads whose streams were touched.
    fn read_once<'a>(&'a self, mut st: Guard<'a>, deadline: Option<Instant>) -> Guard<'a> {
        let now = Instant::now();
        self.retire(&mut st);
        self.flush(&mut st);
        st.reading = true;
        let until = earliest(deadline, st.proto.deadline());
        drop(st);
        let t = until.map(|u| u.saturating_duration_since(now).max(Duration::from_millis(1)));
        let mut buf = self.rbuf.lock().unwrap_or_else(|p| p.into_inner());
        let r = self.io.read(&mut buf, t);
        let mut st = self.lock();
        st.reading = false;
        let now = Instant::now();
        match r {
            Ok((0, _)) if self.io.is_stream() => {
                if st.dead.is_none() {
                    st.dead = Some(Error::new(ErrorKind::Closed, format!("connection closed by the peer: {}", self.what)));
                }
                self.fail_all(&mut st);
            }
            Ok((n, from)) => {
                let mut evs = std::mem::take(&mut st.evs);
                st.proto.input(&mut buf[..n], from, now, &self.io, &mut evs);
                st.evs = evs;
                drop(buf);
                self.dispatch(&mut st, now);
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                if st.dead.is_none() {
                    st.dead = Some(if e.kind() == io::ErrorKind::InvalidData { Error::new(ErrorKind::Tls, format!("{e}: {}", self.what)) } else { Error::io(&e, &self.what) });
                }
                self.fail_all(&mut st);
            }
        }
        if st.proto.deadline().is_some_and(|d| d <= now) {
            let mut evs = std::mem::take(&mut st.evs);
            st.proto.timeout(now, &mut evs);
            st.evs = evs;
            self.dispatch(&mut st, now);
        }
        self.flush(&mut st);
        self.limit.store(st.proto.max_streams(), Ordering::Release);
        if st.proto.is_done() {
            self.going_away.store(true, Ordering::Release);
        }
        if st.any_waiting > 0 {
            // openers waiting for capacity or SETTINGS, pings, handshakes
            self.cv.notify_all();
        }
        st
    }

    /// One step for a thread whose answer is not there yet: start the pump (two or more
    /// streams), read the socket itself (one stream), or wait for the thread that reads.
    fn step(&self, deadline: Option<Instant>) {
        let mut st = self.lock();
        if st.dead.is_some() {
            return;
        }
        if self.active.load(Ordering::Acquire) >= 2 {
            // the pump reads; fall through and wait for it (returning here would make a
            // thread with no stream of its own, such as an opener, spin)
            self.start_pump();
        }
        if st.reading || self.pump.load(Ordering::Acquire) {
            st.any_waiting += 1;
            self.any_hint.fetch_add(1, Ordering::AcqRel);
            let t = deadline.map_or(MAX_WAIT, |d| d.saturating_duration_since(Instant::now()).min(MAX_WAIT));
            st.wait_on(&self.cv, t.max(Duration::from_millis(1)));
            st.any_waiting = st.any_waiting.saturating_sub(1);
            self.any_hint.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        drop(self.read_once(st, deadline));
    }

    /// Waits on a stream's slot until `f` answers.
    fn wait_slot<T>(&self, slot: &Slot, deadline: Option<Instant>, kind: TimeoutKind, mut f: impl FnMut(&mut SlotSt) -> Option<Result<T>>) -> Result<T> {
        loop {
            {
                let mut s = slot.lock();
                if let Some(r) = f(&mut s) {
                    return r;
                }
                if let Some(e) = s.error.clone() {
                    return Err(e);
                }
                if self.dead.load(Ordering::Acquire) {
                    drop(s);
                    let st = self.lock();
                    return Err(st.dead.clone().unwrap_or_else(|| Error::new(ErrorKind::Closed, format!("connection closed: {}", self.what))));
                }
                let now = Instant::now();
                if deadline.is_some_and(|d| now >= d) {
                    return Err(Error::timeout(kind, &self.what));
                }
                if self.pump.load(Ordering::Acquire) {
                    s.waiting = true;
                    let t = deadline.map_or(MAX_WAIT, |d| d.saturating_duration_since(now).min(MAX_WAIT));
                    let mut s = slot.cv.wait_timeout(s, t.max(Duration::from_millis(1))).unwrap_or_else(|p| p.into_inner()).0;
                    s.waiting = false;
                    continue;
                }
            }
            self.step(deadline);
        }
    }

    /// Waits on the connection (no stream of its own) until `f` answers.
    fn wait_conn<T>(&self, deadline: Option<Instant>, kind: TimeoutKind, mut f: impl FnMut(&mut State) -> Option<Result<T>>) -> Result<T> {
        loop {
            {
                let mut st = self.lock();
                self.retire(&mut st);
                if let Some(r) = f(&mut st) {
                    return r;
                }
                if let Some(e) = &st.dead {
                    return Err(e.clone());
                }
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Err(Error::timeout(kind, &self.what));
            }
            self.step(deadline);
        }
    }

    /// Starts the pump thread if it is not running; false if it cannot.
    fn start_pump(&self) -> bool {
        if self.pump.load(Ordering::Acquire) {
            return true;
        }
        let Some(me) = self.me.get().and_then(|w| w.upgrade()) else { return false };
        if self.pump.swap(true, Ordering::AcqRel) {
            return true;
        }
        let ok = std::thread::Builder::new().name("simoom-client-mux".into()).spawn(move || me.pump()).is_ok();
        if !ok {
            self.pump.store(false, Ordering::Release);
        }
        ok
    }

    /// The pump: reads while at least two streams are open, then exits and wakes the waiting
    /// threads so one of them reads again.
    fn pump(&self) {
        loop {
            let st = self.lock();
            if st.dead.is_some() || self.active.load(Ordering::Acquire) < 2 {
                self.pump.store(false, Ordering::Release);
                drop(st);
                for s in self.slots.read().unwrap_or_else(|p| p.into_inner()).values() {
                    let w = s.lock().waiting;
                    if w {
                        s.cv.notify_all();
                    }
                }
                self.cv.notify_all();
                return;
            }
            if st.reading {
                // a requesting thread is in a read it started before the pump existed
                let mut st = st;
                st.any_waiting += 1;
                st.wait_on(&self.cv, MAX_WAIT);
                st.any_waiting = st.any_waiting.saturating_sub(1);
                continue;
            }
            drop(self.read_once(st, Some(Instant::now() + Duration::from_millis(50))));
        }
    }

    #[cfg(feature = "client-h3")]
    /// Sends whatever the engine has queued (the first flight of a new connection).
    pub(crate) fn kick(&self) {
        let mut st = self.lock();
        self.flush(&mut st);
    }

    #[cfg(feature = "client-h3")]
    /// Waits for the handshake (QUIC + SETTINGS).
    pub(crate) fn wait_ready(&self, deadline: Option<Instant>, kind: TimeoutKind) -> Result<()> {
        self.wait_conn(deadline, kind, |st| if st.proto.ready() { Some(Ok(())) } else { None })
    }

    /// Registers a stream the engine opened by itself (stream 1 after an h2c upgrade) and
    /// feeds bytes that arrived with the upgrade answer.
    #[cfg(feature = "h2c-upgrade")]
    pub(crate) fn adopt(&self, id: u64, input: &[u8]) {
        let mut st = self.lock();
        self.register(&mut st, id);
        if !input.is_empty() {
            let mut data = input.to_vec();
            let mut evs = std::mem::take(&mut st.evs);
            st.proto.input(&mut data, None, Instant::now(), &self.io, &mut evs);
            st.evs = evs;
            self.dispatch(&mut st, Instant::now());
        }
        self.flush(&mut st);
    }

    fn register(&self, st: &mut State, id: u64) {
        self.slots.write().unwrap_or_else(|p| p.into_inner()).insert(id, Arc::new(Slot::default()));
        self.active.fetch_add(1, Ordering::AcqRel);
        st.requests += 1;
    }

    /// Opens a stream, waiting for a free slot until `deadline`.
    pub(crate) fn open(&self, head: &ReqHead<'_>, end: bool, deadline: Option<Instant>) -> Result<u64> {
        self.wait_conn(deadline, TimeoutKind::Pool, |st| {
            if st.dead.is_some() {
                return None;
            }
            if st.proto.is_done() {
                return Some(Err(Error::new(ErrorKind::Closed, format!("connection is going away: {}", self.what))));
            }
            if !st.proto.ready() || !st.proto.can_open() {
                return None;
            }
            let r = st.proto.open(head, end);
            Some(r.map(|id| {
                self.register(st, id);
                self.flush(st);
                id
            }))
        })
    }

    /// Opens an extended CONNECT stream (WebSocket over HTTP/2), once the peer's SETTINGS
    /// say it may.
    #[cfg(feature = "client-ws")]
    pub(crate) fn open_extended(&self, protocol: &str, head: &ReqHead<'_>, deadline: Option<Instant>) -> Result<u64> {
        self.wait_conn(deadline, TimeoutKind::Connect, |st| {
            if st.dead.is_some() {
                return None;
            }
            match st.proto.extended_connect() {
                None => None,
                Some(false) => Some(Err(Error::new(ErrorKind::Unsupported, format!("the server does not allow extended CONNECT (RFC 8441): {}", self.what)))),
                Some(true) if !st.proto.can_open() => None,
                Some(true) => Some(st.proto.open_extended(protocol, head).map(|id| {
                    self.register(st, id);
                    self.flush(st);
                    id
                })),
            }
        })
    }

    /// Sends body bytes, waiting for flow-control credit.
    pub(crate) fn write(&self, id: u64, data: &[u8], end: bool, deadline: Option<Instant>) -> Result<()> {
        let slot = self.slot(id).ok_or_else(|| Error::new(ErrorKind::Closed, "stream closed"))?;
        let mut off = 0;
        loop {
            {
                let mut st = self.lock();
                if let Some(e) = &st.dead {
                    return Err(e.clone());
                }
                if let Some(e) = slot.lock().error.clone() {
                    return Err(e);
                }
                slot.lock().writable = false;
                let n = st.proto.send_data(id, &data[off..], end)?;
                off += n;
                self.flush(&mut st);
                if off == data.len() {
                    return Ok(());
                }
                if st.proto.capacity(id) > 0 {
                    continue;
                }
            }
            self.wait_slot(&slot, deadline, TimeoutKind::Idle, |s| if s.writable || s.end { Some(Ok(())) } else { None })?;
        }
    }

    pub(crate) fn send_trailers(&self, id: u64, trailers: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let mut st = self.lock();
        st.proto.send_trailers(id, trailers)?;
        self.flush(&mut st);
        Ok(())
    }

    /// Waits for the response head.
    pub(crate) fn head(&self, id: u64, deadline: Option<Instant>, kind: TimeoutKind) -> Result<(u16, Headers)> {
        let slot = self.slot(id).ok_or_else(|| Error::new(ErrorKind::Closed, "stream closed"))?;
        self.wait_slot(&slot, deadline, kind, |s| s.headers.take().map(|h| Ok((s.status, h))))
    }

    /// Reads body bytes; `Ok(0)` at the end. Trailers are returned once, at the end (with the
    /// last bytes when nothing more can come).
    pub(crate) fn read(&self, id: u64, out: &mut [u8], deadline: Option<Instant>, kind: TimeoutKind) -> Result<(usize, Option<Headers>)> {
        let slot = self.slot(id).ok_or_else(|| Error::new(ErrorKind::Closed, "stream closed"))?;
        loop {
            let mut pull = false;
            let r = {
                let mut s = slot.lock();
                if s.pos < s.data.len() {
                    let n = (s.data.len() - s.pos).min(out.len());
                    out[..n].copy_from_slice(&s.data[s.pos..s.pos + n]);
                    s.pos += n;
                    let done = s.pos == s.data.len() && s.end && !s.more;
                    let t = if done { Some(s.trailers.take().unwrap_or_default()) } else { None };
                    Some(Ok((n, t)))
                } else if s.more {
                    pull = true;
                    None
                } else if s.end {
                    Some(Ok((0, Some(s.trailers.take().unwrap_or_default()))))
                } else {
                    None
                }
            };
            if pull {
                let mut st = self.lock();
                let mut s = slot.lock();
                self.pull(&mut st, id, &mut s, Instant::now());
                drop(s);
                if !st.evs.is_empty() {
                    self.dispatch(&mut st, Instant::now());
                }
                self.flush(&mut st);
            }
            if let Some(r) = r {
                return r;
            }
            if pull {
                continue;
            }
            self.wait_slot(&slot, deadline, kind, |s| if s.pos < s.data.len() || s.more || s.end { Some(Ok(())) } else { None })?;
        }
    }

    /// Forgets a stream (cancelling it if it is still open).
    pub(crate) fn finish(&self, id: u64) {
        let Some(slot) = self.slots.write().unwrap_or_else(|p| p.into_inner()).remove(&id) else { return };
        let complete = {
            let s = slot.lock();
            s.end && s.error.is_none() && !s.more
        };
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.idle_since.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
        }
        if complete {
            // the engine already closed the stream; its leftovers go at the next lock section
            self.retire.lock().unwrap_or_else(|p| p.into_inner()).push(id);
        } else {
            let mut st = self.lock();
            st.proto.cancel(id);
            self.flush(&mut st);
        }
        if self.any_hint.load(Ordering::Acquire) > 0 {
            // a stream slot is free: a thread waiting to open one may go on
            self.cv.notify_all();
        }
    }

    /// Sends a PING and waits for its answer (keepalive on an idle connection).
    pub(crate) fn ping(&self, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();
        let target = {
            let mut st = self.lock();
            let answered = st.proto.ping();
            self.flush(&mut st);
            if !answered {
                return Ok(start.elapsed());
            }
            st.pongs + 1
        };
        let r = self.wait_conn(Some(start + timeout), TimeoutKind::Idle, |st| if st.pongs >= target { Some(Ok(())) } else { None });
        if let Err(e) = &r {
            let mut st = self.lock();
            if st.dead.is_none() {
                st.dead = Some(Error::new(e.kind.clone(), format!("keepalive PING unanswered: {}", self.what)));
            }
            self.fail_all(&mut st);
        }
        r.map(|_| start.elapsed())
    }

    pub(crate) fn close(&self) {
        let mut st = self.lock();
        st.proto.close(Instant::now());
        self.flush(&mut st);
        if st.dead.is_none() {
            st.dead = Some(Error::new(ErrorKind::Closed, format!("connection closed: {}", self.what)));
        }
        self.fail_all(&mut st);
        drop(st);
        if let Some(d) = self.io.duplex() {
            d.close();
        }
    }

    /// Writes `buf`, then whatever other threads queued meanwhile, holding the write lock.
    fn write_out(&self, w: MutexGuard<'_, ()>, mut buf: Vec<u8>) {
        loop {
            let r = match self.io.duplex() {
                Some(d) => d.write_all(&buf),
                None => Ok(()),
            };
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(e) = r {
                if st.dead.is_none() {
                    st.dead = Some(Error::io(&e, &self.what));
                }
                st.wbuf.clear();
                self.fail_all(&mut st);
                drop(w);
                return;
            }
            if st.wbuf.is_empty() {
                // released under the state lock: a thread appending now finds the lock free
                drop(w);
                buf.clear();
                if st.wbuf.capacity() == 0 {
                    st.wbuf = buf;
                }
                return;
            }
            buf.clear();
            std::mem::swap(&mut buf, &mut st.wbuf);
        }
    }
}

/// The connection lock. Output queued under it ([`State::wbuf`]) is written after it is
/// released by whichever thread holds the write lock; a thread that finds the write lock taken
/// leaves its bytes for that thread (batched writes, and the system call never runs under the
/// connection lock).
pub(crate) struct Guard<'a> {
    g: Option<MutexGuard<'a, State>>,
    mux: &'a Mux,
}

impl std::ops::Deref for Guard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.g.as_ref().unwrap_or_else(|| unreachable!("guard in use"))
    }
}

impl std::ops::DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.g.as_mut().unwrap_or_else(|| unreachable!("guard in use"))
    }
}

impl Guard<'_> {
    /// Waits on `cv` (with this lock) for at most `t`.
    fn wait_on(&mut self, cv: &Condvar, t: Duration) {
        let Some(g) = self.g.take() else { return };
        let g = cv.wait_timeout(g, t).unwrap_or_else(|p| p.into_inner()).0;
        self.g = Some(g);
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let Some(mut g) = self.g.take() else { return };
        if g.wbuf.is_empty() {
            return;
        }
        let Ok(w) = self.mux.wlock.try_lock() else {
            // another thread is writing; it picks these bytes up before it lets go
            return;
        };
        let buf = std::mem::take(&mut g.wbuf);
        drop(g);
        self.mux.write_out(w, buf);
    }
}

/// Request header fields for HTTP/2 and HTTP/3: lower-case names, connection-specific fields
/// dropped (RFC 9113 §8.2.2), `Host` folded into `:authority`.
pub(crate) fn request_fields(headers: &Headers, body_len: Option<u64>, method: &str) -> (Option<String>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut host = None;
    let mut out = Vec::with_capacity(headers.len() + 1);
    for (n, v) in headers.iter() {
        let lower = n.to_ascii_lowercase();
        match lower.as_str() {
            "host" => host = Some(String::from_utf8_lossy(v).into_owned()),
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "content-length" => {}
            "te" if !simoom_http1::has_token(v, b"trailers") => {}
            "te" => out.push((b"te".to_vec(), b"trailers".to_vec())),
            _ => out.push((lower.into_bytes(), v.to_vec())),
        }
    }
    match body_len {
        Some(0) if !matches!(method, "POST" | "PUT" | "PATCH") => {}
        Some(n) => out.push((b"content-length".to_vec(), n.to_string().into_bytes())),
        None => {}
    }
    (host, out)
}
