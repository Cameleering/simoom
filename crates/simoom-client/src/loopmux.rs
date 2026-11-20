//! The blocking client's HTTP/2 connections, run on an event loop.
//!
//! The blocking [`crate::Client`] still opens the connection itself (resolution, Happy
//! Eyeballs, proxy tunnels, TLS with ALPN, h2c), then hands the connected socket and its TLS
//! session to a loop of a private [`RtClient`], where an HTTP/2 connection pinned to it runs
//! the streams (`rt::h2`). Each request is an `RtCall` there; its response events land in a
//! per-stream slot, and the requesting thread, which waits on that slot, is woken by the loop
//! thread that read the bytes: one wake per batch of news, no pump thread, no connection lock.
//!
//! Flow control stays end to end: response credit goes back only as the caller reads
//! (`CallOptions::manual_release`), and a writer waits while the call's send buffer is full.

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::mux::ReqHead;
use crate::rt::h2::{defer, CallHandler, CallOptions, CloseMsg, Deferred, Ext, PinState, PingMsg, RawHead, RtCall};
use crate::rt::{RtClient, RtRequest};
use crate::types::{Headers, Version};
use crate::url::Url;
use simoom_rt::LoopHandle;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Response bytes handed back to the server in one release at most (credit for bytes read).
const RELEASE_BATCH: usize = 64 * 1024;

/// What one stream received, and its waiting thread.
#[derive(Default)]
struct Slot {
    st: Mutex<SlotSt>,
    cv: Condvar,
}

#[derive(Default)]
struct SlotSt {
    head: Option<(u16, Headers)>,
    data: Vec<u8>,
    pos: usize,
    /// The response ended: its trailers, or the error.
    end: Option<Result<Headers>>,
    /// Bumped when the call's send buffer drained after being full.
    writable: u64,
    /// A thread waits on `cv`.
    waiting: bool,
    /// A wake-up is deferred to the end of the loop's callback.
    queued: bool,
    /// Bytes read and not yet released to the server.
    unreleased: usize,
}

impl Slot {
    fn lock(&self) -> MutexGuard<'_, SlotSt> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Wakes the waiting thread, if there is one, once the loop's callback is over (so a head,
    /// its body and its end that arrive together wake it once).
    fn wake(self: &Arc<Self>, mut st: MutexGuard<'_, SlotSt>) {
        if !st.waiting || st.queued {
            return;
        }
        st.queued = true;
        drop(st);
        defer(self.clone());
    }

    /// Waits for news until `deadline`; false when it passed.
    fn wait<'a>(&'a self, mut st: MutexGuard<'a, SlotSt>, deadline: Option<Instant>) -> (MutexGuard<'a, SlotSt>, bool) {
        let t = match deadline {
            Some(d) => match d.checked_duration_since(Instant::now()) {
                Some(t) if !t.is_zero() => t,
                _ => return (st, false),
            },
            None => Duration::from_secs(3600),
        };
        st.waiting = true;
        let (mut st, _) = self.cv.wait_timeout(st, t).unwrap_or_else(|p| p.into_inner());
        st.waiting = false;
        (st, true)
    }
}

impl Deferred for Slot {
    fn run(&self) {
        let mut st = self.lock();
        st.queued = false;
        let w = st.waiting;
        drop(st);
        if w {
            self.cv.notify_all();
        }
    }
}

/// Fills a [`Slot`] on the loop thread.
struct Fill(Arc<Slot>);

impl CallHandler for Fill {
    fn on_head(&mut self, status: u16, headers: &Headers) {
        let mut st = self.0.lock();
        st.head = Some((status, headers.clone()));
        self.0.wake(st);
    }

    fn on_data(&mut self, data: &[u8]) {
        let mut st = self.0.lock();
        if st.pos > 0 && st.pos == st.data.len() {
            st.data.clear();
            st.pos = 0;
        }
        st.data.extend_from_slice(data);
        self.0.wake(st);
    }

    fn on_writable(&mut self) {
        let mut st = self.0.lock();
        st.writable += 1;
        self.0.wake(st);
    }

    fn on_end(&mut self, result: Result<Headers>) {
        let mut st = self.0.lock();
        st.end = Some(result);
        self.0.wake(st);
    }
}

struct Strm {
    slot: Arc<Slot>,
    call: RtCall,
}

type Fx = std::hash::BuildHasherDefault<crate::pool::FxHasher>;

/// An HTTP/2 connection of the blocking client, pinned on a loop.
pub(crate) struct LoopMux {
    rt: RtClient,
    lh: LoopHandle,
    pin: String,
    state: Arc<PinState>,
    origin: Url,
    streams: Mutex<HashMap<u64, Strm, Fx>>,
    next: AtomicU64,
    active: AtomicUsize,
    idle_since: Mutex<Instant>,
    what: String,
}

impl std::fmt::Debug for LoopMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopMux").field("what", &self.what).finish()
    }
}

impl LoopMux {
    /// Hands a connected transport (TLS done with ALPN `h2`, or h2c) to a loop of `rt`.
    pub(crate) fn adopt(rt: &RtClient, d: crate::transport::Duplex, url: &Url) -> Result<LoopMux> {
        static PINS: AtomicU64 = AtomicU64::new(1);
        let pin = format!("{} #pin{}", url.origin(), PINS.fetch_add(1, Ordering::Relaxed));
        let state = Arc::new(PinState::default());
        state.limit.store(100, Ordering::Relaxed);
        let lh = rt.adopt_h2(d, url, pin.clone(), state.clone())?;
        let mut origin = url.clone();
        origin.path = "/".into();
        origin.query = None;
        Ok(LoopMux {
            rt: rt.clone(),
            lh,
            pin,
            state,
            origin,
            streams: Mutex::new(HashMap::default()),
            next: AtomicU64::new(1),
            active: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
            what: url.origin(),
        })
    }

    fn get(&self, id: u64) -> Result<(Arc<Slot>, RtCall)> {
        let g = self.streams.lock().unwrap_or_else(|p| p.into_inner());
        let s = g.get(&id).ok_or_else(|| Error::new(ErrorKind::Closed, "stream closed"))?;
        Ok((s.slot.clone(), s.call.clone()))
    }

    fn closed(&self) -> Error {
        if self.state.dead.load(Ordering::Acquire) {
            Error::new(ErrorKind::Closed, format!("connection closed: {}", self.what))
        } else {
            Error::new(ErrorKind::Closed, format!("connection is going away: {}", self.what))
        }
    }

    pub(crate) fn version(&self) -> Version {
        Version::Http2
    }

    /// For the pool: (finished for good or idle past `idle_limit`, can open a stream now).
    pub(crate) fn usable(&self, idle_limit: Duration) -> (bool, bool) {
        if self.is_dead() {
            return (true, false);
        }
        let active = self.active.load(Ordering::Acquire);
        let idle = active == 0 && self.idle_since.lock().unwrap_or_else(|p| p.into_inner()).elapsed() >= idle_limit;
        (idle, !idle && active < self.state.limit.load(Ordering::Acquire).max(1))
    }

    pub(crate) fn is_dead(&self) -> bool {
        self.state.dead.load(Ordering::Acquire) || self.state.going_away.load(Ordering::Acquire)
    }

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

    fn start(&self, head: &ReqHead<'_>, body: &[u8], end: bool, protocol: Option<&str>) -> Result<u64> {
        if self.is_dead() {
            return Err(self.closed());
        }
        let raw = RawHead { method: head.method.to_string(), scheme: head.scheme.to_string(), authority: head.authority.to_string(), path: head.path.to_string(), fields: head.fields.clone() };
        let req = RtRequest { method: head.method.to_string(), url: self.origin.clone(), headers: Headers::new(), body: body.to_vec() };
        let opts = CallOptions { manual_release: true, protocol: protocol.map(str::to_string), ..CallOptions::default() };
        let slot = Arc::new(Slot::default());
        let ext = Ext { raw: Some(raw), pin: Some(self.pin.clone()), end };
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        // registered before the call starts: its events may arrive before `call_pinned` returns
        self.active.fetch_add(1, Ordering::AcqRel);
        let call = self.rt.call_pinned(&self.lh, &self.state, req, opts, Box::new(Fill(slot.clone())), ext);
        self.streams.lock().unwrap_or_else(|p| p.into_inner()).insert(id, Strm { slot, call });
        Ok(id)
    }

    /// Opens a stream.
    pub(crate) fn open(&self, head: &ReqHead<'_>, end: bool, _deadline: Option<Instant>) -> Result<u64> {
        self.start(head, &[], end, None)
    }

    /// Opens a stream with a request body known up front: the head and the body leave
    /// together, as flow control allows (the rest follows from the loop).
    pub(crate) fn open_with_body(&self, head: &ReqHead<'_>, body: &[u8], end: bool, _deadline: Option<Instant>) -> Result<(u64, usize)> {
        self.start(head, body, end, None).map(|id| (id, body.len()))
    }

    /// Opens an extended CONNECT stream (WebSocket over HTTP/2) once the peer allows it.
    #[cfg(feature = "client-ws")]
    pub(crate) fn open_extended(&self, protocol: &str, head: &ReqHead<'_>, _deadline: Option<Instant>) -> Result<u64> {
        self.start(head, &[], false, Some(protocol))
    }

    /// Sends body bytes, waiting while the call's send buffer is full.
    pub(crate) fn write(&self, id: u64, data: &[u8], end: bool, deadline: Option<Instant>) -> Result<()> {
        let (slot, call) = self.get(id)?;
        if !data.is_empty() {
            let mut st = slot.lock();
            loop {
                match &st.end {
                    Some(Err(e)) => return Err(e.clone()),
                    // the response is complete: the server needs no more (RFC 9113 §8.1)
                    Some(Ok(_)) => return Ok(()),
                    None => {}
                }
                if !call.is_full() {
                    break;
                }
                let gen = st.writable;
                let (g, ok) = slot.wait(st, deadline);
                st = g;
                if !ok && st.writable == gen && call.is_full() {
                    return Err(Error::timeout(TimeoutKind::Idle, &self.what));
                }
            }
            drop(st);
            if !call.send(data.to_vec()) {
                return Err(self.stream_error(&slot));
            }
        }
        if end && !call.finish() && call.is_over() {
            return Err(self.stream_error(&slot));
        }
        Ok(())
    }

    fn stream_error(&self, slot: &Slot) -> Error {
        match &slot.lock().end {
            Some(Err(e)) => e.clone(),
            _ => Error::new(ErrorKind::Closed, format!("stream closed: {}", self.what)),
        }
    }

    pub(crate) fn send_trailers(&self, id: u64, trailers: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let (slot, call) = self.get(id)?;
        if !call.finish_with_fields(trailers) && call.is_over() {
            return Err(self.stream_error(&slot));
        }
        Ok(())
    }

    /// Waits for the response head.
    pub(crate) fn head(&self, id: u64, deadline: Option<Instant>, kind: TimeoutKind) -> Result<(u16, Headers)> {
        let (slot, _) = self.get(id)?;
        let mut st = slot.lock();
        loop {
            if let Some(h) = st.head.take() {
                return Ok(h);
            }
            match &st.end {
                Some(Err(e)) => return Err(e.clone()),
                Some(Ok(_)) => return Err(Error::new(ErrorKind::Closed, format!("stream ended without a response: {}", self.what))),
                None => {}
            }
            let (g, ok) = slot.wait(st, deadline);
            st = g;
            if !ok && st.head.is_none() && st.end.is_none() {
                return Err(Error::timeout(kind, &self.what));
            }
        }
    }

    /// Reads body bytes; `Ok(0)` at the end. Trailers come once, with the last bytes.
    pub(crate) fn read(&self, id: u64, out: &mut [u8], deadline: Option<Instant>, kind: TimeoutKind) -> Result<(usize, Option<Headers>)> {
        let (slot, call) = self.get(id)?;
        let mut st = slot.lock();
        loop {
            if st.pos < st.data.len() {
                let n = (st.data.len() - st.pos).min(out.len());
                out[..n].copy_from_slice(&st.data[st.pos..st.pos + n]);
                st.pos += n;
                let drained = st.pos == st.data.len();
                if drained {
                    st.data.clear();
                    st.pos = 0;
                }
                // trailers come with the last bytes; an error comes on the next read
                let t = if drained && matches!(st.end, Some(Ok(_))) {
                    match st.end.take() {
                        Some(Ok(t)) => Some(t),
                        _ => None,
                    }
                } else {
                    None
                };
                // credit goes back as the caller reads; once the stream ended the loop
                // returns what is left by itself
                let mut release = 0;
                if st.end.is_none() && t.is_none() {
                    st.unreleased += n;
                    if drained || st.unreleased >= RELEASE_BATCH {
                        release = std::mem::take(&mut st.unreleased);
                    }
                }
                drop(st);
                if release > 0 {
                    call.release(release);
                }
                return Ok((n, t));
            }
            match st.end.take() {
                Some(Ok(t)) => return Ok((0, Some(t))),
                Some(Err(e)) => return Err(e),
                None => {}
            }
            let (g, ok) = slot.wait(st, deadline);
            st = g;
            if !ok && st.pos >= st.data.len() && st.end.is_none() {
                return Err(Error::timeout(kind, &self.what));
            }
        }
    }

    /// Forgets a stream (cancelling it if it is still open).
    pub(crate) fn finish(&self, id: u64) {
        let Some(s) = self.streams.lock().unwrap_or_else(|p| p.into_inner()).remove(&id) else { return };
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.idle_since.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
        }
        if !s.call.is_over() {
            s.call.cancel();
        }
    }

    /// Sends a PING and waits for its answer (keepalive on an idle connection).
    pub(crate) fn ping(&self, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();
        let h = self.state.handle.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(h) = h else { return Ok(start.elapsed()) };
        let mut g = self.state.pongs.lock().unwrap_or_else(|p| p.into_inner());
        let target = *g + 1;
        if !h.send(Box::new(PingMsg)) {
            return Err(self.closed());
        }
        while *g < target {
            if self.state.dead.load(Ordering::Acquire) {
                return Err(self.closed());
            }
            let left = (start + timeout).saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::new(ErrorKind::Timeout(TimeoutKind::Idle), format!("keepalive PING unanswered: {}", self.what)));
            }
            g = self.state.pong_cv.wait_timeout(g, left).unwrap_or_else(|p| p.into_inner()).0;
        }
        Ok(start.elapsed())
    }

    pub(crate) fn close(&self) {
        let h = self.state.handle.lock().unwrap_or_else(|p| p.into_inner()).clone();
        self.state.going_away.store(true, Ordering::Release);
        if let Some(h) = h {
            h.send(Box::new(CloseMsg));
        }
    }
}

impl Drop for LoopMux {
    fn drop(&mut self) {
        self.close();
    }
}
