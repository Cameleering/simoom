//! HTTP/2 on the event loops: a connection lives on one loop, requests reach it through the
//! loop's queue, and each response is completed by callback on that loop.
//!
//! - **Pool.** Each loop keeps its connections per (client, origin) in a thread-local map, up to
//!   [`RtConfig::h2_connections`](super::RtConfig::h2_connections) of them. Work goes to the
//!   least loaded one; while none can open a stream (the peer's
//!   `SETTINGS_MAX_CONCURRENT_STREAMS`) it waits in the entry's queue.
//! - **Submission.** A request from another thread is a task on the loop's queue (one lock-free
//!   push; the loop is signalled only when it is parked). The task appends the work to the
//!   entry's queue and, once per batch, sends the connection a [`Kick`]; the connection opens
//!   every queued stream it can and writes their frames together.
//! - **Completion.** Frames are fed to the sans-io engine in `on_data`; heads, body bytes and
//!   trailers go to the stream's state or straight to a [`CallHandler`], and the callback of a
//!   finished request runs right there, on the loop thread, with no thread hand-off.
//! - **Flow control.** Received body bytes are released as soon as they are delivered (or, with
//!   [`CallOptions::manual_release`], when the application calls [`RtCall::release`]). Request
//!   bodies are handed to the engine as its windows allow and only while the loop's queued
//!   output is below [`SEND_HIGH`]; the rest waits in the stream (and, for calls, the sender
//!   sees it in [`RtCall::buffered`]).
//! - **GOAWAY, refused streams, lost connections.** A connection that goes away leaves the pool
//!   and its queued work moves to another (new) connection; streams the peer refused (REFUSED_STREAM,
//!   or above GOAWAY's last stream) are retried, at most three attempts, when their request can
//!   be sent again.

// The pinned connections and the deferred wakes serve the blocking client's facade
// (`client-h2`); with `rt` and `client-h2-engine` only `RtClient` uses this module.
#![cfg_attr(not(feature = "client-h2"), allow(dead_code))]

use super::{deliver, Job, RtConfig, RtInner, RtRequest, RtResponse, CURRENT, OUTBOX};
use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::types::{Headers, Version};
use crate::url::Url;
use simoom_h2::{ErrorCode, Event};
use simoom_rt::timer::TimerId;
use simoom_rt::{CloseReason, ConnHandle, Connection, Ctx, LoopHandle, Message, Socket};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

#[cfg(feature = "tls")]
use simoom_tls::{ClientConfig, ClientConnection};

/// Work to run once the running callback of a connection is over: waking the threads of the
/// blocking client's facade once per batch of news (a head, its body and its end read together
/// wake their caller once, after all of them are in place).
pub(crate) trait Deferred: Send + Sync {
    fn run(&self);
}

thread_local! {
    static DEFERRED: RefCell<Vec<Arc<dyn Deferred>>> = const { RefCell::new(Vec::new()) };
}

/// Runs `d` when the connection callback running on this thread returns (at once outside one).
pub(crate) fn defer(d: Arc<dyn Deferred>) {
    if CURRENT.with(|c| c.get()).is_some() {
        DEFERRED.with(|v| v.borrow_mut().push(d));
    } else {
        d.run();
    }
}

/// Request body bytes are handed to the engine only while less than this is queued on the
/// connection's socket (the rest waits in the stream).
pub(crate) const SEND_HIGH: usize = 512 * 1024;
/// Timer tokens besides stream ids (stream ids fit in 31 bits).
const QUEUE_TIMER: u64 = 1 << 40;
const ENGINE_TIMER: u64 = 1 << 41;
/// Most attempts of a request whose stream was refused or whose connection was lost before
/// it could be opened.
const MAX_ATTEMPTS: u8 = 3;

/// What the HTTP/2 connections of one client share.
pub(crate) struct Settings {
    h2: simoom_h2::Config,
    #[cfg(feature = "tls")]
    tls: Arc<ClientConfig>,
    #[cfg(feature = "tls")]
    server_name: Option<String>,
    user_agent: Option<String>,
    accept_encoding: Option<String>,
    max_body: u64,
    connections: usize,
    connect_timeout: Duration,
}

impl Settings {
    pub(crate) fn new(cfg: &RtConfig, decoder: Option<Arc<dyn crate::decode::ContentDecoder>>) -> Settings {
        #[cfg(feature = "tls")]
        let tls = {
            let mut c = ClientConfig::new(cfg.tls.roots.clone()).with_alpn(&[b"h2"]);
            c.client_cert = cfg.tls.client_cert.clone();
            if !cfg.tls.resumption {
                c.sessions = None;
            }
            Arc::new(c)
        };
        Settings {
            h2: cfg.h2.clone(),
            #[cfg(feature = "tls")]
            tls,
            #[cfg(feature = "tls")]
            server_name: cfg.tls.server_name.clone(),
            user_agent: cfg.user_agent.clone(),
            accept_encoding: if cfg.decompress { decoder.map(|d| d.accept_encoding().to_string()) } else { None },
            max_body: cfg.max_body,
            connections: cfg.h2_connections.max(1),
            connect_timeout: cfg.connect_timeout,
        }
    }
}

// ------------------------------------------------------------------------------ public API

/// Receives the response of an [`RtClient::call`](super::RtClient::call), on the loop thread
/// that reads the connection. The methods must not block; hand slow work to another thread.
pub trait CallHandler: Send + 'static {
    /// The response head (final status and headers).
    fn on_head(&mut self, status: u16, headers: &Headers) {
        let _ = (status, headers);
    }
    /// Response body bytes, in order. Flow-control credit for them goes back to the server when
    /// this returns, unless [`CallOptions::manual_release`] is set.
    fn on_data(&mut self, data: &[u8]) {
        let _ = data;
    }
    /// The request body bytes waiting to be sent fell to half of [`CallOptions::high_water`]
    /// after reaching it: send more.
    fn on_writable(&mut self) {}
    /// The last call: the trailers (empty when there were none) or the error.
    fn on_end(&mut self, result: Result<Headers>);
}

/// Options of an [`RtClient::call`](super::RtClient::call).
#[derive(Clone, Debug)]
pub struct CallOptions {
    /// Time from submitting the call to its end; `None` for streams that run indefinitely.
    pub timeout: Option<Duration>,
    /// Response body credit goes back to the server only through [`RtCall::release`], so a
    /// consumer on another thread holds the server back while it lags.
    pub manual_release: bool,
    /// Request body bytes buffered (sent with [`RtCall::send`], not yet taken by the
    /// connection) from which [`RtCall::is_full`] says so and [`CallHandler::on_writable`] is
    /// armed.
    pub high_water: usize,
    /// An extended CONNECT (RFC 8441) for this protocol (`websocket`): sent once the server's
    /// SETTINGS allow it, refused with [`ErrorKind::Unsupported`] when they do not.
    pub protocol: Option<String>,
    /// A `content-length` for the request body, when it is known up front.
    pub content_length: Option<u64>,
}

impl Default for CallOptions {
    fn default() -> Self {
        CallOptions { timeout: None, manual_release: false, high_water: 256 * 1024, protocol: None, content_length: None }
    }
}

/// The request side of an HTTP/2 call: send body bytes and trailers, release credit, cancel.
/// Usable from any thread; cheap to clone. Dropping it does not cancel the call.
#[derive(Clone)]
pub struct RtCall {
    ctl: Arc<CallShared>,
}

impl std::fmt::Debug for RtCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtCall").field("buffered", &self.buffered()).finish()
    }
}

impl RtCall {
    /// Queues request body bytes. Returns `false` (and drops them) when the call is over or
    /// its request body was finished.
    pub fn send(&self, data: impl Into<Vec<u8>>) -> bool {
        let data = data.into();
        let n = data.len();
        let mut st = self.ctl.lock();
        if st.over || st.finished {
            return false;
        }
        st.ops.push(Op::Data(data));
        self.ctl.buffered.fetch_add(n, Ordering::AcqRel);
        self.ctl.kick(st);
        true
    }

    /// Ends the request body.
    pub fn finish(&self) -> bool {
        self.end(None)
    }

    /// Ends the request body with trailers.
    pub fn finish_with_trailers(&self, trailers: &[(&str, &str)]) -> bool {
        self.end(Some(trailers.iter().map(|(n, v)| (n.to_ascii_lowercase().into_bytes(), v.as_bytes().to_vec())).collect()))
    }

    /// Ends the request body with trailers already in HTTP/2 form (lower-case names).
    pub(crate) fn finish_with_fields(&self, trailers: &[(Vec<u8>, Vec<u8>)]) -> bool {
        self.end(Some(trailers.to_vec()))
    }

    fn end(&self, trailers: Option<Vec<(Vec<u8>, Vec<u8>)>>) -> bool {
        let mut st = self.ctl.lock();
        if st.over || st.finished {
            return false;
        }
        st.finished = true;
        st.ops.push(Op::Finish(trailers));
        self.ctl.kick(st);
        true
    }

    /// Hands `n` bytes of response body credit back (with [`CallOptions::manual_release`]).
    pub fn release(&self, n: usize) {
        let mut st = self.ctl.lock();
        if st.over || n == 0 {
            return;
        }
        st.ops.push(Op::Release(n));
        self.ctl.kick(st);
    }

    /// Cancels the call: RST_STREAM(CANCEL), and [`CallHandler::on_end`] gets
    /// [`ErrorKind::Cancelled`].
    pub fn cancel(&self) {
        let mut st = self.ctl.lock();
        if st.over || st.cancelled {
            return;
        }
        st.cancelled = true;
        st.ops.push(Op::Cancel);
        self.ctl.kick(st);
    }

    /// Request body bytes sent with [`RtCall::send`] that the connection has not taken yet.
    pub fn buffered(&self) -> usize {
        self.ctl.buffered.load(Ordering::Acquire)
    }

    /// Whether [`RtCall::buffered`] reached [`CallOptions::high_water`]: wait for
    /// [`CallHandler::on_writable`] before sending more.
    pub fn is_full(&self) -> bool {
        self.buffered() >= self.ctl.high
    }

    /// Whether the call has ended (its handler got, or is getting, `on_end`).
    pub fn is_over(&self) -> bool {
        self.ctl.lock().over
    }
}

/// State shared between an [`RtCall`] and the stream that carries it.
pub(crate) struct CallShared {
    st: Mutex<CallSt>,
    buffered: AtomicUsize,
    high: usize,
}

#[derive(Default)]
struct CallSt {
    ops: Vec<Op>,
    /// The stream carrying the call: its connection, that connection's id and the stream id.
    target: Option<(ConnHandle, u64, u32)>,
    /// A [`CallKick`] is on its way to the connection.
    kicked: bool,
    over: bool,
    finished: bool,
    cancelled: bool,
    /// Body bytes beyond the first ones left the call: it cannot be sent again.
    drained: bool,
}

enum Op {
    Data(Vec<u8>),
    Finish(Option<Vec<(Vec<u8>, Vec<u8>)>>),
    Release(usize),
    Cancel,
}

impl CallShared {
    fn lock(&self) -> MutexGuard<'_, CallSt> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Tells the connection carrying the call that there is something to do (once per batch).
    fn kick(self: &Arc<Self>, mut st: MutexGuard<'_, CallSt>) {
        if st.kicked {
            return;
        }
        let Some((h, _, _)) = st.target.clone() else { return };
        st.kicked = true;
        drop(st);
        h.send(Box::new(CallKick(self.clone())));
    }
}

/// An HTTP/2 call: the request head and its first body bytes, a handler for the response.
pub(crate) struct CallJob {
    pub(crate) req: RtRequest,
    pub(crate) handler: Box<dyn CallHandler>,
    pub(crate) ctl: Arc<CallShared>,
    pub(crate) deadline: Option<Instant>,
    pub(crate) manual: bool,
    pub(crate) attempts: u8,
    pub(crate) protocol: Option<String>,
    pub(crate) content_length: Option<u64>,
    pub(crate) ext: Ext,
}

/// What the blocking client's facade adds to a call ([`crate::mux::LoopMux`]).
#[derive(Default)]
pub(crate) struct Ext {
    /// The request head exactly as the blocking client built it.
    pub(crate) raw: Option<RawHead>,
    /// The call goes to this pinned connection (and fails when it is gone).
    pub(crate) pin: Option<String>,
    /// The request ends with its first body bytes (END_STREAM on the HEADERS when there are
    /// none).
    pub(crate) end: bool,
}

/// A request head in HTTP/2 form.
pub(crate) struct RawHead {
    pub(crate) method: String,
    pub(crate) scheme: String,
    pub(crate) authority: String,
    pub(crate) path: String,
    pub(crate) fields: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Starts a call on loop `index` (see [`super::RtClient::call`]).
pub(super) fn start_call(inner: &Arc<RtInner>, lh: LoopHandle, req: RtRequest, opts: CallOptions, handler: Box<dyn CallHandler>) -> RtCall {
    start_call_ext(inner, lh, req, opts, handler, Ext::default())
}

/// A call's handle and its job; `Err` with the handle when the call failed at once.
fn new_call(req: RtRequest, opts: CallOptions, mut handler: Box<dyn CallHandler>, ext: Ext) -> std::result::Result<(RtCall, CallJob), RtCall> {
    let ctl = Arc::new(CallShared { st: Mutex::new(CallSt { finished: ext.end, ..CallSt::default() }), buffered: AtomicUsize::new(0), high: opts.high_water.max(1) });
    let call = RtCall { ctl: ctl.clone() };
    if req.url.scheme != "http" && req.url.scheme != "https" {
        end_call(&ctl);
        handler.on_end(Err(Error::new(ErrorKind::InvalidUrl, format!("RtClient takes http and https URLs: {}", req.url))));
        return Err(call);
    }
    let job = CallJob { req, handler, ctl, deadline: opts.timeout.map(|t| Instant::now() + t), manual: opts.manual_release, attempts: 0, protocol: opts.protocol, content_length: opts.content_length, ext };
    Ok((call, job))
}

/// A call for a pinned connection, delivered to it in one message (no loop task).
pub(crate) struct PinWork(Option<CallJob>);

impl Drop for PinWork {
    fn drop(&mut self) {
        // not delivered (the connection is gone): the call ends instead of hanging
        if let Some(j) = self.0.take() {
            let e = Error::new(ErrorKind::Closed, format!("HTTP/2 connection is going away: {}", j.req.url.origin()));
            Work::Call(j).fail(e);
        }
    }
}

/// Starts a call on the pinned connection whose state is `state`: one message straight to it
/// once it is registered, a task through its loop before that.
pub(super) fn call_pinned(inner: &Arc<RtInner>, lh: LoopHandle, state: &PinState, req: RtRequest, opts: CallOptions, handler: Box<dyn CallHandler>, ext: Ext) -> RtCall {
    let h = state.handle.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let Some(h) = h else { return start_call_ext(inner, lh, req, opts, handler, ext) };
    match new_call(req, opts, handler, ext) {
        Ok((call, job)) => {
            h.send(Box::new(PinWork(Some(job))));
            call
        }
        Err(call) => call,
    }
}

/// [`start_call`] with the facade's additions.
pub(super) fn start_call_ext(inner: &Arc<RtInner>, lh: LoopHandle, req: RtRequest, opts: CallOptions, handler: Box<dyn CallHandler>, ext: Ext) -> RtCall {
    let (call, job) = match new_call(req, opts, handler, ext) {
        Ok(x) => x,
        Err(call) => return call,
    };
    let pos = inner.loops.iter().position(|l| l == &lh).unwrap_or(0);
    if lh.is_current() {
        dispatch(inner, Work::Call(job), &lh, pos);
        return call;
    }
    let slot = Arc::new(Mutex::new(Some(job)));
    let (s2, inner2, lh2) = (slot.clone(), inner.clone(), lh.clone());
    let ok = lh.run(move |_| {
        if let Some(j) = s2.lock().unwrap_or_else(|p| p.into_inner()).take() {
            dispatch(&inner2, Work::Call(j), &lh2, pos);
        }
    });
    if !ok {
        if let Some(j) = slot.lock().unwrap_or_else(|p| p.into_inner()).take() {
            Work::Call(j).fail(Error::new(ErrorKind::Closed, "the event loop has stopped"));
        }
    }
    call
}

// ------------------------------------------------------------------------------ work

/// A request waiting for or carried by an HTTP/2 stream.
pub(super) enum Work {
    Unary(Job),
    Call(CallJob),
}

impl Work {
    fn url(&self) -> &Url {
        match self {
            Work::Unary(j) => &j.req.url,
            Work::Call(c) => &c.req.url,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match self {
            Work::Unary(j) => Some(j.deadline),
            Work::Call(c) => c.deadline,
        }
    }

    fn pin(&self) -> Option<&str> {
        match self {
            Work::Call(c) => c.ext.pin.as_deref(),
            Work::Unary(_) => None,
        }
    }

    fn attempts(&mut self) -> &mut u8 {
        match self {
            Work::Unary(j) => &mut j.attempts,
            Work::Call(c) => &mut c.attempts,
        }
    }

    fn cancelled(&self) -> bool {
        match self {
            Work::Unary(_) => false,
            Work::Call(c) => c.ctl.lock().cancelled,
        }
    }

    /// Whether the request can be sent again (nothing of it is lost).
    fn replayable(&self) -> bool {
        match self {
            Work::Unary(_) => true,
            Work::Call(c) => !c.ctl.lock().drained,
        }
    }

    fn fail(self, e: Error) {
        match self {
            Work::Unary(j) => (j.cb)(Err(e)),
            Work::Call(mut c) => {
                end_call(&c.ctl);
                c.handler.on_end(Err(e));
            }
        }
    }
}

/// The call is over: no more operations reach a stream.
fn end_call(ctl: &CallShared) {
    let mut st = ctl.lock();
    st.over = true;
    st.target = None;
    st.ops.clear();
    drop(st);
    ctl.buffered.store(0, Ordering::Release);
}

// ------------------------------------------------------------------------------ pool

type Key = (u64, String);

/// A pooled connection: open, or being opened by the connector thread.
struct Entry {
    id: u64,
    /// Set once the connection is registered with the loop.
    handle: Option<ConnHandle>,
    /// Work waiting for a stream.
    queue: VecDeque<Work>,
    /// A [`Kick`] is on its way.
    kicked: bool,
    /// Streams open on the connection.
    active: usize,
    /// The peer's concurrent-stream limit, as last seen.
    limit: usize,
}

thread_local! {
    static POOL: RefCell<HashMap<Key, Vec<Rc<RefCell<Entry>>>>> = RefCell::new(HashMap::new());
}

/// Connections of client `id` pooled on this loop (for tests).
pub(crate) fn pooled(id: u64) -> usize {
    POOL.with(|p| p.borrow().iter().filter(|(k, _)| k.0 == id).map(|(_, v)| v.len()).sum())
}

fn key_of(inner: &RtInner, url: &Url) -> Key {
    (inner.id, url.origin())
}

/// Wakes a connection whose queue got work, once per batch.
struct Kick;
/// Wakes a connection carrying a call that got operations.
struct CallKick(Arc<CallShared>);

/// On a loop thread: queues `work` on a pooled connection to its origin, opening one if needed.
pub(super) fn dispatch(inner: &Arc<RtInner>, work: Work, lh: &LoopHandle, pos: usize) {
    if work.cancelled() {
        work.fail(Error::new(ErrorKind::Cancelled, "call cancelled"));
        return;
    }
    if let Some(pin) = work.pin() {
        let key = (inner.id, pin.to_string());
        let entry = POOL.with(|p| p.borrow().get(&key).and_then(|v| v.first().cloned()));
        let Some(entry) = entry else {
            let e = Error::new(ErrorKind::Closed, format!("HTTP/2 connection is going away: {}", work.url().origin()));
            work.fail(e);
            return;
        };
        let kick = {
            let mut e = entry.borrow_mut();
            e.queue.push_back(work);
            match e.handle.clone() {
                Some(h) if !e.kicked => {
                    e.kicked = true;
                    Some(h)
                }
                _ => None,
            }
        };
        if let Some(h) = kick {
            if !h.send(Box::new(Kick)) {
                fail_entry(&key, entry.borrow().id, Error::new(ErrorKind::Closed, "the event loop has stopped"));
            }
        }
        return;
    }
    let key = key_of(inner, work.url());
    let max = inner.h2.connections;
    let (entry, new) = POOL.with(|p| {
        let mut p = p.borrow_mut();
        let v = p.entry(key.clone()).or_default();
        let load = |e: &Rc<RefCell<Entry>>| {
            let e = e.borrow();
            (e.active + e.queue.len(), e.limit)
        };
        // an idle connection, else a new one while fewer than `max` exist, else the least loaded
        let best = v.iter().min_by_key(|e| load(e).0).cloned();
        match best {
            Some(e) if load(&e).0 == 0 || v.len() >= max => (e, false),
            _ => {
                static IDS: AtomicU64 = AtomicU64::new(1);
                let e = Rc::new(RefCell::new(Entry { id: IDS.fetch_add(1, Ordering::Relaxed), handle: None, queue: VecDeque::new(), kicked: false, active: 0, limit: 100 }));
                v.push(e.clone());
                (e, true)
            }
        }
    });
    let url = work.url().clone();
    let deadline = work.deadline();
    let kick = {
        let mut e = entry.borrow_mut();
        e.queue.push_back(work);
        match e.handle.clone() {
            Some(h) if !e.kicked => {
                e.kicked = true;
                Some(h)
            }
            _ => None,
        }
    };
    if let Some(h) = kick {
        if !h.send(Box::new(Kick)) {
            fail_entry(&key, entry.borrow().id, Error::new(ErrorKind::Closed, "the event loop has stopped"));
        }
    }
    if new {
        let id = entry.borrow().id;
        let cdl = Instant::now() + inner.h2.connect_timeout;
        let deadline = deadline.map_or(cdl, |d| d.min(cdl));
        super::connect_req(inner, super::ConnectReq::H2(Connect { key, id, url, lh: lh.clone(), pos, deadline }));
    }
}

/// Removes a pooled entry; its queued work fails with `e`.
fn fail_entry(key: &Key, id: u64, e: Error) {
    let entry = POOL.with(|p| {
        let mut p = p.borrow_mut();
        let v = p.get_mut(key)?;
        let i = v.iter().position(|x| x.borrow().id == id)?;
        let e = v.remove(i);
        if v.is_empty() {
            p.remove(key);
        }
        Some(e)
    });
    let Some(entry) = entry else { return };
    let works: Vec<Work> = entry.borrow_mut().queue.drain(..).collect();
    for w in works {
        w.fail(e.clone());
    }
}

/// Takes an entry out of the pool (the connection goes away or is gone).
fn unpool(key: &Key, id: u64) {
    POOL.with(|p| {
        let mut p = p.borrow_mut();
        if let Some(v) = p.get_mut(key) {
            v.retain(|x| x.borrow().id != id);
            if v.is_empty() {
                p.remove(key);
            }
        }
    });
}

fn find(key: &Key, id: u64) -> Option<Rc<RefCell<Entry>>> {
    POOL.with(|p| p.borrow().get(key).and_then(|v| v.iter().find(|x| x.borrow().id == id).cloned()))
}

/// A connection for the connector thread to open.
pub(crate) struct Connect {
    key: Key,
    id: u64,
    url: Url,
    lh: LoopHandle,
    pos: usize,
    deadline: Instant,
}

impl Connect {
    /// The connection could not be opened: its queued work fails (on the loop).
    pub(crate) fn failed(self, e: Error) {
        let (key, id) = (self.key, self.id);
        let _ = self.lh.run(move |_| fail_entry(&key, id, e));
    }
}

/// On the connector thread: TCP (and a proxy tunnel), then the connection on its loop.
pub(super) fn open(inner: &Arc<RtInner>, c: Connect) {
    let (tcp, _) = match super::tcp_for(inner, &c.url, c.deadline, true) {
        Ok(t) => t,
        Err(e) => {
            c.failed(e);
            return;
        }
    };
    let sock = Socket::from(tcp);
    let weak = Arc::downgrade(inner);
    let set = inner.h2.clone();
    let Connect { key, id, url, lh, pos, .. } = c;
    let lh2 = lh.clone();
    let cell = Arc::new(Mutex::new(Some(sock)));
    let c2 = cell.clone();
    let ok = lh.run(move |lcx| {
        let Some(sock) = c2.lock().unwrap_or_else(|p| p.into_inner()).take() else { return };
        let Some(entry) = find(&key, id) else { return };
        match H2Conn::new(set, weak, lh2, pos, key.clone(), entry, &url) {
            Ok(conn) => {
                if let Err(e) = lcx.adopt(sock, Box::new(conn)) {
                    fail_entry(&key, id, Error::io(&e, &url.origin()));
                }
            }
            Err(e) => fail_entry(&key, id, e),
        }
    });
    if !ok {
        drop(cell);
    }
}

/// The state of a pinned connection that the blocking client's facade reads.
#[derive(Default)]
pub(crate) struct PinState {
    pub(crate) dead: std::sync::atomic::AtomicBool,
    pub(crate) going_away: std::sync::atomic::AtomicBool,
    /// The peer's concurrent-stream limit, as last seen.
    pub(crate) limit: AtomicUsize,
    /// PING answers received, and a condition variable for [`crate::mux::LoopMux::ping`].
    pub(crate) pongs: Mutex<u64>,
    pub(crate) pong_cv: std::sync::Condvar,
    pub(crate) handle: Mutex<Option<ConnHandle>>,
}

/// Asks a pinned connection for a PING.
pub(crate) struct PingMsg;
/// Closes a pinned connection.
pub(crate) struct CloseMsg;

/// A transport the blocking client connected (TCP, proxy tunnel, TLS with ALPN `h2` done),
/// handed to a loop as a pinned HTTP/2 connection.
pub(crate) struct Connected {
    #[cfg(feature = "tls")]
    pub(crate) tls: Option<ClientConnection>,
    /// Bytes read from the socket and not yet processed.
    pub(crate) leftover: Vec<u8>,
    pub(crate) url: Url,
}

/// Registers a connected transport as pinned connection `pin` on loop `lh` (from any thread).
/// Calls sent to `pin` after this returns reach it in order.
pub(super) fn adopt_connected(inner: &Arc<RtInner>, lh: &LoopHandle, tcp: std::net::TcpStream, c: Connected, pin: String, state: Arc<PinState>) -> Result<()> {
    tcp.set_nonblocking(true).map_err(|e| Error::io(&e, &c.url.origin()))?;
    let pos = inner.loops.iter().position(|l| l == lh).unwrap_or(0);
    let (set, weak, lh2, id) = (inner.h2.clone(), Arc::downgrade(inner), lh.clone(), inner.id);
    let cell = Arc::new(Mutex::new(Some((tcp, c))));
    let c2 = cell.clone();
    let st2 = state.clone();
    let ok = lh.run(move |lcx| {
        let Some((tcp, c)) = c2.lock().unwrap_or_else(|p| p.into_inner()).take() else { return };
        static IDS: AtomicU64 = AtomicU64::new(1 << 32);
        let entry = Rc::new(RefCell::new(Entry { id: IDS.fetch_add(1, Ordering::Relaxed), handle: None, queue: VecDeque::new(), kicked: false, active: 0, limit: 100 }));
        let eid = entry.borrow().id;
        let key = (id, pin);
        POOL.with(|p| p.borrow_mut().entry(key.clone()).or_default().push(entry.clone()));
        let what = c.url.origin();
        let conn = H2Conn::adopted(set, weak, lh2, pos, key.clone(), entry, c, st2.clone());
        if let Err(e) = lcx.adopt(Socket::from(tcp), Box::new(conn)) {
            st2.dead.store(true, Ordering::Release);
            fail_entry(&key, eid, Error::io(&e, &what));
        }
    });
    if !ok {
        state.dead.store(true, Ordering::Release);
        return Err(Error::new(ErrorKind::Closed, "the event loop has stopped"));
    }
    Ok(())
}

// ------------------------------------------------------------------------------ connection

/// How a stream ended.
enum End {
    Complete,
    /// Not processed by the peer: REFUSED_STREAM, or above the last stream of its GOAWAY.
    Refused,
    Reset(u32),
    Fail(Error),
}

enum Kind {
    Unary {
        job: Job,
        resp: Option<RtResponse>,
        /// Request body bytes handed to the engine.
        off: usize,
    },
    Call {
        job: CallJob,
        out: VecDeque<Vec<u8>>,
        off: usize,
        fin: Option<Option<Vec<(Vec<u8>, Vec<u8>)>>>,
        trailers: Headers,
        /// Body bytes delivered and not released yet (manual release).
        unreleased: usize,
        /// [`CallHandler::on_writable`] is due once the buffer drains to half the high water.
        want_writable: bool,
    },
}

struct Stream {
    kind: Kind,
    timer: Option<TimerId>,
    /// Our side ended (END_STREAM or trailers sent).
    local_end: bool,
    head: bool,
}

type Fx = std::hash::BuildHasherDefault<crate::pool::FxHasher>;

struct H2Conn {
    set: Arc<Settings>,
    inner: Weak<RtInner>,
    lh: LoopHandle,
    pos: usize,
    key: Key,
    id: u64,
    entry: Rc<RefCell<Entry>>,
    h2: simoom_h2::Connection,
    epoch: Instant,
    #[cfg(feature = "tls")]
    tls: Option<ClientConnection>,
    /// TLS plaintext not consumed by the engine yet.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    input: Vec<u8>,
    streams: HashMap<u32, Stream, Fx>,
    /// Streams with request body bytes (or an end) still to send.
    sending: Vec<u32>,
    ready: bool,
    going_away: bool,
    dead: bool,
    engine_timer: Option<(TimerId, u64)>,
    queue_timer: Option<(TimerId, Instant)>,
    handle: Option<ConnHandle>,
    what: String,
    secure: bool,
    /// The peer's SETTINGS arrived (extended CONNECT waits for them).
    settings_seen: bool,
    /// A connection the blocking client connected and pinned ([`adopt_connected`]).
    pin: Option<Arc<PinState>>,
    /// Socket bytes read before the loop took the connection over.
    leftover: Vec<u8>,
}

impl H2Conn {
    fn new(set: Arc<Settings>, inner: Weak<RtInner>, lh: LoopHandle, pos: usize, key: Key, entry: Rc<RefCell<Entry>>, url: &Url) -> Result<H2Conn> {
        let secure = url.is_secure();
        #[cfg(feature = "tls")]
        let tls = if secure {
            let name = set.server_name.clone().unwrap_or_else(|| url.host.clone());
            Some(ClientConnection::new(set.tls.clone(), &name).map_err(|e| crate::transport::tls_error(&e, &url.origin()))?)
        } else {
            None
        };
        #[cfg(not(feature = "tls"))]
        if secure {
            return Err(Error::new(ErrorKind::Unsupported, "https needs the `tls` feature of simoom-client"));
        }
        let id = entry.borrow().id;
        Ok(H2Conn {
            h2: simoom_h2::Connection::client(set.h2.clone()),
            set,
            inner,
            lh,
            pos,
            key,
            id,
            entry,
            epoch: Instant::now(),
            #[cfg(feature = "tls")]
            tls,
            input: Vec::new(),
            streams: HashMap::default(),
            sending: Vec::new(),
            ready: false,
            going_away: false,
            dead: false,
            engine_timer: None,
            queue_timer: None,
            handle: None,
            what: url.origin(),
            secure,
            settings_seen: false,
            pin: None,
            leftover: Vec::new(),
        })
    }

    /// A connection whose transport is already up (TLS done): ready at once.
    #[allow(clippy::too_many_arguments)]
    fn adopted(set: Arc<Settings>, inner: Weak<RtInner>, lh: LoopHandle, pos: usize, key: Key, entry: Rc<RefCell<Entry>>, c: Connected, pin: Arc<PinState>) -> H2Conn {
        let id = entry.borrow().id;
        H2Conn {
            h2: simoom_h2::Connection::client(set.h2.clone()),
            set,
            inner,
            lh,
            pos,
            key,
            id,
            entry,
            epoch: Instant::now(),
            #[cfg(feature = "tls")]
            secure: c.tls.is_some(),
            #[cfg(not(feature = "tls"))]
            secure: false,
            #[cfg(feature = "tls")]
            tls: c.tls,
            input: Vec::new(),
            streams: HashMap::default(),
            sending: Vec::new(),
            ready: true,
            going_away: false,
            dead: false,
            engine_timer: None,
            queue_timer: None,
            handle: None,
            what: c.url.origin(),
            settings_seen: false,
            pin: Some(pin),
            leftover: c.leftover,
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    // -------------------------------------------------------------- output

    #[cfg(feature = "tls")]
    fn flush_tls(&mut self, cx: &mut Ctx<'_>) {
        if let Some(t) = &mut self.tls {
            let out = t.tls_output();
            if !out.is_empty() {
                let n = out.len();
                let mut b = cx.buffer(n);
                b.extend_from_slice(out);
                t.consume_tls_output(n);
                cx.send(b);
            }
        }
    }

    /// Moves the engine's output to the socket.
    fn flush(&mut self, cx: &mut Ctx<'_>) {
        if !self.ready || self.h2.output().is_empty() {
            return;
        }
        #[cfg(feature = "tls")]
        if let Some(t) = &mut self.tls {
            let out = self.h2.output();
            let mut off = 0;
            while off < out.len() {
                match t.write_plaintext(&out[off..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => off += n,
                }
            }
            self.h2.advance_output(off);
            self.flush_tls(cx);
            return;
        }
        let empty = cx.buffer(0);
        let out = self.h2.take_output(empty);
        cx.send(out);
    }

    /// The end of every callback: open queued streams, send request bodies, write, re-arm the
    /// engine timer, close a connection that went away once its streams are done.
    fn settle(&mut self, cx: &mut Ctx<'_>) {
        if self.dead {
            return;
        }
        self.open_queued(cx);
        loop {
            self.pump(cx);
            let had = !self.h2.output().is_empty();
            self.flush(cx);
            // the engine accepts DATA only while its own buffer has room: go on after a flush
            // while streams still wait and the socket is not backed up
            if !had || self.sending.is_empty() || cx.queued() >= SEND_HIGH {
                break;
            }
        }
        if !self.sending.is_empty() && cx.queued() >= SEND_HIGH {
            cx.notify_drain();
        }
        if let Some(ms) = self.h2.poll_timeout() {
            if self.engine_timer.is_none_or(|(_, at)| ms < at) {
                if let Some((t, _)) = self.engine_timer.take() {
                    cx.cancel_timer(t);
                }
                let after = Duration::from_millis(ms.saturating_sub(self.now_ms()).max(1));
                self.engine_timer = Some((cx.set_timer(after, ENGINE_TIMER), ms));
            }
        }
        if self.h2.close_code().is_some() || (self.going_away && self.streams.is_empty()) {
            self.flush(cx);
            cx.close();
        }
    }

    // -------------------------------------------------------------- streams

    /// Opens streams for queued work while the peer allows.
    fn open_queued(&mut self, cx: &mut Ctx<'_>) {
        if !self.ready || self.going_away {
            return;
        }
        loop {
            if !self.h2.can_open_stream() {
                if self.h2.close_code().is_some() || self.h2.wants_close() {
                    self.go_away(cx);
                }
                break;
            }
            let w = self.entry.borrow_mut().queue.pop_front();
            let Some(w) = w else { break };
            if !self.open(cx, w) {
                break;
            }
        }
        let limit = self.h2.peer_max_concurrent_streams() as usize;
        self.entry.borrow_mut().limit = limit;
        if let Some(p) = &self.pin {
            p.limit.store(limit, Ordering::Release);
        }
        self.arm_queue_timer(cx);
    }

    fn arm_queue_timer(&mut self, cx: &mut Ctx<'_>) {
        let next = self.entry.borrow().queue.iter().filter_map(|w| w.deadline()).min();
        match (next, self.queue_timer) {
            (Some(n), Some((_, at))) if at <= n => {}
            (Some(n), cur) => {
                if let Some((t, _)) = cur {
                    cx.cancel_timer(t);
                }
                let after = n.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
                self.queue_timer = Some((cx.set_timer(after, QUEUE_TIMER), n));
            }
            (None, _) => {}
        }
    }

    /// Opens a stream for `w`; false when the queue must wait (extended CONNECT before the
    /// peer's SETTINGS).
    fn open(&mut self, cx: &mut Ctx<'_>, w: Work) -> bool {
        if w.cancelled() {
            w.fail(Error::new(ErrorKind::Cancelled, "call cancelled"));
            return true;
        }
        if w.deadline().is_some_and(|d| Instant::now() >= d) {
            let e = Error::timeout(TimeoutKind::Total, &w.url().to_string());
            w.fail(e);
            return true;
        }
        let protocol = match &w {
            Work::Call(c) => c.protocol.clone(),
            Work::Unary(_) => None,
        };
        if protocol.is_some() {
            if !self.settings_seen {
                self.entry.borrow_mut().queue.push_front(w);
                return false;
            }
            if !self.h2.peer_connect_protocol() {
                w.fail(Error::new(ErrorKind::Unsupported, format!("the server does not allow extended CONNECT (RFC 8441): {}", self.what)));
                return true;
            }
        }
        let (req, unary) = match &w {
            Work::Unary(j) => (&j.req, true),
            Work::Call(c) => (&c.req, false),
        };
        let mut headers = req.headers.clone();
        if let Some(ua) = &self.set.user_agent {
            if !headers.contains("user-agent") {
                headers.append("User-Agent", ua);
            }
        }
        if unary && req.method != "HEAD" {
            if let Some(ae) = &self.set.accept_encoding {
                if !headers.contains("accept-encoding") {
                    headers.append("Accept-Encoding", ae);
                }
            }
        }
        let (raw, content_length, ends) = match &w {
            Work::Call(c) => (c.ext.raw.as_ref(), c.content_length, c.ext.end),
            Work::Unary(_) => (None, Some(req.body.len() as u64), true),
        };
        let end = ends && req.body.is_empty();
        let r = match raw {
            Some(h) => {
                let f: Vec<(&[u8], &[u8])> = h.fields.iter().map(|(n, v)| (&n[..], &v[..])).collect();
                match &protocol {
                    Some(p) => self.h2.send_extended_connect(p.as_bytes(), h.scheme.as_bytes(), h.authority.as_bytes(), h.path.as_bytes(), &f),
                    None => self.h2.send_request(h.method.as_bytes(), h.scheme.as_bytes(), h.authority.as_bytes(), h.path.as_bytes(), &f, end),
                }
            }
            None => {
                let (host, fields) = crate::mux::request_fields(&headers, content_length, &req.method);
                let authority = host.unwrap_or_else(|| req.url.host_header());
                let path = req.url.request_target();
                let scheme: &[u8] = if self.secure { b"https" } else { b"http" };
                let f: Vec<(&[u8], &[u8])> = fields.iter().map(|(n, v)| (&n[..], &v[..])).collect();
                match &protocol {
                    Some(p) => self.h2.send_extended_connect(p.as_bytes(), scheme, authority.as_bytes(), path.as_bytes(), &f),
                    None => self.h2.send_request(req.method.as_bytes(), scheme, authority.as_bytes(), path.as_bytes(), &f, end),
                }
            }
        };
        let end = end && protocol.is_none();
        let id = match r {
            Ok(id) => id,
            Err(simoom_h2::Error::StreamLimit) => {
                self.entry.borrow_mut().queue.push_front(w);
                return false;
            }
            Err(simoom_h2::Error::GoingAway | simoom_h2::Error::StreamIdsExhausted | simoom_h2::Error::ConnectionClosed) => {
                self.entry.borrow_mut().queue.push_front(w);
                self.go_away(cx);
                return false;
            }
            Err(simoom_h2::Error::InvalidHeader) => {
                w.fail(Error::new(ErrorKind::InvalidRequest, format!("header not allowed in HTTP/2: {}", self.what)));
                return true;
            }
            Err(simoom_h2::Error::HeaderListTooLarge) => {
                w.fail(Error::new(ErrorKind::InvalidRequest, format!("request header list larger than the server allows: {}", self.what)));
                return true;
            }
            Err(simoom_h2::Error::ConnectProtocolDisabled) => {
                w.fail(Error::new(ErrorKind::Unsupported, format!("the server does not allow extended CONNECT (RFC 8441): {}", self.what)));
                return true;
            }
            Err(e) => {
                w.fail(Error::protocol(format!("HTTP/2 ({e})"), &self.what));
                return true;
            }
        };
        let timer = w.deadline().map(|d| cx.set_timer(d.saturating_duration_since(Instant::now()).max(Duration::from_millis(1)), id as u64));
        self.entry.borrow_mut().active += 1;
        let kind = match w {
            Work::Unary(job) => Kind::Unary { job, resp: None, off: 0 },
            Work::Call(mut job) => {
                let first = std::mem::take(&mut job.req.body);
                let mut out = VecDeque::new();
                if !first.is_empty() {
                    job.ctl.buffered.fetch_add(first.len(), Ordering::AcqRel);
                    out.push_back(first.clone());
                }
                // keep the first bytes for a retry
                job.req.body = first;
                let ops = {
                    let mut st = job.ctl.lock();
                    st.target = self.handle.clone().map(|h| (h, self.id, id));
                    st.kicked = false;
                    std::mem::take(&mut st.ops)
                };
                // the request ends with its first bytes: END_STREAM goes with the last of them
                let fin = if job.ext.end && !end { Some(None) } else { None };
                let mut k = Kind::Call { job, out, off: 0, fin, trailers: Headers::new(), unreleased: 0, want_writable: false };
                let mut cancel = false;
                apply_ops(&mut k, ops, &mut self.h2, id, &mut cancel);
                if cancel {
                    let st = Stream { kind: k, timer, local_end: false, head: false };
                    self.streams.insert(id, st);
                    self.h2.reset(id, ErrorCode::CANCEL);
                    self.finish(cx, id, End::Fail(Error::new(ErrorKind::Cancelled, "call cancelled")));
                    return true;
                }
                k
            }
        };
        let pending = match &kind {
            Kind::Unary { job, .. } => !job.req.body.is_empty(),
            Kind::Call { .. } => true,
        };
        self.streams.insert(id, Stream { kind, timer, local_end: end, head: false });
        if pending && !end {
            self.sending.push(id);
        }
        true
    }

    /// Hands request body bytes of the waiting streams to the engine, as flow control allows.
    fn pump(&mut self, cx: &mut Ctx<'_>) {
        while self.h2.poll_writable().is_some() {}
        if self.sending.is_empty() {
            return;
        }
        let mut i = 0;
        let mut writable = Vec::new();
        while i < self.sending.len() {
            if cx.queued() >= SEND_HIGH {
                break;
            }
            let id = self.sending[i];
            let done = match self.streams.get_mut(&id) {
                None => true,
                Some(s) => pump_stream(&mut self.h2, id, s, &mut writable),
            };
            if done {
                self.sending.swap_remove(i);
            } else {
                i += 1;
            }
        }
        for id in writable {
            if let Some(Stream { kind: Kind::Call { job, .. }, .. }) = self.streams.get_mut(&id) {
                job.handler.on_writable();
            }
        }
    }

    /// A stream is over: callbacks, retries, bookkeeping.
    fn finish(&mut self, cx: &mut Ctx<'_>, id: u32, end: End) {
        let Some(mut s) = self.streams.remove(&id) else { return };
        if let Some(t) = s.timer.take() {
            cx.cancel_timer(t);
        }
        self.finish_stream(id, s, end);
    }

    /// Like [`H2Conn::finish`], without a context (timers are dropped with the connection).
    fn finish_stream(&mut self, id: u32, s: Stream, end: End) {
        {
            let mut e = self.entry.borrow_mut();
            e.active = e.active.saturating_sub(1);
        }
        if let Kind::Call { unreleased, .. } = &s.kind {
            if *unreleased > 0 {
                self.h2.release(id, *unreleased);
            }
        }
        self.h2.stream_finished(id);
        let mut work = match s.kind {
            Kind::Unary { job, resp, .. } => match end {
                End::Complete => {
                    let resp = resp.unwrap_or_else(|| RtResponse { status: 0, reason: String::new(), version: Version::Http2, headers: Headers::new(), body: Vec::new(), trailers: Headers::new() });
                    match self.inner.upgrade() {
                        Some(inner) => deliver(&inner, &self.lh, job, resp),
                        None => (job.cb)(Ok(resp)),
                    }
                    return;
                }
                _ => Work::Unary(job),
            },
            Kind::Call { mut job, trailers, .. } => match end {
                End::Complete => {
                    end_call(&job.ctl);
                    job.handler.on_end(Ok(trailers));
                    return;
                }
                _ => {
                    // the call is detached until it is opened again (or fails)
                    let mut st = job.ctl.lock();
                    st.target = None;
                    st.kicked = false;
                    drop(st);
                    Work::Call(job)
                }
            },
        };
        let err = match end {
            End::Complete => unreachable!("handled above"),
            End::Refused => {
                if *work.attempts() + 1 < MAX_ATTEMPTS && work.replayable() {
                    *work.attempts() += 1;
                    self.reroute(work);
                    return;
                }
                Error::new(ErrorKind::Reset(ErrorCode::REFUSED_STREAM.0 as u64), format!("stream refused by the peer: {}", self.what))
            }
            End::Reset(code) => Error::new(ErrorKind::Reset(code as u64), format!("stream reset by the peer (code {code:#x}): {}", self.what)),
            End::Fail(e) => e,
        };
        work.fail(err);
    }

    /// Sends work to another connection of the pool (opened if needed).
    fn reroute(&self, work: Work) {
        match self.inner.upgrade() {
            Some(inner) => dispatch(&inner, work, &self.lh, self.pos),
            None => work.fail(Error::new(ErrorKind::Closed, "client dropped")),
        }
    }

    /// The connection takes no new streams: it leaves the pool, its queue goes elsewhere.
    fn go_away(&mut self, cx: &mut Ctx<'_>) {
        if self.going_away {
            return;
        }
        self.going_away = true;
        if let Some(p) = &self.pin {
            p.going_away.store(true, Ordering::Release);
        }
        unpool(&self.key, self.id);
        if let Some((t, _)) = self.queue_timer.take() {
            cx.cancel_timer(t);
        }
        let works: Vec<Work> = self.entry.borrow_mut().queue.drain(..).collect();
        for w in works {
            self.reroute(w);
        }
    }

    /// The connection failed or closed: every stream ends; queued requests (never sent) move to
    /// another connection when `retry` (a lost connection, not a protocol or TLS failure).
    fn die(&mut self, e: Error, retry: bool) {
        if self.dead {
            return;
        }
        self.dead = true;
        self.going_away = true;
        if let Some(p) = &self.pin {
            p.dead.store(true, Ordering::Release);
            p.going_away.store(true, Ordering::Release);
            // a ping waiting for an answer gives up now
            p.pong_cv.notify_all();
        }
        unpool(&self.key, self.id);
        self.entry.borrow_mut().handle = None;
        let works: Vec<Work> = self.entry.borrow_mut().queue.drain(..).collect();
        for mut w in works {
            // never sent: another connection may carry it
            if retry && *w.attempts() + 1 < MAX_ATTEMPTS {
                *w.attempts() += 1;
                self.reroute(w);
            } else {
                w.fail(e.clone());
            }
        }
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            if let Some(s) = self.streams.remove(&id) {
                self.finish_stream(id, s, End::Fail(e.clone()));
            }
        }
    }

    // -------------------------------------------------------------- input

    /// Feeds received plaintext to the engine; returns the bytes consumed.
    fn feed(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let mut off = 0;
        while off < data.len() && !self.dead {
            let used = self.recv(cx, &data[off..]);
            off += used;
            if used == 0 {
                // a partial frame, or input paused while output waits: write and go on
                if self.h2.output().is_empty() {
                    break;
                }
                self.flush(cx);
            }
        }
        off
    }

    fn recv(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let ms = self.now_ms();
        let mut done: Vec<(u32, End)> = Vec::new();
        let mut release: Vec<(u32, usize)> = Vec::new();
        let mut goaway = false;
        let mut settings = false;
        let mut pongs = 0u64;
        let mut closed: Option<Error> = None;
        let max_body = self.set.max_body;
        let what = &self.what;
        let streams = &mut self.streams;
        let used = self.h2.recv(data, ms, &mut |e| match e {
            Event::Headers { stream, headers, end_stream } => {
                let status = headers.status().unwrap_or(0);
                if (100..200).contains(&status) && !end_stream {
                    return;
                }
                let Some(s) = streams.get_mut(&stream) else { return };
                if !s.head {
                    s.head = true;
                    let mut h = Headers::new();
                    for (n, v) in headers.iter() {
                        h.push_raw(n, v);
                    }
                    match &mut s.kind {
                        Kind::Unary { resp, .. } => {
                            *resp = Some(RtResponse { status, reason: crate::body::reason_of(status).into_owned(), version: Version::Http2, headers: h, body: Vec::new(), trailers: Headers::new() });
                        }
                        Kind::Call { job, .. } => job.handler.on_head(status, &h),
                    }
                }
                if end_stream {
                    done.push((stream, End::Complete));
                }
            }
            Event::Data { stream, data, end_stream } => {
                match streams.get_mut(&stream) {
                    Some(s) => match &mut s.kind {
                        Kind::Unary { resp, .. } => {
                            release.push((stream, data.len()));
                            if let Some(r) = resp {
                                r.body.extend_from_slice(data);
                                if r.body.len() as u64 > max_body {
                                    done.push((stream, End::Fail(Error::new(ErrorKind::Protocol, format!("response body larger than the limit: {what}")))));
                                    return;
                                }
                            }
                        }
                        Kind::Call { job, unreleased, .. } => {
                            if !data.is_empty() {
                                job.handler.on_data(data);
                            }
                            if job.manual {
                                *unreleased += data.len();
                            } else {
                                release.push((stream, data.len()));
                            }
                        }
                    },
                    None => release.push((stream, data.len())),
                }
                if end_stream {
                    done.push((stream, End::Complete));
                }
            }
            Event::Trailers { stream, trailers } => {
                if let Some(s) = streams.get_mut(&stream) {
                    let mut h = Headers::new();
                    for (n, v) in trailers.iter() {
                        h.push_raw(n, v);
                    }
                    match &mut s.kind {
                        Kind::Unary { resp: Some(r), .. } => r.trailers = h,
                        Kind::Call { trailers, .. } => *trailers = h,
                        _ => {}
                    }
                }
                done.push((stream, End::Complete));
            }
            Event::Reset { stream, code, .. } => {
                if code == ErrorCode::REFUSED_STREAM {
                    done.push((stream, End::Refused));
                } else {
                    done.push((stream, End::Reset(code.0)));
                }
            }
            Event::GoAway { code, .. } => {
                goaway = true;
                if code != ErrorCode::NO_ERROR {
                    closed = Some(Error::new(ErrorKind::Protocol, format!("HTTP/2 GOAWAY {}: {what}", code.name())));
                }
            }
            Event::Closed { code } => closed = Some(Error::new(ErrorKind::Protocol, format!("HTTP/2 connection error {}: {what}", code.name()))),
            Event::Settings => settings = true,
            Event::Pong { .. } => pongs += 1,
        });
        if settings {
            self.settings_seen = true;
        }
        if pongs > 0 {
            if let Some(p) = &self.pin {
                *p.pongs.lock().unwrap_or_else(|e| e.into_inner()) += pongs;
                p.pong_cv.notify_all();
            }
        }
        for (id, n) in release {
            if n > 0 {
                self.h2.release(id, n);
            }
        }
        for (id, end) in done {
            if matches!(end, End::Fail(_)) {
                self.h2.reset(id, ErrorCode::CANCEL);
            }
            self.finish(cx, id, end);
        }
        if goaway {
            self.go_away(cx);
        }
        if let Some(e) = closed {
            self.flush(cx);
            self.die(e, false);
            cx.close();
        }
        used
    }

    /// Takes received bytes through TLS into the engine; returns the bytes consumed.
    fn ingest(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let consumed;

        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            let mut off = 0;
            let was = self.handshaking();
            loop {
                let Some(t) = self.tls.as_mut() else { break };
                let k = t.read_tls(&data[off..]);
                off += k;
                if let Err(e) = t.process_new_packets() {
                    self.flush_tls(cx);
                    let e = crate::transport::tls_error(&e, &self.what);
                    self.die(e, false);
                    cx.close();
                    return data.len();
                }
                let p = t.plaintext();
                let got = !p.is_empty();
                if got {
                    let n = p.len();
                    self.input.extend_from_slice(p);
                    t.consume_plaintext(n);
                }
                if !got && (k == 0 || off >= data.len()) {
                    break;
                }
            }
            self.flush_tls(cx);
            if was && !self.handshaking() {
                self.transport_ready(cx);
                // the preface and SETTINGS were waiting for the handshake
                self.flush(cx);
            }
            let mut input = std::mem::take(&mut self.input);
            let used = self.feed(cx, &input);
            input.drain(..used);
            self.input = input;
            consumed = off;
        } else {
            consumed = self.feed(cx, data);
        }
        #[cfg(not(feature = "tls"))]
        {
            consumed = self.feed(cx, data);
        }
        consumed
    }

    fn handshaking(&self) -> bool {
        #[cfg(feature = "tls")]
        if let Some(t) = &self.tls {
            return t.is_handshaking();
        }
        false
    }

    /// The transport is ready: TLS done with ALPN `h2`, or plain TCP.
    fn transport_ready(&mut self, cx: &mut Ctx<'_>) {
        #[cfg(feature = "tls")]
        if let Some(t) = &self.tls {
            if t.alpn_protocol() != Some(b"h2") {
                let e = Error::new(ErrorKind::Unsupported, format!("the server did not select HTTP/2 in ALPN: {}", self.what));
                self.die(e, false);
                cx.close();
                return;
            }
        }
        let _ = &cx;
        self.ready = true;
    }

    fn enter(&self) {
        let (id, pos) = (self.key.0, self.pos);
        CURRENT.with(|c| c.set(Some((id, pos))));
    }

    /// The end of a callback: routes the requests its callbacks sent on this loop (they join
    /// this connection's queue, or another's), settles, and repeats while callbacks run by the
    /// settling sent more.
    fn leave(&mut self, cx: &mut Ctx<'_>) {
        for _ in 0..8 {
            let jobs = OUTBOX.with(|o| std::mem::take(&mut *o.borrow_mut()));
            if !jobs.is_empty() {
                match self.inner.upgrade() {
                    Some(inner) => {
                        // the settle below opens what lands in this connection's queue: no kick
                        let was = std::mem::replace(&mut self.entry.borrow_mut().kicked, true);
                        for j in jobs {
                            dispatch(&inner, Work::Unary(j), &self.lh, self.pos);
                        }
                        self.entry.borrow_mut().kicked = was;
                    }
                    None => {
                        for j in jobs {
                            (j.cb)(Err(Error::new(ErrorKind::Closed, "client dropped")));
                        }
                    }
                }
            }
            self.settle(cx);
            if OUTBOX.with(|o| o.borrow().is_empty()) {
                break;
            }
        }
        CURRENT.with(|c| c.set(None));
        let deferred = DEFERRED.with(|v| std::mem::take(&mut *v.borrow_mut()));
        for d in deferred {
            d.run();
        }
        // anything sent by the last round's callbacks goes through the loop's queue
        let jobs = OUTBOX.with(|o| std::mem::take(&mut *o.borrow_mut()));
        if let Some(inner) = self.inner.upgrade() {
            for j in jobs {
                dispatch(&inner, Work::Unary(j), &self.lh, self.pos);
            }
        }
    }
}

/// Moves a call's operations into its stream. `cancel` is set when the call was cancelled.
fn apply_ops(k: &mut Kind, ops: Vec<Op>, h2: &mut simoom_h2::Connection, id: u32, cancel: &mut bool) {
    let Kind::Call { job, out, fin, unreleased, .. } = k else { return };
    for op in ops {
        match op {
            Op::Data(d) => {
                if !d.is_empty() {
                    job.ctl.lock().drained = true;
                    out.push_back(d);
                }
            }
            Op::Finish(t) => *fin = Some(t),
            Op::Release(n) => {
                let n = n.min(*unreleased);
                if n > 0 {
                    *unreleased -= n;
                    h2.release(id, n);
                }
            }
            Op::Cancel => *cancel = true,
        }
    }
}

/// Sends what a stream has as far as flow control allows. Returns true when nothing is left
/// to send. Streams whose buffer drained below half the high water go to `writable`.
fn pump_stream(h2: &mut simoom_h2::Connection, id: u32, s: &mut Stream, writable: &mut Vec<u32>) -> bool {
    if s.local_end {
        return true;
    }
    match &mut s.kind {
        Kind::Unary { job, off, .. } => {
            let body = &job.req.body;
            match h2.send_data(id, &body[*off..], true) {
                Ok(n) => {
                    *off += n;
                    if *off == body.len() {
                        s.local_end = true;
                    }
                }
                // the reset event that follows ends the stream
                Err(_) => s.local_end = true,
            }
            s.local_end
        }
        Kind::Call { job, out, off, fin, want_writable, .. } => {
            let mut taken = 0;
            let mut stop = false;
            while let Some(front) = out.front() {
                let last = out.len() == 1;
                let end = last && matches!(fin, Some(None));
                match h2.send_data(id, &front[*off..], end) {
                    Ok(n) => {
                        *off += n;
                        taken += n;
                        if *off < front.len() {
                            stop = true;
                            break;
                        }
                        out.pop_front();
                        *off = 0;
                        if end {
                            *fin = None;
                            s.local_end = true;
                            break;
                        }
                    }
                    Err(_) => {
                        s.local_end = true;
                        out.clear();
                        break;
                    }
                }
            }
            if !stop && !s.local_end && out.is_empty() {
                match fin.take() {
                    Some(Some(t)) => {
                        let f: Vec<(&[u8], &[u8])> = t.iter().map(|(n, v)| (&n[..], &v[..])).collect();
                        let _ = h2.send_trailers(id, &f);
                        s.local_end = true;
                    }
                    Some(None) => {
                        let _ = h2.send_data(id, &[], true);
                        s.local_end = true;
                    }
                    None => {}
                }
            }
            if taken > 0 {
                let before = job.ctl.buffered.fetch_sub(taken, Ordering::AcqRel);
                let now = before.saturating_sub(taken);
                if before >= job.ctl.high {
                    *want_writable = true;
                }
                if *want_writable && now <= job.ctl.high / 2 {
                    *want_writable = false;
                    writable.push(id);
                }
            }
            // a call stays in the sending list until its end is sent (more bytes may come)
            s.local_end
        }
    }
}

impl Connection for H2Conn {
    fn on_open(&mut self, cx: &mut Ctx<'_>) {
        self.enter();
        let h = cx.handle();
        self.handle = Some(h.clone());
        let kicked = {
            let mut e = self.entry.borrow_mut();
            e.handle = Some(h);
            std::mem::replace(&mut e.kicked, false)
        };
        let _ = kicked;
        #[cfg(feature = "tls")]
        self.flush_tls(cx);
        if !self.handshaking() {
            self.transport_ready(cx);
        }
        if let Some(p) = &self.pin {
            *p.handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.handle());
            // what the blocking side read before the hand-over (and, with TLS, plaintext the
            // session already holds)
            self.flush(cx);
            let left = std::mem::take(&mut self.leftover);
            self.ingest(cx, &left);
        }
        self.leave(cx);
    }

    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        self.enter();
        let consumed = self.ingest(cx, data);
        self.leave(cx);
        consumed
    }

    fn on_eof(&mut self, cx: &mut Ctx<'_>) {
        self.enter();
        let e = Error::new(ErrorKind::Closed, format!("connection closed by the peer: {}", self.what));
        self.die(e, true);
        cx.close();
        self.leave(cx);
    }

    fn on_drain(&mut self, cx: &mut Ctx<'_>) {
        self.enter();
        self.leave(cx);
    }

    fn on_timer(&mut self, cx: &mut Ctx<'_>, token: u64) {
        self.enter();
        match token {
            ENGINE_TIMER => {
                self.engine_timer = None;
                let ms = self.now_ms();
                let mut closed = None;
                let what = self.what.clone();
                self.h2.handle_timeout(ms, &mut |e| {
                    if let Event::Closed { code } = e {
                        closed = Some(Error::new(ErrorKind::Protocol, format!("HTTP/2 connection error {}: {what}", code.name())));
                    }
                });
                if let Some(e) = closed {
                    self.flush(cx);
                    self.die(e, false);
                    cx.close();
                }
            }
            QUEUE_TIMER => {
                self.queue_timer = None;
                let now = Instant::now();
                let expired: Vec<Work> = {
                    let mut e = self.entry.borrow_mut();
                    let (gone, keep): (Vec<Work>, Vec<Work>) = e.queue.drain(..).partition(|w| w.deadline().is_some_and(|d| now >= d));
                    e.queue.extend(keep);
                    gone
                };
                for w in expired {
                    let e = Error::timeout(TimeoutKind::Total, &w.url().to_string());
                    w.fail(e);
                }
                self.arm_queue_timer(cx);
            }
            id => {
                let id = id as u32;
                if let Some(s) = self.streams.get_mut(&id) {
                    s.timer = None;
                    self.h2.reset(id, ErrorCode::CANCEL);
                    let what = match &s.kind {
                        Kind::Unary { job, .. } => job.req.url.to_string(),
                        Kind::Call { job, .. } => job.req.url.to_string(),
                    };
                    self.finish(cx, id, End::Fail(Error::timeout(TimeoutKind::Total, &what)));
                }
            }
        }
        self.leave(cx);
    }

    fn on_message(&mut self, cx: &mut Ctx<'_>, msg: Message) {
        self.enter();
        let msg = match msg.downcast::<PingMsg>() {
            Ok(_) => {
                self.h2.ping(*b"simoomka");
                self.leave(cx);
                return;
            }
            Err(m) => m,
        };
        let msg = match msg.downcast::<CloseMsg>() {
            Ok(_) => {
                self.h2.shutdown(self.now_ms());
                self.flush(cx);
                let e = Error::new(ErrorKind::Closed, format!("connection closed: {}", self.what));
                self.die(e, false);
                cx.close();
                self.leave(cx);
                return;
            }
            Err(m) => m,
        };
        let msg = match msg.downcast::<PinWork>() {
            Ok(mut w) => {
                if let Some(job) = w.0.take() {
                    if self.going_away {
                        let e = Error::new(ErrorKind::Closed, format!("HTTP/2 connection is going away: {}", self.what));
                        Work::Call(job).fail(e);
                    } else {
                        self.entry.borrow_mut().queue.push_back(Work::Call(job));
                    }
                }
                self.leave(cx);
                return;
            }
            Err(m) => m,
        };
        match msg.downcast::<Kick>() {
            Ok(_) => self.entry.borrow_mut().kicked = false,
            Err(msg) => {
                if let Ok(k) = msg.downcast::<CallKick>() {
                    let ctl = k.0;
                    let (ops, sid) = {
                        let mut st = ctl.lock();
                        st.kicked = false;
                        match st.target {
                            Some((_, conn, sid)) if conn == self.id => (std::mem::take(&mut st.ops), Some(sid)),
                            _ => (Vec::new(), None),
                        }
                    };
                    if let Some(sid) = sid {
                        let mut cancel = false;
                        if let Some(s) = self.streams.get_mut(&sid) {
                            apply_ops(&mut s.kind, ops, &mut self.h2, sid, &mut cancel);
                            if !s.local_end && !self.sending.contains(&sid) {
                                self.sending.push(sid);
                            }
                        }
                        if cancel {
                            self.h2.reset(sid, ErrorCode::CANCEL);
                            self.finish(cx, sid, End::Fail(Error::new(ErrorKind::Cancelled, "call cancelled")));
                        }
                    }
                }
            }
        }
        self.leave(cx);
    }

    fn on_stop(&mut self, cx: &mut Ctx<'_>) {
        self.h2.shutdown(self.now_ms());
        self.flush(cx);
        self.go_away(cx);
        if self.streams.is_empty() {
            cx.close();
        }
    }

    fn on_close(&mut self, reason: CloseReason) {
        let msg = match &reason {
            CloseReason::Error(e) => format!("connection error ({e}): {}", self.what),
            _ => format!("connection closed: {}", self.what),
        };
        self.die(Error::new(ErrorKind::Closed, msg), true);
    }
}

impl Drop for H2Conn {
    fn drop(&mut self) {
        if !self.dead {
            self.die(Error::new(ErrorKind::Closed, format!("connection dropped: {}", self.what)), false);
        }
    }
}
