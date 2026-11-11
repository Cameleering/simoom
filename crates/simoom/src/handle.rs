//! `Send` handles that reach a connection from any thread: [`Responder`] (a deferred reply),
//! [`BodySink`] (a streamed response body) and [`BodySource`] (a streamed request body).

use crate::types::{HeaderBuf, Response};
use simoom_rt::ConnHandle;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

/// Where messages for a request go: a TCP connection, or an HTTP/3 connection inside a UDP
/// endpoint.
#[derive(Clone, Debug)]
pub(crate) enum Route {
    Conn(ConnHandle),
    #[cfg(feature = "http3")]
    Ep(simoom_rt::EndpointHandle),
}

/// A message to a connection about one request (`token`: the HTTP/1.1 request number, or the
/// HTTP/2 or HTTP/3 stream id; `conn`: the HTTP/3 connection id).
pub(crate) struct Envelope {
    #[cfg_attr(not(feature = "http3"), allow(dead_code))]
    pub(crate) conn: u64,
    pub(crate) token: u64,
    pub(crate) msg: Msg,
}

pub(crate) enum Msg {
    /// A whole deferred response.
    Reply(Response),
    /// Start a streamed response with this head.
    Stream(Response, Arc<SinkShared>),
    /// Streamed body bytes.
    Chunk(Vec<u8>),
    /// End of a streamed body; `abort` resets it instead.
    End { abort: bool },
    /// End of a streamed body with trailer fields.
    EndTrailers(HeaderBuf),
    /// A responder was dropped without replying.
    Dropped,
    /// A body source has room again: read more from the socket.
    BodyResume,
    #[cfg(feature = "websocket")]
    Ws(crate::ws::WsCmd),
}

impl Route {
    pub(crate) fn send(&self, conn: u64, token: u64, msg: Msg) -> bool {
        let env = Box::new(Envelope { conn, token, msg });
        match self {
            Route::Conn(h) => h.send(env),
            #[cfg(feature = "http3")]
            Route::Ep(h) => h.send(env),
        }
    }
}

/// The cancellation state of a deferred request, shared by its [`Responder`] and its
/// connection.
#[derive(Default)]
pub(crate) struct Cancel {
    flag: std::sync::atomic::AtomicBool,
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl std::fmt::Debug for Cancel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cancel").field("cancelled", &self.is_set()).finish()
    }
}

impl Cancel {
    pub(crate) fn is_set(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The client is gone or the reply timed out: wakes the responder's holder (once).
    pub(crate) fn cancel(&self) {
        if self.flag.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        let hook = self.hook.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(f) = hook {
            f();
        }
    }
}

/// Answers a request later, from any thread ([`crate::Reply::defer`]). It completes exactly
/// once: [`Responder::send`] or [`Responder::stream`] consume it, and dropping it unanswered
/// sends a 500.
///
/// A deferred request ends early when the client goes away (the connection closes or resets,
/// an HTTP/2 or HTTP/3 stream is reset, an HTTP/1.1 client closes its side, as Go's
/// `net/http` treats it) or when [`crate::Limits::defer_timeout`] expires (the client then gets
/// a 504). [`Responder::is_cancelled`] and [`Responder::on_cancel`] tell the holder, which can
/// stop its work; a response sent after that is dropped.
#[derive(Debug)]
pub struct Responder {
    route: Route,
    conn: u64,
    token: u64,
    limit: usize,
    armed: bool,
    cancel: Arc<Cancel>,
    /// The negotiated content coding (feature `compression`): applied by `send` and `stream`.
    #[cfg(feature = "compression")]
    coding: Option<crate::compress::Neg>,
}

impl Responder {
    pub(crate) fn new(route: Route, conn: u64, token: u64, limit: usize, cancel: Arc<Cancel>) -> Responder {
        Responder {
            route,
            conn,
            token,
            limit,
            armed: true,
            cancel,
            #[cfg(feature = "compression")]
            coding: None,
        }
    }

    /// Sets the coding (keeps an earlier one when `n` is `None`: a reply on an offload worker
    /// passes on the responder it was given).
    #[cfg(feature = "compression")]
    pub(crate) fn with_coding(mut self, n: Option<crate::compress::Neg>) -> Self {
        if n.is_some() {
            self.coding = n;
        }
        self
    }

    /// True once the request was cancelled: the client went away or the deferred reply timed
    /// out ([`crate::Limits::defer_timeout`]). Cheap (one atomic load): poll it between steps of
    /// long work.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_set()
    }

    /// Runs `f` once when the request is cancelled (see [`Responder::is_cancelled`]): on the
    /// connection's loop thread, so it must be quick and must not block (set a flag, wake a
    /// thread). Runs at once, here, if the request is already cancelled. A later call replaces
    /// an earlier hook that has not run.
    pub fn on_cancel(&self, f: impl FnOnce() + Send + 'static) {
        let mut g = self.cancel.hook.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_set() {
            drop(g);
            f();
            return;
        }
        *g = Some(Box::new(f));
        drop(g);
        // cancelled between the check and the store: run it now
        if self.cancel.is_set() {
            let f = self.cancel.hook.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(f) = f {
                f();
            }
        }
    }

    /// Sends the response. Returns `false` if the connection is gone (the response is dropped).
    pub fn send(mut self, response: Response) -> bool {
        self.armed = false;
        #[cfg(feature = "compression")]
        let response = {
            let mut response = response;
            if let Some(n) = self.coding.take() {
                crate::compress::apply_response(&n, &mut response);
            }
            response
        };
        self.route.send(self.conn, self.token, Msg::Reply(response))
    }

    /// Starts a streamed response with `head`'s status and headers (its body is ignored) and
    /// returns the sink for the body.
    pub fn stream(mut self, head: Response) -> BodySink {
        self.armed = false;
        let shared = Arc::new(SinkShared::new(self.limit));
        #[cfg(feature = "compression")]
        let (head, enc) = {
            let mut head = head;
            let enc = match self.coding.take() {
                Some(n) if !head.invalid => crate::compress::stream(&n, head.status, &mut head.headers),
                _ => None,
            };
            (head, enc)
        };
        self.route.send(self.conn, self.token, Msg::Stream(head, shared.clone()));
        let sink = BodySink::new(self.route.clone(), self.conn, self.token, shared);
        #[cfg(feature = "compression")]
        let sink = match enc {
            Some(e) => sink.with_encoder(e),
            None => sink,
        };
        sink
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if self.armed {
            self.route.send(self.conn, self.token, Msg::Dropped);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Response body sink
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct SinkState {
    pending: usize,
    closed: bool,
    waker: Option<Waker>,
}

/// State shared between a [`BodySink`] and its connection.
#[derive(Debug)]
pub(crate) struct SinkShared {
    st: Mutex<SinkState>,
    cv: Condvar,
    limit: usize,
}

impl SinkShared {
    pub(crate) fn new(limit: usize) -> SinkShared {
        SinkShared { st: Mutex::new(SinkState::default()), cv: Condvar::new(), limit: limit.max(1) }
    }

    /// The connection wrote `n` bytes: writers may continue.
    pub(crate) fn credit(&self, n: usize) {
        if n == 0 {
            return;
        }
        let mut st = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        st.pending = st.pending.saturating_sub(n);
        let w = st.waker.take();
        drop(st);
        self.cv.notify_all();
        if let Some(w) = w {
            w.wake();
        }
    }

    /// The peer is gone or the stream was reset: writes fail from now on.
    pub(crate) fn close(&self) {
        let mut st = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        st.closed = true;
        let w = st.waker.take();
        drop(st);
        self.cv.notify_all();
        if let Some(w) = w {
            w.wake();
        }
    }
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the connection is gone")
}

/// The body of a streamed response ([`crate::Reply::stream`], [`crate::Reply::sse`]): chunked on
/// HTTP/1.1, DATA frames on HTTP/2 and HTTP/3. `Send`: write from any thread.
///
/// Backpressure: at most [`crate::Limits::stream_buffer`] bytes are handed to the connection and
/// not yet written. [`BodySink::write`] blocks beyond that (never call it on a loop thread);
/// [`BodySink::try_write`] fails with `WouldBlock`, and [`BodySink::ready`] is a future that
/// resolves when there is room. Dropping the sink ends the body; [`BodySink::abort`] cuts it off.
#[derive(Debug)]
pub struct BodySink {
    route: Route,
    conn: u64,
    token: u64,
    shared: Arc<SinkShared>,
    done: bool,
    /// Compresses the body (feature `compression`, [`crate::Compression::streams`]).
    #[cfg(feature = "compression")]
    enc: Option<Box<simoom_compress::Encoder>>,
}

impl BodySink {
    pub(crate) fn new(route: Route, conn: u64, token: u64, shared: Arc<SinkShared>) -> BodySink {
        BodySink {
            route,
            conn,
            token,
            shared,
            done: false,
            #[cfg(feature = "compression")]
            enc: None,
        }
    }

    #[cfg(feature = "compression")]
    pub(crate) fn with_encoder(mut self, e: Box<simoom_compress::Encoder>) -> Self {
        self.enc = Some(e);
        self
    }

    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if !self.route.send(self.conn, self.token, Msg::Chunk(data.to_vec())) {
            return Err(broken());
        }
        Ok(())
    }

    /// The bytes that go out for `data`: compressed and flushed when the body is compressed.
    #[inline]
    fn coded<'d>(&mut self, data: &'d [u8]) -> std::borrow::Cow<'d, [u8]> {
        #[cfg(feature = "compression")]
        if let Some(e) = &mut self.enc {
            if !data.is_empty() {
                return std::borrow::Cow::Owned(crate::compress::stream_chunk(e, data));
            }
        }
        std::borrow::Cow::Borrowed(data)
    }

    /// The end of a compressed body (its last block and trailer).
    fn end_coding(&mut self) {
        #[cfg(feature = "compression")]
        if let Some(mut e) = self.enc.take() {
            let tail = crate::compress::stream_end(&mut e);
            let _ = self.push(&tail);
        }
    }

    /// Writes `data`, waiting while the connection has `stream_buffer` bytes pending. Fails
    /// with `BrokenPipe` once the peer is gone.
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let data = self.coded(data);
        {
            let mut st = self.shared.st.lock().unwrap_or_else(PoisonError::into_inner);
            while st.pending >= self.shared.limit && !st.closed {
                st = self.shared.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
            }
            if st.closed {
                return Err(broken());
            }
            st.pending += data.len();
        }
        self.push(&data)
    }

    /// Writes all of `data` if fewer than `stream_buffer` bytes are pending, else fails with
    /// `WouldBlock`. Safe on a loop thread.
    pub fn try_write(&mut self, data: &[u8]) -> io::Result<usize> {
        {
            let mut st = self.shared.st.lock().unwrap_or_else(PoisonError::into_inner);
            if st.closed {
                return Err(broken());
            }
            if st.pending >= self.shared.limit {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            #[cfg(feature = "compression")]
            if self.enc.is_some() {
                // compressed only once there is room, so a refused write leaves no trace
                drop(st);
                let coded = self.coded(data);
                self.shared.st.lock().unwrap_or_else(PoisonError::into_inner).pending += coded.len();
                self.push(&coded)?;
                return Ok(data.len());
            }
            st.pending += data.len();
        }
        self.push(data)?;
        Ok(data.len())
    }

    /// Ready when a write would not wait (or the peer is gone).
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.shared.st.lock().unwrap_or_else(PoisonError::into_inner);
        if st.closed {
            return Poll::Ready(Err(broken()));
        }
        if st.pending < self.shared.limit {
            return Poll::Ready(Ok(()));
        }
        st.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// A future for [`BodySink::poll_ready`], for async callers (no runtime attached).
    pub fn ready(&mut self) -> Ready<'_> {
        Ready { sink: self }
    }

    /// Writes one server-sent event: each line of `data` as a `data:` field, then a blank line.
    pub fn send_event(&mut self, data: &str) -> io::Result<()> {
        let mut b = Vec::with_capacity(data.len() + 16);
        for line in data.split('\n') {
            b.extend_from_slice(b"data: ");
            b.extend_from_slice(line.as_bytes());
            b.push(b'\n');
        }
        b.push(b'\n');
        self.write(&b)
    }

    /// True once the peer is gone.
    pub fn is_closed(&self) -> bool {
        self.shared.st.lock().unwrap_or_else(PoisonError::into_inner).closed
    }

    /// Ends the body (same as dropping the sink).
    pub fn finish(mut self) {
        self.done = true;
        self.end_coding();
        self.route.send(self.conn, self.token, Msg::End { abort: false });
    }

    /// Ends the body with trailer fields: trailing HEADERS on HTTP/2 and HTTP/3 (gRPC's
    /// `grpc-status` and `grpc-message`), a trailer section after the last chunk on HTTP/1.1.
    /// HTTP/1.0 (a close-delimited body) and `HEAD` drop them. Invalid fields and framing fields
    /// are left out.
    pub fn finish_with_trailers(mut self, trailers: &[(&str, &str)]) {
        self.done = true;
        self.end_coding();
        let mut t = HeaderBuf::default();
        for (n, v) in trailers {
            t.push(n.as_bytes(), v.as_bytes());
        }
        self.route.send(self.conn, self.token, Msg::EndTrailers(t));
    }

    /// Cuts the body off: the HTTP/1.1 connection is closed, the HTTP/2 or HTTP/3 stream reset.
    pub fn abort(mut self) {
        self.done = true;
        self.route.send(self.conn, self.token, Msg::End { abort: true });
    }
}

impl io::Write for BodySink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        BodySink::write(self, buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BodySink {
    fn drop(&mut self) {
        if !self.done {
            self.end_coding();
            self.route.send(self.conn, self.token, Msg::End { abort: false });
        }
    }
}

/// The future returned by [`BodySink::ready`].
#[derive(Debug)]
pub struct Ready<'a> {
    sink: &'a mut BodySink,
}

impl Future for Ready<'_> {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sink.poll_ready(cx)
    }
}

// ---------------------------------------------------------------------------------------------
// Request body source
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct SrcState {
    buf: Vec<u8>,
    pos: usize,
    done: bool,
    error: Option<&'static str>,
    waker: Option<Waker>,
    /// The connection stopped reading because the buffer is full.
    loop_paused: bool,
    /// The [`BodySource`] was dropped: the connection discards the rest.
    abandoned: bool,
    /// Trailer fields, set with the end of the body.
    trailers: Vec<(Vec<u8>, Vec<u8>)>,
}

/// State shared between a [`BodySource`] and its connection.
#[derive(Debug)]
pub(crate) struct SrcShared {
    st: Mutex<SrcState>,
    cv: Condvar,
    cap: usize,
}

/// What [`SrcShared::push`] tells the connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Pushed {
    /// Room left.
    More,
    /// The buffer is full: stop reading until a `BodyResume` message.
    Full,
    /// Nobody reads any more: discard the rest of the body.
    Abandoned,
}

impl SrcShared {
    pub(crate) fn new(cap: usize, prefill: Vec<u8>) -> SrcShared {
        SrcShared { st: Mutex::new(SrcState { buf: prefill, ..SrcState::default() }), cv: Condvar::new(), cap: cap.max(1024) }
    }

    fn wake(&self, st: std::sync::MutexGuard<'_, SrcState>) {
        let mut st = st;
        let w = st.waker.take();
        drop(st);
        self.cv.notify_all();
        if let Some(w) = w {
            w.wake();
        }
    }

    pub(crate) fn push(&self, data: &[u8]) -> Pushed {
        let mut st = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        if st.abandoned {
            return Pushed::Abandoned;
        }
        if st.pos > 0 && st.pos == st.buf.len() {
            st.buf.clear();
            st.pos = 0;
        }
        st.buf.extend_from_slice(data);
        let full = st.buf.len() - st.pos >= self.cap;
        if full {
            st.loop_paused = true;
        }
        self.wake(st);
        if full {
            Pushed::Full
        } else {
            Pushed::More
        }
    }

    #[cfg(feature = "http2")]
    pub(crate) fn finish(&self) {
        self.finish_with(Vec::new());
    }

    /// The end of the body, with its trailer fields.
    pub(crate) fn finish_with(&self, trailers: Vec<(Vec<u8>, Vec<u8>)>) {
        let mut st = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        st.done = true;
        st.trailers = trailers;
        self.wake(st);
    }

    pub(crate) fn fail(&self, why: &'static str) {
        let mut st = self.st.lock().unwrap_or_else(PoisonError::into_inner);
        if !st.done {
            st.error = Some(why);
        }
        self.wake(st);
    }
}

/// A request body that streams ([`crate::Request::take_body`]): bodies larger than
/// [`crate::Limits::body_buffer`] or of unknown length. `Send`: read it from any thread.
///
/// Pull-based backpressure: the connection reads from the socket only while this source has
/// less than `body_buffer` bytes waiting, so a slow reader slows the client. [`BodySource`]
/// implements [`std::io::Read`] (blocking: never on a loop thread); [`BodySource::try_read`]
/// and [`BodySource::poll_read`] don't block. A body over [`crate::Limits::max_body`], or a
/// client that disappears, gives an error.
#[derive(Debug)]
pub struct BodySource {
    shared: Arc<SrcShared>,
    route: Route,
    conn: u64,
    token: u64,
}

impl BodySource {
    pub(crate) fn new(shared: Arc<SrcShared>, route: Route, conn: u64, token: u64) -> BodySource {
        BodySource { shared, route, conn, token }
    }

    fn take(&mut self, st: &mut SrcState, buf: &mut [u8]) -> usize {
        let n = buf.len().min(st.buf.len() - st.pos);
        buf[..n].copy_from_slice(&st.buf[st.pos..st.pos + n]);
        st.pos += n;
        if st.pos == st.buf.len() {
            st.buf.clear();
            st.pos = 0;
        }
        if st.loop_paused && st.buf.len() - st.pos < self.shared.cap / 2 {
            st.loop_paused = false;
            self.route.send(self.conn, self.token, Msg::BodyResume);
        }
        n
    }

    fn step(&mut self, st: &mut SrcState, buf: &mut [u8]) -> Option<io::Result<usize>> {
        if st.pos < st.buf.len() {
            return Some(Ok(self.take(st, buf)));
        }
        if let Some(e) = st.error {
            return Some(Err(io::Error::new(io::ErrorKind::UnexpectedEof, e)));
        }
        if st.done || buf.is_empty() {
            return Some(Ok(0));
        }
        None
    }

    /// Reads what is buffered; `WouldBlock` when nothing is.
    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let shared = self.shared.clone();
        let mut st = shared.st.lock().unwrap_or_else(PoisonError::into_inner);
        self.step(&mut st, buf).unwrap_or_else(|| Err(io::ErrorKind::WouldBlock.into()))
    }

    /// Reads what is buffered, or registers the waker.
    pub fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let shared = self.shared.clone();
        let mut st = shared.st.lock().unwrap_or_else(PoisonError::into_inner);
        match self.step(&mut st, buf) {
            Some(r) => Poll::Ready(r),
            None => {
                st.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// True once the whole body was received (it may still be buffered here).
    pub fn is_complete(&self) -> bool {
        self.shared.st.lock().unwrap_or_else(PoisonError::into_inner).done
    }

    /// The request's trailer fields (see [`crate::Request::trailers`]), once the whole body was
    /// received ([`BodySource::is_complete`]; reading to the end guarantees it); empty before,
    /// and when the request has none.
    pub fn trailers(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let st = self.shared.st.lock().unwrap_or_else(PoisonError::into_inner);
        if st.done {
            st.trailers.clone()
        } else {
            Vec::new()
        }
    }
}

impl io::Read for BodySource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let shared = self.shared.clone();
        let mut st = shared.st.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(r) = self.step(&mut st, buf) {
                return r;
            }
            st = shared.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl Drop for BodySource {
    fn drop(&mut self) {
        let mut st = self.shared.st.lock().unwrap_or_else(PoisonError::into_inner);
        st.abandoned = true;
        st.buf = Vec::new();
        st.pos = 0;
        if st.loop_paused {
            st.loop_paused = false;
            drop(st);
            self.route.send(self.conn, self.token, Msg::BodyResume);
        }
    }
}
