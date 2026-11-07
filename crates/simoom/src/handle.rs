//! `Send` handles that reach a connection from any thread: [`Responder`] (a deferred reply),
//! [`BodySink`] (a streamed response body) and [`BodySource`] (a streamed request body).

use crate::types::Response;
use simoom_rt::ConnHandle;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
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

/// Answers a request later, from any thread ([`crate::Reply::defer`]). It completes exactly
/// once: [`Responder::send`] or [`Responder::stream`] consume it, and dropping it unanswered
/// sends a 500.
#[derive(Debug)]
pub struct Responder {
    route: Route,
    conn: u64,
    token: u64,
    limit: usize,
    armed: bool,
}

impl Responder {
    pub(crate) fn new(route: Route, conn: u64, token: u64, limit: usize) -> Responder {
        Responder { route, conn, token, limit, armed: true }
    }

    /// Sends the response. Returns `false` if the connection is gone (the response is dropped).
    pub fn send(mut self, response: Response) -> bool {
        self.armed = false;
        self.route.send(self.conn, self.token, Msg::Reply(response))
    }

    /// Starts a streamed response with `head`'s status and headers (its body is ignored) and
    /// returns the sink for the body.
    pub fn stream(mut self, head: Response) -> BodySink {
        self.armed = false;
        let shared = Arc::new(SinkShared::new(self.limit));
        self.route.send(self.conn, self.token, Msg::Stream(head, shared.clone()));
        BodySink { route: self.route.clone(), conn: self.conn, token: self.token, shared, done: false }
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
        let mut st = self.st.lock().unwrap();
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
        let mut st = self.st.lock().unwrap();
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
}

impl BodySink {
    pub(crate) fn new(route: Route, conn: u64, token: u64, shared: Arc<SinkShared>) -> BodySink {
        BodySink { route, conn, token, shared, done: false }
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

    /// Writes `data`, waiting while the connection has `stream_buffer` bytes pending. Fails
    /// with `BrokenPipe` once the peer is gone.
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        {
            let mut st = self.shared.st.lock().unwrap();
            while st.pending >= self.shared.limit && !st.closed {
                st = self.shared.cv.wait(st).unwrap();
            }
            if st.closed {
                return Err(broken());
            }
            st.pending += data.len();
        }
        self.push(data)
    }

    /// Writes all of `data` if fewer than `stream_buffer` bytes are pending, else fails with
    /// `WouldBlock`. Safe on a loop thread.
    pub fn try_write(&mut self, data: &[u8]) -> io::Result<usize> {
        {
            let mut st = self.shared.st.lock().unwrap();
            if st.closed {
                return Err(broken());
            }
            if st.pending >= self.shared.limit {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            st.pending += data.len();
        }
        self.push(data)?;
        Ok(data.len())
    }

    /// Ready when a write would not wait (or the peer is gone).
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.shared.st.lock().unwrap();
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
        self.shared.st.lock().unwrap().closed
    }

    /// Ends the body (same as dropping the sink).
    pub fn finish(mut self) {
        self.done = true;
        self.route.send(self.conn, self.token, Msg::End { abort: false });
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
        let mut st = self.st.lock().unwrap();
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

    pub(crate) fn finish(&self) {
        let mut st = self.st.lock().unwrap();
        st.done = true;
        self.wake(st);
    }

    pub(crate) fn fail(&self, why: &'static str) {
        let mut st = self.st.lock().unwrap();
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
        let mut st = shared.st.lock().unwrap();
        self.step(&mut st, buf).unwrap_or_else(|| Err(io::ErrorKind::WouldBlock.into()))
    }

    /// Reads what is buffered, or registers the waker.
    pub fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let shared = self.shared.clone();
        let mut st = shared.st.lock().unwrap();
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
        self.shared.st.lock().unwrap().done
    }
}

impl io::Read for BodySource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let shared = self.shared.clone();
        let mut st = shared.st.lock().unwrap();
        loop {
            if let Some(r) = self.step(&mut st, buf) {
                return r;
            }
            st = shared.cv.wait(st).unwrap();
        }
    }
}

impl Drop for BodySource {
    fn drop(&mut self) {
        let mut st = self.shared.st.lock().unwrap();
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
