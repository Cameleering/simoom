//! [`Reply`]: how a service answers, and the protocol-side `Target` it writes through.

use crate::handle::{BodySink, Responder};
use crate::request::{OwnedRequest, Request};
use crate::server::Shared;
use crate::service::{Outcome, Service};
use crate::types::{Body, HeaderBuf, Pushed, Response, StaticReply};
use simoom_rt::offload::OffloadPool;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// A body handed to a target: borrowed, static, or owned (moved, no copy).
pub(crate) enum BodyRef<'b> {
    Slice(&'b [u8]),
    Static(&'static [u8]),
    Owned(Vec<u8>),
}

impl BodyRef<'_> {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            BodyRef::Slice(s) => s,
            BodyRef::Static(s) => s,
            BodyRef::Owned(v) => v,
        }
    }

    fn into_body(self) -> Body {
        match self {
            BodyRef::Slice(s) => Body::Bytes(s.to_vec()),
            BodyRef::Static(s) => Body::Static(s),
            BodyRef::Owned(v) => Body::Bytes(v),
        }
    }
}

impl From<Body> for BodyRef<'static> {
    fn from(b: Body) -> Self {
        match b {
            Body::Empty => BodyRef::Static(b""),
            Body::Static(s) => BodyRef::Static(s),
            Body::Bytes(v) => BodyRef::Owned(v),
        }
    }
}

/// The protocol side of a [`Reply`]: one per request, implemented by each connection type.
pub(crate) trait Target {
    /// The header list the reply fills (cleared when the reply is created).
    fn headers(&mut self) -> &mut HeaderBuf;
    /// A complete response with the headers in [`Target::headers`].
    fn respond(&mut self, status: u16, body: BodyRef<'_>, close: bool);
    /// A pre-serialized response.
    fn fixed(&mut self, r: &StaticReply, close: bool) {
        let h = self.headers();
        h.clear();
        for (n, v) in r.headers.iter() {
            h.push(n, v);
        }
        self.respond(r.status, BodyRef::Slice(r.body.as_bytes()), close);
    }
    /// The response comes later through the returned responder.
    fn defer(&mut self) -> Responder;
    /// Undoes [`Target::defer`] (the offload pool refused the job).
    fn undefer(&mut self);
    /// Sends the head of a streamed response; the body comes through the sink.
    fn stream(&mut self, status: u16, close: bool) -> BodySink;
    /// The offload pool, or `None` when already running on it.
    fn pool(&mut self) -> Option<OffloadPool>;
    /// The server state (limits, counters).
    fn shared(&self) -> &Shared;
    /// The loop the request is on.
    fn loop_index(&self) -> usize;
    /// Switches the connection to WebSocket; `false` when the request isn't an upgrade.
    #[cfg(feature = "websocket")]
    fn websocket(&mut self, protocol: Option<&[u8]>, handler: Box<dyn crate::ws::WebSocketHandler>) -> bool {
        let _ = (protocol, handler);
        false
    }
}

/// How a [`crate::Service`] answers one request. Build the response with [`Reply::status`] and
/// [`Reply::header`], then finish it with exactly one of:
///
/// - [`Reply::body`], [`Reply::body_static`], [`Reply::body_copy`], [`Reply::empty`],
///   [`Reply::send`], [`Reply::fixed`]: an immediate response, written on the loop thread;
/// - [`Reply::defer`]: a [`Responder`] to answer later from any thread;
/// - [`Reply::stream`] / [`Reply::sse`]: a [`BodySink`] for a chunked or SSE body;
/// - [`Reply::offload`] / [`Reply::blocking`]: run the work on the offload pool;
/// - [`Reply::websocket`]: accept a WebSocket upgrade.
///
/// Dropping a reply without any of these sends a 500.
pub struct Reply<'a> {
    t: &'a mut dyn Target,
    status: u16,
    close: bool,
    invalid: bool,
}

impl std::fmt::Debug for Reply<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply").field("status", &self.status).finish()
    }
}

impl<'a> Reply<'a> {
    pub(crate) fn new(t: &'a mut dyn Target) -> Reply<'a> {
        t.headers().clear();
        Reply { t, status: 200, close: false, invalid: false }
    }

    /// Sets the status code (default 200). A code outside 100..=999, or a 1xx, turns into a 500.
    pub fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Adds a header. Names are sent in lower case. Framing fields are written by the server
    /// and ignored here; `connection: close` closes the connection after the response. An
    /// invalid name or value (CR, LF, NUL...) turns the response into a 500.
    pub fn header(mut self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Self {
        match self.t.headers().push(name.as_ref(), value.as_ref()) {
            Pushed::Close => self.close = true,
            Pushed::Invalid => self.invalid = true,
            _ => {}
        }
        self
    }

    fn ok(&self) -> bool {
        !self.invalid && (200..=999).contains(&self.status)
    }

    fn finish(self, body: BodyRef<'_>) -> Outcome {
        if self.ok() {
            self.t.respond(self.status, body, self.close);
        } else {
            self.t.headers().clear();
            self.t.respond(500, BodyRef::Static(b"Internal Server Error"), self.close);
        }
        Outcome::Done
    }

    /// Sends the response with this body.
    pub fn body(self, body: impl Into<Body>) -> Outcome {
        self.finish(body.into().into())
    }

    /// Sends the response with a static body (no copy for large bodies on plain HTTP/1.1).
    pub fn body_static(self, body: &'static [u8]) -> Outcome {
        self.finish(BodyRef::Static(body))
    }

    /// Sends the response with a copy of `body`.
    pub fn body_copy(self, body: &[u8]) -> Outcome {
        self.finish(BodyRef::Slice(body))
    }

    /// Sends the response without a body (`content-length: 0`).
    pub fn empty(self) -> Outcome {
        self.finish(BodyRef::Static(b""))
    }

    /// Sends an owned [`Response`] (its status and headers replace any set on this reply).
    pub fn send(mut self, response: Response) -> Outcome {
        let h = self.t.headers();
        h.clear();
        for (n, v) in response.headers.iter() {
            h.push(n, v);
        }
        self.status = response.status;
        self.close |= response.close;
        self.invalid = response.invalid;
        self.finish(response.body.into())
    }

    /// Sends a pre-serialized reply: the fastest path for fixed answers. Headers and status set
    /// on this reply are ignored.
    pub fn fixed(self, r: &StaticReply) -> Outcome {
        self.t.fixed(r, self.close);
        Outcome::Done
    }

    /// Defers the response: answer later, from any thread, with the [`Responder`]. While a
    /// response is deferred an HTTP/1.1 connection reads no further requests (replies stay in
    /// order); HTTP/2 and HTTP/3 streams carry on independently.
    pub fn defer(self) -> Responder {
        self.t.defer()
    }

    /// Sends the status and headers now and streams the body through the returned
    /// [`BodySink`]: chunked on HTTP/1.1 (close-delimited on HTTP/1.0).
    pub fn stream(self) -> BodySink {
        let status = if self.ok() { self.status } else { 500 };
        self.t.stream(status, self.close)
    }

    /// [`Reply::stream`] with `content-type: text/event-stream` and `cache-control: no-cache`:
    /// write events with [`BodySink::send_event`].
    pub fn sse(self) -> BodySink {
        self.header("content-type", "text/event-stream").header("cache-control", "no-cache").stream()
    }

    /// Runs `f` on the offload pool with an owned copy of the request; `f` answers through the
    /// reply it gets there, as an inline service would. Over capacity: a fast 503 with
    /// `Retry-After`.
    pub fn offload<F>(self, req: &mut Request<'_>, f: F) -> Outcome
    where
        F: FnOnce(&mut Request<'_>, Reply<'_>) -> Outcome + Send + 'static,
    {
        let owned = req.to_owned_request();
        let shared_loop = req.loop_index;
        self.submit(move |responder| run_detached(owned, responder, shared_loop, f))
    }

    /// Runs the blocking function `f` on the offload pool and sends its response. Over
    /// capacity: a fast 503 with `Retry-After`. See [`crate::blocking`].
    pub fn blocking<F>(self, req: &mut Request<'_>, f: F) -> Outcome
    where
        F: FnOnce(OwnedRequest) -> Response + Send + 'static,
    {
        let owned = req.to_owned_request();
        self.submit(move |responder| {
            let r = catch_unwind(AssertUnwindSafe(|| f(owned))).unwrap_or_else(|_| {
                let mut r = Response::error(500);
                r.close = true;
                r
            });
            responder.send(r);
        })
    }

    /// Runs a route the watchdog moved to the offload pool, timing each call there so the
    /// route can come back inline once it is fast again.
    pub(crate) fn offload_watched(self, req: &mut Request<'_>, svc: Arc<dyn Service>, watch: Arc<crate::watchdog::Watch>) -> Outcome {
        self.offload(req, move |r, reply| {
            let t0 = std::time::Instant::now();
            let (o, s) = crate::watchdog::measured(|| svc.call(r, reply));
            watch.offloaded_call(t0.elapsed().as_nanos() as u64, s);
            o
        })
    }

    fn submit(self, job: impl FnOnce(Responder) + Send + 'static) -> Outcome {
        let Some(pool) = self.t.pool() else {
            // Already on a worker: run here.
            job(self.t.defer());
            return Outcome::Deferred;
        };
        let responder = self.t.defer();
        match pool.try_submit(Box::new(move || job(responder))) {
            Ok(()) => Outcome::Deferred,
            Err(_) => {
                self.t.undefer();
                let li = self.t.loop_index();
                self.t.shared().counters(li).overloaded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let h = self.t.headers();
                h.clear();
                h.push(b"retry-after", b"1");
                h.push(b"content-type", b"text/plain");
                self.t.respond(503, BodyRef::Static(b"Service Unavailable"), false);
                Outcome::Done
            }
        }
    }

    /// Accepts a WebSocket upgrade ([`Request::is_websocket_upgrade`]): the `101` goes out and
    /// `handler` runs on the loop thread for the life of the connection. A request that is not
    /// a valid upgrade gets a 400.
    #[cfg(feature = "websocket")]
    pub fn websocket(self, handler: impl crate::ws::WebSocketHandler) -> Outcome {
        self.websocket_with_protocol(None, handler)
    }

    /// [`Reply::websocket`], choosing a subprotocol the client offered
    /// (`Sec-WebSocket-Protocol`).
    #[cfg(feature = "websocket")]
    pub fn websocket_with_protocol(self, protocol: Option<&str>, handler: impl crate::ws::WebSocketHandler) -> Outcome {
        if !self.t.websocket(protocol.map(str::as_bytes), Box::new(handler)) {
            self.t.headers().clear();
            self.t.respond(400, BodyRef::Static(b"Bad Request"), true);
        }
        Outcome::Done
    }
}

/// Runs a service-style closure on a worker thread with a reply that ends in `responder`.
fn run_detached<F>(mut owned: OwnedRequest, responder: Responder, loop_index: usize, f: F)
where
    F: FnOnce(&mut Request<'_>, Reply<'_>) -> Outcome,
{
    let mut t = Detached { responder: Some(responder), headers: HeaderBuf::default(), loop_index };
    let mut req = owned.as_request();
    let r = catch_unwind(AssertUnwindSafe(|| {
        let _ = f(&mut req, Reply::new(&mut t));
    }));
    if let Some(responder) = t.responder.take() {
        // No answer: a panic or a dropped reply.
        let mut resp = Response::error(500);
        resp.close = r.is_err();
        responder.send(resp);
    }
}

/// The target of a reply running on an offload worker: it answers through a responder.
struct Detached {
    responder: Option<Responder>,
    headers: HeaderBuf,
    loop_index: usize,
}

impl Target for Detached {
    fn headers(&mut self) -> &mut HeaderBuf {
        &mut self.headers
    }

    fn respond(&mut self, status: u16, body: BodyRef<'_>, close: bool) {
        if let Some(r) = self.responder.take() {
            r.send(Response { status, headers: std::mem::take(&mut self.headers), body: body.into_body(), close, invalid: false });
        }
    }

    fn fixed(&mut self, r: &StaticReply, close: bool) {
        if let Some(resp) = self.responder.take() {
            let mut x = r.to_response();
            x.close = close;
            resp.send(x);
        }
    }

    fn defer(&mut self) -> Responder {
        self.responder.take().expect("a reply completes once")
    }

    fn undefer(&mut self) {}

    fn stream(&mut self, status: u16, close: bool) -> BodySink {
        let r = self.responder.take().expect("a reply completes once");
        r.stream(Response { status, headers: std::mem::take(&mut self.headers), body: Body::Empty, close, invalid: false })
    }

    fn pool(&mut self) -> Option<OffloadPool> {
        None
    }

    fn shared(&self) -> &Shared {
        unreachable!("detached replies never refuse work")
    }

    fn loop_index(&self) -> usize {
        self.loop_index
    }
}
