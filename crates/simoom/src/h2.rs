//! HTTP/2 on a connection (h2c prior knowledge, `Upgrade: h2c`, h2 over TLS): drives the
//! sans-io `simoom_h2::Connection`, one request per stream.

use crate::conn::{Io, Layer};
use crate::handle::{BodySink, BodySource, Cancel, Envelope, Msg, Pushed as SrcPushed, Responder, Route, SinkShared, SrcShared};
use crate::reply::{BodyRef, Target};
use crate::request::{HeaderView, Request};
use crate::server::{bump, Shared};
use crate::types::{HeaderBuf, OwnedHead, Version};
use crate::util::{decimal, has_body, with_date, FastMap};
use simoom_h2::{Connection, ErrorCode, Event};
use simoom_rt::offload::OffloadPool;
use std::collections::VecDeque;
use std::sync::Arc;

#[derive(Default)]
enum Phase {
    /// The request is being received or the handler runs.
    #[default]
    Open,
    /// Deferred.
    Waiting(Arc<Cancel>, crate::util::Pending),
    /// The response head is out; body bytes may be pending.
    Sending,
    /// A streamed body.
    Streaming(Arc<SinkShared>),
    /// The response is complete.
    Done,
    /// A WebSocket runs on the stream (RFC 8441): the 200 is out, frames go both ways.
    #[cfg(feature = "websocket-h2")]
    Socket,
}

/// WebSocket over HTTP/2 (RFC 8441) on one stream.
#[cfg(feature = "websocket-h2")]
#[derive(Default)]
struct WsPart {
    /// An extended CONNECT with `:protocol websocket`.
    req: bool,
    core: Option<Box<crate::ws::WsCore>>,
    /// DATA received since the last run, and whether the client ended its side.
    input: Vec<u8>,
    eof: bool,
    queued: bool,
    /// The request's `sec-websocket-extensions` (permessage-deflate offers).
    extensions: Option<Vec<u8>>,
}

#[derive(Default)]
struct ReqPart {
    head: OwnedHead,
    body: Vec<u8>,
    /// The request's trailing HEADERS, when they came before the service was called.
    trailers: Option<OwnedHead>,
}

#[derive(Default)]
struct RespPart {
    phase: Phase,
    /// Body bytes not yet accepted by the flow-control windows.
    pending: Vec<u8>,
    pending_fin: bool,
    /// Streamed bytes not yet credited to the sink.
    unacked: usize,
    head_only: bool,
    /// Trailer fields sent once `pending` is out (instead of END_STREAM on the last DATA).
    trailers: Option<Box<HeaderBuf>>,
    /// The status sent and the body bytes handed over ([`crate::Builder::on_complete`]).
    status: u16,
    out: u64,
    /// The streamed body was cut off.
    aborted: bool,
}

/// Finished streams kept per connection for reuse (their buffers keep their capacity).
const FREE_STREAMS: usize = 64;

#[derive(Default)]
struct St {
    req: ReqPart,
    resp: RespPart,
    end: bool,
    queued: bool,
    dispatched: bool,
    src: Option<Arc<SrcShared>>,
    /// Received DATA to release (credit) after `recv`.
    release: usize,
    /// DATA held back while the source is full.
    held: usize,
    full: bool,
    error: Option<u16>,
    /// When the request head arrived (loop clock) and its body bytes so far.
    t0: u64,
    b_in: u64,
    #[cfg(feature = "websocket-h2")]
    ws: WsPart,
}

pub(crate) struct H2Layer {
    conn: Connection,
    streams: FastMap<u32, Box<St>>,
    ready: Vec<u32>,
    resets: Vec<u32>,
    touched: Vec<u32>,
    hdrs: HeaderBuf,
    idle_since: u64,
    stopping: bool,
    /// Close after the current streams (a panic, or `connection: close`).
    close_after: bool,
    /// Finished streams for reuse: a new stream allocates nothing once its buffers grew.
    free: Vec<Box<St>>,
    /// Trailer fields of the next response ([`crate::Reply::trailer`]).
    trl: HeaderBuf,
    /// Deferred streams in deadline order ([`crate::Limits::defer_timeout`]).
    waits: VecDeque<(u64, u32)>,
    /// WebSocket streams with input to process; a WebSocket was ever accepted here.
    #[cfg(feature = "websocket-h2")]
    ws_ready: Vec<u32>,
    #[cfg(feature = "websocket-h2")]
    has_ws: bool,
}

impl St {
    /// Clears a finished stream for reuse, keeping the capacity of its buffers.
    fn recycle(mut self: Box<St>) -> Box<St> {
        let mut head = std::mem::take(&mut self.req.head);
        head.clear();
        let mut body = std::mem::take(&mut self.req.body);
        body.clear();
        let mut pending = std::mem::take(&mut self.resp.pending);
        pending.clear();
        *self = St::default();
        self.req.head = head;
        self.req.body = body;
        self.resp.pending = pending;
        self
    }
}

impl H2Layer {
    pub(crate) fn new(sh: &Shared, now: u64) -> H2Layer {
        H2Layer::with(Connection::server(sh.h2.clone()), now)
    }

    fn with(conn: Connection, now: u64) -> H2Layer {
        H2Layer {
            conn,
            streams: FastMap::default(),
            ready: Vec::new(),
            resets: Vec::new(),
            touched: Vec::new(),
            hdrs: HeaderBuf::default(),
            idle_since: now,
            stopping: false,
            close_after: false,
            free: Vec::new(),
            trl: HeaderBuf::default(),
            waits: VecDeque::new(),
            #[cfg(feature = "websocket-h2")]
            ws_ready: Vec::new(),
            #[cfg(feature = "websocket-h2")]
            has_ws: false,
        }
    }

    fn release_stream(&mut self, st: Box<St>) {
        if self.free.len() < FREE_STREAMS && st.req.body.capacity() <= 64 * 1024 && st.resp.pending.capacity() <= 64 * 1024 {
            self.free.push(st.recycle());
        }
    }

    /// After `101 Switching Protocols` for `Upgrade: h2c`: the request becomes stream 1.
    pub(crate) fn upgrade(io: &mut Io<'_, '_>, settings: &[u8], head: OwnedHead) -> Option<H2Layer> {
        let conn = Connection::server_upgrade(io.sh.h2.clone(), settings).ok()?;
        io.write(simoom_http1::h2c::SWITCHING_PROTOCOLS);
        let mut l = H2Layer::with(conn, io.now);
        let mut st = Box::<St>::default();
        st.resp.head_only = head.method() == b"HEAD";
        st.req.head = head;
        st.end = true;
        l.streams.insert(1, st);
        l.ready.push(1);
        Some(l)
    }

    fn now_ms(io: &Io<'_, '_>) -> u64 {
        io.now / 1_000_000
    }

    /// Applies what `recv` (or a timeout) collected: credits, resets, dispatches.
    fn process(&mut self, io: &mut Io<'_, '_>) {
        for id in std::mem::take(&mut self.touched) {
            if let Some(st) = self.streams.get_mut(&id) {
                let n = std::mem::take(&mut st.release);
                if n > 0 {
                    self.conn.release(id, n);
                }
            }
        }
        for id in std::mem::take(&mut self.resets) {
            if let Some(st) = self.streams.remove(&id) {
                match &st.resp.phase {
                    Phase::Streaming(s) => s.close(),
                    Phase::Waiting(c, _) => c.cancel(),
                    _ => {}
                }
                if let Some(src) = &st.src {
                    src.fail("the stream was reset");
                }
                if st.dispatched {
                    report(io, &st, true);
                }
            }
            self.conn.stream_finished(id);
        }
        #[cfg(feature = "websocket-h2")]
        for id in std::mem::take(&mut self.ws_ready) {
            self.ws_feed(io, id);
        }
        for id in std::mem::take(&mut self.ready) {
            self.dispatch(io, id);
        }
    }

    /// Runs `f` on the WebSocket of stream `id` and sends what it wrote; ends the stream when
    /// the WebSocket closed.
    #[cfg(feature = "websocket-h2")]
    #[cold]
    #[inline(never)]
    fn ws_run(&mut self, io: &mut Io<'_, '_>, id: u32, st: &mut St, f: &mut dyn FnMut(&mut crate::ws::WsCore, &mut crate::ws::WsIo)) {
        let Some(core) = st.ws.core.as_mut() else { return };
        let mut w = crate::ws::WsIo::new(Route::Conn(io.cx.handle()), 0, u64::from(id), io.now);
        f(core, &mut w);
        if w.panicked {
            bump(&io.sh.counters(io.li).panics);
        }
        if matches!(st.resp.phase, Phase::Socket) {
            st.resp.out += w.out.len() as u64;
            st.resp.pending.extend_from_slice(&w.out);
            st.resp.pending_fin |= w.close;
            push_pending(&mut self.conn, id, &mut st.resp);
        }
    }

    /// Feeds received DATA to a WebSocket stream.
    #[cfg(feature = "websocket-h2")]
    #[cold]
    #[inline(never)]
    fn ws_feed(&mut self, io: &mut Io<'_, '_>, id: u32) {
        let Some(mut st) = self.streams.remove(&id) else { return };
        st.ws.queued = false;
        let data = std::mem::take(&mut st.ws.input);
        let eof = st.ws.eof;
        self.ws_run(io, id, &mut st, &mut |c, w| {
            c.input(w, &data);
            if eof && !c.is_done() {
                c.eof(w);
            }
        });
        let mut data = data;
        data.clear();
        if st.ws.input.is_empty() {
            st.ws.input = data;
        }
        self.settle(io, id, st);
    }

    /// The WebSocket streams, for a connection-wide action (stop, close timeouts).
    #[cfg(feature = "websocket-h2")]
    #[cold]
    #[inline(never)]
    fn ws_each(&mut self, io: &mut Io<'_, '_>, due: &dyn Fn(&crate::ws::WsCore) -> bool, f: &mut dyn FnMut(&mut crate::ws::WsCore, &mut crate::ws::WsIo)) {
        if !self.has_ws {
            return;
        }
        let ids: Vec<u32> = self.streams.iter().filter(|(_, st)| st.ws.core.as_deref().is_some_and(due)).map(|(&id, _)| id).collect();
        for id in ids {
            if let Some(mut st) = self.streams.remove(&id) {
                self.ws_run(io, id, &mut st, f);
                self.settle(io, id, st);
            }
        }
    }

    fn dispatch(&mut self, io: &mut Io<'_, '_>, id: u32) {
        let Some(mut st) = self.streams.remove(&id) else { return };
        st.queued = false;
        if st.dispatched {
            self.streams.insert(id, st);
            return;
        }
        st.dispatched = true;
        bump(&io.sh.counters(io.li).requests);
        let sh = io.sh;
        let mut panicked = false;
        if let Some(code) = st.error {
            let reason = simoom_http1::write::reason(code).as_bytes();
            self.hdrs.clear();
            respond(&mut self.conn, &self.hdrs, &mut self.trl, &mut st.resp, sh, io.now, id, code, BodyRef::Static(reason));
        } else if io.shed || crate::util::over_pending() {
            // Admission control: the loop is behind, or has too many replies outstanding (K5);
            // refuse the stream without the service.
            bump(&sh.counters(io.li).shed);
            self.hdrs.clear();
            self.hdrs.push(b"retry-after", b"1");
            self.hdrs.push(b"content-type", b"text/plain");
            respond(&mut self.conn, &self.hdrs, &mut self.trl, &mut st.resp, sh, io.now, id, 503, BodyRef::Static(b"Service Unavailable"));
        } else {
            #[cfg(feature = "websocket-h2")]
            let streaming = !st.end && !st.ws.req;
            #[cfg(not(feature = "websocket-h2"))]
            let streaming = !st.end;
            if streaming {
                st.src = Some(Arc::new(SrcShared::new(sh.limits.body_buffer, std::mem::take(&mut st.req.body))));
            }
            let St {
                req,
                resp,
                src,
                #[cfg(feature = "websocket-h2")]
                ws,
                ..
            } = &mut *st;
            let mut r = Request::new(req.head.method(), req.head.target(), Version::H2, HeaderView::Owned(&req.head));
            r.authority = req.head.authority();
            r.body = &req.body;
            r.trailers = req.trailers.as_ref();
            r.peer = io.peer;
            r.secure = io.secure;
            r.loop_index = io.li;
            r.meta = Some(io.meta);
            #[cfg(feature = "websocket-h2")]
            {
                r.websocket = ws.req;
            }
            if let Some(s) = src {
                r.streamed = true;
                r.source = Some(BodySource::new(s.clone(), Route::Conn(io.cx.handle()), 0, u64::from(id)));
            }
            let mut clock = io.clock.take();
            let mut t = H2Target {
                conn: &mut self.conn,
                hdrs: &mut self.hdrs,
                trl: &mut self.trl,
                waits: &mut self.waits,
                resp,
                io,
                id,
                answered: false,
                close: false,
                #[cfg(feature = "websocket-h2")]
                ws,
            };
            panicked = crate::server::call(sh, &mut r, &mut t, &mut clock);
            let (answered, close) = (t.answered, t.close);
            io.clock = clock;
            drop(r);
            self.close_after |= close || panicked;
            if !answered {
                self.hdrs.clear();
                self.trl.clear();
                respond(&mut self.conn, &self.hdrs, &mut self.trl, &mut st.resp, sh, io.now, id, 500, BodyRef::Static(b"Internal Server Error"));
            }
        }
        if panicked {
            self.conn.shutdown(Self::now_ms(io));
        }
        #[cfg(feature = "websocket-h2")]
        if st.ws.core.is_some() {
            // accepted: open it, with any frames that came with the request
            self.has_ws = true;
            let body = std::mem::take(&mut st.req.body);
            let eof = st.end;
            self.ws_run(io, id, &mut st, &mut |c, w| {
                c.start(w);
                if !body.is_empty() {
                    c.input(w, &body);
                }
                if eof && !c.is_done() {
                    c.eof(w);
                }
            });
        }
        self.settle(io, id, st);
    }

    /// Puts a stream back, or finishes it when its response is complete.
    fn settle(&mut self, io: &Io<'_, '_>, id: u32, st: Box<St>) {
        if matches!(st.resp.phase, Phase::Done) {
            report(io, &st, st.resp.aborted);
            if let Some(src) = &st.src {
                if !st.end {
                    src.fail("the response ended before the request body");
                }
            }
            self.conn.stream_finished(id);
            self.release_stream(st);
        } else {
            self.streams.insert(id, st);
        }
    }

    /// Continues pending body bytes of `id`.
    fn resume_send(&mut self, io: &Io<'_, '_>, id: u32) {
        let Some(mut st) = self.streams.remove(&id) else { return };
        push_pending(&mut self.conn, id, &mut st.resp);
        self.settle(io, id, st);
    }

    /// [`crate::Limits::defer_timeout`]: deferred streams whose responder took too long get a
    /// 504 and are cancelled.
    fn expire_waits(&mut self, io: &mut Io<'_, '_>) {
        while let Some(&(at, id)) = self.waits.front() {
            if at > io.now {
                break;
            }
            self.waits.pop_front();
            let Some(mut st) = self.streams.remove(&id) else { continue };
            if let Phase::Waiting(c, _) = &st.resp.phase {
                c.cancel();
                bump(&io.sh.counters(io.li).timeouts);
                self.hdrs.clear();
                self.trl.clear();
                respond(&mut self.conn, &self.hdrs, &mut self.trl, &mut st.resp, io.sh, io.now, id, 504, BodyRef::Static(b"Gateway Timeout"));
            }
            self.settle(io, id, st);
        }
    }

    /// Moves output to the runtime while it isn't backed up, resuming blocked streams.
    fn flush(&mut self, io: &mut Io<'_, '_>) {
        let high = 256 * 1024;
        loop {
            while let Some(id) = self.conn.poll_writable() {
                self.resume_send(io, id);
            }
            let out = self.conn.output();
            if out.is_empty() || io.cx.queued() >= high {
                break;
            }
            // Every stream's HEADERS and DATA of this turn are in one buffer: hand it over
            // whole (no copy on plain TCP) and send once.
            if io.out_is_empty() && io.plain() {
                let fresh = io.cx.buffer(16 * 1024);
                let v = self.conn.take_output(fresh);
                io.cx.send(v);
                continue;
            }
            let n = out.len();
            io.write(out);
            self.conn.advance_output(n);
            io.flush();
        }
        if self.conn.wants_close() {
            io.close = true;
        }
        if self.streams.is_empty() && self.close_after && !self.stopping {
            self.stopping = true;
            self.conn.shutdown(Self::now_ms(io));
            let out = self.conn.output();
            let n = out.len();
            io.write(out);
            self.conn.advance_output(n);
        }
        if self.streams.is_empty() && self.idle_since == 0 {
            self.idle_since = io.now;
        } else if !self.streams.is_empty() {
            self.idle_since = 0;
        }
    }

    fn recv(&mut self, io: &mut Io<'_, '_>, data: &[u8]) -> usize {
        let now_ms = Self::now_ms(io);
        let buffer = io.sh.limits.body_buffer;
        let max_body = io.sh.limits.max_body;
        let now = io.now;
        let streams = &mut self.streams;
        let free = &mut self.free;
        let ready = &mut self.ready;
        let resets = &mut self.resets;
        let touched = &mut self.touched;
        #[cfg(feature = "websocket-h2")]
        let ws_ready = &mut self.ws_ready;
        let n = self.conn.recv(data, now_ms, &mut |ev| match ev {
            Event::Headers { stream, headers, end_stream } => {
                let mut st = free.pop().unwrap_or_default();
                let h = &mut st.req.head;
                h.set_method(headers.method().unwrap_or(b"GET"));
                h.set_target(headers.path().unwrap_or(b"/"));
                if let Some(a) = headers.authority() {
                    h.set_authority(a);
                }
                for (n, v) in headers.iter() {
                    h.add_field(n, v);
                }
                st.resp.head_only = headers.method() == Some(b"HEAD");
                st.end = end_stream;
                st.t0 = now;
                #[cfg(feature = "websocket-h2")]
                {
                    st.ws.req = headers.protocol() == Some(b"websocket");
                    st.ws.extensions = if st.ws.req { headers.get(b"sec-websocket-extensions").map(<[u8]>::to_vec) } else { None };
                }
                if end_stream || headers.method() == Some(b"CONNECT") {
                    st.queued = true;
                    ready.push(stream);
                }
                streams.insert(stream, st);
            }
            Event::Data { stream, data, end_stream } => {
                let Some(st) = streams.get_mut(&stream) else { return };
                touched.push(stream);
                st.b_in += data.len() as u64;
                #[cfg(feature = "websocket-h2")]
                if st.ws.core.is_some() {
                    st.release += data.len();
                    st.ws.input.extend_from_slice(data);
                    st.ws.eof |= end_stream;
                    st.end |= end_stream;
                    if !st.ws.queued {
                        st.ws.queued = true;
                        ws_ready.push(stream);
                    }
                    return;
                }
                if st.dispatched {
                    match &st.src {
                        Some(src) if !st.end => match src.push(data) {
                            SrcPushed::Full => {
                                st.full = true;
                                st.held += data.len();
                            }
                            _ if st.full => st.held += data.len(),
                            _ => st.release += data.len(),
                        },
                        _ => st.release += data.len(),
                    }
                    if end_stream {
                        st.end = true;
                        if let Some(src) = &st.src {
                            src.finish();
                        }
                    }
                } else {
                    st.req.body.extend_from_slice(data);
                    st.release += data.len();
                    if end_stream {
                        st.end = true;
                    }
                    if st.req.body.len() as u64 > max_body {
                        st.error = Some(413);
                        st.end = true;
                    }
                    if (st.end || st.req.body.len() > buffer) && !st.queued {
                        st.queued = true;
                        ready.push(stream);
                    }
                }
            }
            Event::Trailers { stream, trailers } => {
                if let Some(st) = streams.get_mut(&stream) {
                    st.end = true;
                    if st.dispatched {
                        if let Some(src) = &st.src {
                            src.finish_with(trailers.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect());
                        }
                    } else {
                        let mut t = OwnedHead::default();
                        for (n, v) in trailers.iter() {
                            t.add_field(n, v);
                        }
                        st.req.trailers = Some(t);
                        if !st.queued {
                            st.queued = true;
                            ready.push(stream);
                        }
                    }
                }
            }
            Event::Reset { stream, .. } => resets.push(stream),
            Event::GoAway { .. } | Event::Settings | Event::Pong { .. } | Event::Closed { .. } => {}
        });
        self.process(io);
        n
    }
}

/// Reports a finished stream to [`crate::Builder::on_complete`], when one is set.
fn report(io: &Io<'_, '_>, st: &St, aborted: bool) {
    if io.sh.on_complete.is_some() {
        io.sh.complete(st.resp.status, st.b_in, st.resp.out, st.t0, io.now, Version::H2, io.peer, io.meta.listener, aborted);
    }
}

/// The fields of a trailer list, for the codec.
fn fields(t: &HeaderBuf) -> Vec<(&[u8], &[u8])> {
    t.iter().collect()
}

/// Sends a whole response on `id`, with the trailers in `trl` (emptied).
#[allow(clippy::too_many_arguments)]
fn respond(conn: &mut Connection, hdrs: &HeaderBuf, trl: &mut HeaderBuf, rs: &mut RespPart, sh: &Shared, now: u64, id: u32, status: u16, body: BodyRef<'_>) {
    let bytes = body.as_bytes();
    let with_body = has_body(status) && !rs.head_only;
    rs.status = status;
    rs.out = bytes.len() as u64;
    if !trl.is_empty() {
        let t = std::mem::take(trl);
        if with_body {
            return respond_trailers(conn, hdrs, t, rs, sh, now, id, status, bytes);
        }
    }
    let end = !with_body || bytes.is_empty();
    let mut digits = [0u8; 20];
    let len = decimal(bytes.len() as u64, &mut digits);
    let len = if has_body(status) { Some(len) } else { None };
    if send_head(conn, hdrs, sh, now, id, status, len, end).is_err() {
        rs.phase = Phase::Done;
        return;
    }
    if end {
        rs.phase = Phase::Done;
        return;
    }
    match conn.send_data(id, bytes, true) {
        Ok(n) if n == bytes.len() => rs.phase = Phase::Done,
        Ok(n) => {
            rs.pending.clear();
            rs.pending.extend_from_slice(&bytes[n..]);
            rs.pending_fin = true;
            rs.phase = Phase::Sending;
        }
        Err(_) => rs.phase = Phase::Done,
    }
}

/// A whole response followed by trailing HEADERS.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn respond_trailers(conn: &mut Connection, hdrs: &HeaderBuf, t: HeaderBuf, rs: &mut RespPart, sh: &Shared, now: u64, id: u32, status: u16, bytes: &[u8]) {
    let mut digits = [0u8; 20];
    let len = decimal(bytes.len() as u64, &mut digits);
    if send_head(conn, hdrs, sh, now, id, status, Some(len), false).is_err() {
        rs.phase = Phase::Done;
        return;
    }
    rs.trailers = Some(Box::new(t));
    rs.pending.clear();
    rs.pending.extend_from_slice(bytes);
    rs.pending_fin = true;
    rs.phase = Phase::Sending;
    push_pending(conn, id, rs);
}

/// Response HEADERS: the reply's fields plus `date`, `content-length` and `alt-svc`.
#[allow(clippy::too_many_arguments)]
fn send_head(conn: &mut Connection, hdrs: &HeaderBuf, sh: &Shared, now: u64, id: u32, status: u16, len: Option<&[u8]>, end: bool) -> Result<(), simoom_h2::Error> {
    let date = with_date(now, |d| *d);
    // The field list on the stack for the usual handful of headers (no allocation).
    const STACK: usize = 16;
    let empty: (&[u8], &[u8]) = (b"", b"");
    let mut stack = [empty; STACK];
    let mut heap = Vec::new();
    let n = hdrs.len() + 3;
    let fields: &mut [(&[u8], &[u8])] = if n <= STACK {
        &mut stack[..]
    } else {
        heap.resize(n, empty);
        &mut heap[..]
    };
    let mut i = 0;
    for f in hdrs.iter() {
        fields[i] = f;
        i += 1;
    }
    fields[i] = (b"date", &date);
    i += 1;
    if let Some(l) = len {
        fields[i] = (b"content-length", l);
        i += 1;
    }
    if let Some(a) = sh.alt_svc_value() {
        fields[i] = (b"alt-svc", a);
        i += 1;
    }
    match conn.send_response(id, status, &fields[..i], end) {
        Err(simoom_h2::Error::HeaderListTooLarge) => {
            // larger than the client's SETTINGS_MAX_HEADER_LIST_SIZE: it would refuse it, so
            // answer a bare 500 and drop the body (the callers see the error and stop)
            let _ = conn.send_response(id, 500, &[(b"date", &date), (b"content-length", b"0")], true);
            Err(simoom_h2::Error::HeaderListTooLarge)
        }
        r => r,
    }
}

fn push_pending(conn: &mut Connection, id: u32, rs: &mut RespPart) {
    if rs.pending.is_empty() && !rs.pending_fin {
        return;
    }
    let fin = rs.pending_fin && rs.trailers.is_none();
    let r = if rs.pending.is_empty() && !fin { Ok(0) } else { conn.send_data(id, &rs.pending, fin) };
    match r {
        Ok(n) => {
            let all = n == rs.pending.len();
            rs.pending.drain(..n);
            if all && rs.pending_fin {
                if let Some(t) = rs.trailers.take() {
                    let _ = conn.send_trailers(id, &fields(&t));
                }
                rs.pending_fin = false;
                if let Phase::Streaming(s) = &rs.phase {
                    s.close();
                }
                rs.phase = Phase::Done;
            }
        }
        Err(_) => {
            rs.pending.clear();
            if let Phase::Streaming(s) = &rs.phase {
                s.close();
            }
            rs.phase = Phase::Done;
        }
    }
}

impl Layer for H2Layer {
    fn start(&mut self, io: &mut Io<'_, '_>) {
        bump(&io.sh.counters(io.li).h2_connections);
        self.process(io);
        self.flush(io);
    }

    fn input(&mut self, io: &mut Io<'_, '_>, data: &[u8]) -> usize {
        let n = self.recv(io, data);
        self.flush(io);
        n
    }

    fn message(&mut self, io: &mut Io<'_, '_>, env: Envelope) {
        let id = env.token as u32;
        let Some(mut st) = self.streams.remove(&id) else {
            if let Msg::Stream(_, sink) = env.msg {
                sink.close();
            }
            return;
        };
        let sh = io.sh;
        match env.msg {
            Msg::Reply(mut resp) if matches!(st.resp.phase, Phase::Waiting(..)) => {
                std::mem::swap(&mut self.hdrs, &mut resp.headers);
                let status = if resp.invalid || resp.status < 200 { 500 } else { resp.status };
                if resp.invalid {
                    self.hdrs.clear();
                } else {
                    self.trl = std::mem::take(&mut resp.trailers);
                }
                self.close_after |= resp.close;
                respond(&mut self.conn, &self.hdrs, &mut self.trl, &mut st.resp, sh, io.now, id, status, std::mem::take(&mut resp.body).into());
            }
            Msg::Dropped if matches!(st.resp.phase, Phase::Waiting(..)) => {
                self.hdrs.clear();
                respond(&mut self.conn, &self.hdrs, &mut self.trl, &mut st.resp, sh, io.now, id, 500, BodyRef::Static(b"Internal Server Error"));
            }
            Msg::Stream(mut head, sink) if matches!(st.resp.phase, Phase::Waiting(..)) => {
                std::mem::swap(&mut self.hdrs, &mut head.headers);
                let status = if head.invalid || head.status < 200 { 500 } else { head.status };
                self.close_after |= head.close;
                st.resp.status = status;
                if send_head(&mut self.conn, &self.hdrs, sh, io.now, id, status, None, false).is_ok() {
                    st.resp.phase = Phase::Streaming(sink);
                } else {
                    sink.close();
                    st.resp.phase = Phase::Done;
                }
            }
            Msg::Stream(_, sink) => sink.close(),
            Msg::Chunk(data) => {
                if let Phase::Streaming(_) = st.resp.phase {
                    st.resp.unacked += data.len();
                    st.resp.out += data.len() as u64;
                    if st.resp.head_only {
                        // nothing to send
                    } else if st.resp.pending.is_empty() {
                        match self.conn.send_data(id, &data, false) {
                            Ok(n) => st.resp.pending.extend_from_slice(&data[n..]),
                            Err(_) => {
                                if let Phase::Streaming(s) = &st.resp.phase {
                                    s.close();
                                }
                                st.resp.phase = Phase::Done;
                            }
                        }
                    } else {
                        st.resp.pending.extend_from_slice(&data);
                    }
                    io.cx.notify_drain();
                }
            }
            Msg::End { abort } => {
                if let Phase::Streaming(s) = &st.resp.phase {
                    if abort {
                        s.close();
                        self.conn.reset(id, ErrorCode::INTERNAL_ERROR);
                        st.resp.phase = Phase::Done;
                        st.resp.aborted = true;
                    } else {
                        st.resp.pending_fin = true;
                        push_pending(&mut self.conn, id, &mut st.resp);
                    }
                }
            }
            Msg::EndTrailers(t) => {
                if let Phase::Streaming(_) = &st.resp.phase {
                    if !t.is_empty() && !st.resp.head_only {
                        st.resp.trailers = Some(Box::new(t));
                    }
                    st.resp.pending_fin = true;
                    push_pending(&mut self.conn, id, &mut st.resp);
                }
            }
            Msg::BodyResume => {
                st.full = false;
                let n = std::mem::take(&mut st.held);
                if n > 0 {
                    self.conn.release(id, n);
                }
            }
            #[cfg(feature = "websocket-h2")]
            Msg::Ws(cmd) => {
                let mut cmd = Some(cmd);
                self.ws_run(io, id, &mut st, &mut |c, w| {
                    if let Some(cmd) = cmd.take() {
                        c.command(w, cmd)
                    }
                })
            }
            _ => {}
        }
        self.settle(io, id, st);
        self.flush(io);
    }

    fn drain(&mut self, io: &mut Io<'_, '_>) {
        for st in self.streams.values_mut() {
            if let Phase::Streaming(s) = &st.resp.phase {
                s.credit(std::mem::take(&mut st.resp.unacked));
            }
        }
        self.flush(io);
    }

    fn eof(&mut self, io: &mut Io<'_, '_>) {
        io.close = true;
    }

    fn stop(&mut self, io: &mut Io<'_, '_>) {
        self.stopping = true;
        #[cfg(feature = "websocket-h2")]
        self.ws_each(io, &|_| true, &mut |c, w| c.stop(w));
        self.conn.shutdown(Self::now_ms(io));
        self.flush(io);
    }

    fn tick(&mut self, io: &mut Io<'_, '_>) {
        let now_ms = Self::now_ms(io);
        if !self.waits.is_empty() {
            self.expire_waits(io);
        }
        if self.conn.poll_timeout().is_some_and(|t| now_ms >= t) {
            self.conn.handle_timeout(now_ms, &mut |_| {});
        }
        #[cfg(feature = "websocket-h2")]
        {
            let now = io.now;
            self.ws_each(io, &|c| c.deadline() <= now, &mut |c, w| c.tick(w));
        }
        let ka = io.sh.limits.keep_alive_timeout.as_nanos() as u64;
        if self.streams.is_empty() && self.idle_since != 0 && io.now >= self.idle_since + ka && !self.stopping {
            self.stopping = true;
            self.conn.shutdown(now_ms);
        }
        self.flush(io);
        if self.stopping && self.streams.is_empty() && self.idle_since != 0 && io.now >= self.idle_since + ka + 2_000_000_000 {
            io.close = true;
        }
    }

    fn deadline(&self, now: u64, sh: &Shared) -> u64 {
        let mut d = self.conn.poll_timeout().map_or(u64::MAX, |ms| ms.saturating_mul(1_000_000));
        if let Some(&(at, _)) = self.waits.front() {
            d = d.min(at);
        }
        #[cfg(feature = "websocket-h2")]
        if self.has_ws {
            for st in self.streams.values() {
                if let Some(c) = &st.ws.core {
                    d = d.min(c.deadline());
                }
            }
        }
        if self.streams.is_empty() && self.idle_since != 0 {
            let ka = sh.limits.keep_alive_timeout.as_nanos() as u64;
            let at = self.idle_since + ka;
            d = d.min(if at > now { at } else { at + 2_000_000_000 });
        }
        d
    }

    fn wants_pause(&self) -> bool {
        false
    }

    fn closed(&mut self) {
        for st in self.streams.values() {
            match &st.resp.phase {
                Phase::Streaming(s) => s.close(),
                Phase::Waiting(c, _) => c.cancel(),
                _ => {}
            }
            if let Some(src) = &st.src {
                src.fail("the connection closed");
            }
        }
    }

    fn closed_report(&mut self, sh: &Shared, meta: &crate::request::Meta, peer: Option<std::net::SocketAddr>) {
        let now = simoom_sys::time::now_ns();
        for st in self.streams.values().filter(|st| st.dispatched) {
            sh.complete(st.resp.status, st.b_in, st.resp.out, st.t0, now, Version::H2, peer, meta.listener, true);
        }
    }
}

struct H2Target<'t, 'a, 'c> {
    conn: &'t mut Connection,
    hdrs: &'t mut HeaderBuf,
    trl: &'t mut HeaderBuf,
    waits: &'t mut VecDeque<(u64, u32)>,
    resp: &'t mut RespPart,
    io: &'t mut Io<'a, 'c>,
    id: u32,
    answered: bool,
    close: bool,
    #[cfg(feature = "websocket-h2")]
    ws: &'t mut WsPart,
}

impl Target for H2Target<'_, '_, '_> {
    fn headers(&mut self) -> &mut HeaderBuf {
        self.hdrs
    }

    fn trailers(&mut self) -> &mut HeaderBuf {
        self.trl
    }

    fn respond(&mut self, status: u16, body: BodyRef<'_>, close: bool) {
        self.close |= close;
        respond(self.conn, self.hdrs, self.trl, self.resp, self.io.sh, self.io.now, self.id, status, body);
        self.answered = true;
    }

    fn defer(&mut self) -> Responder {
        let c = Arc::new(Cancel::default());
        self.resp.phase = Phase::Waiting(c.clone(), crate::util::Pending::new(self.io.sh.limits.max_pending_per_loop));
        self.answered = true;
        let d = self.io.sh.defer_ns;
        if d != 0 {
            self.waits.push_back((self.io.now.saturating_add(d), self.id));
        }
        Responder::new(Route::Conn(self.io.cx.handle()), 0, u64::from(self.id), self.io.sh.limits.stream_buffer, c)
    }

    fn undefer(&mut self) {
        self.resp.phase = Phase::Open;
        self.answered = false;
    }

    fn stream(&mut self, status: u16, close: bool) -> BodySink {
        self.close |= close;
        let sink = Arc::new(SinkShared::new(self.io.sh.limits.stream_buffer));
        self.resp.status = status;
        if send_head(self.conn, self.hdrs, self.io.sh, self.io.now, self.id, status, None, false).is_ok() {
            self.resp.phase = Phase::Streaming(sink.clone());
        } else {
            sink.close();
            self.resp.phase = Phase::Done;
        }
        self.answered = true;
        BodySink::new(Route::Conn(self.io.cx.handle()), 0, u64::from(self.id), sink)
    }

    fn pool(&mut self) -> Option<OffloadPool> {
        Some(self.io.cx.offload_pool().clone())
    }

    fn shared(&self) -> &Shared {
        self.io.sh
    }

    fn loop_index(&self) -> usize {
        self.io.li
    }

    /// Accepts an extended CONNECT with `:protocol websocket` (RFC 8441 §5): a 200 without a
    /// body, and the stream carries WebSocket frames from then on (no key, no `101`).
    #[cfg(feature = "websocket-h2")]
    fn websocket(&mut self, protocol: Option<&[u8]>, handler: Box<dyn crate::ws::WebSocketHandler>) -> bool {
        if !self.ws.req {
            return false;
        }
        if let Some(p) = protocol {
            self.hdrs.push(b"sec-websocket-protocol", p);
        }
        let (ext, deflate) = crate::ws::negotiate_deflate(self.io.sh, self.ws.extensions.as_deref());
        if let Some(e) = &ext {
            self.hdrs.push(b"sec-websocket-extensions", e.as_bytes());
        }
        self.answered = true;
        self.resp.status = 200;
        if send_head(self.conn, self.hdrs, self.io.sh, self.io.now, self.id, 200, None, false).is_err() {
            self.resp.phase = Phase::Done;
            return true;
        }
        self.resp.phase = Phase::Socket;
        self.ws.core = Some(Box::new(crate::ws::WsCore::new(handler, self.io.sh.limits.max_ws_message, deflate)));
        true
    }
}
