//! HTTP/2 on a connection (h2c prior knowledge, `Upgrade: h2c`, h2 over TLS): drives the
//! sans-io `simoom_h2::Connection`, one request per stream.

use crate::conn::{Io, Layer};
use crate::handle::{BodySink, BodySource, Envelope, Msg, Pushed as SrcPushed, Responder, Route, SinkShared, SrcShared};
use crate::reply::{BodyRef, Target};
use crate::request::{HeaderView, Request};
use crate::server::{bump, Shared};
use crate::types::{HeaderBuf, OwnedHead, Version};
use crate::util::{decimal, has_body, with_date, FastMap};
use simoom_h2::{Connection, ErrorCode, Event};
use simoom_rt::offload::OffloadPool;
use std::sync::Arc;

#[derive(Default)]
enum Phase {
    /// The request is being received or the handler runs.
    #[default]
    Open,
    /// Deferred.
    Waiting,
    /// The response head is out; body bytes may be pending.
    Sending,
    /// A streamed body.
    Streaming(Arc<SinkShared>),
    /// The response is complete.
    Done,
}

#[derive(Default)]
struct ReqPart {
    head: OwnedHead,
    body: Vec<u8>,
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
}

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
                if let Phase::Streaming(s) = &st.resp.phase {
                    s.close();
                }
                if let Some(src) = &st.src {
                    src.fail("the stream was reset");
                }
            }
            self.conn.stream_finished(id);
        }
        for id in std::mem::take(&mut self.ready) {
            self.dispatch(io, id);
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
            respond(&mut self.conn, &self.hdrs, &mut st.resp, sh, io.now, id, code, BodyRef::Static(reason));
        } else {
            let streaming = !st.end;
            if streaming {
                st.src = Some(Arc::new(SrcShared::new(sh.limits.body_buffer, std::mem::take(&mut st.req.body))));
            }
            let St { req, resp, src, .. } = &mut *st;
            let mut r = Request::new(req.head.method(), req.head.target(), Version::H2, HeaderView::Owned(&req.head));
            r.authority = req.head.authority();
            r.body = &req.body;
            r.peer = io.peer;
            r.secure = io.secure;
            r.loop_index = io.li;
            if let Some(s) = src {
                r.streamed = true;
                r.source = Some(BodySource::new(s.clone(), Route::Conn(io.cx.handle()), 0, u64::from(id)));
            }
            let mut clock = io.clock.take();
            let mut t = H2Target { conn: &mut self.conn, hdrs: &mut self.hdrs, resp, io, id, answered: false, close: false };
            panicked = crate::server::call(sh, &mut r, &mut t, &mut clock);
            let (answered, close) = (t.answered, t.close);
            io.clock = clock;
            drop(r);
            self.close_after |= close || panicked;
            if !answered {
                self.hdrs.clear();
                respond(&mut self.conn, &self.hdrs, &mut st.resp, sh, io.now, id, 500, BodyRef::Static(b"Internal Server Error"));
            }
        }
        if panicked {
            self.conn.shutdown(Self::now_ms(io));
        }
        self.settle(id, st);
    }

    /// Puts a stream back, or finishes it when its response is complete.
    fn settle(&mut self, id: u32, st: Box<St>) {
        if matches!(st.resp.phase, Phase::Done) {
            if let Some(src) = &st.src {
                if !st.end {
                    src.fail("the response ended before the request body");
                }
            }
            self.conn.stream_finished(id);
        } else {
            self.streams.insert(id, st);
        }
    }

    /// Continues pending body bytes of `id`.
    fn resume_send(&mut self, id: u32) {
        let Some(mut st) = self.streams.remove(&id) else { return };
        push_pending(&mut self.conn, id, &mut st.resp);
        self.settle(id, st);
    }

    /// Moves output to the runtime while it isn't backed up, resuming blocked streams.
    fn flush(&mut self, io: &mut Io<'_, '_>) {
        let high = 256 * 1024;
        loop {
            while let Some(id) = self.conn.poll_writable() {
                self.resume_send(id);
            }
            let out = self.conn.output();
            if out.is_empty() || io.cx.queued() >= high {
                break;
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
        let streams = &mut self.streams;
        let ready = &mut self.ready;
        let resets = &mut self.resets;
        let touched = &mut self.touched;
        let n = self.conn.recv(data, now_ms, &mut |ev| match ev {
            Event::Headers { stream, headers, end_stream } => {
                let mut st = Box::<St>::default();
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
                if end_stream || headers.method() == Some(b"CONNECT") {
                    st.queued = true;
                    ready.push(stream);
                }
                streams.insert(stream, st);
            }
            Event::Data { stream, data, end_stream } => {
                let Some(st) = streams.get_mut(&stream) else { return };
                touched.push(stream);
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
            Event::Trailers { stream, .. } => {
                if let Some(st) = streams.get_mut(&stream) {
                    st.end = true;
                    if st.dispatched {
                        if let Some(src) = &st.src {
                            src.finish();
                        }
                    } else if !st.queued {
                        st.queued = true;
                        ready.push(stream);
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

/// Sends a whole response on `id`.
#[allow(clippy::too_many_arguments)]
fn respond(conn: &mut Connection, hdrs: &HeaderBuf, rs: &mut RespPart, sh: &Shared, now: u64, id: u32, status: u16, body: BodyRef<'_>) {
    let bytes = body.as_bytes();
    let with_body = has_body(status) && !rs.head_only;
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

/// Response HEADERS: the reply's fields plus `date`, `content-length` and `alt-svc`.
#[allow(clippy::too_many_arguments)]
fn send_head(conn: &mut Connection, hdrs: &HeaderBuf, sh: &Shared, now: u64, id: u32, status: u16, len: Option<&[u8]>, end: bool) -> Result<(), simoom_h2::Error> {
    let date = with_date(now, |d| *d);
    let mut fields: Vec<(&[u8], &[u8])> = Vec::with_capacity(hdrs.iter().size_hint().0 + 4);
    fields.extend(hdrs.iter());
    fields.push((b"date", &date));
    if let Some(l) = len {
        fields.push((b"content-length", l));
    }
    if let Some(a) = sh.alt_svc_value() {
        fields.push((b"alt-svc", a));
    }
    conn.send_response(id, status, &fields, end)
}

fn push_pending(conn: &mut Connection, id: u32, rs: &mut RespPart) {
    if rs.pending.is_empty() && !rs.pending_fin {
        return;
    }
    match conn.send_data(id, &rs.pending, rs.pending_fin) {
        Ok(n) => {
            let all = n == rs.pending.len();
            rs.pending.drain(..n);
            if all && rs.pending_fin {
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
            Msg::Reply(mut resp) if matches!(st.resp.phase, Phase::Waiting) => {
                std::mem::swap(&mut self.hdrs, &mut resp.headers);
                let status = if resp.invalid || resp.status < 200 { 500 } else { resp.status };
                if resp.invalid {
                    self.hdrs.clear();
                }
                self.close_after |= resp.close;
                respond(&mut self.conn, &self.hdrs, &mut st.resp, sh, io.now, id, status, std::mem::take(&mut resp.body).into());
            }
            Msg::Dropped if matches!(st.resp.phase, Phase::Waiting) => {
                self.hdrs.clear();
                respond(&mut self.conn, &self.hdrs, &mut st.resp, sh, io.now, id, 500, BodyRef::Static(b"Internal Server Error"));
            }
            Msg::Stream(mut head, sink) if matches!(st.resp.phase, Phase::Waiting) => {
                std::mem::swap(&mut self.hdrs, &mut head.headers);
                let status = if head.invalid || head.status < 200 { 500 } else { head.status };
                self.close_after |= head.close;
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
                    } else {
                        st.resp.pending_fin = true;
                        push_pending(&mut self.conn, id, &mut st.resp);
                    }
                }
            }
            Msg::BodyResume => {
                st.full = false;
                let n = std::mem::take(&mut st.held);
                if n > 0 {
                    self.conn.release(id, n);
                }
            }
            _ => {}
        }
        self.settle(id, st);
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
        self.conn.shutdown(Self::now_ms(io));
        self.flush(io);
    }

    fn tick(&mut self, io: &mut Io<'_, '_>) {
        let now_ms = Self::now_ms(io);
        if self.conn.poll_timeout().is_some_and(|t| now_ms >= t) {
            self.conn.handle_timeout(now_ms, &mut |_| {});
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
            if let Phase::Streaming(s) = &st.resp.phase {
                s.close();
            }
            if let Some(src) = &st.src {
                src.fail("the connection closed");
            }
        }
    }
}

struct H2Target<'t, 'a, 'c> {
    conn: &'t mut Connection,
    hdrs: &'t mut HeaderBuf,
    resp: &'t mut RespPart,
    io: &'t mut Io<'a, 'c>,
    id: u32,
    answered: bool,
    close: bool,
}

impl Target for H2Target<'_, '_, '_> {
    fn headers(&mut self) -> &mut HeaderBuf {
        self.hdrs
    }

    fn respond(&mut self, status: u16, body: BodyRef<'_>, close: bool) {
        self.close |= close;
        respond(self.conn, self.hdrs, self.resp, self.io.sh, self.io.now, self.id, status, body);
        self.answered = true;
    }

    fn defer(&mut self) -> Responder {
        self.resp.phase = Phase::Waiting;
        self.answered = true;
        Responder::new(Route::Conn(self.io.cx.handle()), 0, u64::from(self.id), self.io.sh.limits.stream_buffer)
    }

    fn undefer(&mut self) {
        self.resp.phase = Phase::Open;
        self.answered = false;
    }

    fn stream(&mut self, status: u16, close: bool) -> BodySink {
        self.close |= close;
        let sink = Arc::new(SinkShared::new(self.io.sh.limits.stream_buffer));
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
}
