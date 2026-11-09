//! HTTP/3: one QUIC endpoint per loop (a `SO_REUSEPORT` socket each on Linux, loop 0
//! elsewhere), one `Http3` per QUIC connection, one request per stream.
//!
//! Routing across loops: the kernel's `SO_REUSEPORT` hash pins a 4-tuple to one socket, so
//! every datagram of a connection reaches the loop that owns it, and each loop routes by
//! connection ID inside its own endpoint. Active migration is disabled in the transport
//! parameters; a NAT rebinding that changes the client's port can land on another loop, which
//! does not know the connection (the client then retries or times out). Forwarding by a loop
//! index encoded in the connection ID would remove that gap.

use crate::handle::{BodySink, BodySource, Envelope, Msg, Pushed as SrcPushed, Responder, Route, SinkShared, SrcShared};
use crate::reply::{BodyRef, Target};
use crate::request::{HeaderView, Request};
use crate::server::{bump, Shared};
use crate::types::{HeaderBuf, OwnedHead, Version};
use crate::util::{decimal, has_body, with_date, FastMap};
use simoom_h3::{H3Event, Http3};
use simoom_quic::{ConnHandle, DatagramEvent};
use simoom_rt::offload::OffloadPool;
use simoom_rt::timer::TimerId;
use simoom_rt::{Endpoint, EndpointHandle, Message, RecvMeta, Transmit, UdpCtx, UdpInfo};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// The UDP service's endpoint for one loop: a [`LazyEp`] that builds the QUIC endpoint
/// ([`H3Ep`]) on the loop's first datagram, so a loop that never sees HTTP/3 traffic holds
/// only this small shell (bug 12).
pub(crate) fn endpoint(sh: Arc<Shared>, cfg: Arc<simoom_quic::Config>, info: &UdpInfo) -> Box<dyn Endpoint> {
    Box::new(LazyEp { sh, cfg, li: info.loop_index, ep: None, stopping: false })
}

fn build_endpoint(sh: Arc<Shared>, cfg: Arc<simoom_quic::Config>, li: usize) -> H3Ep {
    H3Ep {
        h3cfg: simoom_h3::Config {
            max_field_section_size: u64::from(sh.limits.max_header_list),
            qpack_max_table_capacity: u64::from(sh.limits.header_table_size),
            body_buffer: sh.limits.body_buffer,
            ..simoom_h3::Config::default()
        },
        sh,
        li,
        ep: simoom_quic::Endpoint::new(cfg, true),
        conns: FastMap::default(),
        ids: FastMap::default(),
        next_id: 1,
        timer: None,
        // Buffers grow on first use.
        rx: Vec::new(),
        resp: Vec::new(),
        tx: Vec::new(),
        touched: Vec::new(),
        hdrs: HeaderBuf::default(),
        tmp: Vec::new(),
        handle: None,
        pool: None,
        stopping: false,
    }
}

/// A loop's HTTP/3 endpoint, built on first use. The runtime's contract still holds: before
/// the first datagram there is no connection, so a stop has nothing to wind down
/// ([`Endpoint::is_busy`] is false) and datagrams that arrive after it are dropped (no new
/// connection starts during a stop); timers and messages can only exist once it is built.
struct LazyEp {
    sh: Arc<Shared>,
    cfg: Arc<simoom_quic::Config>,
    li: usize,
    ep: Option<Box<H3Ep>>,
    stopping: bool,
}

impl Endpoint for LazyEp {
    fn on_datagram(&mut self, cx: &mut UdpCtx<'_>, data: &[u8], meta: &RecvMeta) {
        if self.ep.is_none() {
            if self.stopping {
                return;
            }
            bump(&self.sh.counters(self.li).quic_endpoints);
            self.ep = Some(Box::new(build_endpoint(self.sh.clone(), self.cfg.clone(), self.li)));
        }
        if let Some(ep) = &mut self.ep {
            ep.on_datagram(cx, data, meta);
        }
    }

    fn on_timer(&mut self, cx: &mut UdpCtx<'_>, token: u64) {
        if let Some(ep) = &mut self.ep {
            ep.on_timer(cx, token);
        }
    }

    fn on_message(&mut self, cx: &mut UdpCtx<'_>, msg: Message) {
        match &mut self.ep {
            Some(ep) => ep.on_message(cx, msg),
            None => {
                // no connection exists yet: close a sink nobody will drain
                if let Ok(env) = msg.downcast::<Envelope>() {
                    if let Msg::Stream(_, sink) = env.msg {
                        sink.close();
                    }
                }
            }
        }
    }

    fn on_stop(&mut self, cx: &mut UdpCtx<'_>) {
        self.stopping = true;
        if let Some(ep) = &mut self.ep {
            ep.on_stop(cx);
        }
    }

    fn is_busy(&self) -> bool {
        self.ep.as_ref().is_some_and(|ep| ep.is_busy())
    }

    fn on_abort(&mut self, cx: &mut UdpCtx<'_>) {
        if let Some(ep) = &mut self.ep {
            ep.on_abort(cx);
        }
    }
}

#[derive(Default)]
enum Phase {
    #[default]
    Open,
    Waiting,
    Sending,
    Streaming(Arc<SinkShared>),
    Done,
}

#[derive(Default)]
struct RespPart {
    phase: Phase,
    pending: Vec<u8>,
    pending_fin: bool,
    head_only: bool,
}

#[derive(Default)]
struct St {
    head: OwnedHead,
    body: Vec<u8>,
    /// The request's trailing HEADERS.
    trailers: Option<OwnedHead>,
    resp: RespPart,
    end: bool,
    queued: bool,
    dispatched: bool,
    src: Option<Arc<SrcShared>>,
    full: bool,
    error: Option<u16>,
}

struct H3Conn {
    id: u64,
    h3: Http3,
    streams: FastMap<u64, Box<St>>,
    peer: SocketAddr,
    ready: Vec<u64>,
    /// Streams whose response is complete on our side, newest last: a graceful stop waits
    /// until QUIC has their data acknowledged. Only the latest few hundred are kept.
    flushing: Vec<u64>,
    /// CONNECTION_CLOSE sent (graceful stop).
    closing: bool,
}

/// Completed streams remembered per connection for a graceful stop.
const FLUSHING_KEPT: usize = 256;

struct H3Ep {
    sh: Arc<Shared>,
    li: usize,
    h3cfg: simoom_h3::Config,
    ep: simoom_quic::Endpoint,
    conns: FastMap<usize, Box<H3Conn>>,
    ids: FastMap<u64, usize>,
    next_id: u64,
    timer: Option<(TimerId, Instant)>,
    rx: Vec<u8>,
    resp: Vec<u8>,
    tx: Vec<u8>,
    touched: Vec<ConnHandle>,
    hdrs: HeaderBuf,
    tmp: Vec<u8>,
    handle: Option<EndpointHandle>,
    pool: Option<OffloadPool>,
    /// A graceful stop began: GOAWAY was sent, connections close once idle.
    stopping: bool,
}

impl H3Ep {
    fn route(&mut self, cx: &mut UdpCtx<'_>) -> Route {
        Route::Ep(self.handle.get_or_insert_with(|| cx.handle()).clone())
    }

    fn process(&mut self, cx: &mut UdpCtx<'_>, now: Instant, now_ns: u64) {
        let mut touched = std::mem::take(&mut self.touched);
        touched.sort_unstable();
        touched.dedup();
        for h in touched.drain(..) {
            self.conn_events(cx, now, now_ns, h);
        }
        self.touched = touched;
        if self.stopping {
            self.wind_down(now);
        }
        self.transmit(cx, now);
        self.arm(cx, now);
    }

    /// During a graceful stop: closes every connection whose requests are all answered and
    /// whose response data QUIC has delivered (acknowledged).
    fn wind_down(&mut self, now: Instant) {
        for (&hi, c) in self.conns.iter_mut() {
            if c.closing {
                continue;
            }
            let Some(qc) = self.ep.conn_mut(ConnHandle(hi)) else { continue };
            let unacked = c.flushing.iter().any(|&id| qc.stream_unacked(id).is_some_and(|n| n > 0));
            if !qc.is_established() || (c.streams.is_empty() && !unacked) {
                c.closing = true;
                qc.close(now, simoom_h3::code::NO_ERROR, b"server stopping");
            }
        }
    }

    fn conn_events(&mut self, cx: &mut UdpCtx<'_>, now: Instant, now_ns: u64, h: ConnHandle) {
        if !self.conns.contains_key(&h.0) {
            let Some(qc) = self.ep.conn(h) else { return };
            let id = self.next_id;
            self.next_id += 1;
            self.ids.insert(id, h.0);
            bump(&self.sh.counters(self.li).h3_connections);
            let peer = qc.remote_address();
            self.conns.insert(
                h.0,
                Box::new(H3Conn { id, h3: Http3::new(true, self.h3cfg.clone()), streams: FastMap::default(), peer, ready: Vec::new(), flushing: Vec::new(), closing: false }),
            );
        }
        while let Some(ev) = self.ep.poll_event(h) {
            if let (Some(c), Some(qc)) = (self.conns.get_mut(&h.0), self.ep.conn_mut(h)) {
                c.h3.handle(now, qc, &ev);
            }
        }
        if self.ep.conn(h).is_none() {
            if let Some(c) = self.conns.remove(&h.0) {
                self.ids.remove(&c.id);
                close_streams(&c);
            }
            return;
        }
        self.h3_events(cx, now, now_ns, h);
    }

    fn h3_events(&mut self, cx: &mut UdpCtx<'_>, now: Instant, now_ns: u64, h: ConnHandle) {
        let buffer = self.sh.limits.body_buffer;
        let max_body = self.sh.limits.max_body;
        let route = self.route(cx);
        let pool = self.pool.get_or_insert_with(|| cx.offload_pool().clone()).clone();
        let (Some(c), Some(qc)) = (self.conns.get_mut(&h.0), self.ep.conn_mut(h)) else { return };
        while let Some(ev) = c.h3.poll_event() {
            match ev {
                H3Event::Headers { stream, fields } => {
                    if c.streams.contains_key(&stream) {
                        continue; // informational or trailer-like; ignored
                    }
                    let mut st = Box::<St>::default();
                    let mut regular = Vec::new();
                    for f in &fields {
                        match &f.name[..] {
                            b":method" => st.head.set_method(&f.value),
                            b":path" => st.head.set_target(&f.value),
                            b":authority" => st.head.set_authority(&f.value),
                            n if n.starts_with(b":") => {}
                            _ => regular.push(f),
                        }
                    }
                    if st.head.target.is_empty() {
                        st.head.set_target(b"/");
                    }
                    for f in regular {
                        st.head.add_field(&f.name, &f.value);
                    }
                    st.resp.head_only = st.head.method() == b"HEAD";
                    c.streams.insert(stream, st);
                }
                H3Event::Data { stream } => read_body(c, qc, now, stream, &mut self.tmp, buffer, max_body),
                H3Event::Trailers { stream, fields } => {
                    // validated by simoom-h3 (no pseudo-fields); the stream ends next
                    if let Some(st) = c.streams.get_mut(&stream) {
                        let mut t = OwnedHead::default();
                        for f in &fields {
                            t.add_field(&f.name, &f.value);
                        }
                        st.trailers = Some(t);
                    }
                }
                H3Event::GoAway { .. } | H3Event::Error(_) => {}
                H3Event::Finished { stream } => {
                    if let Some(st) = c.streams.get_mut(&stream) {
                        st.end = true;
                        if st.dispatched {
                            if let Some(src) = &st.src {
                                let t = st.trailers.take().map(|t| (0..t.fields.len()).map(|i| t.field(i)).map(|(n, v)| (n.to_vec(), v.to_vec())).collect());
                                src.finish_with(t.unwrap_or_default());
                            }
                        } else if !st.queued {
                            st.queued = true;
                            c.ready.push(stream);
                        }
                    }
                }
                H3Event::Reset { stream, .. } => {
                    if let Some(st) = c.streams.remove(&stream) {
                        if let Phase::Streaming(s) = &st.resp.phase {
                            s.close();
                        }
                        if let Some(src) = &st.src {
                            src.fail("the stream was reset");
                        }
                    }
                }
                H3Event::Writable { stream } => {
                    if let Some(mut st) = c.streams.remove(&stream) {
                        push_pending(&mut c.h3, qc, stream, &mut st.resp);
                        settle(c, stream, st);
                    }
                }
            }
        }
        for id in std::mem::take(&mut c.ready) {
            dispatch(&self.sh, self.li, &mut self.hdrs, c, qc, now_ns, id, &route, &pool);
        }
    }

    fn transmit(&mut self, cx: &mut UdpCtx<'_>, now: Instant) {
        while let Some((_, t)) = self.ep.poll_transmit(now, &mut self.tx, 16) {
            let size = t.size.min(self.tx.len());
            let seg = t.segment_size.filter(|&s| s < size).unwrap_or(0);
            let tr = Transmit { peer: t.destination, data: &self.tx[..size], segment_size: seg, ecn: 0, src_ip: None };
            let _ = cx.send(&[tr]); // a full socket buffer drops it; QUIC recovers
        }
    }

    fn arm(&mut self, cx: &mut UdpCtx<'_>, now: Instant) {
        let Some(d) = self.ep.poll_timeout() else { return };
        if let Some((id, at)) = self.timer {
            if at <= d {
                return;
            }
            cx.cancel_timer(id);
        }
        let id = cx.set_timer(d.saturating_duration_since(now), 0);
        self.timer = Some((id, d));
    }
}

fn close_streams(c: &H3Conn) {
    for st in c.streams.values() {
        if let Phase::Streaming(s) = &st.resp.phase {
            s.close();
        }
        if let Some(src) = &st.src {
            src.fail("the connection closed");
        }
    }
}

fn read_body(c: &mut H3Conn, qc: &mut simoom_quic::Connection, now: Instant, stream: u64, tmp: &mut Vec<u8>, buffer: usize, max_body: u64) {
    if tmp.is_empty() {
        tmp.resize(16 * 1024, 0);
    }
    let Some(st) = c.streams.get_mut(&stream) else { return };
    loop {
        if st.full {
            return;
        }
        let Ok((n, fin)) = c.h3.recv_body(now, qc, stream, tmp) else { return };
        let data = &tmp[..n];
        if st.dispatched {
            if let Some(src) = &st.src {
                if !data.is_empty() && src.push(data) == SrcPushed::Full {
                    st.full = true;
                }
            }
        } else {
            st.body.extend_from_slice(data);
            if st.body.len() as u64 > max_body {
                st.error = Some(413);
                st.end = true;
            }
            if st.body.len() > buffer && !st.queued {
                st.queued = true;
                c.ready.push(stream);
            }
        }
        if fin {
            st.end = true;
            // a dispatched body's source is finished by the `Finished` event that recv_body
            // queued, after the `Trailers` event (so the trailers come with the end)
            if !st.dispatched && !st.queued {
                st.queued = true;
                c.ready.push(stream);
            }
            return;
        }
        if n == 0 {
            return;
        }
    }
}

fn settle(c: &mut H3Conn, id: u64, st: Box<St>) {
    if !matches!(st.resp.phase, Phase::Done) {
        c.streams.insert(id, st);
        return;
    }
    if c.flushing.len() >= FLUSHING_KEPT {
        c.flushing.drain(..FLUSHING_KEPT / 2);
    }
    c.flushing.push(id);
}

#[allow(clippy::too_many_arguments)]
fn dispatch(sh: &Shared, li: usize, hdrs: &mut HeaderBuf, c: &mut H3Conn, qc: &mut simoom_quic::Connection, now_ns: u64, id: u64, route: &Route, pool: &OffloadPool) {
    let Some(mut st) = c.streams.remove(&id) else { return };
    st.queued = false;
    if st.dispatched {
        c.streams.insert(id, st);
        return;
    }
    st.dispatched = true;
    bump(&sh.counters(li).requests);
    if let Some(code) = st.error {
        hdrs.clear();
        let reason = simoom_http1::write::reason(code).as_bytes();
        respond(&mut c.h3, qc, hdrs, &mut st.resp, sh, now_ns, id, code, BodyRef::Static(reason));
        settle(c, id, st);
        return;
    }
    if !st.end {
        st.src = Some(Arc::new(SrcShared::new(sh.limits.body_buffer, std::mem::take(&mut st.body))));
    }
    let St { head, body, trailers, resp, src, .. } = &mut *st;
    let mut r = Request::new(head.method(), head.target(), Version::H3, HeaderView::Owned(head));
    r.authority = head.authority();
    r.body = body;
    r.trailers = trailers.as_ref();
    r.peer = Some(c.peer);
    r.secure = true;
    r.loop_index = li;
    if let Some(s) = src {
        r.streamed = true;
        r.source = Some(BodySource::new(s.clone(), route.clone(), c.id, id));
    }
    let mut t = H3Target { h3: &mut c.h3, qc, hdrs, resp, sh, li, now_ns, id, conn: c.id, route, pool, answered: false };
    let panicked = crate::server::call(sh, &mut r, &mut t, &mut None);
    let answered = t.answered;
    drop(r);
    if !answered {
        hdrs.clear();
        respond(&mut c.h3, qc, hdrs, &mut st.resp, sh, now_ns, id, 500, BodyRef::Static(b"Internal Server Error"));
    }
    if panicked {
        c.h3.goaway(qc);
    }
    settle(c, id, st);
}

fn fields_for<'f>(hdrs: &'f HeaderBuf, sh: &'f Shared, status: &'f [u8; 3], date: &'f [u8; 29], len: Option<&'f [u8]>) -> Vec<(&'f [u8], &'f [u8])> {
    let mut f: Vec<(&[u8], &[u8])> = Vec::with_capacity(8);
    f.push((b":status", status));
    f.extend(hdrs.iter());
    f.push((b"date", date));
    if let Some(l) = len {
        f.push((b"content-length", l));
    }
    let _ = sh;
    f
}

fn status_digits(s: u16) -> [u8; 3] {
    [b'0' + (s / 100 % 10) as u8, b'0' + (s / 10 % 10) as u8, b'0' + (s % 10) as u8]
}

#[allow(clippy::too_many_arguments)]
fn respond(h3: &mut Http3, qc: &mut simoom_quic::Connection, hdrs: &HeaderBuf, rs: &mut RespPart, sh: &Shared, now_ns: u64, id: u64, status: u16, body: BodyRef<'_>) {
    let bytes = body.as_bytes();
    let with_body = has_body(status) && !rs.head_only;
    let end = !with_body || bytes.is_empty();
    let digits = status_digits(status);
    let date = with_date(now_ns, |d| *d);
    let mut lb = [0u8; 20];
    let len = if has_body(status) { Some(decimal(bytes.len() as u64, &mut lb)) } else { None };
    let fields = fields_for(hdrs, sh, &digits, &date, len);
    if h3.send_headers(qc, id, &fields, end).is_err() || end {
        rs.phase = Phase::Done;
        return;
    }
    match h3.send_body(qc, id, bytes, true) {
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

#[allow(clippy::too_many_arguments)]
fn start_stream(h3: &mut Http3, qc: &mut simoom_quic::Connection, hdrs: &HeaderBuf, rs: &mut RespPart, sh: &Shared, now_ns: u64, id: u64, status: u16, sink: Arc<SinkShared>) {
    let digits = status_digits(status);
    let date = with_date(now_ns, |d| *d);
    let fields = fields_for(hdrs, sh, &digits, &date, None);
    if h3.send_headers(qc, id, &fields, false).is_ok() {
        rs.phase = Phase::Streaming(sink);
    } else {
        sink.close();
        rs.phase = Phase::Done;
    }
}

/// Sends pending body bytes; credits a streaming sink with what QUIC accepted.
fn push_pending(h3: &mut Http3, qc: &mut simoom_quic::Connection, id: u64, rs: &mut RespPart) {
    if rs.pending.is_empty() && !rs.pending_fin {
        return;
    }
    match h3.send_body(qc, id, &rs.pending, rs.pending_fin) {
        Ok(n) => {
            let all = n == rs.pending.len();
            rs.pending.drain(..n);
            if let Phase::Streaming(s) = &rs.phase {
                s.credit(n);
            }
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

impl Endpoint for H3Ep {
    fn on_datagram(&mut self, cx: &mut UdpCtx<'_>, data: &[u8], meta: &RecvMeta) {
        let now = Instant::now();
        let now_ns = cx.now_ns();
        if meta.truncated {
            return;
        }
        let seg = if meta.segment_size > 0 { meta.segment_size } else { data.len().max(1) };
        for chunk in data.chunks(seg) {
            self.rx.clear();
            self.rx.extend_from_slice(chunk);
            match self.ep.recv(now, meta.peer, &mut self.rx, &mut self.resp) {
                DatagramEvent::Response(t) => {
                    let size = t.size.min(self.resp.len());
                    let tr = Transmit { peer: t.destination, data: &self.resp[..size], segment_size: 0, ecn: 0, src_ip: None };
                    let _ = cx.send(&[tr]);
                }
                DatagramEvent::Connection(h) | DatagramEvent::NewConnection(h) => self.touched.push(h),
                DatagramEvent::Dropped => {}
            }
        }
        self.process(cx, now, now_ns);
    }

    fn on_timer(&mut self, cx: &mut UdpCtx<'_>, _token: u64) {
        self.timer = None;
        let now = Instant::now();
        let mut touched = std::mem::take(&mut self.touched);
        self.ep.handle_timeout(now, &mut touched);
        self.touched = touched;
        let now_ns = cx.now_ns();
        self.process(cx, now, now_ns);
    }

    fn on_message(&mut self, cx: &mut UdpCtx<'_>, msg: Message) {
        let Ok(env) = msg.downcast::<Envelope>() else { return };
        let now = Instant::now();
        let now_ns = cx.now_ns();
        let Some(&hi) = self.ids.get(&env.conn) else {
            if let Msg::Stream(_, sink) = env.msg {
                sink.close();
            }
            return;
        };
        let h = ConnHandle(hi);
        let sh = self.sh.clone();
        if let (Some(c), Some(qc)) = (self.conns.get_mut(&hi), self.ep.conn_mut(h)) {
            let id = env.token;
            match c.streams.remove(&id) {
                None => {
                    if let Msg::Stream(_, sink) = env.msg {
                        sink.close();
                    }
                }
                Some(mut st) => {
                    match env.msg {
                        Msg::Reply(mut resp) if matches!(st.resp.phase, Phase::Waiting) => {
                            std::mem::swap(&mut self.hdrs, &mut resp.headers);
                            let status = if resp.invalid || resp.status < 200 { 500 } else { resp.status };
                            if resp.invalid {
                                self.hdrs.clear();
                            }
                            respond(&mut c.h3, qc, &self.hdrs, &mut st.resp, &sh, now_ns, id, status, std::mem::take(&mut resp.body).into());
                        }
                        Msg::Dropped if matches!(st.resp.phase, Phase::Waiting) => {
                            self.hdrs.clear();
                            respond(&mut c.h3, qc, &self.hdrs, &mut st.resp, &sh, now_ns, id, 500, BodyRef::Static(b"Internal Server Error"));
                        }
                        Msg::Stream(mut head, sink) if matches!(st.resp.phase, Phase::Waiting) => {
                            std::mem::swap(&mut self.hdrs, &mut head.headers);
                            let status = if head.invalid || head.status < 200 { 500 } else { head.status };
                            start_stream(&mut c.h3, qc, &self.hdrs, &mut st.resp, &sh, now_ns, id, status, sink);
                        }
                        Msg::Stream(_, sink) => sink.close(),
                        Msg::Chunk(data) => {
                            if let Phase::Streaming(s) = &st.resp.phase {
                                if st.resp.head_only {
                                    s.credit(data.len());
                                } else {
                                    st.resp.pending.extend_from_slice(&data);
                                    push_pending(&mut c.h3, qc, id, &mut st.resp);
                                }
                            }
                        }
                        Msg::End { abort } => {
                            if let Phase::Streaming(s) = &st.resp.phase {
                                if abort {
                                    s.close();
                                    c.h3.reset_stream(qc, id, simoom_h3::code::INTERNAL_ERROR);
                                    st.resp.phase = Phase::Done;
                                } else {
                                    st.resp.pending_fin = true;
                                    push_pending(&mut c.h3, qc, id, &mut st.resp);
                                }
                            }
                        }
                        Msg::BodyResume => {
                            st.full = false;
                            c.streams.insert(id, st);
                            let buffer = sh.limits.body_buffer;
                            read_body(c, qc, now, id, &mut self.tmp, buffer, sh.limits.max_body);
                            self.touched.push(h);
                            self.process(cx, now, now_ns);
                            return;
                        }
                        _ => {}
                    }
                    settle(c, id, st);
                }
            }
        }
        self.touched.push(h);
        self.process(cx, now, now_ns);
    }

    /// GOAWAY on every connection; each closes once its streams finish and their data is
    /// acknowledged ([`H3Ep::wind_down`]), while the runtime keeps the loop alive through
    /// [`Endpoint::is_busy`]; [`Endpoint::on_abort`] closes the rest at the deadline.
    fn on_stop(&mut self, cx: &mut UdpCtx<'_>) {
        let now = Instant::now();
        self.stopping = true;
        for (&hi, c) in self.conns.iter_mut() {
            if let Some(qc) = self.ep.conn_mut(ConnHandle(hi)) {
                if qc.is_established() {
                    c.h3.goaway(qc);
                }
            }
        }
        self.wind_down(now);
        self.transmit(cx, now);
        self.arm(cx, now);
    }

    fn is_busy(&self) -> bool {
        self.stopping && self.conns.values().any(|c| !c.closing)
    }

    fn on_abort(&mut self, cx: &mut UdpCtx<'_>) {
        let now = Instant::now();
        for (&hi, c) in self.conns.iter_mut() {
            if !c.closing {
                c.closing = true;
                if let Some(qc) = self.ep.conn_mut(ConnHandle(hi)) {
                    qc.close(now, simoom_h3::code::NO_ERROR, b"server stopping");
                }
            }
        }
        self.transmit(cx, now);
    }
}

struct H3Target<'t> {
    h3: &'t mut Http3,
    qc: &'t mut simoom_quic::Connection,
    hdrs: &'t mut HeaderBuf,
    resp: &'t mut RespPart,
    sh: &'t Shared,
    li: usize,
    now_ns: u64,
    id: u64,
    conn: u64,
    route: &'t Route,
    pool: &'t OffloadPool,
    answered: bool,
}

impl Target for H3Target<'_> {
    fn headers(&mut self) -> &mut HeaderBuf {
        self.hdrs
    }

    fn respond(&mut self, status: u16, body: BodyRef<'_>, _close: bool) {
        respond(self.h3, self.qc, self.hdrs, self.resp, self.sh, self.now_ns, self.id, status, body);
        self.answered = true;
    }

    fn defer(&mut self) -> Responder {
        self.resp.phase = Phase::Waiting;
        self.answered = true;
        Responder::new(self.route.clone(), self.conn, self.id, self.sh.limits.stream_buffer)
    }

    fn undefer(&mut self) {
        self.resp.phase = Phase::Open;
        self.answered = false;
    }

    fn stream(&mut self, status: u16, _close: bool) -> BodySink {
        let sink = Arc::new(SinkShared::new(self.sh.limits.stream_buffer));
        start_stream(self.h3, self.qc, self.hdrs, self.resp, self.sh, self.now_ns, self.id, status, sink.clone());
        self.answered = true;
        BodySink::new(self.route.clone(), self.conn, self.id, sink)
    }

    fn pool(&mut self) -> Option<OffloadPool> {
        Some(self.pool.clone())
    }

    fn shared(&self) -> &Shared {
        self.sh
    }

    fn loop_index(&self) -> usize {
        self.li
    }
}
