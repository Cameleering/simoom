//! HTTP/3: one QUIC endpoint per loop (a `SO_REUSEPORT` socket each on Linux, loop 0
//! elsewhere), one `Http3` per QUIC connection, one request per stream.
//!
//! Routing across loops: the kernel's `SO_REUSEPORT` hash pins a 4-tuple to one socket, so
//! every datagram of a connection reaches the loop that owns it, and each loop routes by
//! connection ID inside its own endpoint. Active migration is disabled in the transport
//! parameters; a NAT rebinding that changes the client's port can land on another loop, which
//! does not know the connection (the client then retries or times out). Forwarding by a loop
//! index encoded in the connection ID would remove that gap.

use crate::handle::{BodySink, BodySource, Cancel, Envelope, Msg, Pushed as SrcPushed, Responder, Route, SinkShared, SrcShared};
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
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// HTTP/3's TLS: the server configuration of the moment, swapped by
/// [`crate::ServerHandle::set_quic_tls`] for connections that start afterwards. The stateless
/// parts (packet keys, tokens, randomness) go to a fixed provider.
pub(crate) struct QuicTls {
    base: simoom_quic::tls::TlsProvider,
    cfg: RwLock<Arc<simoom_tls::ServerConfig>>,
}

impl QuicTls {
    pub(crate) fn new(mut c: simoom_tls::ServerConfig) -> QuicTls {
        c.alpn = vec![b"h3".to_vec()];
        let cfg = Arc::new(c);
        QuicTls { base: simoom_quic::tls::TlsProvider::server(cfg.clone()), cfg: RwLock::new(cfg) }
    }

    pub(crate) fn set(&self, mut c: simoom_tls::ServerConfig) {
        c.alpn = vec![b"h3".to_vec()];
        *self.cfg.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(c);
    }
}

impl simoom_quic::CryptoProvider for QuicTls {
    fn initial_keys(&self, version: u32, dcid: &[u8], is_server: bool) -> simoom_quic::crypto::Keys {
        self.base.initial_keys(version, dcid, is_server)
    }
    fn retry_tag(&self, version: u32, pseudo_packet: &[u8]) -> [u8; 16] {
        self.base.retry_tag(version, pseudo_packet)
    }
    fn hmac(&self, key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
        self.base.hmac(key, parts)
    }
    fn fill_random(&self, buf: &mut [u8]) {
        self.base.fill_random(buf)
    }
    fn server_session(&self, version: u32, tp: Vec<u8>) -> Result<Box<dyn simoom_quic::CryptoSession>, simoom_quic::TransportError> {
        let cfg = self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone();
        simoom_quic::tls::TlsProvider::server(cfg).server_session(version, tp)
    }
    fn client_session(&self, version: u32, name: &str, tp: Vec<u8>) -> Result<Box<dyn simoom_quic::CryptoSession>, simoom_quic::TransportError> {
        self.base.client_session(version, name, tp)
    }
}

/// The UDP service's endpoint for one loop: a [`LazyEp`] that builds the QUIC endpoint
/// ([`H3Ep`]) on the loop's first datagram, so a loop that never sees HTTP/3 traffic holds
/// only this small shell (bug 12).
pub(crate) fn endpoint(sh: Arc<Shared>, cfg: Arc<simoom_quic::Config>, info: &UdpInfo) -> Box<dyn Endpoint> {
    Box::new(LazyEp { sh, cfg, li: info.loop_index, local: info.local_addr, binding: info.binding as u32, ep: None, stopping: false })
}

fn build_endpoint(sh: Arc<Shared>, cfg: Arc<simoom_quic::Config>, li: usize, local: SocketAddr, binding: u32) -> H3Ep {
    H3Ep {
        local,
        binding,
        trl: HeaderBuf::default(),
        waits: VecDeque::new(),
        wait_timer: None,
        h3cfg: simoom_h3::Config {
            max_field_section_size: u64::from(sh.limits.max_header_list),
            qpack_max_table_capacity: u64::from(sh.limits.header_table_size),
            body_buffer: sh.limits.body_buffer,
            enable_connect_protocol: cfg!(feature = "websocket-h3"),
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
    local: SocketAddr,
    binding: u32,
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
            self.ep = Some(Box::new(build_endpoint(self.sh.clone(), self.cfg.clone(), self.li, self.local, self.binding)));
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
    Waiting(Arc<Cancel>),
    Sending,
    Streaming(Arc<SinkShared>),
    Done,
    /// A WebSocket runs on the stream (RFC 9220).
    #[cfg(feature = "websocket-h3")]
    Socket,
}

/// WebSocket over HTTP/3 (RFC 9220) on one stream.
#[cfg(feature = "websocket-h3")]
#[derive(Default)]
struct WsPart {
    /// An extended CONNECT with `:protocol websocket`.
    req: bool,
    core: Option<Box<crate::ws::WsCore>>,
    extensions: Option<Vec<u8>>,
}

#[derive(Default)]
struct RespPart {
    phase: Phase,
    pending: Vec<u8>,
    pending_fin: bool,
    head_only: bool,
    /// Trailer fields sent once `pending` is out (instead of FIN on the last DATA).
    trailers: Option<Box<HeaderBuf>>,
    /// The status sent, body bytes handed over, and whether the body was cut off
    /// ([`crate::Builder::on_complete`]).
    status: u16,
    out: u64,
    aborted: bool,
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
    /// When the request head arrived (loop clock) and its body bytes so far.
    t0: u64,
    b_in: u64,
    #[cfg(feature = "websocket-h3")]
    ws: WsPart,
}

/// Runs `f` on the WebSocket of stream `id` and sends what it wrote; ends the stream when the
/// WebSocket closed.
#[cfg(feature = "websocket-h3")]
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn ws_run(sh: &Shared, li: usize, h3: &mut Http3, qc: &mut simoom_quic::Connection, route: &Route, conn: u64, id: u64, st: &mut St, now_ns: u64, f: &mut dyn FnMut(&mut crate::ws::WsCore, &mut crate::ws::WsIo)) {
    let Some(core) = st.ws.core.as_mut() else { return };
    let mut w = crate::ws::WsIo::new(route.clone(), conn, id, now_ns);
    f(core, &mut w);
    if w.panicked {
        bump(&sh.counters(li).panics);
    }
    if matches!(st.resp.phase, Phase::Socket) {
        st.resp.out += w.out.len() as u64;
        st.resp.pending.extend_from_slice(&w.out);
        st.resp.pending_fin |= w.close;
        push_pending(h3, qc, id, &mut st.resp);
    }
}

/// Reads a WebSocket stream's DATA into its WebSocket.
#[cfg(feature = "websocket-h3")]
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn ws_read(sh: &Shared, li: usize, c: &mut H3Conn, qc: &mut simoom_quic::Connection, now: Instant, now_ns: u64, route: &Route, stream: u64, tmp: &mut Vec<u8>) {
    if tmp.is_empty() {
        tmp.resize(16 * 1024, 0);
    }
    let Some(mut st) = c.streams.remove(&stream) else { return };
    let mut fin = false;
    loop {
        let Ok((n, f)) = c.h3.recv_body(now, qc, stream, tmp) else { break };
        st.b_in += n as u64;
        let data = tmp[..n].to_vec();
        ws_run(sh, li, &mut c.h3, qc, route, c.id, stream, &mut st, now_ns, &mut |core, w| core.input(w, &data));
        if f {
            fin = true;
            break;
        }
        if n == 0 {
            break;
        }
    }
    if fin {
        st.end = true;
        ws_run(sh, li, &mut c.h3, qc, route, c.id, stream, &mut st, now_ns, &mut |core, w| {
            if !core.is_done() {
                core.eof(w)
            }
        });
    }
    settle(sh, now_ns, c, stream, st);
}

struct H3Conn {
    id: u64,
    h3: Http3,
    streams: FastMap<u64, Box<St>>,
    peer: SocketAddr,
    /// Local address, listener and (once the handshake is done) the TLS session.
    meta: crate::request::Meta,
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
    local: SocketAddr,
    binding: u32,
    /// Trailer fields of the next response ([`crate::Reply::trailer`]).
    trl: HeaderBuf,
    /// Deferred streams in deadline order: (deadline, connection id, stream)
    /// ([`crate::Limits::defer_timeout`]), and the timer armed for the first.
    waits: VecDeque<(u64, u64, u64)>,
    wait_timer: Option<(TimerId, u64)>,
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
        self.arm_waits(cx, now_ns);
    }

    /// The timer of the first deferred stream's deadline (token 1).
    fn arm_waits(&mut self, cx: &mut UdpCtx<'_>, now_ns: u64) {
        let Some(&(at, _, _)) = self.waits.front() else { return };
        if let Some((id, t)) = self.wait_timer {
            if t <= at {
                return;
            }
            cx.cancel_timer(id);
        }
        let id = cx.set_timer(std::time::Duration::from_nanos(at.saturating_sub(now_ns)), 1);
        self.wait_timer = Some((id, at));
    }

    /// Deferred streams whose responder took too long: a 504, and the responder is cancelled.
    fn expire_waits(&mut self, now_ns: u64) {
        while let Some(&(at, conn, id)) = self.waits.front() {
            if at > now_ns {
                break;
            }
            self.waits.pop_front();
            let Some(&hi) = self.ids.get(&conn) else { continue };
            let (Some(c), Some(qc)) = (self.conns.get_mut(&hi), self.ep.conn_mut(ConnHandle(hi))) else { continue };
            let Some(mut st) = c.streams.remove(&id) else { continue };
            if let Phase::Waiting(cancel) = &st.resp.phase {
                cancel.cancel();
                bump(&self.sh.counters(self.li).timeouts);
                self.hdrs.clear();
                self.trl.clear();
                respond(&mut c.h3, qc, &self.hdrs, &mut self.trl, &mut st.resp, &self.sh, now_ns, id, 504, BodyRef::Static(b"Gateway Timeout"));
            }
            settle(&self.sh, now_ns, c, id, st);
            self.touched.push(ConnHandle(hi));
        }
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
                Box::new(H3Conn {
                    id,
                    h3: Http3::new(true, self.h3cfg.clone()),
                    streams: FastMap::default(),
                    peer,
                    meta: crate::request::Meta::new(Some(self.local), self.binding),
                    ready: Vec::new(),
                    flushing: Vec::new(),
                    closing: false,
                }),
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
                close_streams(&self.sh, now_ns, &c);
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
                    st.t0 = now_ns;
                    #[cfg(feature = "websocket-h3")]
                    if fields.iter().any(|f| f.name == b":protocol" && f.value == b"websocket") {
                        st.ws.req = true;
                        st.ws.extensions = fields.iter().find(|f| f.name == b"sec-websocket-extensions").map(|f| f.value.to_vec());
                        // the stream stays open: dispatch now
                        st.queued = true;
                        c.ready.push(stream);
                    }
                    c.streams.insert(stream, st);
                }
                #[cfg(feature = "websocket-h3")]
                H3Event::Data { stream } if c.streams.get(&stream).is_some_and(|st| st.ws.core.is_some()) => ws_read(&self.sh, self.li, c, qc, now, now_ns, &route, stream, &mut self.tmp),
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
                        match &st.resp.phase {
                            Phase::Streaming(s) => s.close(),
                            Phase::Waiting(cancel) => cancel.cancel(),
                            _ => {}
                        }
                        if let Some(src) = &st.src {
                            src.fail("the stream was reset");
                        }
                        if st.dispatched {
                            report(&self.sh, now_ns, c.peer, &c.meta, &st, true);
                        }
                    }
                }
                H3Event::Writable { stream } => {
                    if let Some(mut st) = c.streams.remove(&stream) {
                        push_pending(&mut c.h3, qc, stream, &mut st.resp);
                        settle(&self.sh, now_ns, c, stream, st);
                    }
                }
            }
        }
        for id in std::mem::take(&mut c.ready) {
            dispatch(&self.sh, self.li, &mut self.hdrs, &mut self.trl, &mut self.waits, c, qc, now_ns, id, &route, &pool);
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

fn close_streams(sh: &Shared, now_ns: u64, c: &H3Conn) {
    for st in c.streams.values() {
        match &st.resp.phase {
            Phase::Streaming(s) => s.close(),
            Phase::Waiting(cancel) => cancel.cancel(),
            _ => {}
        }
        if let Some(src) = &st.src {
            src.fail("the connection closed");
        }
        if st.dispatched {
            report(sh, now_ns, c.peer, &c.meta, st, true);
        }
    }
}

/// Reports a finished stream to [`crate::Builder::on_complete`], when one is set.
fn report(sh: &Shared, now_ns: u64, peer: SocketAddr, meta: &crate::request::Meta, st: &St, aborted: bool) {
    if sh.on_complete.is_some() {
        sh.complete(st.resp.status, st.b_in, st.resp.out, st.t0, now_ns, Version::H3, Some(peer), meta.listener, aborted);
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
        st.b_in += n as u64;
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

fn settle(sh: &Shared, now_ns: u64, c: &mut H3Conn, id: u64, st: Box<St>) {
    if !matches!(st.resp.phase, Phase::Done) {
        c.streams.insert(id, st);
        return;
    }
    report(sh, now_ns, c.peer, &c.meta, &st, st.resp.aborted);
    if c.flushing.len() >= FLUSHING_KEPT {
        c.flushing.drain(..FLUSHING_KEPT / 2);
    }
    c.flushing.push(id);
}

#[allow(clippy::too_many_arguments)]
fn dispatch(
    sh: &Shared,
    li: usize,
    hdrs: &mut HeaderBuf,
    trl: &mut HeaderBuf,
    waits: &mut VecDeque<(u64, u64, u64)>,
    c: &mut H3Conn,
    qc: &mut simoom_quic::Connection,
    now_ns: u64,
    id: u64,
    route: &Route,
    pool: &OffloadPool,
) {
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
        respond(&mut c.h3, qc, hdrs, trl, &mut st.resp, sh, now_ns, id, code, BodyRef::Static(reason));
        settle(sh, now_ns, c, id, st);
        return;
    }
    if c.meta.tls.is_none() {
        let s = qc.tls();
        c.meta.tls = Some(Arc::new(crate::request::TlsInfo {
            cipher: s.cipher_suite().unwrap_or(0),
            sni: s.server_name().map(Into::into),
            alpn: qc.alpn().map(Into::into),
            peer_certs: s.peer_certificates().to_vec(),
        }));
    }
    #[cfg(feature = "websocket-h3")]
    let streaming = !st.end && !st.ws.req;
    #[cfg(not(feature = "websocket-h3"))]
    let streaming = !st.end;
    if streaming {
        st.src = Some(Arc::new(SrcShared::new(sh.limits.body_buffer, std::mem::take(&mut st.body))));
    }
    let St {
        head,
        body,
        trailers,
        resp,
        src,
        #[cfg(feature = "websocket-h3")]
        ws,
        ..
    } = &mut *st;
    let mut r = Request::new(head.method(), head.target(), Version::H3, HeaderView::Owned(head));
    r.authority = head.authority();
    r.body = body;
    r.trailers = trailers.as_ref();
    r.peer = Some(c.peer);
    r.secure = true;
    r.loop_index = li;
    r.meta = Some(&c.meta);
    #[cfg(feature = "websocket-h3")]
    {
        r.websocket = ws.req;
    }
    if let Some(s) = src {
        r.streamed = true;
        r.source = Some(BodySource::new(s.clone(), route.clone(), c.id, id));
    }
    let mut t = H3Target {
        h3: &mut c.h3,
        qc,
        hdrs,
        trl,
        waits,
        resp,
        sh,
        li,
        now_ns,
        id,
        conn: c.id,
        route,
        pool,
        answered: false,
        #[cfg(feature = "websocket-h3")]
        ws,
    };
    let panicked = crate::server::call(sh, &mut r, &mut t, &mut None);
    let answered = t.answered;
    drop(r);
    if !answered {
        hdrs.clear();
        trl.clear();
        respond(&mut c.h3, qc, hdrs, trl, &mut st.resp, sh, now_ns, id, 500, BodyRef::Static(b"Internal Server Error"));
    }
    if panicked {
        c.h3.goaway(qc);
    }
    #[cfg(feature = "websocket-h3")]
    if st.ws.core.is_some() {
        // accepted: open it, with any frames that came with the request
        let body = std::mem::take(&mut st.body);
        let eof = st.end;
        ws_run(sh, li, &mut c.h3, qc, route, c.id, id, &mut st, now_ns, &mut |core, w| {
            core.start(w);
            if !body.is_empty() {
                core.input(w, &body);
            }
            if eof && !core.is_done() {
                core.eof(w);
            }
        });
    }
    settle(sh, now_ns, c, id, st);
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
fn respond(h3: &mut Http3, qc: &mut simoom_quic::Connection, hdrs: &HeaderBuf, trl: &mut HeaderBuf, rs: &mut RespPart, sh: &Shared, now_ns: u64, id: u64, status: u16, body: BodyRef<'_>) {
    let bytes = body.as_bytes();
    let with_body = has_body(status) && !rs.head_only;
    rs.status = status;
    rs.out = bytes.len() as u64;
    let trailers = if trl.is_empty() { None } else { Some(std::mem::take(trl)).filter(|_| with_body) };
    let end = (!with_body || bytes.is_empty()) && trailers.is_none();
    let digits = status_digits(status);
    let date = with_date(now_ns, |d| *d);
    let mut lb = [0u8; 20];
    let len = if has_body(status) { Some(decimal(bytes.len() as u64, &mut lb)) } else { None };
    let fields = fields_for(hdrs, sh, &digits, &date, len);
    if h3.send_headers(qc, id, &fields, end).is_err() || end {
        rs.phase = Phase::Done;
        return;
    }
    if let Some(t) = trailers {
        rs.trailers = Some(Box::new(t));
        rs.pending.clear();
        rs.pending.extend_from_slice(bytes);
        rs.pending_fin = true;
        rs.phase = Phase::Sending;
        return push_pending(h3, qc, id, rs);
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
    rs.status = status;
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
    let fin = rs.pending_fin && rs.trailers.is_none();
    let r = if rs.pending.is_empty() && !fin { Ok(0) } else { h3.send_body(qc, id, &rs.pending, fin) };
    match r {
        Ok(n) => {
            let all = n == rs.pending.len();
            rs.pending.drain(..n);
            if let Phase::Streaming(s) = &rs.phase {
                s.credit(n);
            }
            if all && rs.pending_fin {
                if let Some(t) = rs.trailers.take() {
                    let f: Vec<(&[u8], &[u8])> = t.iter().collect();
                    let _ = h3.send_trailers(qc, id, &f);
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

    fn on_timer(&mut self, cx: &mut UdpCtx<'_>, token: u64) {
        if token == 1 {
            self.wait_timer = None;
            let now_ns = cx.now_ns();
            self.expire_waits(now_ns);
            return self.process(cx, Instant::now(), now_ns);
        }
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
                        Msg::Reply(mut resp) if matches!(st.resp.phase, Phase::Waiting(_)) => {
                            std::mem::swap(&mut self.hdrs, &mut resp.headers);
                            let status = if resp.invalid || resp.status < 200 { 500 } else { resp.status };
                            if resp.invalid {
                                self.hdrs.clear();
                            } else {
                                self.trl = std::mem::take(&mut resp.trailers);
                            }
                            respond(&mut c.h3, qc, &self.hdrs, &mut self.trl, &mut st.resp, &sh, now_ns, id, status, std::mem::take(&mut resp.body).into());
                        }
                        Msg::Dropped if matches!(st.resp.phase, Phase::Waiting(_)) => {
                            self.hdrs.clear();
                            respond(&mut c.h3, qc, &self.hdrs, &mut self.trl, &mut st.resp, &sh, now_ns, id, 500, BodyRef::Static(b"Internal Server Error"));
                        }
                        Msg::Stream(mut head, sink) if matches!(st.resp.phase, Phase::Waiting(_)) => {
                            std::mem::swap(&mut self.hdrs, &mut head.headers);
                            let status = if head.invalid || head.status < 200 { 500 } else { head.status };
                            start_stream(&mut c.h3, qc, &self.hdrs, &mut st.resp, &sh, now_ns, id, status, sink);
                        }
                        Msg::Stream(_, sink) => sink.close(),
                        Msg::Chunk(data) => {
                            if let Phase::Streaming(s) = &st.resp.phase {
                                st.resp.out += data.len() as u64;
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
                                    st.resp.aborted = true;
                                } else {
                                    st.resp.pending_fin = true;
                                    push_pending(&mut c.h3, qc, id, &mut st.resp);
                                }
                            }
                        }
                        Msg::EndTrailers(t) => {
                            if let Phase::Streaming(_) = &st.resp.phase {
                                if !t.is_empty() && !st.resp.head_only {
                                    st.resp.trailers = Some(Box::new(t));
                                }
                                st.resp.pending_fin = true;
                                push_pending(&mut c.h3, qc, id, &mut st.resp);
                            }
                        }
                        #[cfg(feature = "websocket-h3")]
                        Msg::Ws(cmd) => {
                            let mut cmd = Some(cmd);
                            let route = Route::Ep(self.handle.get_or_insert_with(|| cx.handle()).clone());
                            ws_run(&sh, self.li, &mut c.h3, qc, &route, c.id, id, &mut st, now_ns, &mut |core, w| {
                                if let Some(cmd) = cmd.take() {
                                    core.command(w, cmd)
                                }
                            });
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
                    settle(&sh, now_ns, c, id, st);
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
        #[cfg(feature = "websocket-h3")]
        {
            // open WebSockets close with 1001
            let route = Route::Ep(self.handle.get_or_insert_with(|| cx.handle()).clone());
            let now_ns = cx.now_ns();
            for (&hi, c) in self.conns.iter_mut() {
                let Some(qc) = self.ep.conn_mut(ConnHandle(hi)) else { continue };
                let ids: Vec<u64> = c.streams.iter().filter(|(_, st)| st.ws.core.is_some()).map(|(&id, _)| id).collect();
                for id in ids {
                    if let Some(mut st) = c.streams.remove(&id) {
                        ws_run(&self.sh, self.li, &mut c.h3, qc, &route, c.id, id, &mut st, now_ns, &mut |core, w| core.stop(w));
                        settle(&self.sh, now_ns, c, id, st);
                    }
                }
            }
        }
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
    trl: &'t mut HeaderBuf,
    waits: &'t mut VecDeque<(u64, u64, u64)>,
    resp: &'t mut RespPart,
    sh: &'t Shared,
    li: usize,
    now_ns: u64,
    id: u64,
    conn: u64,
    route: &'t Route,
    pool: &'t OffloadPool,
    answered: bool,
    #[cfg(feature = "websocket-h3")]
    ws: &'t mut WsPart,
}

impl Target for H3Target<'_> {
    fn headers(&mut self) -> &mut HeaderBuf {
        self.hdrs
    }

    fn trailers(&mut self) -> &mut HeaderBuf {
        self.trl
    }

    fn respond(&mut self, status: u16, body: BodyRef<'_>, _close: bool) {
        respond(self.h3, self.qc, self.hdrs, self.trl, self.resp, self.sh, self.now_ns, self.id, status, body);
        self.answered = true;
    }

    fn defer(&mut self) -> Responder {
        let c = Arc::new(Cancel::default());
        self.resp.phase = Phase::Waiting(c.clone());
        self.answered = true;
        let d = self.sh.defer_ns;
        if d != 0 {
            self.waits.push_back((self.now_ns.saturating_add(d), self.conn, self.id));
        }
        Responder::new(self.route.clone(), self.conn, self.id, self.sh.limits.stream_buffer, c)
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

    /// Accepts an extended CONNECT with `:protocol websocket` (RFC 9220): a 200 without a
    /// body; the stream carries WebSocket frames from then on.
    #[cfg(feature = "websocket-h3")]
    fn websocket(&mut self, protocol: Option<&[u8]>, handler: Box<dyn crate::ws::WebSocketHandler>) -> bool {
        if !self.ws.req {
            return false;
        }
        if let Some(p) = protocol {
            self.hdrs.push(b"sec-websocket-protocol", p);
        }
        let (ext, deflate) = crate::ws::negotiate_deflate(self.sh, self.ws.extensions.as_deref());
        if let Some(e) = &ext {
            self.hdrs.push(b"sec-websocket-extensions", e.as_bytes());
        }
        self.answered = true;
        self.resp.status = 200;
        let digits = status_digits(200);
        let date = with_date(self.now_ns, |d| *d);
        let fields = fields_for(self.hdrs, self.sh, &digits, &date, None);
        if self.h3.send_headers(self.qc, self.id, &fields, false).is_err() {
            self.resp.phase = Phase::Done;
            return true;
        }
        self.resp.phase = Phase::Socket;
        self.ws.core = Some(Box::new(crate::ws::WsCore::new(handler, self.sh.limits.max_ws_message, deflate)));
        true
    }
}
