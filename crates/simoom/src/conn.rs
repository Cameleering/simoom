//! The runtime connection: optional TLS, the protocol layer (HTTP/1.1, HTTP/2, WebSocket) and
//! its switches, one timer per connection, write deadlines and read backpressure.

use crate::handle::Envelope;
use crate::reply::BodyRef;
use crate::server::{bump, Shared};
use simoom_rt::timer::TimerId;
use simoom_rt::{CloseReason, ConnInfo, Connection, Ctx, Message};
use std::net::SocketAddr;
use std::sync::Arc;

/// Output and context for a protocol layer during one callback.
pub(crate) struct Io<'a, 'c> {
    pub(crate) cx: &'a mut Ctx<'c>,
    buf: &'a mut Vec<u8>,
    #[cfg(feature = "tls")]
    tls: Option<&'a mut simoom_tls::Connection>,
    /// The loop clock, nanoseconds.
    pub(crate) now: u64,
    pub(crate) sh: &'a Shared,
    pub(crate) li: usize,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) secure: bool,
    /// Close gracefully once the output is flushed.
    pub(crate) close: bool,
    /// Close at once, discarding output.
    pub(crate) abort: bool,
    /// When the last service call of this callback ended (for the stall watchdog).
    pub(crate) clock: Option<std::time::Instant>,
    /// The loop is behind ([`crate::Limits::shed_lag`]): refuse new requests.
    pub(crate) shed: bool,
}

/// Bodies at least this large go out as their own buffer (no copy) on plain TCP.
const OWN_BUFFER: usize = 4096;

impl Io<'_, '_> {
    /// The output buffer for this callback (pooled).
    pub(crate) fn out(&mut self) -> &mut Vec<u8> {
        if self.buf.capacity() == 0 {
            *self.buf = self.cx.buffer(2048);
        }
        self.buf
    }

    pub(crate) fn write(&mut self, b: &[u8]) {
        self.out().extend_from_slice(b);
    }

    /// Nothing is waiting in this callback's output buffer.
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    pub(crate) fn out_is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn plain(&self) -> bool {
        #[cfg(feature = "tls")]
        {
            self.tls.is_none()
        }
        #[cfg(not(feature = "tls"))]
        {
            true
        }
    }

    pub(crate) fn write_body(&mut self, b: BodyRef<'_>) {
        match b {
            BodyRef::Owned(v) if v.len() >= OWN_BUFFER && self.plain() => {
                self.flush();
                self.cx.send(v);
            }
            BodyRef::Static(s) if s.len() >= OWN_BUFFER && self.plain() => {
                self.flush();
                self.cx.send_static(s);
            }
            b => self.write(b.as_bytes()),
        }
    }

    /// Hands the output to the runtime (encrypting it first with TLS).
    pub(crate) fn flush(&mut self) {
        #[cfg(feature = "tls")]
        if let Some(t) = self.tls.as_mut() {
            if !self.buf.is_empty() {
                let _ = t.write_plaintext(self.buf);
                self.buf.clear();
            }
            if t.wants_write() {
                let mut o = self.cx.buffer(t.tls_output().len());
                t.write_tls_into(&mut o);
                self.cx.send(o);
            }
            return;
        }
        if !self.buf.is_empty() {
            let b = std::mem::take(self.buf);
            self.cx.send(b);
        }
    }
}

/// A protocol driven by [`Conn`].
pub(crate) trait Layer {
    /// Called once when the layer takes over the connection.
    fn start(&mut self, io: &mut Io<'_, '_>) {
        let _ = io;
    }
    /// Received bytes; returns how many were consumed.
    fn input(&mut self, io: &mut Io<'_, '_>, data: &[u8]) -> usize;
    /// A message from another thread.
    fn message(&mut self, io: &mut Io<'_, '_>, env: Envelope);
    /// Output drained below the low-water mark (after `notify_drain`).
    fn drain(&mut self, io: &mut Io<'_, '_>) {
        let _ = io;
    }
    /// The peer closed its sending side.
    fn eof(&mut self, io: &mut Io<'_, '_>) {
        io.close = true;
    }
    /// Graceful stop.
    fn stop(&mut self, io: &mut Io<'_, '_>);
    /// The connection timer fired.
    fn tick(&mut self, io: &mut Io<'_, '_>);
    /// The next deadline (loop-clock ns), or `u64::MAX`.
    fn deadline(&self, now: u64, sh: &Shared) -> u64;
    /// True while reading should pause (backpressure, or a reply in progress).
    fn wants_pause(&self) -> bool;
    /// The next layer, after an upgrade.
    fn take_switch(&mut self) -> Option<Box<dyn Layer>> {
        None
    }
    /// The connection is gone.
    fn closed(&mut self) {}
}

/// Waits for the TLS handshake (when TLS is on), then hands over to the protocol ALPN chose.
struct Handshake;

impl Layer for Handshake {
    fn input(&mut self, _io: &mut Io<'_, '_>, _data: &[u8]) -> usize {
        0
    }
    fn message(&mut self, _io: &mut Io<'_, '_>, _env: Envelope) {}
    fn stop(&mut self, io: &mut Io<'_, '_>) {
        io.close = true;
    }
    fn tick(&mut self, io: &mut Io<'_, '_>) {
        bump(&io.sh.counters(io.li).timeouts);
        io.abort = true;
    }
    fn deadline(&self, _now: u64, _sh: &Shared) -> u64 {
        u64::MAX // Conn keeps the handshake deadline
    }
    fn wants_pause(&self) -> bool {
        false
    }
}

#[cfg(feature = "tls")]
struct TlsState {
    conn: simoom_tls::Connection,
    plain: Vec<u8>,
    ready: bool,
}

/// One accepted TCP connection.
pub(crate) struct Conn {
    sh: Arc<Shared>,
    li: usize,
    peer: Option<SocketAddr>,
    secure: bool,
    layer: Box<dyn Layer>,
    out: Vec<u8>,
    #[cfg(feature = "tls")]
    tls: Option<Box<TlsState>>,
    paused: bool,
    timer: Option<(TimerId, u64)>,
    /// When the handshake must be done (TLS) — the head timeout from the accept.
    hs_deadline: u64,
    /// Write progress: queued bytes at the last check and since when it has not shrunk.
    wq_last: usize,
    wq_since: u64,
    closing: bool,
    /// Held for the connection's life when connections per IP are capped.
    _ip_slot: Option<crate::server::IpSlot>,
}

/// Initial layer for plain TCP: HTTP/1.1 (which detects the HTTP/2 preface).
fn initial(sh: &Shared, now: u64) -> Box<dyn Layer> {
    #[cfg(feature = "http1")]
    {
        let _ = sh;
        Box::new(crate::h1::H1::new(now))
    }
    #[cfg(all(not(feature = "http1"), feature = "http2"))]
    {
        let _ = now;
        Box::new(crate::h2::H2Layer::new(sh, now))
    }
    #[cfg(all(not(feature = "http1"), not(feature = "http2")))]
    {
        let _ = (sh, now);
        Box::new(Handshake)
    }
}

impl Conn {
    pub(crate) fn new(sh: Arc<Shared>, info: &ConnInfo, secure: bool, ip_slot: Option<crate::server::IpSlot>) -> Conn {
        let _ = &secure;
        Conn {
            #[cfg(feature = "tls")]
            tls: if secure { sh.tls.as_ref().map(|c| Box::new(TlsState { conn: simoom_tls::ServerConnection::new(c.clone()).into_inner(), plain: Vec::new(), ready: false })) } else { None },
            li: info.loop_index,
            peer: info.peer,
            secure,
            layer: Box::new(Handshake),
            out: Vec::new(),
            paused: false,
            timer: None,
            hs_deadline: 0,
            wq_last: 0,
            wq_since: 0,
            closing: false,
            _ip_slot: ip_slot,
            sh,
        }
    }

    /// Runs `f` with an [`Io`], then flushes, applies close, pause and the timer.
    fn with_io(&mut self, cx: &mut Ctx<'_>, f: impl FnOnce(&mut dyn Layer, &mut Io<'_, '_>)) {
        if self.closing {
            return;
        }
        let now = cx.now_ns();
        // Loop lag: how long after this turn's events were ready the loop got here.
        let shed = self.sh.shed_ns != 0 && simoom_sys::time::now_ns().saturating_sub(now) > self.sh.shed_ns;
        let (close, abort) = {
            let mut io = Io {
                cx,
                buf: &mut self.out,
                #[cfg(feature = "tls")]
                tls: self.tls.as_mut().map(|t| &mut t.conn),
                now,
                sh: &self.sh,
                li: self.li,
                peer: self.peer,
                secure: self.secure,
                close: false,
                abort: false,
                clock: None,
                shed,
            };
            f(&mut *self.layer, &mut io);
            io.flush();
            (io.close, io.abort)
        };
        self.after(cx, close, abort);
    }

    fn after(&mut self, cx: &mut Ctx<'_>, close: bool, abort: bool) {
        if abort {
            self.closing = true;
            cx.abort();
            return;
        }
        if close {
            self.closing = true;
            #[cfg(feature = "tls")]
            if let Some(t) = self.tls.as_mut() {
                t.conn.send_close_notify();
                if t.conn.wants_write() {
                    let mut o = cx.buffer(64);
                    t.conn.write_tls_into(&mut o);
                    cx.send(o);
                }
            }
            cx.close();
            return;
        }
        let want = self.layer.wants_pause();
        if want != self.paused {
            self.paused = want;
            if want {
                cx.pause_reading();
            } else {
                cx.resume_reading();
                #[cfg(feature = "tls")]
                if self.tls.as_ref().is_some_and(|t| !t.plain.is_empty()) {
                    self.pump(cx);
                    return;
                }
            }
        }
        self.arm(cx);
    }

    fn arm(&mut self, cx: &mut Ctx<'_>) {
        let now = cx.now_ns();
        let mut d = self.layer.deadline(now, &self.sh);
        if self.hs_deadline != 0 {
            d = d.min(self.hs_deadline);
        }
        let q = cx.queued();
        if q == 0 {
            self.wq_since = 0;
        } else if self.wq_since == 0 || q < self.wq_last {
            self.wq_since = now;
        }
        self.wq_last = q;
        if q > 0 {
            d = d.min(self.wq_since + self.sh.limits.write_timeout.as_nanos() as u64);
        }
        if d == u64::MAX {
            return;
        }
        if let Some((id, at)) = self.timer {
            if at <= d {
                return;
            }
            cx.cancel_timer(id);
        }
        let id = cx.set_timer(std::time::Duration::from_nanos(d.saturating_sub(now)), 0);
        self.timer = Some((id, d));
    }

    /// Feeds input to the layer (and the next one after an upgrade); returns bytes consumed.
    fn feed(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let mut pos = 0;
        self.with_io(cx, |layer, io| {
            pos = layer.input(io, data);
        });
        while let Some(next) = self.layer.take_switch() {
            if self.closing {
                break;
            }
            self.layer = next;
            self.with_io(cx, |l, io| l.start(io));
            if pos < data.len() {
                let rest = &data[pos..];
                let mut n = 0;
                self.with_io(cx, |layer, io| n = layer.input(io, rest));
                pos += n;
            }
        }
        pos
    }

    /// TLS: feeds buffered plaintext to the layer.
    #[cfg(feature = "tls")]
    fn pump(&mut self, cx: &mut Ctx<'_>) {
        loop {
            let Some(t) = self.tls.as_mut() else { return };
            if t.plain.is_empty() || self.paused || self.closing {
                // Still flush handshake output and arm timers.
                self.with_io(cx, |_, _| {});
                return;
            }
            let plain = std::mem::take(&mut t.plain);
            let n = self.feed(cx, &plain);
            let Some(t) = self.tls.as_mut() else { return };
            let mut rest = plain;
            rest.drain(..n.min(rest.len()));
            rest.extend_from_slice(&t.plain);
            t.plain = rest;
            if n == 0 {
                self.with_io(cx, |_, _| {});
                return;
            }
        }
    }

    #[cfg(feature = "tls")]
    fn tls_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let t = self.tls.as_mut().expect("tls");
        let mut used = 0;
        loop {
            let n = t.conn.read_tls(&data[used..]);
            used += n;
            if t.conn.process_new_packets().is_err() {
                bump(&self.sh.counters(self.li).tls_errors);
                if t.conn.wants_write() {
                    let mut o = cx.buffer(64);
                    t.conn.write_tls_into(&mut o);
                    cx.send(o);
                }
                self.closing = true;
                cx.close();
                return data.len();
            }
            let p = t.conn.plaintext();
            if !p.is_empty() {
                let k = p.len();
                t.plain.extend_from_slice(p);
                t.conn.consume_plaintext(k);
            }
            if n == 0 || used >= data.len() {
                break;
            }
        }
        if !t.ready && !t.conn.is_handshaking() {
            t.ready = true;
            self.hs_deadline = 0;
            let now = cx.now_ns();
            #[cfg(feature = "http2")]
            let h2 = t.conn.alpn_protocol() == Some(b"h2") && self.sh.http2;
            #[cfg(not(feature = "http2"))]
            let h2 = false;
            let layer: Box<dyn Layer> = if h2 {
                #[cfg(feature = "http2")]
                {
                    Box::new(crate::h2::H2Layer::new(&self.sh, now))
                }
                #[cfg(not(feature = "http2"))]
                {
                    initial(&self.sh, now)
                }
            } else {
                initial(&self.sh, now)
            };
            self.layer = layer;
            self.with_io(cx, |l, io| l.start(io));
        }
        self.pump(cx);
        used
    }
}

impl Connection for Conn {
    fn on_open(&mut self, cx: &mut Ctx<'_>) {
        let now = cx.now_ns();
        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            self.hs_deadline = now + self.sh.limits.head_timeout.as_nanos() as u64;
            self.arm(cx);
            return;
        }
        self.layer = initial(&self.sh, now);
        self.with_io(cx, |l, io| l.start(io));
    }

    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        if self.closing {
            return data.len();
        }
        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            return self.tls_data(cx, data);
        }
        self.feed(cx, data)
    }

    fn on_eof(&mut self, cx: &mut Ctx<'_>) {
        self.with_io(cx, |l, io| l.eof(io));
    }

    fn on_drain(&mut self, cx: &mut Ctx<'_>) {
        self.with_io(cx, |l, io| l.drain(io));
    }

    fn on_timer(&mut self, cx: &mut Ctx<'_>, _token: u64) {
        self.timer = None;
        let now = cx.now_ns();
        if self.hs_deadline != 0 && now >= self.hs_deadline {
            bump(&self.sh.counters(self.li).timeouts);
            self.closing = true;
            cx.abort();
            return;
        }
        let q = cx.queued();
        if q > 0 && self.wq_since != 0 && q >= self.wq_last && now >= self.wq_since + self.sh.limits.write_timeout.as_nanos() as u64 {
            bump(&self.sh.counters(self.li).timeouts);
            self.closing = true;
            cx.abort();
            return;
        }
        self.with_io(cx, |l, io| l.tick(io));
    }

    fn on_message(&mut self, cx: &mut Ctx<'_>, msg: Message) {
        let Ok(env) = msg.downcast::<Envelope>() else { return };
        self.with_io(cx, |l, io| l.message(io, *env));
        while let Some(next) = self.layer.take_switch() {
            if self.closing {
                break;
            }
            self.layer = next;
            self.with_io(cx, |l, io| l.start(io));
        }
    }

    fn on_stop(&mut self, cx: &mut Ctx<'_>) {
        self.with_io(cx, |l, io| l.stop(io));
    }

    fn on_close(&mut self, _reason: CloseReason) {
        self.layer.closed();
    }
}
