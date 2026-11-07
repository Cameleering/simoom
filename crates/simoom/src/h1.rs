//! HTTP/1.1 on a connection: strict parsing, pipelining, bodies (buffered or streamed),
//! 100-continue, deferred and streamed replies, timeouts, and upgrades to h2c and WebSocket.

use crate::conn::{Io, Layer};
use crate::handle::{BodySink, BodySource, Envelope, Msg, Pushed as SrcPushed, Responder, Route, SinkShared, SrcShared};
use crate::reply::{BodyRef, Target};
use crate::request::{HeaderView, Request};
use crate::server::{bump, Shared};
use crate::types::{HeaderBuf, StaticReply, Version};
use crate::util::{content_length, has_body, status_line, with_date};
use simoom_http1::write::{ChunkHeader, CONTINUE, LAST_CHUNK};
use simoom_http1::{BodyDecoder, BodyEvent, Error as ParseError, Framing, RequestParser, Status, EMPTY_HEADER};
use simoom_rt::offload::OffloadPool;
use std::sync::Arc;

/// Header slots on the stack; requests with more fields are parsed again into a heap array.
const STACK_HEADERS: usize = 32;

enum Resp {
    /// No response outstanding.
    Idle,
    /// Deferred: a [`Responder`] will answer.
    Waiting,
    /// A streamed body is being written.
    Streaming(Box<Stream>),
}

struct Stream {
    chunked: bool,
    head_only: bool,
    sink: Arc<SinkShared>,
    unacked: usize,
}

/// A request body that did not arrive with its head.
struct BodyIn {
    /// The head, copied, to parse again at dispatch.
    head: Vec<u8>,
    dec: BodyDecoder,
    /// Buffered body while not dispatched.
    buf: Vec<u8>,
    /// The streaming source once dispatched.
    src: Option<Arc<SrcShared>>,
    /// When the body started, moved forward by the time reading was paused for the reader
    /// (the minimum body rate applies to the client, not to a slow handler).
    started: u64,
    bytes: u64,
    /// The source is full: reading paused until it drains.
    full: bool,
    paused_at: u64,
}

pub(crate) struct H1 {
    parser: RequestParser,
    /// Request number: the token of deferred and streamed replies.
    seq: u64,
    resp: Resp,
    body: Option<Box<BodyIn>>,
    /// A body is still arriving for the current request.
    reading_body: bool,
    hdrs: HeaderBuf,
    close_after: bool,
    head_only: bool,
    http10: bool,
    requests: u64,
    /// When the current head started (0: none in progress).
    head_started: u64,
    idle_since: u64,
    first: bool,
    stopping: bool,
    /// The connection is closing or switched: no more input.
    done: bool,
    switch: Option<Box<dyn Layer>>,
}

enum TState {
    None,
    Responded,
    Deferred,
    Streaming,
    #[cfg(feature = "websocket")]
    Upgraded,
}

impl H1 {
    pub(crate) fn new(now: u64) -> H1 {
        H1 {
            parser: RequestParser::new(),
            seq: 0,
            resp: Resp::Idle,
            body: None,
            reading_body: false,
            hdrs: HeaderBuf::default(),
            close_after: false,
            head_only: false,
            http10: false,
            requests: 0,
            head_started: now,
            idle_since: now,
            first: true,
            stopping: false,
            done: false,
            switch: None,
        }
    }

    fn idle(&self) -> bool {
        matches!(self.resp, Resp::Idle) && !self.reading_body
    }

    // ------------------------------------------------------------------ writing

    fn connection_lines(&self, out: &mut Vec<u8>, sh: &Shared, close: bool) {
        if close {
            out.extend_from_slice(b"connection: close\r\n");
        } else if self.http10 {
            out.extend_from_slice(b"connection: keep-alive\r\n");
        }
        if let Some(a) = sh.alt_svc_line() {
            out.extend_from_slice(a);
        }
    }

    /// Whether the connection closes after the current response.
    fn closing(&self) -> bool {
        self.close_after || self.stopping || self.reading_body
    }

    /// Writes a whole response with the headers in `self.hdrs`.
    fn write_full(&mut self, io: &mut Io<'_, '_>, status: u16, body: BodyRef<'_>, close: bool) {
        self.close_after |= close;
        let close = self.closing();
        let sh = io.sh;
        let now = io.now;
        let len = body.as_bytes().len() as u64;
        let with_body = has_body(status);
        {
            let out = io.out();
            status_line(out, status);
            self.hdrs.write_h1(out);
            with_date(now, |d| {
                out.extend_from_slice(b"date: ");
                out.extend_from_slice(d);
                out.extend_from_slice(b"\r\n");
            });
            if with_body {
                content_length(out, len);
            }
            self.connection_lines(out, sh, close);
            out.extend_from_slice(b"\r\n");
        }
        if with_body && !self.head_only && len > 0 {
            io.write_body(body);
        }
    }

    fn write_fixed(&mut self, io: &mut Io<'_, '_>, r: &StaticReply, close: bool) {
        self.close_after |= close;
        let close = self.closing();
        let sh = io.sh;
        let now = io.now;
        let http10 = self.http10;
        let head_only = self.head_only;
        let out = io.out();
        out.extend_from_slice(&r.h1_pre);
        with_date(now, |d| out.extend_from_slice(d));
        if close {
            out.extend_from_slice(b"\r\nconnection: close");
        } else if http10 {
            out.extend_from_slice(b"\r\nconnection: keep-alive");
        }
        if let Some(a) = sh.alt_svc_line() {
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(&a[..a.len() - 2]);
        }
        let post = if head_only { &r.h1_post[..r.h1_post.len() - r.body_len] } else { &r.h1_post[..] };
        out.extend_from_slice(post);
    }

    fn start_stream(&mut self, io: &mut Io<'_, '_>, status: u16, close: bool, sink: Arc<SinkShared>) {
        self.close_after |= close;
        let chunked = !self.http10 && has_body(status);
        if !chunked {
            self.close_after = true; // close-delimited body on HTTP/1.0
        }
        let close = self.closing();
        let sh = io.sh;
        let now = io.now;
        {
            let out = io.out();
            status_line(out, status);
            self.hdrs.write_h1(out);
            with_date(now, |d| {
                out.extend_from_slice(b"date: ");
                out.extend_from_slice(d);
                out.extend_from_slice(b"\r\n");
            });
            if chunked {
                out.extend_from_slice(b"transfer-encoding: chunked\r\n");
            }
            self.connection_lines(out, sh, close);
            out.extend_from_slice(b"\r\n");
        }
        self.resp = Resp::Streaming(Box::new(Stream { chunked, head_only: self.head_only || !has_body(status), sink, unacked: 0 }));
    }

    fn chunk(&mut self, io: &mut Io<'_, '_>, data: Vec<u8>) {
        let Resp::Streaming(s) = &mut self.resp else { return };
        let n = data.len();
        if !s.head_only && n > 0 {
            if s.chunked {
                io.write(ChunkHeader::new(n).as_bytes());
                io.write_body(BodyRef::Owned(data));
                io.write(b"\r\n");
            } else {
                io.write_body(BodyRef::Owned(data));
            }
        }
        s.unacked += n;
        io.cx.notify_drain();
    }

    fn end_stream(&mut self, io: &mut Io<'_, '_>, abort: bool) {
        let Resp::Streaming(s) = &mut self.resp else { return };
        if abort {
            s.sink.close();
            self.done = true;
            io.abort = true;
            return;
        }
        if s.chunked && !s.head_only {
            io.write(LAST_CHUNK);
        }
        s.sink.close();
        self.finish_response(io);
    }

    /// The current response is complete.
    fn finish_response(&mut self, io: &mut Io<'_, '_>) {
        self.resp = Resp::Idle;
        self.idle_since = io.now;
        if self.closing() {
            self.done = true;
            io.close = true;
        }
    }

    /// A request error: an error response, then close.
    fn fail(&mut self, io: &mut Io<'_, '_>, status: u16) {
        let c = io.sh.counters(io.li);
        bump(match status {
            413 | 414 | 431 => &c.too_large,
            408 => &c.timeouts,
            _ => &c.bad_requests,
        });
        if matches!(self.resp, Resp::Idle) {
            self.hdrs.clear();
            self.hdrs.push(b"content-type", b"text/plain");
            self.close_after = true;
            self.head_only = false;
            let reason = simoom_http1::write::reason(status).as_bytes();
            self.write_full(io, status, BodyRef::Slice(reason), true);
        }
        self.done = true;
        io.close = true;
    }

    // ------------------------------------------------------------------ reading

    fn head(&mut self, io: &mut Io<'_, '_>, rest: &[u8]) -> Option<usize> {
        let lim = io.sh.h1;
        let mut hs = [EMPTY_HEADER; STACK_HEADERS];
        match self.parser.parse(rest, &mut hs, &lim) {
            Err(ParseError::TooManyHeaders) if lim.max_headers > STACK_HEADERS => {
                self.parser.reset();
                let mut big = vec![EMPTY_HEADER; lim.max_headers];
                let r = self.parser.parse(rest, &mut big, &lim);
                self.parsed(io, rest, r)
            }
            r => self.parsed(io, rest, r),
        }
    }

    fn parsed(&mut self, io: &mut Io<'_, '_>, rest: &[u8], r: Result<Status<simoom_http1::Request<'_, '_>>, ParseError>) -> Option<usize> {
        match r {
            Ok(Status::Partial) => {
                if self.head_started == 0 {
                    self.head_started = io.now;
                }
                None
            }
            Err(e) => {
                self.fail(io, e.status());
                None
            }
            Ok(Status::Complete(req)) => {
                self.head_started = 0;
                Some(self.request(io, &req, rest))
            }
        }
    }

    fn request(&mut self, io: &mut Io<'_, '_>, req: &simoom_http1::Request<'_, '_>, rest: &[u8]) -> usize {
        self.seq += 1;
        self.requests += 1;
        bump(&io.sh.counters(io.li).requests);
        self.head_only = req.method == b"HEAD";
        self.http10 = req.version == simoom_http1::Version::Http10;
        let max = io.sh.limits.max_requests_per_connection;
        self.close_after = !req.keep_alive || self.stopping || (max != 0 && self.requests >= max);
        let hl = req.head_len;
        #[cfg(feature = "http2")]
        if io.sh.http2 && req.upgrade.is_some() && self.h2c(io, req) {
            return hl;
        }
        match req.framing {
            Framing::None => {
                self.dispatch(io, req, b"", None);
                hl
            }
            Framing::Length(n) if (rest.len() - hl) as u64 >= n => {
                let end = hl + n as usize;
                self.dispatch(io, req, &rest[hl..end], None);
                end
            }
            framing => {
                let dec = BodyDecoder::new(framing, &io.sh.h1);
                let buffer = io.sh.limits.body_buffer;
                let mut b = Box::new(BodyIn { head: Vec::new(), dec, buf: Vec::new(), src: None, started: io.now, bytes: 0, full: false, paused_at: 0 });
                self.reading_body = true;
                if matches!(framing, Framing::Length(n) if n > buffer as u64) {
                    // Too large to buffer: stream it from the start.
                    let src = Arc::new(SrcShared::new(buffer, Vec::new()));
                    b.src = Some(src.clone());
                    self.body = Some(b);
                    self.dispatch(io, req, b"", Some(src.clone()));
                    if req.wants_continue() && !self.done && Arc::strong_count(&src) > 1 && matches!(self.resp, Resp::Waiting) {
                        io.write(CONTINUE);
                    }
                } else {
                    b.head.extend_from_slice(&rest[..hl]);
                    if req.wants_continue() {
                        io.write(CONTINUE);
                    }
                    self.body = Some(b);
                }
                hl
            }
        }
    }

    /// Feeds body bytes; returns (consumed, finished).
    fn body_input(&mut self, io: &mut Io<'_, '_>, data: &[u8]) -> (usize, bool) {
        let Some(mut b) = self.body.take() else { return (0, true) };
        let buffer = io.sh.limits.body_buffer;
        let mut pos = 0;
        loop {
            if b.dec.is_done() {
                break;
            }
            if b.full {
                self.body = Some(b);
                return (pos, false);
            }
            match b.dec.decode(&data[pos..]) {
                Err(e) => {
                    self.reading_body = false;
                    if let Some(src) = &b.src {
                        src.fail("the request body is malformed or too large");
                    }
                    self.fail(io, e.status());
                    return (data.len(), false);
                }
                Ok((n, ev)) => {
                    pos += n;
                    match ev {
                        BodyEvent::Data(d) => {
                            b.bytes += d.len() as u64;
                            if let Some(src) = &b.src {
                                if src.push(d) == SrcPushed::Full {
                                    b.full = true;
                                    b.paused_at = io.now;
                                }
                            } else {
                                b.buf.extend_from_slice(d);
                                if b.buf.len() > buffer {
                                    // Too long to buffer: dispatch with a streaming source.
                                    let src = Arc::new(SrcShared::new(buffer, std::mem::take(&mut b.buf)));
                                    b.src = Some(src.clone());
                                    let head = std::mem::take(&mut b.head);
                                    self.body = Some(b);
                                    self.reparse(io, &head, b"", Some(src));
                                    match self.body.take() {
                                        Some(x) => b = x,
                                        None => return (data.len(), false),
                                    }
                                    if self.done {
                                        self.body = Some(b);
                                        return (data.len(), false);
                                    }
                                }
                            }
                        }
                        BodyEvent::End(_) => break,
                        BodyEvent::NeedMore => {
                            self.body = Some(b);
                            return (pos, false);
                        }
                    }
                }
            }
        }
        // The body is complete.
        self.reading_body = false;
        match &b.src {
            Some(src) => src.finish(),
            None => {
                let head = std::mem::take(&mut b.head);
                let body = std::mem::take(&mut b.buf);
                self.reparse(io, &head, &body, None);
            }
        }
        (pos, true)
    }

    /// Parses a copied head again and dispatches it.
    fn reparse(&mut self, io: &mut Io<'_, '_>, head: &[u8], body: &[u8], src: Option<Arc<SrcShared>>) {
        let lim = io.sh.h1;
        let mut hs = [EMPTY_HEADER; STACK_HEADERS];
        let mut big = Vec::new();
        let slots: &mut [simoom_http1::Header<'_>] = if lim.max_headers > STACK_HEADERS && head.iter().filter(|&&b| b == b'\n').count() > STACK_HEADERS {
            big.resize(lim.max_headers, EMPTY_HEADER);
            &mut big
        } else {
            &mut hs
        };
        if let Ok(Status::Complete(req)) = simoom_http1::parse_request(head, slots, &lim) {
            self.dispatch(io, &req, body, src);
        } else {
            self.fail(io, 400);
        }
    }

    /// Calls the service for a parsed request.
    fn dispatch(&mut self, io: &mut Io<'_, '_>, req: &simoom_http1::Request<'_, '_>, body: &[u8], src: Option<Arc<SrcShared>>) {
        let sh = io.sh;
        let version = if self.http10 { Version::Http10 } else { Version::Http11 };
        let mut r = Request::new(req.method, req.target, version, HeaderView::H1(req.headers));
        r.body = body;
        r.peer = io.peer;
        r.secure = io.secure;
        r.loop_index = io.li;
        if let Some(s) = src {
            r.streamed = true;
            r.source = Some(BodySource::new(s, Route::Conn(io.cx.handle()), 0, self.seq));
        }
        #[cfg(feature = "websocket")]
        let ws = if req.upgrade.is_some_and(|u| crate::util::has_token(u, b"websocket")) { simoom_http1::ws::validate_handshake(req).ok() } else { None };
        #[cfg(feature = "websocket")]
        {
            r.websocket = ws.is_some();
        }
        let mut clock = io.clock.take();
        let (panicked, state) = {
            let mut t = H1Target {
                h: self,
                io,
                state: TState::None,
                #[cfg(feature = "websocket")]
                ws,
            };
            let p = crate::server::call(sh, &mut r, &mut t, &mut clock);
            (p, t.state)
        };
        io.clock = clock;
        drop(r);
        if panicked {
            self.close_after = true;
        }
        match state {
            TState::Responded => self.finish_response(io),
            TState::None => {
                self.hdrs.clear();
                self.write_full(io, 500, BodyRef::Static(b"Internal Server Error"), panicked);
                self.finish_response(io);
            }
            TState::Deferred | TState::Streaming => {}
            #[cfg(feature = "websocket")]
            TState::Upgraded => {}
        }
    }

    /// Answers `Upgrade: h2c` (RFC 7540 §3.2) and hands the connection to HTTP/2.
    #[cfg(feature = "http2")]
    fn h2c(&mut self, io: &mut Io<'_, '_>, req: &simoom_http1::Request<'_, '_>) -> bool {
        let mut s = Vec::new();
        if !simoom_http1::h2c::upgrade_settings(req, &mut s) {
            return false;
        }
        let Some(v) = req.header(b"http2-settings") else { return false };
        let mut head = crate::types::OwnedHead::default();
        head.set_method(req.method);
        head.set_target(req.target);
        if let Some(h) = req.host {
            head.set_authority(h);
        }
        for h in req.headers {
            let n = h.name;
            let skip = [&b"connection"[..], b"upgrade", b"http2-settings", b"host", b"keep-alive", b"proxy-connection", b"te", b"transfer-encoding"];
            if !skip.iter().any(|s| n.eq_ignore_ascii_case(s)) {
                head.add_field(n, h.value);
            }
        }
        let Some(layer) = crate::h2::H2Layer::upgrade(io, v, head) else { return false };
        bump(&io.sh.counters(io.li).upgrades);
        self.switch = Some(Box::new(layer));
        self.done = true;
        true
    }
}

impl Layer for H1 {
    fn input(&mut self, io: &mut Io<'_, '_>, data: &[u8]) -> usize {
        let mut pos = 0;
        while !self.done {
            if self.body.is_some() {
                let (n, finished) = self.body_input(io, &data[pos..]);
                pos += n;
                if !finished {
                    break;
                }
                continue;
            }
            if !self.idle() || pos >= data.len() || self.stopping {
                break;
            }
            let rest = &data[pos..];
            #[cfg(feature = "http2")]
            if self.first && io.sh.http2 {
                match simoom_http1::h2c::detect_preface(rest) {
                    simoom_http1::h2c::Preface::H2 => {
                        self.switch = Some(Box::new(crate::h2::H2Layer::new(io.sh, io.now)));
                        self.done = true;
                        break;
                    }
                    simoom_http1::h2c::Preface::Partial => {
                        if self.head_started == 0 {
                            self.head_started = io.now;
                        }
                        break;
                    }
                    simoom_http1::h2c::Preface::Http1 => {}
                }
            }
            self.first = false;
            match self.head(io, rest) {
                Some(n) => pos += n,
                None => break,
            }
        }
        if self.done && self.switch.is_none() {
            return data.len();
        }
        pos
    }

    fn message(&mut self, io: &mut Io<'_, '_>, env: Envelope) {
        if env.token != self.seq {
            if let Msg::Stream(_, sink) = env.msg {
                sink.close();
            }
            return;
        }
        match env.msg {
            Msg::Reply(mut resp) if matches!(self.resp, Resp::Waiting) => {
                std::mem::swap(&mut self.hdrs, &mut resp.headers);
                let (status, close) = if resp.invalid { (500, resp.close) } else { (resp.status.max(200), resp.close) };
                if resp.invalid {
                    self.hdrs.clear();
                }
                self.write_full(io, status, std::mem::take(&mut resp.body).into(), close);
                self.finish_response(io);
            }
            Msg::Dropped if matches!(self.resp, Resp::Waiting) => {
                self.hdrs.clear();
                self.write_full(io, 500, BodyRef::Static(b"Internal Server Error"), false);
                self.finish_response(io);
            }
            Msg::Stream(mut head, sink) if matches!(self.resp, Resp::Waiting) => {
                std::mem::swap(&mut self.hdrs, &mut head.headers);
                let status = if head.invalid || head.status < 200 { 500 } else { head.status };
                self.start_stream(io, status, head.close, sink);
            }
            Msg::Stream(_, sink) => sink.close(),
            Msg::Chunk(data) => self.chunk(io, data),
            Msg::End { abort } => self.end_stream(io, abort),
            Msg::BodyResume => {
                if let Some(b) = self.body.as_mut() {
                    if b.full {
                        b.started += io.now.saturating_sub(b.paused_at);
                    }
                    b.full = false;
                    if b.dec.is_done() {
                        self.body_input(io, &[]);
                    }
                }
            }
            _ => {}
        }
    }

    fn drain(&mut self, _io: &mut Io<'_, '_>) {
        if let Resp::Streaming(s) = &mut self.resp {
            s.sink.credit(std::mem::take(&mut s.unacked));
        }
    }

    fn eof(&mut self, io: &mut Io<'_, '_>) {
        if self.reading_body {
            if let Some(src) = self.body.as_ref().and_then(|b| b.src.as_ref()) {
                src.fail("the client closed the connection inside the body");
            }
            self.done = true;
            io.close = true;
            return;
        }
        if self.idle() {
            self.done = true;
            io.close = true;
        } else {
            self.close_after = true;
        }
    }

    fn stop(&mut self, io: &mut Io<'_, '_>) {
        self.stopping = true;
        if self.idle() {
            self.done = true;
            io.close = true;
        }
    }

    fn tick(&mut self, io: &mut Io<'_, '_>) {
        let now = io.now;
        let l = &io.sh.limits;
        if self.head_started != 0 && now >= self.head_started + l.head_timeout.as_nanos() as u64 {
            self.fail(io, 408);
            return;
        }
        if let Some(b) = self.body.as_ref() {
            let el = now.saturating_sub(b.started);
            if l.min_body_rate > 0 && !b.full && el > l.body_rate_grace.as_nanos() as u64 && (b.bytes as u128) * 1_000_000_000 < u128::from(l.min_body_rate) * el as u128 {
                if let Some(src) = &b.src {
                    src.fail("the request body arrived too slowly");
                }
                self.reading_body = false;
                self.fail(io, 408);
                return;
            }
        }
        if self.idle() && self.head_started == 0 && now >= self.idle_since + l.keep_alive_timeout.as_nanos() as u64 {
            self.done = true;
            io.close = true;
        }
    }

    fn deadline(&self, now: u64, sh: &Shared) -> u64 {
        let l = &sh.limits;
        let mut d = u64::MAX;
        if self.head_started != 0 {
            d = d.min(self.head_started.saturating_add(l.head_timeout.as_nanos() as u64));
        }
        if let Some(b) = self.body.as_ref() {
            if l.min_body_rate > 0 && !b.full {
                let grace = b.started.saturating_add(l.body_rate_grace.as_nanos() as u64);
                d = d.min(if grace > now { grace } else { now + 1_000_000_000 });
            }
        }
        if self.idle() && self.head_started == 0 {
            d = d.min(self.idle_since.saturating_add(l.keep_alive_timeout.as_nanos() as u64));
        }
        d
    }

    fn wants_pause(&self) -> bool {
        self.done || (!matches!(self.resp, Resp::Idle) && !self.reading_body) || self.body.as_ref().is_some_and(|b| b.full)
    }

    fn take_switch(&mut self) -> Option<Box<dyn Layer>> {
        self.switch.take()
    }

    fn closed(&mut self) {
        if let Resp::Streaming(s) = &self.resp {
            s.sink.close();
        }
        if let Some(src) = self.body.as_ref().and_then(|b| b.src.as_ref()) {
            src.fail("the connection closed");
        }
    }
}

struct H1Target<'h, 'a, 'c> {
    h: &'h mut H1,
    io: &'h mut Io<'a, 'c>,
    state: TState,
    #[cfg(feature = "websocket")]
    ws: Option<simoom_http1::ws::Handshake<'h>>,
}

impl Target for H1Target<'_, '_, '_> {
    fn headers(&mut self) -> &mut HeaderBuf {
        &mut self.h.hdrs
    }

    fn respond(&mut self, status: u16, body: BodyRef<'_>, close: bool) {
        self.h.write_full(self.io, status, body, close);
        self.state = TState::Responded;
    }

    fn fixed(&mut self, r: &StaticReply, close: bool) {
        self.h.write_fixed(self.io, r, close);
        self.state = TState::Responded;
    }

    fn defer(&mut self) -> Responder {
        self.h.resp = Resp::Waiting;
        self.state = TState::Deferred;
        Responder::new(Route::Conn(self.io.cx.handle()), 0, self.h.seq, self.io.sh.limits.stream_buffer)
    }

    fn undefer(&mut self) {
        self.h.resp = Resp::Idle;
        self.state = TState::None;
    }

    fn stream(&mut self, status: u16, close: bool) -> BodySink {
        let sink = Arc::new(SinkShared::new(self.io.sh.limits.stream_buffer));
        self.h.start_stream(self.io, status, close, sink.clone());
        self.state = TState::Streaming;
        BodySink::new(Route::Conn(self.io.cx.handle()), 0, self.h.seq, sink)
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

    #[cfg(feature = "websocket")]
    fn websocket(&mut self, protocol: Option<&[u8]>, handler: Box<dyn crate::ws::WebSocketHandler>) -> bool {
        let Some(hs) = self.ws.take() else { return false };
        if self.h.reading_body {
            return false;
        }
        let protocol = protocol.filter(|p| hs.protocols.is_some_and(|offered| offered.split(|&b| b == b',').any(|o| o.trim_ascii() == *p)));
        let mut out = Vec::with_capacity(160);
        if simoom_http1::ws::write_accept(&mut out, &hs, protocol).is_err() {
            return false;
        }
        self.io.write(&out);
        bump(&self.io.sh.counters(self.io.li).upgrades);
        self.h.switch = Some(Box::new(crate::ws::WsLayer::new(handler, self.io.sh.limits.max_ws_message)));
        self.h.done = true;
        self.state = TState::Upgraded;
        true
    }
}
