//! HTTP/1.1 over a [`Duplex`]: request heads and bodies out, response heads and bodies in.

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::transport::{is_timeout, Duplex};
use crate::types::{Body, Headers, Version};
use simoom_http1::{BodyDecoder, BodyEvent, Framing, Status, EMPTY_HEADER};
use std::io::{self, Read};
use std::time::{Duration, Instant};

/// Parser limits used for responses: Camel's default 256 MiB body cap is applied by the client,
/// not the decoder.
pub(crate) fn limits(max_head: usize) -> simoom_http1::Limits {
    simoom_http1::Limits { max_head, max_request_line: max_head.min(64 * 1024), max_header_line: max_head.min(64 * 1024), max_headers: 256, max_body: u64::MAX, ..simoom_http1::Limits::default() }
}

/// A response head.
#[derive(Debug)]
pub(crate) struct Head {
    pub status: u16,
    pub version: Version,
    pub reason: std::borrow::Cow<'static, str>,
    pub headers: Headers,
    pub framing: Framing,
    pub keep_alive: bool,
    pub upgraded: bool,
}

/// What a request needs to know about the connection's position.
pub(crate) struct Out<'a> {
    pub method: &'a str,
    /// The target (origin form, or absolute form with `absolute`); `Host` comes from it too.
    pub url: &'a crate::url::Url,
    pub absolute: bool,
    pub headers: &'a Headers,
    /// Client defaults sent when `headers` has no field of that name (`User-Agent`,
    /// `Accept-Encoding`, `Authorization` from the URL).
    pub extra: &'a [(&'a str, &'a [u8])],
    pub proxy_auth: Option<&'a str>,
    pub expect_continue: bool,
    pub expect_timeout: Duration,
    /// The idle read timeout, used while waiting for the head when there is no head deadline.
    pub idle: Option<Duration>,
    /// Send `Connection: close` (no pooling).
    pub close: bool,
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn put_field(out: &mut Vec<u8>, n: &[u8], v: &[u8]) -> std::result::Result<(), ()> {
    if n.is_empty() || !n.iter().all(|&b| is_tchar(b)) || v.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(());
    }
    out.extend_from_slice(n);
    out.extend_from_slice(b": ");
    out.extend_from_slice(v);
    out.extend_from_slice(b"\r\n");
    Ok(())
}

fn put_dec(out: &mut Vec<u8>, mut n: u64) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&d[i..]);
}

/// `host[:port]` (IPv6 in brackets, the port only when it is not the scheme's default).
pub(crate) fn put_host(out: &mut Vec<u8>, u: &crate::url::Url) {
    let v6 = u.host.contains(':');
    if v6 {
        out.push(b'[');
    }
    out.extend_from_slice(u.host.as_bytes());
    if v6 {
        out.push(b']');
    }
    if u.port != crate::url::default_port(&u.scheme) {
        out.push(b':');
        put_dec(out, u64::from(u.port));
    }
}

/// Where decoded body bytes go.
enum Sink<'a> {
    Slice(&'a mut [u8]),
    Vec(&'a mut Vec<u8>),
}

impl Sink<'_> {
    /// Copies as much of `d` as fits; returns how much.
    fn put(&mut self, d: &[u8]) -> usize {
        match self {
            Sink::Slice(o) => {
                let n = d.len().min(o.len());
                o[..n].copy_from_slice(&d[..n]);
                n
            }
            Sink::Vec(v) => {
                v.extend_from_slice(d);
                d.len()
            }
        }
    }
}

/// One HTTP/1.1 connection.
pub(crate) struct H1Conn {
    pub io: Duplex,
    /// Request head buffer, reused.
    wbuf: Vec<u8>,
    /// Receive buffer: initialized once to its capacity (no zeroing per read); `buf[..len]` is
    /// what arrived.
    buf: Vec<u8>,
    len: usize,
    pos: usize,
    /// Decoded body bytes waiting in `buf[pending.0..pending.1]`.
    pending: (usize, usize),
    pub requests: u32,
    pub idle_since: Instant,
    pub reusable: bool,
    /// Plain-HTTP requests through a proxy use the absolute form.
    pub absolute: bool,
    max_head: usize,
    /// Idle read timeout for the head when no head deadline applies.
    pub idle: Option<Duration>,
    /// Set once any byte of the current response arrived (a reused connection that fails
    /// before that may be retried).
    pub got_bytes: bool,
}

impl std::fmt::Debug for H1Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H1Conn").field("io", &self.io).field("requests", &self.requests).finish()
    }
}

fn map_read(e: io::Error, kind: TimeoutKind, what: &dyn std::fmt::Display) -> Error {
    if is_timeout(&e) {
        Error::timeout(kind, what)
    } else if e.kind() == io::ErrorKind::InvalidData {
        Error::new(ErrorKind::Tls, format!("{e}: {what}"))
    } else {
        Error::io(&e, what)
    }
}

impl H1Conn {
    pub(crate) fn new(io: Duplex, absolute: bool, max_head: usize) -> H1Conn {
        let now = Instant::now();
        H1Conn { io, wbuf: Vec::new(), buf: Vec::new(), len: 0, pos: 0, pending: (0, 0), requests: 0, idle_since: now, reusable: true, absolute, max_head, idle: None, got_bytes: false }
    }

    /// Reads more bytes into the buffer; false at end of stream.
    fn fill(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        if self.pos > 0 && self.pos == self.len && self.pending.0 == self.pending.1 {
            self.len = 0;
            self.pos = 0;
            self.pending = (0, 0);
        } else if self.pos > 0 && self.pending.0 == self.pending.1 && self.buf.len() - self.len < 4096 {
            self.buf.copy_within(self.pos..self.len, 0);
            self.len -= self.pos;
            self.pos = 0;
            self.pending = (0, 0);
        }
        if self.buf.len() - self.len < 4096 {
            let grow = self.buf.len().max(16 * 1024);
            self.buf.resize(self.buf.len() + grow, 0);
        }
        let start = self.len;
        let n = self.io.read(&mut self.buf[start..], timeout)?;
        self.len += n;
        if n > 0 {
            self.got_bytes = true;
        }
        Ok(n > 0)
    }

    /// Serializes the request head (and a small in-memory body) into `out`.
    /// Writes the request head straight into `out` (no intermediate strings); field names and
    /// values are validated, so a value cannot split the request.
    pub(crate) fn write_head(o: &Out<'_>, body: &Body, out: &mut Vec<u8>) -> Result<()> {
        let inval = |what: &str| Error::new(ErrorKind::InvalidRequest, format!("invalid request ({what}): {} {}", o.method, o.url));
        let m = o.method.as_bytes();
        if m.is_empty() || !m.iter().all(|&b| is_tchar(b)) {
            return Err(inval("method"));
        }
        out.extend_from_slice(m);
        out.push(b' ');
        let u = o.url;
        if o.absolute {
            out.extend_from_slice(u.scheme.as_bytes());
            out.extend_from_slice(b"://");
            put_host(out, u);
        }
        out.extend_from_slice(u.path.as_bytes());
        if let Some(q) = u.query.as_deref().filter(|q| !q.is_empty()) {
            out.push(b'?');
            out.extend_from_slice(q.as_bytes());
        }
        out.extend_from_slice(b" HTTP/1.1\r\n");
        let mut has_host = false;
        for (n, v) in o.headers.iter() {
            if n.eq_ignore_ascii_case("content-length") || n.eq_ignore_ascii_case("transfer-encoding") || (o.close && n.eq_ignore_ascii_case("connection")) {
                continue;
            }
            if o.expect_continue && n.eq_ignore_ascii_case("expect") {
                continue;
            }
            has_host |= n.eq_ignore_ascii_case("host");
            put_field(out, n.as_bytes(), v).map_err(|_| inval("header field"))?;
        }
        if !has_host {
            out.extend_from_slice(b"Host: ");
            put_host(out, u);
            out.extend_from_slice(b"\r\n");
        }
        for (n, v) in o.extra {
            if !o.headers.contains(n) {
                put_field(out, n.as_bytes(), v).map_err(|_| inval("header field"))?;
            }
        }
        if let Some(a) = o.proxy_auth {
            if !o.headers.contains("proxy-authorization") {
                put_field(out, b"Proxy-Authorization", a.as_bytes()).map_err(|_| inval("proxy credentials"))?;
            }
        }
        match body.known_len() {
            Some(0) if !matches!(o.method, "POST" | "PUT" | "PATCH") => {}
            Some(n) => {
                out.extend_from_slice(b"Content-Length: ");
                put_dec(out, n);
                out.extend_from_slice(b"\r\n");
            }
            None => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
        }
        if o.expect_continue && !body.is_empty() {
            out.extend_from_slice(b"Expect: 100-continue\r\n");
        }
        if o.close {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Ok(())
    }

    /// Sends a request and reads the response head. The body is then read with
    /// [`H1Conn::read_body`].
    pub(crate) fn exchange(&mut self, o: &Out<'_>, body: &mut Body, head_deadline: Option<Instant>, what: &dyn std::fmt::Display) -> Result<Head> {
        self.requests += 1;
        self.got_bytes = false;
        self.idle = o.idle;
        if o.close {
            self.reusable = false;
        }
        // the head buffer is kept with the connection and reused
        let mut out = std::mem::take(&mut self.wbuf);
        out.clear();
        Self::write_head(o, body, &mut out)?;
        let expect = o.expect_continue && !body.is_empty();
        let werr = |e: io::Error| map_read(e, TimeoutKind::Idle, what);
        if expect {
            self.io.write_all(&out).map_err(werr)?;
            let wait = Instant::now() + o.expect_timeout;
            let d = Some(head_deadline.map_or(wait, |h| h.min(wait)));
            match self.read_head_until(o.method, d, true, what) {
                Ok(Some(h)) => {
                    // A final answer before the body: the body is not sent; the connection
                    // cannot be reused (the server may still expect it).
                    self.reusable = false;
                    return Ok(h);
                }
                Ok(None) => {}
                Err(e) if e.kind == ErrorKind::Timeout(TimeoutKind::ResponseHead) && head_deadline.is_none_or(|h| Instant::now() < h) => {}
                Err(e) => return Err(e),
            }
            out.clear();
        }
        let sent = match body {
            Body::Empty => self.io.write_all(&out),
            Body::Bytes(b) => {
                if b.len() <= 16 * 1024 {
                    out.extend_from_slice(b);
                    self.io.write_all(&out)
                } else {
                    self.io.write_all(&out).and_then(|_| self.io.write_all(b))
                }
            }
            Body::Reader { reader, len } => {
                let len = *len;
                self.write_stream(&mut out, reader.as_mut(), len)
            }
        };
        if self.wbuf.capacity() == 0 && out.capacity() <= 64 * 1024 {
            self.wbuf = std::mem::take(&mut out);
        }
        if let Err(e) = sent {
            // The server may have answered early (413, 401) and closed: read that answer.
            if !out.is_empty() || self.requests > 0 {
                let d = Some(Instant::now() + Duration::from_millis(500));
                if let Ok(Some(h)) = self.read_head_until(o.method, d, false, what) {
                    self.reusable = false;
                    return Ok(h);
                }
            }
            return Err(werr(e));
        }
        match self.read_head_until(o.method, head_deadline, false, what)? {
            Some(h) => Ok(h),
            None => Err(Error::protocol("unexpected 100 Continue", what)),
        }
    }

    fn write_stream(&mut self, out: &mut Vec<u8>, r: &mut dyn Read, len: Option<u64>) -> io::Result<()> {
        let mut chunk = vec![0u8; 16 * 1024];
        let mut sent = 0u64;
        loop {
            let n = match r.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("reading the request body: {e}"))),
            };
            if n == 0 {
                break;
            }
            match len {
                Some(l) => {
                    if sent + n as u64 > l {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "request body longer than its length"));
                    }
                    out.extend_from_slice(&chunk[..n]);
                }
                None => simoom_http1::write::write_chunk(out, &chunk[..n]),
            }
            sent += n as u64;
            self.io.write_all(out)?;
            out.clear();
        }
        match len {
            Some(l) if sent != l => return Err(io::Error::new(io::ErrorKind::InvalidInput, "request body shorter than its length")),
            Some(_) => {}
            None => out.extend_from_slice(simoom_http1::write::LAST_CHUNK),
        }
        if !out.is_empty() {
            self.io.write_all(out)?;
            out.clear();
        }
        Ok(())
    }

    /// Reads the next response head (1xx skipped).
    #[cfg(feature = "pipeline")]
    pub(crate) fn read_head(&mut self, method: &str, deadline: Option<Instant>, what: &dyn std::fmt::Display) -> Result<Head> {
        self.got_bytes = false;
        match self.read_head_until(method, deadline, false, what)? {
            Some(h) => Ok(h),
            None => Err(Error::protocol("unexpected 100 Continue", what)),
        }
    }

    /// Reads response heads. With `stop_at_continue`, returns `None` on `100 Continue`. Other
    /// 1xx heads are skipped; `101` is returned (an upgrade).
    fn read_head_until(&mut self, method: &str, deadline: Option<Instant>, stop_at_continue: bool, what: &dyn std::fmt::Display) -> Result<Option<Head>> {
        let lim = limits(self.max_head);
        loop {
            if self.pos < self.len {
                let mut hs = [EMPTY_HEADER; 128];
                let parsed = simoom_http1::parse_response(&self.buf[self.pos..self.len], &mut hs, &lim, method.as_bytes());
                match parsed {
                    Ok(Status::Complete(r)) => {
                        let hl = r.head_len;
                        if r.status / 100 == 1 && r.status != 101 {
                            let cont = r.status == 100;
                            self.pos += hl;
                            if cont && stop_at_continue {
                                return Ok(None);
                            }
                            continue;
                        }
                        let mut headers = Headers::with_capacity(r.headers.len(), hl);
                        for h in r.headers {
                            headers.push_raw(h.name, h.value);
                        }
                        let head = Head {
                            status: r.status,
                            version: if r.version == simoom_http1::Version::Http10 { Version::Http10 } else { Version::Http11 },
                            // the standard phrase is borrowed, not allocated
                            reason: {
                                let std = simoom_http1::write::reason(r.status);
                                if r.reason == std.as_bytes() {
                                    std::borrow::Cow::Borrowed(std)
                                } else {
                                    std::borrow::Cow::Owned(String::from_utf8_lossy(r.reason).into_owned())
                                }
                            },
                            headers,
                            framing: r.framing,
                            keep_alive: r.keep_alive,
                            upgraded: r.upgraded,
                        };
                        self.pos += hl;
                        if !head.keep_alive {
                            self.reusable = false;
                        }
                        return Ok(Some(head));
                    }
                    Ok(Status::Partial) => {}
                    Err(e) => {
                        self.reusable = false;
                        return Err(Error::protocol(format!("invalid response head ({e})"), what));
                    }
                }
            }
            let t = match crate::transport::remaining(deadline, TimeoutKind::ResponseHead, what)? {
                Some(r) => Some(self.idle.map_or(r, |i| i.min(r))),
                None => self.idle,
            };
            match self.fill(t) {
                Ok(true) => {}
                Ok(false) => {
                    self.reusable = false;
                    return Err(Error::new(ErrorKind::Closed, format!("connection closed before the response head: {what}")));
                }
                Err(e) => {
                    self.reusable = false;
                    return Err(map_read(e, TimeoutKind::ResponseHead, what));
                }
            }
        }
    }

    /// Reads decoded body bytes. `Ok(0)` with `trailers` filled means the body is complete.
    pub(crate) fn read_body(&mut self, dec: &mut BodyDecoder, out: &mut [u8], trailers: &mut Option<Headers>, idle: Option<Duration>, deadline: Option<Instant>, what: &dyn std::fmt::Display) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        self.read_body_to(dec, Sink::Slice(out), trailers, idle, deadline, what)
    }

    /// Like [`H1Conn::read_body`], appending whole decoded pieces to `out` (no bounce buffer).
    pub(crate) fn read_body_vec(&mut self, dec: &mut BodyDecoder, out: &mut Vec<u8>, trailers: &mut Option<Headers>, idle: Option<Duration>, deadline: Option<Instant>, what: &dyn std::fmt::Display) -> Result<usize> {
        self.read_body_to(dec, Sink::Vec(out), trailers, idle, deadline, what)
    }

    fn read_body_to(&mut self, dec: &mut BodyDecoder, mut out: Sink<'_>, trailers: &mut Option<Headers>, idle: Option<Duration>, deadline: Option<Instant>, what: &dyn std::fmt::Display) -> Result<usize> {
        loop {
            if self.pending.0 < self.pending.1 {
                let (a, b) = self.pending;
                let n = out.put(&self.buf[a..b]);
                self.pending.0 += n;
                return Ok(n);
            }
            if dec.is_done() {
                if trailers.is_none() {
                    *trailers = Some(Headers::new());
                }
                return Ok(0);
            }
            if self.pos < self.len {
                let start = self.pos;
                let r = dec.decode(&self.buf[start..self.len]);
                match r {
                    Ok((used, BodyEvent::Data(d))) => {
                        let off = d.as_ptr() as usize - self.buf[start..].as_ptr() as usize + start;
                        let dl = d.len();
                        self.pos = start + used;
                        let n = out.put(&self.buf[off..off + dl]);
                        self.pending = (off + n, off + dl);
                        return Ok(n);
                    }
                    Ok((used, BodyEvent::End(section))) => {
                        let mut t = Headers::new();
                        if !section.is_empty() {
                            let mut hs = [EMPTY_HEADER; 64];
                            let parsed = simoom_http1::parse_trailers(section, &mut hs, &limits(self.max_head));
                            match parsed {
                                Ok(list) => {
                                    for h in list {
                                        t.push_raw(h.name, h.value);
                                    }
                                }
                                Err(e) => {
                                    self.reusable = false;
                                    return Err(Error::protocol(format!("invalid trailers ({e})"), what));
                                }
                            }
                        }
                        self.pos = start + used;
                        *trailers = Some(t);
                        return Ok(0);
                    }
                    Ok((used, BodyEvent::NeedMore)) => {
                        self.pos = start + used;
                    }
                    Err(e) => {
                        self.reusable = false;
                        return Err(Error::protocol(format!("invalid response body ({e})"), what));
                    }
                }
            }
            let t = match crate::transport::remaining(deadline, TimeoutKind::Total, what)? {
                Some(r) => Some(idle.map_or(r, |i| i.min(r))),
                None => idle,
            };
            match self.fill(t) {
                Ok(true) => {}
                Ok(false) => {
                    self.reusable = false;
                    match dec.eof() {
                        Ok(()) => {
                            *trailers = Some(Headers::new());
                            return Ok(0);
                        }
                        Err(_) => return Err(Error::new(ErrorKind::Closed, format!("connection closed inside the response body: {what}"))),
                    }
                }
                Err(e) => {
                    self.reusable = false;
                    let kind = if deadline.is_some_and(|d| Instant::now() >= d) { TimeoutKind::Total } else { TimeoutKind::Idle };
                    return Err(map_read(e, kind, what));
                }
            }
        }
    }

    /// Consumes the rest of a body if it is already buffered; true when the body is complete.
    pub(crate) fn drain_buffered(&mut self, dec: &mut BodyDecoder) -> bool {
        self.pending.0 = self.pending.1;
        loop {
            if dec.is_done() {
                return true;
            }
            if self.pos >= self.len {
                return false;
            }
            let start = self.pos;
            match dec.decode(&self.buf[start..self.len]) {
                Ok((used, BodyEvent::Data(_))) => self.pos = start + used,
                Ok((used, BodyEvent::End(_))) => {
                    self.pos = start + used;
                    return true;
                }
                Ok((used, BodyEvent::NeedMore)) => {
                    self.pos = start + used;
                    if used == 0 {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    /// Bytes received after the response head that belong to the upgraded protocol.
    #[cfg(any(feature = "client-ws", feature = "h2c-upgrade"))]
    pub(crate) fn take_leftover(&mut self) -> Vec<u8> {
        let v = self.buf[self.pos..self.len].to_vec();
        self.pos = self.len;
        v
    }

    /// Whether unread bytes remain buffered (the connection cannot be reused for a new request
    /// if a response sent more than its framing allowed).
    pub(crate) fn has_buffered(&self) -> bool {
        self.pos < self.len || self.pending.0 < self.pending.1
    }
}
