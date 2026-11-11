//! Responses and streamed response bodies.

use crate::error::{Error, ErrorKind, Result, StatusError};
#[cfg(any(feature = "client-h2", feature = "client-h3"))]
use crate::error::TimeoutKind;
use crate::h1::H1Conn;
use crate::pool::Slot;
use crate::types::{Headers, Version};
use crate::url::Url;
use simoom_http1::BodyDecoder;
use std::io::{self, Read};
use std::time::{Duration, Instant};

#[cfg(any(feature = "client-h2", feature = "client-h3"))]
use crate::mux::Mux;
use std::sync::Arc;

pub(crate) struct H1Body {
    pub conn: Option<H1Conn>,
    pub slot: Option<Slot>,
    pub dec: BodyDecoder,
    pub idle: Option<Duration>,
    pub deadline: Option<Instant>,
    pub what: Arc<Url>,
    pub len_hint: Option<u64>,
}

impl H1Body {
    /// The body length when the response said (Content-Length).
    fn dec_len_hint(&self) -> Option<u64> {
        self.len_hint
    }

    fn finish(&mut self) {
        if let (Some(c), Some(s)) = (self.conn.take(), self.slot.take()) {
            if c.reusable && !c.has_buffered() {
                s.put_back(c);
            } else {
                c.io.close();
            }
        }
    }
}

impl Drop for H1Body {
    fn drop(&mut self) {
        // A body that was not read to the end: if the rest is already buffered, consume it
        // and keep the connection; otherwise close it.
        if let Some(c) = self.conn.as_mut() {
            if !c.drain_buffered(&mut self.dec) {
                c.reusable = false;
            }
        }
        self.finish();
    }
}

#[cfg(any(feature = "client-h2", feature = "client-h3"))]
pub(crate) struct MuxBody {
    pub mux: Arc<Mux>,
    pub id: u64,
    pub idle: Option<Duration>,
    pub deadline: Option<Instant>,
    pub done: bool,
}

#[cfg(any(feature = "client-h2", feature = "client-h3"))]
impl Drop for MuxBody {
    fn drop(&mut self) {
        self.mux.finish(self.id);
    }
}

pub(crate) enum Inner {
    Empty,
    Bytes(Vec<u8>, usize),
    H1(Box<H1Body>),
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    Mux(Box<MuxBody>),
    #[cfg(feature = "compress")]
    Decoded(Box<dyn Read + Send>),
}

/// A response body, read as it arrives (backpressure: nothing more is read from the network
/// than the reader asks for, within the flow-control windows). Implements [`Read`].
///
/// Read to the end, an HTTP/1.1 connection goes back to the pool; dropped earlier, it is closed
/// (unless the rest was already buffered), and an HTTP/2 or HTTP/3 stream is cancelled.
pub struct ResponseBody {
    pub(crate) inner: Inner,
    trailers: Option<Headers>,
    read: u64,
    limit: Option<u64>,
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseBody").field("read", &self.read).finish()
    }
}

impl ResponseBody {
    pub(crate) fn new(inner: Inner, limit: Option<u64>) -> ResponseBody {
        ResponseBody { inner, trailers: None, read: 0, limit }
    }

    pub(crate) fn empty() -> ResponseBody {
        ResponseBody::new(Inner::Empty, None)
    }

    #[cfg(feature = "pipeline")]
    pub(crate) fn set_trailers(&mut self, t: Option<Headers>) {
        self.trailers = t;
    }

    /// Trailers, once the body has been read to the end (empty when there were none).
    pub fn trailers(&self) -> Option<&Headers> {
        self.trailers.as_ref()
    }

    /// Bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    /// Reads, with errors as [`Error`].
    pub fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = match &mut self.inner {
            Inner::Empty => {
                self.trailers.get_or_insert_with(Headers::new);
                0
            }
            Inner::Bytes(b, pos) => {
                let n = (b.len() - *pos).min(buf.len());
                buf[..n].copy_from_slice(&b[*pos..*pos + n]);
                *pos += n;
                if n == 0 {
                    self.trailers.get_or_insert_with(Headers::new);
                }
                n
            }
            Inner::H1(h) => {
                let Some(c) = h.conn.as_mut() else {
                    self.trailers.get_or_insert_with(Headers::new);
                    return Ok(0);
                };
                let n = c.read_body(&mut h.dec, buf, &mut self.trailers, h.idle, h.deadline, &*h.what)?;
                if n == 0 && self.trailers.is_some() {
                    h.finish();
                }
                n
            }
            #[cfg(any(feature = "client-h2", feature = "client-h3"))]
            Inner::Mux(m) => {
                if m.done {
                    return Ok(0);
                }
                let d = match (m.idle, m.deadline) {
                    (Some(i), Some(d)) => Some((Instant::now() + i).min(d)),
                    (Some(i), None) => Some(Instant::now() + i),
                    (None, d) => d,
                };
                let kind = if m.deadline.is_some() && d == m.deadline { TimeoutKind::Total } else { TimeoutKind::Idle };
                let (n, t) = m.mux.read(m.id, buf, d, kind)?;
                if let Some(t) = t {
                    m.done = true;
                    self.trailers = Some(t);
                }
                n
            }
            #[cfg(feature = "compress")]
            Inner::Decoded(r) => r.read(buf).map_err(|e| Error::new(ErrorKind::Decode, format!("decoding the response body: {e}")))?,
        };
        self.read += n as u64;
        if let Some(l) = self.limit {
            if self.read > l {
                return Err(Error::new(ErrorKind::Protocol, format!("response body larger than the limit of {l} bytes")));
            }
        }
        Ok(n)
    }

    /// Reads the rest into a vector.
    pub fn read_all(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        if let Inner::Bytes(b, pos) = &mut self.inner {
            if *pos == 0 {
                let v = std::mem::take(b);
                self.read += v.len() as u64;
                self.trailers = Some(Headers::new());
                return Ok(v);
            }
        }
        if let Inner::H1(h) = &mut self.inner {
            // decoded pieces go straight into `out`
            if let Some(l) = h.dec_len_hint() {
                out.reserve(l.min(16 << 20) as usize);
            }
            loop {
                let Some(c) = h.conn.as_mut() else { return Ok(out) };
                let n = c.read_body_vec(&mut h.dec, &mut out, &mut self.trailers, h.idle, h.deadline, &*h.what)?;
                self.read += n as u64;
                if let Some(l) = self.limit {
                    if self.read > l {
                        return Err(Error::new(ErrorKind::Protocol, format!("response body larger than the limit of {l} bytes")));
                    }
                }
                if n == 0 && self.trailers.is_some() {
                    h.finish();
                    return Ok(out);
                }
            }
        }
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = self.read_chunk(&mut buf)?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
}

impl Read for ResponseBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_chunk(buf).map_err(io::Error::from)
    }
}

/// A response: status, headers, and a body that is read on demand.
#[derive(Debug)]
pub struct Response {
    pub(crate) status: u16,
    pub(crate) version: Version,
    pub(crate) reason: std::borrow::Cow<'static, str>,
    pub(crate) headers: Headers,
    pub(crate) url: Arc<Url>,
    pub(crate) body: ResponseBody,
}

impl Response {
    /// The status code (Camel's `CamelHttpResponseCode`).
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The reason phrase (Camel's `CamelHttpResponseText`); the standard phrase on HTTP/2 and
    /// HTTP/3, which carry none.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The protocol version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Response headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The first value of a header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    /// The final URL (after redirects).
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// `Content-Length`, when present.
    pub fn content_length(&self) -> Option<u64> {
        self.headers.get("content-length").and_then(|v| v.trim().parse().ok())
    }

    /// The body, for streaming reads.
    pub fn body_mut(&mut self) -> &mut ResponseBody {
        &mut self.body
    }

    /// Consumes the response and returns the body reader.
    pub fn into_body(self) -> ResponseBody {
        self.body
    }

    /// Reads the whole body.
    pub fn bytes(mut self) -> Result<Vec<u8>> {
        self.body.read_all()
    }

    /// Reads the whole body as text (invalid UTF-8 is replaced).
    pub fn text(self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.bytes()?).into_owned())
    }

    /// Reads the whole body and keeps it in the response; returns the body and the trailers.
    pub fn buffer(&mut self) -> Result<&[u8]> {
        let v = self.body.read_all()?;
        let t = self.body.trailers.take();
        self.body = ResponseBody::new(Inner::Bytes(v, 0), None);
        self.body.trailers = t;
        match &self.body.inner {
            Inner::Bytes(b, _) => Ok(b),
            _ => unreachable!(),
        }
    }

    /// Trailers, once the body was read to the end.
    pub fn trailers(&self) -> Option<&Headers> {
        self.body.trailers()
    }

    /// An error when the status is outside `ranges` (Camel's `throwExceptionOnFailure` with
    /// `okStatusCodeRange`); the body is read into the error.
    pub fn error_for_status(self, ranges: &[(u16, u16)]) -> Result<Response> {
        if ranges.iter().any(|(a, b)| (*a..=*b).contains(&self.status)) {
            return Ok(self);
        }
        Err(self.into_status_error())
    }

    pub(crate) fn into_status_error(mut self) -> Error {
        let body = self.body.read_all().unwrap_or_default();
        let location = self.headers.get("location").map(str::to_string);
        let uri = self.url.to_string();
        let mut message = format!("HTTP operation failed invoking {uri} with statusCode: {}", self.status);
        if let Some(l) = &location {
            message.push_str(&format!(", redirectLocation: {l}"));
        }
        let se = StatusError { uri, status: self.status, status_text: self.reason.to_string(), location, body, headers: self.headers.to_strings() };
        Error::new(ErrorKind::Status(Box::new(se)), message)
    }
}

/// The standard reason phrase of a status.
#[cfg(any(feature = "client-h2", feature = "client-h3"))]
pub(crate) fn reason_of(status: u16) -> std::borrow::Cow<'static, str> {
    std::borrow::Cow::Borrowed(simoom_http1::write::reason(status))
}
