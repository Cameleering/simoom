//! Requests, header lists and bodies.

use crate::url::Url;
use std::io::Read;
use std::time::Duration;

/// An ordered list of header fields. Names keep their case; lookups ignore it. Values are
/// bytes (HTTP allows obs-text); [`Headers::get`] returns them as text when they are UTF-8.
///
/// All names and values live in one buffer with an index beside it, so a parsed response head
/// costs two allocations whatever its number of fields.
#[derive(Clone, Default)]
pub struct Headers {
    buf: Vec<u8>,
    /// (start, name length, value length): the value follows the name in `buf`.
    idx: Vec<(u32, u32, u32)>,
}

impl PartialEq for Headers {
    fn eq(&self, o: &Headers) -> bool {
        self.len() == o.len() && self.iter().zip(o.iter()).all(|(a, b)| a == b)
    }
}

impl Eq for Headers {}

impl std::fmt::Debug for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter().map(|(n, v)| (n, String::from_utf8_lossy(v)))).finish()
    }
}

impl Headers {
    /// An empty list.
    pub fn new() -> Headers {
        Headers::default()
    }

    /// An empty list with room for `fields` fields of `bytes` bytes in all.
    pub fn with_capacity(fields: usize, bytes: usize) -> Headers {
        Headers { buf: Vec::with_capacity(bytes), idx: Vec::with_capacity(fields) }
    }

    #[inline]
    fn field(&self, e: (u32, u32, u32)) -> (&str, &[u8]) {
        let (s, n, v) = (e.0 as usize, e.1 as usize, e.2 as usize);
        // names come from `&str` or from a parser that allows only tchar (ASCII)
        (std::str::from_utf8(&self.buf[s..s + n]).unwrap_or(""), &self.buf[s + n..s + n + v])
    }

    /// The first value of `name`, as text.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.get_bytes(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Fields as raw bytes (no UTF-8 check), for lookups.
    #[inline]
    fn raw(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.idx.iter().map(move |&(s, n, v)| {
            let (s, n, v) = (s as usize, n as usize, v as usize);
            (&self.buf[s..s + n], &self.buf[s + n..s + n + v])
        })
    }

    /// The first value of `name`.
    pub fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        self.raw().find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes())).map(|(_, v)| v)
    }

    /// Every value of `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).filter_map(|(_, v)| std::str::from_utf8(v).ok())
    }

    /// Replaces every value of `name` with `value`.
    pub fn set(&mut self, name: impl AsRef<str>, value: impl AsRef<[u8]>) {
        let name = name.as_ref();
        self.remove(name);
        self.push_raw(name.as_bytes(), value.as_ref());
    }

    /// Adds a value, keeping existing ones.
    pub fn append(&mut self, name: impl AsRef<str>, value: impl AsRef<[u8]>) {
        self.push_raw(name.as_ref().as_bytes(), value.as_ref());
    }

    /// Removes every value of `name`; true if there was one.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.idx.len();
        let buf = &self.buf;
        self.idx.retain(|&(s, n, _)| !buf[s as usize..(s + n) as usize].eq_ignore_ascii_case(name.as_bytes()));
        if self.idx.is_empty() {
            self.buf.clear();
        }
        before != self.idx.len()
    }

    /// Whether `name` is present.
    pub fn contains(&self, name: &str) -> bool {
        self.raw().any(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
    }

    /// Whether a comma-separated value of `name` contains `token` (case-insensitive).
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.raw().filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes())).any(|(_, v)| simoom_http1::has_token(v, token.as_bytes()))
    }

    /// All fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.idx.iter().map(move |&e| self.field(e))
    }

    /// All fields as text (non-UTF-8 values are converted lossily).
    pub fn to_strings(&self) -> Vec<(String, String)> {
        self.iter().map(|(n, v)| (n.to_string(), String::from_utf8_lossy(v).into_owned())).collect()
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.idx.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }

    pub(crate) fn push_raw(&mut self, name: &[u8], value: &[u8]) {
        let s = self.buf.len() as u32;
        self.buf.extend_from_slice(name);
        self.buf.extend_from_slice(value);
        self.idx.push((s, name.len() as u32, value.len() as u32));
    }
}

impl<N: AsRef<str>, V: AsRef<[u8]>> FromIterator<(N, V)> for Headers {
    fn from_iter<I: IntoIterator<Item = (N, V)>>(iter: I) -> Headers {
        let mut h = Headers::new();
        for (n, v) in iter {
            h.append(n, v);
        }
        h
    }
}

/// Which HTTP version to use for a request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// `http`: HTTP/1.1. `https`: ALPN chooses HTTP/2 or HTTP/1.1 (HTTP/2 needs `client-h2`).
    /// With [`crate::ClientBuilder::alt_svc`], an origin that announced `h3` in `Alt-Svc` is
    /// then reached over HTTP/3.
    #[default]
    Auto,
    /// HTTP/1.1 only.
    Http1,
    /// HTTP/2 only: h2c with prior knowledge for `http`, ALPN `h2` for `https` (an error when
    /// the server does not choose it). Camel's `httpVersion=HTTP/2`.
    Http2,
    /// HTTP/3 only (`https` URLs).
    Http3,
}

/// The version a response arrived with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    Http2,
    /// HTTP/3
    Http3,
}

impl Version {
    /// `HTTP/1.1`, `HTTP/2`...
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
            Version::Http2 => "HTTP/2",
            Version::Http3 => "HTTP/3",
        }
    }
}

/// A request body.
pub enum Body {
    /// No body.
    Empty,
    /// Bytes in memory: sent with `Content-Length`, and replayable (redirects, retries).
    Bytes(Vec<u8>),
    /// A stream: sent with `Content-Length` when `len` is known, otherwise chunked on HTTP/1.1
    /// (plain DATA frames on HTTP/2 and HTTP/3). Read as the connection accepts data, so a slow
    /// server pushes back on the reader. Not replayable.
    Reader {
        /// The source.
        reader: Box<dyn Read + Send>,
        /// The exact length, when known.
        len: Option<u64>,
    },
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Empty => f.write_str("Empty"),
            Body::Bytes(b) => write!(f, "Bytes({})", b.len()),
            Body::Reader { len, .. } => write!(f, "Reader({len:?})"),
        }
    }
}

impl Body {
    /// A streamed body of unknown length.
    pub fn reader(r: impl Read + Send + 'static) -> Body {
        Body::Reader { reader: Box::new(r), len: None }
    }

    /// A streamed body of known length.
    pub fn sized_reader(r: impl Read + Send + 'static, len: u64) -> Body {
        Body::Reader { reader: Box::new(r), len: Some(len) }
    }

    /// True for [`Body::Empty`].
    pub fn is_empty(&self) -> bool {
        matches!(self, Body::Empty)
    }

    pub(crate) fn replayable(&self) -> bool {
        !matches!(self, Body::Reader { .. })
    }

    pub(crate) fn known_len(&self) -> Option<u64> {
        match self {
            Body::Empty => Some(0),
            Body::Bytes(b) => Some(b.len() as u64),
            Body::Reader { len, .. } => *len,
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Body {
        Body::Bytes(v)
    }
}

impl From<&[u8]> for Body {
    fn from(v: &[u8]) -> Body {
        Body::Bytes(v.to_vec())
    }
}

impl From<String> for Body {
    fn from(v: String) -> Body {
        Body::Bytes(v.into_bytes())
    }
}

impl From<&str> for Body {
    fn from(v: &str) -> Body {
        Body::Bytes(v.as_bytes().to_vec())
    }
}

/// A request. Build one with [`crate::Client::request`] or directly.
#[derive(Debug)]
pub struct Request {
    /// The method, upper case (`GET`, `POST`...).
    pub method: String,
    /// The target.
    pub url: Url,
    /// Request headers. `Host`, `Content-Length` and `Transfer-Encoding` are set by the client
    /// (a `Host` given here is kept: Camel's `customHostHeader` / `preserveHostHeader`).
    pub headers: Headers,
    /// The body.
    pub body: Body,
    /// Version override for this request.
    pub version: Option<HttpVersion>,
    /// Whole-request deadline override (redirects included).
    pub timeout: Option<Duration>,
    /// Response-head timeout override.
    pub response_timeout: Option<Duration>,
    /// Redirect override: follow (`Some(true)`) or not.
    pub follow_redirects: Option<bool>,
    /// Status ranges that are accepted; any other status becomes an
    /// [`ErrorKind::Status`](crate::ErrorKind::Status) error (Camel's `throwExceptionOnFailure`
    /// with `okStatusCodeRange`). `None` accepts every status.
    pub ok_status: Option<Vec<(u16, u16)>>,
    /// Send `Expect: 100-continue` and wait for the server's go-ahead before the body
    /// (HTTP/1.1, bodies only).
    pub expect_continue: bool,
}

impl Request {
    /// A request without body or headers.
    pub fn new(method: &str, url: Url) -> Request {
        Request {
            method: method.to_ascii_uppercase(),
            url,
            headers: Headers::new(),
            body: Body::Empty,
            version: None,
            timeout: None,
            response_timeout: None,
            follow_redirects: None,
            ok_status: None,
            expect_continue: false,
        }
    }
}

/// Parses Camel's `okStatusCodeRange` (`200-299`, `200-204,209,301-304`).
pub fn parse_status_ranges(s: &str) -> Option<Vec<(u16, u16)>> {
    s.split(',')
        .map(|r| {
            let r = r.trim();
            let (a, b) = r.split_once('-').unwrap_or((r, r));
            Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_ranges() {
        let mut h: Headers = [("Content-Type", "a"), ("X", "1"), ("x", "2")].into_iter().collect();
        assert_eq!(h.get("content-type"), Some("a"));
        assert_eq!(h.get_all("X").collect::<Vec<_>>(), vec!["1", "2"]);
        h.set("x", "3");
        assert_eq!(h.get_all("X").collect::<Vec<_>>(), vec!["3"]);
        assert!(h.remove("CONTENT-TYPE") && !h.contains("content-type"));
        h.set("Connection", "keep-alive, Upgrade");
        assert!(h.has_token("connection", "upgrade"));
        assert_eq!(parse_status_ranges("200-299"), Some(vec![(200, 299)]));
        assert_eq!(parse_status_ranges("200-204,209,301-304"), Some(vec![(200, 204), (209, 209), (301, 304)]));
        assert_eq!(parse_status_ranges("abc"), None);
    }
}
