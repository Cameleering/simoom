//! Owned value types shared by every protocol: header lists, bodies, responses, owned request
//! heads and pre-serialized fixed replies.

use std::ops::Range;

/// The HTTP version a request arrived with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    H2,
    /// HTTP/3
    H3,
}

/// Byte classes: bit 0 `tchar` (RFC 9110 §5.6.2), bit 1 allowed in a field value (§5.5: no
/// controls except HTAB).
static CLASS: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        let tchar = matches!(b, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~') || b.is_ascii_alphanumeric();
        let value = b == b'\t' || (b >= 0x20 && b != 0x7f);
        t[i] = tchar as u8 | (value as u8) << 1;
        i += 1;
    }
    t
};

/// A `tchar`.
#[inline]
pub(crate) fn is_tchar(b: u8) -> bool {
    CLASS[b as usize] & 1 != 0
}

/// A field value without CR, LF or NUL and other controls except HTAB.
#[inline]
pub(crate) fn valid_value(v: &[u8]) -> bool {
    v.iter().all(|&b| CLASS[b as usize] & 2 != 0)
}

/// Header fields to send, stored in one buffer: names lower case, validated on insert.
#[derive(Clone, Default)]
pub(crate) struct HeaderBuf {
    bytes: Vec<u8>,
    /// (start, name length, value length)
    idx: Vec<(u32, u16, u32)>,
}

impl std::fmt::Debug for HeaderBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut l = f.debug_list();
        for (n, v) in self.iter() {
            l.entry(&(String::from_utf8_lossy(n), String::from_utf8_lossy(v)));
        }
        l.finish()
    }
}

/// What [`HeaderBuf::push`] did with a field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Pushed {
    Added,
    /// `connection: close`: the connection closes after this response.
    Close,
    /// A framing or connection-specific field the server writes itself; dropped.
    Ignored,
    /// An invalid name or value.
    Invalid,
}

impl HeaderBuf {
    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
        self.idx.clear();
    }

    pub(crate) fn push(&mut self, name: &[u8], value: &[u8]) -> Pushed {
        if name.is_empty() || name.len() > u16::MAX as usize || !valid_value(value) {
            return Pushed::Invalid;
        }
        let value = trim(value);
        let start = self.bytes.len();
        self.bytes.reserve(name.len() + value.len());
        for &b in name {
            if !is_tchar(b) {
                self.bytes.truncate(start);
                return Pushed::Invalid;
            }
            self.bytes.push(b.to_ascii_lowercase());
        }
        let lower = &self.bytes[start..];
        match lower {
            b"connection" => {
                self.bytes.truncate(start);
                return if crate::util::has_token(value, b"close") { Pushed::Close } else { Pushed::Ignored };
            }
            b"content-length" | b"transfer-encoding" | b"keep-alive" | b"upgrade" | b"proxy-connection" | b"date" => {
                self.bytes.truncate(start);
                return Pushed::Ignored;
            }
            _ => {}
        }
        self.bytes.extend_from_slice(value);
        self.idx.push((start as u32, name.len() as u16, value.len() as u32));
        Pushed::Added
    }

    /// Number of fields.
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.idx.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        self.idx.iter().map(move |&(s, n, v)| {
            let s = s as usize;
            let m = s + n as usize;
            (&self.bytes[s..m], &self.bytes[m..m + v as usize])
        })
    }

    pub(crate) fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }

    /// Bytes of the `name: value\r\n` lines.
    pub(crate) fn h1_len(&self) -> usize {
        self.bytes.len() + 4 * self.idx.len()
    }

    /// Appends `name: value\r\n` lines.
    pub(crate) fn write_h1(&self, out: &mut Vec<u8>) {
        for (n, v) in self.iter() {
            out.extend_from_slice(n);
            out.extend_from_slice(b": ");
            out.extend_from_slice(v);
            out.extend_from_slice(b"\r\n");
        }
    }
}

fn trim(v: &[u8]) -> &[u8] {
    let s = v.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(v.len());
    let e = v.iter().rposition(|&b| b != b' ' && b != b'\t').map_or(s, |i| i + 1);
    &v[s..e]
}

/// A response body.
#[derive(Clone, Debug, Default)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// Static bytes (no copy on HTTP/1.1 without TLS for large bodies).
    Static(&'static [u8]),
    /// Owned bytes.
    Bytes(Vec<u8>),
}

impl Body {
    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Body::Empty => b"",
            Body::Static(s) => s,
            Body::Bytes(b) => b,
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// True when there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Body {
        Body::Bytes(v)
    }
}
impl From<String> for Body {
    fn from(v: String) -> Body {
        Body::Bytes(v.into_bytes())
    }
}
impl From<&'static [u8]> for Body {
    fn from(v: &'static [u8]) -> Body {
        Body::Static(v)
    }
}
impl From<&'static str> for Body {
    fn from(v: &'static str) -> Body {
        Body::Static(v.as_bytes())
    }
}
impl<const N: usize> From<&'static [u8; N]> for Body {
    fn from(v: &'static [u8; N]) -> Body {
        Body::Static(v)
    }
}

/// An owned response: what a [`crate::Responder`] or a [`crate::blocking`] handler sends.
///
/// ```
/// let r = simoom::Response::new(201).header("content-type", "application/json").body(r#"{"ok":true}"#);
/// assert_eq!(r.status(), 201);
/// ```
#[derive(Clone, Debug)]
pub struct Response {
    pub(crate) status: u16,
    pub(crate) headers: HeaderBuf,
    pub(crate) body: Body,
    pub(crate) close: bool,
    pub(crate) invalid: bool,
}

impl Default for Response {
    fn default() -> Self {
        Response::new(200)
    }
}

impl Response {
    /// A response with `status` (100 to 999), no headers and no body.
    pub fn new(status: u16) -> Response {
        Response { status, headers: HeaderBuf::default(), body: Body::Empty, close: false, invalid: !(100..=999).contains(&status) }
    }

    /// `200 OK` with a `text/plain` body.
    pub fn text(body: impl Into<Body>) -> Response {
        Response::new(200).header("content-type", "text/plain; charset=utf-8").body(body)
    }

    /// Adds a header. Framing fields (`content-length`, `transfer-encoding`) are written by the
    /// server and ignored here; `connection: close` closes the connection after the response.
    /// An invalid name or value turns the response into a 500.
    pub fn header(mut self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Response {
        match self.headers.push(name.as_ref(), value.as_ref()) {
            Pushed::Close => self.close = true,
            Pushed::Invalid => self.invalid = true,
            _ => {}
        }
        self
    }

    /// Sets the body.
    pub fn body(mut self, body: impl Into<Body>) -> Response {
        self.body = body.into();
        self
    }

    /// The status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The first header named `name` (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&[u8]> {
        self.headers.get(name.as_bytes())
    }

    /// The body.
    pub fn body_bytes(&self) -> &[u8] {
        self.body.as_bytes()
    }

    pub(crate) fn error(status: u16) -> Response {
        let mut r = Response::new(status);
        r.body = Body::Static(simoom_http1::write::reason(status).as_bytes());
        r.headers.push(b"content-type", b"text/plain");
        r
    }
}

/// A request head copied out of the receive buffer (HTTP/2, HTTP/3, offloaded requests, and
/// HTTP/1.1 requests whose body arrives later).
#[derive(Clone, Default, Debug)]
pub(crate) struct OwnedHead {
    pub(crate) buf: Vec<u8>,
    pub(crate) method: Range<u32>,
    pub(crate) target: Range<u32>,
    pub(crate) authority: Option<Range<u32>>,
    /// (name start, name end, value end); the value starts at the name end.
    pub(crate) fields: Vec<(u32, u32, u32)>,
}

impl OwnedHead {
    /// Empties the head, keeping the capacity of its buffers.
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    pub(crate) fn clear(&mut self) {
        self.buf.clear();
        self.fields.clear();
        self.method = 0..0;
        self.target = 0..0;
        self.authority = None;
    }

    fn put(&mut self, b: &[u8]) -> Range<u32> {
        let s = self.buf.len() as u32;
        self.buf.extend_from_slice(b);
        s..self.buf.len() as u32
    }

    pub(crate) fn set_method(&mut self, b: &[u8]) {
        self.method = self.put(b);
    }
    pub(crate) fn set_target(&mut self, b: &[u8]) {
        self.target = self.put(b);
    }
    pub(crate) fn set_authority(&mut self, b: &[u8]) {
        self.authority = Some(self.put(b));
    }
    pub(crate) fn add_field(&mut self, name: &[u8], value: &[u8]) {
        let s = self.buf.len() as u32;
        self.buf.extend_from_slice(name);
        let m = self.buf.len() as u32;
        self.buf.extend_from_slice(value);
        self.fields.push((s, m, self.buf.len() as u32));
    }

    pub(crate) fn r(&self, r: &Range<u32>) -> &[u8] {
        &self.buf[r.start as usize..r.end as usize]
    }
    pub(crate) fn method(&self) -> &[u8] {
        self.r(&self.method)
    }
    pub(crate) fn target(&self) -> &[u8] {
        self.r(&self.target)
    }
    pub(crate) fn authority(&self) -> Option<&[u8]> {
        self.authority.as_ref().map(|a| self.r(a))
    }
    pub(crate) fn field(&self, i: usize) -> (&[u8], &[u8]) {
        let (s, m, e) = self.fields[i];
        (&self.buf[s as usize..m as usize], &self.buf[m as usize..e as usize])
    }
}

/// A reply serialized once, for the fast path of fixed answers ([`crate::Reply::fixed`]). On
/// HTTP/1.1 it is copied out with the current `Date` spliced in: one copy, no formatting.
///
/// ```
/// let hello = simoom::StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!");
/// assert_eq!(hello.body(), b"Hello, World!");
/// ```
#[derive(Clone, Debug)]
pub struct StaticReply {
    pub(crate) status: u16,
    pub(crate) headers: HeaderBuf,
    pub(crate) body: Body,
    /// `HTTP/1.1 ...` through `date: `.
    pub(crate) h1_pre: Vec<u8>,
    /// `\r\n` after the date, `content-length`, the final CRLF, and the body.
    pub(crate) h1_post: Vec<u8>,
    /// Length of the body at the end of `h1_post`.
    pub(crate) body_len: usize,
}

impl StaticReply {
    /// Serializes a reply. Invalid header names or values are dropped (and framing fields are
    /// written by the server).
    pub fn new(status: u16, headers: &[(&str, &str)], body: impl Into<Body>) -> StaticReply {
        let mut hb = HeaderBuf::default();
        for (n, v) in headers {
            hb.push(n.as_bytes(), v.as_bytes());
        }
        let body: Body = body.into();
        let status = status.clamp(100, 999);
        let mut pre = Vec::with_capacity(96);
        crate::util::status_line(&mut pre, status);
        hb.write_h1(&mut pre);
        pre.extend_from_slice(b"date: ");
        let mut post = Vec::with_capacity(32 + body.len());
        post.extend_from_slice(b"\r\n");
        if crate::util::has_body(status) {
            crate::util::content_length(&mut post, body.len() as u64);
        }
        post.extend_from_slice(b"\r\n");
        let body_len = if crate::util::has_body(status) { body.len() } else { 0 };
        post.extend_from_slice(&body.as_bytes()[..body_len]);
        StaticReply { status, headers: hb, body, h1_pre: pre, h1_post: post, body_len }
    }

    /// The status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The body.
    pub fn body(&self) -> &[u8] {
        self.body.as_bytes()
    }

    pub(crate) fn to_response(&self) -> Response {
        Response { status: self.status, headers: self.headers.clone(), body: self.body.clone(), close: false, invalid: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_buf_validates_and_lowercases() {
        let mut h = HeaderBuf::default();
        assert_eq!(h.push(b"X-Thing", b"  v 1 "), Pushed::Added);
        assert_eq!(h.push(b"Content-Length", b"5"), Pushed::Ignored);
        assert_eq!(h.push(b"Connection", b"keep-alive, close"), Pushed::Close);
        assert_eq!(h.push(b"bad name", b"v"), Pushed::Invalid);
        assert_eq!(h.push(b"x", b"a\r\nb"), Pushed::Invalid);
        assert_eq!(h.push(b"x", b"tab\tok"), Pushed::Added);
        let all: Vec<_> = h.iter().collect();
        assert_eq!(all, vec![(&b"x-thing"[..], &b"v 1"[..]), (&b"x"[..], &b"tab\tok"[..])]);
        let mut out = Vec::new();
        h.write_h1(&mut out);
        assert_eq!(out, b"x-thing: v 1\r\nx: tab\tok\r\n");
    }

    #[test]
    fn static_reply_pieces() {
        let r = StaticReply::new(200, &[("content-type", "text/plain")], b"hi");
        assert_eq!(r.h1_pre, b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ndate: ");
        assert_eq!(r.h1_post, b"\r\ncontent-length: 2\r\n\r\nhi");
        let n = StaticReply::new(204, &[], b"ignored");
        assert_eq!(n.h1_post, b"\r\n\r\n");
    }
}
