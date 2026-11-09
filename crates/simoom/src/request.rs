//! The request a [`crate::Service`] sees, and its owned copy.

use crate::handle::BodySource;
use crate::types::{OwnedHead, Version};
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum HeaderView<'a> {
    #[cfg(feature = "http1")]
    H1(&'a [simoom_http1::Header<'a>]),
    Owned(&'a OwnedHead),
}

/// A route parameter: name, and its range in the request target.
pub(crate) type Param = (Arc<str>, u32, u32);

/// A request, borrowed from the connection for the duration of [`crate::Service::call`].
///
/// The head is zero-copy on HTTP/1.1. The body is either buffered whole ([`Request::body`]) or,
/// for bodies larger than [`crate::Limits::body_buffer`], streamed ([`Request::take_body`]).
pub struct Request<'a> {
    pub(crate) method: &'a [u8],
    pub(crate) target: &'a [u8],
    pub(crate) version: Version,
    pub(crate) authority: Option<&'a [u8]>,
    pub(crate) headers: HeaderView<'a>,
    pub(crate) body: &'a [u8],
    pub(crate) source: Option<BodySource>,
    pub(crate) streamed: bool,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) secure: bool,
    pub(crate) params: Vec<Param>,
    pub(crate) route: u32,
    /// What the call cost its thread, when the watchdog measured it.
    pub(crate) sample: Option<crate::watchdog::Sample>,
    pub(crate) websocket: bool,
    pub(crate) loop_index: usize,
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &String::from_utf8_lossy(self.method))
            .field("target", &String::from_utf8_lossy(self.target))
            .field("version", &self.version)
            .finish()
    }
}

fn path_of(target: &[u8]) -> &[u8] {
    match target.iter().position(|&b| b == b'?') {
        Some(i) => &target[..i],
        None => target,
    }
}

fn query_of(target: &[u8]) -> Option<&[u8]> {
    target.iter().position(|&b| b == b'?').map(|i| &target[i + 1..])
}

/// Looks up `name=` in a query string; the raw (still percent-encoded) value.
fn query_param<'q>(query: &'q [u8], name: &str) -> Option<&'q [u8]> {
    query.split(|&b| b == b'&').find_map(|kv| {
        let (k, v) = match kv.iter().position(|&b| b == b'=') {
            Some(i) => (&kv[..i], &kv[i + 1..]),
            None => (kv, &kv[kv.len()..]),
        };
        (k == name.as_bytes()).then_some(v)
    })
}

impl<'a> Request<'a> {
    pub(crate) fn new(method: &'a [u8], target: &'a [u8], version: Version, headers: HeaderView<'a>) -> Request<'a> {
        Request {
            method,
            target,
            version,
            authority: None,
            headers,
            body: b"",
            source: None,
            streamed: false,
            peer: None,
            secure: false,
            params: Vec::new(),
            route: 0,
            sample: None,
            websocket: false,
            loop_index: 0,
        }
    }

    /// The method, for example `b"GET"`.
    pub fn method(&self) -> &'a [u8] {
        self.method
    }

    /// The request target as sent: path and query (origin form), or an absolute URI.
    pub fn target(&self) -> &'a [u8] {
        self.target
    }

    /// The path: the target up to `?`. Not percent-decoded (see [`crate::percent_decode`]).
    pub fn path(&self) -> &'a [u8] {
        path_of(self.target)
    }

    /// The path as text, or `""` if it isn't UTF-8.
    pub fn path_str(&self) -> &'a str {
        std::str::from_utf8(self.path()).unwrap_or("")
    }

    /// The query string after `?`, if any.
    pub fn query(&self) -> Option<&'a [u8]> {
        query_of(self.target)
    }

    /// One query parameter, raw.
    pub fn query_param(&self, name: &str) -> Option<&'a [u8]> {
        query_param(self.query()?, name)
    }

    /// The HTTP version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The authority: `:authority` on HTTP/2 and HTTP/3, `Host` on HTTP/1.1.
    pub fn host(&self) -> Option<&'a [u8]> {
        self.authority.or_else(|| self.header("host"))
    }

    /// The first header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        let name = name.as_bytes();
        match self.headers {
            #[cfg(feature = "http1")]
            HeaderView::H1(h) => h.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value),
            HeaderView::Owned(o) => (0..o.fields.len()).map(|i| o.field(i)).find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v),
        }
    }

    /// Every header field in order.
    pub fn headers(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        let view = self.headers;
        let n = match view {
            #[cfg(feature = "http1")]
            HeaderView::H1(h) => h.len(),
            HeaderView::Owned(o) => o.fields.len(),
        };
        (0..n).map(move |i| match view {
            #[cfg(feature = "http1")]
            HeaderView::H1(h) => (h[i].name, h[i].value),
            HeaderView::Owned(o) => o.field(i),
        })
    }

    /// The buffered body. Empty when the body streams ([`Request::is_streamed`]).
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// True when the body is too large to buffer and arrives through [`Request::take_body`].
    pub fn is_streamed(&self) -> bool {
        self.streamed
    }

    /// The streaming body source, once. `None` when the body was buffered whole.
    pub fn take_body(&mut self) -> Option<BodySource> {
        self.source.take()
    }

    /// A route parameter captured by [`crate::Router`] (`/users/:id`), raw.
    pub fn param(&self, name: &str) -> Option<&'a [u8]> {
        let t = self.target;
        self.params.iter().find(|p| &*p.0 == name).map(|p| &t[p.1 as usize..p.2 as usize])
    }

    /// A route parameter as text.
    pub fn param_str(&self, name: &str) -> Option<&'a str> {
        self.param(name).and_then(|p| std::str::from_utf8(p).ok())
    }

    /// The peer's address, when known.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// True over TLS (and always on HTTP/3).
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// True for a valid WebSocket opening handshake: answer it with
    /// [`crate::Reply::websocket`].
    pub fn is_websocket_upgrade(&self) -> bool {
        self.websocket
    }

    /// The loop thread serving this request.
    pub fn loop_index(&self) -> usize {
        self.loop_index
    }

    /// Copies the request (head and buffered body) and takes the body source, so the request
    /// can move to another thread.
    pub fn to_owned_request(&mut self) -> OwnedRequest {
        let mut head = OwnedHead::default();
        head.buf.reserve(self.target.len() + 64);
        head.set_method(self.method);
        head.set_target(self.target);
        if let Some(a) = self.authority {
            head.set_authority(a);
        }
        for (n, v) in self.headers() {
            head.add_field(n, v);
        }
        OwnedRequest {
            head,
            version: self.version,
            body: self.body.to_vec(),
            source: self.source.take(),
            streamed: self.streamed,
            peer: self.peer,
            secure: self.secure,
            params: self.params.clone(),
            route: self.route,
            websocket: false,
            loop_index: self.loop_index,
        }
    }
}

/// An owned request, for work on other threads ([`crate::blocking`], [`crate::Reply::offload`]).
#[derive(Debug)]
pub struct OwnedRequest {
    pub(crate) head: OwnedHead,
    pub(crate) version: Version,
    pub(crate) body: Vec<u8>,
    pub(crate) source: Option<BodySource>,
    pub(crate) streamed: bool,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) secure: bool,
    pub(crate) params: Vec<Param>,
    pub(crate) route: u32,
    pub(crate) websocket: bool,
    pub(crate) loop_index: usize,
}

impl OwnedRequest {
    /// The method.
    pub fn method(&self) -> &[u8] {
        self.head.method()
    }
    /// The request target.
    pub fn target(&self) -> &[u8] {
        self.head.target()
    }
    /// The path (the target up to `?`).
    pub fn path(&self) -> &[u8] {
        path_of(self.head.target())
    }
    /// The path as text, or `""`.
    pub fn path_str(&self) -> &str {
        std::str::from_utf8(self.path()).unwrap_or("")
    }
    /// The query string.
    pub fn query(&self) -> Option<&[u8]> {
        query_of(self.head.target())
    }
    /// One query parameter, raw.
    pub fn query_param(&self, name: &str) -> Option<&[u8]> {
        query_param(self.query()?, name)
    }
    /// The version.
    pub fn version(&self) -> Version {
        self.version
    }
    /// The first header named `name`.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        (0..self.head.fields.len()).map(|i| self.head.field(i)).find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes())).map(|(_, v)| v)
    }
    /// Every header field.
    pub fn headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        (0..self.head.fields.len()).map(|i| self.head.field(i))
    }
    /// The authority (`:authority` or `Host`).
    pub fn host(&self) -> Option<&[u8]> {
        self.head.authority().or_else(|| self.header("host"))
    }
    /// A route parameter.
    pub fn param(&self, name: &str) -> Option<&[u8]> {
        let t = self.head.target();
        self.params.iter().find(|p| &*p.0 == name).map(|p| &t[p.1 as usize..p.2 as usize])
    }
    /// The peer's address.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }
    /// True over TLS.
    pub fn is_secure(&self) -> bool {
        self.secure
    }
    /// The buffered body (empty if it streams).
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// True when the body streams through [`OwnedRequest::take_body`].
    pub fn is_streamed(&self) -> bool {
        self.streamed
    }
    /// The streaming body source, once.
    pub fn take_body(&mut self) -> Option<BodySource> {
        self.source.take()
    }

    /// The whole body: the buffered one, or the stream read to its end (blocking; up to
    /// [`crate::Limits::max_body`], which the connection enforces).
    pub fn read_body(&mut self) -> std::io::Result<Vec<u8>> {
        match self.source.take() {
            None => Ok(std::mem::take(&mut self.body)),
            Some(mut s) => {
                let mut v = std::mem::take(&mut self.body);
                s.read_to_end(&mut v)?;
                Ok(v)
            }
        }
    }

    pub(crate) fn as_request(&mut self) -> Request<'_> {
        Request {
            method: self.head.method(),
            target: self.head.target(),
            version: self.version,
            authority: self.head.authority(),
            headers: HeaderView::Owned(&self.head),
            body: &self.body,
            source: self.source.take(),
            streamed: self.streamed,
            peer: self.peer,
            secure: self.secure,
            params: std::mem::take(&mut self.params),
            route: self.route,
            sample: None,
            websocket: self.websocket,
            loop_index: self.loop_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_query_and_params() {
        let mut h = OwnedHead::default();
        h.set_method(b"GET");
        h.set_target(b"/a/b?x=1&y=two&z");
        h.add_field(b"Host", b"example.com");
        let mut r = Request::new(b"GET", b"/a/b?x=1&y=two&z", Version::Http11, HeaderView::Owned(&h));
        assert_eq!(r.path(), b"/a/b");
        assert_eq!(r.query_param("y"), Some(&b"two"[..]));
        assert_eq!(r.query_param("z"), Some(&b""[..]));
        assert_eq!(r.query_param("w"), None);
        assert_eq!(r.header("HOST"), Some(&b"example.com"[..]));
        assert_eq!(r.host(), Some(&b"example.com"[..]));
        r.params.push((Arc::from("p"), 3, 4));
        assert_eq!(r.param("p"), Some(&b"b"[..]));
        let o = r.to_owned_request();
        assert_eq!(o.path_str(), "/a/b");
        assert_eq!(o.param("p"), Some(&b"b"[..]));
        assert_eq!(o.headers().count(), 1);
    }
}
