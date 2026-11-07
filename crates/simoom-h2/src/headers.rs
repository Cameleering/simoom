//! Received header blocks: one reusable byte buffer plus field offsets, validated as fields
//! arrive (RFC 9113 §8.2, §8.3).

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Request,
    Response,
    Trailers,
}

const METHOD: usize = 0;
const SCHEME: usize = 1;
const AUTHORITY: usize = 2;
const PATH: usize = 3;
const STATUS: usize = 4;

/// tchar (RFC 9110 §5.6.2) without upper-case letters.
const fn name_table() -> [bool; 256] {
    let mut t = [false; 256];
    let extra = b"!#$%&'*+-.^_`|~";
    let mut i = 0;
    while i < extra.len() {
        t[extra[i] as usize] = true;
        i += 1;
    }
    let mut c = b'0';
    while c <= b'9' {
        t[c as usize] = true;
        c += 1;
    }
    let mut c = b'a';
    while c <= b'z' {
        t[c as usize] = true;
        c += 1;
    }
    t
}
static NAME_CHARS: [bool; 256] = name_table();

/// A field value is valid when it has no NUL, CR or LF and no leading or trailing whitespace
/// (RFC 9113 §8.2.1).
#[inline]
pub(crate) fn valid_value(v: &[u8]) -> bool {
    if let (Some(&f), Some(&l)) = (v.first(), v.last()) {
        if f == b' ' || f == b'\t' || l == b' ' || l == b'\t' {
            return false;
        }
    }
    !v.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n')
}

/// A regular field name is valid when it is a lower-case token.
#[inline]
pub(crate) fn valid_name(n: &[u8]) -> bool {
    !n.is_empty() && n.iter().all(|&b| NAME_CHARS[b as usize])
}

/// Connection-specific fields are not allowed in HTTP/2 (RFC 9113 §8.2.2).
#[inline]
pub(crate) fn connection_specific(name: &[u8]) -> bool {
    matches!(name, b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade")
}

fn parse_u64(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 19 {
        return None;
    }
    let mut n = 0u64;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (b - b'0') as u64;
    }
    Some(n)
}

/// A received header block (request or response headers, or trailers).
///
/// Pseudo-header fields are reached through [`Headers::method`], [`Headers::path`] and so on;
/// [`Headers::iter`] yields the regular fields in order. Names are lower case.
#[derive(Clone)]
pub struct Headers {
    buf: Vec<u8>,
    /// (start in buf, name length, value length)
    fields: Vec<(u32, u32, u32)>,
    /// index + 1 into `fields` for each pseudo-header, 0 when absent
    pseudo: [u16; 5],
    npseudo: usize,
    host: u16,
    content_length: Option<u64>,
    malformed: Option<&'static str>,
    kind: Kind,
}

impl Default for Headers {
    fn default() -> Self {
        Headers {
            buf: Vec::new(),
            fields: Vec::new(),
            pseudo: [0; 5],
            npseudo: 0,
            host: 0,
            content_length: None,
            malformed: None,
            kind: Kind::Request,
        }
    }
}

impl Headers {
    pub(crate) fn reset(&mut self, kind: Kind) {
        self.buf.clear();
        self.fields.clear();
        self.pseudo = [0; 5];
        self.npseudo = 0;
        self.host = 0;
        self.content_length = None;
        self.malformed = None;
        self.kind = kind;
    }

    #[inline]
    fn fail(&mut self, why: &'static str) {
        if self.malformed.is_none() {
            self.malformed = Some(why);
        }
    }

    fn store(&mut self, name: &[u8], value: &[u8]) -> usize {
        let start = self.buf.len() as u32;
        self.buf.extend_from_slice(name);
        self.buf.extend_from_slice(value);
        self.fields.push((start, name.len() as u32, value.len() as u32));
        self.fields.len()
    }

    /// Adds a decoded field, checking it.
    pub(crate) fn push(&mut self, name: &[u8], value: &[u8]) {
        if self.malformed.is_some() {
            return;
        }
        if !valid_value(value) {
            return self.fail("invalid field value");
        }
        if name.first() == Some(&b':') {
            if self.kind == Kind::Trailers {
                return self.fail("pseudo-header in trailers");
            }
            if self.fields.len() > self.npseudo {
                return self.fail("pseudo-header after a regular field");
            }
            let slot = match (self.kind, name) {
                (Kind::Request, b":method") => METHOD,
                (Kind::Request, b":scheme") => SCHEME,
                (Kind::Request, b":authority") => AUTHORITY,
                (Kind::Request, b":path") => PATH,
                (Kind::Response, b":status") => STATUS,
                _ => return self.fail("unknown or misplaced pseudo-header"),
            };
            if self.pseudo[slot] != 0 {
                return self.fail("duplicate pseudo-header");
            }
            self.pseudo[slot] = self.store(name, value) as u16;
            self.npseudo += 1;
            return;
        }
        if !valid_name(name) {
            return self.fail("invalid field name");
        }
        match name {
            _ if connection_specific(name) => return self.fail("connection-specific field"),
            b"te" if value != b"trailers" => return self.fail("te other than trailers"),
            b"content-length" => match parse_u64(value) {
                Some(n) if self.content_length.is_none_or(|c| c == n) => self.content_length = Some(n),
                _ => return self.fail("invalid content-length"),
            },
            _ => {}
        }
        let i = self.store(name, value);
        if name == b"host" && self.host == 0 {
            self.host = i as u16;
        }
    }

    /// Checks the required pseudo-headers once the block is complete (RFC 9113 §8.3).
    pub(crate) fn finish(&mut self) {
        if self.malformed.is_some() {
            return;
        }
        match self.kind {
            Kind::Request => {
                let Some(method) = self.method() else { return self.fail("missing :method") };
                if method == b"CONNECT" {
                    if self.authority().is_none() || self.scheme().is_some() || self.path().is_some() {
                        return self.fail("malformed CONNECT");
                    }
                } else {
                    let (Some(scheme), Some(path)) = (self.scheme(), self.path()) else {
                        return self.fail("missing :scheme or :path");
                    };
                    if path.is_empty() {
                        return self.fail("empty :path");
                    }
                    let http = scheme == b"http" || scheme == b"https";
                    if http && path[0] != b'/' && !(path == b"*" && method == b"OPTIONS") {
                        return self.fail("invalid :path");
                    }
                }
                if let (Some(a), Some(h)) = (self.authority(), self.get(b"host")) {
                    if a != h {
                        return self.fail(":authority and host differ");
                    }
                }
            }
            Kind::Response => match self.status() {
                Some(s) if (100..1000).contains(&s) && s != 101 => {}
                _ => self.fail("missing or invalid :status"),
            },
            Kind::Trailers => {}
        }
    }

    pub(crate) fn malformed(&self) -> Option<&'static str> {
        self.malformed
    }

    #[inline]
    fn field(&self, i: usize) -> (&[u8], &[u8]) {
        let (s, n, v) = self.fields[i];
        let (s, n, v) = (s as usize, n as usize, v as usize);
        (&self.buf[s..s + n], &self.buf[s + n..s + n + v])
    }

    #[inline]
    fn pseudo(&self, slot: usize) -> Option<&[u8]> {
        match self.pseudo[slot] {
            0 => None,
            i => Some(self.field(i as usize - 1).1),
        }
    }

    /// `:method`.
    pub fn method(&self) -> Option<&[u8]> {
        self.pseudo(METHOD)
    }
    /// `:scheme`.
    pub fn scheme(&self) -> Option<&[u8]> {
        self.pseudo(SCHEME)
    }
    /// `:authority` (when absent, a `host` field may carry the authority: see [`Headers::get`]).
    pub fn authority(&self) -> Option<&[u8]> {
        self.pseudo(AUTHORITY)
    }
    /// `:path`.
    pub fn path(&self) -> Option<&[u8]> {
        self.pseudo(PATH)
    }
    /// `:status` as a number.
    pub fn status(&self) -> Option<u16> {
        let s = self.pseudo(STATUS)?;
        if s.len() != 3 {
            return None;
        }
        parse_u64(s).map(|n| n as u16)
    }
    /// The content-length value, when present.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }
    /// Number of regular fields.
    pub fn len(&self) -> usize {
        self.fields.len() - self.npseudo
    }
    /// True when there are no regular fields.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Regular fields (name, value) in order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        (self.npseudo..self.fields.len()).map(move |i| self.field(i))
    }
    /// The first regular field named `name` (lower case).
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut l = f.debug_list();
        for i in 0..self.fields.len() {
            let (n, v) = self.field(i);
            l.entry(&(String::from_utf8_lossy(n), String::from_utf8_lossy(v)));
        }
        l.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(fields: &[(&str, &str)]) -> Headers {
        let mut h = Headers::default();
        h.reset(Kind::Request);
        for (n, v) in fields {
            h.push(n.as_bytes(), v.as_bytes());
        }
        h.finish();
        h
    }

    const BASE: [(&str, &str); 4] = [(":method", "GET"), (":scheme", "https"), (":path", "/x"), (":authority", "a")];

    #[test]
    fn valid_request() {
        let h = req(&[BASE[0], BASE[1], BASE[2], BASE[3], ("accept", "*/*"), ("te", "trailers"), ("content-length", "0")]);
        assert_eq!(h.malformed(), None);
        assert_eq!(h.method(), Some(&b"GET"[..]));
        assert_eq!(h.path(), Some(&b"/x"[..]));
        assert_eq!(h.len(), 3);
        assert_eq!(h.get(b"accept"), Some(&b"*/*"[..]));
        assert_eq!(h.content_length(), Some(0));
        assert!(format!("{h:?}").contains("accept"));
        let h = req(&[(":method", "CONNECT"), (":authority", "a:443")]);
        assert_eq!(h.malformed(), None);
        let h = req(&[(":method", "OPTIONS"), (":scheme", "http"), (":path", "*")]);
        assert_eq!(h.malformed(), None);
    }

    #[test]
    fn malformed_requests() {
        let cases: Vec<Vec<(&str, &str)>> = vec![
            vec![BASE[1], BASE[2]],                                     // no method
            vec![BASE[0], BASE[2]],                                     // no scheme
            vec![BASE[0], BASE[1]],                                     // no path
            vec![BASE[0], BASE[1], (":path", "")],                      // empty path
            vec![BASE[0], BASE[1], (":path", "x")],                     // relative path
            vec![BASE[0], BASE[0], BASE[1], BASE[2]],                   // duplicate
            vec![BASE[0], BASE[1], BASE[2], (":status", "200")],        // response pseudo
            vec![BASE[0], BASE[1], BASE[2], (":protocol", "ws")],       // extended CONNECT not enabled
            vec![BASE[0], BASE[1], ("a", "b"), BASE[2]],                // pseudo after regular
            vec![BASE[0], BASE[1], BASE[2], ("Accept", "x")],           // upper case
            vec![BASE[0], BASE[1], BASE[2], ("", "x")],                 // empty name
            vec![BASE[0], BASE[1], BASE[2], ("a b", "x")],              // space in name
            vec![BASE[0], BASE[1], BASE[2], ("connection", "close")],
            vec![BASE[0], BASE[1], BASE[2], ("keep-alive", "1")],
            vec![BASE[0], BASE[1], BASE[2], ("transfer-encoding", "chunked")],
            vec![BASE[0], BASE[1], BASE[2], ("upgrade", "h2c")],
            vec![BASE[0], BASE[1], BASE[2], ("proxy-connection", "x")],
            vec![BASE[0], BASE[1], BASE[2], ("te", "gzip")],
            vec![BASE[0], BASE[1], BASE[2], ("content-length", "1x")],
            vec![BASE[0], BASE[1], BASE[2], ("content-length", "1"), ("content-length", "2")],
            vec![BASE[0], BASE[1], BASE[2], ("x", "a\r\nb")],
            vec![BASE[0], BASE[1], BASE[2], ("x", " a")],
            vec![BASE[0], BASE[1], BASE[2], ("x", "a\t")],
            vec![BASE[0], BASE[1], BASE[2], ("x", "a\0")],
            vec![BASE[0], BASE[1], BASE[2], BASE[3], ("host", "b")],    // host differs
            vec![(":method", "CONNECT"), (":authority", "a"), (":path", "/")],
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(req(c).malformed().is_some(), "case {i}: {c:?}");
        }
    }

    #[test]
    fn responses_and_trailers() {
        let mut h = Headers::default();
        h.reset(Kind::Response);
        h.push(b":status", b"204");
        h.finish();
        assert_eq!((h.malformed(), h.status()), (None, Some(204)));
        for bad in [&b"101"[..], b"20", b"abc", b"2000"] {
            h.reset(Kind::Response);
            h.push(b":status", bad);
            h.finish();
            assert!(h.malformed().is_some());
        }
        h.reset(Kind::Response);
        h.finish();
        assert!(h.malformed().is_some());
        h.reset(Kind::Trailers);
        h.push(b"grpc-status", b"0");
        h.finish();
        assert_eq!(h.malformed(), None);
        h.reset(Kind::Trailers);
        h.push(b":status", b"200");
        assert!(h.malformed().is_some());
    }
}
