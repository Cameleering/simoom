//! `multipart/form-data` request bodies (RFC 7578; feature `multipart`).
//!
//! ```no_run
//! use simoom_client::{multipart::{Multipart, Part}, Client};
//!
//! let form = Multipart::new()
//!     .text("title", "Quarterly report")
//!     .file("attachment", "report.pdf", "application/pdf", std::fs::read("report.pdf").unwrap())
//!     .part("log", Part::reader(std::fs::File::open("app.log").unwrap(), None).file_name("app.log"));
//! let resp = Client::new().post("https://files.example/upload").multipart(form).send().unwrap();
//! ```
//!
//! Parts stream from readers as the connection takes data; the body has a `Content-Length` when
//! every reader's length is given, and is chunked otherwise. The boundary is 32 random
//! alphanumeric characters after `----simoom` (about 190 bits), and in-memory parts are checked
//! not to contain it. Field names and file names are escaped as browsers do (the WHATWG HTML
//! form encoding: `"` as `%22`, CR as `%0D`, LF as `%0A`); other text, including non-ASCII, is
//! sent as UTF-8. CR, LF and NUL are removed from content types and extra header values, and
//! extra headers whose names are not tokens are dropped.

use crate::types::Body;
use std::collections::VecDeque;
use std::io::{self, Read};

enum Data {
    Bytes(Vec<u8>),
    Reader(Box<dyn Read + Send>, Option<u64>),
}

/// One part: a field value or a file.
pub struct Part {
    data: Data,
    file_name: Option<String>,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
}

impl std::fmt::Debug for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = match &self.data {
            Data::Bytes(b) => Some(b.len() as u64),
            Data::Reader(_, l) => *l,
        };
        f.debug_struct("Part").field("len", &len).field("file_name", &self.file_name).field("content_type", &self.content_type).finish()
    }
}

fn clean(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n' && c != '\0').collect()
}

/// The WHATWG form-data escaping of names and file names.
fn escape(s: &str) -> String {
    s.replace('"', "%22").replace('\r', "%0D").replace('\n', "%0A")
}

impl Part {
    /// A text value.
    pub fn text(value: impl Into<String>) -> Part {
        Part::bytes(value.into().into_bytes())
    }

    /// Bytes in memory.
    pub fn bytes(data: impl Into<Vec<u8>>) -> Part {
        Part { data: Data::Bytes(data.into()), file_name: None, content_type: None, headers: Vec::new() }
    }

    /// Data streamed from `reader`; `len` is its exact length when known (a reader that yields
    /// another length fails the request).
    pub fn reader(reader: impl Read + Send + 'static, len: Option<u64>) -> Part {
        Part { data: Data::Reader(Box::new(reader), len), file_name: None, content_type: None, headers: Vec::new() }
    }

    /// The `filename` parameter (makes the part a file upload; its content type defaults to
    /// `application/octet-stream`).
    pub fn file_name(mut self, name: impl Into<String>) -> Part {
        self.file_name = Some(name.into());
        self
    }

    /// The part's `Content-Type`.
    pub fn mime(mut self, content_type: impl AsRef<str>) -> Part {
        self.content_type = Some(clean(content_type.as_ref()));
        self
    }

    /// An extra header for the part (RFC 7578 allows few; `Content-Transfer-Encoding` is
    /// deprecated there).
    pub fn header(mut self, name: &str, value: &str) -> Part {
        if !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)) {
            self.headers.push((name.to_string(), clean(value)));
        }
        self
    }

    fn head(&self, boundary: &str, name: &str) -> Vec<u8> {
        let mut h = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{}\"", escape(name));
        if let Some(f) = &self.file_name {
            h.push_str(&format!("; filename=\"{}\"", escape(f)));
        }
        h.push_str("\r\n");
        let ct = self.content_type.clone().or_else(|| self.file_name.as_ref().map(|_| "application/octet-stream".to_string()));
        if let Some(ct) = ct {
            h.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        for (n, v) in &self.headers {
            h.push_str(&format!("{n}: {v}\r\n"));
        }
        h.push_str("\r\n");
        h.into_bytes()
    }
}

/// A `multipart/form-data` body under construction.
pub struct Multipart {
    boundary: String,
    fixed: bool,
    parts: Vec<(String, Part)>,
}

impl std::fmt::Debug for Multipart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Multipart").field("boundary", &self.boundary).field("parts", &self.parts).finish()
    }
}

impl Default for Multipart {
    fn default() -> Self {
        Multipart::new()
    }
}

fn random_boundary() -> String {
    const A: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut r = [0u8; 32];
    if !simoom_sys::arch::os_random(&mut r) {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
        let mut x = t | 1;
        for v in r.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *v = x as u8;
        }
    }
    // 62 symbols: rejection would be uniform; modulo bias here is under 1%, irrelevant for a
    // delimiter
    let s: String = r.iter().map(|b| A[*b as usize % A.len()] as char).collect();
    format!("----simoom{s}")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

impl Multipart {
    /// An empty form with a random boundary.
    pub fn new() -> Multipart {
        Multipart { boundary: random_boundary(), fixed: false, parts: Vec::new() }
    }

    /// Uses this boundary (RFC 2046: 1 to 70 characters from `bchars`, not ending in a
    /// space); `None` if it is invalid. It is not regenerated when a part contains it.
    pub fn with_boundary(boundary: &str) -> Option<Multipart> {
        let ok = !boundary.is_empty()
            && boundary.len() <= 70
            && !boundary.ends_with(' ')
            && boundary.bytes().all(|c| c.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&c));
        ok.then(|| Multipart { boundary: boundary.to_string(), fixed: true, parts: Vec::new() })
    }

    /// Adds a part named `name`.
    pub fn part(mut self, name: impl Into<String>, part: Part) -> Multipart {
        self.parts.push((name.into(), part));
        self
    }

    /// Adds a text field.
    pub fn text(self, name: impl Into<String>, value: impl Into<String>) -> Multipart {
        self.part(name, Part::text(value))
    }

    /// Adds a file from memory.
    pub fn file(self, name: impl Into<String>, file_name: impl Into<String>, content_type: &str, data: impl Into<Vec<u8>>) -> Multipart {
        self.part(name, Part::bytes(data).file_name(file_name).mime(content_type))
    }

    /// Adds a file streamed from `reader` (`len`: its exact length when known).
    pub fn file_reader(self, name: impl Into<String>, file_name: impl Into<String>, content_type: &str, reader: impl Read + Send + 'static, len: Option<u64>) -> Multipart {
        self.part(name, Part::reader(reader, len).file_name(file_name).mime(content_type))
    }

    /// The boundary.
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// The request's `Content-Type`: `multipart/form-data; boundary=...`.
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    fn collides(&self) -> bool {
        let d = format!("--{}", self.boundary);
        self.parts.iter().any(|(n, p)| {
            contains(n.as_bytes(), d.as_bytes())
                || p.file_name.as_ref().is_some_and(|f| contains(f.as_bytes(), d.as_bytes()))
                || matches!(&p.data, Data::Bytes(b) if contains(b, d.as_bytes()))
        })
    }

    /// The body: bytes when every part is in memory, otherwise a stream (with a length when
    /// every reader's length is known). Call [`Multipart::content_type`] first, or use
    /// [`RequestBuilder::multipart`](crate::RequestBuilder::multipart), which does both.
    pub fn into_body(mut self) -> Body {
        let mut tries = 0;
        while !self.fixed && tries < 8 && self.collides() {
            self.boundary = random_boundary();
            tries += 1;
        }
        let mut segs: VecDeque<Seg> = VecDeque::new();
        let mut len: Option<u64> = Some(0);
        let mut all_bytes = true;
        let mut cur = Vec::new();
        for (name, p) in self.parts {
            cur.extend_from_slice(&p.head(&self.boundary, &name));
            match p.data {
                Data::Bytes(b) => cur.extend_from_slice(&b),
                Data::Reader(r, l) => {
                    all_bytes = false;
                    len = len.and_then(|x| l.map(|l| x + l));
                    segs.push_back(Seg::Bytes(std::mem::take(&mut cur), 0));
                    segs.push_back(Seg::Reader(r, l, 0));
                }
            }
            cur.extend_from_slice(b"\r\n");
        }
        cur.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        if all_bytes {
            return Body::Bytes(cur);
        }
        for s in &segs {
            if let Seg::Bytes(b, _) = s {
                len = len.map(|x| x + b.len() as u64);
            }
        }
        len = len.map(|x| x + cur.len() as u64);
        segs.push_back(Seg::Bytes(cur, 0));
        Body::Reader { reader: Box::new(Stream { segs }), len }
    }

    /// The boundary and body together (the boundary may change in `into_body` when a part
    /// contains it, so read it from here).
    pub fn into_parts(mut self) -> (String, Body) {
        let mut tries = 0;
        while !self.fixed && tries < 8 && self.collides() {
            self.boundary = random_boundary();
            tries += 1;
        }
        self.fixed = true;
        let ct = self.content_type();
        (ct, self.into_body())
    }
}

enum Seg {
    Bytes(Vec<u8>, usize),
    Reader(Box<dyn Read + Send>, Option<u64>, u64),
}

struct Stream {
    segs: VecDeque<Seg>,
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let Some(front) = self.segs.front_mut() else { return Ok(0) };
            match front {
                Seg::Bytes(b, pos) => {
                    if *pos < b.len() {
                        let n = (b.len() - *pos).min(buf.len());
                        buf[..n].copy_from_slice(&b[*pos..*pos + n]);
                        *pos += n;
                        return Ok(n);
                    }
                }
                Seg::Reader(r, want, got) => {
                    let n = r.read(buf)?;
                    if n > 0 {
                        *got += n as u64;
                        if want.is_some_and(|w| *got > w) {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "multipart part longer than its declared length"));
                        }
                        return Ok(n);
                    }
                    if want.is_some_and(|w| *got != w) {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "multipart part shorter than its declared length"));
                    }
                }
            }
            self.segs.pop_front();
        }
    }
}

impl crate::client::RequestBuilder {
    /// A `multipart/form-data` body; sets `Content-Type` with the boundary.
    pub fn multipart(self, form: Multipart) -> Self {
        let (ct, body) = form.into_parts();
        self.map(|r| r.headers.set("Content-Type", ct)).body(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(b: Body) -> (Vec<u8>, Option<u64>) {
        match b {
            Body::Bytes(v) => {
                let l = v.len() as u64;
                (v, Some(l))
            }
            Body::Reader { mut reader, len } => {
                let mut v = Vec::new();
                reader.read_to_end(&mut v).unwrap();
                (v, len)
            }
            Body::Empty => (Vec::new(), Some(0)),
        }
    }

    #[test]
    fn layout_escaping_and_lengths() {
        let m = Multipart::with_boundary("XyZ").unwrap().text("a\"b\r\nc", "v1").file("f", "na\"me.txt", "text/plain\r\nX: y", "hi");
        let (v, len) = read_all(m.into_body());
        let s = String::from_utf8(v.clone()).unwrap();
        assert_eq!(
            s,
            "--XyZ\r\nContent-Disposition: form-data; name=\"a%22b%0D%0Ac\"\r\n\r\nv1\r\n--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"na%22me.txt\"\r\nContent-Type: text/plainX: y\r\n\r\nhi\r\n--XyZ--\r\n"
        );
        assert_eq!(len, Some(v.len() as u64));
        // streamed parts: known lengths give a total, unknown ones none
        let m = Multipart::with_boundary("B").unwrap().text("t", "x").part("r", Part::reader(io::Cursor::new(vec![7u8; 1000]), Some(1000)).header("X-Id", "1").header("bad name", "x"));
        let (v, len) = read_all(m.into_body());
        assert_eq!(len, Some(v.len() as u64));
        assert!(String::from_utf8_lossy(&v).contains("X-Id: 1\r\n") && !String::from_utf8_lossy(&v).contains("bad name"));
        let m = Multipart::new().part("r", Part::reader(io::Cursor::new(vec![1u8; 10]), None));
        assert_eq!(read_all(m.into_body()).1, None);
        // a reader that lies about its length fails
        let m = Multipart::new().part("r", Part::reader(io::Cursor::new(vec![1u8; 10]), Some(11)));
        let Body::Reader { mut reader, .. } = m.into_body() else { panic!() };
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        let m = Multipart::new().part("r", Part::reader(io::Cursor::new(vec![1u8; 10]), Some(9)));
        let Body::Reader { mut reader, .. } = m.into_body() else { panic!() };
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        // boundaries: random ones differ and are valid; invalid custom ones are refused
        let (a, b) = (Multipart::new(), Multipart::new());
        assert_ne!(a.boundary(), b.boundary());
        assert!(Multipart::with_boundary(a.boundary()).is_some());
        assert!(Multipart::with_boundary("").is_none() && Multipart::with_boundary("a\"b").is_none() && Multipart::with_boundary("ab ").is_none());
        assert!(Multipart::with_boundary(&"x".repeat(71)).is_none());
    }

    #[test]
    fn boundary_collision_is_avoided() {
        let m = Multipart::new();
        let evil = format!("x--{}y", m.boundary());
        let old = m.boundary().to_string();
        let (ct, body) = m.text("a", evil.clone()).into_parts();
        assert!(!ct.ends_with(&old));
        let (v, _) = read_all(body);
        let b = ct.split("boundary=").nth(1).unwrap();
        assert_eq!(String::from_utf8_lossy(&v).matches(&format!("--{b}")).count(), 2);
    }
}
