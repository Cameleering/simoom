//! `multipart/form-data` (RFC 7578, RFC 2046 §5.1) parsing (feature `multipart`): a
//! streaming, sans-io [`MultipartParser`] with limits, and [`Request::multipart`] for a
//! buffered body.
//!
//! ```
//! # #[cfg(feature = "multipart")] {
//! use simoom::multipart::{boundary, parse, MultipartLimits};
//! let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--XyZ--\r\n";
//! let b = boundary(b"multipart/form-data; boundary=XyZ").unwrap();
//! let parts = parse(body, &b, &MultipartLimits::default()).unwrap();
//! assert_eq!((parts[0].head.name.as_deref(), &parts[0].data[..]), (Some("a"), &b"hello"[..]));
//! # }
//! ```

use std::fmt;

/// Bounds on what a multipart body may hold. Exceeding one is an error.
#[derive(Clone, Debug)]
pub struct MultipartLimits {
    /// Parts. Default 128.
    pub max_parts: usize,
    /// One part's header section, in bytes. Default 8 KiB.
    pub max_header_size: usize,
    /// One part's content, in bytes. Default 16 MiB.
    pub max_part_size: u64,
    /// The whole body, in bytes. Default 64 MiB.
    pub max_total: u64,
}

impl Default for MultipartLimits {
    fn default() -> Self {
        MultipartLimits { max_parts: 128, max_header_size: 8 * 1024, max_part_size: 16 << 20, max_total: 64 << 20 }
    }
}

/// Why a multipart body was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MultipartError {
    /// Not `multipart/*` with a valid boundary.
    NoBoundary,
    /// The body is malformed (a header line, a missing CRLF after a delimiter...).
    Malformed(&'static str),
    /// The body ended before the closing delimiter.
    Truncated,
    /// A limit of [`MultipartLimits`] was exceeded.
    TooLarge(&'static str),
}

impl MultipartError {
    /// The status to answer with: 413 for a limit, else 400.
    pub fn status(&self) -> u16 {
        match self {
            MultipartError::TooLarge(_) => 413,
            _ => 400,
        }
    }
}

impl fmt::Display for MultipartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MultipartError::NoBoundary => f.write_str("not a multipart body with a boundary"),
            MultipartError::Malformed(m) => write!(f, "malformed multipart body: {m}"),
            MultipartError::Truncated => f.write_str("multipart body ended early"),
            MultipartError::TooLarge(m) => write!(f, "multipart body too large: {m}"),
        }
    }
}

impl std::error::Error for MultipartError {}

/// A part's header section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartHead {
    /// The form field name (`Content-Disposition: form-data; name=...`).
    pub name: Option<String>,
    /// The file name of an uploaded file (`filename=`, or `filename*=` per RFC 5987).
    pub filename: Option<String>,
    /// The part's `Content-Type`, if given (`text/plain` is the default per RFC 7578).
    pub content_type: Option<String>,
    /// Every header field, names lower case.
    pub headers: Vec<(String, String)>,
}

/// A whole part (from [`parse`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Part {
    pub head: PartHead,
    pub data: Vec<u8>,
}

/// What the parser found.
#[derive(Debug)]
pub enum MultipartEvent<'a> {
    /// A part begins.
    Start(&'a PartHead),
    /// Content of the current part (any number of chunks).
    Data(&'a [u8]),
    /// The current part ended.
    End,
}

/// The boundary of a `Content-Type: multipart/...; boundary=...` value.
pub fn boundary(content_type: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(content_type).ok()?;
    let mut it = s.split(';');
    if !it.next()?.trim().to_ascii_lowercase().starts_with("multipart/") {
        return None;
    }
    for p in it {
        let (k, v) = p.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v);
            // RFC 2046: 1 to 70 characters, not ending in a space
            if v.is_empty() || v.len() > 70 || v.ends_with(' ') || v.bytes().any(|b| b < 0x20 || b > 0x7E) {
                return None;
            }
            return Some(v.as_bytes().to_vec());
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St {
    Preamble,
    /// After a delimiter: `--` (the end) or CRLF (a part).
    After,
    Head,
    Body,
    Epilogue,
}

/// A streaming `multipart/form-data` parser: feed it the body in pieces with
/// [`MultipartParser::feed`]; it calls back with each part's head and content. It holds at most
/// one part header section and the delimiter's length of content.
pub struct MultipartParser {
    delim: Vec<u8>,
    st: St,
    buf: Vec<u8>,
    limits: MultipartLimits,
    parts: usize,
    part_size: u64,
    total: u64,
    head: PartHead,
}

impl fmt::Debug for MultipartParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultipartParser").field("parts", &self.parts).field("state", &self.st).finish()
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    let first = n[0];
    let mut i = 0;
    while i + n.len() <= h.len() {
        match h[i..=h.len() - n.len()].iter().position(|&b| b == first) {
            None => return None,
            Some(p) => {
                i += p;
                if &h[i..i + n.len()] == n {
                    return Some(i);
                }
                i += 1;
            }
        }
    }
    None
}

impl MultipartParser {
    /// A parser for parts separated by `boundary` (see [`boundary`]).
    pub fn new(boundary: &[u8], limits: MultipartLimits) -> MultipartParser {
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary);
        // the first delimiter may come without the CRLF before it
        MultipartParser { delim, st: St::Preamble, buf: b"\r\n".to_vec(), limits, parts: 0, part_size: 0, total: 0, head: PartHead::default() }
    }

    /// Feeds body bytes.
    pub fn feed(&mut self, input: &[u8], f: &mut dyn FnMut(MultipartEvent<'_>)) -> Result<(), MultipartError> {
        self.total += input.len() as u64;
        if self.total > self.limits.max_total {
            return Err(MultipartError::TooLarge("body"));
        }
        if self.st == St::Epilogue {
            return Ok(());
        }
        self.buf.extend_from_slice(input);
        let mut pos = 0;
        loop {
            let rest = &self.buf[pos..];
            match self.st {
                St::Preamble => match find(rest, &self.delim) {
                    Some(i) => {
                        pos += i + self.delim.len();
                        self.st = St::After;
                    }
                    None => {
                        pos += rest.len().saturating_sub(self.delim.len() - 1);
                        break;
                    }
                },
                St::After => {
                    if rest.len() < 2 {
                        break;
                    }
                    if rest.starts_with(b"--") {
                        self.st = St::Epilogue;
                        pos = self.buf.len();
                        break;
                    }
                    // transport padding, then CRLF
                    let sp = rest.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
                    if rest.len() < sp + 2 {
                        if sp > 64 {
                            return Err(MultipartError::Malformed("padding after a delimiter"));
                        }
                        break;
                    }
                    if &rest[sp..sp + 2] != b"\r\n" {
                        return Err(MultipartError::Malformed("no CRLF after a delimiter"));
                    }
                    pos += sp + 2;
                    self.parts += 1;
                    if self.parts > self.limits.max_parts {
                        return Err(MultipartError::TooLarge("parts"));
                    }
                    self.st = St::Head;
                }
                St::Head => {
                    let end = if rest.starts_with(b"\r\n") { Some(0) } else { find(rest, b"\r\n\r\n").map(|i| i + 2) };
                    let Some(end) = end else {
                        if rest.len() > self.limits.max_header_size {
                            return Err(MultipartError::TooLarge("part header section"));
                        }
                        break;
                    };
                    if end > self.limits.max_header_size {
                        return Err(MultipartError::TooLarge("part header section"));
                    }
                    self.head = parse_head(&rest[..end])?;
                    pos += end + 2;
                    self.part_size = 0;
                    self.st = St::Body;
                    f(MultipartEvent::Start(&self.head));
                }
                St::Body => match find(rest, &self.delim) {
                    Some(i) => {
                        self.part_size += i as u64;
                        if self.part_size > self.limits.max_part_size {
                            return Err(MultipartError::TooLarge("part"));
                        }
                        if i > 0 {
                            f(MultipartEvent::Data(&rest[..i]));
                        }
                        f(MultipartEvent::End);
                        pos += i + self.delim.len();
                        self.st = St::After;
                    }
                    None => {
                        let n = rest.len().saturating_sub(self.delim.len() - 1);
                        self.part_size += n as u64;
                        if self.part_size > self.limits.max_part_size {
                            return Err(MultipartError::TooLarge("part"));
                        }
                        if n > 0 {
                            f(MultipartEvent::Data(&rest[..n]));
                        }
                        pos += n;
                        break;
                    }
                },
                St::Epilogue => {
                    pos = self.buf.len();
                    break;
                }
            }
        }
        self.buf.drain(..pos);
        Ok(())
    }

    /// The body ended: fails unless the closing delimiter was seen.
    pub fn finish(&self) -> Result<(), MultipartError> {
        if self.st == St::Epilogue {
            Ok(())
        } else if self.parts == 0 && self.st == St::Preamble {
            Err(MultipartError::Malformed("no delimiter"))
        } else {
            Err(MultipartError::Truncated)
        }
    }
}

/// Unquotes a quoted-string (or returns a token as is).
fn unquote(v: &str) -> String {
    let v = v.trim();
    if let Some(inner) = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut esc = false;
        for c in inner.chars() {
            if esc {
                out.push(c);
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else {
                out.push(c);
            }
        }
        out
    } else {
        v.to_string()
    }
}

/// Splits `a; b=c; d="e;f"` at the semicolons outside quotes.
fn params(v: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut esc) = (0, false, false);
    for (i, c) in v.char_indices() {
        if esc {
            esc = false;
        } else if c == '\\' && quoted {
            esc = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == ';' && !quoted {
            out.push(&v[start..i]);
            start = i + 1;
        }
    }
    out.push(&v[start..]);
    out
}

/// RFC 5987 `filename*=UTF-8''percent%20encoded`.
fn ext_value(v: &str) -> Option<String> {
    let (charset, rest) = v.trim().split_once('\'')?;
    let (_, enc) = rest.split_once('\'')?;
    if !charset.eq_ignore_ascii_case("utf-8") {
        return None;
    }
    String::from_utf8(crate::util::percent_decode(enc.as_bytes())?).ok()
}

fn parse_head(h: &[u8]) -> Result<PartHead, MultipartError> {
    let s = String::from_utf8_lossy(h);
    let mut head = PartHead::default();
    for line in s.split("\r\n").filter(|l| !l.is_empty()) {
        let (n, v) = line.split_once(':').ok_or(MultipartError::Malformed("part header line"))?;
        let n = n.trim().to_ascii_lowercase();
        if n.is_empty() || n.bytes().any(|b| b <= b' ') {
            return Err(MultipartError::Malformed("part header name"));
        }
        let v = v.trim().to_string();
        if n == "content-disposition" {
            let mut ext_name = None;
            for p in params(&v).into_iter().skip(1) {
                if let Some((k, val)) = p.split_once('=') {
                    match k.trim().to_ascii_lowercase().as_str() {
                        "name" => head.name = Some(unquote(val)),
                        "filename" => head.filename = Some(unquote(val)),
                        "filename*" => ext_name = ext_value(val),
                        _ => {}
                    }
                }
            }
            if ext_name.is_some() {
                head.filename = ext_name;
            }
        } else if n == "content-type" {
            head.content_type = Some(v.clone());
        }
        head.headers.push((n, v));
    }
    Ok(head)
}

/// Parses a whole buffered body.
pub fn parse(body: &[u8], boundary: &[u8], limits: &MultipartLimits) -> Result<Vec<Part>, MultipartError> {
    let mut p = MultipartParser::new(boundary, limits.clone());
    let mut parts: Vec<Part> = Vec::new();
    p.feed(body, &mut |e| match e {
        MultipartEvent::Start(h) => parts.push(Part { head: h.clone(), data: Vec::new() }),
        MultipartEvent::Data(d) => {
            if let Some(last) = parts.last_mut() {
                last.data.extend_from_slice(d);
            }
        }
        MultipartEvent::End => {}
    })?;
    p.finish()?;
    Ok(parts)
}

impl crate::Request<'_> {
    /// The parts of a buffered `multipart/form-data` body (the boundary comes from
    /// `Content-Type`). For a streamed body, feed [`crate::Request::take_body`] to a
    /// [`MultipartParser`].
    pub fn multipart(&self, limits: &MultipartLimits) -> Result<Vec<Part>, MultipartError> {
        let b = boundary(self.header("content-type").unwrap_or(b"")).ok_or(MultipartError::NoBoundary)?;
        parse(self.body(), &b, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = b"preamble\r\n--b0und\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue one\r\n--b0und\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a \\\"b\\\".txt\"\r\nContent-Type: text/plain\r\n\r\nline1\r\nline2 --b0un not a delimiter\r\n\r\n--b0und  \r\nContent-Disposition: form-data; name=\"u\"; filename*=UTF-8''na%C3%AFve.txt\r\n\r\n\r\n--b0und--\r\nepilogue";

    #[test]
    fn parses_in_one_go_and_in_pieces() {
        let parts = parse(BODY, b"b0und", &MultipartLimits::default()).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].head.name.as_deref(), Some("field"));
        assert_eq!(parts[0].data, b"value one");
        assert_eq!(parts[1].head.filename.as_deref(), Some("a \"b\".txt"));
        assert_eq!(parts[1].head.content_type.as_deref(), Some("text/plain"));
        assert_eq!(parts[1].data, b"line1\r\nline2 --b0un not a delimiter\r\n");
        assert_eq!(parts[2].head.filename.as_deref(), Some("naïve.txt"));
        assert_eq!(parts[2].data, b"");
        for step in [1, 2, 3, 7, 13] {
            let mut p = MultipartParser::new(b"b0und", MultipartLimits::default());
            let mut got: Vec<Part> = Vec::new();
            for c in BODY.chunks(step) {
                p.feed(c, &mut |e| match e {
                    MultipartEvent::Start(h) => got.push(Part { head: h.clone(), data: Vec::new() }),
                    MultipartEvent::Data(d) => got.last_mut().unwrap().data.extend_from_slice(d),
                    MultipartEvent::End => {}
                })
                .unwrap();
            }
            p.finish().unwrap();
            assert_eq!(got, parts, "step {step}");
        }
        // the first delimiter at the very start, no preamble
        let p = parse(b"--x\r\n\r\nabc\r\n--x--", b"x", &MultipartLimits::default()).unwrap();
        assert_eq!(p[0].data, b"abc");
    }

    #[test]
    fn limits_and_errors() {
        let l = MultipartLimits { max_parts: 2, ..Default::default() };
        assert_eq!(parse(BODY, b"b0und", &l).unwrap_err(), MultipartError::TooLarge("parts"));
        let l = MultipartLimits { max_part_size: 10, ..Default::default() };
        assert_eq!(parse(BODY, b"b0und", &l).unwrap_err().status(), 413);
        let l = MultipartLimits { max_header_size: 20, ..Default::default() };
        assert_eq!(parse(BODY, b"b0und", &l).unwrap_err().status(), 413);
        let l = MultipartLimits { max_total: 100, ..Default::default() };
        assert_eq!(parse(BODY, b"b0und", &l).unwrap_err().status(), 413);
        assert_eq!(parse(&BODY[..150], b"b0und", &MultipartLimits::default()).unwrap_err(), MultipartError::Truncated);
        assert!(parse(b"--x\r\nno colon here\r\n\r\nabc\r\n--x--", b"x", &MultipartLimits::default()).is_err());
        assert!(parse(b"--xjunk", b"x", &MultipartLimits::default()).is_err());
        assert_eq!(boundary(b"multipart/form-data; boundary=\"a b\""), Some(b"a b".to_vec()));
        assert_eq!(boundary(b"text/plain; boundary=x"), None);
        assert_eq!(boundary(b"multipart/mixed"), None);
    }
}
