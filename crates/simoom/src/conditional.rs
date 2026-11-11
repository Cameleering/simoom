//! Conditional and range requests (RFC 9110 §13, §14) for content the handler provides
//! (feature `conditional`): [`crate::Request::preconditions`], [`crate::Request::ranges`], and
//! [`crate::Reply::content`], which does all of it: `304`, `412`, `206` (one range, or several
//! as `multipart/byteranges`), `416`, and `200` with `accept-ranges: bytes`.

use std::ops::Range;
use std::time::SystemTime;

/// The validators of the current representation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Validators<'a> {
    /// The entity tag as sent in `ETag`, quotes included: `"v1"` or `W/"v1"`.
    pub etag: Option<&'a str>,
    /// The last modification time.
    pub last_modified: Option<SystemTime>,
}

/// The outcome of the precondition headers (RFC 9110 §13.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precondition {
    /// Go on and answer.
    Proceed,
    /// `304 Not Modified` (GET and HEAD).
    NotModified,
    /// `412 Precondition Failed`.
    Failed,
}

/// The outcome of `Range` (RFC 9110 §14.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeRequest {
    /// Send the whole representation (no `Range`, an unknown unit, a stale `If-Range`, or too
    /// many ranges).
    Full,
    /// Send these byte ranges (sorted, merged, non-empty).
    Ranges(Vec<Range<u64>>),
    /// `416 Range Not Satisfiable`.
    Unsatisfiable,
}

/// At most this many ranges are honoured; more get the whole representation (a defence against
/// overlapping-range amplification).
pub const MAX_RANGES: usize = 16;

/// Splits an entity-tag list (`"a", W/"b"` or `*`).
fn etags(v: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        while i < v.len() && matches!(v[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        let start = i;
        if v[i..].starts_with(b"W/") {
            i += 2;
        }
        if i < v.len() && v[i] == b'"' {
            i += 1;
            while i < v.len() && v[i] != b'"' {
                i += 1;
            }
            i = (i + 1).min(v.len());
        } else {
            while i < v.len() && v[i] != b',' {
                i += 1;
            }
        }
        let t = v[start..i].trim_ascii();
        if !t.is_empty() {
            out.push(t);
        }
    }
    out
}

fn opaque(t: &[u8]) -> (&[u8], bool) {
    match t.strip_prefix(b"W/") {
        Some(rest) => (rest, true),
        None => (t, false),
    }
}

fn strong_eq(a: &[u8], b: &[u8]) -> bool {
    let (x, wx) = opaque(a);
    let (y, wy) = opaque(b);
    !wx && !wy && x == y
}

fn weak_eq(a: &[u8], b: &[u8]) -> bool {
    opaque(a).0 == opaque(b).0
}

fn matches_list(header: &[u8], etag: Option<&str>, strong: bool) -> bool {
    let tags = etags(header);
    if tags.iter().any(|&t| t == b"*") {
        return etag.is_some();
    }
    let Some(e) = etag else { return false };
    tags.iter().any(|&t| if strong { strong_eq(t, e.as_bytes()) } else { weak_eq(t, e.as_bytes()) })
}

impl crate::Request<'_> {
    /// Evaluates `If-Match`, `If-Unmodified-Since`, `If-None-Match` and `If-Modified-Since` in
    /// the order RFC 9110 §13.2.2 gives.
    pub fn preconditions(&self, v: &Validators<'_>) -> Precondition {
        let get = matches!(self.method(), b"GET" | b"HEAD");
        let lm = v.last_modified.map(crate::httpdate::secs);
        if let Some(h) = self.header("if-match") {
            if !matches_list(h, v.etag, true) {
                return Precondition::Failed;
            }
        } else if let (Some(h), Some(lm)) = (self.header("if-unmodified-since"), lm) {
            if let Some(t) = crate::httpdate::parse(h) {
                if lm > crate::httpdate::secs(t) {
                    return Precondition::Failed;
                }
            }
        }
        if let Some(h) = self.header("if-none-match") {
            if matches_list(h, v.etag, false) {
                return if get { Precondition::NotModified } else { Precondition::Failed };
            }
        } else if let (true, Some(h), Some(lm)) = (get, self.header("if-modified-since"), lm) {
            if let Some(t) = crate::httpdate::parse(h) {
                if lm <= crate::httpdate::secs(t) {
                    return Precondition::NotModified;
                }
            }
        }
        Precondition::Proceed
    }

    /// Evaluates `Range` (and `If-Range`) for a representation of `len` bytes. Only GET has
    /// ranges.
    pub fn ranges(&self, len: u64, v: &Validators<'_>) -> RangeRequest {
        if self.method() != b"GET" {
            return RangeRequest::Full;
        }
        let Some(h) = self.header("range") else { return RangeRequest::Full };
        if let Some(ir) = self.header("if-range") {
            let ir = ir.trim_ascii();
            let fresh = if ir.starts_with(b"\"") || ir.starts_with(b"W/") {
                v.etag.is_some_and(|e| strong_eq(ir, e.as_bytes()))
            } else {
                match (crate::httpdate::parse(ir), v.last_modified) {
                    (Some(t), Some(lm)) => crate::httpdate::secs(t) == crate::httpdate::secs(lm),
                    _ => false,
                }
            };
            if !fresh {
                return RangeRequest::Full;
            }
        }
        parse_range(h, len)
    }
}

/// Parses `bytes=0-99,200-,-50` against a length (RFC 9110 §14.1.2).
pub(crate) fn parse_range(h: &[u8], len: u64) -> RangeRequest {
    let Ok(s) = std::str::from_utf8(h) else { return RangeRequest::Full };
    let Some(spec) = s.trim().strip_prefix("bytes=").or_else(|| s.trim().strip_prefix("BYTES=")) else { return RangeRequest::Full };
    let mut ranges: Vec<Range<u64>> = Vec::new();
    let mut any = false;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        any = true;
        let Some((a, b)) = part.split_once('-') else { return RangeRequest::Full };
        let r = if a.is_empty() {
            let Ok(n) = b.parse::<u64>() else { return RangeRequest::Full };
            if n == 0 {
                continue;
            }
            len.saturating_sub(n)..len
        } else {
            let Ok(first) = a.parse::<u64>() else { return RangeRequest::Full };
            let last = if b.is_empty() {
                len.saturating_sub(1)
            } else {
                match b.parse::<u64>() {
                    Ok(l) if l >= first => l.min(len.saturating_sub(1)),
                    _ => return RangeRequest::Full,
                }
            };
            if first >= len {
                continue;
            }
            first..last + 1
        };
        if r.start < r.end {
            ranges.push(r);
        }
        if ranges.len() > MAX_RANGES {
            return RangeRequest::Full;
        }
    }
    if !any {
        return RangeRequest::Full;
    }
    if ranges.is_empty() {
        return RangeRequest::Unsatisfiable;
    }
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::new();
    for r in ranges {
        match merged.last_mut() {
            Some(m) if r.start <= m.end => m.end = m.end.max(r.end),
            _ => merged.push(r),
        }
    }
    RangeRequest::Ranges(merged)
}

impl crate::Reply<'_> {
    /// Answers `req` with `body` (of `content_type`) honouring the conditional and range
    /// headers: `304` or `412` from the preconditions, `206` for satisfiable ranges (one range
    /// directly, several as `multipart/byteranges`), `416` for unsatisfiable ones, otherwise
    /// `200`. Sends `ETag`, `Last-Modified` and `Accept-Ranges: bytes`.
    pub fn content(self, req: &crate::Request<'_>, body: &[u8], content_type: &str, v: &Validators<'_>) -> crate::Outcome {
        let mut r = self;
        if let Some(e) = v.etag {
            r = r.header("etag", e);
        }
        if let Some(t) = v.last_modified {
            r = r.header("last-modified", crate::httpdate::format(t));
        }
        match req.preconditions(v) {
            Precondition::NotModified => return r.status(304).empty(),
            Precondition::Failed => return r.status(412).empty(),
            Precondition::Proceed => {}
        }
        let len = body.len() as u64;
        r = r.header("accept-ranges", "bytes");
        match req.ranges(len, v) {
            RangeRequest::Full => r.header("content-type", content_type).body_copy(body),
            RangeRequest::Unsatisfiable => r.status(416).header("content-range", format!("bytes */{len}")).empty(),
            RangeRequest::Ranges(rs) if rs.len() == 1 => {
                let x = &rs[0];
                r.status(206).header("content-type", content_type).header("content-range", format!("bytes {}-{}/{len}", x.start, x.end - 1)).body_copy(&body[x.start as usize..x.end as usize])
            }
            RangeRequest::Ranges(rs) => {
                let boundary = boundary_for(body);
                let mut out = Vec::new();
                for x in &rs {
                    out.extend_from_slice(format!("\r\n--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {}-{}/{len}\r\n\r\n", x.start, x.end - 1).as_bytes());
                    out.extend_from_slice(&body[x.start as usize..x.end as usize]);
                }
                out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
                r.status(206).header("content-type", format!("multipart/byteranges; boundary={boundary}")).body(out)
            }
        }
    }
}

/// A boundary that doesn't occur in `body`.
fn boundary_for(body: &[u8]) -> String {
    let mut n = body.iter().take(4096).fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3)) | 1;
    loop {
        let b = format!("simoom-{n:016x}");
        if !body.windows(b.len()).any(|w| w == b.as_bytes()) {
            return b;
        }
        n = n.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range(b"bytes=0-99", 1000), RangeRequest::Ranges(vec![0..100]));
        assert_eq!(parse_range(b"bytes=-100", 1000), RangeRequest::Ranges(vec![900..1000]));
        assert_eq!(parse_range(b"bytes=900-", 1000), RangeRequest::Ranges(vec![900..1000]));
        assert_eq!(parse_range(b"bytes=0-5000", 1000), RangeRequest::Ranges(vec![0..1000]));
        assert_eq!(parse_range(b"bytes=10-20, 0-15, 50-60", 1000), RangeRequest::Ranges(vec![0..21, 50..61]));
        assert_eq!(parse_range(b"bytes=1000-", 1000), RangeRequest::Unsatisfiable);
        assert_eq!(parse_range(b"bytes=-0", 1000), RangeRequest::Unsatisfiable);
        assert_eq!(parse_range(b"items=0-1", 1000), RangeRequest::Full);
        assert_eq!(parse_range(b"bytes=5-1", 1000), RangeRequest::Full);
        assert_eq!(parse_range(b"bytes=x-1", 1000), RangeRequest::Full);
        let many: String = (0..20).map(|i| format!("{}-{},", i * 10, i * 10 + 1)).collect();
        assert_eq!(parse_range(format!("bytes={many}").as_bytes(), 1000), RangeRequest::Full);
    }

    #[test]
    fn etag_matching() {
        assert!(matches_list(b"\"a\", \"b\"", Some("\"b\""), true));
        assert!(!matches_list(b"W/\"b\"", Some("\"b\""), true));
        assert!(matches_list(b"W/\"b\"", Some("\"b\""), false));
        assert!(matches_list(b"*", Some("\"x\""), true));
        assert!(!matches_list(b"*", None, true));
        assert_eq!(etags(b"\"a,b\", W/\"c\""), [&b"\"a,b\""[..], b"W/\"c\""]);
    }
}
