//! Content coding (feature `compression`): gzip and deflate responses negotiated from
//! `Accept-Encoding`, and decoding of request bodies sent with `Content-Encoding`.
//!
//! Responses are compressed when all of these hold:
//! - the client accepts `gzip` or `deflate` (q-values honoured; `gzip` wins ties);
//! - the status has a body (not 1xx, 204, 206 or 304);
//! - the service set no `content-encoding` and no `content-range`, and `cache-control` doesn't
//!   say `no-transform`;
//! - the `content-type` is compressible: `text/*`, JSON, XML, JavaScript and their `+json` /
//!   `+xml` relatives, SVG, and the extra types given to [`Compression::content_type`];
//!   images, audio, video, archives and responses without a type are left alone;
//! - a whole body has at least [`Compression::min_size`] bytes, and compressing makes it
//!   smaller.
//!
//! Every response that could be compressed carries `vary: accept-encoding`, whether or not this
//! client got the compressed form; a strong `etag` becomes weak on a compressed response.
//! Streamed bodies are compressed only with [`Compression::streams`], each write flushed so the
//! client sees it at once.

use crate::types::{Body, HeaderBuf, Response};
use simoom_compress::{Encoder, Format};
use std::borrow::Cow;
use std::io::{self, Read};
use std::sync::Arc;

/// A content coding the server can produce.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[non_exhaustive]
pub enum ContentCoding {
    /// `zstd` (RFC 8878, RFC 9659), feature `zstd`.
    Zstd,
    /// `br` (RFC 7932), feature `brotli`.
    Brotli,
    /// `gzip`.
    Gzip,
    /// `deflate` (zlib).
    Deflate,
}

/// Response compression settings ([`crate::Builder::compression`]).
///
/// The coding is the one the client accepts with the highest q-value; among equal q-values the
/// server's [`Compression::preference`] decides. The default preference is zstd, Brotli
/// (each when its cargo feature is on), gzip, deflate, with zstd and Brotli used only for
/// bodies of at least [`Compression::modern_min_size`] (streamed bodies qualify).
#[derive(Clone, Debug)]
pub struct Compression {
    level: u32,
    brotli_level: u32,
    zstd_level: u32,
    min_size: usize,
    modern_min: usize,
    pref: Vec<ContentCoding>,
    streams: bool,
    types: Vec<Box<str>>,
}

impl Default for Compression {
    fn default() -> Self {
        let mut pref = Vec::new();
        if cfg!(feature = "zstd") {
            pref.push(ContentCoding::Zstd);
        }
        if cfg!(feature = "brotli") {
            pref.push(ContentCoding::Brotli);
        }
        pref.extend([ContentCoding::Gzip, ContentCoding::Deflate]);
        Compression { level: 6, brotli_level: 4, zstd_level: 3, min_size: 1024, modern_min: 1024, pref, streams: false, types: Vec::new() }
    }
}

impl Compression {
    /// Every built-in coding (zstd 3, Brotli 4, gzip and deflate 6), bodies of 1 KiB and
    /// more, streamed bodies not compressed.
    pub fn new() -> Compression {
        Compression::default()
    }

    /// The codings to offer, most preferred first; others are not used. Codings whose cargo
    /// feature is off are ignored.
    pub fn preference(mut self, order: &[ContentCoding]) -> Self {
        self.pref = order.iter().copied().filter(|c| available(*c)).collect();
        self
    }

    /// Brotli quality, 0 to 11. Default 4.
    pub fn brotli_level(mut self, q: u32) -> Self {
        self.brotli_level = q.min(11);
        self
    }

    /// zstd level, 1 to 22. Default 3.
    pub fn zstd_level(mut self, level: u32) -> Self {
        self.zstd_level = level.clamp(1, 22);
        self
    }

    /// zstd and Brotli are chosen only for whole bodies of at least this size (smaller ones get
    /// gzip or deflate, whose output is smaller and cheaper for tiny inputs). Default 1024.
    pub fn modern_min_size(mut self, bytes: usize) -> Self {
        self.modern_min = bytes;
        self
    }

    /// The DEFLATE level, 1 (fastest) to 9 (smallest). Default 6.
    pub fn level(mut self, level: u32) -> Self {
        self.level = level.clamp(1, 9);
        self
    }

    /// Whole bodies smaller than this are sent as they are. Default 1024.
    pub fn min_size(mut self, bytes: usize) -> Self {
        self.min_size = bytes;
        self
    }

    /// Offer `gzip`. Default on.
    pub fn gzip(self, on: bool) -> Self {
        self.toggle(ContentCoding::Gzip, on)
    }

    /// Offer `deflate` (zlib, RFC 9110 §8.4.1.2). Default on.
    pub fn deflate(self, on: bool) -> Self {
        self.toggle(ContentCoding::Deflate, on)
    }

    fn toggle(mut self, c: ContentCoding, on: bool) -> Self {
        self.pref.retain(|&x| x != c);
        if on {
            self.pref.push(c);
        }
        self
    }

    /// Compress streamed bodies ([`crate::Reply::stream`], [`crate::Reply::sse`],
    /// [`crate::Responder::stream`]) too, flushing after every write. Each such response holds a
    /// compressor (about 256 KiB) while it runs. Default off.
    pub fn streams(mut self, on: bool) -> Self {
        self.streams = on;
        self
    }

    /// Also compress this content type: an exact type (`application/x-custom`) or a prefix
    /// ending in `/` (`model/`).
    pub fn content_type(mut self, mime: &str) -> Self {
        self.types.push(mime.to_ascii_lowercase().into());
        self
    }
}

fn available(c: ContentCoding) -> bool {
    match c {
        ContentCoding::Zstd => cfg!(feature = "zstd"),
        ContentCoding::Brotli => cfg!(feature = "brotli"),
        _ => true,
    }
}

pub(crate) type Coding = ContentCoding;

impl ContentCoding {
    fn idx(self) -> usize {
        self as usize
    }
    fn token(self) -> &'static [u8] {
        match self {
            ContentCoding::Zstd => b"zstd",
            ContentCoding::Brotli => b"br",
            ContentCoding::Gzip => b"gzip",
            ContentCoding::Deflate => b"deflate",
        }
    }
    fn format(self) -> Format {
        match self {
            #[cfg(feature = "zstd")]
            ContentCoding::Zstd => Format::Zstd,
            #[cfg(feature = "brotli")]
            ContentCoding::Brotli => Format::Brotli,
            ContentCoding::Deflate => Format::Zlib,
            _ => Format::Gzip,
        }
    }
    fn modern(self) -> bool {
        matches!(self, ContentCoding::Zstd | ContentCoding::Brotli)
    }
}

/// The outcome of negotiation for one request: the settings, and the client's q-value (in
/// thousandths; 0 = refused) for each coding.
#[derive(Clone, Debug)]
pub(crate) struct Neg {
    cfg: Arc<Compression>,
    q: [u16; 4],
}

impl Neg {
    /// The coding for a body of `len` bytes (`None`: streamed).
    fn pick(&self, len: Option<usize>) -> Option<Coding> {
        let mut best: Option<(u16, Coding)> = None;
        for &c in &self.cfg.pref {
            let q = self.q[c.idx()];
            if q == 0 || (c.modern() && len.is_some_and(|l| l < self.cfg.modern_min)) {
                continue;
            }
            if best.is_none_or(|(bq, _)| q > bq) {
                best = Some((q, c));
            }
        }
        best.map(|(_, c)| c)
    }

    fn level(&self, c: Coding) -> u32 {
        match c {
            ContentCoding::Zstd => self.cfg.zstd_level,
            ContentCoding::Brotli => self.cfg.brotli_level,
            _ => self.cfg.level,
        }
    }
}

/// A q-value in thousandths (RFC 9110 §12.4.2); `None` when malformed.
fn qvalue(v: &[u8]) -> Option<u16> {
    let v = trim(v);
    match v {
        [b'0'] => Some(0),
        [b'1'] => Some(1000),
        [b'0', b'.', rest @ ..] if rest.len() <= 3 && rest.iter().all(u8::is_ascii_digit) => {
            let mut n = 0u16;
            for i in 0..3 {
                n = n * 10 + rest.get(i).map_or(0, |d| (d - b'0') as u16);
            }
            Some(n)
        }
        [b'1', b'.', rest @ ..] if rest.len() <= 3 && rest.iter().all(|&d| d == b'0') => Some(1000),
        _ => None,
    }
}

fn trim(v: &[u8]) -> &[u8] {
    let s = v.iter().position(|b| !matches!(b, b' ' | b'\t')).unwrap_or(v.len());
    let e = v.iter().rposition(|b| !matches!(b, b' ' | b'\t')).map_or(s, |i| i + 1);
    &v[s..e]
}

/// The client's q-value per coding for an `Accept-Encoding` value.
fn qvalues(accept: Option<&[u8]>) -> [u16; 4] {
    let Some(accept) = accept else { return [0; 4] };
    let mut q4: [Option<u16>; 4] = [None; 4];
    let mut star = None;
    for item in accept.split(|&b| b == b',') {
        let mut parts = item.split(|&b| b == b';');
        let token = trim(parts.next().unwrap_or(b""));
        let mut q = Some(1000);
        for p in parts {
            let p = trim(p);
            if p.len() >= 2 && p[..2].eq_ignore_ascii_case(b"q=") {
                q = qvalue(&p[2..]);
            }
        }
        let Some(q) = q else { continue };
        let slot = if token.eq_ignore_ascii_case(b"gzip") || token.eq_ignore_ascii_case(b"x-gzip") {
            Some(ContentCoding::Gzip)
        } else if token.eq_ignore_ascii_case(b"deflate") {
            Some(ContentCoding::Deflate)
        } else if token.eq_ignore_ascii_case(b"br") {
            Some(ContentCoding::Brotli)
        } else if token.eq_ignore_ascii_case(b"zstd") {
            Some(ContentCoding::Zstd)
        } else {
            if token == b"*" {
                star = Some(q);
            }
            None
        };
        if let Some(c) = slot {
            let e = &mut q4[c.idx()];
            *e = Some(e.map_or(q, |old| old.max(q)));
        }
    }
    q4.map(|x| x.or(star).unwrap_or(0))
}

/// Picks the coding for an `Accept-Encoding` value and a body of `len` bytes.
#[cfg(test)]
pub(crate) fn choose(cfg: &Compression, accept: Option<&[u8]>) -> Option<Coding> {
    Neg { cfg: Arc::new(cfg.clone()), q: qvalues(accept) }.pick(Some(usize::MAX))
}

pub(crate) fn negotiate(cfg: &Arc<Compression>, accept: Option<&[u8]>) -> Neg {
    Neg { cfg: cfg.clone(), q: qvalues(accept) }
}

/// Is `ct` (a `content-type` value) worth compressing?
fn compressible(ct: &[u8], extra: &[Box<str>]) -> bool {
    let mime = trim(ct.split(|&b| b == b';').next().unwrap_or(b""));
    let mut buf = [0u8; 128];
    if mime.is_empty() || mime.len() > buf.len() {
        return false;
    }
    let m = &mut buf[..mime.len()];
    m.copy_from_slice(mime);
    m.make_ascii_lowercase();
    let m: &[u8] = m;
    if m.starts_with(b"text/") || m.ends_with(b"+json") || m.ends_with(b"+xml") {
        return true;
    }
    const TYPES: [&[u8]; 16] = [
        b"application/json",
        b"application/javascript",
        b"application/ecmascript",
        b"application/x-javascript",
        b"application/xml",
        b"application/x-ndjson",
        b"application/ndjson",
        b"application/graphql",
        b"application/yaml",
        b"application/x-yaml",
        b"application/toml",
        b"application/x-www-form-urlencoded",
        b"application/wasm",
        b"image/x-icon",
        b"font/ttf",
        b"font/otf",
    ];
    if TYPES.contains(&m) {
        return true;
    }
    extra.iter().any(|t| {
        let t = t.as_bytes();
        if t.ends_with(b"/") {
            m.starts_with(t)
        } else {
            m == t
        }
    })
}

/// Could this response be compressed (whatever the client accepts)?
fn eligible(cfg: &Compression, status: u16, h: &HeaderBuf, len: Option<usize>) -> bool {
    if !crate::util::has_body(status) || status == 206 {
        return false;
    }
    if len.is_some_and(|l| l < cfg.min_size.max(1)) {
        return false;
    }
    if h.get(b"content-encoding").is_some() || h.get(b"content-range").is_some() {
        return false;
    }
    if h.iter().any(|(n, v)| n == b"cache-control" && crate::util::has_token(v, b"no-transform")) {
        return false;
    }
    h.get(b"content-type").is_some_and(|ct| compressible(ct, &cfg.types))
}

fn add_vary(h: &mut HeaderBuf) {
    let has = h.iter().any(|(n, v)| n == b"vary" && (crate::util::has_token(v, b"accept-encoding") || trim(v) == b"*"));
    if !has {
        h.push(b"vary", b"accept-encoding");
    }
}

/// Marks a response compressed: `content-encoding`, and a strong `etag` made weak (the
/// compressed bytes differ from the identity form, RFC 9110 §8.8.3).
fn mark(h: &mut HeaderBuf, coding: Coding) {
    if let Some(e) = h.get(b"etag") {
        if e.starts_with(b"\"") {
            let mut old = std::mem::take(h);
            for (n, v) in old.iter() {
                if n == b"etag" {
                    let mut weak = b"W/".to_vec();
                    weak.extend_from_slice(v);
                    h.push(n, &weak);
                } else {
                    h.push(n, v);
                }
            }
            old.clear();
        }
    }
    h.push(b"content-encoding", coding.token());
}

/// A whole body: the compressed bytes, with the headers updated, or `None` to send it as it is
/// (the headers may still gain `vary`).
pub(crate) fn apply(n: &Neg, status: u16, h: &mut HeaderBuf, body: &[u8]) -> Option<Vec<u8>> {
    if !eligible(&n.cfg, status, h, Some(body.len())) {
        return None;
    }
    add_vary(h);
    let coding = n.pick(Some(body.len()))?;
    let c = simoom_compress::compress(body, coding.format(), n.level(coding));
    if c.len() >= body.len() {
        return None;
    }
    mark(h, coding);
    Some(c)
}

/// [`apply`] on an owned response (deferred replies; runs on the responder's thread).
pub(crate) fn apply_response(n: &Neg, r: &mut Response) {
    if r.invalid {
        return;
    }
    let body = match &r.body {
        Body::Empty => return,
        Body::Static(s) => *s,
        Body::Bytes(v) => &v[..],
    };
    if let Some(c) = apply(n, r.status, &mut r.headers, body) {
        r.body = Body::Bytes(c);
    }
}

/// A streamed body: the compressor to run it through, with the headers updated.
pub(crate) fn stream(n: &Neg, status: u16, h: &mut HeaderBuf) -> Option<Box<Encoder>> {
    if !n.cfg.streams || !eligible(&n.cfg, status, h, None) {
        return None;
    }
    add_vary(h);
    let coding = n.pick(None)?;
    mark(h, coding);
    Some(Box::new(Encoder::new(coding.format(), n.level(coding))))
}

/// One write of a compressed stream: the input, then a sync flush.
pub(crate) fn stream_chunk(e: &mut Encoder, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 + 16);
    e.encode(data, &mut out);
    e.flush(&mut out);
    out
}

/// The end of a compressed stream (last block and trailer).
pub(crate) fn stream_end(e: &mut Encoder) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    e.finish(&mut out);
    out
}

// ---------------------------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------------------------

/// Why a request body could not be decoded ([`crate::Request::decoded_body`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeBodyError {
    /// A content coding other than `gzip`, `x-gzip`, `deflate` and `identity`.
    Unsupported(String),
    /// The decoded body would be larger than the limit.
    TooLarge,
    /// The body is not valid for its coding (or truncated, or a checksum is wrong).
    Invalid(String),
}

impl DecodeBodyError {
    /// The status to answer with: 415, 413 or 400.
    pub fn status(&self) -> u16 {
        match self {
            DecodeBodyError::Unsupported(_) => 415,
            DecodeBodyError::TooLarge => 413,
            DecodeBodyError::Invalid(_) => 400,
        }
    }
}

impl std::fmt::Display for DecodeBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeBodyError::Unsupported(c) => write!(f, "unsupported content coding: {c}"),
            DecodeBodyError::TooLarge => f.write_str("decoded request body too large"),
            DecodeBodyError::Invalid(m) => write!(f, "invalid request body: {m}"),
        }
    }
}

impl std::error::Error for DecodeBodyError {}

fn map_err(e: simoom_compress::Error) -> DecodeBodyError {
    match e.kind() {
        simoom_compress::ErrorKind::LimitExceeded => DecodeBodyError::TooLarge,
        _ => DecodeBodyError::Invalid(e.to_string()),
    }
}

/// The codings of a `Content-Encoding` value, in the order they must be undone (last applied
/// first), `identity` left out.
fn codings(value: Option<&[u8]>) -> Result<Vec<Format>, DecodeBodyError> {
    let mut v = Vec::new();
    for t in value.unwrap_or(b"").split(|&b| b == b',').map(trim).filter(|t| !t.is_empty()).rev() {
        if t.eq_ignore_ascii_case(b"identity") {
            continue;
        }
        match Format::from_content_encoding(t) {
            Some(f) => v.push(f),
            None => return Err(DecodeBodyError::Unsupported(String::from_utf8_lossy(t).into_owned())),
        }
    }
    if v.len() > 2 {
        return Err(DecodeBodyError::Unsupported("more than two content codings".into()));
    }
    Ok(v)
}

/// Decodes a buffered body.
pub(crate) fn decode_body<'b>(coding: Option<&[u8]>, body: &'b [u8], limit: usize) -> Result<Cow<'b, [u8]>, DecodeBodyError> {
    let mut cur = Cow::Borrowed(body);
    for f in codings(coding)? {
        cur = Cow::Owned(simoom_compress::decompress(&cur, f, limit).map_err(map_err)?);
    }
    Ok(cur)
}

/// A reader that undoes the `Content-Encoding` of a streamed request body
/// ([`crate::Request::take_decoded_body`]), failing with `InvalidData` on a corrupt body and
/// once more than its limit would come out.
pub struct DecodedRead<R> {
    inner: R,
    dec: Option<simoom_compress::Decoder>,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    eof: bool,
}

impl<R> std::fmt::Debug for DecodedRead<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedRead").field("eof", &self.eof).finish()
    }
}

impl<R: Read> DecodedRead<R> {
    /// Wraps `inner`, a body sent with `Content-Encoding: coding` (one coding: `gzip`, `x-gzip`,
    /// `deflate` or `identity`), producing at most `limit` decoded bytes.
    pub fn new(inner: R, coding: Option<&[u8]>, limit: u64) -> Result<DecodedRead<R>, DecodeBodyError> {
        let c = codings(coding)?;
        if c.len() > 1 {
            return Err(DecodeBodyError::Unsupported("stacked content codings on a streamed body".into()));
        }
        let dec = c.first().map(|&f| simoom_compress::Decoder::with_limit(f, limit));
        Ok(DecodedRead { inner, dec, buf: vec![0; 16 * 1024].into_boxed_slice(), start: 0, end: 0, eof: false })
    }

    /// The wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for DecodedRead<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let Some(dec) = &mut self.dec else { return self.inner.read(out) };
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.start == self.end && !self.eof {
                let n = self.inner.read(&mut self.buf)?;
                self.start = 0;
                self.end = n;
                self.eof = n == 0;
            }
            let (used, written) = dec.decode_into(&self.buf[self.start..self.end], out).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, map_err(e)))?;
            self.start += used;
            if written > 0 {
                return Ok(written);
            }
            if self.eof && !dec.has_pending() {
                dec.finish().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, map_err(e)))?;
                return Ok(0);
            }
            if dec.is_done() && !dec.has_pending() {
                // anything after the end of the coded data is ignored
                return Ok(0);
            }
        }
    }
}

impl<'a> crate::Request<'a> {
    /// The buffered body with its `Content-Encoding` (`gzip`, `x-gzip`, `deflate`, up to two
    /// of them) undone, producing at most `limit` bytes; the body itself when it has no coding.
    /// Answer an error with [`DecodeBodyError::status`] (415, 413 or 400).
    pub fn decoded_body(&self, limit: usize) -> Result<Cow<'a, [u8]>, DecodeBodyError> {
        decode_body(self.header("content-encoding"), self.body(), limit)
    }

    /// The streamed body ([`crate::Request::take_body`]) wrapped in a reader that undoes its
    /// `Content-Encoding`; `None` when the body was buffered or already taken.
    pub fn take_decoded_body(&mut self, limit: u64) -> Option<Result<DecodedRead<crate::BodySource>, DecodeBodyError>> {
        let coding = self.header("content-encoding");
        let src = self.take_body()?;
        Some(DecodedRead::new(src, coding, limit))
    }
}

impl crate::OwnedRequest {
    /// [`crate::Request::decoded_body`] for an owned request.
    pub fn decoded_body(&self, limit: usize) -> Result<Cow<'_, [u8]>, DecodeBodyError> {
        decode_body(self.header("content-encoding"), self.body(), limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_encoding_negotiation() {
        let c = Compression::default().preference(&[ContentCoding::Gzip, ContentCoding::Deflate]);
        let cases: [(&str, Option<Coding>); 14] = [
            ("gzip", Some(Coding::Gzip)),
            ("deflate", Some(Coding::Deflate)),
            ("gzip, deflate, br", Some(Coding::Gzip)),
            ("deflate, gzip", Some(Coding::Gzip)),
            ("br", None),
            ("", None),
            ("gzip;q=0", None),
            ("gzip;q=0.5, deflate;q=0.8", Some(Coding::Deflate)),
            ("gzip; q=0.80, deflate;q=0.8", Some(Coding::Gzip)),
            ("*", Some(Coding::Gzip)),
            ("*;q=0, deflate", Some(Coding::Deflate)),
            ("identity", None),
            ("GZIP;Q=1.000", Some(Coding::Gzip)),
            ("gzip;q=1.5, deflate;q=0.1", Some(Coding::Deflate)),
        ];
        for (a, want) in cases {
            assert_eq!(choose(&c, Some(a.as_bytes())), want, "{a:?}");
        }
        assert_eq!(choose(&c, None), None);
        assert_eq!(choose(&c.clone().gzip(false), Some(b"gzip, deflate")), Some(Coding::Deflate));
        assert_eq!(choose(&c.clone().deflate(false), Some(b"deflate")), None);
        // zstd and Brotli: server preference among equal q-values, q-values first, size threshold
        let all = Compression::new();
        let both = cfg!(feature = "zstd") && cfg!(feature = "brotli");
        if both {
            assert_eq!(choose(&all, Some(b"gzip, deflate, br, zstd")), Some(Coding::Zstd));
            assert_eq!(choose(&all, Some(b"gzip, br")), Some(Coding::Brotli));
            assert_eq!(choose(&all, Some(b"gzip, br;q=0.5")), Some(Coding::Gzip));
            assert_eq!(choose(&all.clone().preference(&[ContentCoding::Brotli, ContentCoding::Zstd, ContentCoding::Gzip]), Some(b"zstd, br")), Some(Coding::Brotli));
            let n = negotiate(&Arc::new(all.clone()), Some(b"zstd, gzip"));
            assert_eq!(n.pick(Some(100)), Some(Coding::Gzip));
            assert_eq!(n.pick(Some(5000)), Some(Coding::Zstd));
            assert_eq!(n.pick(None), Some(Coding::Zstd));
        } else {
            assert_eq!(choose(&all, Some(b"br, zstd")), None);
        }
        assert_eq!(qvalue(b"0.001"), Some(1));
        assert_eq!(qvalue(b"0.0001"), None);
    }

    #[test]
    fn content_types() {
        let extra: Vec<Box<str>> = vec!["application/x-custom".into(), "model/".into()];
        for t in ["text/html", "text/plain; charset=utf-8", "Application/JSON", "application/problem+json", "application/atom+xml", "image/svg+xml", "application/x-custom", "model/gltf"] {
            assert!(compressible(t.as_bytes(), &extra), "{t}");
        }
        for t in ["image/png", "image/jpeg", "video/mp4", "application/zip", "application/gzip", "application/octet-stream", "font/woff2", "", "application/x-customer"] {
            assert!(!compressible(t.as_bytes(), &extra), "{t}");
        }
    }

    #[test]
    fn request_codings() {
        let body = b"a body that is long enough to compress well well well well well";
        let gz = simoom_compress::compress(body, Format::Gzip, 6);
        assert_eq!(&*decode_body(Some(b"gzip"), &gz, 1000).unwrap(), body);
        assert!(matches!(decode_body(None, body, 1000).unwrap(), Cow::Borrowed(_)));
        assert!(matches!(decode_body(Some(b"identity"), body, 1000).unwrap(), Cow::Borrowed(_)));
        let twice = simoom_compress::compress(&simoom_compress::compress(body, Format::Zlib, 6), Format::Gzip, 6);
        assert_eq!(&*decode_body(Some(b"deflate, gzip"), &twice, 1000).unwrap(), body);
        assert_eq!(decode_body(Some(b"compress"), body, 1000).unwrap_err().status(), 415);
        assert_eq!(decode_body(Some(b"gzip"), &gz, 10).unwrap_err().status(), 413);
        assert_eq!(decode_body(Some(b"gzip"), body, 1000).unwrap_err().status(), 400);
        // streamed
        let mut r = DecodedRead::new(&gz[..], Some(b"x-gzip"), 1000).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);
        let mut r = DecodedRead::new(&gz[..gz.len() - 3], Some(b"gzip"), 1000).unwrap();
        assert_eq!(r.read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut r = DecodedRead::new(&gz[..], Some(b"gzip"), 5).unwrap();
        assert_eq!(r.read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut r = DecodedRead::new(&body[..], None, 5).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn whole_bodies() {
        let n = negotiate(&Arc::new(Compression::new().preference(&[ContentCoding::Gzip])), Some(b"gzip"));
        let body = "hello compression ".repeat(200);
        let mut h = HeaderBuf::default();
        h.push(b"content-type", b"text/plain");
        h.push(b"etag", b"\"v1\"");
        let c = apply(&n, 200, &mut h, body.as_bytes()).unwrap();
        assert_eq!(simoom_compress::decompress(&c, Format::Gzip, 1 << 20).unwrap(), body.as_bytes());
        assert_eq!(h.get(b"content-encoding"), Some(&b"gzip"[..]));
        assert_eq!(h.get(b"vary"), Some(&b"accept-encoding"[..]));
        assert_eq!(h.get(b"etag"), Some(&b"W/\"v1\""[..]));
        // small, wrong type, already coded, no-transform, 204, 206: untouched
        let mut small = HeaderBuf::default();
        small.push(b"content-type", b"text/plain");
        assert!(apply(&n, 200, &mut small, b"tiny").is_none());
        assert_eq!(small.get(b"vary"), None);
        for (k, v, status) in [("content-type", "image/png", 200), ("content-encoding", "br", 200), ("cache-control", "public, no-transform", 200), ("x", "y", 204), ("x", "y", 206)] {
            let mut h = HeaderBuf::default();
            h.push(b"content-type", b"text/plain");
            h.push(k.as_bytes(), v.as_bytes());
            if k == "content-type" {
                h = HeaderBuf::default();
                h.push(b"content-type", v.as_bytes());
            }
            assert!(apply(&n, status, &mut h, body.as_bytes()).is_none(), "{k}: {v} {status}");
        }
        // client without gzip: no compression, but vary
        let none = negotiate(&n.cfg, None);
        let mut h = HeaderBuf::default();
        h.push(b"content-type", b"application/json");
        h.push(b"vary", b"Origin");
        assert!(apply(&none, 200, &mut h, body.as_bytes()).is_none());
        assert!(h.iter().any(|(n, v)| n == b"vary" && v == b"accept-encoding"));
        // incompressible bytes stay as they are
        let mut x = 0x1234_5678u32;
        let noise: Vec<u8> = (0..4000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let mut h = HeaderBuf::default();
        h.push(b"content-type", b"text/plain");
        assert!(apply(&n, 200, &mut h, &noise).is_none());
        assert_eq!(h.get(b"content-encoding"), None);
    }
}
