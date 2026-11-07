//! Serialization: the cached `Date`, pre-serialized heads, a head writer and the chunked
//! encoder. Everything writes into caller-owned buffers or returns small stack values, so a
//! response can go out as one `writev`: head, body, and for chunked bodies the chunk header and
//! the CRLF around each piece.

use crate::Error;
use simoom_sys::scan::{scan, FIELD_VALUE, TCHAR};

/// `HTTP/1.1 100 Continue` with its empty line.
pub const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
/// The CRLF that ends each chunk's data.
pub const CRLF: &[u8] = b"\r\n";
/// The last chunk with no trailers.
pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

const DAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
const MONTHS: [&[u8; 3]; 12] =
    [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

fn two(out: &mut [u8], n: u64) {
    out[0] = b'0' + (n / 10) as u8;
    out[1] = b'0' + (n % 10) as u8;
}

/// The IMF-fixdate for a Unix time, e.g. `Sun, 06 Nov 1994 08:49:37 GMT` (RFC 9110 §5.6.7).
pub fn http_date(unix_secs: u64) -> [u8; 29] {
    let days = unix_secs / 86_400;
    let rem = unix_secs % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as usize;
    let year = (yoe + era * 400 + i64::from(month <= 2)) as u64;
    let mut b = *b"Thu, 01 Jan 1970 00:00:00 GMT";
    b[..3].copy_from_slice(DAYS[(days % 7) as usize]);
    two(&mut b[5..7], day);
    b[8..11].copy_from_slice(MONTHS[month - 1]);
    two(&mut b[12..14], (year / 100) % 100);
    two(&mut b[14..16], year % 100);
    two(&mut b[17..19], rem / 3600);
    two(&mut b[20..22], rem / 60 % 60);
    two(&mut b[23..25], rem % 60);
    b
}

/// The `Date` value, formatted once per second. The caller owns the clock: call
/// [`update`](DateCache::update) with the current Unix time, typically once per loop tick.
#[derive(Clone, Copy, Debug)]
pub struct DateCache {
    secs: u64,
    buf: [u8; 29],
}

impl DateCache {
    /// A cache holding the date for `unix_secs`.
    pub fn new(unix_secs: u64) -> Self {
        DateCache { secs: unix_secs, buf: http_date(unix_secs) }
    }

    /// Moves to `unix_secs`; formats only when the second changed. Returns true if it did.
    pub fn update(&mut self, unix_secs: u64) -> bool {
        if unix_secs == self.secs {
            return false;
        }
        *self = DateCache::new(unix_secs);
        true
    }

    /// The formatted date (29 bytes).
    pub fn bytes(&self) -> &[u8; 29] {
        &self.buf
    }

    /// The Unix second it holds.
    pub fn secs(&self) -> u64 {
        self.secs
    }
}

/// The reason phrase for a status code (empty for codes without one).
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// Decimal digits of `n` in a stack buffer.
fn decimal(n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = 20;
    let mut n = n;
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[i..];
        }
    }
}

fn check_field(name: &[u8], value: &[u8]) -> Result<(), Error> {
    if name.is_empty() || scan(name, &TCHAR) != name.len() {
        return Err(Error::InvalidHeaderName);
    }
    if name.eq_ignore_ascii_case(b"content-length") || name.eq_ignore_ascii_case(b"transfer-encoding") {
        return Err(Error::FramingHeader);
    }
    if scan(value, &FIELD_VALUE) != value.len() {
        return Err(Error::InvalidHeaderValue);
    }
    Ok(())
}

/// Writes a message head into a caller-owned buffer (reuse it to avoid allocation). Field names
/// and values are validated, so a value cannot split the response; framing goes through
/// [`content_length`](HeadWriter::content_length) and [`chunked`](HeadWriter::chunked) only.
#[derive(Debug)]
pub struct HeadWriter<'v> {
    out: &'v mut Vec<u8>,
}

impl<'v> HeadWriter<'v> {
    /// Starts a response: `HTTP/1.1 <status> <reason>`. `status` must be 100 to 999.
    pub fn response(out: &'v mut Vec<u8>, status: u16) -> Self {
        let status = status.clamp(100, 999);
        let mut d = [0u8; 20];
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(decimal(u64::from(status), &mut d));
        out.push(b' ');
        out.extend_from_slice(reason(status).as_bytes());
        out.extend_from_slice(CRLF);
        HeadWriter { out }
    }

    /// Starts a request: `<method> <target> HTTP/1.1`.
    pub fn request(out: &'v mut Vec<u8>, method: &[u8], target: &[u8]) -> Result<Self, Error> {
        if method.is_empty() || scan(method, &TCHAR) != method.len() {
            return Err(Error::InvalidMethod);
        }
        if target.is_empty() || target.iter().any(|&b| b <= b' ' || b >= 0x7f) {
            return Err(Error::InvalidTarget);
        }
        out.extend_from_slice(method);
        out.push(b' ');
        out.extend_from_slice(target);
        out.extend_from_slice(b" HTTP/1.1\r\n");
        Ok(HeadWriter { out })
    }

    /// Adds a field.
    pub fn header(&mut self, name: &[u8], value: &[u8]) -> Result<&mut Self, Error> {
        check_field(name, value)?;
        self.out.extend_from_slice(name);
        self.out.extend_from_slice(b": ");
        self.out.extend_from_slice(value);
        self.out.extend_from_slice(CRLF);
        Ok(self)
    }

    /// Adds `Date` from the cache.
    pub fn date(&mut self, date: &DateCache) -> &mut Self {
        self.out.extend_from_slice(b"Date: ");
        self.out.extend_from_slice(date.bytes());
        self.out.extend_from_slice(CRLF);
        self
    }

    /// Adds `Content-Length`.
    pub fn content_length(&mut self, n: u64) -> &mut Self {
        let mut d = [0u8; 20];
        self.out.extend_from_slice(b"Content-Length: ");
        self.out.extend_from_slice(decimal(n, &mut d));
        self.out.extend_from_slice(CRLF);
        self
    }

    /// Adds `Transfer-Encoding: chunked`.
    pub fn chunked(&mut self) -> &mut Self {
        self.out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        self
    }

    /// Adds `Connection: close`.
    pub fn close(&mut self) -> &mut Self {
        self.out.extend_from_slice(b"Connection: close\r\n");
        self
    }

    /// Ends the head with the empty line.
    pub fn finish(self) {
        self.out.extend_from_slice(CRLF);
    }
}

/// A response serialized once, with a `Date` slot patched at most once a second: the fast path
/// for fixed replies. The body (possibly empty) follows the head in the same buffer, so the
/// whole reply is one slice.
#[derive(Clone, Debug)]
pub struct StaticHead {
    bytes: Vec<u8>,
    date_at: usize,
    head_len: usize,
    secs: u64,
}

impl StaticHead {
    /// Serializes `status`, `headers`, `Content-Length: body.len()`, a `Date` slot and the body.
    pub fn new(status: u16, headers: &[(&[u8], &[u8])], body: &[u8]) -> Result<Self, Error> {
        let mut bytes = Vec::with_capacity(128 + body.len());
        let mut w = HeadWriter::response(&mut bytes, status);
        for &(n, v) in headers {
            w.header(n, v)?;
        }
        w.content_length(body.len() as u64);
        w.out.extend_from_slice(b"Date: ");
        let date_at = w.out.len();
        w.date_slot();
        w.finish();
        let head_len = bytes.len();
        bytes.extend_from_slice(body);
        Ok(StaticHead { bytes, date_at, head_len, secs: u64::MAX })
    }

    fn patch(&mut self, date: &DateCache) {
        if self.secs != date.secs() {
            self.bytes[self.date_at..self.date_at + 29].copy_from_slice(date.bytes());
            self.secs = date.secs();
        }
    }

    /// The whole reply, head and body.
    pub fn full(&mut self, date: &DateCache) -> &[u8] {
        self.patch(date);
        &self.bytes
    }

    /// The head alone (for HEAD requests).
    pub fn head(&mut self, date: &DateCache) -> &[u8] {
        self.patch(date);
        &self.bytes[..self.head_len]
    }
}

impl HeadWriter<'_> {
    fn date_slot(&mut self) {
        self.out.extend_from_slice(&[b' '; 29]);
        self.out.extend_from_slice(CRLF);
    }
}

/// A chunk header, `<hex length>\r\n`, on the stack.
#[derive(Clone, Copy, Debug)]
pub struct ChunkHeader {
    buf: [u8; 18],
    start: u8,
}

impl ChunkHeader {
    /// The header for a chunk of `len` bytes (`len` must not be 0: that is the last chunk).
    pub fn new(len: usize) -> Self {
        let mut buf = [0u8; 18];
        buf[16] = b'\r';
        buf[17] = b'\n';
        let mut i = 16;
        let mut n = len as u64;
        loop {
            i -= 1;
            buf[i] = b"0123456789abcdef"[(n & 15) as usize];
            n >>= 4;
            if n == 0 {
                break;
            }
        }
        ChunkHeader { buf, start: i as u8 }
    }

    /// The header bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[self.start as usize..]
    }
}

/// Appends one chunk (header, data, CRLF). Empty data writes nothing, since an empty chunk
/// would end the body.
pub fn write_chunk(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    out.extend_from_slice(ChunkHeader::new(data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(CRLF);
}

/// Appends the last chunk, the trailer fields and the final empty line.
pub fn write_last_chunk(out: &mut Vec<u8>, trailers: &[(&[u8], &[u8])]) -> Result<(), Error> {
    for &(n, v) in trailers {
        check_field(n, v)?;
        if n.eq_ignore_ascii_case(b"host") {
            return Err(Error::ForbiddenTrailer);
        }
    }
    out.extend_from_slice(b"0\r\n");
    for &(n, v) in trailers {
        out.extend_from_slice(n);
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(CRLF);
    }
    out.extend_from_slice(CRLF);
    Ok(())
}
