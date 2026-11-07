//! Request, response and field-section parsing (RFC 9112 §2–§6).

use crate::{Error, Framing, Header, Limits, Request, Response, Status, TargetForm, Version};
use simoom_sys::scan::{field_line, find_byte, scan, FIELD_VALUE, TCHAR, URI};

/// What the field section said about framing and the connection.
#[derive(Default)]
struct Semantics<'b> {
    host: Option<&'b [u8]>,
    hosts: u8,
    content_length: Option<u64>,
    te_codings: u32,
    te_chunked: u32,
    te_last_chunked: bool,
    close: bool,
    keep_alive: bool,
    conn_upgrade: bool,
    expect_continue: bool,
    expect_other: bool,
    upgrade: Option<&'b [u8]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Head,
    Trailers,
}

#[inline]
fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim(mut v: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = v {
        if !is_ws(*first) {
            break;
        }
        v = rest;
    }
    while let [rest @ .., last] = v {
        if !is_ws(*last) {
            break;
        }
        v = rest;
    }
    v
}

/// True if the comma-separated list `value` contains `token` (case-insensitive), as in
/// `has_token(connection_value, b"close")`.
pub fn has_token(value: &[u8], token: &[u8]) -> bool {
    value.split(|&b| b == b',').any(|t| trim(t).eq_ignore_ascii_case(token))
}

fn hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// `uri-host [":" port]` (RFC 9110 §7.2); with `need_port` the port must be present and
/// non-empty, as in the authority form.
fn valid_host(v: &[u8], need_port: bool) -> bool {
    if v.is_empty() {
        return !need_port;
    }
    let rest = if v[0] == b'[' {
        let Some(end) = v.iter().position(|&b| b == b']') else { return false };
        let inner = &v[1..end];
        if inner.is_empty() || !inner.iter().all(|&b| hex(b) || b == b':' || b == b'.') {
            return false;
        }
        &v[end + 1..]
    } else {
        let colon = v.iter().position(|&b| b == b':').unwrap_or(v.len());
        let host = &v[..colon];
        let mut i = 0;
        while i < host.len() {
            let b = host[i];
            if b == b'%' {
                if i + 2 >= host.len() || !hex(host[i + 1]) || !hex(host[i + 2]) {
                    return false;
                }
                i += 3;
                continue;
            }
            if !(b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b)) {
                return false;
            }
            i += 1;
        }
        if host.is_empty() {
            return false;
        }
        &v[colon..]
    };
    match rest {
        [] => !need_port,
        [b':', port @ ..] => port.iter().all(u8::is_ascii_digit) && (!need_port || !port.is_empty()),
        _ => false,
    }
}

/// `absolute-URI`: a scheme, `:`, and the rest (already checked byte by byte); brackets only
/// inside the authority.
fn valid_absolute(t: &[u8], brackets: bool) -> bool {
    let Some(colon) = t.iter().position(|&b| b == b':') else { return false };
    let scheme = &t[..colon];
    if scheme.is_empty()
        || !scheme[0].is_ascii_alphabetic()
        || !scheme.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return false;
    }
    // userinfo hides the real authority (`http://trusted@evil/`): RFC 9110 §4.2.4 says to treat
    // it as an error.
    if let Some(rest) = t[colon + 1..].strip_prefix(b"//") {
        let end = rest.iter().position(|&b| b == b'/' || b == b'?').unwrap_or(rest.len());
        if rest[..end].contains(&b'@') {
            return false;
        }
    }
    if !brackets {
        return true;
    }
    let Some(rest) = t[colon + 1..].strip_prefix(b"//") else { return false };
    let auth_end = rest.iter().position(|&b| b == b'/' || b == b'?').unwrap_or(rest.len());
    let auth = &rest[..auth_end];
    let host = match auth.iter().rposition(|&b| b == b'@') {
        Some(at) => &auth[at + 1..],
        None => auth,
    };
    !rest[auth_end..].iter().any(|&b| b == b'[' || b == b']') && valid_host(host, false)
}

fn parse_content_length(v: &[u8]) -> Result<u64, Error> {
    let digits = |s: &[u8]| -> Option<u64> {
        if s.is_empty() {
            return None;
        }
        s.iter().try_fold(0u64, |n, &b| {
            if b.is_ascii_digit() {
                n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
            } else {
                None
            }
        })
    };
    if let Some(n) = digits(v) {
        return Ok(n);
    }
    if v.contains(&b',') && v.split(|&b| b == b',').all(|p| digits(trim(p)).is_some()) {
        return Err(Error::DuplicateContentLength);
    }
    Err(Error::InvalidContentLength)
}

impl<'b> Semantics<'b> {
    fn field(&mut self, name: &[u8], value: &'b [u8]) -> Result<(), Error> {
        match name.len() {
            4 if name.eq_ignore_ascii_case(b"host") => {
                self.hosts = self.hosts.saturating_add(1);
                if self.hosts > 1 {
                    return Err(Error::DuplicateHost);
                }
                if !valid_host(value, false) {
                    return Err(Error::InvalidHost);
                }
                self.host = Some(value);
            }
            6 if name.eq_ignore_ascii_case(b"expect") => {
                if value.eq_ignore_ascii_case(b"100-continue") {
                    self.expect_continue = true;
                } else {
                    self.expect_other = true;
                }
            }
            7 if name.eq_ignore_ascii_case(b"upgrade") => {
                if self.upgrade.is_some() {
                    return Err(Error::DuplicateUpgrade);
                }
                self.upgrade = Some(value);
            }
            10 if name.eq_ignore_ascii_case(b"connection") => {
                for t in value.split(|&b| b == b',') {
                    let t = trim(t);
                    if t.eq_ignore_ascii_case(b"close") {
                        self.close = true;
                    } else if t.eq_ignore_ascii_case(b"keep-alive") {
                        self.keep_alive = true;
                    } else if t.eq_ignore_ascii_case(b"upgrade") {
                        self.conn_upgrade = true;
                    }
                }
            }
            14 if name.eq_ignore_ascii_case(b"content-length") => {
                if self.content_length.is_some() {
                    return Err(Error::DuplicateContentLength);
                }
                self.content_length = Some(parse_content_length(value)?);
            }
            17 if name.eq_ignore_ascii_case(b"transfer-encoding") => {
                for c in value.split(|&b| b == b',') {
                    let c = trim(c);
                    if c.is_empty() || scan(c, &TCHAR) != c.len() {
                        return Err(Error::InvalidTransferEncoding);
                    }
                    self.te_codings += 1;
                    self.te_last_chunked = c.eq_ignore_ascii_case(b"chunked");
                    self.te_chunked += u32::from(self.te_last_chunked);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Request framing (RFC 9112 §6.3 rules 3–7).
    fn request_framing(&self, version: Version, lim: &Limits) -> Result<Framing, Error> {
        if self.te_codings > 0 {
            if self.content_length.is_some() {
                return Err(Error::TeWithContentLength);
            }
            if version == Version::Http10 {
                return Err(Error::TransferEncodingHttp10);
            }
            if self.te_chunked != 1 || !self.te_last_chunked {
                return Err(Error::ChunkedNotFinal);
            }
            if self.te_codings > 1 {
                return Err(Error::UnsupportedTransferCoding);
            }
            return Ok(Framing::Chunked);
        }
        match self.content_length {
            Some(n) if n > lim.max_body => Err(Error::BodyTooLarge),
            Some(0) | None => Ok(Framing::None),
            Some(n) => Ok(Framing::Length(n)),
        }
    }

    fn keep_alive(&self, version: Version) -> bool {
        !self.close && (version == Version::Http11 || self.keep_alive)
    }
}

/// Parses field lines from `p` up to and including the empty line. Returns the end offset and
/// the number of fields, or `None` when more bytes are needed. `start` is where the section (or
/// the whole head) begins, for the `max_total` limit.
#[allow(clippy::too_many_arguments)]
fn parse_fields<'b>(
    buf: &'b [u8],
    mut p: usize,
    start: usize,
    hs: &mut [Header<'b>],
    store: bool,
    lim: &Limits,
    section: Section,
    sem: &mut Semantics<'b>,
) -> Result<Option<(usize, usize)>, Error> {
    let (max_total, too_large) = match section {
        Section::Head => (lim.max_head, Error::HeadTooLarge),
        Section::Trailers => (lim.max_trailers, Error::TrailersTooLarge),
    };
    let partial = |ls: usize| -> Result<Option<(usize, usize)>, Error> {
        if buf.len() - ls > lim.max_header_line {
            Err(Error::HeaderLineTooLong)
        } else if buf.len() - start > max_total {
            Err(too_large)
        } else {
            Ok(None)
        }
    };
    let mut count = 0;
    loop {
        let ls = p;
        let Some(&first) = buf.get(p) else { return partial(ls) };
        match first {
            b'\r' => {
                let Some(&lf) = buf.get(p + 1) else { return partial(ls) };
                if lf != b'\n' {
                    return Err(Error::BareCr);
                }
                p += 2;
                if p - start > max_total {
                    return Err(too_large);
                }
                return Ok(Some((p, count)));
            }
            b'\n' => return Err(Error::BareLf),
            b' ' | b'\t' => return Err(Error::ObsFold),
            _ => {}
        }
        // Name, colon, OWS and value in one dispatch.
        let (n, v0, v1) = field_line(&buf[p..]);
        let Some(&stop) = buf.get(p + n) else { return partial(ls) };
        match stop {
            b':' if n > 0 => {}
            b' ' | b'\t' if n > 0 => return Err(Error::WhitespaceBeforeColon),
            _ => return Err(Error::InvalidHeaderName),
        }
        let name = &buf[p..p + n];
        let vs = p + v0;
        p += v1;
        let Some(&cr) = buf.get(p) else { return partial(ls) };
        if cr != b'\r' {
            return Err(if cr == b'\n' { Error::BareLf } else { Error::InvalidHeaderValue });
        }
        let Some(&lf) = buf.get(p + 1) else { return partial(ls) };
        if lf != b'\n' {
            return Err(Error::BareCr);
        }
        let mut ve = p;
        while ve > vs && is_ws(buf[ve - 1]) {
            ve -= 1;
        }
        let value = &buf[vs..ve];
        p += 2;
        if p - ls > lim.max_header_line {
            return Err(Error::HeaderLineTooLong);
        }
        if p - start > max_total {
            return Err(too_large);
        }
        if count >= lim.max_headers || (store && count >= hs.len()) {
            return Err(Error::TooManyHeaders);
        }
        if store {
            hs[count] = Header { name, value };
        }
        count += 1;
        match section {
            Section::Head => sem.field(name, value)?,
            Section::Trailers => {
                if name.eq_ignore_ascii_case(b"content-length")
                    || name.eq_ignore_ascii_case(b"transfer-encoding")
                    || name.eq_ignore_ascii_case(b"host")
                {
                    return Err(Error::ForbiddenTrailer);
                }
            }
        }
    }
}

/// Skips the empty lines a recipient may ignore before a start line (RFC 9112 §2.2).
fn skip_empty_lines(buf: &[u8], lim: &Limits) -> Result<Option<usize>, Error> {
    let mut p = 0;
    loop {
        match buf.get(p) {
            None => return Ok(None),
            Some(b'\r') => match buf.get(p + 1) {
                None => return Ok(None),
                Some(b'\n') => {
                    p += 2;
                    if p > lim.max_head {
                        return Err(Error::HeadTooLarge);
                    }
                }
                Some(_) => return Err(Error::BareCr),
            },
            Some(b'\n') => return Err(Error::BareLf),
            Some(_) => return Ok(Some(p)),
        }
    }
}

/// Checks that the bytes present at offsets 5..8 of a possibly short `HTTP/x.y` are digit, dot,
/// digit.
fn version_shape(v: &[u8]) -> Result<(), Error> {
    let ok = v.iter().enumerate().take(8).skip(5).all(|(i, &b)| if i == 6 { b == b'.' } else { b.is_ascii_digit() });
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidVersion)
    }
}

/// Parses the `HTTP/x.y` at `p` and the CRLF after it; returns the version and the offset after
/// the CRLF, or `None` if more bytes are needed.
fn parse_version_crlf(buf: &[u8], p: usize) -> Result<Option<(Version, usize)>, Error> {
    let rest = &buf[p..];
    let want = b"HTTP/";
    let k = rest.len().min(5);
    if rest[..k] != want[..k] {
        return Err(Error::InvalidVersion);
    }
    if rest.len() < 10 {
        // Judge the bytes that are here, so a short version line ending in CRLF CRLF is an
        // error now rather than a wait for bytes that change nothing.
        version_shape(rest)?;
        if rest.len() == 9 && rest[8] != b'\r' {
            return Err(if rest[8] == b'\n' { Error::BareLf } else { Error::InvalidVersion });
        }
        return Ok(None);
    }
    let version = match &rest[..8] {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        [.., a, b'.', b] if a.is_ascii_digit() && b.is_ascii_digit() => return Err(Error::VersionNotSupported),
        _ => return Err(Error::InvalidVersion),
    };
    match &rest[8..10] {
        b"\r\n" => Ok(Some((version, p + 10))),
        [b'\r', _] => Err(Error::BareCr),
        [b'\n', _] => Err(Error::BareLf),
        _ => Err(Error::InvalidVersion),
    }
}

/// Parses a whole request head from the start of `buf` into `hs`.
///
/// Returns `Partial` until the head is complete; limits are enforced on partial input too. The
/// parse never allocates. For input that arrives in pieces, [`RequestParser`] avoids parsing
/// the same bytes again until a head can be complete.
pub fn parse_request<'b, 'h>(
    buf: &'b [u8],
    hs: &'h mut [Header<'b>],
    lim: &Limits,
) -> Result<Status<Request<'b, 'h>>, Error> {
    let Some(ls) = skip_empty_lines(buf, lim)? else { return Ok(Status::Partial) };
    let line_partial = || -> Result<Status<Request<'b, 'h>>, Error> {
        if buf.len() - ls > lim.max_request_line {
            Err(Error::RequestLineTooLong)
        } else if buf.len() > lim.max_head {
            Err(Error::HeadTooLarge)
        } else {
            Ok(Status::Partial)
        }
    };
    // method SP
    let mut p = ls;
    let n = scan(&buf[p..], &TCHAR);
    let Some(&sp) = buf.get(p + n) else { return line_partial() };
    if n == 0 || sp != b' ' {
        return Err(Error::InvalidMethod);
    }
    let method = &buf[p..p + n];
    p += n + 1;
    // request-target SP
    let t0 = p;
    let mut brackets = false;
    loop {
        p += scan(&buf[p..], &URI);
        let Some(&b) = buf.get(p) else { return line_partial() };
        match b {
            b' ' => break,
            b'%' => {
                if p + 2 >= buf.len() {
                    if buf[p + 1..].iter().all(|&c| hex(c)) {
                        return line_partial();
                    }
                    return Err(Error::InvalidTarget);
                }
                if !hex(buf[p + 1]) || !hex(buf[p + 2]) {
                    return Err(Error::InvalidTarget);
                }
                p += 3;
            }
            b'[' | b']' => {
                brackets = true;
                p += 1;
            }
            _ => return Err(Error::InvalidTarget),
        }
    }
    let target = &buf[t0..p];
    if target.is_empty() {
        return Err(Error::InvalidTarget);
    }
    p += 1;
    let Some((version, after)) = parse_version_crlf(buf, p)? else { return line_partial() };
    if after - ls > lim.max_request_line {
        return Err(Error::RequestLineTooLong);
    }
    let connect = method == b"CONNECT";
    let form = if target[0] == b'/' && !connect {
        if brackets {
            return Err(Error::InvalidTarget);
        }
        TargetForm::Origin
    } else if target == b"*" && method == b"OPTIONS" {
        TargetForm::Asterisk
    } else if connect {
        if !valid_host(target, true) {
            return Err(Error::InvalidTarget);
        }
        TargetForm::Authority
    } else if valid_absolute(target, brackets) {
        TargetForm::Absolute
    } else {
        return Err(Error::InvalidTarget);
    };
    let mut sem = Semantics::default();
    let Some((end, count)) = parse_fields(buf, after, 0, hs, true, lim, Section::Head, &mut sem)? else {
        return Ok(Status::Partial);
    };
    if version == Version::Http11 && sem.hosts == 0 {
        return Err(Error::MissingHost);
    }
    let framing = sem.request_framing(version, lim)?;
    let http11 = version == Version::Http11;
    if sem.expect_other && http11 {
        return Err(Error::ExpectationFailed);
    }
    Ok(Status::Complete(Request {
        method,
        target,
        form,
        version,
        headers: &hs[..count],
        framing,
        keep_alive: sem.keep_alive(version),
        expect_continue: sem.expect_continue && http11,
        upgrade: if sem.conn_upgrade && http11 { sem.upgrade } else { None },
        host: sem.host,
        head_len: end,
    }))
}

/// Incremental request-head parsing for one connection: remembers how far the input was
/// scanned, so a head that trickles in is fully parsed only once the empty line (or a limit)
/// arrives. Eight bytes of state; reset automatically after each complete head or error.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestParser {
    scanned: u32,
    line_start: u32,
}

impl RequestParser {
    /// A parser at the start of a head.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses `buf`, which holds everything received since the head began (the previous call's
    /// bytes plus new ones).
    pub fn parse<'b, 'h>(
        &mut self,
        buf: &'b [u8],
        hs: &'h mut [Header<'b>],
        lim: &Limits,
    ) -> Result<Status<Request<'b, 'h>>, Error> {
        let scanned = self.scanned as usize;
        if scanned > 0 && buf.len() >= scanned {
            let mut i = scanned.saturating_sub(3);
            let mut line_start = self.line_start as usize;
            let mut complete = false;
            while let Some(k) = find_byte(&buf[i..], b'\n') {
                let at = i + k;
                if at >= 3 && &buf[at - 3..=at] == b"\r\n\r\n" {
                    complete = true;
                    break;
                }
                line_start = at + 1;
                i = at + 1;
            }
            let line_limit = if line_start == 0 { lim.max_request_line } else { lim.max_header_line };
            if !complete && buf.len() - line_start <= line_limit && buf.len() <= lim.max_head {
                self.scanned = buf.len() as u32;
                self.line_start = line_start as u32;
                return Ok(Status::Partial);
            }
        }
        let r = parse_request(buf, hs, lim);
        match r {
            Ok(Status::Partial) => {
                self.scanned = buf.len().max(1) as u32;
                self.line_start = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1) as u32;
            }
            _ => *self = Self::default(),
        }
        r
    }

    /// Forgets any partial head.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Parses a response head. `request_method` decides the framing of HEAD and CONNECT replies.
/// A 1xx head is returned like any other; read the next head after it.
pub fn parse_response<'b, 'h>(
    buf: &'b [u8],
    hs: &'h mut [Header<'b>],
    lim: &Limits,
    request_method: &[u8],
) -> Result<Status<Response<'b, 'h>>, Error> {
    let line_partial = || -> Result<Status<Response<'b, 'h>>, Error> {
        if buf.len() > lim.max_request_line {
            Err(Error::RequestLineTooLong)
        } else {
            Ok(Status::Partial)
        }
    };
    let k = buf.len().min(5);
    if buf[..k] != b"HTTP/"[..k] {
        return Err(Error::InvalidVersion);
    }
    if buf.len() < 13 {
        version_shape(buf)?;
        if buf.len() > 8 && buf[8] != b' ' {
            return Err(Error::InvalidVersion);
        }
        if buf.iter().skip(9).any(|b| !b.is_ascii_digit()) {
            return Err(Error::InvalidStatus);
        }
        return line_partial();
    }
    let version = match &buf[..8] {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        [.., a, b'.', b] if a.is_ascii_digit() && b.is_ascii_digit() => return Err(Error::VersionNotSupported),
        _ => return Err(Error::InvalidVersion),
    };
    if buf[8] != b' ' {
        return Err(Error::InvalidVersion);
    }
    let code = &buf[9..12];
    if !code.iter().all(u8::is_ascii_digit) || buf[12] != b' ' {
        return Err(Error::InvalidStatus);
    }
    let status = code.iter().fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
    if !(100..=599).contains(&status) {
        return Err(Error::InvalidStatus);
    }
    let rs = 13;
    let mut p = rs + scan(&buf[rs..], &FIELD_VALUE);
    let Some(&cr) = buf.get(p) else { return line_partial() };
    if cr != b'\r' {
        return Err(if cr == b'\n' { Error::BareLf } else { Error::InvalidReason });
    }
    let Some(&lf) = buf.get(p + 1) else { return line_partial() };
    if lf != b'\n' {
        return Err(Error::BareCr);
    }
    let reason = &buf[rs..p];
    p += 2;
    if p > lim.max_request_line {
        return Err(Error::RequestLineTooLong);
    }
    let mut sem = Semantics::default();
    let Some((end, count)) = parse_fields(buf, p, 0, hs, true, lim, Section::Head, &mut sem)? else {
        return Ok(Status::Partial);
    };
    let ok_connect = request_method == b"CONNECT" && (200..300).contains(&status);
    let upgraded = status == 101 || ok_connect;
    let framing = if request_method == b"HEAD" || status < 200 || status == 204 || status == 304 || ok_connect {
        Framing::None
    } else if sem.te_codings > 0 {
        if sem.content_length.is_some() {
            return Err(Error::TeWithContentLength);
        }
        if sem.te_chunked > 1 {
            return Err(Error::ChunkedNotFinal);
        }
        match (sem.te_last_chunked, sem.te_codings) {
            (true, 1) => Framing::Chunked,
            (true, _) => return Err(Error::UnsupportedTransferCoding),
            (false, _) => Framing::Close,
        }
    } else {
        match sem.content_length {
            Some(0) => Framing::None,
            Some(n) => Framing::Length(n),
            None => Framing::Close,
        }
    };
    Ok(Status::Complete(Response {
        version,
        status,
        reason,
        headers: &hs[..count],
        framing,
        keep_alive: framing != Framing::Close && sem.keep_alive(version),
        upgraded,
        head_len: end,
    }))
}

/// Parses a trailer section as returned by [`BodyEvent::End`](crate::BodyEvent::End): field
/// lines followed by the empty line, or nothing.
pub fn parse_trailers<'b, 'h>(
    section: &'b [u8],
    hs: &'h mut [Header<'b>],
    lim: &Limits,
) -> Result<&'h [Header<'b>], Error> {
    if section.is_empty() {
        return Ok(&hs[..0]);
    }
    let mut sem = Semantics::default();
    match parse_fields(section, 0, 0, hs, true, lim, Section::Trailers, &mut sem)? {
        Some((end, count)) if end == section.len() => Ok(&hs[..count]),
        _ => Err(Error::InvalidHeaderValue),
    }
}

/// Validates a complete trailer section (ending with the empty line) without storing it.
pub(crate) fn check_trailers(section: &[u8], lim: &Limits) -> Result<(), Error> {
    let mut sem = Semantics::default();
    match parse_fields(section, 0, 0, &mut [], false, lim, Section::Trailers, &mut sem)? {
        Some((end, _)) if end == section.len() => Ok(()),
        _ => Err(Error::InvalidHeaderValue),
    }
}
