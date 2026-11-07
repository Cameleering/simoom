//! A slow, plain reference request parser written straight from the RFC 9112 / RFC 9110 /
//! RFC 3986 ABNF, with the same policy choices as simoom-http1 (reject TE with CL, duplicate
//! CL, non-final chunked, obs-fold, bare CR/LF, whitespace before the colon). It works on whole
//! heads with ordinary string handling and shares no code with the fast parser.
#![allow(dead_code)]

use simoom_http1::{Framing, Limits, TargetForm, Version};

#[derive(Debug, PartialEq, Eq)]
pub enum RefResult {
    Complete(RefReq),
    /// No empty line yet, and no limit passed.
    Incomplete,
    Rejected(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
pub struct RefReq {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub form: TargetForm,
    pub version: Version,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub framing: Framing,
    pub keep_alive: bool,
    pub expect: bool,
    pub upgrade: Option<Vec<u8>>,
    pub host: Option<Vec<u8>>,
    pub head_len: usize,
}

// RFC 5234 core rules and RFC 9110 / 3986 character classes.
fn alpha(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_lowercase()
}
fn digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn hexdig(c: u8) -> bool {
    digit(c) || (b'A'..=b'F').contains(&c) || (b'a'..=b'f').contains(&c)
}
fn vchar(c: u8) -> bool {
    (0x21..=0x7e).contains(&c)
}
fn obs_text(c: u8) -> bool {
    c >= 0x80
}
fn tchar(c: u8) -> bool {
    alpha(c) || digit(c) || "!#$%&'*+-.^_`|~".as_bytes().contains(&c)
}
fn token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&c| tchar(c))
}
fn unreserved(c: u8) -> bool {
    alpha(c) || digit(c) || "-._~".as_bytes().contains(&c)
}
fn sub_delim(c: u8) -> bool {
    "!$&'()*+,;=".as_bytes().contains(&c)
}
fn pchar_or_query(c: u8) -> bool {
    unreserved(c) || sub_delim(c) || c == b':' || c == b'@' || c == b'/' || c == b'?'
}

/// Every byte is a URI character (pct-encoded included); brackets allowed here, checked by form.
fn uri_chars(t: &[u8]) -> bool {
    let mut i = 0;
    while i < t.len() {
        let c = t[i];
        if c == b'%' {
            if i + 2 < t.len() && hexdig(t[i + 1]) && hexdig(t[i + 2]) {
                i += 3;
                continue;
            }
            return false;
        }
        if !(pchar_or_query(c) || c == b'[' || c == b']') {
            return false;
        }
        i += 1;
    }
    true
}

/// uri-host [ ":" port ]
fn host_port(v: &[u8], need_port: bool) -> bool {
    if v.is_empty() {
        return !need_port;
    }
    let (host_ok, rest): (bool, &[u8]) = if v[0] == b'[' {
        match v.iter().position(|&c| c == b']') {
            None => (false, b""),
            Some(e) => {
                let inner = &v[1..e];
                (!inner.is_empty() && inner.iter().all(|&c| hexdig(c) || c == b':' || c == b'.'), &v[e + 1..])
            }
        }
    } else {
        let colon = v.iter().position(|&c| c == b':').unwrap_or(v.len());
        let reg = &v[..colon];
        let mut ok = !reg.is_empty();
        let mut i = 0;
        while ok && i < reg.len() {
            if reg[i] == b'%' {
                ok = i + 2 < reg.len() && hexdig(reg[i + 1]) && hexdig(reg[i + 2]);
                i += 3;
            } else {
                ok = unreserved(reg[i]) || sub_delim(reg[i]);
                i += 1;
            }
        }
        (ok, &v[colon..])
    };
    if !host_ok {
        return false;
    }
    if rest.is_empty() {
        return !need_port;
    }
    rest[0] == b':' && rest[1..].iter().all(|&c| digit(c)) && (!need_port || rest.len() > 1)
}

fn target_form(method: &[u8], t: &[u8]) -> Option<TargetForm> {
    if t.is_empty() || !uri_chars(t) {
        return None;
    }
    let brackets = t.contains(&b'[') || t.contains(&b']');
    if method == b"CONNECT" {
        return host_port(t, true).then_some(TargetForm::Authority);
    }
    if t[0] == b'/' {
        return (!brackets).then_some(TargetForm::Origin);
    }
    if t == b"*" {
        return (method == b"OPTIONS").then_some(TargetForm::Asterisk);
    }
    // absolute-URI = scheme ":" hier-part [ "?" query ]
    let colon = t.iter().position(|&c| c == b':')?;
    let scheme = &t[..colon];
    if scheme.is_empty() || !alpha(scheme[0]) || !scheme.iter().all(|&c| alpha(c) || digit(c) || c == b'+' || c == b'-' || c == b'.') {
        return None;
    }
    // RFC 9110 §4.2.4: userinfo in an http(s) authority is treated as an error.
    if let Some(rest) = t[colon + 1..].strip_prefix(b"//") {
        let end = rest.iter().position(|&c| c == b'/' || c == b'?').unwrap_or(rest.len());
        if rest[..end].contains(&b'@') {
            return None;
        }
    }
    if brackets {
        let rest = t[colon + 1..].strip_prefix(b"//")?;
        let end = rest.iter().position(|&c| c == b'/' || c == b'?').unwrap_or(rest.len());
        let authority = &rest[..end];
        let hostport = match authority.iter().rposition(|&c| c == b'@') {
            Some(a) => &authority[a + 1..],
            None => authority,
        };
        if rest[end..].contains(&b'[') || rest[end..].contains(&b']') || !host_port(hostport, false) {
            return None;
        }
    }
    Some(TargetForm::Absolute)
}

fn ows_trim(v: &[u8]) -> &[u8] {
    let s = v.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(v.len());
    let e = v.iter().rposition(|&c| c != b' ' && c != b'\t').map_or(s, |e| e + 1);
    &v[s..e]
}

fn list(v: &[u8]) -> Vec<&[u8]> {
    v.split(|&c| c == b',').map(ows_trim).collect()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn parse(input: &[u8], lim: &Limits) -> RefResult {
    use RefResult::*;
    // Leading empty lines (RFC 9112 §2.2).
    let mut start = 0;
    while input[start..].starts_with(b"\r\n") {
        start += 2;
    }
    let Some(rel) = find(&input[start..], b"\r\n\r\n") else {
        // Incomplete: only limits can be judged.
        let first_line_open = find(&input[start..], b"\r\n").is_none();
        if first_line_open && input.len() - start > lim.max_request_line {
            return Rejected("request line too long");
        }
        if input.len() > lim.max_head {
            return Rejected("head too large");
        }
        return Incomplete;
    };
    let head_len = start + rel + 4;
    if head_len > lim.max_head {
        return Rejected("head too large");
    }
    let text = &input[start..start + rel + 2];
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = text;
    while let Some(i) = find(rest, b"\r\n") {
        lines.push(&rest[..i]);
        rest = &rest[i + 2..];
    }
    for l in &lines {
        if l.contains(&b'\r') || l.contains(&b'\n') {
            return Rejected("bare CR or LF");
        }
    }
    // request-line = method SP request-target SP HTTP-version
    let line = lines[0];
    if line.len() + 2 > lim.max_request_line {
        return Rejected("request line too long");
    }
    let parts: Vec<&[u8]> = line.split(|&c| c == b' ').collect();
    if parts.len() != 3 || !token(parts[0]) {
        return Rejected("request line");
    }
    let (method, target, ver) = (parts[0], parts[1], parts[2]);
    let version = match ver {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        _ => return Rejected("version"),
    };
    let Some(form) = target_form(method, target) else { return Rejected("target") };
    // field-line = field-name ":" OWS field-value OWS
    let fields = &lines[1..];
    if fields.len() > lim.max_headers {
        return Rejected("too many fields");
    }
    let mut headers = Vec::new();
    for l in fields {
        if l.len() + 2 > lim.max_header_line {
            return Rejected("field line too long");
        }
        let Some(colon) = l.iter().position(|&c| c == b':') else { return Rejected("no colon") };
        let name = &l[..colon];
        if !token(name) {
            return Rejected("field name");
        }
        let value = ows_trim(&l[colon + 1..]);
        if !value.iter().all(|&c| c == b' ' || c == b'\t' || vchar(c) || obs_text(c)) {
            return Rejected("field value");
        }
        headers.push((name.to_vec(), value.to_vec()));
    }
    let named = |n: &str| -> Vec<&[u8]> {
        headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(n.as_bytes())).map(|(_, v)| v.as_slice()).collect()
    };
    let hosts = named("host");
    if hosts.len() > 1 {
        return Rejected("duplicate host");
    }
    if hosts.len() == 1 && !host_port(hosts[0], false) {
        return Rejected("host value");
    }
    let upgrades = named("upgrade");
    if upgrades.len() > 1 {
        return Rejected("duplicate upgrade");
    }
    let cls = named("content-length");
    if cls.len() > 1 {
        return Rejected("duplicate content-length");
    }
    let cl = match cls.first() {
        None => None,
        Some(v) => {
            if v.is_empty() || !v.iter().all(|&c| digit(c)) {
                return Rejected("content-length value");
            }
            match std::str::from_utf8(v).unwrap().parse::<u64>() {
                Ok(n) => Some(n),
                Err(_) => return Rejected("content-length overflow"),
            }
        }
    };
    let mut codings: Vec<&[u8]> = Vec::new();
    for v in named("transfer-encoding") {
        for c in list(v) {
            if !token(c) {
                return Rejected("transfer-coding");
            }
            codings.push(c);
        }
    }
    let conn: Vec<&[u8]> = named("connection").into_iter().flat_map(list).collect();
    let has = |t: &str| conn.iter().any(|c| c.eq_ignore_ascii_case(t.as_bytes()));
    if version == Version::Http11 && hosts.is_empty() {
        return Rejected("missing host");
    }
    let framing = if !codings.is_empty() {
        if cl.is_some() {
            return Rejected("te with cl");
        }
        if version == Version::Http10 {
            return Rejected("te in 1.0");
        }
        let is_chunked = |c: &&[u8]| c.eq_ignore_ascii_case(b"chunked");
        if codings.iter().filter(|c| is_chunked(c)).count() != 1 || !is_chunked(codings.last().unwrap()) {
            return Rejected("chunked not final");
        }
        if codings.len() > 1 {
            return Rejected("unsupported coding");
        }
        Framing::Chunked
    } else {
        match cl {
            Some(n) if n > lim.max_body => return Rejected("body too large"),
            Some(0) | None => Framing::None,
            Some(n) => Framing::Length(n),
        }
    };
    let expects = named("expect");
    let expect = !expects.is_empty() && expects.iter().all(|v| v.eq_ignore_ascii_case(b"100-continue"));
    let http11 = version == Version::Http11;
    if http11 && !expects.is_empty() && !expect {
        return Rejected("expectation");
    }
    Complete(RefReq {
        method: method.to_vec(),
        target: target.to_vec(),
        form,
        version,
        headers: headers.clone(),
        framing,
        keep_alive: !has("close") && (http11 || has("keep-alive")),
        expect: expect && http11,
        upgrade: if http11 && has("upgrade") { upgrades.first().map(|u| u.to_vec()) } else { None },
        host: hosts.first().map(|h| h.to_vec()),
        head_len,
    })
}
