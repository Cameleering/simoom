//! A small, strict-enough HTTP/1.1 response framer for the load generator: it finds where each
//! response ends (Content-Length, chunked, or no body for 1xx/204/304) and reports the status
//! and whether the server will close the connection.

/// One framed response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framed {
    /// Bytes from the start of the input to the end of this response.
    pub len: usize,
    pub status: u16,
    /// `Connection: close` or HTTP/1.0 without keep-alive.
    pub close: bool,
}

/// Why a response could not be framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Not HTTP, or a malformed header the generator cannot frame.
    Malformed,
    /// No length and not chunked: the body runs to the end of the connection.
    UntilClose,
}

fn find_head_end(d: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(p) = d[i..].iter().position(|&b| b == b'\r') {
        let at = i + p;
        if at + 4 > d.len() {
            return None;
        }
        if &d[at..at + 4] == b"\r\n\r\n" {
            return Some(at + 4);
        }
        i = at + 1;
    }
    None
}

fn parse_usize(v: &[u8]) -> Option<usize> {
    let v = trim(v);
    if v.is_empty() || v.len() > 18 {
        return None;
    }
    let mut n = 0usize;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (b - b'0') as usize;
    }
    Some(n)
}

fn trim(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t' | b'\r', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t' | b'\r'] = v {
        v = rest;
    }
    v
}

/// Frames the response at the front of `d`. `Ok(None)` means more bytes are needed.
/// `head_request` is true when the request was HEAD (no body whatever the headers say).
pub fn frame(d: &[u8], head_request: bool) -> Result<Option<Framed>, FrameError> {
    if d.len() < 12 {
        if d.len() >= 5 && &d[..5] != b"HTTP/" {
            return Err(FrameError::Malformed);
        }
        return Ok(None);
    }
    if &d[..5] != b"HTTP/" || d[8] != b' ' {
        return Err(FrameError::Malformed);
    }
    let s = &d[9..12];
    if !s.iter().all(u8::is_ascii_digit) {
        return Err(FrameError::Malformed);
    }
    let status = (s[0] - b'0') as u16 * 100 + (s[1] - b'0') as u16 * 10 + (s[2] - b'0') as u16;
    let Some(head) = find_head_end(d) else {
        if d.len() > 64 * 1024 {
            return Err(FrameError::Malformed);
        }
        return Ok(None);
    };
    let http10 = &d[5..8] == b"1.0";
    let mut close = http10;
    let mut clen: Option<usize> = None;
    let mut chunked = false;
    let first_eol = d.iter().position(|&b| b == b'\n').unwrap_or(0);
    for line in d[first_eol + 1..head].split(|&b| b == b'\n') {
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            clen = Some(parse_usize(value).ok_or(FrameError::Malformed)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            chunked = trim(value).eq_ignore_ascii_case(b"chunked");
        } else if name.eq_ignore_ascii_case(b"connection") {
            let v = trim(value);
            if v.eq_ignore_ascii_case(b"close") {
                close = true;
            } else if v.eq_ignore_ascii_case(b"keep-alive") {
                close = false;
            }
        }
    }
    if (100..200).contains(&status) || status == 204 || status == 304 || head_request {
        return Ok(Some(Framed { len: head, status, close }));
    }
    if chunked {
        let mut pos = head;
        loop {
            let Some(eol) = d[pos..].iter().position(|&b| b == b'\n') else { return Ok(None) };
            let line = &d[pos..pos + eol];
            let hex = trim(line.split(|&b| b == b';').next().unwrap_or(b""));
            if hex.is_empty() || hex.len() > 15 {
                return Err(FrameError::Malformed);
            }
            let mut n = 0usize;
            for &b in hex {
                let v = (b as char).to_digit(16).ok_or(FrameError::Malformed)? as usize;
                n = n * 16 + v;
            }
            pos += eol + 1;
            if n == 0 {
                // trailers until an empty line
                loop {
                    let Some(eol) = d[pos..].iter().position(|&b| b == b'\n') else { return Ok(None) };
                    let empty = trim(&d[pos..pos + eol]).is_empty();
                    pos += eol + 1;
                    if empty {
                        return Ok(Some(Framed { len: pos, status, close }));
                    }
                }
            }
            if d.len() < pos + n + 2 {
                return Ok(None);
            }
            pos += n + 2;
        }
    }
    match clen {
        Some(n) => {
            if d.len() >= head + n {
                Ok(Some(Framed { len: head + n, status, close }))
            } else {
                Ok(None)
            }
        }
        None => Err(FrameError::UntilClose),
    }
}

/// Builds a request head (and body).
pub fn build_request(method: &str, path: &str, host: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        r.push_str(k);
        r.push_str(": ");
        r.push_str(v);
        r.push_str("\r\n");
    }
    if !body.is_empty() || method == "POST" || method == "PUT" {
        r.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    r.push_str("\r\n");
    let mut v = r.into_bytes();
    v.extend_from_slice(body);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_common_responses() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!HTTP/1.1 404 X\r\n";
        let f = frame(r, false).unwrap().unwrap();
        assert_eq!((f.len, f.status, f.close), (52, 200, false));
        assert_eq!(frame(&r[52..], false), Ok(None));
        assert_eq!(frame(&r[..40], false), Ok(None));
        let c = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let f = frame(c, false).unwrap().unwrap();
        assert_eq!((f.len, f.status, f.close), (c.len(), 200, true));
        for cut in 0..c.len() {
            assert_eq!(frame(&c[..cut], false), Ok(None), "cut {cut}");
        }
        assert_eq!(frame(b"HTTP/1.1 204 No Content\r\n\r\n", false).unwrap().unwrap().len, 27);
        assert_eq!(frame(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", false).unwrap().unwrap().close, true);
        assert_eq!(frame(b"HTTP/1.1 200 OK\r\n\r\nabc", false), Err(FrameError::UntilClose));
        assert_eq!(frame(b"GARBAGE/1.1 200 OK\r\n\r\n", false), Err(FrameError::Malformed));
        assert_eq!(frame(b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n", false), Err(FrameError::Malformed));
    }

    #[test]
    fn frames_pipelined_batches() {
        let one = b"HTTP/1.1 200 OK\r\nServer: x\r\nContent-Length: 2\r\n\r\nok";
        let mut d = Vec::new();
        for _ in 0..16 {
            d.extend_from_slice(one);
        }
        let mut pos = 0;
        let mut n = 0;
        while let Some(f) = frame(&d[pos..], false).unwrap() {
            pos += f.len;
            n += 1;
        }
        assert_eq!((n, pos), (16, d.len()));
    }

    #[test]
    fn builds_requests() {
        let r = build_request("POST", "/echo", "h:1", &[("Content-Type".into(), "application/json".into())], b"{}");
        assert_eq!(r, b"POST /echo HTTP/1.1\r\nHost: h:1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
    }
}
