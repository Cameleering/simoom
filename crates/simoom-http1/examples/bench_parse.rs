//! Parse cost per request head: simoom-http1 with SIMD and with scalar scanning, against the
//! cameleer-http parsing logic (copied below, unchanged in substance, so there is no
//! dependency on it).
//!
//! ```text
//! cargo run --release -p simoom-http1 --example bench_parse
//! ```

use simoom_http1::write::{DateCache, HeadWriter, StaticHead};
use simoom_http1::*;
use simoom_sys::scan::{force, level, Level};
use std::hint::black_box;
use std::time::Instant;

const CURL: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n";

const BROWSER: &[u8] = b"GET /index.html?q=1 HTTP/1.1\r\nHost: www.example.com\r\nConnection: keep-alive\r\nsec-ch-ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"Windows\"\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nSec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-User: ?1\r\nSec-Fetch-Dest: document\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: session=8f2a9c1d4e5b6a7f8091a2b3c4d5e6f7; theme=dark; _ga=GA1.1.123456789.1700000000\r\n\r\n";

fn twenty_headers() -> Vec<u8> {
    let mut s = b"POST /api/v1/orders HTTP/1.1\r\nHost: api.internal:8443\r\nContent-Type: application/json\r\nContent-Length: 128\r\n".to_vec();
    for i in 0..17 {
        s.extend_from_slice(format!("X-Custom-Header-{i}: value-{i}-abcdefghijklmnop\r\n").as_bytes());
    }
    s.extend_from_slice(b"\r\n");
    s
}

/// Best of several rounds, in nanoseconds per call.
fn measure(mut f: impl FnMut()) -> f64 {
    let mut iters = 1_000u64;
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        if t.elapsed().as_millis() >= 50 {
            break;
        }
        iters *= 4;
    }
    (0..7)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        })
        .fold(f64::INFINITY, f64::min)
}

fn simoom(req: &[u8]) -> usize {
    let mut hs = [EMPTY_HEADER; 32];
    match parse_request(black_box(req), &mut hs, &Limits::default()) {
        Ok(Status::Complete(r)) => r.head_len + r.headers.len(),
        other => panic!("{other:?}"),
    }
}

fn main() {
    let twenty = twenty_headers();
    let cases: [(&str, &[u8]); 3] = [("curl (3 fields)", CURL), ("browser (15 fields)", BROWSER), ("20 fields", &twenty)];
    let best = level();
    println!("scan level detected: {best:?}");
    println!("{:<22} {:>6} {:>12} {:>12} {:>14} {:>9}", "request", "bytes", "simd ns", "scalar ns", "cameleer ns", "GB/s simd");
    for (name, req) in cases {
        assert!(cameleer::parse(req).is_ok());
        force(best);
        let simd = measure(|| {
            black_box(simoom(req));
        });
        force(Level::Scalar);
        let scalar = measure(|| {
            black_box(simoom(req));
        });
        force(best);
        let cam = measure(|| {
            black_box(cameleer::parse(black_box(req)).ok());
        });
        println!(
            "{name:<22} {:>6} {simd:>12.1} {scalar:>12.1} {cam:>14.1} {:>9.2}",
            req.len(),
            req.len() as f64 / simd
        );
    }
    // Serialization.
    let date = DateCache::new(1_700_000_000);
    let mut out = Vec::with_capacity(256);
    let head = measure(|| {
        out.clear();
        let mut w = HeadWriter::response(&mut out, 200);
        w.header(b"Content-Type", b"application/json").unwrap().date(&date).content_length(1234);
        w.finish();
        black_box(&out);
    });
    let mut fixed = StaticHead::new(200, &[(b"Content-Type", b"text/plain"), (b"Server", b"simoom")], b"Hello, World!").unwrap();
    let mut secs = 1_700_000_000;
    let mut dc = DateCache::new(secs);
    let stat = measure(|| {
        black_box(fixed.full(&dc).len());
    });
    let stat_tick = measure(|| {
        secs += 1;
        dc.update(secs);
        black_box(fixed.full(&dc).len());
    });
    println!("HeadWriter (status, 1 field, Date, Content-Length): {head:.1} ns");
    println!("StaticHead::full (fixed reply, same second): {stat:.1} ns; with a new second every call: {stat_tick:.1} ns");
}

/// The request-head parsing path of `cameleer-http` (`crates/cameleer-http/src/http.rs`:
/// `read_line`, `read_head`, `body_kind`, the request-line split, Host check and target
/// handling), copied here so the comparison has no dependency. It reads through `BufRead` and
/// builds owned `String`s, as the original does.
mod cameleer {
    // Copied as is: some fields are built but not read here, exactly as in the original.
    #![allow(dead_code)]

    use std::io::BufRead;

    #[derive(Debug)]
    pub enum HttpError {
        BadRequest(String),
        HeaderTooLarge,
        UnexpectedEof,
        NotImplemented(String),
        PayloadTooLarge,
        Io,
    }

    #[derive(Default)]
    pub struct HttpHeaders {
        entries: Vec<(String, String)>,
    }

    impl HttpHeaders {
        fn get_all(&self, name: &str) -> Vec<&str> {
            self.entries.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
        }
        fn contains(&self, name: &str) -> bool {
            self.entries.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
        }
    }

    pub struct HttpRequest {
        pub method: String,
        pub target: String,
        pub headers: HttpHeaders,
    }

    #[derive(Debug)]
    pub enum BodyKind {
        None,
        Length(usize),
        Chunked,
    }

    fn read_line<R: BufRead>(r: &mut R, budget: &mut usize) -> Result<Option<String>, HttpError> {
        let mut buf = Vec::new();
        loop {
            let available = r.fill_buf().map_err(|_| HttpError::Io)?;
            if available.is_empty() {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(HttpError::UnexpectedEof);
            }
            let (consume, done) = match available.iter().position(|&b| b == b'\n') {
                Some(i) => (i + 1, true),
                None => (available.len(), false),
            };
            if consume > *budget {
                return Err(HttpError::HeaderTooLarge);
            }
            *budget -= consume;
            buf.extend_from_slice(&available[..consume]);
            r.consume(consume);
            if done {
                break;
            }
        }
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        String::from_utf8(buf).map(Some).map_err(|_| HttpError::BadRequest("invalid UTF-8 in header".into()))
    }

    fn is_token(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    }

    fn read_head<R: BufRead>(r: &mut R) -> Result<Option<(String, HttpHeaders)>, HttpError> {
        let mut budget = 16 * 1024;
        let start = loop {
            match read_line(r, &mut budget)? {
                None => return Ok(None),
                Some(l) if l.is_empty() => continue,
                Some(l) => break l,
            }
        };
        let mut headers = HttpHeaders::default();
        loop {
            let line = read_line(r, &mut budget)?.ok_or(HttpError::UnexpectedEof)?;
            if line.is_empty() {
                break;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(HttpError::BadRequest("obsolete header line folding".into()));
            }
            let colon = line.find(':').ok_or_else(|| HttpError::BadRequest(format!("malformed header: {}", line)))?;
            let name = &line[..colon];
            if !is_token(name) {
                return Err(HttpError::BadRequest(format!("invalid header name: {}", name)));
            }
            if headers.entries.len() >= 100 {
                return Err(HttpError::HeaderTooLarge);
            }
            headers.entries.push((name.to_string(), line[colon + 1..].trim().to_string()));
        }
        Ok(Some((start, headers)))
    }

    fn body_kind(headers: &HttpHeaders) -> Result<BodyKind, HttpError> {
        if let Some(te) = headers.get_all("Transfer-Encoding").last().copied() {
            let last = te.split(',').next_back().map(|s| s.trim().to_ascii_lowercase()).unwrap_or_default();
            if last == "chunked" {
                return Ok(BodyKind::Chunked);
            }
            return Err(HttpError::NotImplemented(format!("Transfer-Encoding: {}", te)));
        }
        let lengths = headers.get_all("Content-Length");
        if !lengths.is_empty() {
            let mut value: Option<usize> = None;
            for l in lengths {
                for part in l.split(',') {
                    let part = part.trim();
                    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(HttpError::BadRequest(format!("invalid Content-Length: {}", l)));
                    }
                    let n: usize = part.parse().map_err(|_| HttpError::PayloadTooLarge)?;
                    if value.is_some_and(|v| v != n) {
                        return Err(HttpError::BadRequest("conflicting Content-Length values".into()));
                    }
                    value = Some(n);
                }
            }
            return Ok(BodyKind::Length(value.unwrap_or(0)));
        }
        Ok(BodyKind::None)
    }

    pub fn parse(mut input: &[u8]) -> Result<(HttpRequest, BodyKind), HttpError> {
        let (start, headers) = read_head(&mut input)?.ok_or(HttpError::UnexpectedEof)?;
        let mut parts = start.split(' ').filter(|s| !s.is_empty());
        let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(m), Some(t), Some(v), None) => (m, t, v),
            _ => return Err(HttpError::BadRequest(format!("malformed request line: {}", start))),
        };
        if !is_token(method) {
            return Err(HttpError::BadRequest(format!("invalid method: {}", method)));
        }
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return Err(HttpError::BadRequest(format!("unsupported version: {}", version)));
        }
        if version == "HTTP/1.1" && !headers.contains("Host") {
            return Err(HttpError::BadRequest("missing Host header".into()));
        }
        let target = if let Some(rest) = target.strip_prefix("http://").or_else(|| target.strip_prefix("https://")) {
            match rest.find('/') {
                Some(i) => rest[i..].to_string(),
                None => "/".to_string(),
            }
        } else {
            target.to_string()
        };
        if !target.starts_with('/') && target != "*" {
            return Err(HttpError::BadRequest(format!("invalid request target: {}", target)));
        }
        let kind = body_kind(&headers)?;
        Ok((HttpRequest { method: method.to_string(), target, headers }, kind))
    }
}
