//! Request-body encodings: `application/x-www-form-urlencoded` and request-body compression
//! (`Content-Encoding: gzip`, `deflate`, and with features `compress-br` / `compress-zstd`,
//! `br` and `zstd`, through simoom-compress).
//!
//! ```no_run
//! use simoom_client::{encode::Coding, Client};
//!
//! let c = Client::new();
//! c.post("https://example.test/login").form([("user", "ann"), ("pass", "s3cret & more")]).send().unwrap();
//! # #[cfg(feature = "compress")]
//! c.post("https://example.test/ingest").body(vec![b'x'; 1 << 20]).compress(Coding::Gzip).send().unwrap();
//! ```
//!
//! Only compress bodies for servers known to accept the coding: HTTP has no negotiation for
//! request bodies, and a server that does not decode answers `415`.

/// The `application/x-www-form-urlencoded` serialisation of `pairs` (the WHATWG URL
/// standard's byte serializer: `*-._`, digits and letters as they are, space as `+`, every
/// other byte of the UTF-8 text as `%XX`).
pub fn form_urlencode<K: AsRef<str>, V: AsRef<str>>(pairs: impl IntoIterator<Item = (K, V)>) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        push_form(&mut out, k.as_ref());
        out.push('=');
        push_form(&mut out, v.as_ref());
    }
    out
}

fn push_form(out: &mut String, s: &str) {
    for b in s.bytes() {
        match b {
            b'*' | b'-' | b'.' | b'_' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
}

/// Parses `application/x-www-form-urlencoded` text (WHATWG): `&`-separated, `+` as space,
/// `%XX` decoded (invalid escapes kept), the first `=` splits name from value, invalid UTF-8
/// replaced.
pub fn form_urldecode(s: &str) -> Vec<(String, String)> {
    let dec = |p: &str| -> String {
        let b = p.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < b.len() => {
                    let h = |c: u8| (c as char).to_digit(16);
                    match (h(b[i + 1]), h(b[i + 2])) {
                        (Some(x), Some(y)) => {
                            out.push((x * 16 + y) as u8);
                            i += 3;
                            continue;
                        }
                        _ => out.push(b'%'),
                    }
                }
                c => out.push(c),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (dec(k), dec(v)),
            None => (dec(p), String::new()),
        })
        .collect()
}

impl crate::client::RequestBuilder {
    /// An `application/x-www-form-urlencoded` body from name and value pairs (sets
    /// `Content-Type`).
    pub fn form<K: AsRef<str>, V: AsRef<str>>(self, pairs: impl IntoIterator<Item = (K, V)>) -> Self {
        let body = form_urlencode(pairs);
        self.map(|r| r.headers.set("Content-Type", "application/x-www-form-urlencoded")).body(body)
    }
}

/// A content coding for request bodies (feature `compress`).
#[cfg(feature = "compress")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Coding {
    /// `gzip`.
    Gzip,
    /// `deflate` (zlib, RFC 9110 §8.4.1.2).
    Deflate,
    /// `br` (feature `compress-br`).
    #[cfg(feature = "compress-br")]
    Brotli,
    /// `zstd` (feature `compress-zstd`).
    #[cfg(feature = "compress-zstd")]
    Zstd,
}

#[cfg(feature = "compress")]
impl Coding {
    fn format(self) -> simoom_compress::Format {
        match self {
            Coding::Gzip => simoom_compress::Format::Gzip,
            Coding::Deflate => simoom_compress::Format::Zlib,
            #[cfg(feature = "compress-br")]
            Coding::Brotli => simoom_compress::Format::Brotli,
            #[cfg(feature = "compress-zstd")]
            Coding::Zstd => simoom_compress::Format::Zstd,
        }
    }

    /// The `Content-Encoding` token.
    pub fn token(self) -> &'static str {
        self.format().content_encoding()
    }

    /// The default level: 6 for gzip and deflate, 5 for Brotli, 3 for zstd.
    pub fn default_level(self) -> u32 {
        match self {
            #[cfg(feature = "compress-br")]
            Coding::Brotli => 5,
            #[cfg(feature = "compress-zstd")]
            Coding::Zstd => 3,
            _ => 6,
        }
    }
}

/// Compresses a reader as it is read.
#[cfg(feature = "compress")]
struct CompressReader {
    inner: Box<dyn std::io::Read + Send>,
    enc: simoom_compress::Encoder,
    out: Vec<u8>,
    pos: usize,
    done: bool,
    buf: Vec<u8>,
}

#[cfg(feature = "compress")]
impl std::io::Read for CompressReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.pos == self.out.len() {
            if self.done {
                return Ok(0);
            }
            self.out.clear();
            self.pos = 0;
            let n = self.inner.read(&mut self.buf)?;
            if n == 0 {
                self.enc.finish(&mut self.out);
                self.done = true;
            } else {
                self.enc.encode(&self.buf[..n], &mut self.out);
            }
        }
        let n = (self.out.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(feature = "compress")]
impl crate::client::RequestBuilder {
    /// Compresses the body with `coding` at its default level (see [`Coding::default_level`])
    /// and adds it to `Content-Encoding`. An in-memory body is compressed now and keeps a
    /// `Content-Length`; a streamed body is compressed as it is sent (chunked on HTTP/1.1). An
    /// empty body is left alone.
    pub fn compress(self, coding: Coding) -> Self {
        self.compress_level(coding, coding.default_level())
    }

    /// [`RequestBuilder::compress`](crate::RequestBuilder::compress) at `level` (DEFLATE 0-9,
    /// Brotli 0-11, zstd 1-22; clamped).
    pub fn compress_level(self, coding: Coding, level: u32) -> Self {
        use crate::types::Body;
        self.map(|r| {
            let body = std::mem::replace(&mut r.body, Body::Empty);
            r.body = match body {
                Body::Empty => return,
                Body::Bytes(b) => Body::Bytes(simoom_compress::compress(&b, coding.format(), level)),
                Body::Reader { reader, .. } => Body::Reader {
                    reader: Box::new(CompressReader { inner: reader, enc: simoom_compress::Encoder::new(coding.format(), level), out: Vec::new(), pos: 0, done: false, buf: vec![0u8; 32 * 1024] }),
                    len: None,
                },
            };
            let v = match r.headers.get("content-encoding") {
                Some(old) if !old.trim().is_empty() => format!("{old}, {}", coding.token()),
                _ => coding.token().to_string(),
            };
            r.headers.set("Content-Encoding", v);
            r.headers.remove("content-length");
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_round_trip() {
        let s = form_urlencode([("name", "Ann Lee"), ("q", "a&b=c+d/é*-._~")]);
        assert_eq!(s, "name=Ann+Lee&q=a%26b%3Dc%2Bd%2F%C3%A9*-._%7E");
        assert_eq!(form_urldecode(&s), vec![("name".to_string(), "Ann Lee".to_string()), ("q".to_string(), "a&b=c+d/é*-._~".to_string())]);
        assert_eq!(form_urldecode("a&&b=1=2&%zz=%4"), vec![("a".into(), "".into()), ("b".into(), "1=2".into()), ("%zz".into(), "%4".into())]);
        assert_eq!(form_urlencode(Vec::<(&str, &str)>::new()), "");
    }
}
