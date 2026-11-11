//! Request-body helpers against simoom's server: multipart/form-data round trips (in memory,
//! streamed with and without lengths, HTTP/1.1 and HTTP/2), form-urlencoded bodies, and
//! request-body compression decoded on the server side.
#![cfg(any(feature = "multipart", feature = "encode"))]

mod common;

use simoom::{Outcome, Reply, Request, Response, Server, ServerHandle};
use simoom_client::Client;
#[cfg(feature = "multipart")]
use simoom_client::HttpVersion;
use std::io::Read;

/// Echoes the request body; `x-ct`, `x-ce`, `x-te` and `x-len` report the request headers.
fn echo(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let h = |n: &str| req.header(n).map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
    let (ct, ce, te, len) = (h("content-type"), h("content-encoding"), h("transfer-encoding"), h("content-length"));
    match req.take_body() {
        Some(mut src) => {
            let r = reply.defer();
            std::thread::spawn(move || {
                let mut v = Vec::new();
                src.read_to_end(&mut v).unwrap();
                r.send(Response::new(200).header("x-ct", ct).header("x-ce", ce).header("x-te", te).header("x-len", len).body(v));
            });
            Outcome::Deferred
        }
        None => {
            let b = req.body().to_vec();
            reply.header("x-ct", ct).header("x-ce", ce).header("x-te", te).header("x-len", len).body(b)
        }
    }
}

fn server() -> ServerHandle {
    Server::builder().listen("127.0.0.1:0").threads(2).service(echo).start().expect("server")
}

fn url(h: &ServerHandle) -> String {
    format!("http://127.0.0.1:{}/echo", h.local_addrs()[0].port())
}

/// A minimal multipart/form-data parser (RFC 7578) for the checks: (headers, data) per part.
#[cfg(feature = "multipart")]
fn parse_multipart(body: &[u8], boundary: &str) -> Vec<(String, Vec<u8>)> {
    let delim = format!("--{boundary}");
    let find = |hay: &[u8], from: usize, n: &[u8]| hay[from..].windows(n.len()).position(|w| w == n).map(|p| p + from);
    let mut out = Vec::new();
    let mut at = find(body, 0, delim.as_bytes()).expect("first boundary") + delim.len();
    loop {
        if body[at..].starts_with(b"--") {
            break;
        }
        assert!(body[at..].starts_with(b"\r\n"));
        at += 2;
        let head_end = find(body, at, b"\r\n\r\n").expect("part head");
        let head = String::from_utf8_lossy(&body[at..head_end]).into_owned();
        let data_start = head_end + 4;
        let next = find(body, data_start, format!("\r\n{delim}").as_bytes()).expect("next boundary");
        out.push((head, body[data_start..next].to_vec()));
        at = next + 2 + delim.len();
    }
    out
}

#[cfg(feature = "multipart")]
#[test]
fn multipart_round_trips() {
    use simoom_client::multipart::{Multipart, Part};
    let h = server();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    for version in [HttpVersion::Http1, HttpVersion::Http2] {
        for streamed_len in [None, Some(big.len() as u64)] {
            let form = Multipart::new()
                .text("title", "Q3 report – draft")
                .file("small", "a \"quoted\".txt", "text/plain; charset=utf-8", b"hello\r\n--not-a-boundary".to_vec())
                .part("big", Part::reader(std::io::Cursor::new(big.clone()), streamed_len).file_name("big.bin"));
            let r = Client::new().post(&url(&h)).version(version).multipart(form).send().unwrap();
            let ct = r.header("x-ct").unwrap().to_string();
            let te = r.header("x-te").unwrap_or("").to_string();
            let len = r.header("x-len").unwrap_or("").to_string();
            let body = r.bytes().unwrap();
            let boundary = ct.strip_prefix("multipart/form-data; boundary=").expect("content type");
            if version == HttpVersion::Http1 {
                // a length when every part's length is known, chunked otherwise
                match streamed_len {
                    Some(_) => assert_eq!(len, body.len().to_string()),
                    None => assert_eq!(te, "chunked"),
                }
            }
            let parts = parse_multipart(&body, boundary);
            assert_eq!(parts.len(), 3);
            assert_eq!(parts[0].0, "Content-Disposition: form-data; name=\"title\"");
            assert_eq!(String::from_utf8(parts[0].1.clone()).unwrap(), "Q3 report – draft");
            assert!(parts[1].0.contains("filename=\"a %22quoted%22.txt\"") && parts[1].0.contains("Content-Type: text/plain; charset=utf-8"), "{}", parts[1].0);
            assert_eq!(parts[1].1, b"hello\r\n--not-a-boundary");
            assert!(parts[2].0.contains("filename=\"big.bin\"") && parts[2].0.contains("application/octet-stream"));
            assert!(parts[2].1 == big, "{version:?} {streamed_len:?}");
        }
    }
}

#[cfg(feature = "encode")]
#[test]
fn form_urlencoded_round_trip() {
    let h = server();
    let r = Client::new().post(&url(&h)).form([("user", "ann lee"), ("next", "/a?b=c&d")]).send().unwrap();
    assert_eq!(r.header("x-ct"), Some("application/x-www-form-urlencoded"));
    let t = r.text().unwrap();
    assert_eq!(t, "user=ann+lee&next=%2Fa%3Fb%3Dc%26d");
    assert_eq!(simoom_client::encode::form_urldecode(&t), vec![("user".into(), "ann lee".into()), ("next".into(), "/a?b=c&d".into())]);
}

#[cfg(feature = "encode")]
#[test]
fn request_body_compression() {
    use simoom_client::encode::Coding;
    let h = server();
    let data: Vec<u8> = b"the quick brown fox jumps over the lazy dog. ".iter().cycle().take(200_000).copied().collect();
    #[allow(unused_mut)]
    let mut codings = vec![(Coding::Gzip, simoom_compress::Format::Gzip), (Coding::Deflate, simoom_compress::Format::Zlib)];
    #[cfg(feature = "compress-br")]
    codings.push((Coding::Brotli, simoom_compress::Format::Brotli));
    #[cfg(feature = "compress-zstd")]
    codings.push((Coding::Zstd, simoom_compress::Format::Zstd));
    // the server echoes the bytes as received (a client that decompresses responses would undo
    // gzip on the way back, so turn that off)
    let c = Client::builder().decompress(false).build();
    for (coding, fmt) in codings {
        for streamed in [false, true] {
            let rb = c.post(&url(&h)).header("Content-Encoding", "identity-marker");
            let rb = if streamed { rb.body(simoom_client::Body::reader(std::io::Cursor::new(data.clone()))) } else { rb.body(data.clone()) };
            let r = rb.compress(coding).send().unwrap();
            assert_eq!(r.header("x-ce").unwrap(), format!("identity-marker, {}", coding.token()));
            if streamed {
                assert_eq!(r.header("x-te"), Some("chunked"));
            }
            let sent = r.bytes().unwrap();
            assert!(sent.len() < data.len() / 4, "{coding:?}: {} bytes", sent.len());
            assert_eq!(simoom_compress::decompress(&sent, fmt, 1 << 24).unwrap(), data, "{coding:?} streamed={streamed}");
        }
    }
    // an empty body is left alone
    let r = c.post(&url(&h)).compress(Coding::Gzip).send().unwrap();
    assert_eq!(r.header("x-ce"), Some(""));
}
