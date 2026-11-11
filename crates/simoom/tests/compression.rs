//! Response compression and request body decoding (feature `compression`): negotiation, the
//! rules for what is compressed, every way to answer (immediate, deferred, offloaded,
//! streamed), HTTP/1.1 and HTTP/2.

#![cfg(all(feature = "compression", feature = "http1"))]

mod common;

use common::*;
use simoom::{blocking, BodySink, Compression, Limits, OwnedRequest, Reply, Request, Response, Server, ServerHandle};
use simoom_compress::{decompress, Format};
use std::io::Read;

const JSON: &str = r#"{"id":1,"name":"widget","tags":["a","b","c"],"price":12.5,"stock":100}"#;

fn json(n: usize) -> String {
    format!("[{}]", vec![JSON; n].join(","))
}

fn service(req: &mut Request<'_>, reply: Reply<'_>) -> simoom::Outcome {
    let body = json(50);
    match req.path() {
        b"/json" => reply.header("content-type", "application/json").body(body),
        b"/png" => reply.header("content-type", "image/png").body(body),
        b"/none" => reply.body(body),
        b"/small" => reply.header("content-type", "text/plain").body("short"),
        b"/coded" => reply.header("content-type", "text/plain").header("content-encoding", "br").body(body),
        b"/etag" => reply.header("content-type", "text/html").header("etag", "\"abc\"").body(body),
        b"/204" => reply.status(204).header("content-type", "text/plain").empty(),
        b"/deferred" => {
            let r = reply.header("content-type", "text/plain").defer();
            std::thread::spawn(move || {
                r.send(Response::text(json(40)).header("content-type", "application/json"));
            });
            simoom::Outcome::Deferred
        }
        b"/stream" => {
            let mut sink: BodySink = reply.header("content-type", "text/plain").stream();
            std::thread::spawn(move || {
                for i in 0..20 {
                    sink.write(format!("line {i} {JSON}\n").as_bytes()).unwrap();
                }
                sink.finish();
            });
            simoom::Outcome::Deferred
        }
        b"/echo" => match req.decoded_body(1 << 20) {
            Ok(b) => reply.header("content-type", "text/plain").body(format!("{} bytes: {}", b.len(), String::from_utf8_lossy(&b[..b.len().min(20)]))),
            Err(e) => reply.status(e.status()).body(e.to_string()),
        },
        _ => reply.status(404).empty(),
    }
}

fn start(c: Compression) -> ServerHandle {
    Server::builder().listen("127.0.0.1:0").threads(1).compression(c).service(service).start().unwrap()
}

fn get_with(h: &ServerHandle, path: &str, accept: Option<&str>) -> Resp {
    let mut c = Client::new(h);
    let ae = accept.map(|a| format!("Accept-Encoding: {a}\r\n")).unwrap_or_default();
    c.send(format!("GET {path} HTTP/1.1\r\nHost: t\r\n{ae}\r\n").as_bytes());
    c.read()
}

fn plain(r: &Resp) -> Vec<u8> {
    match r.header("content-encoding") {
        Some("gzip") => decompress(&r.body, Format::Gzip, 1 << 24).unwrap(),
        Some("deflate") => decompress(&r.body, Format::Zlib, 1 << 24).unwrap(),
        #[cfg(feature = "brotli")]
        Some("br") => decompress(&r.body, Format::Brotli, 1 << 24).unwrap(),
        #[cfg(feature = "zstd")]
        Some("zstd") => decompress(&r.body, Format::Zstd, 1 << 24).unwrap(),
        None => r.body.clone(),
        Some(o) => panic!("unexpected coding {o}"),
    }
}

#[test]
fn negotiated_responses_on_http1() {
    let h = start(Compression::new());
    let want = json(50);
    // gzip, deflate, preference by q, refusal
    for (accept, coding) in [(Some("gzip, deflate"), Some("gzip")), (Some("deflate"), Some("deflate")), (Some("gzip;q=0.2, deflate;q=0.9"), Some("deflate")), (Some("compress"), None), (None, None), (Some("gzip;q=0"), None)] {
        let r = get_with(&h, "/json", accept);
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-encoding"), coding, "{accept:?}");
        assert_eq!(r.header("vary"), Some("accept-encoding"), "{accept:?}");
        assert_eq!(r.header("content-length").map(|l| l.parse::<usize>().unwrap()), Some(r.body.len()));
        assert_eq!(plain(&r), want.as_bytes());
        if coding.is_some() {
            assert!(r.body.len() * 5 < want.len(), "{} vs {}", r.body.len(), want.len());
        }
    }
    // not compressed: already-compressed type, no type, small, coded by the service, 204
    for path in ["/png", "/none", "/small", "/coded"] {
        let r = get_with(&h, path, Some("gzip"));
        let ce = r.header("content-encoding");
        assert!(ce.is_none() || ce == Some("br"), "{path}");
        assert_eq!(r.header("vary"), None, "{path}");
    }
    let r = get_with(&h, "/204", Some("gzip"));
    assert_eq!((r.status, r.header("content-encoding")), (204, None));
    // a strong etag becomes weak
    let r = get_with(&h, "/etag", Some("gzip"));
    assert_eq!(r.header("etag"), Some("W/\"abc\""));
    let r = get_with(&h, "/etag", None);
    assert_eq!(r.header("etag"), Some("\"abc\""));
    // HEAD: same headers, no body
    let mut c = Client::new(&h);
    c.send(b"HEAD /json HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n");
    let r = c.read_any(b"HEAD", false).unwrap();
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert!(r.body.is_empty());
    h.stop(std::time::Duration::from_secs(1));
}

#[test]
fn deferred_offloaded_and_streamed_replies() {
    let h = start(Compression::new().streams(true).level(1));
    let r = get_with(&h, "/deferred", Some("gzip"));
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert_eq!(plain(&r), json(40).as_bytes());
    let r = get_with(&h, "/stream", Some("gzip"));
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    let text = String::from_utf8(plain(&r)).unwrap();
    assert_eq!(text.lines().count(), 20);
    assert!(text.starts_with("line 0 "));
    // without `streams`, streamed bodies are left alone
    let h2 = start(Compression::new());
    let r = get_with(&h2, "/stream", Some("gzip"));
    assert_eq!(r.header("content-encoding"), None);
    assert_eq!(String::from_utf8(r.body).unwrap().lines().count(), 20);
    // offloaded (blocking) replies go through the responder
    let h3 = Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .compression(Compression::new())
        .service(blocking(|_r: OwnedRequest| Response::text(json(30)).header("content-type", "text/csv")))
        .start()
        .unwrap();
    let r = get_with(&h3, "/x", Some("deflate, gzip"));
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert_eq!(plain(&r), json(30).as_bytes());
    for h in [h, h2, h3] {
        h.stop(std::time::Duration::from_secs(1));
    }
}

#[test]
fn streamed_chunks_arrive_promptly() {
    // Each write is flushed: the client can decode it before the body ends.
    let h = Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .compression(Compression::new().streams(true))
        .service(|_r: &mut Request<'_>, reply: Reply<'_>| {
            let mut sink = reply.sse();
            std::thread::spawn(move || {
                sink.send_event("first event, long enough to matter").unwrap();
                std::thread::sleep(std::time::Duration::from_millis(400));
                sink.send_event("second").unwrap();
            });
            simoom::Outcome::Deferred
        })
        .start()
        .unwrap();
    let mut s = connect(&h);
    use std::io::Write;
    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n").unwrap();
    let t0 = std::time::Instant::now();
    let mut got = Vec::new();
    let mut dec = simoom_compress::Decoder::new(Format::Gzip);
    let mut plain = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&plain).contains("first event") {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
        // body starts after the head; chunk framing: "<hex>\r\n<data>\r\n"
        if let Some(p) = find(&got, b"\r\n\r\n") {
            let mut body = &got[p + 4..];
            plain.clear();
            dec.reset();
            while let Some(e) = find(body, b"\r\n") {
                let len = usize::from_str_radix(std::str::from_utf8(&body[..e]).unwrap(), 16).unwrap();
                if body.len() < e + 2 + len + 2 {
                    break;
                }
                dec.decode(&body[e + 2..e + 2 + len], &mut plain).unwrap();
                body = &body[e + 2 + len + 2..];
            }
        }
    }
    assert!(t0.elapsed() < std::time::Duration::from_millis(350), "the first event waited for the second");
    h.stop(std::time::Duration::from_secs(1));
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[test]
fn request_bodies_are_decoded_on_request() {
    let h = Server::builder().listen("127.0.0.1:0").threads(1).limits(Limits::default()).service(service).start().unwrap();
    let body = "x".repeat(10_000);
    for (coding, data) in [("gzip", simoom_compress::compress(body.as_bytes(), Format::Gzip, 6)), ("deflate", simoom_compress::compress(body.as_bytes(), Format::Zlib, 6))] {
        let mut c = Client::new(&h);
        let mut req = format!("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n", data.len()).into_bytes();
        req.extend_from_slice(&data);
        c.send(&req);
        let r = c.read();
        assert_eq!((r.status, r.text()), (200, "10000 bytes: xxxxxxxxxxxxxxxxxxxx".to_string()));
    }
    // unknown coding: 415; corrupt: 400
    for (coding, data, status) in [("compress", b"abc".to_vec(), 415), ("gzip", b"not gzip".to_vec(), 400)] {
        let mut c = Client::new(&h);
        let mut req = format!("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n", data.len()).into_bytes();
        req.extend_from_slice(&data);
        c.send(&req);
        assert_eq!(c.read().status, status);
    }
    // a bomb: 413
    let bomb = simoom_compress::compress(&vec![0u8; 5 << 20], Format::Gzip, 9);
    let mut c = Client::new(&h);
    let mut req = format!("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", bomb.len()).into_bytes();
    req.extend_from_slice(&bomb);
    c.send(&req);
    assert_eq!(c.read().status, 413);
    h.stop(std::time::Duration::from_secs(1));
}

#[test]
fn streamed_request_bodies_are_decoded() {
    let h = serve_with(
        Limits { body_buffer: 1024, ..Limits::default() },
        blocking(|mut req: OwnedRequest| {
            let coding = req.header("content-encoding").map(|v| v.to_vec());
            let src = req.take_body().expect("streamed");
            let mut r = simoom::DecodedRead::new(src, coding.as_deref(), 1 << 20).unwrap();
            let mut v = Vec::new();
            match r.read_to_end(&mut v) {
                Ok(_) => Response::text(format!("{}", v.len())),
                Err(e) => Response::new(400).body(e.to_string()),
            }
        }),
    );
    let mut x = 1u32;
    let body: Vec<u8> = (0..200_000)
        .map(|i| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            if i % 3 == 0 {
                (x >> 24) as u8
            } else {
                b'a' + (i % 7) as u8
            }
        })
        .collect();
    let gz = simoom_compress::compress(&body, Format::Gzip, 6);
    assert!(gz.len() > 1024, "streamed, not buffered");
    let mut c = Client::new(&h);
    let mut req = format!("POST /up HTTP/1.1\r\nHost: t\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", gz.len()).into_bytes();
    req.extend_from_slice(&gz);
    c.send(&req);
    assert_eq!(c.read().text(), "200000");
    h.stop(std::time::Duration::from_secs(1));
}

#[cfg(feature = "http2")]
#[test]
fn negotiated_responses_on_http2() {
    use simoom_h2::{Config, Connection, Event};
    use std::io::Write;
    let h = start(Compression::new());
    let mut s = connect(&h);
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    let mut conn = Connection::client(Config::default());
    let id = conn.send_request(b"GET", b"http", b"t", b"/json", &[(b"accept-encoding", b"gzip")], true).unwrap();
    let (mut status, mut ce, mut body, mut done) = (0, None, Vec::new(), false);
    let mut buf = vec![0u8; 65536];
    let mut inbuf = Vec::new();
    while !done {
        let out = conn.output().to_vec();
        conn.advance_output(out.len());
        s.write_all(&out).unwrap();
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0);
        inbuf.extend_from_slice(&buf[..n]);
        let used = conn.recv(&inbuf, 0, &mut |e| match e {
            Event::Headers { stream, headers, .. } if stream == id => {
                status = headers.status().unwrap_or(0);
                ce = headers.get(b"content-encoding").map(|v| v.to_vec());
            }
            Event::Data { stream, data, end_stream } if stream == id => {
                body.extend_from_slice(data);
                done |= end_stream;
            }
            _ => {}
        });
        inbuf.drain(..used);
    }
    assert_eq!(status, 200);
    assert_eq!(ce.as_deref(), Some(&b"gzip"[..]));
    assert_eq!(decompress(&body, Format::Gzip, 1 << 20).unwrap(), json(50).as_bytes());
    h.stop(std::time::Duration::from_secs(1));
}

#[cfg(all(feature = "brotli", feature = "zstd"))]
#[test]
fn brotli_and_zstd_responses() {
    use simoom::ContentCoding;
    let h = start(Compression::new().streams(true));
    let want = json(50);
    // equal q-values: the server's preference (zstd, br, gzip); q-values win over preference
    for (accept, coding) in [("gzip, deflate, br, zstd", "zstd"), ("gzip, br", "br"), ("zstd;q=0.5, br", "br"), ("gzip;q=1, zstd;q=0.9", "gzip")] {
        let r = get_with(&h, "/json", Some(accept));
        assert_eq!(r.header("content-encoding"), Some(coding), "{accept}");
        assert_eq!(plain(&r), want.as_bytes());
    }
    // deferred and streamed bodies too
    let r = get_with(&h, "/deferred", Some("br"));
    assert_eq!((r.header("content-encoding"), plain(&r)), (Some("br"), json(40).into_bytes()));
    let r = get_with(&h, "/stream", Some("zstd"));
    assert_eq!(r.header("content-encoding"), Some("zstd"));
    assert_eq!(String::from_utf8(plain(&r)).unwrap().lines().count(), 20);
    // a server that prefers Brotli, and bodies under the threshold fall back to gzip
    let h2 = start(Compression::new().preference(&[ContentCoding::Brotli, ContentCoding::Zstd, ContentCoding::Gzip]).modern_min_size(1 << 20));
    let r = get_with(&h2, "/json", Some("zstd, br, gzip"));
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    let h3 = start(Compression::new().preference(&[ContentCoding::Brotli, ContentCoding::Zstd]));
    let r = get_with(&h3, "/json", Some("zstd, br, gzip"));
    assert_eq!(r.header("content-encoding"), Some("br"));
    // request bodies in br and zstd decode
    for (coding, f) in [("br", Format::Brotli), ("zstd", Format::Zstd)] {
        let data = simoom_compress::compress(&b"y".repeat(5000), f, 5);
        let mut c = Client::new(&h);
        let mut req = format!("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n", data.len()).into_bytes();
        req.extend_from_slice(&data);
        c.send(&req);
        assert_eq!(c.read().text(), "5000 bytes: yyyyyyyyyyyyyyyyyyyy");
    }
    for h in [h, h2, h3] {
        h.stop(std::time::Duration::from_secs(1));
    }
}
