//! L7 server helpers through a running server: multipart uploads (buffered and streamed),
//! cookies, conditional and range requests, CORS.

#![cfg(all(feature = "http1", feature = "multipart", feature = "cookies", feature = "conditional", feature = "cors"))]

mod common;

use common::*;
use simoom::conditional::Validators;
use simoom::cookie::{SameSite, SetCookie};
use simoom::cors::Cors;
use simoom::multipart::{boundary, MultipartEvent, MultipartLimits, MultipartParser};
use simoom::{blocking, Limits, OwnedRequest, Reply, Request, Response};
use std::io::Read;
use std::time::{Duration, SystemTime};

const DOC: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

fn app(req: &mut Request<'_>, reply: Reply<'_>) -> simoom::Outcome {
    let lm = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    match req.path() {
        b"/upload" => match req.multipart(&MultipartLimits::default()) {
            Ok(parts) => {
                let s: Vec<String> = parts.iter().map(|p| format!("{}={}", p.head.name.clone().unwrap_or_default(), p.data.len())).collect();
                reply.body(s.join(","))
            }
            Err(e) => reply.status(e.status()).body(e.to_string()),
        },
        b"/cookies" => {
            let sid = req.cookie("sid").map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
            reply
                .cookie(&SetCookie::new("seen", "yes").path("/").http_only(true).same_site(SameSite::Strict))
                .cookie(&SetCookie::removal("old"))
                .body(format!("sid={sid} n={}", req.cookies().len()))
        }
        b"/doc" => reply.content(req, DOC, "text/plain", &Validators { etag: Some("\"v1\""), last_modified: Some(lm) }),
        _ => reply.body("plain"),
    }
}

fn send(h: &simoom::ServerHandle, raw: &str) -> Resp {
    let mut c = Client::new(h);
    c.send(raw.as_bytes());
    c.read()
}

#[test]
fn multipart_uploads() {
    let h = serve(app);
    let body = "--zz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--zz\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n0123456789\r\n--zz--\r\n";
    let r = send(&h, &format!("POST /upload HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=zz\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
    assert_eq!(r.text(), "a=5,f=10");
    let r = send(&h, "POST /upload HTTP/1.1\r\nHost: t\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nx");
    assert_eq!(r.status, 400);
    h.stop(Duration::from_secs(1));
    // streamed: a large upload through a BodySource
    let h = serve_with(
        Limits { body_buffer: 1024, ..Limits::default() },
        blocking(|mut req: OwnedRequest| {
            let b = boundary(req.header("content-type").unwrap_or(b"")).unwrap();
            let mut src = req.take_body().expect("streamed");
            let mut p = MultipartParser::new(&b, MultipartLimits::default());
            let mut sizes: Vec<usize> = Vec::new();
            let mut buf = [0u8; 3000];
            loop {
                let n = src.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                p.feed(&buf[..n], &mut |e| match e {
                    MultipartEvent::Start(_) => sizes.push(0),
                    MultipartEvent::Data(d) => *sizes.last_mut().unwrap() += d.len(),
                    MultipartEvent::End => {}
                })
                .unwrap();
            }
            p.finish().unwrap();
            Response::text(format!("{sizes:?}"))
        }),
    );
    let big = "x".repeat(200_000);
    let body = format!("--B\r\nContent-Disposition: form-data; name=\"big\"\r\n\r\n{big}\r\n--B\r\nContent-Disposition: form-data; name=\"small\"\r\n\r\nok\r\n--B--");
    let r = send(&h, &format!("POST /u HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
    assert_eq!(r.text(), "[200000, 2]");
    h.stop(Duration::from_secs(1));
}

#[test]
fn cookies_in_and_out() {
    let h = serve(app);
    let r = send(&h, "GET /cookies HTTP/1.1\r\nHost: t\r\nCookie: a=1; sid=xyz\r\nCookie: b=2\r\n\r\n");
    assert_eq!(r.text(), "sid=xyz n=3");
    let sc: Vec<&str> = r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.as_str()).collect();
    assert_eq!(sc, ["seen=yes; Path=/; HttpOnly; SameSite=Strict", "old=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0"]);
    h.stop(Duration::from_secs(1));
}

#[test]
fn conditional_and_range_requests() {
    let h = serve(app);
    let lm = "Tue, 14 Nov 2023 22:13:20 GMT";
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!((r.status, r.header("etag"), r.header("last-modified"), r.header("accept-ranges")), (200, Some("\"v1\""), Some(lm), Some("bytes")));
    assert_eq!(r.body, DOC);
    for hdr in ["If-None-Match: \"v1\"", "If-None-Match: W/\"v1\", \"v2\"", &format!("If-Modified-Since: {lm}")] {
        let r = send(&h, &format!("GET /doc HTTP/1.1\r\nHost: t\r\n{hdr}\r\n\r\n"));
        assert_eq!((r.status, r.body.len()), (304, 0), "{hdr}");
    }
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: Mon, 13 Nov 2023 00:00:00 GMT\r\n\r\n");
    assert_eq!(r.status, 200);
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nIf-Match: \"other\"\r\n\r\n");
    assert_eq!(r.status, 412);
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nRange: bytes=0-9\r\n\r\n");
    assert_eq!((r.status, r.header("content-range"), &r.body[..]), (206, Some("bytes 0-9/36"), &b"0123456789"[..]));
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nRange: bytes=-3\r\n\r\n");
    assert_eq!(r.body, b"xyz");
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nRange: bytes=0-1,30-31\r\n\r\n");
    assert_eq!(r.status, 206);
    let ct = r.header("content-type").unwrap().to_string();
    assert!(ct.starts_with("multipart/byteranges; boundary="), "{ct}");
    let parts = simoom::multipart::parse(&r.body, &boundary(ct.as_bytes()).unwrap(), &MultipartLimits::default()).unwrap();
    assert_eq!(parts.iter().map(|p| p.data.clone()).collect::<Vec<_>>(), [b"01".to_vec(), b"uv".to_vec()]);
    assert_eq!(parts[1].head.headers.iter().find(|(n, _)| n == "content-range").unwrap().1, "bytes 30-31/36");
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nRange: bytes=100-\r\n\r\n");
    assert_eq!((r.status, r.header("content-range")), (416, Some("bytes */36")));
    // a stale If-Range gets the whole document
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nRange: bytes=0-1\r\nIf-Range: \"v0\"\r\n\r\n");
    assert_eq!((r.status, r.body.len()), (200, 36));
    let r = send(&h, "GET /doc HTTP/1.1\r\nHost: t\r\nRange: bytes=0-1\r\nIf-Range: \"v1\"\r\n\r\n");
    assert_eq!(r.status, 206);
    h.stop(Duration::from_secs(1));
}

#[test]
fn cors_preflight_and_actual() {
    let cors = Cors::new().allow_origin("https://app.example").allow_methods(&["GET", "PUT"]).allow_headers(&["x-token"]).expose_headers(&["x-trace"]).allow_credentials(true).max_age(600);
    let h = serve(cors.wrap(app));
    let r = send(&h, "OPTIONS /x HTTP/1.1\r\nHost: t\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: X-Token\r\n\r\n");
    assert_eq!(r.status, 204);
    assert_eq!(r.header("access-control-allow-origin"), Some("https://app.example"));
    assert_eq!(r.header("access-control-allow-methods"), Some("GET, PUT"));
    assert_eq!(r.header("access-control-allow-headers"), Some("x-token"));
    assert_eq!(r.header("access-control-max-age"), Some("600"));
    assert_eq!(r.header("access-control-allow-credentials"), Some("true"));
    // a method or header not allowed: no grant
    let r = send(&h, "OPTIONS /x HTTP/1.1\r\nHost: t\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: DELETE\r\n\r\n");
    assert_eq!((r.status, r.header("access-control-allow-methods")), (204, None));
    // actual request
    let r = send(&h, "GET /x HTTP/1.1\r\nHost: t\r\nOrigin: https://app.example\r\n\r\n");
    assert_eq!((r.text().as_str(), r.header("access-control-allow-origin"), r.header("access-control-expose-headers")), ("plain", Some("https://app.example"), Some("x-trace")));
    assert!(r.headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("vary") && v == "origin"));
    // another origin: no CORS headers; no origin: untouched
    let r = send(&h, "GET /x HTTP/1.1\r\nHost: t\r\nOrigin: https://evil.example\r\n\r\n");
    assert_eq!(r.header("access-control-allow-origin"), None);
    let r = send(&h, "GET /x HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!((r.text().as_str(), r.header("vary")), ("plain", None));
    h.stop(Duration::from_secs(1));
    let h = serve(Cors::new().allow_any_origin().wrap(app));
    let r = send(&h, "GET /x HTTP/1.1\r\nHost: t\r\nOrigin: https://any.example\r\n\r\n");
    assert_eq!((r.header("access-control-allow-origin"), r.header("vary")), (Some("*"), None));
    h.stop(Duration::from_secs(1));
}
