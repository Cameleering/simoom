//! HTTP/1.1 against simoom and scripted servers: methods, headers, pooling, streaming bodies,
//! 100-continue, redirects, status checks, timeouts, proxies.

mod common;

use common::{client, plain, raw, read_head, read_n, url};
use simoom_client::{Body, Client, ErrorKind, HttpVersion, ProxyAddr, ProxyConfig, TimeoutKind, Version};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn get_post_headers_query() {
    let h = plain();
    let c = client().user_agent(Some("simoom-test/1".into())).build();
    let r = c.get(&url(&h, "/echo")).query("x", "a b&c").header("X-Custom", "1").send().unwrap();
    assert_eq!((r.status(), r.version(), r.reason()), (200, Version::Http11, "OK"));
    assert_eq!(r.header("content-type"), Some("text/plain"));
    assert_eq!(r.headers().get_all("x-multi").collect::<Vec<_>>(), vec!["a", "b"]);
    let t = r.text().unwrap();
    assert!(t.starts_with("Http11 GET /echo q=a b&c"), "{t}");
    assert!(t.contains("ua=simoom-test/1"), "{t}");
    assert!(t.contains(&format!("host=127.0.0.1:{}", h.local_addrs()[0].port())), "{t}");

    let r = c.post(&url(&h, "/echo")).header("Content-Type", "application/json").body("{\"a\":1}").send().unwrap();
    let t = r.text().unwrap();
    assert!(t.contains("POST /echo") && t.contains("ct=application/json") && t.ends_with("len=7"), "{t}");

    // PUT with an empty body sends Content-Length: 0; HEAD has no body
    let r = c.put(&url(&h, "/echo")).send().unwrap();
    assert!(r.text().unwrap().ends_with("len=0"));
    let r = c.head(&url(&h, "/echo")).send().unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.bytes().unwrap().is_empty());

    // Basic credentials from the builder and from the URL
    let r = c.get(&url(&h, "/echo")).basic_auth("u", "p").send().unwrap();
    assert!(r.text().unwrap().contains("auth=Basic dTpw"));
    let u = format!("http://u:p@127.0.0.1:{}/echo", h.local_addrs()[0].port());
    assert!(c.get(&u).send().unwrap().text().unwrap().contains("auth=Basic dTpw"));
}

#[test]
fn keep_alive_pool_reuses_connections() {
    let h = plain();
    let c = client().build();
    for _ in 0..20 {
        assert_eq!(c.get(&url(&h, "/echo")).send().unwrap().bytes().unwrap().len() > 0, true);
    }
    let s = c.pool_stats();
    assert_eq!((s.idle, s.http1), (1, 1), "{s:?}");
    // Concurrent requests use several connections, all returned afterwards.
    let ts: Vec<_> = (0..8)
        .map(|_| {
            let (c, u) = (c.clone(), url(&h, "/slow?ms=50"));
            std::thread::spawn(move || c.get(&u).send().unwrap().text().unwrap())
        })
        .collect();
    for t in ts {
        assert_eq!(t.join().unwrap(), "slow done");
    }
    let s = c.pool_stats();
    assert!(s.http1 >= 2 && s.idle == s.http1, "{s:?}");
    // keep_alive off: Connection: close, nothing pooled
    let c2 = client().keep_alive(false).build();
    let r = c2.get(&url(&h, "/echo")).send().unwrap();
    assert_eq!(r.header("connection"), Some("close"));
    drop(r);
    assert_eq!(c2.pool_stats().idle, 0);
}

#[test]
fn max_connections_and_pool_timeout() {
    let h = plain();
    let c = client().max_connections_per_origin(1).pool_timeout(Some(Duration::from_millis(200))).build();
    // Hold the only connection by not reading a streamed body.
    let held = c.get(&url(&h, "/stream?parts=50")).send().unwrap();
    let e = c.get(&url(&h, "/echo")).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Timeout(TimeoutKind::Pool), "{e}");
    assert_eq!(held.text().unwrap().matches("part").count(), 50);
    // the slot is free again
    assert_eq!(c.get(&url(&h, "/echo")).send().unwrap().status(), 200);
}

#[test]
fn max_requests_per_connection() {
    let srv = raw(|mut s, _| {
        while let Some(_) = read_head(&mut s) {
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
        }
    });
    let c = Client::builder().max_requests_per_connection(Some(3)).build();
    for _ in 0..7 {
        assert_eq!(c.get(&format!("http://{}/", srv.addr)).send().unwrap().text().unwrap(), "ok");
    }
    assert_eq!(srv.accepted.load(Ordering::SeqCst), 3);
}

#[test]
fn stale_pooled_connection_is_retried() {
    // The server answers one request per connection without saying `Connection: close`.
    let srv = raw(|mut s, _| {
        if read_head(&mut s).is_some() {
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
        }
    });
    let c = Client::new();
    for _ in 0..5 {
        assert_eq!(c.get(&format!("http://{}/", srv.addr)).send().unwrap().text().unwrap(), "ok");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(srv.accepted.load(Ordering::SeqCst), 5);
}

#[test]
fn chunked_and_close_delimited_responses_and_trailers() {
    let h = plain();
    let c = client().build();
    let r = c.get(&url(&h, "/stream?parts=5")).send().unwrap();
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    assert_eq!(r.text().unwrap(), "part0;part1;part2;part3;part4;");

    let srv = raw(|mut s, n| {
        read_head(&mut s);
        if n == 0 {
            s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: x-sum\r\n\r\n5\r\nhello\r\n0\r\nx-sum: 42\r\n\r\n").unwrap();
            read_head(&mut s);
        } else {
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\nuntil close").unwrap();
        }
    });
    let c = Client::new();
    let mut r = c.get(&format!("http://{}/", srv.addr)).send().unwrap();
    let mut body = Vec::new();
    r.body_mut().read_to_end(&mut body).unwrap();
    assert_eq!(body, b"hello");
    assert_eq!(r.trailers().unwrap().get("x-sum"), Some("42"));
    let r = c.get(&format!("http://{}/x", srv.addr)).send().unwrap();
    assert_eq!(r.text().unwrap(), "until close");
}

#[test]
fn large_response_streams_with_small_reads() {
    let h = plain();
    let c = client().build();
    let n = 5_000_000;
    let r = c.get(&url(&h, &format!("/big?n={n}"))).send().unwrap();
    assert_eq!(r.content_length(), Some(n as u64));
    let mut body = r.into_body();
    let mut buf = [0u8; 1000];
    let mut total = 0usize;
    loop {
        let k = body.read(&mut buf).unwrap();
        if k == 0 {
            break;
        }
        for (i, &b) in buf[..k].iter().enumerate() {
            assert_eq!(b, ((total + i) % 251) as u8);
        }
        total += k;
    }
    assert_eq!(total, n);
    assert_eq!(c.pool_stats().idle, 1, "connection returned after the body");
    // max_body
    let c2 = client().max_body(Some(1000)).build();
    let e = c2.get(&url(&h, "/big?n=5000")).send().unwrap().bytes().unwrap_err();
    assert!(e.message.contains("limit"), "{e}");
}

/// A reader that produces `n` bytes in small pieces, slowly enough to interleave.
struct Gen {
    left: usize,
    i: usize,
}

impl Read for Gen {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = buf.len().min(self.left).min(7777);
        for b in &mut buf[..k] {
            *b = (self.i % 253) as u8;
            self.i += 1;
        }
        self.left -= k;
        Ok(k)
    }
}

fn checksum(n: usize) -> u64 {
    (0..n).fold(0u64, |a, i| a.wrapping_mul(31).wrapping_add((i % 253) as u64))
}

#[test]
fn streamed_request_bodies_chunked_and_sized() {
    let h = plain();
    let c = client().build();
    let n = 3_000_000;
    let r = c.post(&url(&h, "/upload")).body(Body::reader(Gen { left: n, i: 0 })).send().unwrap();
    assert_eq!(r.text().unwrap(), format!("{n} {}", checksum(n)));
    let r = c.post(&url(&h, "/upload")).body(Body::sized_reader(Gen { left: n, i: 0 }, n as u64)).send().unwrap();
    assert_eq!(r.text().unwrap(), format!("{n} {}", checksum(n)));
    // a sized reader that lies is refused
    let e = c.post(&url(&h, "/upload")).body(Body::sized_reader(Gen { left: 10, i: 0 }, 20)).send().unwrap_err();
    assert!(e.message.contains("shorter") || e.kind == ErrorKind::Closed || matches!(e.kind, ErrorKind::Io(_)), "{e}");
    // the chunked request reached the server as chunked
    let srv = raw(|mut s, _| {
        let head = read_head(&mut s).unwrap();
        let chunked = head.to_ascii_lowercase().contains("transfer-encoding: chunked");
        let mut rest = Vec::new();
        let mut b = [0u8; 1024];
        while !rest.ends_with(b"0\r\n\r\n") {
            let k = s.read(&mut b).unwrap();
            rest.extend_from_slice(&b[..k]);
        }
        let msg = format!("chunked={chunked} raw={}", rest.len());
        s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{msg}", msg.len()).as_bytes()).unwrap();
    });
    let r = Client::new().post(&format!("http://{}/", srv.addr)).body(Body::reader(&b"abc"[..])).send().unwrap();
    assert_eq!(r.text().unwrap(), "chunked=true raw=13");
}

#[test]
fn expect_continue() {
    let h = plain();
    let c = client().build();
    let body = vec![9u8; 200_000];
    let r = c.post(&url(&h, "/upload")).expect_continue(true).body(body.clone()).send().unwrap();
    let sum = body.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64));
    assert_eq!(r.text().unwrap(), format!("200000 {sum}"));

    // A server that refuses before the body: the body is not sent.
    let srv = raw(|mut s, _| {
        let head = read_head(&mut s).unwrap();
        assert!(head.to_ascii_lowercase().contains("expect: 100-continue"));
        s.write_all(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let mut b = [0u8; 16];
        let got = s.read(&mut b).unwrap_or(0);
        assert_eq!(got, 0, "the body must not follow a final answer");
    });
    let r = Client::new().post(&format!("http://{}/", srv.addr)).expect_continue(true).body(vec![1u8; 1000]).send().unwrap();
    assert_eq!(r.status(), 417);
    // A server that ignores Expect: the body goes after the expect timeout.
    let srv = raw(|mut s, _| {
        read_head(&mut s).unwrap();
        let b = read_n(&mut s, 5);
        s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}", String::from_utf8_lossy(&b)).as_bytes()).unwrap();
    });
    let c = Client::builder().expect_timeout(Duration::from_millis(100)).build();
    let t = Instant::now();
    let r = c.post(&format!("http://{}/", srv.addr)).expect_continue(true).body("hello").send().unwrap();
    assert_eq!(r.text().unwrap(), "hello");
    assert!(t.elapsed() >= Duration::from_millis(90));
}

#[test]
fn redirects() {
    let h = plain();
    let c = client().build();
    // not followed by default (Camel followRedirects=false)
    let r = c.get(&url(&h, "/redirect?to=/echo")).send().unwrap();
    assert_eq!((r.status(), r.header("location")), (302, Some("/echo")));
    drop(r);
    let c = client().follow_redirects(true).build();
    let r = c.post(&url(&h, "/redirect?code=303&to=/echo")).body("data").send().unwrap();
    assert_eq!(r.url().path, "/echo");
    let t = r.text().unwrap();
    assert!(t.contains("GET /echo") && t.ends_with("len=0"), "303 turns POST into GET: {t}");
    let r = c.post(&url(&h, "/redirect?code=307&to=/echo")).body("data").send().unwrap();
    assert!(r.text().unwrap().contains("POST /echo"), "307 keeps the method");
    let r = c.put(&url(&h, "/redirect?code=308&to=echo")).body("abcd").send().unwrap();
    let t = r.text().unwrap();
    assert!(t.contains("PUT /echo") && t.ends_with("len=4"), "{t}");
    // a loop
    let e = c.get(&url(&h, "/loop")).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::TooManyRedirects);
    // credentials are dropped on a redirect to another origin
    let other = plain();
    let to = url(&other, "/echo");
    let r = c.get(&url(&h, &format!("/redirect?to={}", simoom_client::percent_encode(&to)))).basic_auth("u", "p").send().unwrap();
    let t = r.text().unwrap();
    assert!(t.contains("auth= "), "{t}");
    // ... and kept on the same origin
    let r = c.get(&url(&h, "/redirect?to=/echo")).basic_auth("u", "p").send().unwrap();
    assert!(r.text().unwrap().contains("auth=Basic"));
    // a streamed body cannot be replayed: the 307 is returned
    let r = c.post(&url(&h, "/redirect?code=307&to=/echo")).body(Body::reader(&b"xyz"[..])).send().unwrap();
    assert_eq!(r.status(), 307);
}

#[test]
fn status_checks_like_throw_exception_on_failure() {
    let h = plain();
    let c = client().ok_status(Some(vec![(200, 299)])).build();
    let e = c.get(&url(&h, "/status?code=404")).send().unwrap_err();
    let s = e.status().expect("status error");
    assert_eq!((s.status, s.status_text.as_str(), &s.body[..]), (404, "Not Found", &b"status 404"[..]));
    assert!(s.headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("x-reason") && v == "test"));
    assert!(e.message.contains("with statusCode: 404"), "{e}");
    let e = client().build().get(&url(&h, "/redirect?to=/x")).ok_status(&[(200, 299)]).send().unwrap_err();
    assert_eq!(e.status().unwrap().location.as_deref(), Some("/x"));
    assert!(e.message.contains("redirectLocation: /x"));
    // throwExceptionOnFailure=false
    assert_eq!(c.get(&url(&h, "/status?code=500")).accept_any_status().send().unwrap().status(), 500);
    // custom ranges
    assert_eq!(c.get(&url(&h, "/status?code=404")).ok_status(&[(200, 204), (404, 404)]).send().unwrap().status(), 404);
}

#[test]
fn timeouts() {
    // connect refused
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let e = Client::new().get(&format!("http://127.0.0.1:{port}/")).send().unwrap_err();
    assert!(e.is_connect(), "{e}");
    // response head
    let srv = raw(|mut s, _| {
        read_head(&mut s);
        std::thread::sleep(Duration::from_secs(3));
    });
    let c = Client::builder().response_timeout(Some(Duration::from_millis(200))).build();
    let t = Instant::now();
    let e = c.get(&format!("http://{}/", srv.addr)).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Timeout(TimeoutKind::ResponseHead), "{e}");
    assert!(t.elapsed() < Duration::from_secs(2));
    // idle read inside the body
    let srv = raw(|mut s, _| {
        read_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial").unwrap();
        std::thread::sleep(Duration::from_secs(3));
    });
    let c = Client::builder().read_timeout(Some(Duration::from_millis(200))).build();
    let r = c.get(&format!("http://{}/", srv.addr)).send().unwrap();
    let e = r.bytes().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Timeout(TimeoutKind::Idle), "{e}");
    // whole-request deadline while bytes keep trickling
    let srv = raw(|mut s, _| {
        read_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n").unwrap();
        for _ in 0..100 {
            if s.write_all(b"x").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
    });
    let c = Client::builder().read_timeout(Some(Duration::from_secs(5))).build();
    let t = Instant::now();
    let e = c.get(&format!("http://{}/", srv.addr)).timeout(Duration::from_millis(300)).send().unwrap().bytes().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Timeout(TimeoutKind::Total), "{e}");
    assert!(t.elapsed() < Duration::from_secs(2));
    // TLS handshake: the server never answers the ClientHello
    let srv = raw(|_s, _| std::thread::sleep(Duration::from_secs(3)));
    let c = Client::builder().tls_timeout(Some(Duration::from_millis(200))).build();
    let e = c.get(&format!("https://{}/", srv.addr)).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Timeout(TimeoutKind::Tls), "{e}");
}

#[test]
fn proxies_connect_absolute_form_and_no_proxy() {
    let h = plain();
    let p = common::proxy(Some("bob:s3cret"));
    let cfg = ProxyConfig::new(ProxyAddr::new("127.0.0.1", p.addr.port()).with_credentials("bob", "s3cret"));
    let c = client().proxy(Some(cfg.clone())).build();
    // plain http: absolute form with Proxy-Authorization
    let r = c.get(&url(&h, "/echo")).send().unwrap();
    assert!(r.text().unwrap().contains("GET /echo"));
    let line = p.seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(line, format!("GET {} HTTP/1.1", url(&h, "/echo")));
    // tunnelled http
    let mut tcfg = cfg.clone();
    tcfg.tunnel_http = true;
    let c2 = client().proxy(Some(tcfg)).build();
    assert!(c2.get(&url(&h, "/echo")).send().unwrap().text().unwrap().contains("GET /echo"));
    let line = p.seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(line, format!("CONNECT 127.0.0.1:{} HTTP/1.1", h.local_addrs()[0].port()));
    // https through CONNECT
    let s = common::secure();
    let r = c.get(&common::surl(&s, "/echo")).version(HttpVersion::Http1).send().unwrap();
    assert!(r.text().unwrap().contains("GET /echo"));
    assert!(p.seen.lock().unwrap().last().unwrap().starts_with("CONNECT localhost:"));
    // wrong credentials
    let bad = ProxyConfig::new(ProxyAddr::new("127.0.0.1", p.addr.port()).with_credentials("bob", "nope"));
    let e = client().proxy(Some(bad)).build().get(&common::surl(&s, "/echo")).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Proxy, "{e}");
    assert!(e.message.contains("407"), "{e}");
    // NO_PROXY: direct
    let before = p.seen.lock().unwrap().len();
    let c3 = client().proxy(Some(cfg.with_no_proxy("127.0.0.0/8"))).build();
    assert!(c3.get(&url(&h, "/echo")).send().unwrap().status() == 200);
    assert_eq!(p.seen.lock().unwrap().len(), before);
}

#[test]
fn invalid_requests_and_responses() {
    let c = Client::new();
    assert_eq!(c.get("ftp://x/").send().unwrap_err().kind, ErrorKind::InvalidUrl);
    let h = plain();
    let e = c.get(&url(&h, "/")).header("bad name", "v").send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidRequest, "{e}");
    let e = c.get(&url(&h, "/")).header("x", "a\r\nb: c").send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidRequest, "{e}");
    let srv = raw(|mut s, _| {
        read_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc").unwrap();
    });
    let e = c.get(&format!("http://{}/", srv.addr)).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Protocol, "{e}");
    let srv = raw(|mut s, _| {
        read_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").unwrap();
    });
    let e = c.get(&format!("http://{}/", srv.addr)).send().unwrap().bytes().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Closed, "{e}");
}

#[test]
fn many_threads_share_one_client() {
    let h = plain();
    let c = Arc::new(client().build());
    let ok = Arc::new(AtomicUsize::new(0));
    let ts: Vec<_> = (0..8)
        .map(|i| {
            let (c, ok, u) = (c.clone(), ok.clone(), url(&h, "/echo"));
            std::thread::spawn(move || {
                for j in 0..50 {
                    let body = format!("{i}-{j}");
                    let r = c.post(&u).body(body.clone()).send().unwrap();
                    assert!(r.text().unwrap().ends_with(&format!("len={}", body.len())));
                    ok.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for t in ts {
        t.join().unwrap();
    }
    assert_eq!(ok.load(Ordering::SeqCst), 400);
    assert!(c.pool_stats().http1 <= 8);
}

#[cfg(feature = "compress")]
#[test]
fn response_decompression() {
    use simoom_compress::{compress, Format};
    let text = b"the quick brown fox jumps over the lazy dog. ".repeat(2000);
    let gz = compress(&text, Format::Gzip, 6);
    let zl = compress(&text, Format::Zlib, 6);
    let raw_d = compress(&text, Format::Raw, 6);
    let bodies: Vec<(&'static str, Vec<u8>)> = vec![("gzip", gz.clone()), ("deflate", zl), ("deflate", raw_d), ("x-gzip", gz.clone()), ("identity", text.clone())];
    let bodies = Arc::new(bodies);
    let b2 = bodies.clone();
    let srv = raw(move |mut s, n| {
        let head = read_head(&mut s).unwrap().to_ascii_lowercase();
        if n < 5 {
            assert!(head.contains("accept-encoding: gzip, deflate"), "{head}");
            let (enc, body) = &b2[n];
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Encoding: {enc}\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).unwrap();
            s.write_all(body).unwrap();
        } else {
            // corrupted gzip
            let mut bad = b2[0].1.clone();
            let mid = bad.len() / 2;
            bad[mid] ^= 0xff;
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", bad.len()).as_bytes()).unwrap();
            s.write_all(&bad).unwrap();
        }
    });
    let c = Client::builder().keep_alive(false).build();
    for i in 0..5 {
        let r = c.get(&format!("http://{}/", srv.addr)).send().unwrap();
        assert_eq!(r.header("content-encoding"), if bodies[i].0 == "identity" { Some("identity") } else { None }, "case {i}");
        assert_eq!(r.bytes().unwrap(), text, "case {i}");
    }
    let e = c.get(&format!("http://{}/", srv.addr)).send().unwrap().bytes().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Decode, "{e}");
    // a decompression bomb stops at max_body
    let bomb = compress(&vec![0u8; 50_000_000], Format::Gzip, 9);
    let srv = raw(move |mut s, _| {
        read_head(&mut s);
        let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", bomb.len()).as_bytes());
        let _ = s.write_all(&bomb);
    });
    let c = Client::builder().max_body(Some(1 << 20)).build();
    let e = c.get(&format!("http://{}/", srv.addr)).send().unwrap().bytes().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Decode, "{e}");
    // decompression off: the bytes and the header as sent, no Accept-Encoding
    let gz2 = gz.clone();
    let srv = raw(move |mut s, _| {
        let head = read_head(&mut s).unwrap().to_ascii_lowercase();
        assert!(!head.contains("accept-encoding"));
        s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", gz2.len()).as_bytes()).unwrap();
        s.write_all(&gz2).unwrap();
    });
    let r = Client::builder().decompress(false).build().get(&format!("http://{}/", srv.addr)).send().unwrap();
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert_eq!(r.bytes().unwrap(), gz);
}

#[test]
fn chunked_option_streams_in_memory_bodies() {
    let srv = raw(|mut s, _| {
        while let Some(head) = read_head(&mut s) {
            let lower = head.to_ascii_lowercase();
            let host = head.lines().find(|l| l.to_ascii_lowercase().starts_with("host:")).unwrap_or("").to_string();
            let body = if lower.contains("transfer-encoding: chunked") {
                let mut rest = Vec::new();
                let mut b = [0u8; 1];
                while !rest.ends_with(b"0\r\n\r\n") {
                    s.read_exact(&mut b).unwrap();
                    rest.push(b[0]);
                }
                format!("chunked {}", rest.len())
            } else if let Some(l) = lower.lines().find_map(|l| l.strip_prefix("content-length: ")) {
                let n: usize = l.trim().parse().unwrap();
                format!("sized {}", read_n(&mut s, n).len())
            } else {
                "none".to_string()
            };
            let msg = format!("{} {body} {host}", head.split(' ').next().unwrap());
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{msg}", msg.len()).as_bytes()).unwrap();
        }
    });
    let c = Client::new();
    let u = format!("http://{}/", srv.addr);
    assert_eq!(c.post(&u).body("hello").chunked(true).send().unwrap().text().unwrap(), format!("POST chunked 15 Host: {}", srv.addr));
    // GET and DELETE may carry a body (Camel getWithBody / deleteWithBody)
    assert_eq!(c.get(&u).body("abc").send().unwrap().text().unwrap(), format!("GET sized 3 Host: {}", srv.addr));
    assert_eq!(c.delete(&u).body("abcd").send().unwrap().text().unwrap(), format!("DELETE sized 4 Host: {}", srv.addr));
    // a Host header on the request is kept (customHostHeader / preserveHostHeader)
    assert_eq!(c.get(&u).header("Host", "virtual.example").send().unwrap().text().unwrap(), "GET none Host: virtual.example");
    // ... and becomes :authority on HTTP/2
    let h = common::plain();
    let r = Client::builder().version(HttpVersion::Http2).build().get(&url(&h, "/echo")).header("Host", "virtual.example").send().unwrap();
    assert!(r.text().unwrap().contains("host=virtual.example"));
}

#[cfg(feature = "hooks")]
#[test]
fn interceptors_see_requests_and_can_retry() {
    use simoom_client::hooks::{Action, Interceptor};
    use simoom_client::{Request, Response};
    struct Auth(AtomicUsize);
    impl Interceptor for Auth {
        fn before_send(&self, req: &mut Request) {
            if self.0.load(Ordering::SeqCst) > 0 {
                req.headers.set("Authorization", "Bearer fresh");
            }
        }
        fn on_response(&self, _req: &Request, resp: &Response) -> Action {
            if resp.status() == 401 {
                self.0.fetch_add(1, Ordering::SeqCst);
                Action::Retry
            } else {
                Action::Continue
            }
        }
    }
    let srv = raw(|mut s, _| {
        while let Some(head) = read_head(&mut s) {
            if head.contains("Bearer fresh") {
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
            } else {
                s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nContent-Length: 0\r\n\r\n").unwrap();
            }
        }
    });
    let a = Arc::new(Auth(AtomicUsize::new(0)));
    let c = Client::builder().interceptor(a.clone()).build();
    assert_eq!(c.get(&format!("http://{}/", srv.addr)).send().unwrap().text().unwrap(), "ok");
    assert_eq!(a.0.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "socks")]
/// A SOCKS5 server (RFC 1928, username/password RFC 1929) for the tests; records the target
/// it was asked for.
fn socks5_server(user: &'static str, pass: &'static str) -> (std::net::SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let srv = raw(move |mut c, _| {
        let mut b = [0u8; 2];
        c.read_exact(&mut b).unwrap();
        let mut methods = vec![0u8; b[1] as usize];
        c.read_exact(&mut methods).unwrap();
        if !methods.contains(&2) {
            c.write_all(&[5, 0xff]).unwrap();
            return;
        }
        c.write_all(&[5, 2]).unwrap();
        let mut v = [0u8; 2];
        c.read_exact(&mut v).unwrap();
        let mut u = vec![0u8; v[1] as usize];
        c.read_exact(&mut u).unwrap();
        let mut pl = [0u8; 1];
        c.read_exact(&mut pl).unwrap();
        let mut p = vec![0u8; pl[0] as usize];
        c.read_exact(&mut p).unwrap();
        if u != user.as_bytes() || p != pass.as_bytes() {
            c.write_all(&[1, 1]).unwrap();
            return;
        }
        c.write_all(&[1, 0]).unwrap();
        let mut h = [0u8; 4];
        c.read_exact(&mut h).unwrap();
        let host = match h[3] {
            1 => {
                let mut a = [0u8; 4];
                c.read_exact(&mut a).unwrap();
                std::net::Ipv4Addr::from(a).to_string()
            }
            3 => {
                let mut l = [0u8; 1];
                c.read_exact(&mut l).unwrap();
                let mut n = vec![0u8; l[0] as usize];
                c.read_exact(&mut n).unwrap();
                String::from_utf8(n).unwrap()
            }
            _ => return,
        };
        let mut pb = [0u8; 2];
        c.read_exact(&mut pb).unwrap();
        let port = u16::from_be_bytes(pb);
        s2.lock().unwrap().push(format!("{host}:{port}"));
        let target = if host == "localhost" { format!("127.0.0.1:{port}") } else { format!("{host}:{port}") };
        let Ok(up) = std::net::TcpStream::connect(target) else {
            c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            return;
        };
        c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        let (mut a2, mut b2) = (c.try_clone().unwrap(), up.try_clone().unwrap());
        let (mut a, mut b) = (c, up);
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut a2, &mut b2);
            let _ = b2.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut b, &mut a);
        let _ = a.shutdown(std::net::Shutdown::Write);
    });
    (srv.addr, seen)
}

#[cfg(feature = "socks")]
#[test]
fn socks5_proxies() {
    let h = plain();
    let (addr, seen) = socks5_server("alice", "pw");
    for (remote, host) in [(false, "127.0.0.1"), (true, "localhost")] {
        let p = ProxyAddr::socks5("127.0.0.1", addr.port(), remote).with_credentials("alice", "pw");
        let c = client().proxy(Some(ProxyConfig::new(p))).build();
        let u = format!("http://{host}:{}/echo", h.local_addrs()[0].port());
        assert!(c.get(&u).send().unwrap().text().unwrap().contains("GET /echo"));
        assert_eq!(seen.lock().unwrap().last().unwrap(), &format!("{host}:{}", h.local_addrs()[0].port()), "remote dns {remote}");
    }
    // https through SOCKS5 (the TLS handshake runs inside the tunnel)
    let s = common::secure();
    let p = ProxyAddr::parse(&format!("socks5h://alice:pw@127.0.0.1:{}", addr.port())).unwrap();
    let c = client().proxy(Some(ProxyConfig::new(p))).build();
    assert_eq!(c.get(&common::surl(&s, "/echo")).send().unwrap().status(), 200);
    // wrong password
    let p = ProxyAddr::socks5("127.0.0.1", addr.port(), true).with_credentials("alice", "nope");
    let e = client().proxy(Some(ProxyConfig::new(p))).build().get(&format!("http://127.0.0.1:{}/", h.local_addrs()[0].port())).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Proxy, "{e}");
}

#[cfg(feature = "retry")]
#[test]
fn retries_with_backoff_for_idempotent_requests() {
    // 503 twice, then 200; Retry-After 0
    let srv = raw(|mut s, n| {
        if read_head(&mut s).is_some() {
            if n < 2 {
                s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            } else {
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
            }
        }
    });
    let c = Client::builder().retries(3).retry_backoff(Duration::from_millis(10)).retry_statuses(vec![503]).build();
    assert_eq!(c.get(&format!("http://{}/", srv.addr)).send().unwrap().text().unwrap(), "ok");
    assert_eq!(srv.accepted.load(Ordering::SeqCst), 3);
    // POST is not retried
    let srv2 = raw(|mut s, _| {
        if read_head(&mut s).is_some() {
            let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    assert_eq!(c.post(&format!("http://{}/", srv2.addr)).body("x").send().unwrap().status(), 503);
    assert_eq!(srv2.accepted.load(Ordering::SeqCst), 1);
    // connection refused: retried with growing backoff, then the error
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let t = Instant::now();
    let e = Client::builder().retries(2).retry_backoff(Duration::from_millis(50)).build().get(&format!("http://127.0.0.1:{port}/")).send().unwrap_err();
    assert!(e.is_connect());
    assert!(t.elapsed() >= Duration::from_millis(150), "50 + 100 ms of backoff: {:?}", t.elapsed());
}

#[cfg(feature = "evict")]
#[test]
fn idle_sockets_are_evicted_in_the_background() {
    let h = plain();
    let c = client().pool_idle_timeout(Duration::from_millis(200)).build();
    for _ in 0..3 {
        c.get(&url(&h, "/echo")).send().unwrap().bytes().unwrap();
    }
    // one from another thread too (it lands in that thread's cache, then the shared pool)
    let c2 = c.clone();
    let u = url(&h, "/echo");
    std::thread::spawn(move || c2.get(&u).send().unwrap().bytes().unwrap()).join().unwrap();
    assert!(c.pool_stats().idle >= 1);
    let end = Instant::now() + Duration::from_secs(5);
    while c.pool_stats().http1 > 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(c.pool_stats(), simoom_client::PoolStats::default(), "no request needed to close them");
}

#[cfg(feature = "pipeline")]
#[test]
fn pipelining() {
    // the server checks that all requests arrived before it answers the first
    let srv = raw(|mut s, n| {
        let mut heads = Vec::new();
        let want = if n == 0 { 5 } else { 2 };
        for _ in 0..want {
            match read_head(&mut s) {
                Some(h) => heads.push(h),
                None => return,
            }
        }
        for (i, h) in heads.iter().enumerate() {
            let path = h.split(' ').nth(1).unwrap().to_string();
            let close = n == 0 && i == 2; // the first connection ends after the third answer
            let body = format!("{path} of {}", heads.len());
            let c = if close { "Connection: close\r\n" } else { "" };
            s.write_all(format!("HTTP/1.1 200 OK\r\n{c}Content-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
            if close {
                return;
            }
        }
    });
    let c = Client::new();
    let reqs: Vec<_> = (0..5).map(|i| c.get(&format!("http://{}/r{i}", srv.addr)).build().unwrap()).collect();
    let out: Vec<String> = c.pipeline(reqs).into_iter().map(|r| r.unwrap().text().unwrap()).collect();
    assert_eq!(out, vec!["/r0 of 5", "/r1 of 5", "/r2 of 5", "/r3 of 2", "/r4 of 2"], "the last two were resent on a new connection");
    assert_eq!(srv.accepted.load(Ordering::SeqCst), 2);
    // POST is refused
    let reqs = vec![c.post(&format!("http://{}/", srv.addr)).body("x").build().unwrap()];
    assert_eq!(c.pipeline(reqs)[0].as_ref().unwrap_err().kind, ErrorKind::InvalidRequest);
    // against simoom: many requests on one connection, in order
    let h = plain();
    let reqs: Vec<_> = (0..50).map(|i| c.get(&url(&h, &format!("/echo?x={i}"))).build().unwrap()).collect();
    for (i, r) in c.pipeline(reqs).into_iter().enumerate() {
        assert!(r.unwrap().text().unwrap().contains(&format!("q={i} ")));
    }
}
