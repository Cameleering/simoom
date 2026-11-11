//! The non-blocking client on simoom-rt loops.

#![cfg(feature = "rt")]

mod common;

use simoom_client::rt::{RtClient, RtConfig, RtRequest, RtResponse};
use simoom_client::{ErrorKind, Result};
use std::io::{Read, Write};
use std::sync::mpsc::channel;
use std::time::Duration;

fn send(c: &RtClient, req: RtRequest) -> Result<RtResponse> {
    let (tx, rx) = channel();
    c.send(req, move |r| tx.send(r).unwrap());
    rx.recv_timeout(Duration::from_secs(20)).expect("callback")
}

#[test]
fn requests_on_event_loops_reuse_connections() {
    let h = common::plain();
    let c = RtClient::spawn(1, RtConfig { user_agent: Some("rt/1".into()), ..RtConfig::default() }).unwrap();
    let r = send(&c, RtRequest::get(&common::url(&h, "/echo?x=1")).unwrap()).unwrap();
    assert_eq!(r.status, 200);
    let t = String::from_utf8(r.body).unwrap();
    assert!(t.starts_with("Http11 GET /echo q=1") && t.contains("ua=rt/1"), "{t}");
    let r = send(&c, RtRequest::new("POST", &common::url(&h, "/upload")).unwrap().body(vec![7u8; 300_000])).unwrap();
    let sum = (0..300_000).fold(0u64, |a, _| a.wrapping_mul(31).wrapping_add(7));
    assert_eq!(String::from_utf8(r.body).unwrap(), format!("300000 {sum}"));
    let r = send(&c, RtRequest::get(&common::url(&h, "/stream?parts=3")).unwrap()).unwrap();
    assert_eq!(r.body, b"part0;part1;part2;");
    assert_eq!(c.idle_on(0), 1, "one connection, kept idle on the loop");
    // many at once
    let (tx, rx) = channel();
    for i in 0..200 {
        let tx = tx.clone();
        c.send(RtRequest::get(&common::url(&h, &format!("/echo?x={i}"))).unwrap(), move |r| tx.send((i, r)).unwrap());
    }
    for _ in 0..200 {
        let (i, r) = rx.recv_timeout(Duration::from_secs(20)).unwrap();
        let body = String::from_utf8(r.unwrap().body).unwrap();
        assert!(body.contains(&format!("q={i} ")), "{body}");
    }
}

#[cfg(feature = "tls")]
#[test]
fn https_on_event_loops() {
    let h = common::secure();
    let mut cfg = RtConfig::default();
    cfg.tls.roots = common::roots();
    let c = RtClient::spawn(2, cfg).unwrap();
    for _ in 0..5 {
        let r = send(&c, RtRequest::get(&common::surl(&h, "/echo")).unwrap()).unwrap();
        assert!(String::from_utf8(r.body).unwrap().starts_with("Http11 GET /echo"));
        let r = send(&c, RtRequest::get(&common::surl(&h, "/big?n=100000")).unwrap()).unwrap();
        assert_eq!(r.body.len(), 100_000);
    }
    assert_eq!(c.idle_on(0) + c.idle_on(1), 2, "one TLS connection kept per loop");
    let mut bad = RtConfig::default();
    bad.tls.roots = simoom_client::tls::RootStore::empty();
    let c = RtClient::spawn(1, bad).unwrap();
    let e = send(&c, RtRequest::get(&common::surl(&h, "/")).unwrap()).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Tls, "{e}");
}

#[test]
fn errors_timeouts_and_stale_connections() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let c = RtClient::spawn(1, RtConfig { timeout: Duration::from_millis(300), ..RtConfig::default() }).unwrap();
    let e = send(&c, RtRequest::get(&format!("http://127.0.0.1:{port}/")).unwrap()).unwrap_err();
    assert!(e.is_connect(), "{e}");
    let stall = common::raw(|mut s, _| {
        common::read_head(&mut s);
        std::thread::sleep(Duration::from_secs(2));
    });
    let e = send(&c, RtRequest::get(&format!("http://{}/", stall.addr)).unwrap()).unwrap_err();
    assert!(e.is_timeout(), "{e}");
    // one response per connection without `Connection: close`: retried on a new connection
    let once = common::raw(|mut s, _| {
        if common::read_head(&mut s).is_some() {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    let c = RtClient::spawn(1, RtConfig::default()).unwrap();
    for _ in 0..4 {
        assert_eq!(send(&c, RtRequest::get(&format!("http://{}/", once.addr)).unwrap()).unwrap().body, b"ok");
        std::thread::sleep(Duration::from_millis(30));
    }
    // close-delimited and chunked with trailers
    let srv = common::raw(|mut s, n| {
        common::read_head(&mut s);
        if n == 0 {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\nuntil close");
        } else {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nx-t: 1\r\n\r\n");
        }
    });
    assert_eq!(send(&c, RtRequest::get(&format!("http://{}/", srv.addr)).unwrap()).unwrap().body, b"until close");
    let r = send(&c, RtRequest::get(&format!("http://{}/", srv.addr)).unwrap()).unwrap();
    assert_eq!((r.body.as_slice(), r.trailers.get("x-t")), (&b"abc"[..], Some("1")));
}

#[test]
fn redirects_proxies_and_decompression_on_the_loop() {
    let h = common::plain();
    let c = RtClient::spawn(1, RtConfig { follow_redirects: true, ..RtConfig::default() }).unwrap();
    let r = send(&c, RtRequest::new("POST", &common::url(&h, "/redirect?code=303&to=/echo")).unwrap().body("x")).unwrap();
    assert!(String::from_utf8(r.body).unwrap().contains("GET /echo"));
    let e = send(&c, RtRequest::get(&common::url(&h, "/loop")).unwrap()).unwrap_err();
    assert_eq!(e.kind, ErrorKind::TooManyRedirects);
    // through an HTTP proxy (absolute form) and a CONNECT tunnel to https
    let p = common::proxy(None);
    let pc = simoom_client::ProxyConfig::new(simoom_client::ProxyAddr::new("127.0.0.1", p.addr.port()));
    let mut cfg = RtConfig { proxy: Some(pc), ..RtConfig::default() };
    #[cfg(feature = "tls")]
    {
        cfg.tls.roots = common::roots();
    }
    let c = RtClient::spawn(1, cfg).unwrap();
    let r = send(&c, RtRequest::get(&common::url(&h, "/echo")).unwrap()).unwrap();
    assert!(String::from_utf8(r.body).unwrap().contains("GET /echo"));
    assert!(p.seen.lock().unwrap().last().unwrap().starts_with("GET http://"));
    #[cfg(feature = "tls")]
    {
        let s = common::secure();
        assert_eq!(send(&c, RtRequest::get(&common::surl(&s, "/echo")).unwrap()).unwrap().status, 200);
        assert!(p.seen.lock().unwrap().last().unwrap().starts_with("CONNECT "));
    }
    // gzip decoded on the loop
    #[cfg(feature = "compress")]
    {
        let gz = simoom_compress::compress(b"hello hello hello hello", simoom_compress::Format::Gzip, 6);
        let srv = common::raw(move |mut s, _| {
            common::read_head(&mut s);
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", gz.len()).as_bytes());
            let _ = s.write_all(&gz);
        });
        let c = RtClient::spawn(1, RtConfig::default()).unwrap();
        let r = send(&c, RtRequest::get(&format!("http://{}/", srv.addr)).unwrap()).unwrap();
        assert_eq!(r.body, b"hello hello hello hello");
        assert!(r.headers.get("content-encoding").is_none());
    }
}

#[test]
fn http2_streamed_bodies_and_streamed_responses_on_workers() {
    let h = common::plain();
    let c = RtClient::spawn(1, RtConfig { version: simoom_client::HttpVersion::Http2, ..RtConfig::default() }).unwrap();
    let r = send(&c, RtRequest::get(&common::url(&h, "/echo")).unwrap()).unwrap();
    assert_eq!(r.version, simoom_client::Version::Http2);
    // a streamed request body through send_request
    let c = RtClient::spawn(1, RtConfig::default()).unwrap();
    let mut req = simoom_client::Request::new("POST", simoom_client::Url::parse(&common::url(&h, "/upload")).unwrap());
    req.body = simoom_client::Body::reader(std::io::repeat(7).take(100_000));
    let (tx, rx) = channel();
    c.send_request(req, move |r| tx.send(r).unwrap());
    let r = rx.recv_timeout(Duration::from_secs(20)).unwrap().unwrap();
    assert!(String::from_utf8(r.body).unwrap().starts_with("100000 "));
    // a streamed response
    let (tx, rx) = channel();
    let tx2 = tx.clone();
    let tx3 = tx.clone();
    let req = simoom_client::Request::new("GET", simoom_client::Url::parse(&common::url(&h, "/stream?parts=4")).unwrap());
    c.send_streaming(req, move |s, _| tx.send(format!("head {s}")).unwrap(), move |d| tx2.send(String::from_utf8_lossy(d).into_owned()).unwrap(), move |r| tx3.send(format!("end {}", r.is_ok())).unwrap());
    let mut got = String::new();
    loop {
        let m = rx.recv_timeout(Duration::from_secs(20)).unwrap();
        if m.starts_with("end") {
            assert_eq!(m, "end true");
            break;
        }
        got.push_str(&m);
    }
    assert_eq!(got, "head 200part0;part1;part2;part3;");
}
