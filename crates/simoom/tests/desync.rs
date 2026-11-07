//! Regression tests for the request-smuggling findings of the differential desync run
//! (`scripts/desync/desync.py`: simoom behind nginx and haproxy, and against both as origins).

#![cfg(feature = "http1")]

mod common;

use common::*;
use simoom::{Outcome, Reply, Request};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A server that records `method target host` for every request it sees.
fn recording() -> (simoom::ServerHandle, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let h = serve(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let line = format!(
            "{} {} {}",
            String::from_utf8_lossy(req.method()),
            String::from_utf8_lossy(req.target()),
            String::from_utf8_lossy(req.host().unwrap_or(b"-"))
        );
        s.lock().unwrap().push(line);
        reply.body_static(b"ok")
    });
    (h, seen)
}

fn read_all(c: &mut Client) -> Vec<u8> {
    c.s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut out = std::mem::take(&mut c.buf);
    let mut t = [0u8; 4096];
    loop {
        match c.s.read(&mut t) {
            Ok(0) | Err(_) => return out,
            Ok(n) => out.extend_from_slice(&t[..n]),
        }
    }
}

/// A front proxy that sees a 2xx to CONNECT switches the connection to a tunnel; simoom is no
/// tunnel, so it must close after answering instead of parsing the tunnelled bytes as requests
/// (found through haproxy: it logged one CONNECT while simoom ran a second request).
#[test]
fn connect_closes_the_connection_after_its_response() {
    let (h, seen) = recording();
    let mut c = Client::new(&h);
    c.send(b"CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n");
    let out = read_all(&mut c);
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert_eq!(text.matches("HTTP/1.1").count(), 1, "only the CONNECT is answered: {text}");
    assert_eq!(*seen.lock().unwrap(), ["CONNECT x:443 x:443"]);
}

/// RFC 9112 §3.2.2: with an absolute-form target the server uses the target's authority and
/// ignores Host. simoom passed the raw absolute URI as the path and reported the Host header, so
/// a request addressed to `y` looked to the service like one for `x`.
#[test]
fn absolute_form_uses_the_target_authority() {
    let (h, seen) = recording();
    let mut c = Client::new(&h);
    c.send(b"GET http://y/a?q=1 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(c.read().status, 200);
    c.send(b"GET http://z HTTP/1.1\r\nHost: z\r\n\r\n");
    assert_eq!(c.read().status, 200);
    assert_eq!(*seen.lock().unwrap(), ["GET /a?q=1 y", "GET / z"]);
}

/// RFC 9110 §4.2.4: userinfo hides the real authority and is treated as an error.
#[test]
fn absolute_form_with_userinfo_is_refused() {
    let (h, seen) = recording();
    let mut c = Client::new(&h);
    c.send(b"GET http://trusted@evil/a HTTP/1.1\r\nHost: evil\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n");
    let out = read_all(&mut c);
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    assert_eq!(text.matches("HTTP/1.1").count(), 1, "the connection closes after a framing error: {text}");
    assert!(seen.lock().unwrap().is_empty());
}

/// The smuggling corpus of the desync run, kept as a hermetic check: for each stream the
/// requests simoom runs (their targets, in order). Every ambiguous framing is refused with the
/// connection closed, so `/smuggled` is never reached behind it.
#[test]
fn smuggling_corpus() {
    let smuggle = "GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
    let post = |h: &str, body: &str| format!("POST /a HTTP/1.1\r\nHost: x\r\n{h}\r\n{body}{smuggle}");
    let both = ["POST /a x", "GET /smuggled x"];
    let none: [&str; 0] = [];
    let cases: Vec<(String, Vec<&str>)> = vec![
        (post("Content-Length: 5\r\n", "hello"), both.to_vec()),
        (post("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), both.to_vec()),
        (post("Content-Length: 40\r\nTransfer-Encoding: chunked\r\n", "0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding: chunked\r\nContent-Length: 3\r\n", "5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding: xchunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding: chunked, identity\r\n", "5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding: identity, chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n", "5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding : chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding:\r\n chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Content-Length: 5\r\nContent-Length: 6\r\n", "hello"), none.to_vec()),
        (post("Content-Length: 5, 5\r\n", "hello"), none.to_vec()),
        (post("Content-Length: +5\r\n", "hello"), none.to_vec()),
        (post("Content-Length : 5\r\n", "hello"), none.to_vec()),
        // BWS before a chunk extension is allowed (RFC 9112 §7.1.1).
        (post("Transfer-Encoding: chunked\r\n", "5 ;ext\r\nhello\r\n0\r\n\r\n"), both.to_vec()),
        (post("Transfer-Encoding: chunked\r\n", "5\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding: chunked\r\n", "fffffffffffffffff5\r\nhello\r\n0\r\n\r\n"), none.to_vec()),
        (post("Transfer-Encoding: chunked\r\n", "5\r\nhello0\r\n\r\n"), none.to_vec()),
        (format!("GET /a HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\n\r\n{smuggle}"), none.to_vec()),
        (format!("GET /a HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n\r\n{smuggle}"), none.to_vec()),
        (format!("GET /a HTTP/1.1\nHost: x\n\n{smuggle}"), none.to_vec()),
        (format!("POST /a HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n{smuggle}"), none.to_vec()),
    ];
    for (input, want) in cases {
        let (h, seen) = recording();
        let mut c = Client::new(&h);
        c.send(input.as_bytes());
        let _ = read_all(&mut c);
        let got = seen.lock().unwrap().clone();
        assert_eq!(got, want, "input {input:?}");
        h.stop(Duration::from_millis(50));
        h.join();
    }
}
