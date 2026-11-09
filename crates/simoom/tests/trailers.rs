//! Request trailers reach the service on HTTP/1.1 (bug 14); HTTP/2 and HTTP/3 are in
//! `http2.rs` and `http3.rs`.

#![cfg(feature = "http1")]

mod common;

use common::*;
use simoom::{blocking, Limits, OwnedRequest, Response};
use std::io::{Read, Write};

/// Echoes the body length and every trailer, from a buffered or a streamed body.
pub fn trailer_echo(mut req: OwnedRequest) -> Response {
    // on the offload pool (blocking): a streamed body is read with blocking reads
    let (len, trailers) = match req.take_body() {
        Some(mut src) => {
            let mut v = Vec::new();
            src.read_to_end(&mut v).unwrap();
            (v.len(), src.trailers())
        }
        None => (req.body().len(), req.trailers().map(|(n, v)| (n.to_vec(), v.to_vec())).collect()),
    };
    let t: Vec<String> = trailers.iter().map(|(n, v)| format!("{}={}", String::from_utf8_lossy(n), String::from_utf8_lossy(v))).collect();
    Response::text(format!("{len} {}", t.join(",")))
}

fn post_chunked(h: &simoom::ServerHandle, chunks: &[&[u8]], trailers: &str) -> String {
    let mut s = connect(h);
    let mut req = b"POST /t HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTrailer: x-sum\r\nConnection: close\r\n\r\n".to_vec();
    for c in chunks {
        req.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        req.extend_from_slice(c);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n");
    req.extend_from_slice(trailers.as_bytes());
    req.extend_from_slice(b"\r\n");
    s.write_all(&req).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    text.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

#[test]
fn http1_trailers_buffered_and_streamed() {
    let h = serve_with(Limits { body_buffer: 1024, ..Limits::default() }, blocking(trailer_echo));
    // buffered: the whole body fits
    assert_eq!(post_chunked(&h, &[b"hello", b" world"], "x-sum: 42\r\nx-other: a b\r\n"), "11 x-sum=42,x-other=a b");
    // no trailers
    assert_eq!(post_chunked(&h, &[b"abc"], ""), "3 ");
    // streamed: the body is larger than body_buffer; the trailers come with its end
    let big = vec![b'z'; 4000];
    assert_eq!(post_chunked(&h, &[&big, &big], "x-sum: 8000\r\n"), "8000 x-sum=8000");
}
