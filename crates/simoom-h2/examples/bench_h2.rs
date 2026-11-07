//! In-memory cost of HTTP/2 through the sans-io client and server engines.
//!
//! `cargo run -p simoom-h2 --release --example bench_h2 [iterations]`
//!
//! Measures, per request: a small GET (5 request fields) answered with a 13-byte body
//! (`content-type` plus DATA with END_STREAM), driven through both state machines with no
//! sockets, one stream at a time and 100 concurrent streams; then HPACK encode and decode of
//! the request header list with a warm and a cold dynamic table, and Huffman decoding.

use std::hint::black_box;
use std::time::Instant;

use simoom_h2::{Config, Connection, Event};
use simoom_hpack::{Decoder, Encoder};

const BODY: &[u8] = b"Hello, world!";

fn transfer(from: &mut Connection, buf: &mut Vec<u8>) {
    buf.clear();
    buf.extend_from_slice(from.output());
    from.advance_output(buf.len());
}

fn pair() -> (Connection, Connection, Vec<u8>) {
    let cfg = Config { window_autotune: false, ..Config::default() };
    let mut c = Connection::client(cfg.clone());
    let mut s = Connection::server(cfg);
    let mut buf = Vec::with_capacity(64 * 1024);
    for _ in 0..3 {
        transfer(&mut c, &mut buf);
        s.recv(&buf, 0, &mut |_| {});
        transfer(&mut s, &mut buf);
        c.recv(&buf, 0, &mut |_| {});
    }
    (c, s, buf)
}

/// One batch: `streams` requests out, responses back. Returns body bytes received.
fn batch(c: &mut Connection, s: &mut Connection, buf: &mut Vec<u8>, ids: &mut Vec<u32>, streams: usize) -> usize {
    for _ in 0..streams {
        c.send_request(b"GET", b"https", b"example.com", b"/hello", &[(b"user-agent", b"simoom-bench"), (b"accept", b"*/*")], true).unwrap();
    }
    transfer(c, buf);
    ids.clear();
    let n = s.recv(buf, 0, &mut |e| {
        if let Event::Headers { stream, .. } = e {
            ids.push(stream);
        }
    });
    debug_assert_eq!(n, buf.len());
    for &id in ids.iter() {
        s.send_response(id, 200, &[(b"content-type", b"text/plain")], false).unwrap();
        s.send_data(id, BODY, true).unwrap();
        s.stream_finished(id);
    }
    transfer(s, buf);
    let mut got = 0;
    c.recv(buf, 0, &mut |e| {
        if let Event::Data { data, .. } = e {
            got += data.len();
        }
    });
    got
}

fn bench_requests(streams: usize, total: usize) -> f64 {
    let (mut c, mut s, mut buf) = pair();
    let mut ids = Vec::with_capacity(streams);
    // warm up (tables, buffers)
    for _ in 0..100 {
        batch(&mut c, &mut s, &mut buf, &mut ids, streams);
    }
    let rounds = total / streams;
    let t = Instant::now();
    let mut got = 0;
    for _ in 0..rounds {
        got += batch(&mut c, &mut s, &mut buf, &mut ids, streams);
    }
    let ns = t.elapsed().as_nanos() as f64 / (rounds * streams) as f64;
    assert_eq!(got, rounds * streams * BODY.len());
    assert_eq!(s.tracked_streams(), 0);
    ns
}

const REQ: [(&[u8], &[u8]); 6] = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"example.com"),
    (b":path", b"/hello"),
    (b"user-agent", b"simoom-bench"),
    (b"accept", b"*/*"),
];

fn bench_hpack(iters: usize) -> (f64, f64, f64, f64, usize) {
    let mut enc = Encoder::new(4096);
    let mut dec = Decoder::new(4096, 16 * 1024);
    let mut block = Vec::with_capacity(256);
    enc.encode(&REQ, &mut block);
    dec.decode(&block, &mut |_, _| {}).unwrap();
    let t = Instant::now();
    for _ in 0..iters {
        block.clear();
        enc.encode(black_box(&REQ), &mut block);
    }
    let enc_warm = t.elapsed().as_nanos() as f64 / iters as f64;
    let warm_len = block.len();
    let t = Instant::now();
    let mut n = 0;
    for _ in 0..iters {
        dec.decode(black_box(&block), &mut |a, b| n += a.len() + b.len()).unwrap();
    }
    let dec_warm = t.elapsed().as_nanos() as f64 / iters as f64;
    black_box(n);
    // cold: a fresh context every time (the first request on a connection)
    let t = Instant::now();
    for _ in 0..iters {
        let mut e = Encoder::new(4096);
        block.clear();
        e.encode(black_box(&REQ), &mut block);
        black_box(&block);
    }
    let enc_cold = t.elapsed().as_nanos() as f64 / iters as f64;
    let t = Instant::now();
    for _ in 0..iters {
        let mut d = Decoder::new(4096, 16 * 1024);
        d.decode(black_box(&block), &mut |a, b| n += a.len() + b.len()).unwrap();
    }
    let dec_cold = t.elapsed().as_nanos() as f64 / iters as f64;
    black_box(n);
    (enc_warm, dec_warm, enc_cold, dec_cold, warm_len)
}

fn bench_huffman(iters: usize) -> f64 {
    let s = b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)";
    let mut h = Vec::new();
    simoom_hpack::huffman::encode(s, &mut h);
    let mut out = Vec::with_capacity(128);
    let t = Instant::now();
    for _ in 0..iters {
        out.clear();
        simoom_hpack::huffman::decode(black_box(&h), &mut out).unwrap();
    }
    let ns = t.elapsed().as_nanos() as f64 / iters as f64;
    assert_eq!(out, s);
    ns / s.len() as f64
}

fn main() {
    let total: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(1_000_000);
    let one = bench_requests(1, total);
    let hundred = bench_requests(100, total);
    println!("request + 13-byte response, client and server engines, in memory:");
    println!("  1 stream at a time      {one:8.0} ns/request  ({:.2} M req/s on one core)", 1e3 / one);
    println!("  100 concurrent streams  {hundred:8.0} ns/request  ({:.2} M req/s on one core)", 1e3 / hundred);
    let (ew, dw, ec, dc, len) = bench_hpack(total);
    println!("HPACK, request list of 6 fields:");
    println!("  encode warm {ew:6.1} ns ({len} bytes), decode warm {dw:6.1} ns");
    println!("  encode cold {ec:6.1} ns, decode cold {dc:6.1} ns (fresh tables, includes allocation)");
    println!("Huffman decode: {:.2} ns/byte", bench_huffman(total));
}
