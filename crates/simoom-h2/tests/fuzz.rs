//! A std-only seeded mutation fuzzer (plan §7.3 option F2, without coverage feedback) for the
//! frame layer, the connection state machine and HPACK.
//!
//! Quick by default. For a long run:
//! `SIMOOM_FUZZ_ITERS=2000000 cargo test -p simoom-h2 --release --test fuzz -- --nocapture`;
//! `SIMOOM_FUZZ_SEED=<n>` replays a run.
//!
//! Invariants checked on every input: no panic, `recv` never consumes more than it was given
//! and always makes progress with a full frame buffered (unless output backpressure applies),
//! the output buffer and the number of tracked streams stay bounded, a closed connection stays
//! closed, and HPACK honours its list cap and round-trips what the encoder produced.

mod common;

use common::*;
use simoom_h2::frame::{self, kind, setting};
use simoom_h2::{Budgets, Config, Connection, ErrorCode, Event};
use simoom_hpack::{Decoder, Encoder};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn some_bytes(&mut self, below: usize) -> Vec<u8> {
        let n = self.below(below);
        self.bytes(n)
    }
}

fn iterations(default: usize) -> usize {
    std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_1234_abcd_0001)
}

/// Seed inputs: what a client sends, as a list of frames (after the preface).
fn corpus() -> Vec<Vec<Vec<u8>>> {
    let mut seeds = Vec::new();
    // real client traffic
    let mut c = Connection::client(Config::default());
    let id = c.send_request(b"POST", b"https", b"example.com", b"/upload?x=1", &[(b"content-type", b"text/plain"), (b"content-length", b"11")], false).unwrap();
    c.send_data(id, b"hello world", true).unwrap();
    for i in 0..5 {
        let id = c.send_request(b"GET", b"http", b"h", format!("/r/{i}").as_bytes(), &[(b"accept", b"*/*"), (b"cookie", b"a=b")], true).unwrap();
        if i == 3 {
            c.reset(id, ErrorCode::CANCEL);
        }
    }
    let id = c.send_request(b"POST", b"http", b"h", b"/grpc", &[(b"te", b"trailers")], false).unwrap();
    c.send_data(id, &[0u8; 300], false).unwrap();
    c.send_trailers(id, &[(b"x-t", b"1")]).unwrap();
    c.ping(*b"12345678");
    seeds.push(split(&c.output()[24..]));
    // hand-made frames covering the other types and flags
    let mut r = Raw::new();
    r.settings(&[(setting::INITIAL_WINDOW_SIZE, 10), (setting::MAX_FRAME_SIZE, 20000), (setting::HEADER_TABLE_SIZE, 100)]);
    r.settings_ack();
    r.headers(1, &POST, false);
    r.raw(kind::DATA, frame::flag::PADDED, 1, &[2, b'a', 0, 0]);
    r.priority(1, 3);
    r.window_update(0, 1000).window_update(1, 5);
    let b = r.block(&GET);
    r.raw(kind::HEADERS, frame::flag::END_STREAM | frame::flag::PRIORITY | frame::flag::PADDED, 3, &[[1u8, 0, 0, 0, 1, 9].as_slice(), &b[..2]].concat());
    r.raw(kind::CONTINUATION, frame::flag::END_HEADERS, 3, &[&b[2..], &[0u8][..]].concat());
    r.rst(1, ErrorCode::CANCEL);
    r.raw(kind::GOAWAY, 0, 0, &[0, 0, 0, 3, 0, 0, 0, 0, b'x']);
    r.raw(0x42, 0xff, 7, b"ext");
    seeds.push(split(&r.take()));
    seeds
}

fn split(b: &[u8]) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    let mut pos = 0;
    while b.len() - pos >= 9 {
        let h = frame::FrameHeader::parse(&b[pos..]);
        let end = (pos + 9 + h.len).min(b.len());
        v.push(b[pos..end].to_vec());
        pos = end;
    }
    v
}

fn mutate(rng: &mut Rng, seeds: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut frames = seeds[rng.below(seeds.len())].clone();
    for _ in 0..1 + rng.below(6) {
        if frames.is_empty() {
            let f = rng.some_bytes(20);
            frames.push([[0u8; 9].as_slice(), &f].concat());
        }
        let i = rng.below(frames.len());
        if frames[i].len() < 9 {
            frames[i].resize(9, 0); // an earlier truncation: header mutations need 9 bytes
        }
        match rng.below(12) {
            0 => frames.remove(i).len(),
            1 => {
                let f = frames[i].clone();
                let n = 1 + rng.below(50);
                for _ in 0..n {
                    frames.insert(i, f.clone());
                }
                0
            }
            2 => {
                let j = rng.below(frames.len());
                frames.swap(i, j);
                0
            }
            3 => {
                // splice a frame from another seed
                let s = &seeds[rng.below(seeds.len())];
                if !s.is_empty() {
                    let f = s[rng.below(s.len())].clone();
                    frames.insert(i, f);
                }
                0
            }
            4 => {
                frames[i][3] = rng.below(11) as u8; // type
                0
            }
            5 => {
                frames[i][4] = rng.next() as u8; // flags
                0
            }
            6 => {
                let id = [0u32, 1, 2, 3, 5, 0x7fff_ffff, rng.next() as u32][rng.below(7)];
                frames[i][5..9].copy_from_slice(&id.to_be_bytes());
                0
            }
            7 => {
                // break the length field
                let l = rng.below(1 << 15);
                frames[i][0] = (l >> 16) as u8;
                frames[i][1] = (l >> 8) as u8;
                frames[i][2] = l as u8;
                0
            }
            8 => {
                let f = &mut frames[i];
                for _ in 0..1 + rng.below(4) {
                    let p = rng.below(f.len());
                    f[p] ^= 1 << rng.below(8);
                }
                0
            }
            9 => {
                let f = &mut frames[i];
                if f.len() > 9 {
                    let p = 9 + rng.below(f.len() - 9);
                    f[p] = rng.next() as u8;
                }
                0
            }
            10 => {
                // random payload with a matching length
                let n = rng.below(64);
                let mut f = frames[i][..9].to_vec();
                f[0] = 0;
                f[1] = 0;
                f[2] = n as u8;
                f.extend(rng.bytes(n));
                frames[i] = f;
                0
            }
            _ => {
                let f = &mut frames[i];
                let n = rng.below(f.len() + 1);
                f.truncate(n);
                0
            }
        };
    }
    frames.concat()
}

/// Drives a server through `input` in random chunks, playing a random application.
fn run_server(rng: &mut Rng, cfg: &Config, input: &[u8]) {
    let mut srv = Connection::server(cfg.clone());
    let mut buf: Vec<u8> = Vec::new();
    let mut fed = 0;
    let mut wire = simoom_h2::PREFACE.to_vec();
    wire.extend_from_slice(input);
    let mut now = 0u64;
    let mut closed = false;
    let mut stalls = 0;
    while fed < wire.len() || !buf.is_empty() {
        let chunk = (1 + rng.below(4000)).min(wire.len() - fed);
        buf.extend_from_slice(&wire[fed..fed + chunk]);
        fed += chunk;
        now += rng.below(50) as u64;
        let mut started = Vec::new();
        let mut resets = Vec::new();
        let mut data = Vec::new();
        let len = buf.len();
        let n = srv.recv(&buf, now, &mut |e| match e {
            Event::Headers { stream, .. } => started.push(stream),
            Event::Data { stream, data: d, .. } => data.push((stream, d.len())),
            Event::Reset { stream, .. } => resets.push(stream),
            _ => {}
        });
        for (s, len) in data {
            if rng.chance(2) {
                srv.release(s, len);
            }
        }
        assert!(n <= len);
        if closed {
            assert_eq!(n, len, "a closed connection consumes everything");
        }
        closed |= srv.wants_close() && srv.close_code().is_some();
        buf.drain(..n);
        // the application: respond, stream, finish or leave work running
        for s in started {
            match rng.below(5) {
                0 => {
                    let _ = srv.send_response(s, 200, &[(b"x", b"y")], true);
                    srv.stream_finished(s);
                }
                1 => {
                    let _ = srv.send_response(s, 200, &[], false);
                    let _ = srv.send_data(s, &[1u8; 3000], rng.chance(2));
                }
                2 => srv.release(s, rng.below(5000)),
                3 => srv.stream_finished(s),
                _ => {}
            }
        }
        for s in resets {
            srv.stream_finished(s);
        }
        while let Some(s) = srv.poll_writable() {
            let _ = srv.send_data(s, &[2u8; 500], true);
        }
        if rng.chance(3) {
            srv.handle_timeout(now, &mut |_| {});
        }
        if rng.chance(50) {
            srv.shutdown(now);
        }
        // invariants
        assert!(srv.output().len() <= 3 * cfg.max_send_buffer + 64 * 1024, "output {}", srv.output().len());
        assert!(srv.active_handlers() <= cfg.max_concurrent_streams);
        assert!(srv.tracked_streams() <= 2 * cfg.max_concurrent_streams as usize);
        if n == 0 && buf.len() >= cfg.max_frame_size as usize + 9 && srv.output().len() <= 2 * cfg.max_send_buffer {
            panic!("no progress with a full frame buffered");
        }
        // the transport writes some or all of the output
        let out = srv.output().len();
        let w = if rng.chance(4) { rng.below(out + 1) } else { out };
        srv.advance_output(w);
        if n == 0 && fed == wire.len() {
            stalls += 1;
            if stalls > 1000 {
                break;
            }
        }
    }
}

#[test]
fn fuzz_server_frames() {
    let seeds = corpus();
    let mut rng = Rng(seed());
    let configs = [
        Config::default(),
        Config { max_concurrent_streams: 3, initial_window_size: 100, max_header_list_size: 300, max_send_buffer: 2048, ..Config::default() },
        Config { budgets: Budgets { window_ms: 50, rst_received: 2, rst_sent: 2, ping: 2, settings: 2, empty_frames: 2, priority: 2, small_window_updates: 2 }, ..Config::default() },
    ];
    let n = iterations(3000);
    for i in 0..n {
        let input = mutate(&mut rng, &seeds);
        run_server(&mut rng, &configs[i % configs.len()], &input);
    }
}

#[test]
fn fuzz_server_random_bytes() {
    let mut rng = Rng(seed() ^ 0xabcdef);
    for _ in 0..iterations(2000) {
        let n = rng.below(2000);
        let mut input = Vec::new();
        // a plausible frame header now and then keeps the parser past the first frame
        while input.len() < n {
            let len = rng.below(40);
            frame::write_header(&mut input, len, rng.below(12) as u8, rng.next() as u8, rng.below(8) as u32);
            input.extend(rng.bytes(len));
        }
        run_server(&mut rng, &Config::default(), &input);
    }
}

#[test]
fn fuzz_client_role() {
    // server bytes, mutated, into a client with requests in flight
    let mut base = Connection::server(Config::default());
    let mut raw = Raw::new();
    raw.preface();
    let mut c = Connection::client(Config::default());
    for _ in 0..4 {
        c.send_request(b"GET", b"https", b"h", b"/", &[], true).unwrap();
    }
    let c2s = c.output().to_vec();
    base.recv(&c2s, 0, &mut |_| {});
    for id in [1u32, 3, 5] {
        base.send_response(id, if id == 5 { 100 } else { 200 }, &[(b"content-length", b"3")], false).unwrap();
        if id != 5 {
            base.send_data(id, b"abc", true).unwrap();
            base.send_trailers(id, &[]).ok();
        }
    }
    base.ping(*b"pingpong");
    base.shutdown(1);
    let seeds = vec![split(base.output())];
    let mut rng = Rng(seed() ^ 0x77);
    for _ in 0..iterations(3000) {
        let mut c = Connection::client(Config { max_send_buffer: 4096, ..Config::default() });
        for _ in 0..4 {
            let _ = c.send_request(b"GET", b"https", b"h", b"/", &[], true);
        }
        let input = mutate(&mut rng, &seeds);
        let mut off = 0;
        while off < input.len() {
            let end = (off + 1 + rng.below(3000)).min(input.len());
            let n = c.recv(&input[off..end], 1, &mut |e| {
                let _ = format!("{e:?}");
            });
            if n == 0 {
                if end == input.len() {
                    break;
                }
                // keep the partial frame: feed it with the next chunk
                let n2 = c.recv(&input[off..], 1, &mut |_| {});
                if n2 == 0 {
                    break;
                }
                off += n2;
            } else {
                off += n;
            }
            let out = c.output().len();
            c.advance_output(out);
            let _ = c.send_request(b"GET", b"https", b"h", b"/", &[], true);
        }
        assert!(c.tracked_streams() <= 1000);
    }
}

#[test]
fn fuzz_hpack() {
    let mut rng = Rng(seed() ^ 0x4ac);
    let names: [&[u8]; 8] = [b":path", b"content-type", b"cookie", b"x-a", b"x-bb", b"authorization", b"date", b"content-length"];
    for _ in 0..iterations(5000) {
        // round trip of a random list through an encoder with a random table size
        let mut enc = Encoder::new([0usize, 64, 256, 4096][rng.below(4)]);
        let mut dec = Decoder::new(4096, 1 << 20);
        let mut blocks = Vec::new();
        for _ in 0..1 + rng.below(5) {
            let list: Vec<(Vec<u8>, Vec<u8>)> = (0..rng.below(10))
                .map(|_| {
                    let n = names[rng.below(names.len())].to_vec();
                    let vlen = rng.below(80);
                    (n, rng.bytes(vlen))
                })
                .collect();
            if rng.chance(5) {
                enc.set_peer_max_table_size(rng.below(5000));
            }
            let mut block = Vec::new();
            enc.begin_block(&mut block);
            for (n, v) in &list {
                enc.field(n, v, &mut block);
            }
            let mut got = Vec::new();
            dec.decode(&block, &mut |n: &[u8], v: &[u8]| got.push((n.to_vec(), v.to_vec()))).unwrap();
            assert_eq!(got, list);
            blocks.push(block);
        }
        // mutated blocks into a fresh decoder with a small list cap: errors, never panics, and
        // never emits past the cap
        let cap = 1 + rng.below(2000);
        let mut dec = Decoder::new(4096, cap);
        for b in &blocks {
            let mut m = b.clone();
            for _ in 0..rng.below(4) {
                if m.is_empty() {
                    break;
                }
                let p = rng.below(m.len());
                match rng.below(3) {
                    0 => m[p] ^= 1 << rng.below(8),
                    1 => m.insert(p, rng.next() as u8),
                    _ => {
                        m.remove(p);
                    }
                }
            }
            if rng.chance(4) {
                m = rng.some_bytes(100);
            }
            let mut total = 0usize;
            let _ = dec.decode(&m, &mut |n: &[u8], v: &[u8]| total += n.len() + v.len() + 32);
            assert!(total <= cap);
            assert!(dec.table_size() <= 4096);
        }
        // Huffman: random bytes decode or fail cleanly; encodings round-trip
        let s = rng.some_bytes(64);
        let mut h = Vec::new();
        simoom_hpack::huffman::encode(&s, &mut h);
        let mut back = Vec::new();
        simoom_hpack::huffman::decode(&h, &mut back).unwrap();
        assert_eq!(back, s);
        let mut junk = Vec::new();
        let _ = simoom_hpack::huffman::decode(&rng.some_bytes(32), &mut junk);
    }
}
