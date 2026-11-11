//! A std-only fuzz harness for response parsing through the client (plan §7.3 F2): valid
//! HTTP/1.1 responses are mutated (bit flips, inserted and deleted bytes, splices, truncation,
//! hostile numbers) and served over loopback in random pieces. The client must never panic or
//! hang, and a response it accepts must be consistent with its framing.
//!
//! `SIMOOM_FUZZ_ITERS` sets the number of cases (default 5000); `SIMOOM_FUZZ_SEED` the seed.

use simoom_client::{Client, ErrorKind};
use std::io::Write;
use std::net::TcpListener;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const SEEDS: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nx-t: 1\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose delimited body",
    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc",
    b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\n",
    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\nX-A: a\r\nX-A: b\r\n\r\nno",
];

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        if v.is_empty() {
            v.push(b'H');
        }
        match rng.below(9) {
            0 => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(v.len() + 1);
                let b = [b'\r', b'\n', b' ', b':', b'0', b'9', b'f', 0, 0x80, b';', b'"', b'\t'][rng.below(12)];
                v.insert(i, b);
            }
            2 => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            3 => {
                let n = rng.below(v.len());
                v.truncate(n);
            }
            4 => {
                let other = SEEDS[rng.below(SEEDS.len())];
                let a = rng.below(v.len());
                let b = rng.below(other.len());
                v.truncate(a);
                v.extend_from_slice(&other[b..]);
            }
            5 => {
                // a hostile number somewhere
                let i = rng.below(v.len() + 1);
                let n = ["99999999999999999999", "-1", "0x10", "1 2", "", "4294967296"][rng.below(6)];
                v.splice(i..i, n.bytes());
            }
            6 => {
                // duplicate a header line
                if let Some(p) = v.windows(2).position(|w| w == b"\r\n") {
                    let line = v[..p + 2].to_vec();
                    let at = p + 2;
                    v.splice(at..at, line);
                }
            }
            7 => {
                // bare LF
                if let Some(p) = v.iter().position(|&b| b == b'\r') {
                    v.remove(p);
                }
            }
            _ => {
                let i = rng.below(v.len());
                let j = (i + rng.below(16)).min(v.len());
                let piece = v[i..j].to_vec();
                v.splice(i..i, piece);
            }
        }
    }
    v
}

/// Serves queued responses, one per connection, in random pieces.
fn server(cases: Receiver<(Vec<u8>, u64)>) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let cases = Arc::new(Mutex::new(cases));
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let Ok((bytes, seed)) = cases.lock().unwrap().recv() else { return };
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                let mut head = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut head);
                let mut rng = Rng(seed | 1);
                let mut off = 0;
                while off < bytes.len() {
                    let n = (1 + rng.below(64)).min(bytes.len() - off);
                    if s.write_all(&bytes[off..off + n]).is_err() {
                        return;
                    }
                    let _ = s.flush();
                    off += n;
                }
            });
        }
    });
    addr
}

#[test]
fn mutated_responses_never_panic_or_hang() {
    let iters: usize = std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);
    let seed: u64 = std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_c11e_47);
    let (tx, rx) = channel();
    let addr = server(rx);
    let client = Client::builder().keep_alive(false).read_timeout(Some(Duration::from_secs(2))).response_timeout(Some(Duration::from_secs(2))).max_body(Some(1 << 20)).build();
    let mut rng = Rng(seed);
    let (mut ok, mut err) = (0usize, 0usize);
    let start = Instant::now();
    for i in 0..iters {
        let base = SEEDS[rng.below(SEEDS.len())];
        let case = if i < SEEDS.len() { SEEDS[i].to_vec() } else { mutate(&mut rng, base) };
        tx.send((case.clone(), rng.next())).unwrap();
        let method = if rng.below(10) == 0 { "HEAD" } else { "GET" };
        let t = Instant::now();
        let r = client.request(method, &format!("http://{addr}/")).send();
        match r {
            Ok(resp) => {
                let status = resp.status();
                assert!((100..=599).contains(&status), "case {i}: status {status}");
                let cl = resp.content_length();
                let chunked = resp.headers().has_token("transfer-encoding", "chunked");
                match resp.bytes() {
                    Ok(body) => {
                        if let (Some(n), false, "GET") = (cl, chunked, method) {
                            if !(status == 204 || status == 304 || status < 200) {
                                assert_eq!(body.len() as u64, n, "case {i}: body length against Content-Length: {:?}", String::from_utf8_lossy(&case));
                            }
                        }
                        if method == "HEAD" {
                            assert!(body.is_empty(), "case {i}: HEAD body");
                        }
                        ok += 1;
                    }
                    Err(e) => {
                        assert!(!matches!(e.kind, ErrorKind::InvalidRequest), "case {i}: {e}");
                        err += 1;
                    }
                }
            }
            Err(e) => {
                assert!(!matches!(e.kind, ErrorKind::InvalidRequest | ErrorKind::InvalidUrl), "case {i}: {e}");
                err += 1;
            }
        }
        assert!(t.elapsed() < Duration::from_secs(5), "case {i} hung: {:?}", String::from_utf8_lossy(&case));
    }
    eprintln!("fuzz: {iters} cases, {ok} accepted, {err} refused, {:?}", start.elapsed());
    assert!(ok >= SEEDS.len() / 2, "the valid seeds must pass");
}
