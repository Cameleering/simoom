//! K2: large responses over TLS are encrypted a piece at a time as the socket drains, so a
//! connection whose client reads slowly holds a bounded amount of memory, not the whole body
//! (three times over, as it did); responses still arrive whole and in order, a `close` waits for
//! the body, and the buffers go back once the loop is idle.

#![cfg(feature = "tls-client")]

use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Outcome, Reply, Request, Server, ServerHandle};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::{ClientConfig, ClientConnection};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[global_allocator]
static A: simoom_sys::alloc::Counting = simoom_sys::alloc::Counting;

const MIB: usize = 1 << 20;

fn body() -> &'static [u8] {
    static B: OnceLock<Vec<u8>> = OnceLock::new();
    // A pattern that shows a reordered or lost piece.
    B.get_or_init(|| (0..MIB).map(|i| (i / 7 % 251) as u8).collect())
}

fn cert() -> &'static certgen::SelfSigned {
    static C: OnceLock<certgen::SelfSigned> = OnceLock::new();
    C.get_or_init(|| certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None))
}

fn start() -> ServerHandle {
    let ss = cert();
    let cfg = ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap());
    let big: &'static [u8] = body();
    Server::builder()
        .listen_tls("127.0.0.1:0")
        .tls(cfg)
        .threads(1)
        .service(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            match req.path() {
                b"/1m" => reply.body_static(big),
                b"/1m-owned" => reply.body(big.to_vec()),
                _ => reply.body_static(b"small"),
            }
        })
        .start()
        .unwrap()
}

struct Tls {
    s: TcpStream,
    c: ClientConnection,
    got: Vec<u8>,
}

impl Tls {
    fn connect(h: &ServerHandle) -> Tls {
        let mut roots = RootStore::empty();
        roots.add_der(&cert().cert_der).unwrap();
        let cfg = Arc::new(ClientConfig::new(roots).with_alpn(&[b"http/1.1"]));
        let s = TcpStream::connect(h.local_addr()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut t = Tls { s, c: ClientConnection::new(cfg, "localhost").unwrap(), got: Vec::new() };
        while t.c.is_handshaking() {
            t.flush();
            t.read_more();
        }
        t.flush();
        t
    }

    fn flush(&mut self) {
        if self.c.wants_write() {
            let mut out = Vec::new();
            self.c.write_tls_into(&mut out);
            self.s.write_all(&out).unwrap();
        }
    }

    fn send(&mut self, b: &[u8]) {
        self.c.write_plaintext(b).unwrap();
        self.flush();
    }

    /// Reads once from the socket; false at EOF.
    fn read_more(&mut self) -> bool {
        let mut tmp = vec![0u8; 64 * 1024];
        let n = self.s.read(&mut tmp).unwrap();
        let mut off = 0;
        while off < n {
            off += self.c.read_tls(&tmp[off..n]);
            self.c.process_new_packets().unwrap();
        }
        let p = self.c.plaintext();
        let k = p.len();
        self.got.extend_from_slice(p);
        self.c.consume_plaintext(k);
        n > 0
    }

    /// The next response's body (content-length framing).
    fn response(&mut self) -> Vec<u8> {
        loop {
            if let Some(end) = self.got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.got[..end]).to_ascii_lowercase();
                let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length: ")).unwrap().trim().parse().unwrap();
                while self.got.len() < end + 4 + len {
                    assert!(self.read_more(), "eof inside a body");
                }
                let b = self.got[end + 4..end + 4 + len].to_vec();
                self.got.drain(..end + 4 + len);
                return b;
            }
            assert!(self.read_more(), "eof before a head");
        }
    }
}

fn wait_until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    f()
}

#[test]
fn a_slow_reader_holds_a_bounded_amount_and_gets_every_byte_in_order() {
    let h = start();
    let big = body();
    // Warm up (the loop's pools, the session) on one connection, then measure.
    let mut w = Tls::connect(&h);
    w.send(b"GET /1m HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(w.response(), big);
    let mut conns: Vec<Tls> = (0..8).map(|_| Tls::connect(&h)).collect();
    std::thread::sleep(Duration::from_millis(100));
    let base = simoom_sys::alloc::total_bytes();
    // Eight clients ask for 1 MiB each (one of them owned by the handler) and read nothing yet.
    for (i, c) in conns.iter_mut().enumerate() {
        let path = if i == 0 { "/1m-owned" } else { "/1m" };
        c.send(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\nGET /s HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes());
    }
    std::thread::sleep(Duration::from_millis(300));
    let held = simoom_sys::alloc::total_bytes() - base;
    eprintln!("8 slow readers hold {} KiB", held / 1024);
    // The owned body itself is 1 MiB; every other connection holds at most its window of
    // records. Copied whole into plaintext, ciphertext and send buffers, each held about 3 MiB.
    assert!(held < 3 * MIB as i64, "8 slow readers hold {} KiB", held / 1024);
    // Every byte arrives, in order, and the pipelined small response after it.
    for c in conns.iter_mut() {
        assert!(c.response() == big, "the body arrived whole and in order");
        assert_eq!(c.response(), b"small");
    }
    // A request that closes the connection gets its whole body, then close_notify and EOF.
    let mut c = Tls::connect(&h);
    c.send(b"GET /1m HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(c.response() == big);
    while c.read_more() {}
    assert!(c.c.peer_has_closed(), "close_notify after the body");
    // Idle: the loop gives back the buffers the burst left in its pool.
    drop(conns);
    let peak_pool = h.stats().runtime.loops[0].pool_cached;
    assert!(wait_until(5, || h.stats().runtime.loops[0].pool_cached <= 12), "pool still holds {} buffers (was {peak_pool})", h.stats().runtime.loops[0].pool_cached);
}
