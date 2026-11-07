//! HTTP/3 bulk upload over loopback: an in-process server (one loop) and a simoom-quic +
//! simoom-h3 client on one thread that sends with segmentation offload (GSO), so the server's
//! GRO can take whole batches. Prints the upload throughput.
//!
//! ```text
//! cargo run --release -p simoom --features http3 --example h3_bulk -- [--mb 200] [--rounds 3] [--no-gro]
//! ```

#![forbid(unsafe_code)]

use simoom::tls::{certgen, CertifiedKey, ServerConfig};
use simoom::{Limits, Outcome, Reply, Request, Response, Server};
use simoom_h3::{H3Event, Http3};
use simoom_quic::tls::TlsProvider;
use simoom_quic::{Config, Endpoint};
use simoom_rt::{RecvMeta, Socket, Transmit, UdpOptions};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::ClientConfig;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let mut mb = 200usize;
    let mut rounds = 3usize;
    let mut gro = true;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        if v[i] == "--no-gro" {
            gro = false;
            i += 1;
            continue;
        }
        match v[i].as_str() {
            "--mb" => mb = v[i + 1].parse().expect("--mb"),
            "--rounds" => rounds = v[i + 1].parse().expect("--rounds"),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let ss = certgen::issue(&certgen::CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let server = Server::builder()
        .listen_quic("127.0.0.1:0")
        .quic_tls(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()))
        .threads(1)
        .quic_gro(gro)
        .limits(Limits { max_body: u64::MAX, ..Limits::default() })
        .service(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            let Some(mut src) = req.take_body() else {
                let n = req.body().len();
                return reply.body(n.to_string());
            };
            let responder = reply.defer();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 256 * 1024];
                let mut n = 0usize;
                while let Ok(k) = src.read(&mut buf) {
                    if k == 0 {
                        break;
                    }
                    n += k;
                }
                responder.send(Response::text(n.to_string()));
            });
            Outcome::Deferred
        })
        .start()
        .expect("start");
    let addr = server.quic_addrs()[0];

    let mut roots = RootStore::empty();
    roots.add_der(&ss.cert_der).unwrap();
    let cfg = Arc::new(Config::new(Arc::new(TlsProvider::client(Arc::new(ClientConfig::new(roots).with_alpn(&[b"h3"]))))));
    for r in 0..rounds {
        let mut c = Client::connect(cfg.clone(), addr);
        let t0 = Instant::now();
        let got = c.upload(mb * 1024 * 1024);
        let secs = t0.elapsed().as_secs_f64();
        assert_eq!(got, mb * 1024 * 1024, "the server counted {got} bytes");
        let st = c.ep.conn(c.h).map(|q| q.stats()).unwrap_or_default();
        println!(
            "round {r}: {mb} MiB up in {secs:.2} s = {:.0} Mbit/s ({} packets sent, {} lost)",
            (mb * 8 * 1024 * 1024) as f64 / secs / 1e6,
            st.sent_packets,
            st.lost_packets
        );
    }
    let stats = server.stats();
    let t = stats.runtime.total();
    println!("server: {} receive calls, {} OS events", t.driver.recv_calls, t.driver.os_events);
    server.stop(Duration::from_secs(1));
    server.join();
}

struct Client {
    sock: Socket,
    ep: Endpoint,
    h: simoom_quic::ConnHandle,
    h3: Http3,
    tx: Vec<u8>,
    resp: Vec<u8>,
    bufs: Vec<Vec<u8>>,
    meta: Vec<RecvMeta>,
    body: Vec<u8>,
    done: bool,
}

impl Client {
    fn connect(cfg: Arc<Config>, server: std::net::SocketAddr) -> Client {
        let mut ep = Endpoint::new(cfg, false);
        let sock = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions { recv_buffer: Some(4 << 20), send_buffer: Some(4 << 20), ..UdpOptions::default() }).unwrap();
        let h = ep.connect(Instant::now(), server, "localhost", &[]).unwrap();
        let mut c = Client {
            sock,
            ep,
            h,
            h3: Http3::new(false, simoom_h3::Config::default()),
            tx: Vec::new(),
            resp: Vec::new(),
            bufs: (0..32).map(|_| Vec::with_capacity(2048)).collect(),
            meta: vec![RecvMeta::default(); 32],
            body: Vec::new(),
            done: false,
        };
        let end = Instant::now() + Duration::from_secs(10);
        while !(c.ep.conn(c.h).is_some_and(|q| q.is_established()) && c.h3.peer_settings().is_some()) {
            assert!(Instant::now() < end, "handshake timed out");
            c.step();
        }
        c
    }

    fn send_all(&mut self) {
        let now = Instant::now();
        while let Some((_, t)) = self.ep.poll_transmit(now, &mut self.tx, 16) {
            let size = t.size.min(self.tx.len());
            let seg = t.segment_size.filter(|&s| s < size).unwrap_or(0);
            let tr = Transmit { peer: t.destination, data: &self.tx[..size], segment_size: seg, ecn: 0, src_ip: None };
            // A full socket buffer: wait for room rather than drop (QUIC would recover, slowly).
            let end = Instant::now() + Duration::from_millis(50);
            while self.sock.send_msgs(&[tr]).is_err() && Instant::now() < end {
                std::thread::yield_now();
            }
        }
    }

    fn step(&mut self) {
        self.send_all();
        match self.sock.recv_msgs(&mut self.bufs, &mut self.meta) {
            Ok(n) => {
                let now = Instant::now();
                for k in 0..n {
                    let seg = self.meta[k].segment_size.max(1);
                    let peer = self.meta[k].peer;
                    let mut b = std::mem::take(&mut self.bufs[k]);
                    for chunk in b.chunks_mut(seg) {
                        let _ = self.ep.recv(now, peer, chunk, &mut self.resp);
                    }
                    self.bufs[k] = b;
                }
            }
            Err(_) => {
                if self.ep.poll_timeout().is_some_and(|d| d <= Instant::now()) {
                    let mut touched = Vec::new();
                    self.ep.handle_timeout(Instant::now(), &mut touched);
                } else {
                    std::thread::yield_now();
                }
            }
        }
        let now = Instant::now();
        while let Some(ev) = self.ep.poll_event(self.h) {
            if let Some(q) = self.ep.conn_mut(self.h) {
                self.h3.handle(now, q, &ev);
            }
        }
        while let Some(ev) = self.h3.poll_event() {
            match ev {
                H3Event::Data { stream } => {
                    let q = self.ep.conn_mut(self.h).unwrap();
                    let mut tmp = [0u8; 4096];
                    while let Ok((n, fin)) = self.h3.recv_body(now, q, stream, &mut tmp) {
                        self.body.extend_from_slice(&tmp[..n]);
                        if fin {
                            self.done = true;
                            break;
                        }
                        if n == 0 {
                            break;
                        }
                    }
                }
                H3Event::Finished { .. } | H3Event::Reset { .. } => self.done = true,
                _ => {}
            }
        }
    }

    /// Uploads `total` bytes; returns the byte count the server reports.
    fn upload(&mut self, total: usize) -> usize {
        let fields: Vec<(&[u8], &[u8])> = vec![(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/up")];
        let q = self.ep.conn_mut(self.h).unwrap();
        let id = self.h3.send_request(q, &fields, false).unwrap();
        let chunk = vec![0x5au8; 64 * 1024];
        let mut sent = 0;
        let end = Instant::now() + Duration::from_secs(300);
        while sent < total {
            assert!(Instant::now() < end, "upload timed out");
            let q = self.ep.conn_mut(self.h).unwrap();
            let want = (total - sent).min(chunk.len());
            let n = self.h3.send_body(q, id, &chunk[..want], sent + want == total).unwrap();
            sent += n;
            self.step();
        }
        self.body.clear();
        self.done = false;
        while !self.done {
            assert!(Instant::now() < end, "no response");
            self.step();
        }
        String::from_utf8_lossy(&self.body).parse().unwrap_or(0)
    }
}
