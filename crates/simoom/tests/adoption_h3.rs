//! The Cameleer adoption items on HTTP/3 (docs/BUGS.md U1, U2, U4, U5, U6): response trailers,
//! connection info, the deferred-reply timeout, the completion hook and QUIC certificate reload,
//! with the simoom-quic and simoom-h3 clients.

#![cfg(all(feature = "http3", feature = "tls-client"))]

mod common;

use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Completion, Limits, Outcome, Reply, Request, Response, Server, ServerHandle, Version};
use simoom_h3::{H3Event, Http3};
use simoom_quic::tls::TlsProvider;
use simoom_quic::{Config, ConnHandle, Endpoint};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::ClientConfig;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

fn cert2() -> &'static certgen::SelfSigned {
    static C: OnceLock<certgen::SelfSigned> = OnceLock::new();
    C.get_or_init(|| certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None))
}

fn cert() -> &'static certgen::SelfSigned {
    static C: OnceLock<certgen::SelfSigned> = OnceLock::new();
    C.get_or_init(|| certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None))
}

fn server_config() -> ServerConfig {
    let ss = cert();
    ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap())
}

#[derive(Default, Debug)]
struct Resp {
    status: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
    trailers: Vec<(Vec<u8>, Vec<u8>)>,
    done: bool,
}

struct H3Client {
    sock: UdpSocket,
    ep: Endpoint,
    h: ConnHandle,
    h3: Http3,
    server: SocketAddr,
    resps: HashMap<u64, Resp>,
    tx: Vec<u8>,
    resp_buf: Vec<u8>,
    goaway: bool,
}

impl H3Client {
    fn connect(server: SocketAddr) -> H3Client {
        let mut roots = RootStore::empty();
        roots.add_der(&cert().cert_der).unwrap();
        roots.add_der(&cert2().cert_der).unwrap();
        let cfg = Config::new(Arc::new(TlsProvider::client(Arc::new(ClientConfig::new(roots).with_alpn(&[b"h3"])))));
        let mut ep = Endpoint::new(Arc::new(cfg), false);
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let h = ep.connect(Instant::now(), server, "localhost", &[]).unwrap();
        let mut c = H3Client { sock, ep, h, h3: Http3::new(false, simoom_h3::Config::default()), server, resps: HashMap::new(), tx: Vec::new(), resp_buf: Vec::new(), goaway: false };
        let end = Instant::now() + Duration::from_secs(10);
        while !(c.ep.conn(c.h).is_some_and(|q| q.is_established()) && c.h3.peer_settings().is_some()) {
            assert!(Instant::now() < end, "HTTP/3 handshake timed out");
            c.step();
        }
        c
    }

    fn send_all(&mut self) {
        let now = Instant::now();
        while let Some((_, t)) = self.ep.poll_transmit(now, &mut self.tx, 1) {
            let _ = self.sock.send_to(&self.tx[..t.size], t.destination);
        }
    }

    fn step(&mut self) {
        self.send_all();
        let now = Instant::now();
        let wait = self.ep.poll_timeout().map_or(Duration::from_millis(50), |d| d.saturating_duration_since(now)).clamp(Duration::from_millis(1), Duration::from_millis(50));
        self.sock.set_read_timeout(Some(wait)).unwrap();
        let mut buf = vec![0u8; 65536];
        match self.sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let _ = self.ep.recv(Instant::now(), from, &mut buf[..n], &mut self.resp_buf);
            }
            Err(_) => {
                let mut touched = Vec::new();
                self.ep.handle_timeout(Instant::now(), &mut touched);
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
                H3Event::Headers { stream, fields } => {
                    let r = self.resps.entry(stream).or_default();
                    for f in fields {
                        if f.name == b":status" {
                            r.status = f.value.clone();
                        } else {
                            r.headers.push((f.name.clone(), f.value.clone()));
                        }
                    }
                }
                H3Event::Data { stream } => {
                    let q = self.ep.conn_mut(self.h).unwrap();
                    let mut tmp = vec![0u8; 65536];
                    while let Ok((n, fin)) = self.h3.recv_body(now, q, stream, &mut tmp) {
                        let r = self.resps.entry(stream).or_default();
                        r.body.extend_from_slice(&tmp[..n]);
                        if fin {
                            r.done = true;
                            break;
                        }
                        if n == 0 {
                            break;
                        }
                    }
                }
                H3Event::Trailers { stream, fields } => self.resps.entry(stream).or_default().trailers = fields.iter().map(|f| (f.name.clone(), f.value.clone())).collect(),
                H3Event::Finished { stream } => self.resps.entry(stream).or_default().done = true,
                H3Event::Reset { stream, .. } => self.resps.entry(stream).or_default().done = true,
                H3Event::GoAway { .. } => self.goaway = true,
                _ => {}
            }
        }
        self.send_all();
    }

    fn request(&mut self, method: &str, path: &str, body: &[u8]) -> u64 {
        let fields: Vec<(&[u8], &[u8])> = vec![(b":method", method.as_bytes()), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", path.as_bytes())];
        let q = self.ep.conn_mut(self.h).unwrap();
        let id = self.h3.send_request(q, &fields, body.is_empty()).unwrap();
        let mut sent = 0;
        while !body.is_empty() {
            let q = self.ep.conn_mut(self.h).unwrap();
            let n = self.h3.send_body(q, id, &body[sent..], true).unwrap();
            sent += n;
            if sent == body.len() {
                break;
            }
            self.step();
        }
        self.send_all();
        id
    }

    fn wait(&mut self, id: u64) -> Resp {
        let end = Instant::now() + Duration::from_secs(15);
        while !self.resps.get(&id).is_some_and(|r| r.done) {
            assert!(Instant::now() < end, "timeout on stream {id} ({:?})", self.server);
            self.step();
        }
        self.resps.remove(&id).unwrap()
    }
}


fn tr<'a>(r: &'a Resp, name: &str) -> Option<&'a [u8]> {
    r.trailers.iter().find(|(n, _)| n == name.as_bytes()).map(|(_, v)| v.as_slice())
}

#[allow(clippy::type_complexity)]
fn start(limits: Limits) -> (ServerHandle, Arc<Mutex<Vec<Completion>>>, mpsc::Receiver<simoom::Responder>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let h = Server::builder()
        .listen_quic("127.0.0.1:0")
        .quic_tls(server_config())
        .threads(1)
        .limits(limits)
        .on_complete(move |c: &Completion| l2.lock().unwrap().push(c.clone()))
        .service(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            match req.path() {
                b"/now" => reply.trailer("grpc-status", "0").body_static(b"payload"),
                b"/big" => reply.trailer("grpc-status", "0").body(vec![b'b'; 300_000]),
                b"/later" => {
                    let r = reply.defer();
                    std::thread::spawn(move || {
                        r.send(Response::new(200).body("deferred").trailer("grpc-status", "7"));
                    });
                    Outcome::Deferred
                }
                b"/stream" => {
                    let mut sink = reply.stream();
                    std::thread::spawn(move || {
                        sink.write(b"part").unwrap();
                        sink.finish_with_trailers(&[("grpc-status", "13")]);
                    });
                    Outcome::Done
                }
                b"/hold" => {
                    tx.lock().unwrap().send(reply.defer()).unwrap();
                    Outcome::Deferred
                }
                _ => {
                    let t = req.tls().expect("tls");
                    let s = format!("{} {} {:?} {} {}", req.listener(), req.local_addr().unwrap(), req.version(), String::from_utf8_lossy(t.alpn().unwrap_or(b"-")), t.server_name().unwrap_or("-"));
                    reply.body(s)
                }
            }
        })
        .start()
        .unwrap();
    (h, log, rx)
}

#[test]
fn h3_trailers_info_and_completions() {
    let (h, log, _rx) = start(Limits::default());
    let mut c = H3Client::connect(h.quic_addrs()[0]);
    let ids: Vec<u64> = ["/now", "/big", "/later", "/stream", "/info"].iter().map(|p| c.request("GET", p, b"")).collect();
    let r = c.wait(ids[0]);
    assert_eq!((r.body.as_slice(), tr(&r, "grpc-status")), (&b"payload"[..], Some(&b"0"[..])));
    let r = c.wait(ids[1]);
    assert_eq!((r.body.len(), tr(&r, "grpc-status")), (300_000, Some(&b"0"[..])));
    let r = c.wait(ids[2]);
    assert_eq!((r.body.as_slice(), tr(&r, "grpc-status")), (&b"deferred"[..], Some(&b"7"[..])));
    let r = c.wait(ids[3]);
    assert_eq!((r.body.as_slice(), tr(&r, "grpc-status")), (&b"part"[..], Some(&b"13"[..])));
    let r = c.wait(ids[4]);
    assert_eq!(String::from_utf8_lossy(&r.body), format!("0 {} H3 h3 localhost", h.quic_addrs()[0]));
    assert!(common::wait_for(5, || log.lock().unwrap().len() >= 5));
    let l = log.lock().unwrap();
    assert!(l.iter().all(|c| c.version == Version::H3 && !c.aborted && c.status == 200), "{l:?}");
    assert!(l.iter().any(|c| c.bytes_out == 300_000), "{l:?}");
}

#[test]
fn h3_deferred_timeout() {
    let (h, log, rx) = start(Limits { defer_timeout: Some(Duration::from_millis(200)), ..Limits::default() });
    let mut c = H3Client::connect(h.quic_addrs()[0]);
    let t0 = Instant::now();
    let id = c.request("GET", "/hold", b"");
    let r = c.wait(id);
    assert_eq!(r.status, b"504");
    assert!(t0.elapsed() >= Duration::from_millis(190));
    assert!(rx.recv().unwrap().is_cancelled());
    assert!(common::wait_for(5, || log.lock().unwrap().iter().any(|c| c.status == 504)));
}

#[test]
fn a_new_quic_certificate_applies_to_new_connections() {
    let (h, _log, _rx) = start(Limits::default());
    let leaf = |c: &H3Client| c.ep.conn(c.h).unwrap().tls().peer_certificates()[0].clone();
    let c1 = H3Client::connect(h.quic_addrs()[0]);
    assert_eq!(leaf(&c1), cert().cert_der);
    let ss = cert2();
    h.set_quic_tls(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap())).unwrap();
    let mut c2 = H3Client::connect(h.quic_addrs()[0]);
    assert_eq!(leaf(&c2), ss.cert_der);
    let id = c2.request("GET", "/now", b"");
    assert_eq!(c2.wait(id).body, b"payload");
}
