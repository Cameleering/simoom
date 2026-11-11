//! HTTP/3 over QUIC on a real UDP socket, with the simoom-quic and simoom-h3 clients, plus
//! `alt-svc` on the TCP side.

#![cfg(all(feature = "http3", feature = "tls-client"))]

mod common;

use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Outcome, Reply, Request, Response, Server, ServerHandle};
use simoom_h3::{H3Event, Http3};
use simoom_quic::tls::TlsProvider;
use simoom_quic::{Config, ConnHandle, Endpoint};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::ClientConfig;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

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

fn start() -> ServerHandle {
    Server::builder()
        .listen("127.0.0.1:0")
        .listen_quic("127.0.0.1:0")
        .quic_tls(server_config())
        .threads(2)
        .service(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            match req.path() {
                b"/defer" => {
                    let responder = reply.defer();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(20));
                        responder.send(Response::text("deferred over h3"));
                    });
                    Outcome::Deferred
                }
                b"/stream" => {
                    let mut sink = reply.stream();
                    std::thread::spawn(move || {
                        for i in 0..4 {
                            sink.write(format!("part{i};").as_bytes()).unwrap();
                        }
                    });
                    Outcome::Done
                }
                b"/big" => reply.body(vec![b'q'; 1_100_000]),
                b"/slow" => {
                    let responder = reply.defer();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(400));
                        responder.send(Response::new(200).body(vec![b's'; 200_000]));
                    });
                    Outcome::Deferred
                }
                _ => {
                    let s = format!("{:?} {} {} {}", req.version(), String::from_utf8_lossy(req.method()), req.path_str(), req.body().len());
                    reply.header("content-type", "text/plain").body(s)
                }
            }
        })
        .start()
        .unwrap()
}

#[test]
fn http3_round_trips() {
    let h = start();
    let quic = h.quic_addrs()[0];
    let mut c = H3Client::connect(quic);
    let id = c.request("GET", "/hello", b"");
    let r = c.wait(id);
    assert_eq!(r.status, b"200");
    assert_eq!(r.body, b"H3 GET /hello 0");
    assert!(r.headers.iter().any(|(n, _)| n == b"date"));
    let id = c.request("POST", "/up", &vec![7u8; 20_000]);
    assert_eq!(c.wait(id).body, b"H3 POST /up 20000");
    let id = c.request("GET", "/defer", b"");
    assert_eq!(c.wait(id).body, b"deferred over h3");
    let id = c.request("GET", "/stream", b"");
    assert_eq!(c.wait(id).body, b"part0;part1;part2;part3;");
    let id = c.request("GET", "/big", b"");
    assert_eq!(c.wait(id).body.len(), 1_100_000, "a response over the 1 MiB stream window");
    // Several streams at once.
    let ids: Vec<u64> = (0..10).map(|i| c.request("GET", &format!("/m{i}"), b"")).collect();
    for (i, id) in ids.into_iter().enumerate() {
        assert_eq!(c.wait(id).body, format!("H3 GET /m{i} 0").into_bytes());
    }
    assert!(h.stats().h3_connections >= 1);
}

#[test]
fn tcp_responses_announce_http3() {
    let h = start();
    let port = h.quic_addrs()[0].port();
    let r = common::get(&h, "/");
    assert_eq!(r.header("alt-svc"), Some(&*format!("h3=\":{port}\"; ma=86400")));
}

#[test]
fn http3_graceful_stop_finishes_in_flight_streams() {
    let h = start();
    let quic = h.quic_addrs()[0];
    let mut c = H3Client::connect(quic);
    let id = c.request("GET", "/slow", b"");
    let end = Instant::now() + Duration::from_secs(10);
    while h.stats().requests == 0 {
        assert!(Instant::now() < end, "the request never reached the server");
        c.step();
    }
    // Stop while the response is still being produced: GOAWAY, then the stream finishes.
    let t0 = Instant::now();
    h.stop(Duration::from_secs(10));
    let joiner = std::thread::spawn(move || {
        h.join();
        t0.elapsed()
    });
    let r = c.wait(id);
    assert_eq!(r.status, b"200");
    assert_eq!(r.body.len(), 200_000, "the in-flight response was cut short");
    assert!(c.goaway, "no GOAWAY before the close");
    // Then the server closes the connection, and the loops exit long before the deadline.
    let end = Instant::now() + Duration::from_secs(8);
    while !c.ep.conn(c.h).is_none_or(|q| q.is_closed()) {
        assert!(Instant::now() < end, "the server never closed the idle connection");
        c.step();
    }
    while !joiner.is_finished() {
        assert!(Instant::now() < end, "the server did not exit after its streams finished");
        c.step();
    }
    let took = joiner.join().unwrap();
    assert!(took >= Duration::from_millis(300), "stopped after {took:?}, before the deferred reply");
    assert!(took < Duration::from_secs(8), "stop took {took:?}");
}

// Bug 12: a loop builds its QUIC endpoint on its first datagram; loops without HTTP/3 traffic
// build none, and a stop before any traffic finishes at once.
#[test]
fn quic_endpoints_are_built_on_first_datagram() {
    let h = start();
    assert_eq!(h.stats().quic_endpoints, 0, "no endpoint before any datagram");
    let mut c = H3Client::connect(h.quic_addrs()[0]);
    let id = c.request("GET", "/lazy", b"");
    assert_eq!(c.wait(id).body, b"H3 GET /lazy 0");
    // one connection's datagrams all reach one socket (one loop)
    assert_eq!(h.stats().quic_endpoints, 1);

    let idle = start();
    let t0 = Instant::now();
    idle.stop(Duration::from_secs(10));
    idle.join();
    assert!(t0.elapsed() < Duration::from_secs(2), "an idle HTTP/3 listener delayed the stop");
}

/// Bug 14: request trailers reach the service over HTTP/3, buffered and streamed.
#[test]
fn http3_request_trailers_reach_the_service() {
    use std::io::Read;
    let h = Server::builder()
        .listen_quic("127.0.0.1:0")
        .quic_tls(server_config())
        .threads(1)
        .limits(simoom::Limits { body_buffer: 1024, ..simoom::Limits::default() })
        .service(simoom::blocking(|mut req: simoom::OwnedRequest| {
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
        }))
        .start()
        .unwrap();
    let mut c = H3Client::connect(h.quic_addrs()[0]);
    for (body, want) in [(vec![b'a'; 7], "7 x-sum=7"), (vec![b'b'; 5000], "5000 x-sum=5000")] {
        let fields: Vec<(&[u8], &[u8])> = vec![(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/t")];
        let q = c.ep.conn_mut(c.h).unwrap();
        let id = c.h3.send_request(q, &fields, false).unwrap();
        let mut sent = 0;
        while sent < body.len() {
            let q = c.ep.conn_mut(c.h).unwrap();
            sent += c.h3.send_body(q, id, &body[sent..], false).unwrap();
            c.step();
        }
        let sum = body.len().to_string();
        let q = c.ep.conn_mut(c.h).unwrap();
        c.h3.send_trailers(q, id, &[(b"x-sum", sum.as_bytes())]).unwrap();
        c.send_all();
        assert_eq!(String::from_utf8(c.wait(id).body).unwrap(), want);
    }
}
