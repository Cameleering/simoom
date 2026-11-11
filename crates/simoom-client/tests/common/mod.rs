//! Test servers: simoom on loopback (plain, TLS, QUIC), scripted raw servers and a proxy.

#![allow(dead_code)]

use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Outcome, Reply, Request, Response, Server, ServerHandle};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub fn cert() -> &'static certgen::SelfSigned {
    static C: OnceLock<certgen::SelfSigned> = OnceLock::new();
    C.get_or_init(|| certgen::issue(&CertParams::server(&["localhost", "127.0.0.1"]), PrivateKey::generate_ec(EcCurve::P256), None))
}

pub fn server_config() -> ServerConfig {
    let ss = cert();
    ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap())
}

pub fn roots() -> RootStore {
    let mut r = RootStore::empty();
    r.add_der(&cert().cert_der).unwrap();
    r
}

/// A client trusting the test certificate.
pub fn client() -> simoom_client::ClientBuilder {
    let b = simoom_client::Client::builder();
    // `roots` exists only with the client's `tls` feature
    #[cfg(feature = "tls")]
    let b = b.roots(roots());
    b.connect_timeout(Some(Duration::from_secs(5))).read_timeout(Some(Duration::from_secs(10)))
}

fn header_str(req: &Request<'_>, name: &str) -> String {
    req.header(name).map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default()
}

/// The test service: `/echo` describes the request, `/big?n=` sends n bytes, `/stream` streams
/// parts, `/status?code=`, `/redirect?to=&code=`, `/trailers`, `/slow?ms=`, `/count` counts
/// requests per connection peer.
pub fn service(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let q = |n: &str| req.query_param(n).map(|v| String::from_utf8_lossy(&simoom::percent_decode(v).unwrap_or_else(|| v.to_vec())).into_owned());
    match req.path() {
        b"/big" => {
            let n: usize = q("n").and_then(|v| v.parse().ok()).unwrap_or(1 << 20);
            let body: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            reply.header("content-type", "application/octet-stream").body(body)
        }
        b"/stream" => {
            let parts: usize = q("parts").and_then(|v| v.parse().ok()).unwrap_or(4);
            let mut sink = reply.stream();
            std::thread::spawn(move || {
                for i in 0..parts {
                    sink.write(format!("part{i};").as_bytes()).unwrap();
                    std::thread::sleep(Duration::from_millis(2));
                }
            });
            Outcome::Done
        }
        b"/trailers" => {
            let r = reply.defer();
            std::thread::spawn(move || {
                let mut sink = r.stream(Response::new(200).header("trailer", "x-checksum"));
                sink.write(b"payload").unwrap();
                sink.finish_with_trailers(&[("x-checksum", "abc123")]);
            });
            Outcome::Deferred
        }
        b"/status" => {
            let code: u16 = q("code").and_then(|v| v.parse().ok()).unwrap_or(500);
            reply.status(code).header("x-reason", "test").body(format!("status {code}"))
        }
        b"/redirect" => {
            let code: u16 = q("code").and_then(|v| v.parse().ok()).unwrap_or(302);
            let to = q("to").unwrap_or_else(|| "/echo".into());
            reply.status(code).header("location", to).body("moved")
        }
        b"/loop" => reply.status(302).header("location", "/loop").empty(),
        b"/slow" => {
            let ms: u64 = q("ms").and_then(|v| v.parse().ok()).unwrap_or(500);
            let r = reply.defer();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(ms));
                r.send(Response::text("slow done"));
            });
            Outcome::Deferred
        }
        b"/upload" => {
            // streamed request bodies: count the bytes and a checksum
            if let Some(mut src) = req.take_body() {
                let r = reply.defer();
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    let mut n = 0usize;
                    let mut sum = 0u64;
                    loop {
                        match src.read(&mut buf) {
                            Ok(0) => break,
                            Ok(k) => {
                                n += k;
                                sum = buf[..k].iter().fold(sum, |a, &b| a.wrapping_mul(31).wrapping_add(b as u64));
                            }
                            Err(_) => break,
                        }
                    }
                    r.send(Response::text(format!("{n} {sum}")));
                });
                Outcome::Deferred
            } else {
                let b = req.body();
                let sum = b.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64));
                reply.body(format!("{} {}", b.len(), sum))
            }
        }
        _ => {
            let s = format!(
                "{:?} {} {} q={} host={} ua={} auth={} te={} ct={} len={}",
                req.version(),
                String::from_utf8_lossy(req.method()),
                req.path_str(),
                q("x").unwrap_or_default(),
                req.host().map(|h| String::from_utf8_lossy(h).into_owned()).unwrap_or_default(),
                header_str(req, "user-agent"),
                header_str(req, "authorization"),
                header_str(req, "transfer-encoding"),
                header_str(req, "content-type"),
                req.body().len()
            );
            reply.header("content-type", "text/plain").header("x-multi", "a").header("x-multi", "b").body(s)
        }
    }
}

/// simoom on 127.0.0.1: HTTP/1.1 and h2c.
pub fn plain() -> ServerHandle {
    Server::builder().listen("127.0.0.1:0").threads(2).service(service).start().expect("server")
}

/// simoom with TLS (ALPN h2 / http/1.1) and HTTP/3 next to plain HTTP.
pub fn secure() -> ServerHandle {
    Server::builder()
        .listen("127.0.0.1:0")
        .listen_tls("127.0.0.1:0")
        .tls(server_config())
        .listen_quic("127.0.0.1:0")
        .quic_tls(server_config())
        .threads(2)
        .service(service)
        .start()
        .expect("server")
}

pub fn url(h: &ServerHandle, path: &str) -> String {
    format!("http://127.0.0.1:{}{}", h.local_addrs()[0].port(), path)
}

pub fn surl(h: &ServerHandle, path: &str) -> String {
    format!("https://localhost:{}{}", h.local_addrs()[1].port(), path)
}

/// A raw server: each accepted connection is handled by `f` on its own thread.
pub struct Raw {
    pub addr: SocketAddr,
    pub accepted: Arc<AtomicUsize>,
}

pub fn raw(f: impl Fn(TcpStream, usize) + Send + Sync + 'static) -> Raw {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let acc = accepted.clone();
    let f = Arc::new(f);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { break };
            let n = acc.fetch_add(1, Ordering::SeqCst);
            let f = f.clone();
            std::thread::spawn(move || f(s, n));
        }
    });
    Raw { addr, accepted }
}

/// Reads one request head (up to the blank line) from `s`.
pub fn read_head(s: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// Reads exactly `n` bytes.
pub fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v).unwrap();
    v
}

/// An HTTP proxy: `CONNECT` tunnels and absolute-form forwarding, optionally requiring Basic
/// credentials. Records the request lines it saw.
pub struct Proxy {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<String>>>,
}

pub fn proxy(credentials: Option<&str>) -> Proxy {
    let want = credentials.map(|c| {
        let mut out = Vec::new();
        simoom_http1::base64_encode(c.as_bytes(), &mut out);
        format!("Basic {}", String::from_utf8(out).unwrap())
    });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let r = raw(move |mut c, _| {
        let Some(head) = read_head(&mut c) else { return };
        let line = head.lines().next().unwrap_or("").to_string();
        seen2.lock().unwrap().push(line.clone());
        if let Some(w) = &want {
            let ok = head.lines().any(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:") && l.split_once(':').map(|x| x.1.trim()) == Some(w.as_str()));
            if !ok {
                let _ = c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            }
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("").to_string();
        if method == "CONNECT" {
            let Ok(up) = TcpStream::connect(&target) else {
                let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                return;
            };
            c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
            pipe(c, up);
        } else {
            // absolute form: forward the head as is (origin servers accept absolute-form)
            let auth = target.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("").to_string();
            let Ok(mut up) = TcpStream::connect(&auth) else { return };
            let fwd: String = head.lines().filter(|l| !l.to_ascii_lowercase().starts_with("proxy-authorization")).map(|l| format!("{l}\r\n")).collect::<String>();
            up.write_all(fwd.trim_end_matches("\r\n").as_bytes()).unwrap();
            up.write_all(b"\r\n\r\n").unwrap();
            pipe(c, up);
        }
    });
    Proxy { addr: r.addr, seen }
}

fn pipe(a: TcpStream, b: TcpStream) {
    let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    let (mut a, mut b) = (a, b);
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut b, &mut a);
    let _ = a.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}
