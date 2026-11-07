//! TLS 1.3 listeners: HTTP/1.1 and h2 chosen by ALPN, with the simoom-tls client.

#![cfg(feature = "tls-client")]

mod common;

use simoom::tls::{CertifiedKey, ServerConfig};
use simoom::{Outcome, Reply, Request, Server, ServerHandle};
use simoom_http1::{parse_response, Status, EMPTY_HEADER};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::{ClientConfig, ClientConnection};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

fn cert() -> &'static certgen::SelfSigned {
    static C: OnceLock<certgen::SelfSigned> = OnceLock::new();
    C.get_or_init(|| certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None))
}

pub fn server_config() -> ServerConfig {
    let ss = cert();
    ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap())
}

pub fn client_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootStore::empty();
    roots.add_der(&cert().cert_der).unwrap();
    Arc::new(ClientConfig::new(roots).with_alpn(alpn))
}

/// A blocking TLS client stream.
pub struct TlsStream {
    s: TcpStream,
    c: ClientConnection,
}

impl TlsStream {
    pub fn connect(addr: std::net::SocketAddr, alpn: &[&[u8]]) -> TlsStream {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let c = ClientConnection::new(client_config(alpn), "localhost").unwrap();
        let mut t = TlsStream { s, c };
        while t.c.is_handshaking() {
            t.flush_tls();
            t.read_more().expect("handshake");
        }
        t.flush_tls();
        t
    }

    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.c.alpn_protocol().map(<[u8]>::to_vec)
    }

    fn flush_tls(&mut self) {
        if self.c.wants_write() {
            let mut out = Vec::new();
            self.c.write_tls_into(&mut out);
            self.s.write_all(&out).unwrap();
        }
    }

    fn read_more(&mut self) -> std::io::Result<usize> {
        let mut tmp = [0u8; 16384];
        let n = self.s.read(&mut tmp)?;
        if n == 0 {
            return Ok(0);
        }
        let mut off = 0;
        while off < n {
            off += self.c.read_tls(&tmp[off..n]);
            self.c.process_new_packets().map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        }
        Ok(n)
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.c.plaintext().is_empty() {
                return Ok(self.c.read_plaintext(buf));
            }
            if self.c.peer_has_closed() {
                return Ok(0);
            }
            self.flush_tls();
            if self.read_more()? == 0 {
                return Ok(0);
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.c.write_plaintext(buf).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        self.flush_tls();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn read_response(t: &mut TlsStream) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = t.read(&mut tmp).unwrap();
        assert!(n > 0, "eof");
        buf.extend_from_slice(&tmp[..n]);
        let mut hs = [EMPTY_HEADER; 32];
        if let Ok(Status::Complete(r)) = parse_response(&buf, &mut hs, &simoom_http1::Limits::default(), b"GET") {
            let headers: Vec<(String, String)> = r.headers.iter().map(|h| (String::from_utf8_lossy(h.name).into(), String::from_utf8_lossy(h.value).into())).collect();
            let len: usize = r.header(b"content-length").map(|v| std::str::from_utf8(v).unwrap().parse().unwrap()).unwrap_or(0);
            let (status, hl) = (r.status, r.head_len);
            while buf.len() < hl + len {
                let n = t.read(&mut tmp).unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&tmp[..n]);
            }
            return (status, headers, buf[hl..hl + len].to_vec());
        }
    }
}

fn start() -> ServerHandle {
    Server::builder()
        .listen_tls("127.0.0.1:0")
        .tls(server_config())
        .threads(2)
        .service(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            let s = format!("{:?} {} secure={} {}", req.version(), req.path_str(), req.is_secure(), String::from_utf8_lossy(req.body()));
            reply.body(s)
        })
        .start()
        .unwrap()
}

#[test]
fn http1_over_tls_with_keep_alive() {
    let h = start();
    let mut t = TlsStream::connect(h.local_addr(), &[b"http/1.1"]);
    assert_eq!(t.alpn().as_deref(), Some(&b"http/1.1"[..]));
    for i in 0..3 {
        t.write_all(format!("GET /tls/{i} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).unwrap();
        let (status, _, body) = read_response(&mut t);
        assert_eq!(status, 200);
        assert_eq!(body, format!("Http11 /tls/{i} secure=true ").into_bytes());
    }
    t.write_all(b"POST /p HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody").unwrap();
    assert_eq!(read_response(&mut t).2, b"Http11 /p secure=true body");
    // A large body crosses several TLS records.
    let big = vec![b'z'; 50_000];
    t.write_all(format!("POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n", big.len()).as_bytes()).unwrap();
    t.write_all(&big).unwrap();
    let (_, _, body) = read_response(&mut t);
    assert_eq!(body.len(), "Http11 /big secure=true ".len() + big.len());
}

#[test]
fn no_alpn_means_http1() {
    let h = start();
    let mut t = TlsStream::connect(h.local_addr(), &[]);
    t.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut t).0, 200);
}

#[test]
fn a_failed_handshake_is_counted_and_closed() {
    let h = start();
    let mut s = TcpStream::connect(h.local_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut b = Vec::new();
    let _ = s.read_to_end(&mut b);
    assert!(common::wait_for(3, || h.stats().tls_errors == 1));
}

#[cfg(feature = "http2")]
#[test]
fn h2_over_tls_through_alpn() {
    use simoom_h2::{Config, Connection, Event};
    let h = start();
    let mut t = TlsStream::connect(h.local_addr(), &[b"h2", b"http/1.1"]);
    assert_eq!(t.alpn().as_deref(), Some(&b"h2"[..]));
    let mut conn = Connection::client(Config::default());
    let id = conn.send_request(b"GET", b"https", b"localhost", b"/over-tls", &[], true).unwrap();
    let mut body = Vec::new();
    let mut status = 0;
    let mut done = false;
    let mut inbuf = Vec::new();
    let start = std::time::Instant::now();
    while !done {
        assert!(start.elapsed() < Duration::from_secs(10));
        let out = conn.output().to_vec();
        if !out.is_empty() {
            t.write_all(&out).unwrap();
            conn.advance_output(out.len());
        }
        let mut tmp = [0u8; 16384];
        let n = t.read(&mut tmp).unwrap();
        assert!(n > 0);
        inbuf.extend_from_slice(&tmp[..n]);
        let used = conn.recv(&inbuf, start.elapsed().as_millis() as u64, &mut |ev| match ev {
            Event::Headers { stream, headers, end_stream } if stream == id => {
                status = headers.status().unwrap_or(0);
                done |= end_stream;
            }
            Event::Data { stream, data, end_stream } if stream == id => {
                body.extend_from_slice(data);
                done |= end_stream;
            }
            _ => {}
        });
        inbuf.drain(..used);
    }
    assert_eq!(status, 200);
    assert_eq!(body, b"H2 /over-tls secure=true ");
}
