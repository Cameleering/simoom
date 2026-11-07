//! Test helpers: start a server on loopback, a minimal blocking HTTP/1.1 client.

#![allow(dead_code)]

use simoom::{Limits, Server, ServerHandle, Service};
use simoom_http1::{parse_response, BodyDecoder, BodyEvent, Framing, Status, EMPTY_HEADER};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn serve(svc: impl Service) -> ServerHandle {
    serve_with(Limits::default(), svc)
}

pub fn serve_with(limits: Limits, svc: impl Service) -> ServerHandle {
    Server::builder().listen("127.0.0.1:0").threads(2).limits(limits).service(svc).start().expect("start")
}

pub fn connect(h: &ServerHandle) -> TcpStream {
    let s = TcpStream::connect(h.local_addr()).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A blocking HTTP/1.1 client connection that keeps leftover bytes between responses.
pub struct Client {
    pub s: TcpStream,
    pub buf: Vec<u8>,
}

impl Client {
    pub fn new(h: &ServerHandle) -> Client {
        Client { s: connect(h), buf: Vec::new() }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.s.write_all(bytes).unwrap();
    }

    fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 16384];
        match self.s.read(&mut tmp) {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
        }
    }

    /// Reads one response (skipping 1xx unless `keep_interim`). `None` on EOF before a head.
    pub fn read_any(&mut self, method: &[u8], keep_interim: bool) -> Option<Resp> {
        loop {
            let mut hs = [EMPTY_HEADER; 64];
            let parsed = parse_response(&self.buf, &mut hs, &simoom_http1::Limits::default(), method);
            match parsed {
                Ok(Status::Complete(r)) => {
                    let status = r.status;
                    let headers: Vec<(String, String)> =
                        r.headers.iter().map(|h| (String::from_utf8_lossy(h.name).into_owned(), String::from_utf8_lossy(h.value).into_owned())).collect();
                    let framing = r.framing;
                    let hl = r.head_len;
                    self.buf.drain(..hl);
                    if (100..200).contains(&status) && status != 101 && !keep_interim {
                        continue;
                    }
                    let body = if status == 101 { Vec::new() } else { self.read_body(framing) };
                    return Some(Resp { status, headers, body });
                }
                Ok(Status::Partial) => {
                    if !self.fill() {
                        return None;
                    }
                }
                Err(e) => panic!("bad response: {e:?} in {:?}", String::from_utf8_lossy(&self.buf)),
            }
        }
    }

    fn read_body(&mut self, framing: Framing) -> Vec<u8> {
        let mut dec = BodyDecoder::new(framing, &simoom_http1::Limits { max_body: u64::MAX, ..Default::default() });
        let mut body = Vec::new();
        loop {
            let (n, ev) = dec.decode(&self.buf).expect("body");
            let mut done = false;
            let mut more = false;
            match ev {
                BodyEvent::Data(d) => body.extend_from_slice(d),
                BodyEvent::End(_) => done = true,
                BodyEvent::NeedMore => more = true,
            }
            self.buf.drain(..n);
            if done {
                return body;
            }
            if more && !self.fill() {
                dec.eof().expect("eof inside body");
                return body;
            }
        }
    }

    pub fn read(&mut self) -> Resp {
        self.read_any(b"GET", false).expect("response")
    }

    pub fn get(&mut self, path: &str) -> Resp {
        self.send(format!("GET {path} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes());
        self.read()
    }

    /// True when the server closed the connection (EOF or reset) within the read timeout.
    pub fn closed(&mut self) -> bool {
        let mut tmp = [0u8; 1024];
        loop {
            match self.s.read(&mut tmp) {
                Ok(0) => return true,
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => return false,
                Err(_) => return true,
            }
        }
    }
}

/// One request on a fresh connection.
pub fn get(h: &ServerHandle, path: &str) -> Resp {
    Client::new(h).get(path)
}

/// Polls `f` until it returns true or `secs` pass.
pub fn wait_for(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    f()
}
