#![allow(dead_code)]

use simoom_h3::{Config as H3Config, H3Event, Http3};
use simoom_quic::crypto::null::NullProvider;
use simoom_quic::sim::{Link, Pair};
use simoom_quic::{ConnHandle, Config, Event};
use std::sync::Arc;
use std::time::Duration;

pub fn qconfig(seed: u64, f: impl FnOnce(&mut Config)) -> Arc<Config> {
    let mut c = Config::new(Arc::new(NullProvider::new(seed)));
    f(&mut c);
    Arc::new(c)
}

/// A QUIC pair with HTTP/3 on both ends. `client_h3` can be `None` for raw-QUIC clients
/// that hand-craft HTTP/3 bytes.
pub struct H3Pair {
    pub p: Pair,
    pub c: ConnHandle,
    pub s: Option<ConnHandle>,
    pub client: Option<Http3>,
    pub server: Option<Http3>,
    pub server_cfg: H3Config,
    pub cev: Vec<H3Event>,
    pub sev: Vec<H3Event>,
    /// Raw QUIC events of the client when it has no HTTP/3 layer.
    pub raw_cev: Vec<Event>,
}

impl H3Pair {
    pub fn new(link: Link, seed: u64, client: Option<H3Config>, server: H3Config) -> Self {
        Self::with_quic(qconfig(seed, |_| {}), qconfig(seed + 1, |_| {}), link, seed, client, server)
    }

    pub fn with_quic(cq: Arc<Config>, sq: Arc<Config>, link: Link, seed: u64, client: Option<H3Config>, server: H3Config) -> Self {
        let mut p = Pair::new(cq, sq, link, seed);
        let c = p.connect();
        let mut h = H3Pair {
            p,
            c,
            s: None,
            client: client.map(|cfg| Http3::new(false, cfg)),
            server: None,
            server_cfg: server,
            cev: Vec::new(),
            sev: Vec::new(),
            raw_cev: Vec::new(),
        };
        let ok = h.run(Duration::from_secs(30), |h| {
            h.s.is_some()
                && h.p.client.conn(h.c).is_some_and(|c| c.is_established())
                && h.server.as_ref().is_some_and(|s| s.peer_settings().is_some() || h.client.is_none())
                && h.client.as_ref().is_none_or(|c| c.peer_settings().is_some())
        });
        assert!(ok, "HTTP/3 setup did not complete");
        h
    }

    /// Moves QUIC events into the HTTP/3 layers and HTTP/3 events into the vectors.
    pub fn pump(&mut self) {
        let now = self.p.now;
        if self.s.is_none() {
            if let Some(s) = self.p.server_conn() {
                self.s = Some(s);
                self.server = Some(Http3::new(true, self.server_cfg.clone()));
            }
        }
        while let Some(e) = self.p.client.poll_event(self.c) {
            match self.client.as_mut() {
                Some(h3) => {
                    let conn = self.p.client.conn_mut(self.c).unwrap();
                    h3.handle(now, conn, &e);
                }
                None => self.raw_cev.push(e),
            }
        }
        if let Some(h3) = self.client.as_mut() {
            while let Some(e) = h3.poll_event() {
                self.cev.push(e);
            }
        }
        if let (Some(s), Some(h3)) = (self.s, self.server.as_mut()) {
            while let Some(e) = self.p.server.poll_event(s) {
                if let Some(conn) = self.p.server.conn_mut(s) {
                    h3.handle(now, conn, &e);
                }
            }
            while let Some(e) = h3.poll_event() {
                self.sev.push(e);
            }
        }
    }

    pub fn run(&mut self, limit: Duration, mut cond: impl FnMut(&mut H3Pair) -> bool) -> bool {
        let deadline = self.p.now + limit;
        loop {
            self.pump();
            if cond(self) {
                return true;
            }
            if self.p.now >= deadline || !self.p.step_until(Some(deadline)) {
                self.pump();
                return cond(self);
            }
        }
    }

    pub fn run_for(&mut self, d: Duration) {
        self.run(d, |_| false);
    }

    pub fn cconn(&mut self) -> &mut simoom_quic::Connection {
        self.p.client.conn_mut(self.c).unwrap()
    }

    pub fn sconn(&mut self) -> &mut simoom_quic::Connection {
        let s = self.s.unwrap();
        self.p.server.conn_mut(s).unwrap()
    }

    /// Client HTTP/3 and its connection together.
    pub fn client_mut(&mut self) -> (&mut Http3, &mut simoom_quic::Connection) {
        (self.client.as_mut().unwrap(), self.p.client.conn_mut(self.c).unwrap())
    }

    pub fn server_mut(&mut self) -> (&mut Http3, &mut simoom_quic::Connection) {
        let s = self.s.unwrap();
        (self.server.as_mut().unwrap(), self.p.server.conn_mut(s).unwrap())
    }

    /// The error the server closed the connection with, if any.
    pub fn server_error(&self) -> Option<u64> {
        self.sev.iter().find_map(|e| if let H3Event::Error(e) = e { Some(e.code) } else { None })
    }
}

pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed)).collect()
}

pub fn get(path: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"example.com".to_vec()),
        (b":path".to_vec(), path.as_bytes().to_vec()),
        (b"user-agent".to_vec(), b"simoom-test".to_vec()),
    ]
}

pub fn refs(v: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    v.iter().map(|(a, b)| (&a[..], &b[..])).collect()
}
