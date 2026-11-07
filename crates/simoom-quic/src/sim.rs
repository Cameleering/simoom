//! A deterministic in-memory network for tests and benchmarks: two endpoints joined by
//! links that can drop, duplicate, reorder and delay datagrams, with an optional
//! bottleneck (bandwidth and queue). Time is virtual and advanced by the simulation.

use crate::config::Config;
use crate::connection::Transmit;
use crate::endpoint::{ConnHandle, DatagramEvent, Endpoint};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Link behaviour, per direction. Probabilities are in parts per million.
#[derive(Clone, Debug)]
pub struct Link {
    pub delay: Duration,
    pub jitter: Duration,
    pub loss_ppm: u32,
    pub duplicate_ppm: u32,
    /// Reordered datagrams get an extra delay of up to `reorder_delay`.
    pub reorder_ppm: u32,
    pub reorder_delay: Duration,
    /// Bytes per second; `None` is unlimited.
    pub bandwidth: Option<u64>,
    /// Bottleneck queue in bytes (tail drop).
    pub queue: usize,
    /// Datagrams larger than this are dropped (path MTU).
    pub mtu: usize,
}

impl Default for Link {
    fn default() -> Self {
        Link {
            delay: Duration::from_millis(10),
            jitter: Duration::ZERO,
            loss_ppm: 0,
            duplicate_ppm: 0,
            reorder_ppm: 0,
            reorder_delay: Duration::ZERO,
            bandwidth: None,
            queue: usize::MAX,
            mtu: 1500,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinkStats {
    pub sent: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub duplicated: u64,
    pub bytes: u64,
}

struct Dgram {
    from: SocketAddr,
    to: SocketAddr,
    data: Vec<u8>,
}

/// A queued datagram, ordered by delivery time then sequence.
struct Queued(Instant, u64, Dgram);

impl PartialEq for Queued {
    fn eq(&self, o: &Self) -> bool {
        (self.0, self.1) == (o.0, o.1)
    }
}
impl Eq for Queued {}
impl PartialOrd for Queued {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Queued {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.0, self.1).cmp(&(o.0, o.1))
    }
}

/// xorshift64*: deterministic and good enough for simulation.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9e3779b97f4a7c15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545f4914f6cdd1d)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    pub fn chance(&mut self, ppm: u32) -> bool {
        ppm > 0 && self.below(1_000_000) < ppm as u64
    }
}

/// Two endpoints and the links between them.
pub struct Pair {
    pub now: Instant,
    pub client: Endpoint,
    pub server: Endpoint,
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
    /// Old client addresses that still reach the client (after a rebinding).
    pub client_aliases: Vec<SocketAddr>,
    pub to_server: Link,
    pub to_client: Link,
    pub to_server_stats: LinkStats,
    pub to_client_stats: LinkStats,
    pub rng: Rng,
    queue: BinaryHeap<Reverse<Queued>>,
    seq: u64,
    busy_until: [Instant; 2],
    queued_bytes: [usize; 2],
    buf: Vec<u8>,
    resp: Vec<u8>,
    /// Server connections accepted so far.
    pub accepted: Vec<ConnHandle>,
    /// GSO batch size used when polling endpoints.
    pub batch: usize,
    /// Optional hook to inspect or rewrite datagrams in flight; return false to drop.
    pub tamper: Option<Box<dyn FnMut(bool, &mut Vec<u8>) -> bool>>,
}

impl Pair {
    pub fn new(client_cfg: Arc<Config>, server_cfg: Arc<Config>, link: Link, seed: u64) -> Self {
        let now = Instant::now();
        Pair {
            now,
            client: Endpoint::new(client_cfg, false),
            server: Endpoint::new(server_cfg, true),
            client_addr: "10.0.0.1:5000".parse().unwrap(),
            server_addr: "10.0.0.2:443".parse().unwrap(),
            client_aliases: Vec::new(),
            to_server: link.clone(),
            to_client: link,
            to_server_stats: LinkStats::default(),
            to_client_stats: LinkStats::default(),
            rng: Rng::new(seed),
            queue: BinaryHeap::new(),
            seq: 0,
            busy_until: [now; 2],
            queued_bytes: [0; 2],
            buf: Vec::with_capacity(64 * 1024),
            resp: Vec::new(),
            accepted: Vec::new(),
            batch: 8,
            tamper: None,
        }
    }

    /// Starts a client connection to the server.
    pub fn connect(&mut self) -> ConnHandle {
        let addr = self.server_addr;
        self.client.connect(self.now, addr, "localhost", &[]).unwrap()
    }

    fn enqueue(&mut self, to_server: bool, from: SocketAddr, to: SocketAddr, mut data: Vec<u8>) {
        let d = if to_server { 0 } else { 1 };
        let link = if to_server { self.to_server.clone() } else { self.to_client.clone() };
        let stats = if to_server { &mut self.to_server_stats } else { &mut self.to_client_stats };
        stats.sent += 1;
        if let Some(t) = self.tamper.as_mut() {
            if !t(to_server, &mut data) {
                stats.dropped += 1;
                return;
            }
        }
        if data.len() > link.mtu || self.rng.chance(link.loss_ppm) {
            stats.dropped += 1;
            return;
        }
        // Bottleneck: serialisation delay and a tail-drop queue.
        let mut depart = self.now;
        if let Some(bw) = link.bandwidth {
            if self.queued_bytes[d] + data.len() > link.queue && self.busy_until[d] > self.now {
                stats.dropped += 1;
                return;
            }
            let start = self.busy_until[d].max(self.now);
            let tx = Duration::from_nanos(data.len() as u64 * 1_000_000_000 / bw);
            self.busy_until[d] = start + tx;
            depart = start + tx;
            self.queued_bytes[d] += data.len();
        }
        let mut at = depart + link.delay;
        if !link.jitter.is_zero() {
            at += Duration::from_nanos(self.rng.below(link.jitter.as_nanos() as u64));
        }
        if self.rng.chance(link.reorder_ppm) {
            at += Duration::from_nanos(self.rng.below(link.reorder_delay.as_nanos() as u64 + 1));
        }
        let dup = self.rng.chance(link.duplicate_ppm);
        if dup {
            stats.duplicated += 1;
        }
        stats.bytes += data.len() as u64;
        let n = data.len();
        if dup {
            let copy = data.clone();
            self.push(at + Duration::from_micros(50), Dgram { from, to, data: copy });
        }
        let _ = n;
        self.push(at, Dgram { from, to, data });
    }

    fn push(&mut self, at: Instant, d: Dgram) {
        self.seq += 1;
        self.queue.push(Reverse(Queued(at, self.seq, d)));
    }

    fn flush(&mut self) {
        loop {
            let mut any = false;
            while let Some((_, t)) = self.client.poll_transmit(self.now, &mut self.buf, self.batch) {
                any = true;
                let from = self.client_addr;
                self.split_send(true, from, t);
            }
            while let Some((_, t)) = self.server.poll_transmit(self.now, &mut self.buf, self.batch) {
                any = true;
                let from = self.server_addr;
                self.split_send(false, from, t);
            }
            if !any {
                break;
            }
        }
    }

    fn split_send(&mut self, to_server: bool, from: SocketAddr, t: Transmit) {
        let seg = t.segment_size.unwrap_or(t.size);
        let data = std::mem::take(&mut self.buf);
        for chunk in data[..t.size].chunks(seg) {
            self.enqueue(to_server, from, t.destination, chunk.to_vec());
        }
        self.buf = data;
    }

    /// Runs one step: send what is ready, then deliver the next datagram or fire the next
    /// timer. Returns false when nothing is left to do.
    pub fn step(&mut self) -> bool {
        self.step_until(None)
    }

    /// Like [`Pair::step`], but never advances the clock past `limit`.
    pub fn step_until(&mut self, limit: Option<Instant>) -> bool {
        self.flush();
        let next_dgram = self.queue.peek().map(|r| r.0 .0);
        let next_timer = [self.client.poll_timeout(), self.server.poll_timeout()].into_iter().flatten().min();
        let next = match (next_dgram, next_timer) {
            (None, None) => return false,
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (Some(a), Some(b)) => a.min(b),
        };
        if let Some(l) = limit {
            if next > l {
                self.now = self.now.max(l);
                return false;
            }
        }
        if next > self.now {
            self.now = next;
        }
        if next_dgram.is_some_and(|a| a <= self.now) {
            let Reverse(Queued(_, _, mut d)) = self.queue.pop().unwrap();
            let to_server = d.to == self.server_addr;
            let di = if to_server { 0 } else { 1 };
            self.queued_bytes[di] = self.queued_bytes[di].saturating_sub(d.data.len());
            if to_server {
                self.to_server_stats.delivered += 1;
                let ev = self.server.recv(self.now, d.from, &mut d.data, &mut self.resp);
                match ev {
                    DatagramEvent::NewConnection(h) => self.accepted.push(h),
                    DatagramEvent::Response(t) => {
                        let r = self.resp[..t.size].to_vec();
                        let from = self.server_addr;
                        self.enqueue(false, from, t.destination, r);
                    }
                    _ => {}
                }
            } else if d.to == self.client_addr || self.client_aliases.contains(&d.to) {
                self.to_client_stats.delivered += 1;
                let ev = self.client.recv(self.now, d.from, &mut d.data, &mut self.resp);
                if let DatagramEvent::Response(t) = ev {
                    let r = self.resp[..t.size].to_vec();
                    let from = self.client_addr;
                    self.enqueue(true, from, t.destination, r);
                }
            } else {
                self.to_client_stats.dropped += 1;
            }
        } else {
            let mut touched = Vec::new();
            self.client.handle_timeout(self.now, &mut touched);
            self.server.handle_timeout(self.now, &mut touched);
        }
        true
    }

    /// Steps until `cond` holds or `limit` of virtual time passes; returns whether it held.
    pub fn run_until(&mut self, limit: Duration, mut cond: impl FnMut(&mut Pair) -> bool) -> bool {
        let deadline = self.now + limit;
        loop {
            if cond(self) {
                return true;
            }
            if self.now >= deadline || !self.step_until(Some(deadline)) {
                return cond(self);
            }
        }
    }

    /// Runs until both sides are idle (no datagrams or timers due within `limit`).
    pub fn run_for(&mut self, limit: Duration) {
        let deadline = self.now + limit;
        while self.now < deadline {
            if !self.step_until(Some(deadline)) {
                break;
            }
        }
    }

    /// The first accepted server connection.
    pub fn server_conn(&self) -> Option<ConnHandle> {
        self.accepted.first().copied()
    }

    /// Simulates a NAT rebinding: the client's datagrams now come from `addr`.
    pub fn rebind_client(&mut self, addr: SocketAddr) {
        let old = std::mem::replace(&mut self.client_addr, addr);
        self.client_aliases.push(old);
    }

    /// Datagrams in flight.
    pub fn in_flight(&self) -> usize {
        self.queue.len()
    }
}
