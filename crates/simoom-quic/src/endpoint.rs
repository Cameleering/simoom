//! An endpoint: routes datagrams to connections by connection ID, creates server
//! connections, and answers statelessly (Version Negotiation, Retry, stateless reset).
//! It also keeps one deadline heap for all its connections.

use crate::config::Config;
use crate::connection::{Connection, EndpointEvent, Event, Transmit};
use crate::error::TransportError;
use crate::packet::{self, PacketType, MIN_INITIAL_SIZE, MIN_RESET_SIZE};
use crate::params::Cid;
use crate::token::{self, Validated};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Identifies a connection inside an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnHandle(pub usize);

/// What happened to a received datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum DatagramEvent {
    /// Delivered to an existing connection.
    Connection(ConnHandle),
    /// A new server connection was created and the datagram delivered to it.
    NewConnection(ConnHandle),
    /// A stateless reply was written to the response buffer.
    Response(Transmit),
    Dropped,
}

struct Slot {
    conn: Connection,
    gen: u64,
    deadline: Option<Instant>,
    dirty: bool,
    handshaking: bool,
    cids: Vec<Cid>,
    tokens: Vec<[u8; 16]>,
}

pub struct Endpoint {
    cfg: Arc<Config>,
    server: bool,
    slots: Vec<Option<Slot>>,
    free: Vec<usize>,
    by_cid: HashMap<Cid, usize>,
    by_token: HashMap<[u8; 16], usize>,
    timers: BinaryHeap<Reverse<(Instant, usize, u64)>>,
    dirty: VecDeque<usize>,
    next_gen: u64,
    handshaking: usize,
    live: usize,
}

impl Endpoint {
    /// `server` enables accepting connections.
    pub fn new(cfg: Arc<Config>, server: bool) -> Self {
        assert!((4..=20).contains(&cfg.cid_len), "cid_len must be 4..=20");
        Endpoint {
            cfg,
            server,
            slots: Vec::new(),
            free: Vec::new(),
            by_cid: HashMap::new(),
            by_token: HashMap::new(),
            timers: BinaryHeap::new(),
            dirty: VecDeque::new(),
            next_gen: 0,
            handshaking: 0,
            live: 0,
        }
    }

    pub fn config(&self) -> &Arc<Config> {
        &self.cfg
    }

    /// Live connections.
    pub fn len(&self) -> usize {
        self.live
    }
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    fn insert(&mut self, conn: Connection) -> usize {
        self.next_gen += 1;
        let slot = Slot { handshaking: conn.is_handshaking(), conn, gen: self.next_gen, deadline: None, dirty: false, cids: Vec::new(), tokens: Vec::new() };
        if slot.handshaking {
            self.handshaking += 1;
        }
        self.live += 1;
        if let Some(i) = self.free.pop() {
            self.slots[i] = Some(slot);
            i
        } else {
            self.slots.push(Some(slot));
            self.slots.len() - 1
        }
    }

    /// Starts a client connection.
    pub fn connect(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        server_name: &str,
        token: &[u8],
    ) -> Result<ConnHandle, TransportError> {
        self.cfg.epoch.get_or_init(|| now);
        let conn = Connection::connect(self.cfg.clone(), now, remote, server_name, token)?;
        let i = self.insert(conn);
        self.process(i);
        Ok(ConnHandle(i))
    }

    /// Mutable access to a connection; it is scheduled for transmission.
    pub fn conn_mut(&mut self, h: ConnHandle) -> Option<&mut Connection> {
        let slot = self.slots.get_mut(h.0)?.as_mut()?;
        if !slot.dirty {
            slot.dirty = true;
            self.dirty.push_back(h.0);
        }
        Some(&mut slot.conn)
    }

    pub fn conn(&self, h: ConnHandle) -> Option<&Connection> {
        self.slots.get(h.0)?.as_ref().map(|s| &s.conn)
    }

    /// The next event of a connection. A drained connection is removed once its events
    /// have been read.
    pub fn poll_event(&mut self, h: ConnHandle) -> Option<Event> {
        let slot = self.slots.get_mut(h.0)?.as_mut()?;
        let e = slot.conn.poll_event();
        if e.is_none() && slot.conn.is_drained() {
            self.remove(h.0);
        }
        e
    }

    /// Handles of all live connections.
    pub fn handles(&self) -> impl Iterator<Item = ConnHandle> + '_ {
        self.slots.iter().enumerate().filter(|(_, s)| s.is_some()).map(|(i, _)| ConnHandle(i))
    }

    fn remove(&mut self, i: usize) {
        if let Some(slot) = self.slots[i].take() {
            for c in &slot.cids {
                if self.by_cid.get(c) == Some(&i) {
                    self.by_cid.remove(c);
                }
            }
            for t in &slot.tokens {
                if self.by_token.get(t) == Some(&i) {
                    self.by_token.remove(t);
                }
            }
            if slot.handshaking {
                self.handshaking -= 1;
            }
            self.live -= 1;
            self.free.push(i);
        }
    }

    /// Applies routing changes, updates the deadline and schedules transmission.
    fn process(&mut self, i: usize) {
        let Some(slot) = self.slots[i].as_mut() else { return };
        while let Some(ev) = slot.conn.poll_endpoint_event() {
            match ev {
                EndpointEvent::NewCid(c) => {
                    self.by_cid.insert(c, i);
                    slot.cids.push(c);
                }
                EndpointEvent::RetireCid(c) => {
                    if self.by_cid.get(&c) == Some(&i) {
                        self.by_cid.remove(&c);
                    }
                    slot.cids.retain(|x| *x != c);
                }
                EndpointEvent::ResetToken(t) => {
                    self.by_token.insert(t, i);
                    slot.tokens.push(t);
                }
            }
        }
        let hs = slot.conn.is_handshaking();
        if slot.handshaking && !hs {
            self.handshaking -= 1;
        }
        slot.handshaking = hs;
        let d = slot.conn.poll_timeout();
        if d != slot.deadline {
            slot.deadline = d;
            if let Some(d) = d {
                self.timers.push(Reverse((d, i, slot.gen)));
            }
        }
        if !slot.dirty {
            slot.dirty = true;
            self.dirty.push_back(i);
        }
    }

    /// Processes a datagram from `remote`. Stateless replies are written to `response`.
    pub fn recv(&mut self, now: Instant, remote: SocketAddr, data: &mut [u8], response: &mut Vec<u8>) -> DatagramEvent {
        self.cfg.epoch.get_or_init(|| now);
        response.clear();
        let Some(h) = packet::parse_header(data, 0, self.cfg.cid_len) else { return DatagramEvent::Dropped };
        let dcid = Cid::new(&data[h.dcid.clone()]);
        if let Some(&i) = self.by_cid.get(&dcid) {
            if let Some(slot) = self.slots[i].as_mut() {
                slot.conn.recv(now, remote, data);
                self.process(i);
                return DatagramEvent::Connection(ConnHandle(i));
            }
        }
        if h.ty == PacketType::OneRtt {
            // A stateless reset from a peer that lost our connection (RFC 9000 §10.3.1).
            if data.len() >= MIN_RESET_SIZE {
                let tail: [u8; 16] = data[data.len() - 16..].try_into().unwrap();
                if let Some(&i) = self.by_token.get(&tail) {
                    if let Some(slot) = self.slots[i].as_mut() {
                        slot.conn.recv(now, remote, data);
                        self.process(i);
                        return DatagramEvent::Connection(ConnHandle(i));
                    }
                }
            }
            return self.stateless_reset(remote, data.len(), &dcid, response);
        }
        if !self.server || h.ty == PacketType::VersionNegotiation {
            return DatagramEvent::Dropped;
        }
        let scid = &data[h.scid.clone()];
        if !self.cfg.versions.contains(&h.version) {
            if data.len() < MIN_INITIAL_SIZE || scid.len() > 20 || dcid.len() > 20 {
                return DatagramEvent::Dropped;
            }
            let mut r = [0u8; 1];
            self.cfg.provider.fill_random(&mut r);
            packet::version_negotiation(response, r[0], &dcid, scid, &self.cfg.versions);
            return DatagramEvent::Response(Transmit { destination: remote, size: response.len(), segment_size: None });
        }
        if h.ty != PacketType::Initial || data.len() < MIN_INITIAL_SIZE || dcid.len() < 8 {
            return DatagramEvent::Dropped;
        }
        if self.live >= self.cfg.max_connections {
            return DatagramEvent::Dropped;
        }
        let scid = Cid::new(scid);
        let tok = &data[h.token.clone()];
        let mut odcid = dcid;
        let mut retry_scid = None;
        let mut validated = false;
        if !tok.is_empty() {
            match token::validate(&self.cfg, tok, remote, now) {
                Some(Validated::Retry { odcid: o, rscid }) => {
                    if rscid != dcid {
                        return DatagramEvent::Dropped;
                    }
                    odcid = o;
                    retry_scid = Some(rscid);
                    validated = true;
                }
                Some(Validated::NewToken) => validated = true,
                None => {
                    // An invalid Retry token means a forged or stale Retry: drop. An invalid
                    // NEW_TOKEN is treated as no token (RFC 9000 §8.1.3).
                    if tok[0] == 1 {
                        return DatagramEvent::Dropped;
                    }
                }
            }
        }
        if !validated && (self.cfg.retry || self.handshaking >= self.cfg.retry_threshold) {
            let mut b = [0u8; 21];
            self.cfg.provider.fill_random(&mut b);
            let new_scid = Cid::new(&b[1..1 + self.cfg.cid_len]);
            let t = token::retry_token(&self.cfg, remote, now, &dcid, &new_scid);
            packet::retry(response, &*self.cfg.provider, h.version, b[0], &dcid, &scid, &new_scid, &t);
            return DatagramEvent::Response(Transmit { destination: remote, size: response.len(), segment_size: None });
        }
        let mut b = [0u8; 20];
        self.cfg.provider.fill_random(&mut b[..self.cfg.cid_len]);
        let local = Cid::new(&b[..self.cfg.cid_len]);
        let conn = match Connection::accept(self.cfg.clone(), now, remote, h.version, local, dcid, scid, odcid, retry_scid, validated) {
            Ok(c) => c,
            Err(_) => return DatagramEvent::Dropped,
        };
        let i = self.insert(conn);
        // Route both our CID and the client's chosen DCID (for Initial retransmissions).
        for c in [local, dcid] {
            self.by_cid.insert(c, i);
            self.slots[i].as_mut().unwrap().cids.push(c);
        }
        self.slots[i].as_mut().unwrap().conn.recv(now, remote, data);
        self.process(i);
        DatagramEvent::NewConnection(ConnHandle(i))
    }

    /// RFC 9000 §10.3: a reset smaller than the packet that triggered it, at least 21 bytes.
    fn stateless_reset(&self, remote: SocketAddr, len: usize, dcid: &Cid, response: &mut Vec<u8>) -> DatagramEvent {
        if len <= MIN_RESET_SIZE {
            return DatagramEvent::Dropped;
        }
        let size = (len - 1).min(MIN_RESET_SIZE + 22);
        response.resize(size - 16, 0);
        self.cfg.provider.fill_random(response);
        response[0] = 0x40 | (response[0] & 0x3f);
        response.extend_from_slice(&self.cfg.reset_token(dcid));
        DatagramEvent::Response(Transmit { destination: remote, size, segment_size: None })
    }

    /// The next datagram batch to send from any connection.
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut Vec<u8>, max_datagrams: usize) -> Option<(ConnHandle, Transmit)> {
        while let Some(&i) = self.dirty.front() {
            let Some(slot) = self.slots[i].as_mut() else {
                self.dirty.pop_front();
                continue;
            };
            if let Some(t) = slot.conn.poll_transmit(now, buf, max_datagrams) {
                return Some((ConnHandle(i), t));
            }
            slot.dirty = false;
            self.dirty.pop_front();
            self.process_timer_only(i);
        }
        None
    }

    fn process_timer_only(&mut self, i: usize) {
        let Some(slot) = self.slots[i].as_mut() else { return };
        while let Some(ev) = slot.conn.poll_endpoint_event() {
            match ev {
                EndpointEvent::NewCid(c) => {
                    self.by_cid.insert(c, i);
                    slot.cids.push(c);
                }
                EndpointEvent::RetireCid(c) => {
                    if self.by_cid.get(&c) == Some(&i) {
                        self.by_cid.remove(&c);
                    }
                    slot.cids.retain(|x| *x != c);
                }
                EndpointEvent::ResetToken(t) => {
                    self.by_token.insert(t, i);
                    slot.tokens.push(t);
                }
            }
        }
        let d = slot.conn.poll_timeout();
        if d != slot.deadline {
            slot.deadline = d;
            if let Some(d) = d {
                self.timers.push(Reverse((d, i, slot.gen)));
            }
        }
    }

    /// The earliest deadline over all connections.
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        while let Some(&Reverse((t, i, gen))) = self.timers.peek() {
            let live = self.slots.get(i).and_then(|s| s.as_ref()).is_some_and(|s| s.gen == gen && s.deadline == Some(t));
            if live {
                return Some(t);
            }
            self.timers.pop();
        }
        None
    }

    /// Fires due timers; appends the affected connections to `touched`.
    pub fn handle_timeout(&mut self, now: Instant, touched: &mut Vec<ConnHandle>) {
        while let Some(&Reverse((t, i, gen))) = self.timers.peek() {
            if t > now {
                break;
            }
            self.timers.pop();
            let Some(slot) = self.slots.get_mut(i).and_then(|s| s.as_mut()) else { continue };
            if slot.gen != gen || slot.deadline != Some(t) {
                continue;
            }
            slot.deadline = None;
            slot.conn.handle_timeout(now);
            touched.push(ConnHandle(i));
            self.process(i);
        }
    }
}
