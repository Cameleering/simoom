//! The completion model emulated over a readiness poller (epoll, kqueue): edge-triggered
//! registration once per socket, non-blocking `recv` into a stock buffer only after readiness,
//! and one vectored `sendmsg` per connection per turn for everything queued.

use super::{DriverConfig, DriverStats, Event, Id, LargeBufs, OutBuf, Slab, Spin, Waker, LARGE_BATCH, MAX_SKIPS};
use crate::net::{RawSock, Socket};
use crate::udp::{RecvMeta, Transmit, BATCH};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

/// Token reported for the waker.
pub(crate) const WAKE: u64 = u64::MAX;

/// One readiness event.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ready {
    pub token: u64,
    pub readable: bool,
    pub writable: bool,
    /// Hang-up or error: the next call reports it.
    pub closed: bool,
    /// The peer shut down its sending side (EPOLLRDHUP, EV_EOF): read until 0.
    pub hup: bool,
}

/// An edge-triggered readiness poller.
pub(crate) trait Poller: Sized {
    /// Creates the poller and its waker.
    fn new(events: usize) -> io::Result<(Self, Waker)>;
    /// Registers `sock` for edge-triggered read and (unless `listener`) write readiness.
    fn add(&mut self, sock: RawSock, token: u64, listener: bool, stats: &mut DriverStats) -> io::Result<()>;
    /// Waits for readiness and appends events (the waker's as `WAKE`, already reset). Takes
    /// every ready event the OS has, up to the event array's size, in one call.
    fn wait(&mut self, out: &mut Vec<Ready>, timeout: Option<Duration>, stats: &mut DriverStats) -> io::Result<()>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Listener,
    Stream,
    Udp,
}

struct Entry {
    sock: Socket,
    key: u64,
    kind: Kind,
    readable: bool,
    writable: bool,
    armed: bool,
    in_read: bool,
    in_flush: bool,
    failed: bool,
    hup: bool,
    /// Registered with the poller. Streams are registered lazily, just before the next poll,
    /// so a connection that is read, answered and closed within a few turns (one request per
    /// connection) never costs a registration.
    registered: bool,
    /// A UDP socket receiving into large buffers (GRO).
    large: bool,
    off: usize,
    out: VecDeque<OutBuf>,
}

pub(crate) struct Driver<P: Poller> {
    poller: P,
    waker: Waker,
    slab: Slab<Entry>,
    stash: Vec<Vec<u8>>,
    large: LargeBufs,
    target: usize,
    read_list: Vec<Id>,
    flush_list: Vec<Id>,
    accept_list: Vec<Id>,
    /// Streams not yet registered with the poller.
    unregistered: Vec<Id>,
    pending: Vec<Event>,
    ready: Vec<Ready>,
    scratch: Vec<Vec<u8>>,
    stats: DriverStats,
    budget: usize,
    spin: Spin,
    /// Turns in a row that returned results without polling the OS.
    skips: u8,
}

impl<P: Poller> Driver<P> {
    pub(crate) fn new(cfg: &DriverConfig) -> io::Result<Self> {
        let (poller, waker) = P::new(cfg.events.max(16))?;
        Ok(Driver {
            poller,
            waker,
            slab: Slab::new(),
            stash: Vec::new(),
            large: LargeBufs::default(),
            target: 16,
            read_list: Vec::new(),
            flush_list: Vec::new(),
            accept_list: Vec::new(),
            unregistered: Vec::new(),
            pending: Vec::new(),
            ready: Vec::with_capacity(super::EVENTS_START),
            scratch: Vec::with_capacity(BATCH),
            stats: DriverStats::default(),
            budget: cfg.recv_budget.max(1),
            spin: Spin::new(cfg),
            skips: 0,
        })
    }

    pub(crate) fn waker(&self) -> Waker {
        self.waker.clone()
    }

    fn add(&mut self, sock: Socket, key: u64, kind: Kind) -> io::Result<Id> {
        let raw = sock.raw();
        let id = self.slab.insert(Entry {
            sock,
            key,
            kind,
            readable: false,
            writable: true,
            armed: false,
            in_read: false,
            in_flush: false,
            failed: false,
            hup: false,
            registered: kind != Kind::Stream,
            large: false,
            off: 0,
            out: VecDeque::new(),
        });
        if kind == Kind::Stream {
            self.unregistered.push(id);
        } else if let Err(e) = self.poller.add(raw, id.0, kind == Kind::Listener, &mut self.stats) {
            self.slab.remove(id);
            return Err(e);
        }
        if kind == Kind::Listener {
            // Connections may already be queued; edge triggering would not report them.
            self.slab.get_mut(id).unwrap().in_read = true;
            self.accept_list.push(id);
        }
        Ok(id)
    }

    pub(crate) fn listen(&mut self, sock: Socket, key: u64) -> io::Result<Id> {
        self.add(sock, key, Kind::Listener)
    }

    pub(crate) fn stream(&mut self, sock: Socket, key: u64) -> io::Result<Id> {
        self.add(sock, key, Kind::Stream)
    }

    pub(crate) fn udp(&mut self, sock: Socket, key: u64) -> io::Result<Id> {
        self.add(sock, key, Kind::Udp)
    }

    pub(crate) fn udp_large(&mut self, sock: Socket, key: u64, size: usize) -> io::Result<Id> {
        let id = self.add(sock, key, Kind::Udp)?;
        self.large.size = self.large.size.max(size);
        if let Some(e) = self.slab.get_mut(id) {
            e.large = true;
        }
        Ok(id)
    }

    pub(crate) fn recv(&mut self, id: Id, on: bool) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.kind == Kind::Listener {
            return;
        }
        e.armed = on;
        if on && !e.in_read {
            // The socket may hold data that arrived before (a request right behind the
            // handshake, or with TCP_DEFER_ACCEPT always); edge triggering won't repeat it, so
            // read now: the data is reported at the start of the next turn, without a poll.
            e.readable = true;
            e.in_read = true;
            if e.kind == Kind::Stream && !self.stash.is_empty() {
                let mut pending = std::mem::take(&mut self.pending);
                let done = self.read_one(id, &mut pending);
                self.pending = pending;
                if done {
                    return;
                }
            }
            self.read_list.push(id);
        }
    }

    /// Registers streams that are still open with the poller (before a poll).
    fn register_new(&mut self) {
        for id in std::mem::take(&mut self.unregistered) {
            let Some(e) = self.slab.get_mut(id) else { continue };
            if e.registered {
                continue;
            }
            e.registered = true;
            let raw = e.sock.raw();
            if let Err(error) = self.poller.add(raw, id.0, false, &mut self.stats) {
                let key = e.key;
                e.failed = true;
                e.armed = false;
                self.pending.push(Event::Error { key, error });
            }
        }
    }

    pub(crate) fn send(&mut self, id: Id, buf: OutBuf) {
        let Some(e) = self.slab.get_mut(id) else {
            return;
        };
        if e.failed {
            let key = e.key;
            self.pending.push(Event::Sent { key, buf });
            return;
        }
        e.out.push_back(buf);
        if !e.in_flush {
            e.in_flush = true;
            self.flush_list.push(id);
        }
    }

    pub(crate) fn send_to(&mut self, id: Id, msgs: &[Transmit<'_>]) -> io::Result<usize> {
        let e = self.slab.get(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown socket"))?;
        self.stats.send_calls += 1;
        e.sock.send_msgs(msgs)
    }

    pub(crate) fn close(&mut self, id: Id) {
        let Some(e) = self.slab.remove(id) else { return };
        for buf in e.out {
            self.pending.push(Event::Sent { key: e.key, buf });
        }
        self.pending.push(Event::Closed { key: e.key });
        // Dropping the socket closes the descriptor, which removes it from the poller.
    }

    pub(crate) fn socket(&self, id: Id) -> Option<&Socket> {
        self.slab.get(id).map(|e| &e.sock)
    }

    pub(crate) fn provide(&mut self, buf: Vec<u8>) {
        if let Some(buf) = self.large.keep(buf) {
            self.stash.push(buf);
        }
    }

    pub(crate) fn buffers_wanted(&self) -> usize {
        self.target.saturating_sub(self.stash.len())
    }

    pub(crate) fn set_buffer_target(&mut self, n: usize) {
        self.target = n;
    }

    pub(crate) fn stats(&self) -> DriverStats {
        self.stats
    }

    pub(crate) fn len(&self) -> usize {
        self.slab.len()
    }

    pub(crate) fn turn(&mut self, timeout: Option<Duration>, out: &mut Vec<Event>) -> io::Result<()> {
        let start = out.len();
        out.append(&mut self.pending);
        self.flush(out);
        let work = !self.accept_list.is_empty() || (!self.read_list.is_empty() && !self.stash.is_empty());
        if out.len() > start && !work && self.skips < MAX_SKIPS {
            // Results to report already (sends done, a read made when receiving was turned on):
            // hand them over without a system call; the next turn polls. Bounded, so a loop
            // that keeps producing output still looks at new events.
            self.skips += 1;
            self.spin.worked = true;
            return Ok(());
        }
        self.skips = 0;
        if !self.unregistered.is_empty() {
            self.register_new();
            out.append(&mut self.pending);
        }
        let timeout = if out.len() > start || work { Some(Duration::ZERO) } else { timeout };
        let (poller, ready) = (&mut self.poller, &mut self.ready);
        self.spin.wait(timeout, true, &mut self.stats, |t, st| {
            poller.wait(ready, t, st)?;
            Ok(!ready.is_empty())
        })?;
        self.stats.os_events += self.ready.len() as u64;
        for i in 0..self.ready.len() {
            let r = self.ready[i];
            if r.token == WAKE {
                self.waker.clear();
                out.push(Event::Wake);
                continue;
            }
            let id = Id(r.token);
            let Some(e) = self.slab.get_mut(id) else { continue };
            if e.kind == Kind::Listener {
                if !e.in_read {
                    e.in_read = true;
                    self.accept_list.push(id);
                }
                continue;
            }
            if r.hup || r.closed {
                e.hup = true;
            }
            if r.readable || r.closed {
                e.readable = true;
                if e.armed && !e.in_read {
                    e.in_read = true;
                    self.read_list.push(id);
                }
            }
            if r.writable || r.closed {
                e.writable = true;
                if !e.out.is_empty() && !e.in_flush {
                    e.in_flush = true;
                    self.flush_list.push(id);
                }
            }
        }
        self.ready.clear();
        self.accept(out);
        self.read(out);
        self.flush(out);
        out.append(&mut self.pending);
        self.spin.worked = out.len() > start;
        Ok(())
    }

    fn accept(&mut self, out: &mut Vec<Event>) {
        let list = std::mem::take(&mut self.accept_list);
        for id in list {
            let Some(e) = self.slab.get_mut(id) else { continue };
            let mut n = 0;
            loop {
                if n == 64 {
                    self.accept_list.push(id);
                    break;
                }
                self.stats.accept_calls += 1;
                match e.sock.accept() {
                    Ok((socket, peer)) => {
                        out.push(Event::Accepted { key: e.key, socket, peer });
                        n += 1;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        e.in_read = false;
                        break;
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted || err.kind() == io::ErrorKind::ConnectionAborted => {}
                    Err(error) => {
                        // EMFILE and friends: report and wait for the next edge.
                        e.in_read = false;
                        out.push(Event::Error { key: e.key, error });
                        break;
                    }
                }
            }
        }
    }

    fn read(&mut self, out: &mut Vec<Event>) {
        let list = std::mem::take(&mut self.read_list);
        let mut keep = Vec::new();
        for id in list {
            if !self.read_one(id, out) {
                keep.push(id);
            }
        }
        self.read_list = keep;
    }

    /// Reads one socket on the read list up to the budget. Returns `false` when it must stay
    /// on the list (budget used up, or no buffer).
    fn read_one(&mut self, id: Id, out: &mut Vec<Event>) -> bool {
        let Some(e) = self.slab.get_mut(id) else { return true };
        if !e.armed || !e.readable {
            e.in_read = false;
            return true;
        }
        if self.stash.is_empty() && !e.large {
            return false; // starved: wait for buffers
        }
        let mut done = false;
        for _ in 0..self.budget {
            if e.kind == Kind::Udp {
                let n = if e.large {
                    let large = &mut self.large;
                    self.scratch.extend((0..LARGE_BATCH).map(|_| large.take()));
                    LARGE_BATCH
                } else {
                    let n = self.stash.len().min(BATCH);
                    if n == 0 {
                        break;
                    }
                    let at = self.stash.len() - n;
                    self.scratch.extend(self.stash.drain(at..));
                    n
                };
                let mut meta = [RecvMeta::default(); BATCH];
                self.stats.recv_calls += 1;
                let r = e.sock.recv_msgs(&mut self.scratch, &mut meta);
                match r {
                    Ok(got) => {
                        for (i, buf) in self.scratch.drain(..got).enumerate() {
                            out.push(Event::Datagram { key: e.key, buf, meta: meta[i] });
                        }
                        for b in self.scratch.drain(..) {
                            if let Some(mut b) = self.large.keep(b) {
                                b.clear();
                                self.stash.push(b);
                            }
                        }
                        if got < n {
                            done = true;
                            break;
                        }
                    }
                    Err(err) => {
                        for b in self.scratch.drain(..) {
                            if let Some(mut b) = self.large.keep(b) {
                                b.clear();
                                self.stash.push(b);
                            }
                        }
                        if err.kind() != io::ErrorKind::WouldBlock && err.kind() != io::ErrorKind::Interrupted {
                            out.push(Event::Error { key: e.key, error: err });
                        }
                        done = true;
                        break;
                    }
                }
                continue;
            }
            let Some(mut buf) = self.stash.pop() else { break };
            self.stats.recv_calls += 1;
            match e.sock.recv_into(&mut buf) {
                Ok(0) => {
                    self.stash.push(buf);
                    e.armed = false;
                    out.push(Event::Eof { key: e.key });
                    done = true;
                    break;
                }
                Ok(n) => {
                    let full = n == buf.capacity();
                    out.push(Event::Data { key: e.key, buf });
                    if !full && !e.hup {
                        // A short read drained the socket; new data raises a new edge. After
                        // a hang-up no edge follows, so read on until 0.
                        done = true;
                        break;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.stash.push(buf);
                    done = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                    self.stash.push(buf);
                }
                Err(error) => {
                    self.stash.push(buf);
                    e.armed = false;
                    out.push(Event::Error { key: e.key, error });
                    done = true;
                    break;
                }
            }
        }
        if done {
            e.readable = false;
            e.in_read = false;
        }
        done
    }

    fn flush(&mut self, out: &mut Vec<Event>) {
        if self.flush_list.is_empty() {
            return;
        }
        let list = std::mem::take(&mut self.flush_list);
        for id in list {
            let Some(e) = self.slab.get_mut(id) else { continue };
            e.in_flush = false;
            while e.writable && !e.out.is_empty() && !e.failed {
                let mut slices: [&[u8]; 64] = [&[]; 64];
                let mut n = 0;
                for (i, b) in e.out.iter().take(64).enumerate() {
                    slices[i] = if i == 0 { &b.as_slice()[e.off..] } else { b.as_slice() };
                    n += 1;
                }
                let total: usize = slices[..n].iter().map(|s| s.len()).sum();
                self.stats.send_calls += 1;
                let r = if n == 1 { e.sock.send(slices[0]) } else { e.sock.send_vectored(&slices[..n]) };
                match r {
                    Ok(mut w) => {
                        let partial = w < total;
                        while w > 0 {
                            let front = e.out.front().unwrap().len() - e.off;
                            if w >= front {
                                w -= front;
                                e.off = 0;
                                let buf = e.out.pop_front().unwrap();
                                out.push(Event::Sent { key: e.key, buf });
                            } else {
                                e.off += w;
                                w = 0;
                            }
                        }
                        // Zero-length buffers are done as soon as they reach the front.
                        while e.out.front().is_some_and(|b| b.len() == e.off) {
                            e.off = 0;
                            let buf = e.out.pop_front().unwrap();
                            out.push(Event::Sent { key: e.key, buf });
                        }
                        if partial {
                            e.writable = false; // the kernel buffer is full: wait for the edge
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => e.writable = false,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        e.failed = true;
                        e.off = 0;
                        out.push(Event::Error { key: e.key, error });
                        for buf in e.out.drain(..) {
                            out.push(Event::Sent { key: e.key, buf });
                        }
                    }
                }
            }
        }
    }
}
