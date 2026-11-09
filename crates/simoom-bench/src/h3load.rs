//! HTTP/3 load: simoom-quic + simoom-h3 clients on simoom-rt UDP endpoints.
//!
//! Each generator thread is its own one-loop runtime with one UDP socket (an ephemeral port, so
//! the server's replies come back to the loop that owns the connection) and one QUIC endpoint
//! holding that thread's share of the connections. Scheduling and timing are the same as the TCP
//! engine: every connection follows its own open-loop schedule (`rate / conns`), keeps at most
//! `depth` requests (streams) in flight, and latency is timed from the intended send time.
//!
//! The endpoint is created by the runtime, so the generator learns its handle from a one-byte
//! "kick" datagram that it sends to the socket from loopback once the runtime runs.

use crate::load::{self, record, sent, Engine, LoopStats, Report, Sched, Shared, Spec, STATS};
use simoom_h3::{H3Event, Http3};
use simoom_quic::{ConnHandle, DatagramEvent, Endpoint as QuicEndpoint};
use simoom_rt::{EndpointHandle, Message, RecvMeta, Runtime, RuntimeHandle, Transmit, UdpCtx, UdpOptions};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

enum Msg {
    Start,
    Finish,
}

struct Req {
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

struct Conn {
    h: ConnHandle,
    h3: Http3,
    sched: Sched,
    /// Open streams: (stream id, start time, send time, status).
    streams: Vec<(u64, u64, u64, u16)>,
    ready: bool,
    dead: bool,
}

struct Gen {
    sh: Arc<Shared>,
    server: SocketAddr,
    sni: String,
    nconns: usize,
    seed: u64,
    ep: QuicEndpoint,
    conns: Vec<Conn>,
    req: Arc<Req>,
    per_conn_rate: f64,
    slot: Arc<Mutex<Option<EndpointHandle>>>,
    ready: Arc<AtomicUsize>,
    kicked: bool,
    started: bool,
    finished: bool,
    tx: Vec<u8>,
    resp: Vec<u8>,
    rx: Vec<u8>,
    body: Vec<u8>,
    touched: Vec<ConnHandle>,
    armed: Option<(u64, simoom_rt::timer::TimerId)>,
}

impl Gen {
    fn conn_index(&self, h: ConnHandle) -> Option<usize> {
        self.conns.iter().position(|c| c.h == h)
    }

    fn connect_all(&mut self) {
        let now = Instant::now();
        for i in 0..self.nconns {
            if let Ok(h) = self.ep.connect(now, self.server, &self.sni, &[]) {
                let sched = Sched::new(self.per_conn_rate, self.sh_dist(), self.seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                self.conns.push(Conn { h, h3: Http3::new(false, simoom_h3::Config::default()), sched, streams: Vec::new(), ready: false, dead: false });
            }
        }
    }

    fn sh_dist(&self) -> load::Dist {
        self.sh.dist
    }

    /// Feeds QUIC events of `h` to its HTTP/3 layer and records finished responses.
    fn process(&mut self, h: ConnHandle, now_ns: u64) {
        let Some(i) = self.conn_index(h) else { return };
        let inst = Instant::now();
        while let Some(ev) = self.ep.poll_event(h) {
            let c = &mut self.conns[i];
            match self.ep.conn_mut(h) {
                Some(q) => c.h3.handle(inst, q, &ev),
                None => break,
            }
        }
        let c = &mut self.conns[i];
        if self.ep.conn(h).is_none() {
            c.dead = true;
        }
        if !c.ready && self.ep.conn(h).is_some_and(|q| q.is_established()) && c.h3.peer_settings().is_some() {
            c.ready = true;
            self.ready.fetch_add(1, Ordering::Relaxed);
        }
        let mut done: Vec<(u64, u16)> = Vec::new();
        while let Some(ev) = c.h3.poll_event() {
            match ev {
                H3Event::Headers { stream, fields } => {
                    if let Some(s) = c.streams.iter_mut().find(|s| s.0 == stream) {
                        for f in &fields {
                            if f.name == b":status" {
                                s.3 = std::str::from_utf8(&f.value).ok().and_then(|v| v.parse().ok()).unwrap_or(0);
                            }
                        }
                    }
                }
                H3Event::Data { stream } => {
                    if let Some(q) = self.ep.conn_mut(h) {
                        loop {
                            match c.h3.recv_body(inst, q, stream, &mut self.body) {
                                Ok((n, fin)) => {
                                    if fin {
                                        done.push((stream, 0));
                                        break;
                                    }
                                    if n == 0 {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
                H3Event::Finished { stream } => done.push((stream, 0)),
                H3Event::Reset { stream, .. } => done.push((stream, 1)),
                H3Event::Error(_) | H3Event::GoAway { .. } => c.dead = true,
                _ => {}
            }
        }
        for (stream, reset) in done {
            if let Some(k) = c.streams.iter().position(|s| s.0 == stream) {
                let (_, t, ts, st) = c.streams.swap_remove(k);
                record(&self.sh, t, ts, now_ns, if reset == 1 { 0 } else { st });
            }
        }
    }

    fn send_one(&mut self, i: usize, t: u64, now: u64) -> bool {
        let h = self.conns[i].h;
        let Some(q) = self.ep.conn_mut(h) else { return false };
        let fields: Vec<(&[u8], &[u8])> = self.req.fields.iter().map(|(a, b)| (&a[..], &b[..])).collect();
        let c = &mut self.conns[i];
        match c.h3.send_request(q, &fields, self.req.body.is_empty()) {
            Ok(id) => {
                if !self.req.body.is_empty() {
                    let _ = c.h3.send_body(q, id, &self.req.body, true);
                }
                c.streams.push((id, t, now, 0));
                sent(1);
                true
            }
            Err(_) => false,
        }
    }

    /// Sends due requests on every connection; returns the earliest future due time.
    fn pump(&mut self, now: u64) -> u64 {
        let mut next = u64::MAX;
        if !self.started || self.finished {
            return next;
        }
        let stop = self.sh.mend.load(Ordering::Relaxed);
        let depth = self.sh.depth;
        for i in 0..self.conns.len() {
            if !self.conns[i].ready || self.conns[i].dead {
                continue;
            }
            if self.sh.open {
                while self.conns[i].streams.len() < depth {
                    let due = self.conns[i].sched.next;
                    if due >= stop || due > now {
                        break;
                    }
                    if !self.send_one(i, due, now) {
                        break;
                    }
                    self.conns[i].sched.advance();
                }
                let c = &self.conns[i];
                if c.streams.len() < depth && c.sched.next < stop {
                    next = next.min(c.sched.next);
                }
            } else if now < stop {
                while self.conns[i].streams.len() < depth {
                    if !self.send_one(i, now, now) {
                        break;
                    }
                }
            }
        }
        next
    }

    fn flush(&mut self, cx: &mut UdpCtx<'_>) {
        let now = Instant::now();
        while let Some((_, t)) = self.ep.poll_transmit(now, &mut self.tx, 16) {
            let size = t.size.min(self.tx.len());
            let seg = t.segment_size.filter(|&s| s < size).unwrap_or(0);
            let tr = Transmit { peer: t.destination, data: &self.tx[..size], segment_size: seg, ecn: 0, src_ip: None };
            let _ = cx.send(&[tr]);
        }
    }

    /// One turn after any input: process, send, flush, re-arm the timer.
    fn turn(&mut self, cx: &mut UdpCtx<'_>) {
        let now = cx.now_ns();
        let touched = std::mem::take(&mut self.touched);
        for h in &touched {
            self.process(*h, now);
        }
        self.touched = touched;
        self.touched.clear();
        let due = self.pump(now);
        self.flush(cx);
        // the earlier of the next scheduled request and the QUIC timer
        let quic = self.ep.poll_timeout().map(|d| {
            let left = d.saturating_duration_since(Instant::now()).as_nanos() as u64;
            now + left
        });
        let at = due.min(quic.unwrap_or(u64::MAX));
        if at == u64::MAX {
            return;
        }
        if let Some((armed_at, id)) = self.armed {
            if armed_at <= at + 5_000 {
                return;
            }
            cx.cancel_timer(id);
        }
        let id = cx.set_timer(Duration::from_nanos(at.saturating_sub(now)), 1);
        self.armed = Some((at, id));
    }

    fn finish(&mut self, now: u64) {
        if self.finished {
            return;
        }
        self.finished = true;
        let (ms, me) = self.sh.window();
        let open = self.sh.open;
        STATS.with(|s| {
            let mut s = s.borrow_mut();
            for c in &mut self.conns {
                for &(_, t, _, _) in &c.streams {
                    s.inflight -= 1;
                    if t >= ms && t < me {
                        s.incomplete += 1;
                        if open {
                            s.record_lost(now.saturating_sub(t));
                        }
                    }
                }
                c.streams.clear();
                if open && c.ready {
                    let mut guard = 0u64;
                    while c.sched.next < me && guard < 100_000_000 {
                        let due = c.sched.next;
                        if due >= ms {
                            s.incomplete += 1;
                            s.record_lost(now.saturating_sub(due));
                        }
                        c.sched.advance();
                        guard += 1;
                    }
                }
            }
        });
    }
}

impl simoom_rt::Endpoint for Gen {
    fn on_datagram(&mut self, cx: &mut UdpCtx<'_>, data: &[u8], meta: &RecvMeta) {
        if meta.peer != self.server {
            // the kick: learn our handle and open the connections
            if !self.kicked && data == b"K" {
                self.kicked = true;
                *self.slot.lock().unwrap() = Some(cx.handle());
                self.connect_all();
                self.flush(cx);
                self.turn(cx);
            }
            return;
        }
        STATS.with(|s| s.borrow_mut().bytes_in += data.len() as u64);
        let now = Instant::now();
        self.rx.clear();
        self.rx.extend_from_slice(data);
        let seg = if meta.segment_size == 0 { self.rx.len() } else { meta.segment_size };
        let mut rx = std::mem::take(&mut self.rx);
        for chunk in rx.chunks_mut(seg.max(1)) {
            match self.ep.recv(now, meta.peer, chunk, &mut self.resp) {
                DatagramEvent::Connection(h) | DatagramEvent::NewConnection(h) => {
                    if !self.touched.contains(&h) {
                        self.touched.push(h);
                    }
                }
                DatagramEvent::Response(t) => {
                    let tr = Transmit { peer: t.destination, data: &self.resp[..t.size.min(self.resp.len())], segment_size: 0, ecn: 0, src_ip: None };
                    let _ = cx.send(&[tr]);
                }
                DatagramEvent::Dropped => {}
            }
        }
        self.rx = rx;
        self.turn(cx);
    }

    fn on_timer(&mut self, cx: &mut UdpCtx<'_>, _token: u64) {
        let now = cx.now_ns();
        if let Some((at, _)) = self.armed.take() {
            if self.started {
                STATS.with(|s| s.borrow_mut().lag.record(now.saturating_sub(at)));
            }
        }
        if self.ep.poll_timeout().is_some_and(|d| d <= Instant::now()) {
            let mut touched = Vec::new();
            self.ep.handle_timeout(Instant::now(), &mut touched);
            for h in touched {
                if !self.touched.contains(&h) {
                    self.touched.push(h);
                }
            }
        }
        self.turn(cx);
    }

    fn on_message(&mut self, cx: &mut UdpCtx<'_>, msg: Message) {
        let Ok(m) = msg.downcast::<Msg>() else { return };
        match *m {
            Msg::Start => {
                self.started = true;
                if self.sh.open {
                    let t0 = self.sh.t0.load(Ordering::Relaxed);
                    for c in &mut self.conns {
                        c.sched.start(t0);
                    }
                }
                self.turn(cx);
            }
            Msg::Finish => {
                let now = cx.now_ns();
                self.finish(now);
                self.flush(cx);
            }
        }
    }
}

struct H3Prepared {
    spec: Spec,
    sh: Arc<Shared>,
    rts: Vec<RuntimeHandle>,
    handles: Vec<EndpointHandle>,
    ready: Arc<AtomicUsize>,
}

pub(crate) fn prepare(spec: Spec) -> Result<Box<dyn Engine>, String> {
    let open = spec.rate > 0.0 && !spec.idle;
    let mut shared = Shared::for_engine(&spec);
    shared.open = open;
    let sh = Arc::new(shared);
    let tls = load::tls_config(&spec, &[b"h3"], load::wants_resume(&spec))?;
    let qcfg = Arc::new(simoom_quic::Config::new(Arc::new(simoom_quic::tls::TlsProvider::client(tls))));
    let sni = load::server_name(&spec);
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), spec.method.clone().into_bytes()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), spec.host.clone().into_bytes()),
        (b":path".to_vec(), spec.path.clone().into_bytes()),
    ];
    for (k, v) in load::request_headers(&spec) {
        fields.push((k.to_ascii_lowercase().into_bytes(), v.into_bytes()));
    }
    if !spec.body.is_empty() {
        fields.push((b"content-length".to_vec(), spec.body.len().to_string().into_bytes()));
    }
    let req = Arc::new(Req { fields, body: spec.body.clone() });
    let threads = if spec.threads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) } else { spec.threads };
    let threads = threads.min(spec.conns.max(1));
    let cpus = spec.cpus.clone().unwrap_or_else(simoom_sys::cpu::allowed_cpus);
    let per_conn_rate = if open { spec.rate / spec.conns.max(1) as f64 } else { 0.0 };
    let ready = Arc::new(AtomicUsize::new(0));
    let mut rts = Vec::new();
    let mut slots = Vec::new();
    let bind: SocketAddr = if spec.addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    for t in 0..threads {
        let n = spec.conns / threads + usize::from(t < spec.conns % threads);
        let slot: Arc<Mutex<Option<EndpointHandle>>> = Arc::new(Mutex::new(None));
        let (sh2, slot2, ready2, req2, qcfg2, sni2) = (sh.clone(), slot.clone(), ready.clone(), req.clone(), qcfg.clone(), sni.clone());
        let server = spec.addr;
        let seed = spec.seed.wrapping_add(t as u64 * 0x1_0000);
        let backend = spec.backend;
        let tick = spec.tick;
        let cpu = cpus.get(t % cpus.len().max(1)).copied();
        let rt = Runtime::builder()
            .configure(|c| {
                c.threads = 1;
                c.thread_name = "gen".into();
                c.driver.backend = backend;
                c.timer_tick = tick;
                if let Some(cpu) = cpu {
                    c.pin_threads = true;
                    c.cpus = Some(vec![cpu]);
                }
            })
            .udp(bind, UdpOptions { recv_buffer: Some(4 << 20), send_buffer: Some(4 << 20), gro: true, ..UdpOptions::default() }, move |_: &simoom_rt::UdpInfo| -> Box<dyn simoom_rt::Endpoint> {
                Box::new(Gen {
                    sh: sh2.clone(),
                    server,
                    sni: sni2.clone(),
                    nconns: n,
                    seed,
                    ep: QuicEndpoint::new(qcfg2.clone(), false),
                    conns: Vec::new(),
                    req: req2.clone(),
                    per_conn_rate,
                    slot: slot2.clone(),
                    ready: ready2.clone(),
                    kicked: false,
                    started: false,
                    finished: false,
                    tx: Vec::new(),
                    resp: Vec::new(),
                    rx: Vec::new(),
                    body: vec![0u8; 64 * 1024],
                    touched: Vec::new(),
                    armed: None,
                })
            })
            .start()
            .map_err(|e| format!("runtime: {e}"))?;
        rts.push(rt);
        slots.push(slot);
    }
    // kick every endpoint from loopback so it learns its handle and connects
    let kicker = UdpSocket::bind(if spec.addr.is_ipv4() { "127.0.0.1:0" } else { "[::1]:0" }).map_err(|e| e.to_string())?;
    let mut handles = Vec::new();
    for (rt, slot) in rts.iter().zip(&slots) {
        let port = rt.udp_addrs().first().map(|a| a.port()).ok_or("no UDP address")?;
        let target: SocketAddr = if spec.addr.is_ipv4() { format!("127.0.0.1:{port}") } else { format!("[::1]:{port}") }.parse().unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let _ = kicker.send_to(b"K", target);
            std::thread::sleep(Duration::from_millis(5));
            if let Some(h) = slot.lock().unwrap().clone() {
                handles.push(h);
                break;
            }
            if Instant::now() > end {
                return Err("an HTTP/3 generator loop did not start".into());
            }
        }
    }
    // wait for the handshakes
    let want = spec.conns;
    let end = Instant::now() + Duration::from_secs(30);
    while ready.load(Ordering::Relaxed) < want && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    let got = ready.load(Ordering::Relaxed);
    if got < want {
        eprintln!("simoom-bench: {got} of {want} HTTP/3 connections completed the handshake");
    }
    if got == 0 {
        for rt in rts {
            rt.stop(Duration::ZERO);
            rt.join();
        }
        return Err(format!("no HTTP/3 connection to {}", spec.addr));
    }
    Ok(Box::new(H3Prepared { spec, sh, rts, handles, ready }))
}

impl Engine for H3Prepared {
    fn connected(&self) -> usize {
        self.ready.load(Ordering::Relaxed)
    }

    fn go(self: Box<Self>, delay: Duration) -> Report {
        let spec = self.spec.clone();
        let now = simoom_sys::time::now_ns();
        let t0 = now + delay.as_nanos() as u64;
        let (mstart, mend) = self.sh.set_window(t0, &spec);
        for h in &self.handles {
            h.send(Box::new(Msg::Start));
        }
        let sleep_until = |t: u64| {
            let n = simoom_sys::time::now_ns();
            if t > n {
                std::thread::sleep(Duration::from_nanos(t - n));
            }
        };
        sleep_until(mstart);
        let c0 = crate::cpu::sample("gen");
        let s0: u64 = self.rts.iter().map(|r| r.stats().total().driver.syscalls()).sum();
        sleep_until(mend);
        let c1 = crate::cpu::sample("gen");
        let s1: u64 = self.rts.iter().map(|r| r.stats().total().driver.syscalls()).sum();
        let hard_end = mend + spec.drain.as_nanos() as u64;
        sleep_until(mend + 100_000_000u64.min(spec.drain.as_nanos() as u64));
        while simoom_sys::time::now_ns() < hard_end {
            let (tx, rx) = mpsc::channel();
            for rt in &self.rts {
                let tx = tx.clone();
                rt.loops()[0].run(move |_| {
                    let _ = tx.send(STATS.with(|s| s.borrow().inflight));
                });
            }
            drop(tx);
            if rx.iter().sum::<i64>() <= 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        for h in &self.handles {
            h.send(Box::new(Msg::Finish));
        }
        let mut rep = Report {
            spec_rate: if self.sh.open { spec.rate } else { 0.0 },
            conns: spec.conns,
            connected: self.ready.load(Ordering::Relaxed),
            connect_failed: spec.conns.saturating_sub(self.ready.load(Ordering::Relaxed)),
            window_s: spec.duration.as_secs_f64(),
            cpu: crate::cpu::usage(&c0, &c1),
            syscalls: s1.saturating_sub(s0),
            nodes: 1,
            ..Report::default()
        };
        let (tx, rx) = mpsc::channel::<LoopStats>();
        for rt in &self.rts {
            let tx = tx.clone();
            rt.loops()[0].run(move |_| {
                let _ = tx.send(LoopStats::take());
            });
        }
        drop(tx);
        for s in rx.iter() {
            s.add_to(&mut rep);
        }
        rep.backend = format!("{}+quic", self.rts.first().map(|r| crate::load::backend_label(r.backend())).unwrap_or("-"));
        for rt in self.rts {
            rt.stop(Duration::from_millis(200));
            rt.join();
        }
        rep
    }
}
