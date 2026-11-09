//! Runtime tests, on every back end this machine has.

// The UDP tests need the `udp` feature (on by default).
#![cfg_attr(not(feature = "udp"), allow(unused_imports, dead_code))]

mod common;

use common::{backends, builder, wait_until};
use simoom_rt::{
    CloseReason, ConnInfo, Connection, Ctx, Endpoint, Message, RecvMeta, Transmit, UdpCtx, UdpInfo, UdpOptions,
};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

struct Echo;
impl Connection for Echo {
    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let mut out = cx.buffer(data.len());
        out.extend_from_slice(data);
        cx.send(out);
        data.len()
    }
}

fn echo() -> impl Fn(&ConnInfo) -> Option<Box<dyn Connection>> + Send + Sync + 'static {
    |_: &ConnInfo| Some(Box::new(Echo) as Box<dyn Connection>)
}

#[test]
fn tcp_echo_many_connections() {
    for b in backends() {
        let rt = builder(b, 3).listen("127.0.0.1:0", echo()).start().unwrap();
        assert_eq!(rt.backend(), b);
        let addr = rt.local_addrs()[0];
        let clients: Vec<_> = (0..16)
            .map(|i| {
                std::thread::spawn(move || {
                    let mut c = TcpStream::connect(addr).unwrap();
                    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    for round in 0..50 {
                        let msg = format!("client {i} round {round} {}", "x".repeat(round * 37 % 3000));
                        c.write_all(msg.as_bytes()).unwrap();
                        let mut got = vec![0u8; msg.len()];
                        c.read_exact(&mut got).unwrap();
                        assert_eq!(got, msg.as_bytes());
                    }
                })
            })
            .collect();
        for c in clients {
            c.join().unwrap();
        }
        assert!(wait_until(5, || rt.stats().active == 0), "connections close after the clients go");
        let t = rt.stats().total();
        assert_eq!(t.accepted, 16, "{b:?}");
        assert!(t.pool_reused > t.pool_allocated, "{b:?}: pool buffers are reused: {t:?}");
        let used: Vec<u64> = rt.stats().loops.iter().map(|l| l.accepted).collect();
        assert!(used.iter().filter(|&&n| n > 0).count() >= 2, "{b:?}: connections spread over loops: {used:?}");
        rt.stop(Duration::from_secs(1));
        rt.join();
    }
}

#[test]
fn pipelined_requests_are_answered_in_one_batch() {
    struct Lines;
    impl Connection for Lines {
        fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            let mut used = 0;
            while let Some(p) = data[used..].iter().position(|&b| b == b'\n') {
                cx.send_static(b"ok\n");
                used += p + 1;
            }
            used
        }
    }
    for b in backends() {
        let rt = builder(b, 1).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(Lines) as Box<dyn Connection>)).start().unwrap();
        let mut c = TcpStream::connect(rt.local_addrs()[0]).unwrap();
        // 100 requests in one write, the last split over two writes.
        let mut req = "q\n".repeat(99);
        req.push('q');
        c.write_all(req.as_bytes()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        c.write_all(b"\n").unwrap();
        let mut got = vec![0u8; 300];
        c.read_exact(&mut got).unwrap();
        assert!(got.chunks(3).all(|ch| ch == b"ok\n"));
        let t = rt.stats().total();
        assert!(t.driver.send_calls + t.driver.sqes <= 12, "{b:?}: 100 replies took {} send calls", t.driver.send_calls + t.driver.sqes);
    }
}

struct UdpEcho(Arc<AtomicUsize>);
impl Endpoint for UdpEcho {
    fn on_datagram(&mut self, cx: &mut UdpCtx<'_>, data: &[u8], meta: &RecvMeta) {
        self.0.fetch_add(1, Ordering::Relaxed);
        let t = Transmit { peer: meta.peer, data, segment_size: 0, ecn: 0, src_ip: None };
        cx.send(&[t]).unwrap();
    }
}

#[cfg(feature = "udp")]
#[test]
fn udp_echo() {
    for b in backends() {
        let seen = Arc::new(AtomicUsize::new(0));
        let s2 = seen.clone();
        let rt = builder(b, 2)
            .udp("127.0.0.1:0", UdpOptions::default(), move |info: &UdpInfo| {
                assert!(info.local_addr.port() != 0);
                Box::new(UdpEcho(s2.clone())) as Box<dyn Endpoint>
            })
            .start()
            .unwrap();
        let addr = rt.udp_addrs()[0];
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut ok = 0;
        let mut buf = [0u8; 2048];
        for i in 0..50u32 {
            let msg = i.to_be_bytes();
            c.send_to(&msg, addr).unwrap();
            if let Ok((n, _)) = c.recv_from(&mut buf) {
                assert_eq!(&buf[..n], &msg);
                ok += 1;
            }
        }
        assert!(ok >= 48, "{b:?}: {ok}/50 echoed");
        assert!(seen.load(Ordering::Relaxed) >= 48);
    }
}

/// Counts datagrams (segments of GRO batches) and the largest batch.
struct GroCount(Arc<Mutex<(usize, usize, usize)>>);
impl Endpoint for GroCount {
    fn on_datagram(&mut self, _: &mut UdpCtx<'_>, data: &[u8], meta: &RecvMeta) {
        let mut g = self.0.lock().unwrap();
        for seg in data.chunks(meta.segment_size.max(1)) {
            assert_eq!(seg.len(), 1200);
            g.0 += 1;
        }
        g.1 = g.1.max(data.len());
        g.2 += data.len();
    }
}

#[cfg(feature = "udp")]
#[test]
fn udp_with_gro_delivers_whole_batches_to_the_endpoint() {
    for b in backends() {
        let got = Arc::new(Mutex::new((0, 0, 0)));
        let g2 = got.clone();
        let rt = builder(b, 1)
            .udp("127.0.0.1:0", UdpOptions { gro: true, recv_buffer: Some(4 << 20), ..UdpOptions::default() }, move |_: &UdpInfo| Box::new(GroCount(g2.clone())) as Box<dyn Endpoint>)
            .start()
            .unwrap();
        let addr = rt.udp_addrs()[0];
        let sender = simoom_rt::Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions::default()).unwrap();
        let data = vec![5u8; 30 * 1200];
        let mut sent = 0;
        for _ in 0..5 {
            let t = Transmit { peer: addr, data: &data, segment_size: 1200, ecn: 0, src_ip: None };
            if sender.send_msgs(&[t]).is_ok() {
                sent += 30;
            } else {
                for c in data.chunks(1200) {
                    if sender.send_msgs(&[Transmit { peer: addr, data: c, segment_size: 0, ecn: 0, src_ip: None }]).is_ok() {
                        sent += 1;
                    }
                }
            }
            // One batch at a time, so a small socket buffer (Windows) drops nothing.
            assert!(wait_until(10, || got.lock().unwrap().0 >= sent), "{b:?}: {:?} of {sent} datagrams", got.lock().unwrap());
        }
        assert!(wait_until(10, || got.lock().unwrap().0 >= sent), "{b:?}: {:?} of {sent} datagrams", got.lock().unwrap());
        let (n, largest, bytes) = *got.lock().unwrap();
        assert_eq!(bytes, n * 1200);
        #[cfg(target_os = "linux")]
        assert!(largest > 1200, "{b:?}: no GRO batch reached the endpoint");
        let _ = largest;
        rt.stop(Duration::from_secs(1));
        rt.join();
    }
}

/// An endpoint that stays busy after `on_stop` until a timer it sets then fires (or forever).
struct Lingering {
    linger: Option<Duration>,
    busy: bool,
    log: Arc<Mutex<Vec<&'static str>>>,
}
impl Endpoint for Lingering {
    fn on_datagram(&mut self, _: &mut UdpCtx<'_>, _: &[u8], _: &RecvMeta) {}
    fn on_stop(&mut self, cx: &mut UdpCtx<'_>) {
        self.busy = true;
        self.log.lock().unwrap().push("stop");
        // A periodic timer: the loop must keep firing timers while the endpoint is busy.
        cx.set_timer(self.linger.unwrap_or(Duration::from_millis(20)), 0);
    }
    fn on_timer(&mut self, cx: &mut UdpCtx<'_>, _: u64) {
        self.log.lock().unwrap().push("timer");
        match self.linger {
            Some(_) => self.busy = false,
            None => {
                cx.set_timer(Duration::from_millis(20), 0);
            }
        }
    }
    fn is_busy(&self) -> bool {
        self.busy
    }
    fn on_abort(&mut self, _: &mut UdpCtx<'_>) {
        self.log.lock().unwrap().push("abort");
        self.busy = false;
    }
}

#[cfg(feature = "udp")]
fn lingering_runtime(b: simoom_rt::Backend, linger: Option<Duration>, log: &Arc<Mutex<Vec<&'static str>>>) -> simoom_rt::RuntimeHandle {
    let log = log.clone();
    builder(b, 1)
        .udp("127.0.0.1:0", UdpOptions::default(), move |_: &UdpInfo| Box::new(Lingering { linger, busy: false, log: log.clone() }) as Box<dyn Endpoint>)
        .start()
        .unwrap()
}

#[cfg(feature = "udp")]
#[test]
fn a_busy_udp_endpoint_keeps_its_loop_alive_until_idle() {
    for b in backends() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let rt = lingering_runtime(b, Some(Duration::from_millis(300)), &log);
        let t0 = Instant::now();
        rt.stop(Duration::from_secs(10));
        rt.join();
        let took = t0.elapsed();
        assert!(took >= Duration::from_millis(290), "{b:?}: the loop exited after {took:?}, before the endpoint was idle");
        assert!(took < Duration::from_secs(5), "{b:?}: the loop lingered {took:?} after the endpoint was idle");
        assert_eq!(*log.lock().unwrap(), ["stop", "timer"], "{b:?}");
    }
}

#[cfg(feature = "udp")]
#[test]
fn a_udp_endpoint_still_busy_at_the_deadline_is_aborted() {
    for b in backends() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let rt = lingering_runtime(b, None, &log);
        let t0 = Instant::now();
        rt.stop(Duration::from_millis(250));
        rt.join();
        let took = t0.elapsed();
        assert!(took >= Duration::from_millis(240) && took < Duration::from_secs(3), "{b:?}: stop took {took:?}");
        let log = log.lock().unwrap();
        assert_eq!(log.first(), Some(&"stop"), "{b:?}: {log:?}");
        assert_eq!(log.last(), Some(&"abort"), "{b:?}: {log:?}");
        assert!(log.iter().filter(|e| **e == "timer").count() >= 3, "{b:?}: timers stopped while the endpoint was busy: {log:?}");
        assert_eq!(log.iter().filter(|e| **e == "abort").count(), 1, "{b:?}");
    }
}

#[test]
fn timers_fire_and_cancel() {
    struct T {
        log: Arc<Mutex<Vec<(u64, Duration)>>>,
        start: Instant,
        cancel: Option<simoom_rt::timer::TimerId>,
    }
    impl Connection for T {
        fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            self.start = Instant::now();
            cx.set_timer(Duration::from_millis(30), 1);
            cx.set_timer(Duration::from_millis(5), 2);
            self.cancel = Some(cx.set_timer(Duration::from_millis(15), 3));
            data.len()
        }
        fn on_timer(&mut self, cx: &mut Ctx<'_>, token: u64) {
            self.log.lock().unwrap().push((token, self.start.elapsed()));
            if token == 2 {
                assert!(cx.cancel_timer(self.cancel.take().unwrap()));
            }
            if token == 1 {
                cx.send_static(b"done");
                cx.close();
            }
        }
    }
    for b in backends() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l2 = log.clone();
        let rt = builder(b, 1)
            .listen("127.0.0.1:0", move |_: &ConnInfo| Some(Box::new(T { log: l2.clone(), start: Instant::now(), cancel: None }) as Box<dyn Connection>))
            .start()
            .unwrap();
        let mut c = TcpStream::connect(rt.local_addrs()[0]).unwrap();
        c.write_all(b"go").unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"done");
        let log = log.lock().unwrap();
        assert_eq!(log.iter().map(|x| x.0).collect::<Vec<_>>(), vec![2, 1], "{b:?}");
        assert!(log[0].1 >= Duration::from_millis(5), "{b:?} {:?}", log[0].1);
        assert!(log[1].1 >= Duration::from_millis(30), "{b:?} {:?}", log[1].1);
        assert!(log[1].1 < Duration::from_millis(500), "{b:?} {:?}", log[1].1);
    }
}

#[test]
fn messages_from_other_threads_and_offload() {
    struct Deferred;
    impl Connection for Deferred {
        fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            let n = data.len();
            if data.starts_with(b"thread") {
                // Answer later from a plain thread through the connection handle.
                let h = cx.handle();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    assert!(h.send(Box::new(b"from-thread".to_vec())));
                });
            } else {
                cx.offload(move || {
                    std::thread::sleep(Duration::from_millis(5));
                    Box::new(format!("offloaded {n}").into_bytes()) as Message
                })
                .unwrap();
            }
            cx.pause_reading();
            n
        }
        fn on_message(&mut self, cx: &mut Ctx<'_>, msg: Message) {
            let v = msg.downcast::<Vec<u8>>().unwrap();
            cx.send(*v);
            cx.resume_reading();
        }
    }
    for b in backends() {
        let rt = builder(b, 2).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(Deferred) as Box<dyn Connection>)).start().unwrap();
        let mut c = TcpStream::connect(rt.local_addrs()[0]).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(b"thread").unwrap();
        let mut got = [0u8; 11];
        c.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"from-thread");
        c.write_all(b"pool!").unwrap();
        let mut got = [0u8; 11];
        c.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"offloaded 5");
        assert!(rt.offload().stats().completed >= 1);
        // Tasks on a loop.
        let (tx, rx) = mpsc::channel();
        assert!(rt.loops()[1].run(move |lcx| tx.send(lcx.index()).unwrap()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
    }
}

#[test]
fn connection_caps_close_extra_connections_at_once() {
    for b in backends() {
        let rt = builder(b, 2).configure(|c| c.max_connections = 2).listen("127.0.0.1:0", echo()).start().unwrap();
        let addr = rt.local_addrs()[0];
        let mut kept = Vec::new();
        for _ in 0..2 {
            let mut c = TcpStream::connect(addr).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            c.write_all(b"hi").unwrap();
            let mut g = [0u8; 2];
            c.read_exact(&mut g).unwrap();
            kept.push(c);
        }
        let mut extra = TcpStream::connect(addr).unwrap();
        extra.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = extra.write_all(b"hi");
        let mut g = [0u8; 2];
        assert!(!matches!(extra.read(&mut g), Ok(n) if n > 0), "{b:?}: the third connection is closed");
        assert!(wait_until(5, || rt.stats().total().rejected == 1), "{b:?}");
        drop(kept);
        assert!(wait_until(5, || rt.stats().active == 0));
        // Room again.
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"ok").unwrap();
        c.read_exact(&mut g).unwrap();
        assert_eq!(&g, b"ok");
    }
}

#[test]
fn input_limit_closes_a_connection_that_never_consumes() {
    struct Hoard(Arc<Mutex<Option<String>>>);
    impl Connection for Hoard {
        fn on_data(&mut self, _cx: &mut Ctx<'_>, _data: &[u8]) -> usize {
            0
        }
        fn on_close(&mut self, reason: CloseReason) {
            *self.0.lock().unwrap() = Some(format!("{reason:?}"));
        }
    }
    for b in backends() {
        let why = Arc::new(Mutex::new(None));
        let w2 = why.clone();
        let rt = builder(b, 1)
            .configure(|c| c.max_input = 10_000)
            .listen("127.0.0.1:0", move |_: &ConnInfo| Some(Box::new(Hoard(w2.clone())) as Box<dyn Connection>))
            .start()
            .unwrap();
        let mut c = TcpStream::connect(rt.local_addrs()[0]).unwrap();
        let _ = c.write_all(&[b'a'; 30_000]);
        assert!(wait_until(5, || why.lock().unwrap().is_some()), "{b:?}");
        assert_eq!(why.lock().unwrap().as_deref(), Some("InputLimit"));
    }
}

#[test]
fn write_high_water_pauses_reading_and_drain_resumes_it() {
    // Each request asks for 1 MiB, more than the high-water mark in one callback.
    struct Big(Arc<AtomicUsize>);
    impl Connection for Big {
        fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            for _ in 0..data.len() * 16 {
                let mut v = cx.buffer(65536);
                v.resize(65536, b'z');
                cx.send(v);
            }
            data.len()
        }
        fn on_drain(&mut self, _cx: &mut Ctx<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    for b in backends() {
        let drains = Arc::new(AtomicUsize::new(0));
        let d2 = drains.clone();
        let rt = builder(b, 1)
            .configure(|c| {
                c.write_high_water = 128 * 1024;
                c.write_low_water = 32 * 1024;
            })
            .listen("127.0.0.1:0", move |_: &ConnInfo| Some(Box::new(Big(d2.clone())) as Box<dyn Connection>))
            .start()
            .unwrap();
        let mut c = TcpStream::connect(rt.local_addrs()[0]).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        for _ in 0..8 {
            c.write_all(b"r").unwrap();
        }
        let mut total = 0;
        let mut buf = vec![0u8; 1 << 16];
        while total < 8 * 16 * 65536 {
            let n = c.read(&mut buf).unwrap();
            assert!(n > 0);
            total += n;
        }
        assert_eq!(total, 8 * 16 * 65536);
        assert!(wait_until(5, || drains.load(Ordering::Relaxed) >= 1), "{b:?}: reading was paused at the high-water mark and resumed");
    }
}

#[test]
fn graceful_stop_closes_idle_connections_and_aborts_stragglers() {
    struct Stubborn(Arc<Mutex<Vec<String>>>);
    impl Connection for Stubborn {
        fn on_data(&mut self, _cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            data.len()
        }
        fn on_stop(&mut self, _cx: &mut Ctx<'_>) {} // ignores the stop
        fn on_close(&mut self, reason: CloseReason) {
            self.0.lock().unwrap().push(format!("{reason:?}"));
        }
    }
    for b in backends() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l2 = log.clone();
        let rt = builder(b, 2)
            .listen("127.0.0.1:0", echo())
            .listen("127.0.0.1:0", move |_: &ConnInfo| Some(Box::new(Stubborn(l2.clone())) as Box<dyn Connection>))
            .start()
            .unwrap();
        let (a, s) = (rt.local_addrs()[0], rt.local_addrs()[1]);
        let mut polite = TcpStream::connect(a).unwrap();
        polite.write_all(b"x").unwrap();
        let mut g = [0u8; 1];
        polite.read_exact(&mut g).unwrap();
        let stubborn = TcpStream::connect(s).unwrap();
        assert!(wait_until(5, || rt.stats().active == 2));
        let start = Instant::now();
        rt.stop(Duration::from_millis(300));
        // The polite connection is closed at once.
        polite.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(!matches!(polite.read(&mut g), Ok(n) if n > 0));
        assert!(start.elapsed() < Duration::from_millis(250), "{b:?}");
        rt.join();
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(280), "{b:?}: the stubborn one gets the grace period ({took:?})");
        assert!(took < Duration::from_secs(3), "{b:?}: {took:?}");
        assert_eq!(*log.lock().unwrap(), vec!["Stopped".to_string()]);
        drop(stubborn);
        // Listeners are closed.
        assert!(TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_err());
    }
}

#[test]
fn eof_reaches_the_handler_and_half_close_works() {
    struct Count(usize);
    impl Connection for Count {
        fn on_data(&mut self, _cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            self.0 += data.len();
            data.len()
        }
        fn on_eof(&mut self, cx: &mut Ctx<'_>) {
            cx.send(format!("got {}", self.0).into_bytes());
            cx.close();
        }
    }
    for b in backends() {
        let rt = builder(b, 1).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(Count(0)) as Box<dyn Connection>)).start().unwrap();
        let mut c = TcpStream::connect(rt.local_addrs()[0]).unwrap();
        c.write_all(&[1u8; 100_000]).unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut got = String::new();
        c.read_to_string(&mut got).unwrap();
        assert_eq!(got, "got 100000", "{b:?}");
    }
}

#[test]
fn outbound_connections_can_be_adopted() {
    struct Client(mpsc::Sender<Vec<u8>>);
    impl Connection for Client {
        fn on_data(&mut self, _cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            self.0.send(data.to_vec()).unwrap();
            data.len()
        }
    }
    for b in backends() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let rt = builder(b, 1).start().unwrap();
        let (tx, rx) = mpsc::channel();
        let sock = simoom_rt::Socket::tcp_connect(addr).unwrap();
        let (htx, hrx) = mpsc::channel();
        rt.loops()[0].run(move |lcx| htx.send(lcx.adopt(sock, Box::new(Client(tx))).unwrap()).unwrap());
        let _h = hrx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (mut s, _) = server.accept().unwrap();
        s.write_all(b"hello client").unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), b"hello client", "{b:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn io_uring_failure_falls_back_to_epoll_in_the_runtime() {
    use simoom_rt::{Backend, Runtime};
    let rt = Runtime::builder()
        .threads(1)
        .configure(|c| {
            c.driver.backend = Backend::IoUring;
            c.driver.uring_simulate_failure = Some(1); // EPERM, as under seccomp
        })
        .listen("127.0.0.1:0", echo())
        .start()
        .unwrap();
    assert_eq!(rt.backend(), Backend::Epoll);
    assert!(rt.fallback_reason().unwrap().contains("io_uring"));
    let mut c = TcpStream::connect(rt.local_addrs()[0]).unwrap();
    c.write_all(b"still works").unwrap();
    let mut g = [0u8; 11];
    c.read_exact(&mut g).unwrap();
    assert_eq!(&g, b"still works");
}

#[test]
fn listen_on_an_existing_listener() {
    for b in backends() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let rt = builder(b, 2).listen_on(l, echo()).start().unwrap();
        assert_eq!(rt.local_addrs()[0], addr);
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"abc").unwrap();
        let mut g = [0u8; 3];
        c.read_exact(&mut g).unwrap();
        assert_eq!(&g, b"abc");
    }
}

fn ping(c: &mut TcpStream) {
    c.write_all(b"x").unwrap();
    let mut g = [0u8; 1];
    c.read_exact(&mut g).unwrap();
}

// Lazy loops: one loop until three connections are open at once; connections accepted while the
// others start are spread over every loop; a stop before any traffic is prompt.
#[test]
fn lazy_loops_start_on_concurrency_and_spread_the_burst() {
    for b in backends() {
        let rt = builder(b, 4).configure(|c| c.lazy_loops = true).listen("127.0.0.1:0", echo()).start().unwrap();
        assert_eq!(rt.backend(), b);
        let addr = rt.local_addrs()[0];
        assert!(wait_until(5, || rt.loops().len() == 1));
        // one connection at a time: still one loop
        for _ in 0..3 {
            let mut c = TcpStream::connect(addr).unwrap();
            ping(&mut c);
            drop(c);
            assert!(wait_until(5, || rt.stats().active == 0));
        }
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(rt.loops().len(), 1, "{b:?}: sequential connections started loops");
        // several at once: every loop starts; a burst opened meanwhile reaches every loop
        let mut a = TcpStream::connect(addr).unwrap();
        ping(&mut a);
        let mut burst: Vec<TcpStream> = (0..64).map(|_| TcpStream::connect(addr).unwrap()).collect();
        for c in burst.iter_mut() {
            ping(c);
        }
        assert!(wait_until(5, || rt.loops().len() == 4), "{b:?}: {} loops", rt.loops().len());
        let per_loop: Vec<u64> = rt.stats().loops.iter().map(|l| l.accepted).collect();
        assert!(per_loop.iter().all(|&n| n > 0), "{b:?}: connections per loop {per_loop:?}");
        drop(burst);
        rt.stop(Duration::from_secs(5));
        rt.join();

        let idle = builder(b, 4).configure(|c| c.lazy_loops = true).listen("127.0.0.1:0", echo()).start().unwrap();
        let t0 = Instant::now();
        idle.stop(Duration::from_secs(5));
        idle.join();
        assert!(t0.elapsed() < Duration::from_secs(2), "{b:?}: stop of an idle lazy runtime took {:?}", t0.elapsed());
    }
}

// Bug 11: a closed connection's timers leave the wheel at once instead of waiting to fire.
#[test]
fn closed_connections_cancel_their_timers() {
    struct Sleepy;
    impl Connection for Sleepy {
        fn on_open(&mut self, cx: &mut Ctx<'_>) {
            for t in 0..6 {
                cx.set_timer(Duration::from_secs(3600), t);
            }
        }
        fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            cx.send_static(b"k");
            data.len()
        }
    }
    for b in backends() {
        let rt = builder(b, 1).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(Sleepy) as Box<dyn Connection>)).start().unwrap();
        let addr = rt.local_addrs()[0];
        let mut cs: Vec<TcpStream> = (0..10).map(|_| TcpStream::connect(addr).unwrap()).collect();
        for c in cs.iter_mut() {
            ping(c);
        }
        assert!(wait_until(5, || rt.stats().total().timers == 60), "{b:?}: {}", rt.stats().total().timers);
        drop(cs);
        assert!(wait_until(5, || rt.stats().active == 0));
        assert!(wait_until(5, || rt.stats().total().timers == 0), "{b:?}: {} timers left", rt.stats().total().timers);
    }
}

// Bug 20: a graceful close lingers: the client that sends more after its request still reads
// the whole response (no reset from closing over unread input), on every back end.
#[test]
fn lingering_close_delivers_the_last_response() {
    const RESP: usize = 300_000;
    struct CloseAfterReply;
    impl Connection for CloseAfterReply {
        fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
            if data.windows(4).any(|w| w == b"END\n") {
                let mut out = cx.buffer(RESP);
                out.resize(RESP, b'r');
                cx.send(out);
                cx.close();
            }
            data.len()
        }
    }
    for b in backends() {
        let rt = builder(b, 1).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(CloseAfterReply) as Box<dyn Connection>)).start().unwrap();
        let addr = rt.local_addrs()[0];
        for _ in 0..5 {
            let mut c = TcpStream::connect(addr).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            c.write_all(b"request END\n").unwrap();
            // more bytes the server will never read, arriving after it decided to close
            std::thread::sleep(Duration::from_millis(20));
            let _ = c.write_all(&[b'x'; 64 * 1024]);
            let mut got = Vec::new();
            let r = c.read_to_end(&mut got);
            assert!(r.is_ok(), "{b:?}: {r:?} after {} bytes", got.len());
            assert_eq!(got.len(), RESP, "{b:?}");
        }
        // the lingering connections close once the clients close (or the linger time passes)
        assert!(wait_until(5, || rt.stats().active == 0), "{b:?}");
    }
}
