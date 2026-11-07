//! Driver tests, run on every back end this OS has (epoll and io_uring on Linux, IOCP on
//! Windows, kqueue on macOS and BSD).

use super::*;
use crate::net::{ListenOptions, Socket, UdpOptions};
use crate::udp::Transmit;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn backends() -> Vec<Backend> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        v.push(Backend::Epoll);
        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        match uring::available() {
            Ok(()) => v.push(Backend::IoUring),
            Err(e) => eprintln!("io_uring tests skipped: {e}"),
        }
    }
    if cfg!(windows) {
        v.push(Backend::Iocp);
    }
    if cfg!(any(target_os = "macos", target_os = "freebsd")) {
        v.push(Backend::Kqueue);
    }
    v
}

fn driver(b: Backend) -> Driver {
    let d = Driver::new(&DriverConfig { backend: b, ..Default::default() }).unwrap();
    assert_eq!(d.backend(), b, "{:?}", d.fallback_reason());
    d
}

fn topup(d: &mut Driver, size: usize) {
    for _ in 0..d.buffers_wanted() {
        d.provide(Vec::with_capacity(size));
    }
}

/// Runs turns until `done` says stop or 10 s pass; `f` sees every event.
fn run(d: &mut Driver, mut f: impl FnMut(&mut Driver, Event) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut evs = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "timed out");
        topup(d, 2048);
        d.turn(Some(Duration::from_millis(20)), &mut evs).unwrap();
        for e in evs.drain(..) {
            if f(d, e) {
                return;
            }
        }
    }
}

fn listener(d: &mut Driver) -> std::net::SocketAddr {
    let l = Socket::tcp_listen("127.0.0.1:0".parse().unwrap(), &ListenOptions::default()).unwrap();
    let addr = l.local_addr().unwrap();
    d.listen(l, 1).unwrap();
    addr
}

#[test]
fn tcp_echo_on_every_backend() {
    for b in backends() {
        let mut d = driver(b);
        let addr = listener(&mut d);
        const N: usize = 1 << 20;
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            let mut r = c.try_clone().unwrap();
            let reader = std::thread::spawn(move || {
                let mut got = vec![0u8; N];
                r.read_exact(&mut got).unwrap();
                got
            });
            let data: Vec<u8> = (0..N).map(|i| (i * 7 % 251) as u8).collect();
            c.write_all(&data).unwrap();
            let got = reader.join().unwrap();
            assert!(got == data, "echo mismatch on {b:?}");
            c.shutdown(std::net::Shutdown::Write).unwrap();
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
        });
        let mut conn = None;
        let (mut echoed, mut returned, mut sent) = (0usize, 0usize, 0usize);
        run(&mut d, |d, ev| {
            match ev {
                Event::Accepted { socket, .. } => {
                    let id = d.stream(socket, 2).unwrap();
                    d.recv(id, true);
                    conn = Some(id);
                }
                Event::Data { key: 2, buf } => {
                    echoed += buf.len();
                    sent += 1;
                    d.send(conn.unwrap(), OutBuf::Owned(buf));
                }
                Event::Sent { key: 2, buf } => {
                    assert!(matches!(buf, OutBuf::Owned(_)));
                    returned += 1;
                }
                Event::Eof { key: 2 } => d.close(conn.unwrap()),
                Event::Closed { key: 2 } => return true,
                Event::Error { error, .. } => panic!("{b:?}: {error}"),
                _ => {}
            }
            false
        });
        client.join().unwrap();
        assert_eq!(echoed, N, "{b:?}");
        assert_eq!(returned, sent, "every send buffer comes back on {b:?}");
        let s = d.stats();
        eprintln!("{b:?} echo stats: {s:?}");
        assert!(s.waits > 0);
    }
}

#[test]
fn many_queued_sends_are_coalesced() {
    for b in backends() {
        let mut d = driver(b);
        let addr = listener(&mut d);
        let mut c = TcpStream::connect(addr).unwrap();
        let mut conn = None;
        run(&mut d, |d, ev| {
            if let Event::Accepted { socket, .. } = ev {
                conn = Some(d.stream(socket, 2).unwrap());
                return true;
            }
            false
        });
        let id = conn.unwrap();
        let before = d.stats();
        for _ in 0..100 {
            d.send(id, OutBuf::Static(b"0123456789"));
        }
        let mut returned = 0;
        run(&mut d, |_, ev| {
            if let Event::Sent { .. } = ev {
                returned += 1;
            }
            returned == 100
        });
        let after = d.stats();
        let calls = after.send_calls - before.send_calls + (after.sqes - before.sqes);
        assert!(calls <= 4, "{b:?}: 100 queued buffers took {calls} send calls/submissions");
        let mut got = vec![0u8; 1000];
        c.read_exact(&mut got).unwrap();
        assert!(got.chunks(10).all(|ch| ch == b"0123456789"));
    }
}

#[test]
fn udp_echo_on_every_backend() {
    for b in backends() {
        let mut d = driver(b);
        let s = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions { pktinfo: true, ..Default::default() }).unwrap();
        let addr = s.local_addr().unwrap();
        let id = d.udp(s, 9).unwrap();
        d.recv(id, true);
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        for i in 0..20u8 {
            client.send_to(&[i; 100], addr).unwrap();
        }
        let mut n = 0;
        run(&mut d, |d, ev| {
            match ev {
                Event::Datagram { key: 9, buf, meta } => {
                    assert_eq!(meta.peer, client.local_addr().unwrap());
                    assert_eq!(buf.len(), 100);
                    let t = Transmit { peer: meta.peer, data: &buf, segment_size: 0, ecn: 0, src_ip: None };
                    assert_eq!(d.send_to(id, &[t]).unwrap(), 1);
                    d.provide(buf);
                    n += 1;
                }
                Event::Error { error, .. } => panic!("{b:?}: {error}"),
                _ => {}
            }
            n == 20
        });
        let mut seen = [false; 20];
        let mut buf = [0u8; 200];
        for _ in 0..20 {
            let (len, _) = client.recv_from(&mut buf).unwrap();
            assert_eq!(len, 100);
            seen[buf[0] as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "{b:?}");
        d.close(id);
        run(&mut d, |_, ev| matches!(ev, Event::Closed { key: 9 }));
    }
}

#[test]
fn udp_gro_batches_land_in_large_buffers() {
    const SEG: usize = 1200;
    const N: usize = 40;
    for b in backends() {
        let mut d = driver(b);
        let s = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions { gro: true, recv_buffer: Some(4 << 20), ..Default::default() }).unwrap();
        let addr = s.local_addr().unwrap();
        let id = d.udp_large(s, 9, 65536).unwrap();
        d.recv(id, true);
        // Datagram i is SEG bytes of value i. One segmented send (GSO / USO) where the kernel
        // has it, so GRO can hand the batch over as one buffer; else one send per datagram.
        let data: Vec<u8> = (0..N * SEG).map(|i| (i / SEG) as u8).collect();
        let sender = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions::default()).unwrap();
        let gso = Transmit { peer: addr, data: &data, segment_size: SEG, ecn: 0, src_ip: None };
        let segmented = matches!(sender.send_msgs(&[gso]), Ok(1));
        if !segmented {
            for c in data.chunks(SEG) {
                sender.send_msgs(&[Transmit { peer: addr, data: c, segment_size: 0, ecn: 0, src_ip: None }]).unwrap();
            }
        }
        // No stock buffers: a GRO socket receives into the driver's own large buffers.
        let wanted = d.buffers_wanted();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut evs = Vec::new();
        let (mut seen, mut largest) = (vec![false; N], 0);
        while !seen.iter().all(|&s| s) {
            assert!(Instant::now() < deadline, "{b:?}: datagrams missing: {seen:?}");
            d.turn(Some(Duration::from_millis(20)), &mut evs).unwrap();
            for e in evs.drain(..) {
                match e {
                    Event::Datagram { key: 9, buf, meta } => {
                        assert!(buf.capacity() >= 65536, "{b:?}: received into a {}-byte buffer", buf.capacity());
                        assert!(!meta.truncated);
                        assert_eq!(meta.len, buf.len());
                        largest = largest.max(buf.len());
                        for seg in buf.chunks(meta.segment_size.max(1)) {
                            assert_eq!(seg.len(), SEG, "{b:?}: segment size {}", meta.segment_size);
                            assert!(seg.iter().all(|&x| x == seg[0]));
                            seen[seg[0] as usize] = true;
                        }
                        d.provide(buf); // back to the large stock, not the stream stock
                    }
                    Event::Error { error, .. } => panic!("{b:?}: {error}"),
                    _ => {}
                }
            }
        }
        assert_eq!(d.buffers_wanted(), wanted, "{b:?}: large buffers went into the stream stock");
        #[cfg(target_os = "linux")]
        if segmented {
            assert!(largest > SEG, "{b:?}: GRO did not coalesce the segmented send (largest buffer {largest} bytes)");
        }
        let _ = largest;
        d.close(id);
        run(&mut d, |_, ev| matches!(ev, Event::Closed { key: 9 }));
    }
}

#[test]
fn waker_interrupts_a_blocked_turn() {
    for b in backends() {
        let mut d = driver(b);
        let w = d.waker();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            w.wake();
            w.wake(); // collapses with the first
        });
        let start = Instant::now();
        let mut evs = Vec::new();
        while !evs.iter().any(|e| matches!(e, Event::Wake)) {
            d.turn(None, &mut evs).unwrap();
            assert!(start.elapsed() < Duration::from_secs(5));
        }
        assert!(start.elapsed() >= Duration::from_millis(40));
        t.join().unwrap();
        // A wake before the turn is not lost either.
        d.waker().wake();
        evs.clear();
        d.turn(Some(Duration::from_secs(5)), &mut evs).unwrap();
        assert!(evs.iter().any(|e| matches!(e, Event::Wake)), "{b:?}");
        // And a timeout with nothing to do returns after about the timeout.
        evs.clear();
        let start = Instant::now();
        d.turn(Some(Duration::from_millis(30)), &mut evs).unwrap();
        assert!(evs.is_empty(), "{b:?}: {evs:?}");
        assert!(start.elapsed() >= Duration::from_millis(25), "{b:?}");
    }
}

#[test]
fn pausing_receive_holds_data_back() {
    for b in backends() {
        let mut d = driver(b);
        let addr = listener(&mut d);
        let mut c = TcpStream::connect(addr).unwrap();
        let mut conn = None;
        run(&mut d, |d, ev| {
            if let Event::Accepted { socket, .. } = ev {
                let id = d.stream(socket, 2).unwrap();
                d.recv(id, true);
                conn = Some(id);
                return true;
            }
            false
        });
        let id = conn.unwrap();
        c.write_all(b"first").unwrap();
        run(&mut d, |_, ev| matches!(ev, Event::Data { .. }));
        d.recv(id, false);
        // Let the pause land (io_uring cancels its multishot receive).
        let mut evs = Vec::new();
        for _ in 0..3 {
            d.turn(Some(Duration::from_millis(10)), &mut evs).unwrap();
        }
        evs.clear();
        c.write_all(b"second").unwrap();
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(200) {
            topup(&mut d, 2048);
            d.turn(Some(Duration::from_millis(20)), &mut evs).unwrap();
        }
        assert!(!evs.iter().any(|e| matches!(e, Event::Data { .. })), "{b:?} delivered data while paused");
        d.recv(id, true);
        let mut got = Vec::new();
        run(&mut d, |_, ev| {
            if let Event::Data { buf, .. } = ev {
                got.extend_from_slice(&buf);
            }
            got.len() >= 6
        });
        assert_eq!(got, b"second", "{b:?}");
    }
}

#[test]
fn close_discards_queued_sends_and_peer_sees_eof() {
    for b in backends() {
        let mut d = driver(b);
        let addr = listener(&mut d);
        let mut c = TcpStream::connect(addr).unwrap();
        let mut conn = None;
        run(&mut d, |d, ev| {
            if let Event::Accepted { socket, peer, .. } = ev {
                if let Some(p) = peer {
                    assert!(p.ip().is_loopback());
                }
                assert!(socket.peer_addr().unwrap().ip().is_loopback());
                let id = d.stream(socket, 2).unwrap();
                d.recv(id, true);
                conn = Some(id);
                return true;
            }
            false
        });
        let id = conn.unwrap();
        d.send(id, OutBuf::Owned(vec![1; 10]));
        d.close(id);
        d.send(id, OutBuf::Static(b"stale")); // after close: discarded (or handed straight back)
        let mut returned = 0;
        run(&mut d, |_, ev| match ev {
            Event::Sent { buf: OutBuf::Owned(_), .. } => {
                returned += 1;
                false
            }
            Event::Closed { key: 2 } => true,
            _ => false,
        });
        assert_eq!(returned, 1, "{b:?}");
        let mut buf = [0u8; 16];
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(!matches!(c.read(&mut buf), Ok(n) if n > 0), "{b:?}");
        assert!(d.socket(id).is_none());
    }
}

#[test]
fn listener_accepts_many_connections() {
    for b in backends() {
        let mut d = driver(b);
        let addr = listener(&mut d);
        let clients: Vec<TcpStream> = (0..100).map(|_| TcpStream::connect(addr).unwrap()).collect();
        let mut n = 0;
        run(&mut d, |d, ev| {
            if let Event::Accepted { socket, .. } = ev {
                let id = d.stream(socket, 100 + n).unwrap();
                d.send(id, OutBuf::Static(b"hi"));
                n += 1;
            }
            n == 100
        });
        let mut evs = Vec::new();
        d.turn(Some(Duration::ZERO), &mut evs).unwrap();
        for mut c in clients {
            let mut b2 = [0u8; 2];
            c.read_exact(&mut b2).unwrap();
            assert_eq!(&b2, b"hi");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn io_uring_failure_falls_back_to_epoll() {
    for errno in [crate::os::linux::ENOSYS, crate::os::linux::EPERM, crate::os::linux::EINVAL] {
        let d = Driver::new(&DriverConfig { backend: Backend::IoUring, uring_simulate_failure: Some(errno), ..Default::default() }).unwrap();
        assert_eq!(d.backend(), Backend::Epoll);
        let why = d.fallback_reason().unwrap();
        assert!(why.contains("io_uring unavailable"), "{why}");
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[test]
fn io_uring_without_fixed_files_and_with_a_tiny_buffer_ring() {
    if uring::available().is_err() {
        return;
    }
    // A 8-entry ring runs dry under a 256 KiB echo: receives must resume after ENOBUFS.
    let cfg = DriverConfig { backend: Backend::IoUring, uring_fixed_files: false, uring_buffers: 8, ..Default::default() };
    let mut d = Driver::new(&cfg).unwrap();
    assert_eq!(d.backend(), Backend::IoUring);
    d.set_buffer_target(8);
    let addr = listener(&mut d);
    const N: usize = 256 * 1024;
    let client = std::thread::spawn(move || {
        let mut c = TcpStream::connect(addr).unwrap();
        let data = vec![5u8; N];
        c.write_all(&data).unwrap();
        let mut got = vec![0u8; N];
        c.read_exact(&mut got).unwrap();
        assert!(got == data);
    });
    let mut conn = None;
    let mut total = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut evs = Vec::new();
    while total < N {
        assert!(Instant::now() < deadline);
        // Starve on purpose: give buffers back only once per turn, a few at a time.
        for _ in 0..d.buffers_wanted().min(2) {
            d.provide(Vec::with_capacity(4096));
        }
        d.turn(Some(Duration::from_millis(5)), &mut evs).unwrap();
        for e in evs.drain(..) {
            match e {
                Event::Accepted { socket, .. } => {
                    let id = d.stream(socket, 2).unwrap();
                    d.recv(id, true);
                    conn = Some(id);
                }
                Event::Data { buf, .. } => {
                    total += buf.len();
                    d.send(conn.unwrap(), OutBuf::Owned(buf));
                }
                _ => {}
            }
        }
    }
    for _ in 0..50 {
        d.turn(Some(Duration::from_millis(5)), &mut evs).unwrap();
        evs.clear();
    }
    client.join().unwrap();
}

#[cfg(windows)]
#[test]
fn iocp_eager_receive_echo_pause_and_close() {
    let mut d = Driver::new(&DriverConfig { backend: Backend::Iocp, iocp_eager_recv: true, ..Default::default() }).unwrap();
    let addr = listener(&mut d);
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut conn = None;
    run(&mut d, |d, ev| {
        if let Event::Accepted { socket, .. } = ev {
            let id = d.stream(socket, 2).unwrap();
            d.recv(id, true);
            conn = Some(id);
            return true;
        }
        false
    });
    let id = conn.unwrap();
    for round in 0..20u8 {
        let msg = vec![round; 3000]; // more than one 2 KiB buffer
        c.write_all(&msg).unwrap();
        let mut got = Vec::new();
        run(&mut d, |d, ev| {
            if let Event::Data { buf, .. } = ev {
                got.extend_from_slice(&buf);
                d.send(id, OutBuf::Owned(buf));
            }
            got.len() >= 3000
        });
        let mut evs = Vec::new();
        d.turn(Some(Duration::ZERO), &mut evs).unwrap(); // flush the echo
        let mut back = vec![0u8; 3000];
        c.read_exact(&mut back).unwrap();
        assert_eq!(back, msg);
    }
    // The peer closes: EOF, then a graceful close of ours.
    c.shutdown(std::net::Shutdown::Write).unwrap();
    run(&mut d, |d, ev| {
        if let Event::Eof { .. } = ev {
            d.send(id, OutBuf::Static(b"bye"));
            d.close(id);
        }
        matches!(ev, Event::Closed { .. })
    });
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).unwrap_or_default();
    assert!(rest.is_empty() || rest == b"bye");
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[test]
fn io_uring_drops_only_the_setup_flags_the_kernel_refuses() {
    if uring::available().is_err() {
        return;
    }
    for (refuse, missing, kept) in [
        (1u32 << 13, "DEFER_TASKRUN", "SUBMIT_ALL"),
        (1 << 7, "SUBMIT_ALL", "DEFER_TASKRUN"),
        (1 << 12, "SINGLE_ISSUER", "SUBMIT_ALL"),
    ] {
        uring::REFUSE_SETUP.with(|r| r.set(refuse));
        let mut d = driver(Backend::IoUring);
        let why = d.fallback_reason().unwrap().to_string();
        assert!(why.contains(missing) && !why.contains(kept), "refusing {missing}: {why}");
        // The degraded ring still serves.
        let addr = listener(&mut d);
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"ping").unwrap();
        let mut got = Vec::new();
        run(&mut d, |d, ev| {
            match ev {
                Event::Accepted { socket, .. } => {
                    let id = d.stream(socket, 7).unwrap();
                    d.recv(id, true);
                }
                Event::Data { key: 7, buf } => {
                    got.extend_from_slice(&buf);
                    d.provide(buf);
                }
                _ => {}
            }
            got == b"ping"
        });
    }
    uring::REFUSE_SETUP.with(|r| r.set(0));
    let d = driver(Backend::IoUring);
    let why = d.fallback_reason().unwrap_or_default();
    assert!(["SUBMIT_ALL", "DEFER_TASKRUN", "SINGLE_ISSUER", "registered files"].iter().all(|f| !why.contains(f)), "{why}");
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[test]
fn io_uring_falls_back_to_kernel_allocated_rings_then_to_provide_buffers() {
    if uring::available().is_err() {
        return;
    }
    for legacy in [false, true] {
    uring::FORCE_PBUF_MMAP.with(|f| f.set(true));
    uring::FORCE_PBUF_LEGACY.with(|f| f.set(legacy));
    let mut d = driver(Backend::IoUring);
    uring::FORCE_PBUF_MMAP.with(|f| f.set(false));
    uring::FORCE_PBUF_LEGACY.with(|f| f.set(false));
    let why = d.fallback_reason().unwrap().to_string();
    // A kernel that refuses every buffer ring (Ubuntu's 6.8) ends up with PROVIDE_BUFFERS in both.
    assert!(why.contains("PROVIDE_BUFFERS") || (!legacy && why.contains("kernel-allocated")), "{why}");
    // Receives go through the kernel's ring: a 256 KiB echo needs many refills.
    let addr = listener(&mut d);
    const N: usize = 256 * 1024;
    let client = std::thread::spawn(move || {
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(&vec![3u8; N]).unwrap();
    });
    let mut got = 0;
    run(&mut d, |d, ev| {
        match ev {
            Event::Accepted { socket, .. } => {
                let id = d.stream(socket, 7).unwrap();
                d.recv(id, true);
            }
            Event::Data { key: 7, buf } => {
                assert!(buf.iter().all(|&b| b == 3));
                got += buf.len();
                d.provide(buf);
            }
            _ => {}
        }
        got == N
    });
    client.join().unwrap();
    }
}
