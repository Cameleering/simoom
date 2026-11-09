//! User-space memory held per idle connection, measured with a counting allocator on the loop
//! thread. Target: at most 1 KiB (the protocol state itself excluded; this handler has none).

mod common;

use common::{backends, builder, wait_until};
use simoom_rt::{ConnInfo, Connection, Ctx};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

#[global_allocator]
static A: simoom_sys::alloc::Counting = simoom_sys::alloc::Counting;

struct Pong;
impl Connection for Pong {
    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        cx.send_static(b"pong");
        data.len()
    }
}

fn loop_bytes(rt: &simoom_rt::RuntimeHandle) -> i64 {
    let (tx, rx) = mpsc::channel();
    rt.loops()[0].run(move |_| tx.send(simoom_sys::alloc::thread_bytes()).unwrap());
    rx.recv_timeout(Duration::from_secs(5)).unwrap()
}

#[test]
fn idle_connections_hold_less_than_a_kilobyte() {
    const N: usize = 2000;
    for b in backends() {
        let rt = builder(b, 1).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(Pong) as Box<dyn Connection>)).start().unwrap();
        let addr = rt.local_addrs()[0];
        // Warm up: one connection through a request, so one-time allocations are done.
        {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"ping").unwrap();
            let mut g = [0u8; 4];
            c.read_exact(&mut g).unwrap();
        }
        assert!(wait_until(5, || rt.stats().active == 0));
        let before = loop_bytes(&rt);
        let mut clients = Vec::with_capacity(N);
        for _ in 0..N {
            clients.push(TcpStream::connect(addr).unwrap());
        }
        assert!(wait_until(20, || rt.stats().active == N), "{b:?}: {}", rt.stats().active);
        let fresh = loop_bytes(&rt);
        // One request on every connection, one at a time, then idle again.
        for c in clients.iter_mut() {
            c.write_all(b"ping").unwrap();
            let mut g = [0u8; 4];
            c.read_exact(&mut g).unwrap();
        }
        std::thread::sleep(Duration::from_millis(50));
        let used = loop_bytes(&rt);
        drop(clients);
        assert!(wait_until(20, || rt.stats().active == 0));
        let after = loop_bytes(&rt);
        let per_fresh = (fresh - before) as f64 / N as f64;
        let per_used = (used - before) as f64 / N as f64;
        let freed = (used - after) as f64 / N as f64;
        eprintln!(
            "{b:?}: per idle connection: {per_fresh:.0} B never used, {per_used:.0} B after a request; {freed:.0} B freed per closed connection"
        );
        assert!(per_fresh <= 1024.0, "{b:?}: {per_fresh} B per fresh idle connection");
        assert!(per_used <= 1024.0, "{b:?}: {per_used} B per used idle connection");
    }
}

/// Consumes only whole lines, like an HTTP head parser waiting for the rest of a head.
struct Lines;
impl Connection for Lines {
    fn on_data(&mut self, _cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1)
    }
}

// Bug 17: an idle half-request (a slowloris client) holds its few bytes, not a receive buffer.
#[test]
fn partial_input_does_not_hold_a_receive_buffer() {
    const N: usize = 1000;
    for b in backends() {
        let rt = builder(b, 1).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(Lines) as Box<dyn Connection>)).start().unwrap();
        let addr = rt.local_addrs()[0];
        {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"warm up\n").unwrap();
        }
        assert!(wait_until(5, || rt.stats().total().accepted >= 1 && rt.stats().active == 0));
        let before = loop_bytes(&rt);
        let mut clients = Vec::with_capacity(N);
        for _ in 0..N {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nX-Slow: ").unwrap();
            clients.push(c);
        }
        assert!(wait_until(20, || rt.stats().active == N), "{b:?}: {}", rt.stats().active);
        std::thread::sleep(Duration::from_millis(100));
        let held = loop_bytes(&rt);
        let per = (held - before) as f64 / N as f64;
        eprintln!("{b:?}: {per:.0} B per connection holding a 37-byte partial head");
        assert!(per <= 1024.0, "{b:?}: {per} B per half-request (a receive buffer is 2048)");
        drop(clients);
    }
}
