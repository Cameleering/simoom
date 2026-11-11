//! K8: heap held per idle keep-alive connection (after one request), counted with the counting
//! allocator. The campaign measured 913 B of PSS per connection at 10k connections (nginx 538 B);
//! rarely used state (lingering close, partial heads, TLS, trailers, deferred replies) lives in
//! side allocations made only when needed.

use simoom::{Limits, Outcome, Reply, Request, Server, StaticReply};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static A: simoom_sys::alloc::Counting = simoom_sys::alloc::Counting;

/// Heap bytes per idle connection, and allocations live per connection.
fn per_connection(n: usize) -> (i64, i64) {
    let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
    let h = Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(Limits { keep_alive_timeout: Duration::from_secs(60), ..Limits::default() })
        .service(move |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.fixed(&hello) })
        .start()
        .unwrap();
    let addr = h.local_addr();
    let get = |c: &mut TcpStream| {
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut b = [0u8; 256];
        let mut got = 0;
        while !b[..got].windows(13).any(|w| w == b"Hello, World!") {
            got += c.read(&mut b[got..]).unwrap();
        }
    };
    // Warm up: the loop's pools, timer wheel and slabs reach their working size.
    let mut warm: Vec<TcpStream> = (0..n).map(|_| TcpStream::connect(addr).unwrap()).collect();
    for c in warm.iter_mut() {
        get(c);
    }
    drop(warm);
    std::thread::sleep(Duration::from_millis(300));
    let (b0, c0) = (simoom_sys::alloc::total_bytes(), simoom_sys::alloc::live_allocations());
    let mut conns: Vec<TcpStream> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut c = TcpStream::connect(addr).unwrap();
        get(&mut c);
        conns.push(c);
    }
    std::thread::sleep(Duration::from_millis(300));
    let (b1, c1) = (simoom_sys::alloc::total_bytes(), simoom_sys::alloc::live_allocations());
    let client = (n * std::mem::size_of::<TcpStream>()) as i64;
    drop(conns);
    ((b1 - b0 - client) / n as i64, (c1 - c0 - 1) / n as i64)
}

#[test]
fn an_idle_connection_holds_little_heap() {
    let (bytes, allocs) = per_connection(500);
    eprintln!("idle connection: {bytes} B of heap in {allocs} allocations");
    // The facade's connection and its HTTP/1.1 layer; the runtime slot, driver entry and
    // keep-alive timer live in the loop's slabs. Nothing else stays allocated after the request
    // (before K8: 568 B in 4 allocations on Linux, 616 B in 5 on Windows). IOCP keeps its
    // receive and send operation blocks per socket.
    let (max_bytes, max_allocs) = if cfg!(windows) { (480, 4) } else { (320, 2) };
    assert!(bytes <= max_bytes, "{bytes} B of heap per idle connection");
    assert!(allocs <= max_allocs, "{allocs} allocations per idle connection");
}
