//! An idle runtime uses no CPU: after serving traffic (which opens the busy-poll window) the loops
//! go back to sleep. Its own test binary with a single test, so the process CPU clock sees only
//! this runtime.

mod common;

use common::{backends, builder};
use simoom_rt::{ConnInfo, Connection, Ctx};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

struct Echo;
impl Connection for Echo {
    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let mut out = cx.buffer(data.len());
        out.extend_from_slice(data);
        cx.send(out);
        data.len()
    }
}

#[test]
fn idle_loops_do_not_spin() {
    for b in backends() {
        let rt = builder(b, 2).listen("127.0.0.1:0", |_: &ConnInfo| Some(Box::new(Echo) as Box<dyn Connection>)).start().unwrap();
        let addr = rt.local_addrs()[0];
        // Busy for a moment: many round trips on a few connections, on both loops.
        let mut conns: Vec<TcpStream> = (0..4).map(|_| TcpStream::connect(addr).unwrap()).collect();
        for _ in 0..500 {
            for c in conns.iter_mut() {
                c.write_all(b"ping").unwrap();
                let mut got = [0u8; 4];
                c.read_exact(&mut got).unwrap();
            }
        }
        // The connections stay open (idle keep-alive) while we measure.
        std::thread::sleep(Duration::from_millis(50));
        let s0 = rt.stats().total().driver;
        let cpu0 = simoom_sys::time::process_cpu_ns();
        std::thread::sleep(Duration::from_secs(1));
        let cpu = simoom_sys::time::process_cpu_ns() - cpu0;
        let s1 = rt.stats().total().driver;
        eprintln!("{b:?}: idle second used {} us of CPU; {} waits, {} spin polls", cpu / 1000, s1.waits - s0.waits, s1.spin_polls - s0.spin_polls);
        // 1 ms timer ticks may wake the loops; spinning would cost a whole core (1000 ms).
        assert!(cpu < 50_000_000, "{b:?}: an idle second used {} ms of CPU", cpu / 1_000_000);
        drop(conns);
        rt.stop(Duration::from_millis(100));
        rt.join();
    }
}
