//! A closed-loop HTTP/1.1 load generator on the simoom runtime.
//!
//! Each connection keeps `--pipeline` requests outstanding and sends a new one as soon as a
//! response arrives. Generator loops run on their own threads, pinned to `--cpus` when given.
//! It warms up for a second, then counts responses for `--secs`.
//!
//! ```text
//! cargo run --release -p simoom-rt --example loadgen -- --addr 127.0.0.1:8080 --conns 256
//!     --threads 4 --secs 10 [--pipeline 1] [--cpus 8,9,10,11]
//! ```
//!
//! Closed-loop numbers measure throughput at a fixed concurrency; mean latency follows from
//! Little's law (`conns * pipeline / throughput`). They hide queueing at the tail (coordinated
//! omission), which an open-loop generator would show.

#![forbid(unsafe_code)]

use simoom_rt::{ConnHandle, Connection, Ctx, Message, Runtime, Socket};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const REQUEST: &[u8] = b"GET /plaintext HTTP/1.1\r\nHost: localhost\r\nUser-Agent: simoom-loadgen\r\nAccept: */*\r\n\r\n";

thread_local! {
    static DONE: Cell<u64> = const { Cell::new(0) };
    static ERRORS: Cell<u64> = const { Cell::new(0) };
}

/// Parses one response at the front of `data`: returns its length when it is complete.
fn response_len(data: &[u8]) -> Option<usize> {
    let head = data.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let mut clen = 0usize;
    for line in data[..head].split(|&b| b == b'\n') {
        if line.len() > 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
            let v = std::str::from_utf8(&line[15..]).ok()?.trim();
            clen = v.parse().ok()?;
        }
    }
    if data.len() >= head + clen {
        Some(head + clen)
    } else {
        None
    }
}

struct Client {
    pipeline: usize,
}

impl Connection for Client {
    fn on_message(&mut self, cx: &mut Ctx<'_>, _msg: Message) {
        for _ in 0..self.pipeline {
            cx.send_static(REQUEST);
        }
    }

    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let mut pos = 0;
        let mut n = 0u64;
        while let Some(len) = response_len(&data[pos..]) {
            pos += len;
            n += 1;
            cx.send_static(REQUEST);
        }
        DONE.with(|c| c.set(c.get() + n));
        pos
    }

    fn on_close(&mut self, _reason: simoom_rt::CloseReason) {
        ERRORS.with(|c| c.set(c.get() + 1));
    }
}

fn main() {
    let mut addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let (mut conns, mut threads, mut secs, mut pipeline) = (64usize, 4usize, 10u64, 1usize);
    let mut cpus: Option<Vec<usize>> = None;
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--addr" => addr = val.parse().expect("--addr"),
            "--conns" => conns = val.parse().expect("--conns"),
            "--threads" => threads = val.parse().expect("--threads"),
            "--secs" => secs = val.parse().expect("--secs"),
            "--pipeline" => pipeline = val.parse().expect("--pipeline"),
            "--cpus" => cpus = Some(val.split(',').map(|s| s.trim().parse().expect("--cpus")).collect()),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let rt = Runtime::builder()
        .configure(|c| {
            c.threads = threads;
            c.thread_name = "loadgen".into();
            if let Some(cpus) = cpus {
                c.pin_threads = true;
                c.cpus = Some(cpus);
            }
        })
        .start()
        .expect("start");
    let (htx, hrx) = mpsc::channel::<ConnHandle>();
    for k in 0..conns {
        let sock = Socket::tcp_connect(addr).expect("connect");
        let htx = htx.clone();
        rt.loops()[k % threads].run(move |lcx| {
            let h = lcx.adopt(sock, Box::new(Client { pipeline })).expect("adopt");
            htx.send(h).unwrap();
        });
    }
    drop(htx);
    let handles: Vec<ConnHandle> = hrx.iter().take(conns).collect();
    for h in &handles {
        h.send(Box::new(()));
    }
    let count = |rt: &simoom_rt::RuntimeHandle| -> (u64, u64) {
        let (tx, rx) = mpsc::channel();
        for l in rt.loops() {
            let tx = tx.clone();
            l.run(move |_| tx.send((DONE.with(|c| c.get()), ERRORS.with(|c| c.get()))).unwrap());
        }
        drop(tx);
        rx.iter().fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1))
    };
    std::thread::sleep(Duration::from_secs(1));
    let (r0, _) = count(&rt);
    let s0 = rt.stats().total().driver;
    let t0 = Instant::now();
    std::thread::sleep(Duration::from_secs(secs));
    let (r1, errors) = count(&rt);
    let el = t0.elapsed().as_secs_f64();
    let s1 = rt.stats().total().driver;
    let rps = (r1 - r0) as f64 / el;
    let lat_us = (conns * pipeline) as f64 / rps * 1e6;
    println!(
        "{conns} conns x {pipeline} pipelined, {threads} threads: {rps:.0} req/s, mean latency {lat_us:.1} us (Little), closed connections {errors}, client syscalls/req {:.2}",
        (s1.syscalls() - s0.syscalls()) as f64 / (r1 - r0).max(1) as f64
    );
    rt.stop(Duration::ZERO);
    rt.join();
}
