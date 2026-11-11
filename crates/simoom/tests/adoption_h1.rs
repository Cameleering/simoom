//! The Cameleer adoption items on HTTP/1.1 (docs/BUGS.md U1, U2, U4, U5, U10): connection info,
//! deferred-reply timeout and cancellation, the completion hook, response trailers, and
//! blocking routes on the offload pool.

#![cfg(feature = "http1")]

mod common;

use common::*;
use simoom::{Completion, Limits, Outcome, Reply, Request, Response, Server, Version};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Reads until `needle` appears (or the peer closes); returns everything read.
fn read_until(s: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let end = Instant::now() + Duration::from_secs(10);
    while !buf.windows(needle.len()).any(|w| w == needle) && Instant::now() < end {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    buf
}

// ------------------------------------------------------------------ U1

#[test]
fn requests_carry_local_address_listener_and_peer() {
    let h = Server::builder()
        .listen("127.0.0.1:0")
        .listen("127.0.0.1:0")
        .threads(1)
        .service(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            let owned = req.to_owned_request();
            assert_eq!(owned.local_addr(), req.local_addr());
            assert_eq!(owned.listener(), req.listener());
            reply.body(format!("{} {} {} {}", req.listener(), req.local_addr().unwrap(), req.peer_addr().unwrap(), req.tls().is_none()))
        })
        .start()
        .unwrap();
    for (i, addr) in h.local_addrs().to_vec().into_iter().enumerate() {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let me = s.local_addr().unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.ends_with(&format!("{i} {addr} {me} true")), "{out}");
    }
}

// ------------------------------------------------------------------ U2

#[test]
fn a_deferred_reply_times_out_with_504_and_is_cancelled() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let c2 = cancelled.clone();
    let limits = Limits { defer_timeout: Some(Duration::from_millis(150)), ..Limits::default() };
    let h = serve_with(limits, move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/fast" {
            return reply.body_static(b"fast");
        }
        let r = reply.defer();
        let c = c2.clone();
        r.on_cancel(move || c.store(true, Ordering::SeqCst));
        tx.lock().unwrap().send(r).unwrap(); // held, never answered in time
        Outcome::Deferred
    });
    let mut c = Client::new(&h);
    let t0 = Instant::now();
    let r = c.get("/slow");
    assert_eq!(r.status, 504);
    assert!(t0.elapsed() >= Duration::from_millis(140), "{:?}", t0.elapsed());
    let responder = rx.recv().unwrap();
    assert!(responder.is_cancelled() && cancelled.load(Ordering::SeqCst));
    // the late answer is dropped, and the connection serves the next request
    responder.send(Response::text("too late"));
    assert_eq!(c.get("/fast").text(), "fast");
    assert_eq!(h.stats().timeouts, 1);
}

#[test]
fn a_client_that_leaves_cancels_its_deferred_reply() {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let h = serve(move |_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        tx.lock().unwrap().send(reply.defer()).unwrap();
        Outcome::Deferred
    });
    let mut s = connect(&h);
    s.write_all(b"GET /work HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let responder = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (ftx, frx) = mpsc::channel();
    responder.on_cancel(move || ftx.send(()).unwrap());
    assert!(!responder.is_cancelled());
    drop(s);
    frx.recv_timeout(Duration::from_secs(5)).expect("the hook runs when the client leaves");
    assert!(responder.is_cancelled());
    // a hook set after the fact runs at once
    let (ftx, frx) = mpsc::channel();
    responder.on_cancel(move || ftx.send(()).unwrap());
    frx.try_recv().unwrap();
    let _ = responder.send(Response::text("nobody"));
}

#[test]
fn pipelined_requests_behind_a_deferred_reply_still_run_in_order() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let p = req.path_str().to_string();
        let r = reply.defer();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            r.send(Response::text(p));
        });
        Outcome::Deferred
    });
    let mut c = Client::new(&h);
    let mut many = Vec::new();
    for i in 0..20 {
        many.extend_from_slice(format!("GET /{i} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes());
    }
    c.send(&many);
    for i in 0..20 {
        assert_eq!(c.read().text(), format!("/{i}"));
    }
}

// ------------------------------------------------------------------ U4

fn hooked(svc: impl simoom::Service) -> (simoom::ServerHandle, Arc<Mutex<Vec<Completion>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    let h = Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .on_complete(move |c: &Completion| l2.lock().unwrap().push(c.clone()))
        .service(svc)
        .start()
        .unwrap();
    (h, log)
}

#[test]
fn the_completion_hook_sees_every_request() {
    let (htx, hrx) = mpsc::channel();
    let htx = Mutex::new(htx);
    let (h, log) = hooked(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        match req.path() {
            b"/defer" => {
                let r = reply.defer();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(30));
                    r.send(Response::new(201).body("made"));
                });
                Outcome::Deferred
            }
            b"/stream" => {
                let mut sink = reply.stream();
                std::thread::spawn(move || {
                    sink.write(b"abc").unwrap();
                    sink.write(b"de").unwrap();
                });
                Outcome::Done
            }
            b"/hang" => {
                htx.lock().unwrap().send(reply.defer()).unwrap();
                Outcome::Deferred
            }
            _ => reply.status(404).body(format!("{} bytes", req.body().len())),
        }
    });
    let mut c = Client::new(&h);
    c.send(b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello");
    assert_eq!(c.read().status, 404);
    assert_eq!(c.get("/defer").status, 201);
    assert_eq!(c.get("/stream").body, b"abcde");
    // a refused head
    let mut bad = connect(&h);
    bad.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nBad Header\r\n\r\n").unwrap();
    let _ = read_until(&mut bad, b"\r\n\r\n");
    // a client that leaves mid-reply
    let mut gone = connect(&h);
    gone.write_all(b"GET /hang HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let held = hrx.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(gone);
    assert!(wait_for(5, || held.is_cancelled()));
    drop(held); // the holder gives up: a 500 to nobody, reported as aborted
    assert!(wait_for(5, || log.lock().unwrap().len() >= 5), "{:?}", log.lock().unwrap());
    let l = log.lock().unwrap();
    let find = |s: u16| l.iter().find(|c| c.status == s).cloned().unwrap_or_else(|| panic!("{s}: {l:?}"));
    let a = find(404);
    assert_eq!((a.bytes_in, a.bytes_out, a.version, a.aborted, a.listener), (5, 7, Version::Http11, false, 0));
    assert!(a.peer.is_some());
    let d = find(201);
    assert_eq!((d.bytes_out, d.aborted), (4, false));
    assert!(d.duration >= Duration::from_millis(25), "{:?}", d.duration);
    let s = find(200);
    assert_eq!((s.bytes_out, s.aborted), (5, false));
    assert_eq!(find(400).bytes_out, 11);
    assert!(l.iter().any(|c| c.aborted), "{l:?}");
}

// ------------------------------------------------------------------ U5

#[test]
fn http1_response_trailers_immediate_deferred_and_streamed() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        match req.path() {
            b"/now" => reply.header("content-type", "application/grpc").trailer("grpc-status", "0").trailer("grpc-message", "ok").body_static(b"payload"),
            b"/later" => {
                let r = reply.defer();
                std::thread::spawn(move || {
                    r.send(Response::new(200).body("deferred").trailer("x-checksum", "42"));
                });
                Outcome::Deferred
            }
            b"/stream" => {
                let mut sink = reply.stream();
                std::thread::spawn(move || {
                    sink.write(b"part").unwrap();
                    sink.finish_with_trailers(&[("grpc-status", "13"), ("content-length", "9")]);
                });
                Outcome::Done
            }
            _ => reply.trailer("bad name", "x").body_static(b"never"),
        }
    });
    let mut s = connect(&h);
    s.write_all(b"GET /now HTTP/1.1\r\nHost: t\r\nTE: trailers\r\n\r\n").unwrap();
    let out = String::from_utf8(read_until(&mut s, b"grpc-message: ok\r\n\r\n")).unwrap();
    assert!(out.contains("transfer-encoding: chunked\r\n") && !out.contains("content-length"), "{out}");
    assert!(out.ends_with("\r\n\r\n7\r\npayload\r\n0\r\ngrpc-status: 0\r\ngrpc-message: ok\r\n\r\n"), "{out}");
    s.write_all(b"GET /later HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let out = String::from_utf8(read_until(&mut s, b"x-checksum: 42\r\n\r\n")).unwrap();
    assert!(out.ends_with("8\r\ndeferred\r\n0\r\nx-checksum: 42\r\n\r\n"), "{out}");
    s.write_all(b"GET /stream HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let out = String::from_utf8(read_until(&mut s, b"grpc-status: 13\r\n\r\n")).unwrap();
    // a framing field in the trailers is left out
    assert!(out.ends_with("4\r\npart\r\n0\r\ngrpc-status: 13\r\n\r\n"), "{out}");
    // the connection is still in step
    s.write_all(b"GET /bad HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let out = String::from_utf8(read_until(&mut s, b"Internal Server Error")).unwrap();
    assert!(out.starts_with("HTTP/1.1 500"), "{out}");
    // HTTP/1.0 and HEAD get no trailers
    let mut c = Client::new(&h);
    c.send(b"GET /now HTTP/1.0\r\n\r\n");
    let r = c.read();
    assert_eq!((r.body.as_slice(), r.header("content-length")), (&b"payload"[..], Some("7")));
    let mut c = Client::new(&h);
    c.send(b"HEAD /now HTTP/1.1\r\nHost: t\r\n\r\n");
    let r = c.read_any(b"HEAD", false).unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(c.get("/later").text(), "deferred");
}

// ------------------------------------------------------------------ U10

#[test]
fn blocking_routes_of_100_ms_are_not_shed_at_moderate_load() {
    // 64 clients, each calling a 100 ms blocking route in a loop for about a second: with the
    // default pool (at least 64 workers, CoDel target at least the mean run time) nobody gets
    // a 503 (the old defaults shed at 2 x CPUs workers and a 5 ms target).
    let h = serve(simoom::blocking(|_req| {
        std::thread::sleep(Duration::from_millis(100));
        Response::text("done")
    }));
    let ok = Arc::new(AtomicUsize::new(0));
    let shed = Arc::new(AtomicUsize::new(0));
    let addr = h.local_addr();
    let threads: Vec<_> = (0..64)
        .map(|_| {
            let (ok, shed) = (ok.clone(), shed.clone());
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(addr).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                for _ in 0..8 {
                    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
                    let out = read_until(&mut s, b"\r\n\r\n");
                    let text = String::from_utf8_lossy(&out).to_string();
                    let body = if text.starts_with("HTTP/1.1 200") && !text.ends_with("done") { read_until(&mut s, b"done") } else { Vec::new() };
                    if text.starts_with("HTTP/1.1 503") {
                        shed.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    assert!(text.starts_with("HTTP/1.1 200") && (text.ends_with("done") || body.ends_with(b"done")), "{text}");
                    ok.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    let t0 = Instant::now();
    for t in threads {
        t.join().unwrap();
    }
    eprintln!("blocking: {:?} {:?}", t0.elapsed(), h.stats().offload);
    assert_eq!((ok.load(Ordering::Relaxed), shed.load(Ordering::Relaxed), h.stats().overloaded), (512, 0, 0));
}

#[cfg(feature = "watchdog")]
#[test]
fn a_route_blocking_300_ms_per_call_moves_to_the_offload_pool() {
    // Five stalls of 300 ms back to back cannot fit into the one-second window by wall time,
    // yet the loop was held the whole time: the window counts the time between stalls.
    let h = Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .log(|_| {})
        .service(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            std::thread::sleep(Duration::from_millis(300));
            reply.body_static(b"slow")
        })
        .start()
        .unwrap();
    let mut c = Client::new(&h);
    for _ in 0..7 {
        assert_eq!(c.get("/slow").text(), "slow");
        if h.stats().offloaded_routes == 1 {
            break;
        }
    }
    assert_eq!(h.stats().offloaded_routes, 1, "{:?}", h.stats());
}

