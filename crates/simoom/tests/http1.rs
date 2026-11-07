//! HTTP/1.1 through the facade, over real loopback sockets.

mod common;

use common::*;
use simoom::{blocking, Limits, Outcome, Reply, Request, Response, Router, StaticReply};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn echo_path(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let body = format!("{} {}", String::from_utf8_lossy(req.method()), req.path_str());
    reply.header("content-type", "text/plain").body(body)
}

#[test]
fn keep_alive_serves_many_requests_on_one_connection() {
    let h = serve(echo_path);
    let mut c = Client::new(&h);
    for i in 0..5 {
        let r = c.get(&format!("/n/{i}"));
        assert_eq!(r.status, 200);
        assert_eq!(r.text(), format!("GET /n/{i}"));
        assert!(r.header("date").is_some_and(|d| d.ends_with("GMT")));
        assert_eq!(r.header("content-length"), Some(&*r.body.len().to_string()));
        assert_eq!(r.header("connection"), None);
    }
    assert_eq!(h.stats().accepted, 1);
    assert!(h.stats().requests >= 5);
}

#[test]
fn pipelined_requests_are_answered_in_order() {
    let h = serve(echo_path);
    let mut c = Client::new(&h);
    let mut req = Vec::new();
    for i in 0..20 {
        req.extend_from_slice(format!("GET /p/{i} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes());
    }
    c.send(&req);
    for i in 0..20 {
        assert_eq!(c.read().text(), format!("GET /p/{i}"));
    }
}

#[test]
fn fixed_replies_and_head_requests() {
    let fixed = Arc::new(StaticReply::new(200, &[("content-type", "text/plain"), ("x-a", "b")], b"Hello, World!"));
    let h = serve(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/fixed" {
            reply.fixed(&fixed)
        } else {
            reply.body_static(b"dynamic")
        }
    });
    let mut c = Client::new(&h);
    let r = c.get("/fixed");
    assert_eq!((r.status, r.text()), (200, "Hello, World!".into()));
    assert_eq!(r.header("x-a"), Some("b"));
    assert!(r.header("date").is_some());
    c.send(b"HEAD /fixed HTTP/1.1\r\nHost: t\r\n\r\n");
    let r = c.read_any(b"HEAD", false).unwrap();
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert_eq!(r.header("content-length"), Some("13"));
    c.send(b"HEAD /dyn HTTP/1.1\r\nHost: t\r\n\r\n");
    let r = c.read_any(b"HEAD", false).unwrap();
    assert_eq!(r.header("content-length"), Some("7"));
    // And the connection still works after HEAD.
    assert_eq!(c.get("/fixed").text(), "Hello, World!");
}

#[test]
fn http10_closes_unless_keep_alive() {
    let h = serve(echo_path);
    let mut c = Client::new(&h);
    c.send(b"GET /a HTTP/1.0\r\n\r\n");
    let r = c.read();
    assert_eq!(r.header("connection"), Some("close"));
    assert!(c.closed());
    let mut c = Client::new(&h);
    c.send(b"GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    assert_eq!(c.read().header("connection"), Some("keep-alive"));
    c.send(b"GET /b HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    assert_eq!(c.read().text(), "GET /b");
}

fn echo_body(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let b = req.body().to_vec();
    reply.header("x-len", b.len().to_string()).body(b)
}

#[test]
fn request_bodies_content_length_and_chunked() {
    let h = serve(echo_body);
    let mut c = Client::new(&h);
    c.send(b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello");
    assert_eq!(c.read().text(), "hello");
    // Body split over several writes.
    c.send(b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 11\r\n\r\nhel");
    std::thread::sleep(Duration::from_millis(30));
    c.send(b"lo world");
    assert_eq!(c.read().text(), "hello world");
    // Chunked with an extension and trailers, in pieces.
    c.send(b"POST /x HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n");
    std::thread::sleep(Duration::from_millis(30));
    c.send(b"6\r\n world\r\n0\r\nx-trailer: 1\r\n\r\n");
    let r = c.read();
    assert_eq!((r.text().as_str(), r.header("x-len")), ("hello world", Some("11")));
    // Pipelined after a chunked body.
    c.send(b"POST /x HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /y HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(c.read().text(), "abc");
    assert_eq!(c.read().text(), "");
}

#[test]
fn expect_100_continue() {
    let h = serve(echo_body);
    let mut c = Client::new(&h);
    c.send(b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n");
    let r = c.read_any(b"POST", true).unwrap();
    assert_eq!(r.status, 100);
    c.send(b"data");
    assert_eq!(c.read().text(), "data");
}

#[test]
fn limits_give_specific_statuses() {
    let limits = Limits { max_body: 100, max_head: 2048, max_request_line: 1024, max_headers: 10, ..Limits::default() };
    let h = serve_with(limits, echo_body);
    let cases: Vec<(Vec<u8>, u16)> = vec![
        (b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 101\r\n\r\n".to_vec(), 413),
        (format!("GET /{} HTTP/1.1\r\nHost: t\r\n\r\n", "a".repeat(9000)).into_bytes(), 414),
        (format!("GET / HTTP/1.1\r\nHost: t\r\nx: {}\r\n\r\n", "a".repeat(3000)).into_bytes(), 431),
        ({
            let mut v = b"GET / HTTP/1.1\r\nHost: t\r\n".to_vec();
            for i in 0..11 {
                v.extend_from_slice(format!("h{i}: v\r\n").as_bytes());
            }
            v.extend_from_slice(b"\r\n");
            v
        }, 431),
        (b"GET / HTTP/1.1\r\n\r\n".to_vec(), 400),
        (b"GET / HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(), 400),
        (b"GET / HTTP/2.0\r\nHost: t\r\n\r\n".to_vec(), 505),
        (b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n80\r\n".to_vec(), 413),
    ];
    for (req, status) in cases {
        let mut c = Client::new(&h);
        c.send(&req);
        let r = c.read();
        assert_eq!(r.status, status, "for {:?}", String::from_utf8_lossy(&req[..req.len().min(60)]));
        assert_eq!(r.header("connection"), Some("close"));
        assert!(c.closed());
    }
    let s = h.stats();
    assert!(s.too_large >= 5 && s.bad_requests >= 2, "{s:?}");
}

#[test]
fn slowloris_is_closed_by_the_head_deadline() {
    let limits = Limits { head_timeout: Duration::from_millis(300), ..Limits::default() };
    let h = serve_with(limits, echo_path);
    // A partial head that never completes.
    let mut c = Client::new(&h);
    c.send(b"GET / HTTP/1.1\r\nHost: t\r\nX-Slow:");
    let t0 = std::time::Instant::now();
    let r = c.read_any(b"GET", false);
    assert_eq!(r.map(|r| r.status), Some(408));
    assert!(c.closed());
    assert!(t0.elapsed() < Duration::from_secs(3));
    // A connection that never sends a byte.
    let mut c = Client::new(&h);
    assert!(wait_for(3, || c.closed()));
    // Trickling bytes doesn't extend the deadline.
    let mut c = Client::new(&h);
    let t0 = std::time::Instant::now();
    for b in b"GET / HTTP/1.1\r\nHost: t\r\nX: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
        if c.s.write_all(&[*b]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
        if t0.elapsed() > Duration::from_secs(1) {
            break;
        }
    }
    assert!(c.closed());
    assert!(h.stats().timeouts >= 2);
}

#[test]
fn idle_keep_alive_times_out() {
    let limits = Limits { keep_alive_timeout: Duration::from_millis(200), ..Limits::default() };
    let h = serve_with(limits, echo_path);
    let mut c = Client::new(&h);
    assert_eq!(c.get("/").status, 200);
    let t0 = std::time::Instant::now();
    assert!(wait_for(3, || c.closed()));
    assert!(t0.elapsed() >= Duration::from_millis(150));
}

#[test]
fn slow_request_body_is_closed_by_the_minimum_rate() {
    let limits = Limits { body_rate_grace: Duration::from_millis(200), min_body_rate: 1_000_000, ..Limits::default() };
    let h = serve_with(limits, echo_body);
    let mut c = Client::new(&h);
    c.send(b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\nab");
    let r = c.read_any(b"POST", false).unwrap();
    assert_eq!(r.status, 408);
    assert!(c.closed());
}

#[test]
fn deferred_replies_complete_from_another_thread() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let path = req.path_str().to_string();
        let responder = reply.defer();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            responder.send(Response::text(format!("later {path}")).header("x-deferred", "1"));
        });
        Outcome::Deferred
    });
    let mut c = Client::new(&h);
    // Pipelined: replies stay in order even though each is deferred.
    c.send(b"GET /1 HTTP/1.1\r\nHost: t\r\n\r\nGET /2 HTTP/1.1\r\nHost: t\r\n\r\n");
    let a = c.read();
    assert_eq!((a.text().as_str(), a.header("x-deferred")), ("later /1", Some("1")));
    assert_eq!(c.read().text(), "later /2");
    assert_eq!(c.get("/3").text(), "later /3");
}

#[test]
fn a_dropped_responder_gives_500() {
    let h = serve(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        drop(reply.defer());
        Outcome::Deferred
    });
    assert_eq!(get(&h, "/").status, 500);
}

#[test]
fn streamed_replies_are_chunked_with_backpressure() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/sse" {
            let mut sink = reply.sse();
            std::thread::spawn(move || {
                for i in 0..3 {
                    sink.send_event(&format!("event {i}")).unwrap();
                }
            });
        } else {
            let mut sink = reply.header("content-type", "application/octet-stream").stream();
            std::thread::spawn(move || {
                let block = vec![b'x'; 64 * 1024];
                for _ in 0..32 {
                    sink.write(&block).unwrap();
                }
                sink.finish();
            });
        }
        Outcome::Done
    });
    let mut c = Client::new(&h);
    let r = c.get("/sse");
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    assert_eq!(r.header("content-type"), Some("text/event-stream"));
    assert_eq!(r.text(), "data: event 0\n\ndata: event 1\n\ndata: event 2\n\n");
    // 2 MiB through a 64 KiB stream buffer: the writer waits for the socket.
    let r = c.get("/big");
    assert_eq!(r.body.len(), 2 * 1024 * 1024);
    assert_eq!(c.get("/sse").status, 200, "keep-alive after a streamed body");
}

#[test]
fn stream_writer_sees_a_closed_connection() {
    let (tx, rx) = std::sync::mpsc::channel();
    let h = serve(move |_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        let mut sink = reply.stream();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let block = vec![b'x'; 16 * 1024];
            let mut r = Ok(());
            for _ in 0..100_000 {
                r = sink.write(&block);
                if r.is_err() {
                    break;
                }
            }
            tx.send(r.is_err()).unwrap();
        });
        Outcome::Done
    });
    let mut c = Client::new(&h);
    c.send(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
    let mut tmp = [0u8; 1024];
    let _ = c.s.read(&mut tmp);
    drop(c);
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(true));
}

#[test]
fn blocking_handlers_run_on_the_offload_pool() {
    let h = serve(blocking(|req: simoom::OwnedRequest| {
        let name = std::thread::current().name().unwrap_or("").to_string();
        Response::text(format!("{} on {name}", req.path_str()))
    }));
    let r = get(&h, "/work");
    assert_eq!(r.status, 200);
    assert!(r.text().starts_with("/work on simoom-offload"), "{}", r.text());
    assert_eq!(h.stats().offload.completed, 1);
}

#[test]
fn overload_gives_fast_503_with_retry_after() {
    let limits = Limits { offload_threads: 1, offload_queue: 1, ..Limits::default() };
    let h = serve_with(
        limits,
        blocking(|_| {
            std::thread::sleep(Duration::from_millis(400));
            Response::text("slow")
        }),
    );
    let addr = h.local_addr();
    let mut threads = Vec::new();
    for _ in 0..6 {
        threads.push(std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
            let t0 = std::time::Instant::now();
            let mut b = vec![0u8; 4096];
            let n = s.read(&mut b).unwrap();
            (String::from_utf8_lossy(&b[..n]).into_owned(), t0.elapsed())
        }));
        std::thread::sleep(Duration::from_millis(10));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let rejected: Vec<_> = results.iter().filter(|(r, _)| r.starts_with("HTTP/1.1 503")).collect();
    assert!(!rejected.is_empty(), "{results:?}");
    for (r, took) in &rejected {
        assert!(r.contains("retry-after: 1"), "{r}");
        assert!(*took < Duration::from_millis(300), "503 must be fast, took {took:?}");
    }
    assert!(results.iter().any(|(r, _)| r.starts_with("HTTP/1.1 200")));
    assert!(h.stats().overloaded >= 1);
}

#[test]
fn a_panicking_handler_gives_500_and_closes_the_connection() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/panic" {
            panic!("handler bug (expected by the test)");
        }
        reply.body_static(b"fine")
    });
    let mut c = Client::new(&h);
    assert_eq!(c.get("/ok").text(), "fine");
    let r = c.get("/panic");
    assert_eq!(r.status, 500);
    assert_eq!(r.header("connection"), Some("close"));
    assert!(c.closed());
    // The loop thread survived.
    for _ in 0..4 {
        assert_eq!(get(&h, "/ok").text(), "fine");
    }
    assert_eq!(h.stats().panics, 1);
}

#[test]
fn a_reply_that_is_dropped_or_invalid_gives_500() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        match req.path() {
            b"/drop" => {
                let _dropped = reply;
                Outcome::Done
            }
            b"/badheader" => reply.header("x", "a\r\nb").body_static(b"no"),
            _ => reply.status(42).empty(),
        }
    });
    assert_eq!(get(&h, "/drop").status, 500);
    assert_eq!(get(&h, "/badheader").status, 500);
    assert_eq!(get(&h, "/badstatus").status, 500);
}

#[test]
fn router_exact_template_404_405() {
    let router = Router::new()
        .get("/health", |_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
        .get("/users/:id", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let id = req.param_str("id").unwrap_or("?").to_string();
            r.body(format!("user {id}"))
        })
        .post("/users/:id", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let s = format!("posted {} {}", req.param_str("id").unwrap(), String::from_utf8_lossy(req.body()));
            r.status(201).body(s)
        })
        .get("/files/*path", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let p = req.param_str("path").unwrap_or("").to_string();
            r.body(p)
        });
    let h = serve(router);
    let mut c = Client::new(&h);
    assert_eq!(c.get("/health").text(), "ok");
    assert_eq!(c.get("/users/42?x=1").text(), "user 42");
    assert_eq!(c.get("/files/a/b/c.txt").text(), "a/b/c.txt");
    let r = c.get("/nope");
    assert_eq!(r.status, 404);
    c.send(b"DELETE /users/42 HTTP/1.1\r\nHost: t\r\n\r\n");
    let r = c.read();
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("GET, POST"));
    c.send(b"POST /users/7 HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n\r\nhi");
    let r = c.read();
    assert_eq!((r.status, r.text().as_str()), (201, "posted 7 hi"));
    c.send(b"HEAD /health HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(c.read_any(b"HEAD", false).unwrap().status, 200);
}

#[test]
fn streamed_request_bodies_with_backpressure() {
    let limits = Limits { body_buffer: 4096, ..Limits::default() };
    let h = serve_with(
        limits,
        blocking(|mut req: simoom::OwnedRequest| {
            let streamed = req.is_streamed();
            let body = req.read_body().unwrap();
            let sum: u64 = body.iter().map(|&b| u64::from(b)).sum();
            Response::text(format!("{streamed} {} {sum}", body.len()))
        }),
    );
    let mut c = Client::new(&h);
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let sum: u64 = body.iter().map(|&b| u64::from(b)).sum();
    c.send(format!("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
    for part in body.chunks(7000) {
        c.send(part);
    }
    assert_eq!(c.read().text(), format!("true 300000 {sum}"));
    // Chunked, longer than the buffer: switches to streaming mid-body.
    c.send(b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n");
    for part in body.chunks(3000) {
        c.send(format!("{:x}\r\n", part.len()).as_bytes());
        c.send(part);
        c.send(b"\r\n");
    }
    c.send(b"0\r\n\r\n");
    assert_eq!(c.read().text(), format!("true 300000 {sum}"));
    // Small bodies are buffered.
    c.send(b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc");
    assert_eq!(c.read().text(), format!("false 3 {}", 97 + 98 + 99));
}

#[test]
fn slow_body_reader_pauses_the_client() {
    // The handler reads slowly; the server must stop reading the socket instead of buffering.
    let limits = Limits { body_buffer: 8192, ..Limits::default() };
    let read = Arc::new(AtomicUsize::new(0));
    let r2 = read.clone();
    let h = serve_with(
        limits,
        blocking(move |mut req: simoom::OwnedRequest| {
            let mut src = req.take_body().expect("streamed");
            let mut buf = [0u8; 1024];
            let mut n = 0;
            loop {
                let k = src.read(&mut buf).unwrap();
                if k == 0 {
                    break;
                }
                n += k;
                r2.store(n, Ordering::Relaxed);
                if n < 64 * 1024 {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            Response::text(n.to_string())
        }),
    );
    let mut c = Client::new(&h);
    let total = 4 * 1024 * 1024;
    c.send(format!("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: {total}\r\n\r\n").as_bytes());
    let block = vec![7u8; 64 * 1024];
    c.s.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    for _ in 0..total / block.len() {
        c.send(&block);
    }
    assert_eq!(c.read().text(), total.to_string());
}

#[test]
fn stall_watchdog_moves_a_slow_service_to_the_offload_pool() {
    let logs = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let l2 = logs.clone();
    let limits = Limits { inline_budget: Some(Duration::from_millis(1)), stalls_before_offload: 3, ..Limits::default() };
    let h = simoom::Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(limits)
        .log(move |m| l2.lock().unwrap().push(m.to_string()))
        .service(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            std::thread::sleep(Duration::from_millis(5)); // wrongly inline
            let name = std::thread::current().name().unwrap_or("").to_string();
            reply.body(name)
        })
        .start()
        .unwrap();
    let mut c = Client::new(&h);
    for _ in 0..3 {
        assert!(c.get("/").text().starts_with("simoom"));
    }
    assert!(c.get("/").text().starts_with("simoom-offload"), "the 4th call runs offloaded");
    let s = h.stats();
    assert!(s.stalls >= 3, "{s:?}");
    let logs = logs.lock().unwrap();
    assert_eq!(logs.iter().filter(|l| l.contains("took")).count(), 1, "logged once: {logs:?}");
}

#[test]
fn router_moves_only_the_slow_route() {
    let router = Router::new()
        .get("/slow", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            std::thread::sleep(Duration::from_millis(5));
            r.body(std::thread::current().name().unwrap_or("").to_string())
        })
        .get("/fast", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body(std::thread::current().name().unwrap_or("").to_string()) })
        .stalls_before_offload(2);
    let limits = Limits { inline_budget: Some(Duration::from_millis(1)), ..Limits::default() };
    let h = serve_with(limits, router);
    let mut c = Client::new(&h);
    c.get("/slow");
    c.get("/slow");
    assert!(c.get("/slow").text().starts_with("simoom-offload"));
    assert!(!c.get("/fast").text().starts_with("simoom-offload"));
}

#[test]
fn max_requests_per_connection() {
    let limits = Limits { max_requests_per_connection: 2, ..Limits::default() };
    let h = serve_with(limits, echo_path);
    let mut c = Client::new(&h);
    assert_eq!(c.get("/1").header("connection"), None);
    assert_eq!(c.get("/2").header("connection"), Some("close"));
    assert!(c.closed());
}

#[test]
fn graceful_stop_finishes_in_flight_requests() {
    let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/slow" {
            let responder = reply.defer();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                responder.send(Response::text("done"));
            });
            return Outcome::Deferred;
        }
        reply.body_static(b"fast")
    });
    let addr = h.local_addr();
    let mut busy = Client::new(&h);
    let mut idle = Client::new(&h);
    assert_eq!(idle.get("/").text(), "fast");
    busy.send(b"GET /slow HTTP/1.1\r\nHost: t\r\n\r\n");
    std::thread::sleep(Duration::from_millis(50));
    h.stop(Duration::from_secs(5));
    // The idle connection closes at once; the busy one gets its reply with Connection: close.
    assert!(idle.closed());
    let r = busy.read();
    assert_eq!(r.text(), "done");
    assert_eq!(r.header("connection"), Some("close"));
    assert!(busy.closed());
    h.join();
    assert!(std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err());
}

#[cfg(feature = "websocket")]
mod websocket {
    use super::*;
    use simoom::{WebSocket, WebSocketHandler, WsMessage};

    struct Echo;
    impl WebSocketHandler for Echo {
        fn on_open(&mut self, ws: &mut WebSocket<'_>) {
            ws.send_text("welcome");
        }
        fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>) {
            match msg {
                WsMessage::Text("bye") => ws.close(1000, "bye"),
                WsMessage::Text(t) => ws.send_text(&format!("echo {t}")),
                WsMessage::Binary(b) => ws.send_binary(b),
            }
        }
    }

    fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut v = vec![0x80 | op];
        if payload.len() < 126 {
            v.push(0x80 | payload.len() as u8);
        } else {
            v.push(0x80 | 126);
            v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(&mask);
        v.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        v
    }

    fn read_frame(c: &mut Client) -> (u8, Vec<u8>) {
        loop {
            if c.buf.len() >= 2 {
                let op = c.buf[0] & 0x0f;
                let (len, hl) = match c.buf[1] & 0x7f {
                    126 if c.buf.len() >= 4 => (u16::from_be_bytes([c.buf[2], c.buf[3]]) as usize, 4),
                    126 => (usize::MAX, 0),
                    n => (n as usize, 2),
                };
                if len != usize::MAX && c.buf.len() >= hl + len {
                    let p = c.buf[hl..hl + len].to_vec();
                    c.buf.drain(..hl + len);
                    return (op, p);
                }
            }
            let mut tmp = [0u8; 4096];
            let n = c.s.read(&mut tmp).unwrap();
            assert!(n > 0, "eof");
            c.buf.extend_from_slice(&tmp[..n]);
        }
    }

    #[test]
    fn websocket_echo() {
        let h = serve(|req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            if req.is_websocket_upgrade() {
                reply.websocket(Echo)
            } else {
                reply.status(426).empty()
            }
        });
        let mut c = Client::new(&h);
        c.send(b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        let r = c.read();
        assert_eq!(r.status, 101);
        assert_eq!(r.header("sec-websocket-accept"), Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert_eq!(read_frame(&mut c), (1, b"welcome".to_vec()));
        c.send(&frame(1, b"hi"));
        assert_eq!(read_frame(&mut c), (1, b"echo hi".to_vec()));
        // Fragmented text, a ping in between.
        let mut f1 = frame(1, b"frag");
        f1[0] = 0x01; // no FIN
        c.send(&f1);
        c.send(&frame(9, b"p"));
        let mut f2 = frame(0, b"mented");
        f2[0] = 0x80;
        c.send(&f2);
        assert_eq!(read_frame(&mut c), (10, b"p".to_vec()));
        assert_eq!(read_frame(&mut c), (1, b"echo fragmented".to_vec()));
        let big = vec![9u8; 1000];
        c.send(&frame(2, &big));
        assert_eq!(read_frame(&mut c), (2, big));
        c.send(&frame(1, b"bye"));
        let (op, p) = read_frame(&mut c);
        assert_eq!((op, &p[..2]), (8, &1000u16.to_be_bytes()[..]));
        c.send(&frame(8, &1000u16.to_be_bytes()));
        assert!(c.closed());
        assert!(h.stats().upgrades >= 1);
    }

    #[test]
    fn plain_requests_to_a_websocket_service() {
        let h = serve(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.websocket(Echo) });
        assert_eq!(get(&h, "/").status, 400);
    }

    #[test]
    fn websocket_handle_sends_from_another_thread() {
        struct Pusher;
        impl WebSocketHandler for Pusher {
            fn on_open(&mut self, ws: &mut WebSocket<'_>) {
                let h = ws.handle();
                std::thread::spawn(move || {
                    for i in 0..3 {
                        h.send_text(format!("tick {i}"));
                    }
                });
            }
            fn on_message(&mut self, _: &mut WebSocket<'_>, _: WsMessage<'_>) {}
        }
        let h = serve(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.websocket(Pusher) });
        let mut c = Client::new(&h);
        c.send(b"GET / HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        assert_eq!(c.read().status, 101);
        for i in 0..3 {
            assert_eq!(read_frame(&mut c), (1, format!("tick {i}").into_bytes()));
        }
    }
}
