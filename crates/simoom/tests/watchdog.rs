//! The stall watchdog: preemption is not a stall, slow routes move alone and come back.

mod common;

use common::*;
use simoom::{Limits, Outcome, Reply, Request, Router};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The tests run one at a time: the CPU hogs of one would distort the timings of the others.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn thread_name() -> String {
    std::thread::current().name().unwrap_or("").to_string()
}

fn spin(d: Duration) {
    let t = Instant::now();
    while t.elapsed() < d {
        std::hint::spin_loop();
    }
}

fn limits() -> Limits {
    Limits { inline_budget: Some(Duration::from_millis(1)), stalls_before_offload: 3, stall_window: Duration::from_secs(10), stall_recovery: 4, ..Limits::default() }
}

fn offloaded(name: &str) -> bool {
    name.starts_with("simoom-offload")
}

/// Calls `path` until it answers from the offload pool; returns how many calls that took.
fn until_offloaded(c: &mut Client, path: &str, max: usize) -> usize {
    for i in 1..=max {
        if offloaded(&c.get(path).text()) {
            return i;
        }
    }
    panic!("{path} never moved to the offload pool");
}

#[test]
fn a_cpu_bound_route_moves_alone_and_comes_back_when_fast() {
    let _serial = serial();
    let slow = Arc::new(AtomicBool::new(true));
    let s2 = slow.clone();
    let router = Router::new()
        .get("/work", move |_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            if s2.load(Ordering::Relaxed) {
                spin(Duration::from_millis(5));
            }
            r.body(thread_name())
        })
        .get("/fast", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body(thread_name()) });
    let logs = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let l2 = logs.clone();
    let h = simoom::Server::builder()
        .listen("127.0.0.1:0")
        .threads(1)
        .limits(limits())
        .log(move |m| l2.lock().unwrap().push(m.to_string()))
        .service(router)
        .start()
        .unwrap();
    let mut c = Client::new(&h);
    // One wall-clock overrun makes the route suspect; three measured stalls move it.
    let n = until_offloaded(&mut c, "/work", 20);
    assert!((4..=6).contains(&n), "moved after {n} calls");
    assert!(!offloaded(&c.get("/fast").text()), "other routes stay inline");
    let s = h.stats();
    assert!(s.stalls >= 3 && s.offloaded_routes == 1, "{s:?}");
    // Fast again: back inline after `stall_recovery` (4) fast calls on the pool.
    slow.store(false, Ordering::Relaxed);
    let mut back = None;
    for i in 1..=10 {
        if !offloaded(&c.get("/work").text()) {
            back = Some(i);
            break;
        }
    }
    assert_eq!(back, Some(5), "4 fast offloaded calls, then inline");
    let logs = logs.lock().unwrap();
    assert_eq!(logs.iter().filter(|l| l.contains("took")).count(), 1, "logged once: {logs:?}");
    assert!(logs.iter().any(|l| l.contains("/work") && l.contains("offload pool")), "{logs:?}");
}

#[test]
fn a_blocking_path_moves_but_other_paths_of_the_service_stay_inline() {
    let _serial = serial();
    // Not a router: the watchdog tracks the service per method and path.
    let h = serve_with(limits(), |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        if req.path() == b"/block" {
            std::thread::sleep(Duration::from_millis(20)); // wrongly inline
        }
        reply.body(thread_name())
    });
    let mut c = Client::new(&h);
    let n = until_offloaded(&mut c, "/block", 20);
    assert!((4..=6).contains(&n), "moved after {n} calls");
    for _ in 0..20 {
        assert!(!offloaded(&c.get("/other").text()), "the rest of the service stays inline");
    }
}

#[test]
fn slow_calls_spread_wider_than_the_window_never_move_a_route() {
    let _serial = serial();
    let l = Limits { stall_window: Duration::from_millis(30), ..limits() };
    let h = serve_with(l, |_: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
        spin(Duration::from_millis(3));
        reply.body(thread_name())
    });
    let mut c = Client::new(&h);
    for _ in 0..8 {
        assert!(!offloaded(&c.get("/").text()));
        std::thread::sleep(Duration::from_millis(40));
    }
    let s = h.stats();
    assert!(s.stalls >= 3 && s.offloaded_routes == 0, "{s:?}");
}

/// Time the loop thread loses around a fast handler (here a sleep in a wrapping service, outside
/// the route's handler, as a preemption would lose it) shows on the wall clock but not on the
/// thread clocks around the handler: the route is checked, never moved.
#[test]
fn wall_time_lost_outside_the_handler_is_not_a_stall() {
    let _serial = serial();
    struct Preempted(Router);
    impl simoom::Service for Preempted {
        fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
            std::thread::sleep(Duration::from_millis(3));
            self.0.call(req, reply)
        }
        fn watch(&self, req: &Request<'_>) -> Option<simoom::WatchRef<'_>> {
            self.0.watch(req)
        }
    }
    let router = Router::new().get("/", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body(thread_name()) });
    let h = serve_with(limits(), Preempted(router));
    let mut c = Client::new(&h);
    for _ in 0..40 {
        assert!(!offloaded(&c.get("/").text()), "{:?}", h.stats());
    }
    let s = h.stats();
    assert!(s.stall_checks >= 1, "the overruns were checked: {s:?}");
    assert_eq!((s.stalls, s.offloaded_routes), (0, 0), "{s:?}");
}

/// A loop thread preempted while it runs a fast handler (CPU hogs on every core) must not move
/// anything: the wall clock may overrun, but
/// the CPU clock shows the handler is cheap.
#[test]
fn preemption_does_not_trip_the_watchdog() {
    let _serial = serial();
    let router = Router::new().get("/", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body(thread_name()) });
    let h = simoom::Server::builder().listen("127.0.0.1:0").threads(1).limits(limits()).service(router).start().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    let hogs: Vec<_> = (0..cpus * 3)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    spin(Duration::from_millis(1));
                }
            })
        })
        .collect();
    let mut c = Client::new(&h);
    let t = Instant::now();
    let mut n = 0;
    while t.elapsed() < Duration::from_secs(2) {
        assert!(!offloaded(&c.get("/").text()), "after {n} calls: {:?}", h.stats());
        n += 1;
    }
    stop.store(true, Ordering::Relaxed);
    for t in hogs {
        t.join().unwrap();
    }
    let s = h.stats();
    eprintln!("{n} calls under CPU contention: {} wall overruns checked, {} stalls", s.stall_checks, s.stalls);
    assert_eq!(s.offloaded_routes, 0, "{s:?}");
    assert_eq!(s.stalls, 0, "{s:?}");
}
