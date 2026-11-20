# How do I call a database or a service from a simoom handler?

> Never block the loop thread: wrap slow handlers in `simoom::blocking`, or use `Reply::offload`, or `Reply::defer` and answer later from your own threads.

simoom serves thousands of connections on each loop thread. A handler that waits for a database,
a file or another HTTP service stops every one of those connections while it waits. This page
shows the three ways to move that work off the loop, and the safety net for when a handler
blocks anyway.

## Which way to choose

| your situation | use |
|---|---|
| a handler that blocks (database, file, HTTP call) and you have no thread pool of your own | `simoom::blocking(f)` as the route handler |
| a handler that is usually fast but sometimes slow | `reply.blocking(req, f)` or `reply.offload(req, f)` on the slow branch |
| your program already has worker threads, queues or a runtime | `reply.defer()` and answer through the `Responder` from any thread |
| microseconds of CPU, no I/O | answer inline, as usual |

`blocking` and `offload` run on simoom's **offload pool**. `defer` doesn't touch the pool at all.

## The offload pool with `blocking`

`blocking` turns a function that takes an `OwnedRequest` and returns a `Response` into a service.
The request is copied, the function runs on a worker thread, and its response goes back to the
connection:

```rust
use simoom::{blocking, OwnedRequest, Response, Router};
use std::time::Duration;

fn router() -> Router {
    Router::new().get("/report/:id", blocking(|req: OwnedRequest| {
        let id = String::from_utf8_lossy(req.param("id").unwrap_or(b"")).into_owned();
        std::thread::sleep(Duration::from_millis(200)); // stands for a database query
        Response::text(format!("report {id}"))
    }))
}
```

The pool is bounded, so overload can't pile up:

- Worker threads start on demand and exit after 10 seconds idle. The cap is
  `Limits::offload_threads`; the default `0` means 32 per CPU, between 512 and 1024.
- At most `Limits::offload_queue` jobs wait (default 4096).
- The pool measures how long jobs wait (CoDel). When waits keep growing past what the workers can
  absorb, new requests get a fast **`503` with `Retry-After`** instead of joining an endless
  queue. The target adapts to how long your jobs take, so 100 ms database calls are not refused
  just for being 100 ms long.
- A panic in the function becomes a `500`.

## Only the slow branch: `Reply::blocking` and `Reply::offload`

When a handler is fast most of the time, keep the fast path inline and offload only the slow one:

```rust
use simoom::{Outcome, Reply, Request, Response};

fn handler(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    if req.query_param("cached").is_some() {
        return reply.body_static(b"from cache"); // fast: answer inline
    }
    reply.blocking(req, |req| {
        // slow: runs on an offload worker
        Response::text(format!("computed for {}", req.path_str()))
    })
}
```

`Reply::offload` does the same but gives the worker the usual `Request` and `Reply`, so code
written as an inline service runs unchanged on the pool:

```rust
use simoom::{Outcome, Reply, Request};

fn handler(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    reply.offload(req, |req, reply| {
        // the same Request and Reply API, on a worker thread
        let size = req.body().len();
        std::thread::sleep(std::time::Duration::from_millis(50));
        reply.status(202).header("content-type", "text/plain").body(format!("accepted {size} bytes"))
    })
}
```

## Your own threads: `Reply::defer`

If your program already has workers (a job queue, a thread pool, an integration engine), copy the
request with `to_owned_request()`, take a `Responder` with `reply.defer()`, and send both to your
workers. The `Responder` can be sent to any thread and answers once:

```rust
use simoom::{Outcome, Reply, Request, Response, Server};
use std::sync::mpsc;

struct Job {
    request: simoom::OwnedRequest,
    responder: simoom::Responder,
}

fn run() -> std::io::Result<()> {
    let (tx, rx) = mpsc::channel::<Job>();
    let tx = std::sync::Mutex::new(tx);

    // your own worker thread (or pool)
    std::thread::spawn(move || {
        for job in rx {
            if job.responder.is_cancelled() {
                continue; // the client left or the deadline passed
            }
            let answer = format!("done: {}", job.request.path_str());
            job.responder.send(Response::text(answer));
        }
    });

    let server = Server::builder()
        .listen("127.0.0.1:8080")
        .service(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            let job = Job { request: req.to_owned_request(), responder: reply.defer() };
            if let Err(mpsc::SendError(job)) = tx.lock().unwrap().send(job) {
                job.responder.send(Response::new(503).body("worker gone"));
            }
            Outcome::Deferred
        })
        .start()?;
    server.join();
    Ok(())
}
```

This is how [Cameleer](https://github.com/Cameleering/cameleer) embeds simoom: its own route
threads answer, and simoom's pool isn't involved. A few things to know:

- **`Responder::send` returns `false`** when the connection is already gone; the response is
  dropped.
- **Dropping a `Responder`** without sending gives the client a `500`.
- **`Responder::stream(head)`** starts a streamed response instead of a whole one.
- **Order on HTTP/1.1:** while a response is deferred, that HTTP/1.1 connection reads no further
  requests, so responses stay in order. HTTP/2 and HTTP/3 streams carry on independently.

## Deadlines and cancellation

By default a deferred or offloaded reply may take as long as it likes. Set
`Limits::defer_timeout` to your service-level objective: when it expires before an answer has
started, the client gets **`504 Gateway Timeout`** and the late answer is dropped.

The worker can find out that its work is no longer wanted, because the client went away or the
deadline passed. `Responder::is_cancelled()` is one atomic load, cheap to poll between steps.
`Responder::on_cancel(f)` runs `f` once on cancellation, on the loop thread, so `f` must be quick:
set a flag or wake a thread.

```rust
use simoom::Responder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn watch(responder: &Responder) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    responder.on_cancel(move || flag.store(true, Ordering::Relaxed));
    stop
}
```

## Tuning the pool

```rust
use simoom::{Limits, Server};
use std::time::Duration;

fn build() -> simoom::Builder {
    Server::builder().listen("0.0.0.0:8080").limits(Limits {
        offload_threads: 64,                           // what your database allows
        offload_queue: 1024,                           // jobs waiting before 503
        defer_timeout: Some(Duration::from_secs(10)),  // 504 after this
        inline_budget: Some(Duration::from_millis(2)), // watchdog budget per inline call
        ..Limits::default()
    })
}
```

Set `offload_threads` to the concurrency your backends can take: if your database allows 64
connections, more than 64 workers only queue inside the database driver instead of in simoom,
where overload turns into a clean `503`.

## The watchdog, a safety net

A handler that turns out slow (it blocks, or uses more than `Limits::inline_budget` of CPU, 1 ms
by default) is a **stall**. After `Limits::stalls_before_offload` stalls (5) within
`Limits::stall_window` (1 s), that route alone moves to the offload pool. Other routes stay
inline. After `Limits::stall_recovery` fast calls (64) there, it comes back.

The watchdog measures CPU time, not wall time, so a loop thread preempted on a busy machine isn't
mistaken for a slow handler. Each stall is logged once per route and counted in
`stats().stalls`.

The calls before the move still held their loop thread, so treat the watchdog as a seatbelt,
not as a way to avoid choosing. It needs the `watchdog` feature (on by default); a minimal edge
build can leave it out.

## Common questions

### Can I use async/await or tokio inside a handler?

Not directly: a service returns before the loop moves on. You can run tokio in your program and
hand it the work: take a `Responder` with `reply.defer()`, move it into a spawned task, and call
`responder.send(...)` when the future completes. `Responder` is a plain `Send` value.

### What happens when the offload pool is full?

New requests that need it get `503 Service Unavailable` with `Retry-After: 1` right away, and
`stats().overloaded` counts them. Requests already admitted keep their latency.

### Is `blocking` the same as `tokio::task::spawn_blocking`?

Similar idea, different shape: `blocking` wraps a whole handler, the pool is bounded with
admission control, and overload answers `503` instead of queueing without limit.

### How do I read a large request body in a slow handler?

On the pool, `OwnedRequest::read_body()` reads the whole body, and `take_body()` gives a
`std::io::Read` stream. See [Streaming and SSE](streaming-and-sse.md).
