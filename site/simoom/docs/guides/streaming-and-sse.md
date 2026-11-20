# How do I stream bodies and server-sent events with simoom?

> `Reply::stream` and `Reply::sse` return a `BodySink` you write from any thread; large uploads arrive through a `BodySource` read off the loop thread.

Some responses are too large to build in memory, or never end: a log export, a progress feed, a
live dashboard. Some uploads are too large to buffer. simoom streams both directions with
backpressure, so a slow client slows the writer instead of filling memory.

## Streaming a response

`reply.stream()` sends the status and headers at once and returns a `BodySink` for the body. The
body goes out chunked on HTTP/1.1 and as DATA frames on HTTP/2 and HTTP/3. `BodySink` is `Send`
and implements `std::io::Write`, so a thread can write to it:

```rust
use simoom::{Outcome, Reply, Request};
use std::io::Write;

fn numbers(_: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let mut sink = reply.header("content-type", "text/plain").stream();
    std::thread::spawn(move || {
        for i in 0..1000 {
            // write waits while 64 KiB are pending, so a slow client slows this thread
            if writeln!(sink, "line {i}").is_err() {
                return; // the client went away
            }
        }
        sink.finish();
    });
    Outcome::Done
}
```

At most `Limits::stream_buffer` bytes (64 KiB by default) are handed to the connection and not
yet sent. Past that, `write` waits. That is fine on your own thread or an offload worker and
**wrong on the loop thread**, where it would stop the loop. On the loop thread use `try_write`,
which never waits and fails with `WouldBlock` when the buffer is full:

```rust
use simoom::{Outcome, Reply, Request};

fn small(_: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let mut sink = reply.stream();
    // on the loop thread: try_write never waits
    let _ = sink.try_write(b"first part, ");
    let _ = sink.try_write(b"second part");
    sink.finish();
    Outcome::Done
}
```

`BodySink` also has `poll_ready` and a `ready()` future for code that runs its own executor; no
runtime is attached.

Ending the body:

- `finish()`, or dropping the sink, ends it normally.
- `finish_with_trailers(&[("grpc-status", "0")])` ends it with trailer fields (trailing HEADERS on
  HTTP/2 and HTTP/3, a trailer section on HTTP/1.1).
- `abort()` cuts it off: the HTTP/1.1 connection closes, or the HTTP/2 or HTTP/3 stream is reset,
  so the client knows the body is incomplete.
- `is_closed()` tells you the client is gone; `write` then fails with `BrokenPipe`.

```rust
use simoom::{Outcome, Reply, Request};

fn grpc_like(_: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let mut sink = reply.header("content-type", "application/grpc").stream();
    std::thread::spawn(move || {
        let _ = sink.write(b"\0\0\0\0\0");
        sink.finish_with_trailers(&[("grpc-status", "0")]);
    });
    Outcome::Done
}
```

## Server-sent events

`reply.sse()` is `stream()` with `content-type: text/event-stream` and `cache-control: no-cache`.
`send_event` writes one event: each line of the text becomes a `data:` line, followed by a blank
line.

```rust
use simoom::{Outcome, Reply, Request, Router};
use std::time::Duration;

fn router() -> Router {
    Router::new().get("/events", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
        let mut sink = r.sse();
        std::thread::spawn(move || {
            for i in 0.. {
                if sink.send_event(&format!("tick {i}")).is_err() {
                    return; // the browser closed the page
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        Outcome::Done
    })
}
```

In the browser, `new EventSource("/events")` receives the ticks. For named events or ids, write
the fields yourself with `sink.write(b"event: update\ndata: ...\n\n")`.

A thread per stream is simple and fine for tens or hundreds of streams. For many thousands, keep
the sinks in one place and have a single thread (or a timer) write to all of them.

Long-lived streams over HTTP/2 can outlive a client that vanished without closing its
connection. The `h2-keepalive` feature with `Limits::h2_keepalive` sends PINGs to find such
clients ([HTTP/2 and HTTP/3](http2-and-http3.md)).

## Request bodies

Bodies up to `Limits::body_buffer` (64 KiB by default) are read whole before your service is
called, and `req.body()` returns them:

```rust
use simoom::{Outcome, Reply, Request};

fn upload(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    if req.is_streamed() {
        return reply.status(413).body_static(b"send less than 64 KiB here");
    }
    let n = req.body().len();
    reply.body(format!("got {n} bytes"))
}
```

Larger bodies, and bodies of unknown length, stream: `req.is_streamed()` is true, `req.body()` is
empty, and `req.take_body()` returns a `BodySource`. The connection reads from the socket only
while the source has room, so a slow reader slows the client down (pull-based backpressure).

`BodySource` implements `std::io::Read`, which blocks, so read it on the offload pool or your own
thread:

```rust
use simoom::{blocking, OwnedRequest, Response};
use std::io::Read;

fn service() -> impl simoom::Service {
    blocking(|mut req: OwnedRequest| {
        let mut total = 0u64;
        if let Some(mut body) = req.take_body() {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match body.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total += n as u64, // hash it, write it to disk, ...
                    Err(_) => return Response::new(400).body("upload broken off"),
                }
            }
        } else {
            total = req.body().len() as u64;
        }
        Response::text(format!("received {total} bytes"))
    })
}
```

When you just want the whole body, `OwnedRequest::read_body()` returns the buffered body or reads
the stream to its end:

```rust
use simoom::{blocking, OwnedRequest, Response};

fn service() -> impl simoom::Service {
    blocking(|mut req: OwnedRequest| match req.read_body() {
        Ok(body) => Response::text(format!("{} bytes", body.len())),
        Err(_) => Response::new(400).body("bad body"),
    })
}
```

`BodySource::try_read` and `poll_read` don't block, if you need to read on the loop thread.
Trailers of a streamed body are available from `BodySource::trailers()` once it is complete.

Limits that apply to request bodies:

- `Limits::max_body` (10 MiB): a larger `Content-Length` is refused with `413` before any body
  byte is read; a chunked body that grows past it fails the read.
- `Limits::min_body_rate` (1 KiB/s after a 5-second grace): a client that sends slower is cut off.

## Common questions

### Can I stream a file to the client?

Yes: open it on your own thread or an offload worker and copy it into the sink with
`std::io::copy(&mut file, &mut sink)`. simoom has no static-file server, so paths, content types
and range requests are up to you (the `conditional` feature helps with ETags and ranges).

### Does SSE work over HTTP/2 and HTTP/3?

Yes. The same `sse()` call works on every protocol; on HTTP/2 and HTTP/3 many event streams share
one connection.

### How do I know the client disconnected?

`write` and `send_event` return an error, and `is_closed()` returns true. Stop producing and drop
the sink.

### Can response compression apply to streams?

Yes, with the `compression` feature and `Compression::new().streams(true)`; each compressed
stream then holds a compressor of about 256 KiB while it runs.
