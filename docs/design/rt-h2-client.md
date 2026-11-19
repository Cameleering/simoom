# An event-driven HTTP/2 client: `RtClient` over HTTP/2

_2026-11-19. Branch `h2-event-client`, not released._

## Why

The blocking `simoom_client::Client` drives the sans-io `simoom-h2` engine through `Mux`: one
requesting thread per request, a pump thread per connection that reads the socket, a `Slot`
(mutex + condition variable) per stream and a `State` mutex per connection. Each response needs a
hand-off: the pump wakes from `read`, feeds the engine, then wakes the requesting thread through
its condition variable. Profiled in Cameleer's HTTP/2 round (`docs/design/http2-throughput.md` in
the Cameleer repository, sections "The client, measured but not fixed" and "Profiling round"),
that hand-off was what kept HTTP/2 behind HTTP/1.1 once the server was fixed: 36 us of client CPU
per request against 16 us for a hand-written HTTP/1.1 client whose threads block in `read` on
their own sockets, 62% of it in the kernel, the run queue spinlock of cross-CPU wake-ups the
largest kernel item.

The fix is to complete a response on the thread that read it. `rt::RtClient` already ran
HTTP/1.1 on simoom-rt loops with completion callbacks; this adds HTTP/2 to it.

## Design

Code: `crates/simoom-client/src/rt/h2.rs` (the connection, the per-loop pool, calls) and
`crates/simoom-client/src/rt.rs` (routing, the connector thread, the public API).

**Where a connection lives.** Each loop keeps, per (client, origin), up to
`RtConfig::h2_connections` HTTP/2 connections (default 1) in a thread-local pool. A connection is
an `H2Conn`: a `simoom_rt::Connection` that owns the engine, its TLS session, its streams and
their timers. Nothing about it is shared with another thread, so there is no lock.

**Submitting from any thread.** `RtClient::send` picks a loop (round robin, or the current loop
when called from one of the client's callbacks) and queues a task on it: one lock-free push, and
a signal only when the loop is parked (`Waker::post`). On the loop the task appends the request to
the least loaded pooled connection's queue (opening a connection when none is idle and fewer than
`h2_connections` exist) and sends that connection one `Kick` message per batch. The connection
opens a stream for every queued request the peer allows and writes their frames in one write.

**Submitting from a callback.** A request sent from a callback that runs on one of the client's
HTTP/2 connections (the closed loop of a producer: a response arrives, the next request goes out)
goes to a thread-local outbox instead. The connection routes the outbox when its callback returns
and before it writes, so the next request leaves in the same write as everything else of that
turn: no task, no kick, no second loop turn.

**Completing.** Received bytes go through TLS and the engine in `on_data`. Heads, body bytes and
trailers go to the stream: a unary request collects its response (`RtResponse`, with redirects and
decompression as on HTTP/1.1) and its callback runs as soon as the stream ends; a call hands each
event to its `CallHandler`. All of it on the loop thread that read the bytes.

**Opening connections.** Name resolution, TCP connect and proxy tunnels (HTTP `CONNECT` or SOCKS5)
run on the client's connector thread, as for HTTP/1.1; the socket is then adopted by the loop
that asked. TLS runs on the loop with ALPN `h2` only and certificate verification always on (the
client has no way to turn it off); a server that does not select `h2` fails the request with
`ErrorKind::Unsupported`. Plain `http` is h2c with prior knowledge.

### What the blocking client gets right, kept

| property | how |
|---|---|
| concurrent-stream limit | streams open only while `can_open_stream`; the rest wait in the entry's queue (FIFO) and open as streams finish. The peer's limit, as last seen, steers new work to other pooled connections |
| flow control, receiving | body bytes are released right after delivery; with `CallOptions::manual_release` only through `RtCall::release`, so a slow consumer holds the server back |
| flow control, sending | request bodies go to the engine as its windows allow, and only while less than 512 KiB is queued on the socket (`SEND_HIGH`; `on_drain` resumes). For calls, bytes not yet taken are visible as `RtCall::buffered`, `is_full` past `CallOptions::high_water`, and `CallHandler::on_writable` fires at half of it |
| GOAWAY | the connection leaves the pool, its queued requests move to another (new) connection, its open streams below the last stream finish, then it closes |
| refused streams | REFUSED_STREAM, or a stream above GOAWAY's last stream, is sent again elsewhere, at most three attempts, when it can be (a unary request; a call whose streamed body has not started) |
| RST_STREAM, cancellation | a reset fails the request with `ErrorKind::Reset(code)`, except a complete response followed by a reset (RFC 9113 §8.1), which is kept; `RtCall::cancel` sends RST_STREAM(CANCEL) and ends the call with `ErrorKind::Cancelled` |
| deadlines | a timer per stream (`RtConfig::timeout`, `CallOptions::timeout`) resets it with CANCEL; queued requests time out from the queue |
| lost connections | streams in flight fail; requests still queued (never sent) are retried on a new connection |
| keepalive | the engine's PING keepalive (`RtConfig::h2.keepalive_interval_ms`) runs on the loop's timer; an unanswered PING closes the connection |
| streamed bodies, full duplex, trailers | `RtClient::call`: the head and first bytes leave at once, `RtCall::send`/`finish`/`finish_with_trailers` from any thread, the response through `CallHandler` as it arrives |

### API

```rust
use simoom_client::rt::{CallHandler, CallOptions, RtClient, RtConfig, RtRequest};
use simoom_client::{Headers, HttpVersion, Result};

let client = RtClient::spawn(4, RtConfig { version: HttpVersion::Http2, ..RtConfig::default() })?;
// unary: the callback runs on the loop that read the response
client.send(RtRequest::get("http://127.0.0.1:8080/hello")?, |r| println!("{:?}", r.map(|r| r.status)));

// a call: streamed request body, streamed response, trailers both ways
struct Print;
impl CallHandler for Print {
    fn on_data(&mut self, data: &[u8]) { println!("{} bytes", data.len()); }
    fn on_end(&mut self, r: Result<Headers>) { println!("end {:?}", r.map(|t| t.get("grpc-status").map(str::to_string))); }
}
let call = client.call(RtRequest::new("POST", "http://127.0.0.1:8080/svc/Echo")?, CallOptions::default(), Print);
call.send(b"message".to_vec());
call.finish_with_trailers(&[("x-sum", "1")]);
```

`send_request` and `send_streaming` take the loop path too for HTTP/2 with a request body in
memory; HTTP/3 and streamed `Body::Reader` bodies still run on the worker threads through the
blocking engine.

## Tests

`crates/simoom-client/tests/rt_h2.rs` (18 tests, embedded servers only: simoom's own server and a
scripted `simoom-h2` server on loopback): h2c multiplexing and one connection per loop; several
connections per loop; resubmitting from callbacks on the loop; TLS with ALPN `h2` and verification
always on (an untrusted certificate fails); a TLS server without `h2` refused; the stream limit
(peak exactly the server's limit of 2, nothing refused); 3 MB down and a 4 MB streamed upload;
manual release holding the server to its window; refused streams retried, GOAWAY after each
response (a new connection each time) and GOAWAY with streams in flight (those above the last
stream retried on a new connection); RST_STREAM and the kept early answer; cancellation
(RST_STREAM CANCEL at the server); deadlines (unary and call); streamed responses and trailers;
a full-duplex echo with trailers both ways; a full send buffer and `on_writable`; keepalive closing
a dead connection; a lost connection and a refused connect; redirects.

## Measurements

WSL2 Ubuntu 24.04, 12 logical CPUs, the Windows host checked idle (about 12% CPU) before the run.
Peer: simoom's `bench_server` (fixed 13-byte reply, h2c) on CPUs 0-3; client on CPUs 4-11.
`client_bench` (`crates/simoom-client/examples/client_bench.rs`), 64 requests in flight over 4
HTTP/2 connections, 10 s per run, three rounds with the variants interleaved, each run under
`perf stat` (context switches, migrations, syscall tracepoints). CPU is the client process's
user + system time from `/proc/self/stat` divided by requests. Script and raw output:
`side-session-notes/.../h2-client-bench/run.sh` and `results-1.txt` (outside the repository).

| client | req/s (3 rounds) | CPU us/req | user / sys | ctx switches/req | futex/req | send+recv syscalls/req |
|---|---:|---:|---|---:|---:|---:|
| blocking `Client`, 64 threads (today) | 88,215 / 89,445 / 87,666 | 36.2 / 36.4 / 36.7 | 9.0 / 27.5 | 1.05 | 2.06 | 0.74 |
| `RtClient` HTTP/2, async caller (callback sends the next) | 605,801 / 512,845 / 513,573 | 3.2 / 4.7 / 4.8 | 2.4 / 2.3 | 0.06 | 0.00 | 0.12 |
| same, without the callback outbox | 470,150 / 458,477 / 466,639 | 5.2 / 5.4 / 5.3 | 2.8 / 2.5 | 0.06 | 0.00 | 0.12 |
| blocking facade over `RtClient` (64 threads park, the loop unparks) | 235,963 / 212,074 / 239,060 | 24.1 / 26.8 / 23.9 | 6.7 / 18.2 | 1.07 | 2.02 | 0.36 |
| control: blocking `Client` over HTTP/1.1, 64 connections | 254,172 / 245,027 / 249,200 | 22.7 / 23.6 / 23.4 | 4.6 / 18.6 | 1.05 | 0.00 | 2.00 |

The baseline is reproduced: the blocking client costs 36 us per request, as in Cameleer's round.

- **Async caller: 7.6x less CPU per request, 5.8x the requests per second.** A response completes
  on the loop that read it and the next request leaves in the same write: 0.06 context switches
  and no futex per request, about one `sendto` and one `recvfrom` per eight requests (a loop turn
  carries several streams' frames). The callback outbox is worth 10% of the CPU and 12% of the
  throughput (0.09 against 0.22 `epoll_wait` per request: the resubmitted request no longer
  waits two extra loop turns for its task and its kick).
- **Blocking facade: 1.5x less CPU, 2.6x the throughput of today's blocking client**, at the cost
  of the HTTP/1.1 control (24 against 23 us). The one wake per request remains (about 1 context
  switch and 2 futex calls: the caller's park and the loop's unpark), but the pump thread, the
  `State` mutex, the per-stream condition variables and the contended opener are gone, and writes
  are batched by the loop (0.24 `sendto` per request against 0.72).
- The blocking client is not CPU-bound at 64 threads (3 CPUs busy): its throughput is held by the
  hand-off latency, which the facade halves.
- Against the hand-written HTTP/1.1 client of Cameleer's round (16 us): the async path is far
  below it; the facade is above it by the cost of the wake and of a general library.

For Cameleer, whose routing engine is synchronous (`spi::Processor::process`), the facade is what
an HTTP/2 producer gets without engine changes (24 against 36 us); an asynchronous producer path
would bring it to about 5 us per request, which is the measured value of an `AsyncProcessor`.

## Should the blocking `Client` become a facade over it?

**Yes, for HTTP/2**, on these numbers: the facade is cheaper on every count the blocking engine
pays for (1.5x CPU, 2.6x throughput at 64 in flight), it keeps the single wake a blocking API
needs and nothing more, and it would retire `Mux`'s pump thread and its locking for HTTP/2. Not
done on this branch, because `Client` exposes more than unary calls over HTTP/2 and each needs its
own piece on the loop side first:

1. **Streamed response bodies** (`ResponseBody::read_chunk`, `Call::read`): a `CallHandler` that
   fills a bounded per-stream buffer and wakes the reader, with `manual_release` so credit returns
   as the caller reads (flow control stays end to end, as `Mux`'s `SLOT_CAP` does today).
2. **Streamed request bodies** (`Body::Reader`): the caller's thread reads its `Read` and sends
   through `RtCall::send`, waiting on `on_writable` when `is_full`.
3. **`Call`/`CallSender`** on top of 1 and 2; `call_with_body` maps to `RtClient::call` with the
   first bytes.
4. **Pool and lifecycle**: `Client` owns an `RtClient` with its own loops (spawned on first HTTP/2
   use; one or two loops are enough for a client), `PoolStats` and the keepalive come from the loop
   pool, extended CONNECT for WebSocket over HTTP/2 needs `send_extended_connect` on the loop
   connection, and h2c through `Upgrade` adopts its stream 1 there.
5. **The waiter**: today's facade prototype uses `thread::park` plus a mutex slot (2 futex calls per
   request); a one-shot slot with an atomic state and park/unpark is the cheapest blocking hand-off
   std offers.

HTTP/3 stays on `Mux` until a QUIC endpoint runs on the loops. Each step is measured against the
current engine with this benchmark before the old path goes.
