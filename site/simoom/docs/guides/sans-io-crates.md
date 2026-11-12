# Can I use simoom's protocol crates in my own I/O loop?

> Yes: simoom's HTTP/1.1, HTTP/2, QUIC, HTTP/3 and TLS crates are sans-io; they take bytes and time, return bytes and events, and never touch sockets.

simoom's protocols are separate crates that know nothing about sockets, threads or clocks. The
`simoom` server is one way to drive them; your own event loop, a test harness, a simulator or an
embedded runtime can be another.

## The crates

| crate | what it does |
|---|---|
| `simoom-http1` | strict HTTP/1.1 parser and serializer (RFC 9112): zero-copy request and response heads, body decoder, chunked encoder, the WebSocket frame codec |
| `simoom-hpack` | HPACK header compression (RFC 7541) |
| `simoom-h2` | HTTP/2 connection engine (RFC 9113) with flow control and flood accounting |
| `simoom-tls` | TLS 1.3 server and client, X.509, the QUIC handshake interface (RFC 9001); TLS 1.2 behind `tls12` |
| `simoom-quic` | QUIC v1 transport (RFC 9000, 9002), v2 optional |
| `simoom-qpack` | QPACK header compression (RFC 9204) |
| `simoom-h3` | HTTP/3 (RFC 9114) on top of `simoom-quic` streams |
| `simoom-compress` | DEFLATE, zlib, gzip, Brotli and zstd, streaming and bounded |

Each is published on crates.io at 0.1.0 and has no dependencies outside simoom's own crates.
The only `unsafe` code is in `simoom-sys`, which some of them use for SIMD scanning and hardware
crypto.

## The pattern

Every crate works the same way:

1. you read bytes from wherever they come from and hand them in, with the current time where
   timers matter;
2. the crate returns events (a request head, data, a reset) and how many bytes it consumed;
3. you take the bytes it wants to send and write them yourself, then tell it how many went out.

Nothing is hidden: no background thread, no clock read, no allocation you can't bound with a
limit.

## Parsing HTTP/1.1

`parse_request` parses a request head into header storage you provide, without allocating. It
returns `Partial` until the head is complete, and enforces limits on partial input too:

```rust
use simoom_http1::{parse_request, Limits, Status, EMPTY_HEADER};

fn parse() {
    let input = b"GET /hello?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: demo\r\n\r\n";
    let mut headers = [EMPTY_HEADER; 32];
    match parse_request(input, &mut headers, &Limits::default()) {
        Ok(Status::Complete(req)) => {
            assert_eq!(req.method, b"GET");
            assert_eq!(req.target, b"/hello?x=1");
            assert_eq!(req.host, Some(&b"example.com"[..]));
            assert_eq!(req.head_len, input.len()); // the next request starts here
        }
        Ok(Status::Partial) => { /* read more bytes and call again */ }
        Err(e) => eprintln!("refused: {e:?}"), // answer 400 and close
    }
}
```

The parsed head also tells you how the body is framed (`req.framing`), whether the connection can
be kept alive, and whether the client expects `100 Continue`. `BodyDecoder` then reads
Content-Length, chunked or close-delimited bodies incrementally. `RequestParser` avoids parsing
the same bytes again when a head arrives in many small pieces.

## Driving HTTP/2

A `simoom_h2::Connection` takes received bytes and calls you back with events; its output buffer
holds the bytes to send:

```rust
use simoom_h2::{Config, Connection, Event};

fn exchange() {
    let mut server = Connection::server(Config::default());
    let mut client = Connection::client(Config::default());
    let id = client.send_request(b"GET", b"https", b"example.com", b"/", &[], true).unwrap();

    // move the client's bytes to the server (your socket does this)
    let c2s = client.output().to_vec();
    client.advance_output(c2s.len());
    let mut request = None;
    let used = server.recv(&c2s, 0, &mut |ev| {
        if let Event::Headers { stream, headers, .. } = ev {
            request = Some((stream, headers.path().unwrap().to_vec()));
        }
    });
    assert_eq!(used, c2s.len()); // keep unconsumed bytes for the next call
    let (stream, _path) = request.unwrap();

    server.send_response(stream, 200, &[(b"content-type", b"text/plain")], false).unwrap();
    server.send_data(stream, b"hello", true).unwrap();
    server.stream_finished(stream);
    let s2c = server.output().to_vec();
    server.advance_output(s2c.len());
    // ... and back to the client
}
```

Things the engine leaves to you, on purpose:

- **Flow control.** Received data stays charged to the windows until you call
  `Connection::release`, which bounds what a stream can buffer. `send_data` accepts only what the
  windows allow and reports the rest as backpressure.
- **Handler accounting.** The concurrency limit counts streams whose handler is still running.
  Call `stream_finished` when your handler is done; that is what defeats Rapid Reset and
  MadeYouReset.

## QUIC, HTTP/3 and TLS

- `simoom_quic::Endpoint` takes datagrams, the time and the peer address, and returns datagrams to
  send, the next deadline and per-connection events.
- `simoom_h3::Http3` owns the HTTP/3 state of one QUIC connection: feed it that connection's
  events, then drain its events and answer requests with `send_headers` and `send_body`.
- `simoom_tls::ServerConnection` and `ClientConnection` take TLS records and return plaintext and
  records to send; the `simoom-tls` crate documentation has a complete in-memory handshake.

The API reference for each crate is on docs.rs: [simoom-http1](https://docs.rs/simoom-http1),
[simoom-h2](https://docs.rs/simoom-h2), [simoom-quic](https://docs.rs/simoom-quic),
[simoom-h3](https://docs.rs/simoom-h3), [simoom-tls](https://docs.rs/simoom-tls).

## Common questions

### Why sans-io?

It lets the protocol logic be tested in memory, without a network or a clock. It also lets the same code serve several I/O models; simoom drives the crates from epoll,
io_uring, IOCP and kqueue loops, and the client drives them from blocking sockets.

### Can I use simoom-tls on its own?

Yes. It is a complete TLS 1.3 server and client over any byte stream, with a `blocking` feature
that wraps a `Read + Write` stream. Like the rest of simoom, it has not been independently audited.

### Is the QUIC crate a general-purpose QUIC library?

It was written to carry HTTP/3, so its API follows that need. It has no 0-RTT and no ECN. For raw
QUIC streams in production, quinn or s2n-quic are more established.

### Do I need the `simoom` crate to use them?

No. Each protocol crate stands alone; add only the ones you drive.
