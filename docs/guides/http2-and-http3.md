# How do I serve HTTP/2 and HTTP/3 with simoom?

> HTTP/2 is on by default (h2c on plain listeners, ALPN over TLS); for HTTP/3 build with `full` and add `listen_quic` with `quic_tls` on the same port number.

Your services don't change between protocols: the same `Request` and `Reply` work on HTTP/1.1,
HTTP/2 and HTTP/3. What changes is which listeners you open and a few limits.

## One server, every protocol

```rust
use simoom::tls::{certgen, CertifiedKey, ServerConfig};
use simoom::{Reply, Request, Server, Version};

fn main() {
    let cert = certgen::self_signed("localhost");
    let key = CertifiedKey::from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).unwrap();
    let tls = ServerConfig::new(key);

    let server = Server::builder()
        .listen("0.0.0.0:8080") // HTTP/1.1 and h2c
        .listen_tls("0.0.0.0:8443") // HTTP/1.1 and HTTP/2, chosen by ALPN
        .tls(tls.clone())
        .listen_quic("0.0.0.0:8443") // HTTP/3 on the same port number, over UDP
        .quic_tls(tls)
        .service(|req: &mut Request<'_>, r: Reply<'_>| {
            let v = match req.version() {
                Version::H3 => "HTTP/3",
                Version::H2 => "HTTP/2",
                _ => "HTTP/1.x",
            };
            r.body(format!("you came over {v}\n"))
        })
        .start()
        .unwrap();
    println!("TCP {:?}, UDP {:?}", server.local_addrs(), server.quic_addrs());
    server.join();
}
```

Build it with `--features full` (or `tls` and `http3`). Then:

```sh
curl --http2-prior-knowledge http://localhost:8080/   # h2c
curl -k --http2 https://localhost:8443/                # h2 over TLS
curl -k --http3-only https://localhost:8443/           # HTTP/3, with a curl built for it
```

## HTTP/2

With the default `http2` feature, simoom speaks HTTP/2 three ways:

- **h2c with prior knowledge** on plain listeners: the client starts with the HTTP/2 preface.
  This is the recommended protocol between a proxy and simoom, since it has none of HTTP/1.1's
  framing ambiguities.
- **`Upgrade: h2c`** from an HTTP/1.1 request on plain listeners.
- **h2 over TLS**, chosen in the handshake (ALPN).

`Builder::http2(false)` turns it off for one server. h2spec 2.6.0 passes 146 of 146 tests
([SECURITY.md](../SECURITY.md)).

## HTTP/3

HTTP/3 runs over QUIC on UDP. `listen_quic(addr)` opens a UDP listener, and `quic_tls(config)`
gives it a TLS configuration (its ALPN becomes `h3`). It is usual to use the same port number as
the TLS listener, since TCP and UDP ports are separate.

Browsers find HTTP/3 through the **`alt-svc`** header: once a QUIC listener is open, HTTP/1.1 and
HTTP/2 responses carry `alt-svc: h3=":<port>"; ma=86400`, and the browser switches on a later
request. If a load balancer forwards UDP on another public port, set the value yourself with
`Builder::alt_svc`.

What simoom's QUIC does not do in 0.1.0:

- **No 0-RTT**, by design (early data can be replayed).
- **No ECN** and **no migration to a preferred address**.
- It is a transport for HTTP/3, not a general QUIC library: there are no raw QUIC streams in the
  `simoom` API.

In the QUIC Interop Runner, simoom passes 54 of 58 supported pairs against the ngtcp2, quiche and
quic-go clients; the four failures are 0-RTT and ECN.

## Tuning

```rust
use simoom::{FrameBudgets, Limits, Server};
use std::time::Duration;

fn build() -> simoom::Builder {
    Server::builder()
        .listen("127.0.0.1:8080")
        .http2(false) // HTTP/1.1 only on this server
        .alt_svc(r#"h3=":443"; ma=3600"#) // when a load balancer owns the UDP port
        .limits(Limits {
            max_concurrent_streams: 250,
            h2_frame_budgets: FrameBudgets { ping: 50, ..FrameBudgets::default() },
            h2_keepalive: Some(Duration::from_secs(30)), // feature h2-keepalive
            ..Limits::default()
        })
        .quic_config(|c| c.retry = true) // always validate client addresses with Retry
}
```

| setting | default | what it does |
|---|---|---|
| `Limits::max_concurrent_streams` | 100 | streams per connection whose handler is still running; more get `REFUSED_STREAM` |
| `Limits::max_header_list` | 16 KiB | the decoded header block of one request |
| `Limits::header_table_size` | 4096 | the HPACK and QPACK dynamic table |
| `Limits::h2_frame_budgets` | see [Limits and security](limits-and-security.md) | caps RST_STREAM, PING, SETTINGS and other frame floods |
| `Limits::h2_keepalive` | off | PINGs idle clients to find ones that vanished (feature `h2-keepalive`) |
| `Builder::quic_config` | | QUIC transport settings: Retry, connection caps, versions |
| `Builder::quic_gro(false)` | on | turns off UDP receive batching on Linux |

`max_concurrent_streams` counts streams whose handler is still working, not just open streams, so
resetting streams can't free capacity while work continues. That is the defence against Rapid
Reset (CVE-2023-44487) and MadeYouReset (CVE-2025-8671).

## Common questions

### Can I serve HTTP/3 from Rust without quinn, rustls or OpenSSL?

Yes. simoom implements QUIC v1, HTTP/3, QPACK and TLS 1.3 itself, and HTTP/3 is a cargo feature
of the same server that serves HTTP/1.1 and HTTP/2.

### Do I need a certificate for HTTP/3?

Yes. QUIC always uses TLS 1.3, so `listen_quic` needs `quic_tls`; starting without one is an
error.

### Why do browsers keep using HTTP/2 the first time?

Browsers learn about HTTP/3 from the `alt-svc` header of an earlier response, then switch. Also
check that UDP on that port is open in your firewall.

### Does HTTP/3 change my handlers?

No. `req.version()` tells you the protocol if you want to know; everything else is the same,
including streaming and server-sent events. WebSocket over HTTP/3 needs the `websocket-h3`
feature.
