# How do I make HTTP requests with simoom-client?

> `simoom-client` is a blocking HTTP/1.1, HTTP/2 and HTTP/3 client with pooling, TLS, redirects and WebSocket; add it with `cargo add simoom-client`.

The client is a separate crate, so a server that never makes requests doesn't compile it. Like
the server, it uses only the standard library and needs no async runtime: requests run on the
calling thread, and HTTP/2 and HTTP/3 connections are shared between threads.

```sh
cargo add simoom-client
```

The default features give HTTP/1.1, HTTP/2, WebSocket, TLS and gzip/deflate decoding. HTTP/3 needs
`client-h3`; `full` turns on everything (cookies, auth, multipart, retries, proxies over SOCKS...).

## A first request

```rust
use simoom_client::Client;

fn main() -> simoom_client::Result<()> {
    let client = Client::new();
    let resp = client.get("https://example.com/").send()?;
    println!("{} {}", resp.status(), resp.header("content-type").unwrap_or(""));
    let text = resp.text()?;
    println!("{} characters", text.len());
    Ok(())
}
```

Create one `Client` and reuse it: it pools connections per origin. Clone it to use the same pool
from other threads.

## Settings, bodies and versions

```rust
use simoom_client::{Client, HttpVersion};
use std::time::Duration;

fn run() -> simoom_client::Result<()> {
    let client = Client::builder()
        .connect_timeout(Some(Duration::from_secs(5)))
        .timeout(Some(Duration::from_secs(30)))
        .follow_redirects(true)
        .user_agent(Some("my-tool/1.0".into()))
        .build();

    let resp = client
        .post("http://127.0.0.1:8080/orders")
        .header("Content-Type", "application/json")
        .body(r#"{"sku":"A-1","qty":2}"#)
        .version(HttpVersion::Http2) // h2c with prior knowledge
        .timeout(Duration::from_secs(10))
        .send()?;
    println!("{}", resp.status());

    let resp = client.get("https://api.example.com/items").query("page", "2").bearer_auth("token").send()?;
    let bytes = resp.bytes()?;
    Ok(())
}
```

- **Versions.** `HttpVersion::Auto` (the default) uses HTTP/1.1 for `http://` and lets the TLS
  handshake choose HTTP/2 or HTTP/1.1 for `https://`. `Http1`, `Http2` and `Http3` force one.
  With `client-h3` and `.alt_svc(true)` on the builder, an origin that announces HTTP/3 is
  reached over HTTP/3 next time.
- **Timeouts.** Connect, TLS handshake, response head, idle read, write, the whole request and
  the wait for a pooled connection each have a setting.
- **Redirects** are off by default; `follow_redirects(true)` turns them on, with credentials
  stripped across origins.
- **Status checks.** By default any status is a response. `.ok_status(&[(200, 299)])` on a
  request (or the builder) makes other statuses an error.

## Streaming both ways

```rust
use simoom_client::{Body, Client};
use std::fs::File;

fn run(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    // upload a file without loading it into memory (chunked: length unknown)
    let file = File::open("big.log")?;
    let resp = client.put("http://127.0.0.1:8080/upload").body(Body::reader(file)).send()?;

    // read a large response piece by piece
    let mut resp = client.get("http://127.0.0.1:8080/export").send()?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = resp.body_mut().read_chunk(&mut buf)?;
        if n == 0 {
            break;
        }
        // handle buf[..n]
    }
    Ok(())
}
```

`Body::sized_reader(r, len)` sends a known length instead of chunked.

## TLS

Certificate verification is always on, against the system's trust store by default. To trust a
self-signed server, such as a simoom test server made with `certgen`, add its certificate:

```rust
use simoom_client::tls::RootStore;
use simoom_client::Client;

fn client_for_local_tls(cert_pem: &[u8]) -> Result<Client, String> {
    let mut roots = RootStore::empty();
    roots.add_pem(cert_pem)?;
    Ok(Client::builder().roots(roots).build())
}
```

`ClientBuilder::tls(TlsOptions { .. })` also sets a client certificate for mutual TLS, an SNI name
override, and session resumption.

## WebSocket

```rust
use simoom_client::{Client, Message};

fn run() -> simoom_client::Result<()> {
    let client = Client::new();
    let ws = client.websocket("ws://127.0.0.1:8080/ws").connect()?;
    ws.send_text("hello")?;
    match ws.recv()? {
        Message::Text(t) => println!("got {t}"),
        Message::Close(code, reason) => println!("closed: {code:?} {reason}"),
        _ => {}
    }
    ws.close(1000, "bye", std::time::Duration::from_secs(1))?;
    Ok(())
}
```

`wss://` works with TLS. The builder offers subprotocols, extra headers, message limits, and
WebSocket over HTTP/2 or HTTP/3.

## Optional features

| feature | adds |
|---|---|
| `client-h3` | HTTP/3 over QUIC |
| `tls-extra` | P-384 and Ed25519 certificates, ChaCha20-Poly1305 |
| `cookies` | a cookie jar |
| `auth`, `auth-digest`, `auth-ntlm` | Basic and Bearer challenges, Digest, NTLMv2 |
| `multipart`, `encode` | `multipart/form-data`, form bodies and compressed request bodies |
| `retry`, `happy-eyeballs`, `dns-timeout`, `socks` | retries with backoff, address racing, a resolver timeout, SOCKS5 proxies |
| `rt` | a non-blocking client on simoom's event loops, with completion callbacks |
| `full` | all of the above |

HTTP proxies (`CONNECT` tunnels, the `*_PROXY` environment variables, `NO_PROXY`) work with the
default features.

## Common questions

### Is it async?

No. `send()` blocks the calling thread until the response head arrives; the body is read as you
ask for it. Inside a simoom service, call the client from the offload pool or your own thread,
never on the loop thread ([Slow work](slow-work.md)).

### Can I turn off certificate verification?

No. Add the server's certificate or its CA to a `RootStore` instead.

### Does it follow redirects?

Only when you turn it on with `follow_redirects(true)`, on the builder or per request.

### How does it compare with reqwest or ureq?

It is closest to ureq in shape (blocking, no runtime) and adds HTTP/2, HTTP/3 and WebSocket with
no dependencies outside the standard library. reqwest has a much larger ecosystem and an async API.
