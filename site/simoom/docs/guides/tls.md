# How do I serve HTTPS with simoom?

> Turn on the `tls` feature, load your certificate into a `ServerConfig`, and call `listen_tls` and `tls`; simoom does TLS 1.3 itself, with no OpenSSL.

simoom has its own TLS 1.3 implementation, with its own cryptography, in the `simoom-tls` crate.
There is nothing to install and nothing to link. This page covers certificates, several names on
one server, rotation without restart, and client certificates.

## Turn it on

```toml
simoom = { version = "0.1", features = ["tls"] }   # or "full" for TLS and HTTP/3
```

`tls` supports X25519 and P-256 key exchange, ECDSA P-256 and RSA certificates, and AES-GCM.
`tls-extra` adds P-384 and Ed25519 certificates and ChaCha20-Poly1305.

## A self-signed certificate for local testing

`simoom::tls::certgen` makes certificates for tests:

```rust
use simoom::tls::{certgen, ServerConfig, CertifiedKey};
use simoom::{Reply, Request, Server};

fn main() {
    let cert = certgen::self_signed("localhost");
    let key = CertifiedKey::from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("certificate and key");
    let server = Server::builder()
        .listen_tls("127.0.0.1:8443")
        .tls(ServerConfig::new(key))
        .service(|_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"Hello over TLS"))
        .start()
        .unwrap();
    server.join();
}
```

`curl -k https://localhost:8443/` connects (`-k` because the certificate is self-signed). The
`localhost` certificate also covers `127.0.0.1` and `::1`.

## Your own certificate

Load a PEM chain and key, for example from Let's Encrypt. Keys in PKCS#8, SEC1 or PKCS#1 form
work. Plain and TLS listeners can live on one server:

```rust
use simoom::tls::ServerConfig;
use simoom::{Reply, Request, Server};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = std::fs::read("/etc/simoom/fullchain.pem")?;
    let key = std::fs::read("/etc/simoom/privkey.pem")?;
    let tls = ServerConfig::from_pem(&cert, &key).map_err(|e| format!("{e:?}"))?;

    let server = Server::builder()
        .listen("0.0.0.0:80") // plain HTTP on one port
        .listen_tls("0.0.0.0:443") // TLS on another
        .tls(tls)
        .service(|req: &mut Request<'_>, r: Reply<'_>| r.body(format!("secure: {}", req.is_secure())))
        .start()?;
    server.join();
    Ok(())
}
```

On a TLS listener, client and server agree on HTTP/2 or HTTP/1.1 during the handshake (ALPN).
`Builder::tls` sets the ALPN list for you. For HTTP/3, see [HTTP/2 and HTTP/3](http2-and-http3.md).

## Several names on one server

`add_sni_cert` adds a certificate that is chosen when the client asks for one of its names (SNI),
wildcards included. Clients asking for other names get the default certificate:

```rust
use simoom::tls::{CertifiedKey, ServerConfig};

fn config(a: CertifiedKey, b: CertifiedKey) -> ServerConfig {
    let mut tls = ServerConfig::new(a); // the default certificate
    tls.add_sni_cert(b); // chosen when the client asks for one of its names
    tls
}
```

Set `tls.strict_sni = true` to refuse clients whose name matches no certificate.

## Rotating certificates without a restart

`ServerHandle::set_tls` swaps the configuration. New connections use it; open ones keep theirs:

```rust
use simoom::tls::ServerConfig;
use simoom::ServerHandle;

fn reload(server: &ServerHandle) -> Result<(), Box<dyn std::error::Error>> {
    let cert = std::fs::read("/etc/simoom/fullchain.pem")?;
    let key = std::fs::read("/etc/simoom/privkey.pem")?;
    let tls = ServerConfig::from_pem(&cert, &key).map_err(|e| format!("{e:?}"))?;
    server.set_tls(tls)?; // new connections use it; open ones keep theirs
    Ok(())
}
```

`set_quic_tls` does the same for HTTP/3. Session tickets issued before the swap resume only if
the new configuration shares the old one's `ticketer`.

## Client certificates (mutual TLS)

Require or request client certificates with `ServerConfig::client_auth`. The `ClientAuth` and
`RootStore` types live in `simoom-tls`, which `simoom` doesn't re-export in 0.1.0, so add it
next to simoom (`cargo add simoom-tls`, same version):

```rust
use simoom::tls::ServerConfig;
use simoom::{Outcome, Reply, Request};
use simoom_tls::x509::RootStore;
use simoom_tls::ClientAuth;

fn config(mut tls: ServerConfig) -> Result<ServerConfig, String> {
    let mut roots = RootStore::empty();
    roots.add_pem_file("/etc/simoom/client-ca.pem")?;
    tls.client_auth = ClientAuth::Required(roots);
    Ok(tls)
}

fn whoami(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    match req.tls() {
        Some(info) if !info.peer_certificates().is_empty() => {
            reply.body(format!("client certificate of {} bytes, {}", info.peer_certificates()[0].len(), info.cipher_suite_name()))
        }
        _ => reply.status(401).empty(),
    }
}
```

`ClientAuth::Optional(roots)` asks for a certificate but accepts clients without one; the ones
that send one are still verified. `req.tls()` also gives the protocol version, cipher suite, the
SNI name and the negotiated ALPN protocol.

## What simoom's TLS does and doesn't do

- **TLS 1.3 only** on simoom servers. TLS 1.2 exists in `simoom-tls` behind its `tls12` feature,
  but simoom's features don't turn it on. Clients that only speak TLS 1.2 fail the handshake.
- **0-RTT is never accepted**, by design: early data can be replayed.
- **Session resumption** with tickets is on by default, with rotating keys.
- **Constant-time crypto**: hardware AES-GCM where the CPU has it, a bitsliced fallback elsewhere,
  constant-time comparison of secrets.
- **The handshake deadline** is `Limits::head_timeout` (10 s by default).
- **Not independently audited yet.** The TLS stack passed testssl.sh and interop with OpenSSL,
  curl, Python, GnuTLS and Schannel ([SECURITY.md](../SECURITY.md)), but no outside firm has
  audited it. If your rules require an audited stack, terminate TLS in front of simoom.

## Common questions

### Do I need OpenSSL, a C compiler or cmake?

No. simoom's TLS and cryptography are Rust code in the repository, so cross-compiling for another
target needs only the Rust target.

### Can I use rustls or OpenSSL instead?

Not inside simoom's listeners. You can put a TLS terminator (nginx, haproxy, a cloud load
balancer) in front of a plain simoom listener; HTTP/2 with prior knowledge (h2c) is a good
protocol between them.

### How do I redirect HTTP to HTTPS?

Listen on both ports and answer plain requests with a redirect:
`if !req.is_secure() { return r.status(308).header("location", url).empty(); }`.

### Does TLS make start-up slower?

A little. In the committed measurements, the first answer came 0.87 ms after start with TLS
against 0.73 ms without ([benchmarks](https://cameleer.ing/simoom/benchmarks/)).
