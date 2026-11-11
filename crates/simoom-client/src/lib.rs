//! simoom-client: a std-only HTTP/1.1, HTTP/2 and HTTP/3 client and WebSocket client.
//!
//! Built on simoom's sans-io protocol crates (simoom-http1, simoom-h2, simoom-quic +
//! simoom-h3, simoom-tls). No async runtime: the blocking [`Client`] runs requests on the
//! caller's threads, and HTTP/2 and HTTP/3 connections are shared between threads (a reader
//! thread runs only while several streams are in flight). With the `rt` feature,
//! `rt::RtClient` (feature `rt`) runs requests on simoom-rt event loops instead, with completion callbacks.
//!
//! ```no_run
//! use simoom_client::Client;
//! use std::time::Duration;
//!
//! let client = Client::builder().connect_timeout(Some(Duration::from_secs(5))).follow_redirects(true).build();
//! let resp = client.post("http://127.0.0.1:8080/orders").header("Content-Type", "application/json").body("{}").send().unwrap();
//! assert_eq!(resp.status(), 200);
//! let body = resp.bytes().unwrap();
//! # let _ = body;
//! ```
//!
//! # What it does
//!
//! - **Pooling** per origin: idle HTTP/1.1 connections (cap, idle timeout, reuse limit, stale
//!   connections detected and retried once), one multiplexed HTTP/2 or HTTP/3 connection per
//!   origin by default, opened again when it goes away.
//! - **Protocol choice**: [`HttpVersion`]: HTTP/1.1, ALPN `h2`/`http/1.1`, h2c with prior
//!   knowledge, HTTP/3 forced or through `Alt-Svc` with fallback to TCP.
//! - **TLS** through simoom-tls: SNI, ALPN, verification always on, a custom root store, client
//!   certificates, session resumption.
//! - **Proxies**: `CONNECT` tunnels with Basic credentials, absolute-form requests for plain
//!   HTTP, `NO_PROXY` lists with CIDR ranges, the `*_PROXY` environment variables.
//! - **Streaming** both ways with backpressure: [`Body::Reader`] (chunked when the length is
//!   unknown), `Expect: 100-continue`, [`ResponseBody`] reads as the caller asks, trailers both
//!   ways; full-duplex [`Client::call`] on HTTP/2 and HTTP/3.
//! - **Timeouts**: connect, TLS, response head, idle read, write, whole request, pool wait.
//! - **Redirects** (opt-in, as in Camel) with method rewriting and credential stripping across
//!   origins; status checks with Camel's `okStatusCodeRange` semantics ([`StatusError`]).
//! - **Decompression** through a pluggable [`decode::ContentDecoder`].
//! - **HTTP/2 PING keepalive** on idle pooled connections.
//! - **WebSocket client** (`client-ws`): [`WebSocket`], over HTTP/1.1 or HTTP/2 (RFC 8441).
//!
//! # Cargo features
//!
//! | feature | adds |
//! |---|---|
//! | `client-h1` (default) | HTTP/1.1 |
//! | `client-h2` (default) | HTTP/2 (h2c and h2) |
//! | `client-ws` (default) | the WebSocket client |
//! | `tls` (default) | `https` and `wss` (TLS 1.3: X25519, P-256, RSA, AES-GCM) |
//! | `tls-extra` | P-384 and Ed25519 certificates, ChaCha20-Poly1305 |
//! | `client-h3` | HTTP/3 over QUIC |
//! | `rt` | `rt::RtClient`, the non-blocking client on simoom-rt loops |
//! | `cookies` | `cookie::CookieJar`, an RFC 6265bis cookie jar |
//! | `auth-digest` | Digest authentication (RFC 7616) in `auth::Auth` |
//! | `auth-ntlm` | NTLMv2 authentication in `auth::Auth` |
//! | `multipart` | `multipart::Multipart`, `multipart/form-data` bodies |
//! | `compress` (default) | gzip and deflate response decoding, custom decoders |
//! | `compress-br`, `compress-zstd` | `br` and `zstd` for request-body compression (`encode::Coding`) |
//! | `auth` | `auth::Auth` with Basic and Bearer tokens and proxy `CONNECT` challenges |
//! | `encode` | form-urlencoded bodies (`RequestBuilder::form`) and gzip/deflate request bodies (`RequestBuilder::compress`) |
//! | `hooks` | interceptors (`ClientBuilder::interceptor`), used by `cookies` and `auth` |
//! | `happy-eyeballs`, `dns-timeout` | RFC 8305 address racing; a resolver timeout (helper thread) |
//! | `socks`, `retry`, `pipeline`, `h2c-upgrade`, `evict` | SOCKS5 proxies; retries with backoff; `Client::pipeline`; h2c through `Upgrade`; a background idle-connection evictor |
//! | `full` | everything |
//!
//! Plain requests need only `client-h1`; the rest is off unless asked for, to keep binaries small.

#![forbid(unsafe_code)]

mod body;
mod client;
pub mod decode;
pub mod hooks;
#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "cookies")]
pub mod cookie;
#[cfg(feature = "encode")]
pub mod encode;
#[cfg(feature = "multipart")]
pub mod multipart;
mod error;
#[cfg(any(feature = "dns-timeout", feature = "happy-eyeballs"))]
#[allow(unused_imports)] // its two halves are separate features
mod dns;
mod h1;
#[cfg(feature = "pipeline")]
mod pipeline;
mod pool;
mod proxy;
#[cfg(feature = "socks")]
mod socks;
mod transport;
mod types;
mod url;

#[cfg(any(feature = "client-h2", feature = "client-h3"))]
mod call;
#[cfg(feature = "client-h2")]
mod h2;
#[cfg(feature = "client-h3")]
mod h3;
#[cfg(any(feature = "client-h2", feature = "client-h3"))]
mod mux;
#[cfg(feature = "rt")]
pub mod rt;
#[cfg(feature = "client-ws")]
mod ws;

pub use body::{Response, ResponseBody};
#[cfg(any(feature = "client-h2", feature = "client-h3"))]
pub use call::{Call, CallSender};
pub use client::{Client, ClientBuilder, Config, PoolStats, RequestBuilder};
pub use error::{Error, ErrorKind, Result, StatusError, TimeoutKind};
pub use proxy::{ProxyAddr, ProxyConfig, ProxyKind};
pub use types::{parse_status_ranges, Body, Headers, HttpVersion, Request, Version};
pub use url::{percent_decode, percent_encode, Url};
#[cfg(feature = "client-ws")]
pub use ws::{Message, WebSocket, WsBuilder};

/// TLS types for configuring the client (feature `tls`).
#[cfg(feature = "tls")]
pub mod tls {
    pub use crate::client::TlsOptions;
    pub use simoom_tls::x509::RootStore;
    pub use simoom_tls::{certgen, CertifiedKey};
}
