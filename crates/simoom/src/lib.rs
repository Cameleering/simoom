//! simoom: a small, fast, secure embeddable HTTP/1.1, HTTP/2 and HTTP/3 server.
//!
//! The API is synchronous at its core and needs no async runtime. A [`Service`] runs **inline
//! on a loop thread** (one loop per core, shared-nothing); slow or blocking work goes to a
//! bounded offload pool with CoDel admission.
//!
//! ```no_run
//! use simoom::{Outcome, Reply, Request, Server, StaticReply};
//! use std::sync::Arc;
//!
//! let hello = Arc::new(StaticReply::new(200, &[("content-type", "text/plain")], b"Hello, World!"));
//! let server = Server::builder()
//!     .listen("127.0.0.1:8080")
//!     .threads(0) // one loop per core
//!     .service(move |_req: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.fixed(&hello) })
//!     .start()
//!     .unwrap();
//! println!("listening on {}", server.local_addr());
//! # server.stop(std::time::Duration::from_secs(1));
//! # server.join();
//! ```
//!
//! # Answering
//!
//! A [`Reply`] ends in exactly one of: an immediate response ([`Reply::body`],
//! [`Reply::fixed`]...), a [`Responder`] for later ([`Reply::defer`]), a streamed body
//! ([`Reply::stream`], [`Reply::sse`] with a [`BodySink`]), offloaded work ([`Reply::offload`],
//! [`blocking`]), or a WebSocket ([`Reply::websocket`]).
//!
//! # Blocking work: which path to use
//!
//! A service must never block a loop thread. Pick one of:
//!
//! | path | when |
//! |---|---|
//! | [`Reply::defer`] + your own threads | the host already has a worker pool, its own naming, limits and backpressure (an integration engine such as Cameleer): copy the request with [`Request::to_owned_request`], answer through the [`Responder`] from any thread. [`Limits::defer_timeout`] bounds the wait, [`Responder::is_cancelled`] tells the worker the client left. simoom's pool and CoDel are not involved. |
//! | [`blocking`], [`Reply::blocking`], [`Reply::offload`] | blocking handlers without a pool of their own (database or HTTP calls of up to seconds). The offload pool starts up to [`Limits::offload_threads`] workers on demand (32 per CPU by default, 64 to 512) and answers a fast 503 only when its queue keeps growing past what the workers absorb (CoDel with a target of at least the jobs' mean run time). |
//! | inline | microseconds of CPU, no I/O. The stall watchdog (feature `watchdog`) moves a route that turns out slow to the offload pool, as a safety net, not a plan: each call before the move holds the loop. |
//!
//! # Request bodies
//!
//! Bodies up to [`Limits::body_buffer`] are buffered whole ([`Request::body`]); longer ones
//! stream through a [`BodySource`] ([`Request::take_body`]) with pull-based backpressure.
//!
//! # Protocols and features
//!
//! | feature | what it adds |
//! |---|---|
//! | `http1` (default) | HTTP/1.1: keep-alive, pipelining, chunked, 100-continue |
//! | `http2` (default) | h2c prior knowledge, `Upgrade: h2c`, h2 over TLS |
//! | `websocket` (default), alias `ws` | WebSocket upgrades |
//! | `tls` | TLS 1.3 listeners ([`Builder::listen_tls`]), ALPN h2 / http/1.1 |
//! | `http3` | HTTP/3 over QUIC ([`Builder::listen_quic`]); announced with `alt-svc` |
//! | `full` | all of them |
//! | `compression` | gzip and deflate responses negotiated from `Accept-Encoding` (`Builder::compression`), request body decoding (`Request::decoded_body`) |
//! | `websocket-h2` | WebSocket over HTTP/2 (RFC 8441 extended CONNECT) with the same [`Reply::websocket`] |
//! | `h2-keepalive` | HTTP/2 PING keepalive ([`Limits::h2_keepalive`]) |
//!
//! The last three are not part of `default` or `full`, which keep their size budgets.
//!
//! # Safety nets
//!
//! - Every limit of [`Limits`] is enforced (head size, body size, timeouts, minimum body rate,
//!   write deadline, connection caps).
//! - A handler panic becomes a 500 and the connection closes.
//! - The stall watchdog finds inline handlers that use more than [`Limits::inline_budget`] of
//!   CPU, or block, and moves just their route to the offload pool after
//!   [`Limits::stalls_before_offload`] stalls within [`Limits::stall_window`]; a route comes
//!   back after [`Limits::stall_recovery`] fast calls there (cargo feature `watchdog`, on by
//!   default).
//! - Graceful stop ([`ServerHandle::stop`]): GOAWAY on HTTP/2 and HTTP/3, `Connection: close`
//!   on HTTP/1.1.

#![forbid(unsafe_code)]
// A build without any protocol feature serves nothing; it still compiles, quietly.
#![cfg_attr(not(any(feature = "http1", feature = "http2", feature = "http3")), allow(dead_code, unused_imports, unused_variables))]
// Builds without HTTP/1.1 (h2c only, h2 over TLS only, HTTP/3 only) leave the HTTP/1.1 output
// helpers and fields unused; the linker drops them.
#![cfg_attr(not(feature = "http1"), allow(dead_code))]

#[cfg(feature = "compression")]
mod compress;
#[cfg(feature = "conditional")]
pub mod conditional;
#[cfg(feature = "cookies")]
pub mod cookie;
#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "cors")]
pub mod cors;
#[cfg(any(feature = "cookies", feature = "conditional"))]
mod httpdate;
#[cfg(feature = "multipart")]
pub mod multipart;
mod conn;
mod handle;
#[cfg(feature = "http1")]
mod h1;
#[cfg(feature = "http2")]
mod h2;
#[cfg(feature = "http3")]
mod h3;
mod limits;
mod reply;
mod request;
mod router;
mod server;
mod service;
mod types;
mod util;
#[cfg(feature = "watchdog")]
mod watchdog;
#[cfg(not(feature = "watchdog"))]
#[path = "watchdog_off.rs"]
mod watchdog;
#[cfg(feature = "websocket")]
mod ws;

#[cfg(feature = "compression")]
pub use compress::{Compression, ContentCoding, DecodeBodyError, DecodedRead};
pub use handle::{BodySink, BodySource, Ready, Responder};
pub use limits::{FrameBudgets, Limits};
pub use reply::Reply;
pub use request::{OwnedRequest, Request, TlsInfo};
pub use router::Router;
pub use server::{Builder, Completion, Server, ServerHandle, Stats};
pub use service::{blocking, Blocking, Outcome, Service};
#[doc(hidden)]
pub use service::WatchRef;
pub use simoom_rt::offload::OffloadStats;
pub use simoom_rt::Backend;
pub use types::{Body, Response, StaticReply, Version};
pub use util::percent_decode;
#[cfg(feature = "websocket")]
pub use ws::{WebSocket, WebSocketHandler, WsHandle, WsMessage};
/// permessage-deflate settings ([`Builder::websocket_deflate`]).
#[cfg(feature = "ws-deflate")]
pub use simoom_http1::ws::deflate::DeflateConfig as WsDeflate;

/// TLS configuration types (feature `tls`).
#[cfg(feature = "tls")]
pub mod tls {
    pub use simoom_tls::certgen;
    pub use simoom_tls::{CertifiedKey, ServerConfig};
}
