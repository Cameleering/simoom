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
//!
//! # Safety nets
//!
//! - Every limit of [`Limits`] is enforced (head size, body size, timeouts, minimum body rate,
//!   write deadline, connection caps).
//! - A handler panic becomes a 500 and the connection closes.
//! - The stall watchdog counts inline handlers over [`Limits::inline_budget`] and moves them to
//!   the offload pool after [`Limits::stalls_before_offload`] stalls.
//! - Graceful stop ([`ServerHandle::stop`]): GOAWAY on HTTP/2 and HTTP/3, `Connection: close`
//!   on HTTP/1.1.

#![forbid(unsafe_code)]
// A build without any protocol feature serves nothing; it still compiles, quietly.
#![cfg_attr(not(any(feature = "http1", feature = "http2", feature = "http3")), allow(dead_code, unused_imports, unused_variables))]
// Builds without HTTP/1.1 (h2c only, h2 over TLS only, HTTP/3 only) leave the HTTP/1.1 output
// helpers and fields unused; the linker drops them.
#![cfg_attr(not(feature = "http1"), allow(dead_code))]

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
#[cfg(feature = "websocket")]
mod ws;

pub use handle::{BodySink, BodySource, Ready, Responder};
pub use limits::Limits;
pub use reply::Reply;
pub use request::{OwnedRequest, Request};
pub use router::Router;
pub use server::{Builder, Server, ServerHandle, Stats};
pub use service::{blocking, Blocking, Outcome, Service};
pub use simoom_rt::offload::OffloadStats;
pub use simoom_rt::Backend;
pub use types::{Body, Response, StaticReply, Version};
pub use util::percent_decode;
#[cfg(feature = "websocket")]
pub use ws::{WebSocket, WebSocketHandler, WsHandle, WsMessage};

/// TLS configuration types (feature `tls`).
#[cfg(feature = "tls")]
pub mod tls {
    pub use simoom_tls::certgen;
    pub use simoom_tls::{CertifiedKey, ServerConfig};
}
