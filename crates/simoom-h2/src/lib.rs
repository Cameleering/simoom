//! Sans-io HTTP/2 (RFC 9113) connection engine for simoom, with DoS accounting.
//!
//! A [`Connection`] takes received bytes plus the current time and produces [`Event`]s and
//! outbound bytes. It never touches sockets, threads or clocks; the event loop feeds it:
//!
//! ```
//! use simoom_h2::{Config, Connection, Event};
//! let mut server = Connection::server(Config::default());
//! let mut client = Connection::client(Config::default());
//! let id = client.send_request(b"GET", b"https", b"example.com", b"/", &[], true).unwrap();
//!
//! let c2s = client.output().to_vec();
//! client.advance_output(c2s.len());
//! let mut request = None;
//! let used = server.recv(&c2s, 0, &mut |ev| {
//!     if let Event::Headers { stream, headers, .. } = ev {
//!         request = Some((stream, headers.path().unwrap().to_vec()));
//!     }
//! });
//! assert_eq!(used, c2s.len()); // a caller keeps unconsumed bytes for the next call
//! let (stream, path) = request.unwrap();
//! assert_eq!((stream, &path[..]), (id, &b"/"[..]));
//!
//! server.send_response(stream, 200, &[(b"content-type", b"text/plain")], false).unwrap();
//! assert_eq!(server.send_data(stream, b"hello", true), Ok(5));
//! server.stream_finished(stream);
//!
//! let s2c = server.output().to_vec();
//! server.advance_output(s2c.len());
//! let mut body = Vec::new();
//! client.recv(&s2c, 0, &mut |ev| {
//!     if let Event::Data { data, .. } = ev {
//!         body.extend_from_slice(data);
//!     }
//! });
//! assert_eq!(body, b"hello");
//! ```
//!
//! Received data stays charged to the flow-control windows until the application calls
//! [`Connection::release`]; that bounds what a stream and the connection can buffer. Outbound
//! data goes through [`Connection::send_data`], which accepts only what the windows and the
//! output buffer cap allow and reports the rest as backpressure; [`Connection::poll_writable`]
//! names streams that can send again.
//!
//! DoS accounting (plan §2.7): the concurrency limit counts streams whose handler is still
//! running (the application calls [`Connection::stream_finished`]), not just open streams, so
//! resets cannot free capacity while work continues (MadeYouReset, CVE-2025-8671; Rapid Reset,
//! CVE-2023-44487). Sliding-window [`Budgets`] cap RST_STREAM (received and caused), PING,
//! SETTINGS, empty frames, PRIORITY and small WINDOW_UPDATE frames; header blocks are capped in
//! bytes and in CONTINUATION frames. Exceeding any of them sends `GOAWAY(ENHANCE_YOUR_CALM)`.
#![forbid(unsafe_code)]

mod budget;
mod conn;
pub mod frame;
mod headers;
mod upgrade;

pub use budget::Budgets;
pub use conn::{http2_settings_header, Connection, Role};
pub use frame::{ErrorCode, PREFACE};
pub use headers::Headers;
pub use upgrade::{base64url_decode, base64url_encode};

use std::fmt;

/// Settings and limits for one side of a connection.
#[derive(Clone, Debug)]
pub struct Config {
    /// SETTINGS_HEADER_TABLE_SIZE: the HPACK table we let the peer use for our decoder.
    pub header_table_size: u32,
    /// Largest HPACK table our encoder keeps, whatever the peer allows.
    pub encoder_table_size: u32,
    /// SETTINGS_MAX_CONCURRENT_STREAMS, and the cap on streams whose handler is running.
    pub max_concurrent_streams: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE: the starting per-stream receive window.
    pub initial_window_size: u32,
    /// The starting connection receive window.
    pub connection_window_size: u32,
    /// Grow the receive windows from bandwidth-delay estimates (PING round trips).
    pub window_autotune: bool,
    /// Per-stream window cap for auto-tuning: the most a stream can have unreleased.
    pub max_stream_window: u32,
    /// Connection window cap for auto-tuning: the most the connection can have unreleased.
    pub max_connection_window: u32,
    /// SETTINGS_MAX_FRAME_SIZE we accept.
    pub max_frame_size: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE, enforced on the decoded list and on the compressed header
    /// block across CONTINUATION frames.
    pub max_header_list_size: u32,
    /// Most CONTINUATION frames in one header block.
    pub max_continuation_frames: u32,
    /// Output buffer cap: DATA is accepted only while less than this is waiting to be written,
    /// and input processing pauses while twice this is waiting.
    pub max_send_buffer: usize,
    /// How long the peer may take to acknowledge our SETTINGS.
    pub settings_timeout_ms: u64,
    /// Graceful shutdown: how long to wait for the PING that follows the first GOAWAY.
    pub graceful_timeout_ms: u64,
    /// Frame budgets per sliding window.
    pub budgets: Budgets,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            header_table_size: 4096,
            encoder_table_size: 4096,
            max_concurrent_streams: 100,
            initial_window_size: 256 * 1024,
            connection_window_size: 1024 * 1024,
            window_autotune: true,
            max_stream_window: 4 * 1024 * 1024,
            max_connection_window: 16 * 1024 * 1024,
            max_frame_size: 16_384,
            max_header_list_size: 16 * 1024,
            max_continuation_frames: 32,
            max_send_buffer: 128 * 1024,
            settings_timeout_ms: 10_000,
            graceful_timeout_ms: 1_000,
            budgets: Budgets::default(),
        }
    }
}

/// Something the peer did, reported by [`Connection::recv`] and [`Connection::handle_timeout`].
#[derive(Debug)]
pub enum Event<'a> {
    /// Request headers (server), or response headers including 1xx (client).
    Headers { stream: u32, headers: &'a Headers, end_stream: bool },
    /// Request or response body bytes. Call [`Connection::release`] once they are consumed.
    Data { stream: u32, data: &'a [u8], end_stream: bool },
    /// Trailers; they always end the stream.
    Trailers { stream: u32, trailers: &'a Headers },
    /// The stream ended abnormally: reset by the peer (`remote`), refused by its GOAWAY, or
    /// reset by us after a stream error. Stop its work, then call
    /// [`Connection::stream_finished`].
    Reset { stream: u32, code: ErrorCode, remote: bool },
    /// The peer's SETTINGS were applied (and acknowledged).
    Settings,
    /// The answer to [`Connection::ping`].
    Pong { data: [u8; 8] },
    /// The peer is shutting down: no stream above `last_stream` will be processed.
    GoAway { last_stream: u32, code: ErrorCode, debug: &'a [u8] },
    /// We closed the connection with a GOAWAY carrying `code` (a connection error or an
    /// exceeded budget). Flush the output, then close the transport.
    Closed { code: ErrorCode },
}

/// Errors from the sending API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No such stream (never opened, or closed and forgotten).
    UnknownStream,
    /// The stream was reset.
    StreamReset,
    /// We already ended the stream.
    StreamClosed,
    /// Final headers were already sent.
    HeadersAlreadySent,
    /// Data or trailers before the headers.
    HeadersNotSent,
    /// A field name or value that HTTP/2 does not allow, or an invalid status.
    InvalidHeader,
    /// The peer's SETTINGS_MAX_CONCURRENT_STREAMS is reached.
    StreamLimit,
    /// No stream identifiers left: open a new connection.
    StreamIdsExhausted,
    /// The peer sent GOAWAY: no new streams.
    GoingAway,
    /// The connection is closed.
    ConnectionClosed,
    /// The call is for the other role (for example a client sending a response).
    WrongRole,
    /// An `HTTP2-Settings` value that is not valid base64url SETTINGS.
    InvalidUpgradeSettings,
    /// The header block is larger than the peer's SETTINGS_MAX_HEADER_LIST_SIZE; nothing was
    /// sent.
    HeaderListTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}
