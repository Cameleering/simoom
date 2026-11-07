//! Every limit the server enforces, with the defaults of plan §7.1.

use std::time::Duration;

/// Server limits. Every field is a hard bound; exceeding one gives a specific status code (or
/// closes the connection) and increments a counter in [`crate::Stats`].
#[derive(Clone, Debug)]
pub struct Limits {
    /// Request line in bytes, CRLF included (414 beyond it). Default 8 KiB.
    pub max_request_line: usize,
    /// Whole request head in bytes (431 beyond it). Default 16 KiB.
    pub max_head: usize,
    /// Header fields per request (431 beyond it). Default 100.
    pub max_headers: usize,
    /// One header line in bytes (431 beyond it). Default 8 KiB.
    pub max_header_line: usize,
    /// Request body in bytes (413 beyond it); a larger `Content-Length` is refused before any
    /// body byte is read. Default 10 MiB.
    pub max_body: u64,
    /// Bodies up to this size are buffered whole before the service is called
    /// ([`crate::Request::body`]); larger or longer ones are streamed through a
    /// [`crate::BodySource`] with backpressure. Also the size of a body source's buffer.
    /// Default 64 KiB.
    pub body_buffer: usize,
    /// Deadline for a whole request head, from its first byte (and for the first request, from
    /// the accept). Defeats slowloris. Default 10 s.
    pub head_timeout: Duration,
    /// Idle keep-alive timeout between requests (HTTP/1.1) or with no open stream (HTTP/2).
    /// Default 15 s.
    pub keep_alive_timeout: Duration,
    /// Minimum request body rate in bytes per second, enforced after
    /// [`Limits::body_rate_grace`]. 0 disables it. Default 1 KiB/s.
    pub min_body_rate: u32,
    /// Grace period before the body rate is enforced. Default 5 s.
    pub body_rate_grace: Duration,
    /// Queued output that makes no progress for this long closes the connection. Default 30 s.
    pub write_timeout: Duration,
    /// Requests per keep-alive connection; 0 means unlimited (the default).
    pub max_requests_per_connection: u64,
    /// Connections in total; more are accepted and closed at once. Default 1 Mi.
    pub max_connections: usize,
    /// Connections per loop thread. Default 1 Mi.
    pub max_connections_per_loop: usize,
    /// Open connections per client IP address (TCP listeners); more are accepted and closed at
    /// once and counted in [`crate::Stats::rejected`]. 0 (the default) means no cap: behind a
    /// proxy or a NAT every client shares one address.
    pub max_connections_per_ip: usize,
    /// HTTP/2 and HTTP/3: concurrent streams whose handler work is running. Default 100.
    pub max_concurrent_streams: u32,
    /// HTTP/2 header list (CONTINUATION included) and HTTP/3 field section, in bytes.
    /// Default 16 KiB.
    pub max_header_list: u32,
    /// HTTP/2 HPACK and HTTP/3 QPACK dynamic table size. Default 4096.
    pub header_table_size: u32,
    /// Streamed response bytes ([`crate::BodySink`]) handed to a connection and not yet written
    /// before writers wait (backpressure). Default 64 KiB.
    pub stream_buffer: usize,
    /// WebSocket message size (all fragments). Default 1 MiB.
    pub max_ws_message: u64,
    /// Inline handlers that take longer than this are counted as stalls and logged once per
    /// route; `None` turns the stall watchdog off. Default 1 ms.
    pub inline_budget: Option<Duration>,
    /// After this many stalls a service (or a router route) moves to the offload pool. 0 never
    /// moves it. Default 3.
    pub stalls_before_offload: u32,
    /// Offload pool threads; 0 means twice the CPU count, at least 4.
    pub offload_threads: usize,
    /// Offload jobs waiting; more get a 503. Default 4096.
    pub offload_queue: usize,
    /// CoDel target sojourn time for offloaded jobs. Default 5 ms.
    pub offload_target: Duration,
    /// CoDel interval. Default 100 ms.
    pub offload_interval: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_request_line: 8 * 1024,
            max_head: 16 * 1024,
            max_headers: 100,
            max_header_line: 8 * 1024,
            max_body: 10 * 1024 * 1024,
            body_buffer: 64 * 1024,
            head_timeout: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(15),
            min_body_rate: 1024,
            body_rate_grace: Duration::from_secs(5),
            write_timeout: Duration::from_secs(30),
            max_requests_per_connection: 0,
            max_connections: 1 << 20,
            max_connections_per_loop: 1 << 20,
            max_connections_per_ip: 0,
            max_concurrent_streams: 100,
            max_header_list: 16 * 1024,
            header_table_size: 4096,
            stream_buffer: 64 * 1024,
            max_ws_message: 1 << 20,
            inline_budget: Some(Duration::from_millis(1)),
            stalls_before_offload: 3,
            offload_threads: 0,
            offload_queue: 4096,
            offload_target: Duration::from_millis(5),
            offload_interval: Duration::from_millis(100),
        }
    }
}

#[cfg(feature = "http1")]
impl Limits {
    pub(crate) fn http1(&self) -> simoom_http1::Limits {
        simoom_http1::Limits {
            max_request_line: self.max_request_line,
            max_head: self.max_head,
            max_headers: self.max_headers,
            max_header_line: self.max_header_line,
            max_body: self.max_body,
            ..simoom_http1::Limits::default()
        }
    }
}
