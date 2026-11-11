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
    /// How long a request head that is still arriving may stay open after
    /// [`Limits::head_timeout`] while the server is not short of connections (K6). A slow head
    /// holds no buffer (partial heads are compacted to their size), so closing it gains nothing
    /// until open connections pass three quarters of [`Limits::max_connections`] or of the file
    /// descriptor limit; closing slowloris connections early only makes their attacker reconnect,
    /// and the accept and close churn costs every other client. Under that pressure, or once a
    /// head is this old, it is closed at its deadline as before. `Duration::ZERO` closes every
    /// head at [`Limits::head_timeout`]. Default 300 s. Needs the `guard` cargo feature (on by
    /// default); without it every head closes at [`Limits::head_timeout`].
    pub slow_head_limit: Duration,
    /// New connections per second accepted from one client IP address (TCP listeners), as a
    /// token bucket with a burst of the same size; more are accepted and closed at once and
    /// counted in [`crate::Stats::rejected`] (K6: an attacker whose connections are closed
    /// cannot come straight back). 0 (the default) means no limit: behind a proxy or a NAT every
    /// client shares one address. Only the most recent 64 Ki addresses are tracked. Needs the
    /// `guard` cargo feature (on by default).
    pub reconnect_rate: u32,
    /// Admission control by backpressure (K5): when this many replies on one loop thread are
    /// outstanding (deferred, offloaded or streaming) its HTTP/1.1 connections stop reading new
    /// requests, and its HTTP/2 connections refuse new streams, until the count drops to three
    /// quarters of it; the kernel's buffers and TCP flow control then hold the clients back.
    /// With [`Limits::pending_503`] the new requests get a fast `503` instead. 0 turns it off.
    /// Default 16 Ki, far above what a worker pool keeps in flight, so it never acts under
    /// normal load. Needs the `guard` cargo feature (on by default).
    pub max_pending_per_loop: usize,
    /// Answer new requests over [`Limits::max_pending_per_loop`] with `503` and `retry-after`
    /// (counted in [`crate::Stats::shed`]) instead of pausing. Default false.
    pub pending_503: bool,
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
    /// How long a deferred reply ([`crate::Reply::defer`], and the offload paths
    /// [`crate::blocking`] and [`crate::Reply::offload`]) may take to start: when it expires
    /// before the [`crate::Responder`] sent a response or a streamed head, the client gets a
    /// `504 Gateway Timeout`, the responder is cancelled ([`crate::Responder::is_cancelled`])
    /// and its late answer is dropped. A streamed body, once started, is bounded by
    /// [`Limits::write_timeout`] instead. `None` (the default) waits for ever, as before; set
    /// it to the route's SLO.
    pub defer_timeout: Option<Duration>,
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
    /// HTTP/2 frame budgets per connection (RST_STREAM, PING, SETTINGS, empty frames,
    /// PRIORITY, small WINDOW_UPDATE); exceeding one closes the connection with
    /// `GOAWAY(ENHANCE_YOUR_CALM)`. Defaults in [`FrameBudgets`].
    pub h2_frame_budgets: FrameBudgets,
    /// HTTP/2 PING keepalive: after this long without any frame from the client, the server
    /// sends a PING; [`Limits::h2_keepalive_timeout`] later, a client that sent nothing back is
    /// considered dead and its connection is closed (its streams are cancelled). Finds peers that
    /// vanished without a FIN behind long-lived streams (gRPC streaming, SSE, WebSocket over
    /// HTTP/2). `None` (the default) sends no keepalive PINGs. Needs the `h2-keepalive` cargo
    /// feature; without it this is ignored.
    pub h2_keepalive: Option<Duration>,
    /// How long a client has to answer a keepalive PING ([`Limits::h2_keepalive`]). Default 20 s.
    pub h2_keepalive_timeout: Duration,
    /// Streamed response bytes ([`crate::BodySink`]) handed to a connection and not yet written
    /// before writers wait (backpressure). Default 64 KiB.
    pub stream_buffer: usize,
    /// WebSocket message size (all fragments). Default 1 MiB.
    pub max_ws_message: u64,
    /// The stall watchdog's budget for one inline handler call; `None` turns the watchdog off.
    /// A call over it on the wall clock makes its route suspect; the route's next calls are
    /// measured with the thread's CPU clock, and a call is a stall only if it used more CPU than
    /// this or blocked (so a loop thread preempted on a busy machine is not mistaken for a slow
    /// handler). Stalls are logged once per route. Default 1 ms. Needs the `watchdog` cargo
    /// feature (on by default); without it this and the stall limits below are ignored.
    pub inline_budget: Option<Duration>,
    /// Stalls within [`Limits::stall_window`] after which a route (of a [`crate::Router`]; for
    /// another service, the requests with its path) moves to the offload pool. Other routes stay
    /// inline. 0 never moves it. Default 5.
    pub stalls_before_offload: u32,
    /// The window for [`Limits::stalls_before_offload`]. Default 1 s.
    pub stall_window: Duration,
    /// Consecutive fast calls on the offload pool after which a moved route comes back inline;
    /// it needs twice as many each further time. 0 keeps it on the pool. Default 64.
    pub stall_recovery: u32,
    /// Admission control: when a loop thread reaches a connection's input this long after the
    /// loop turn's events were ready (the loop is behind), new HTTP/1.1 requests and HTTP/2
    /// streams on it get a fast `503` with `retry-after` without calling the service (the
    /// connection stays open when the whole request has arrived, else it closes); requests
    /// already admitted keep their latency. Counted in
    /// [`crate::Stats::shed`]. `None` turns it off. Default `None`, from measurement (2026-11-09,
    /// 4 loops, open-loop HTTP/1.1 load): 1 ms shed requests falsely at 50% load and 0.5 ms at
    /// 90%, and under 120-150% overload no value from 0.5 to 5 ms improved goodput or p99 (the
    /// queue builds in the client and the kernel). Lag also grows when the loop thread itself
    /// is preempted (a busy VM). Opt in with a value that matches a latency SLO.
    pub shed_lag: Option<Duration>,
    /// Offload pool threads ([`crate::blocking`], [`crate::Reply::offload`], routes the watchdog
    /// moved). 0 (the default) means 32 per CPU, between 512 and 1024: enough for blocking
    /// integration calls (512 workers serve about 5,000 calls per second of 100 ms each, as a
    /// thread-per-request server with a pool of that size would).
    /// Workers start on demand and exit after 10 s idle, so the cap costs nothing until used.
    /// Set it to the concurrency your backends allow.
    pub offload_threads: usize,
    /// Offload jobs waiting; more get a 503. Default 4096.
    pub offload_queue: usize,
    /// CoDel target sojourn time for offloaded jobs. Default 5 ms. The pool raises it to the
    /// jobs' recent mean run time, so slow jobs (100 ms) are shed only when the queue keeps
    /// growing past what the workers absorb, not because one waits a job's length.
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
            slow_head_limit: Duration::from_secs(300),
            reconnect_rate: 0,
            max_pending_per_loop: 16 * 1024,
            pending_503: false,
            keep_alive_timeout: Duration::from_secs(15),
            min_body_rate: 1024,
            body_rate_grace: Duration::from_secs(5),
            write_timeout: Duration::from_secs(30),
            defer_timeout: None,
            max_requests_per_connection: 0,
            max_connections: 1 << 20,
            max_connections_per_loop: 1 << 20,
            max_connections_per_ip: 0,
            max_concurrent_streams: 100,
            max_header_list: 16 * 1024,
            header_table_size: 4096,
            h2_frame_budgets: FrameBudgets::default(),
            h2_keepalive: None,
            h2_keepalive_timeout: Duration::from_secs(20),
            stream_buffer: 64 * 1024,
            max_ws_message: 1 << 20,
            inline_budget: Some(Duration::from_millis(1)),
            stalls_before_offload: 5,
            stall_window: Duration::from_secs(1),
            stall_recovery: 64,
            shed_lag: None,
            offload_threads: 0,
            offload_queue: 4096,
            offload_target: Duration::from_millis(5),
            offload_interval: Duration::from_millis(100),
        }
    }
}

/// HTTP/2 frame budgets ([`Limits::h2_frame_budgets`]): how many of each frame kind a peer may
/// send (or make us send) within a sliding window before the connection is closed with
/// `GOAWAY(ENHANCE_YOUR_CALM)`. `u32::MAX` turns one off. They defend against the HTTP/2 floods
/// (CVE-2019-9511..9518, Rapid Reset CVE-2023-44487, MadeYouReset CVE-2025-8671); the defaults
/// leave ordinary clients, browsers and gRPC far below them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameBudgets {
    /// The sliding window. Default 10 s.
    pub window: Duration,
    /// RST_STREAM frames received. Default 200.
    pub rst_received: u32,
    /// RST_STREAM frames the peer made us send (stream errors, refused streams). Default 200.
    pub rst_sent: u32,
    /// PING frames received. Default 100.
    pub ping: u32,
    /// SETTINGS frames received. Default 100.
    pub settings: u32,
    /// Empty DATA, HEADERS and CONTINUATION frames that end nothing. Default 200.
    pub empty_frames: u32,
    /// PRIORITY frames received. Default 1000.
    pub priority: u32,
    /// WINDOW_UPDATE frames with an increment under 1024 bytes. Default 500.
    pub small_window_updates: u32,
}

impl Default for FrameBudgets {
    fn default() -> Self {
        FrameBudgets {
            window: Duration::from_secs(10),
            rst_received: 200,
            rst_sent: 200,
            ping: 100,
            settings: 100,
            empty_frames: 200,
            priority: 1000,
            small_window_updates: 500,
        }
    }
}

#[cfg(feature = "http2")]
impl FrameBudgets {
    pub(crate) fn h2(&self) -> simoom_h2::Budgets {
        simoom_h2::Budgets {
            window_ms: (self.window.as_millis().min(u64::MAX as u128) as u64).max(1),
            rst_received: self.rst_received,
            rst_sent: self.rst_sent,
            ping: self.ping,
            settings: self.settings,
            empty_frames: self.empty_frames,
            priority: self.priority,
            small_window_updates: self.small_window_updates,
        }
    }
}

impl Limits {
    pub(crate) fn watchdog(&self) -> crate::watchdog::Policy {
        crate::watchdog::Policy {
            budget_ns: self.inline_budget.map_or(0, |d| (d.as_nanos() as u64).max(1)),
            stalls: self.stalls_before_offload,
            window_ns: self.stall_window.as_nanos() as u64,
            recover: self.stall_recovery,
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

#[cfg(all(test, feature = "http2"))]
mod tests {
    // Bug 15: the facade's defaults are the engine's.
    #[test]
    fn frame_budget_defaults_match_the_engine() {
        assert_eq!(super::FrameBudgets::default().h2(), simoom_h2::Budgets::default());
    }
}
