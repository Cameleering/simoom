//! The traits a protocol layer implements to be driven by the runtime.

use crate::event_loop::{Ctx, UdpCtx};
use simoom_sys::udp::RecvMeta;
use std::any::Any;
use std::io;
use std::net::SocketAddr;

/// A value sent to a connection or endpoint from another thread ([`crate::ConnHandle`],
/// [`crate::EndpointHandle`], [`Ctx::offload`]). Downcast it with `msg.downcast::<T>()`.
pub type Message = Box<dyn Any + Send>;

/// What the runtime knows about a new connection when it asks an [`Acceptor`] for a handler.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    /// Index of the listener in the order the builder registered them.
    pub listener: usize,
    /// The peer's address, when the back end reports it at accept time (epoll, kqueue, IOCP).
    /// io_uring's multishot accept doesn't; ask [`Ctx::peer_addr`] when it's needed.
    pub peer: Option<SocketAddr>,
    /// The loop that will run the connection.
    pub loop_index: usize,
}

/// Why a connection was closed, passed to [`Connection::on_close`].
#[derive(Debug)]
pub enum CloseReason {
    /// [`Ctx::close`] after the output was flushed.
    Closed,
    /// [`Ctx::abort`]: closed at once, unsent output discarded.
    Aborted,
    /// A receive or send failed (often a reset by the peer).
    Error(io::Error),
    /// More than `max_input` bytes were waiting unconsumed.
    InputLimit,
    /// The runtime stopped and the grace period ran out.
    Stopped,
}

/// Creates a [`Connection`] for each accepted socket. Shared by every loop, so it must be
/// `Send + Sync`; any closure `Fn(&ConnInfo) -> Option<Box<dyn Connection>>` is one.
pub trait Acceptor: Send + Sync + 'static {
    /// Returns the connection's handler, or `None` to close the socket at once.
    fn accept(&self, info: &ConnInfo) -> Option<Box<dyn Connection>>;
}

impl<F> Acceptor for F
where
    F: Fn(&ConnInfo) -> Option<Box<dyn Connection>> + Send + Sync + 'static,
{
    fn accept(&self, info: &ConnInfo) -> Option<Box<dyn Connection>> {
        self(info)
    }
}

/// A connection's protocol state machine. It lives on one loop thread and is called only from
/// there, so it need not be `Send`. A sans-io protocol crate sits behind it: received bytes go
/// in through [`Connection::on_data`], bytes to send go out through [`Ctx::send`].
///
/// Callbacks never run concurrently and never re-enter: a call made through the [`Ctx`] (send,
/// close, timer) takes effect after the callback returns or at the end of the loop turn.
pub trait Connection: 'static {
    /// The connection was registered with the loop; called once, before any other callback.
    /// Arm timers here (a request deadline must run even if the peer never sends a byte).
    fn on_open(&mut self, cx: &mut Ctx<'_>) {
        let _ = cx;
    }

    /// Bytes arrived. `data` holds everything received and not yet consumed, in order. Return
    /// how many bytes from the front were consumed; the rest is offered again, with whatever
    /// arrives next, on the next call. Consume every complete message you can in one call.
    /// While reading is paused ([`Ctx::pause_reading`]) this is not called.
    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize;

    /// The peer closed its sending side. The default closes the connection gracefully.
    fn on_eof(&mut self, cx: &mut Ctx<'_>) {
        cx.close();
    }

    /// Queued output drained: below the low-water mark after being above the high-water mark
    /// (reading had been paused for it and is resumed), or after [`Ctx::notify_drain`].
    fn on_drain(&mut self, cx: &mut Ctx<'_>) {
        let _ = cx;
    }

    /// A timer set with [`Ctx::set_timer`] expired.
    fn on_timer(&mut self, cx: &mut Ctx<'_>, token: u64) {
        let _ = (cx, token);
    }

    /// A message from another thread arrived ([`crate::ConnHandle::send`] or an offloaded job).
    fn on_message(&mut self, cx: &mut Ctx<'_>, msg: Message) {
        let _ = (cx, msg);
    }

    /// The runtime is stopping gracefully. Finish what is in flight and close; the default
    /// closes at once (after flushing). Connections still open when the grace period ends are
    /// aborted.
    fn on_stop(&mut self, cx: &mut Ctx<'_>) {
        cx.close();
    }

    /// The connection is gone; this is the last call.
    fn on_close(&mut self, reason: CloseReason) {
        let _ = reason;
    }
}

/// Information for creating a UDP endpoint on a loop.
#[derive(Clone, Debug)]
pub struct UdpInfo {
    /// Index of the UDP binding in the order the builder registered them.
    pub binding: usize,
    /// The loop the endpoint runs on.
    pub loop_index: usize,
    /// The bound address.
    pub local_addr: SocketAddr,
}

/// Creates the per-loop [`Endpoint`] of a UDP binding. On Linux every loop gets its own
/// `SO_REUSEPORT` socket and endpoint; elsewhere only loop 0 does.
pub trait UdpService: Send + Sync + 'static {
    /// Returns the endpoint for one loop.
    fn endpoint(&self, info: &UdpInfo) -> Box<dyn Endpoint>;
}

impl<F> UdpService for F
where
    F: Fn(&UdpInfo) -> Box<dyn Endpoint> + Send + Sync + 'static,
{
    fn endpoint(&self, info: &UdpInfo) -> Box<dyn Endpoint> {
        self(info)
    }
}

/// A UDP endpoint (for QUIC, a whole connection table) on one loop.
pub trait Endpoint: 'static {
    /// A datagram arrived. With GRO on, `data` may hold several datagrams of
    /// `meta.segment_size` bytes each. The buffer is reused once this returns.
    fn on_datagram(&mut self, cx: &mut UdpCtx<'_>, data: &[u8], meta: &RecvMeta);

    /// A timer set with [`UdpCtx::set_timer`] expired.
    fn on_timer(&mut self, cx: &mut UdpCtx<'_>, token: u64) {
        let _ = (cx, token);
    }

    /// A message from another thread arrived.
    fn on_message(&mut self, cx: &mut UdpCtx<'_>, msg: Message) {
        let _ = (cx, msg);
    }

    /// The runtime is stopping gracefully. Start winding down (QUIC: GOAWAY, then close each
    /// connection once its streams finish). The loop keeps serving this endpoint, with its
    /// datagrams, timers and messages, while [`Endpoint::is_busy`] says so and the grace
    /// period lasts; then the socket is closed.
    fn on_stop(&mut self, cx: &mut UdpCtx<'_>) {
        let _ = cx;
    }

    /// Whether the endpoint still has work in flight. Asked after every loop turn once the
    /// runtime is stopping: while it is `true` (and the grace period lasts) the loop stays
    /// alive. The default is `false`: the socket closes as soon as the TCP side is done.
    fn is_busy(&self) -> bool {
        false
    }

    /// The grace period ran out while the endpoint was still busy: close everything now (QUIC:
    /// send CONNECTION_CLOSE). The socket is closed right after.
    fn on_abort(&mut self, cx: &mut UdpCtx<'_>) {
        let _ = cx;
    }
}
