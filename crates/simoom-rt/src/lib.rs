//! simoom runtime: one event loop per core, timer wheel, buffer pools, cross-thread wakeups,
//! offload pool.
//!
//! # Model
//!
//! - **One loop thread per core, shared-nothing.** Each loop owns an I/O driver
//!   ([`simoom_sys::driver::Driver`]: epoll or io_uring on Linux, IOCP on Windows, kqueue on
//!   macOS), a buffer pool ([`pool::BufPool`]), a timer wheel ([`timer::TimerWheel`]) and its
//!   connections. Nothing on the hot path is shared between loops.
//! - **Completion style.** The driver receives into pooled buffers and sends owned buffers; a
//!   connection sees bytes in and hands bytes out. Readiness is never exposed.
//! - **An idle connection holds no buffer.** Buffers are lent to the driver, taken only when
//!   data arrives, and returned to the pool as soon as a handler has consumed the data and the
//!   reply is written.
//! - **Accepting.** Linux: one `SO_REUSEPORT` listener per loop. Windows: one listener with a
//!   queue of `AcceptEx` calls on loop 0, which hands connections to the less busy of two loops.
//!   macOS: one shared listener, handed out the same way.
//! - **UDP.** One endpoint per loop (`SO_REUSEPORT` sockets on Linux; loop 0 elsewhere) with
//!   batched receive and send, GRO/GSO, ECN and packet info, for QUIC.
//! - **Offload.** Blocking work goes to a bounded shared pool ([`offload::OffloadPool`]) with
//!   CoDel admission; results come back to the connection's loop as messages.
//! - **Caps and backpressure.** Connection caps (total and per loop: over the cap a connection is
//!   accepted and closed at once), a cap on unconsumed input per connection, and write
//!   high/low-water marks that pause and resume reading.
//! - **Graceful stop** with a deadline ([`RuntimeHandle::stop`]).
//!
//! # Driving a protocol
//!
//! Protocol crates are sans-io: they take received bytes and produce bytes to send. The glue is
//! a [`Connection`] per connection, created by an [`Acceptor`]:
//!
//! ```no_run
//! use simoom_rt::{Connection, ConnInfo, Ctx, Runtime};
//!
//! struct Echo;
//! impl Connection for Echo {
//!     fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
//!         let mut out = cx.buffer(data.len()); // pooled
//!         out.extend_from_slice(data);
//!         cx.send(out); // written at the end of the loop turn, batched with other output
//!         data.len()    // consumed everything: the input buffer goes back to the pool
//!     }
//! }
//!
//! let rt = Runtime::builder()
//!     .threads(0) // one loop per CPU
//!     .listen("127.0.0.1:8080", |_: &ConnInfo| Some(Box::new(Echo) as Box<dyn Connection>))
//!     .start()
//!     .unwrap();
//! println!("listening on {:?}", rt.local_addrs());
//! rt.stop(std::time::Duration::from_secs(5));
//! rt.join();
//! ```
//!
//! - [`Connection::on_data`] gets every unconsumed byte and returns how many it consumed. A
//!   partial message stays buffered for the next call.
//! - [`Ctx::send`] / [`Ctx::send_static`] queue output; [`Ctx::close`] closes after flushing.
//! - [`Ctx::set_timer`] arms a timer ([`Connection::on_timer`]), for request deadlines and
//!   idle timeouts.
//! - [`Ctx::pause_reading`] / [`Ctx::resume_reading`] for backpressure; [`Ctx::notify_drain`]
//!   and [`Connection::on_drain`] for streaming output.
//! - [`Ctx::handle`] gives a `Send` [`ConnHandle`] to deliver a [`Message`] from any thread
//!   (a deferred reply); [`Ctx::offload`] runs a closure on the offload pool and delivers its
//!   result the same way.
//!
//! UDP protocols (QUIC) implement [`Endpoint`], created per loop by a [`UdpService`].

#![forbid(unsafe_code)]

mod event_loop;
mod handler;
pub mod offload;
pub mod pool;
mod runtime;
pub mod timer;

pub use event_loop::{ConnHandle, Ctx, EndpointHandle, LoopCtx, LoopHandle, UdpCtx};
pub use handler::{Acceptor, CloseReason, ConnInfo, Connection, Endpoint, Message, UdpInfo, UdpService};
pub use runtime::{Builder, Config, LoopSnapshot, RuntimeHandle, Stats};

pub use simoom_sys::driver::{Backend, DriverConfig, DriverStats, OutBuf};
pub use simoom_sys::net::{ListenOptions, Socket, UdpOptions};
pub use simoom_sys::udp::{RecvMeta, Transmit};

/// Entry point: `Runtime::builder()`.
#[derive(Debug)]
pub struct Runtime;

impl Runtime {
    /// A [`Builder`] with the default [`Config`].
    pub fn builder() -> Builder {
        Builder::new()
    }
}
