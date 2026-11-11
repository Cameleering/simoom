//! Operating-system layer of simoom: epoll, io_uring, kqueue, IOCP, sockets, SIMD scanning and
//! hardware crypto intrinsics. This is the only simoom crate that contains `unsafe` code; every
//! `unsafe` block carries a `// SAFETY:` comment.
//!
//! - [`net`]: owned non-blocking TCP and UDP sockets ([`net::Socket`]).
//! - [`udp`]: batched datagram I/O with GRO/GSO, ECN and packet info.
//! - [`driver`]: the completion-style I/O driver over epoll, io_uring, IOCP and kqueue, with a
//!   cross-thread [`driver::Waker`].
//! - [`time`]: cheap monotonic clocks. [`cpu`]: CPU count and thread affinity.
//! - [`alloc`]: a counting global allocator for memory measurements.

/// SIMD byte scanning for the HTTP parsers (owned by the simoom-http1 work).
pub mod scan;

/// Hardware crypto intrinsics behind safe wrappers: AES-NI, PCLMULQDQ, SHA-NI, ARMv8 AES/PMULL
/// (owned by the simoom-tls work).
pub mod arch;

mod os;

pub mod alloc;
/// Codec kernels with CPU features picked at run time: BMI2 (owned by the simoom-compress work).
pub mod bits;
/// Codec inner loops as unchecked pointer code (owned by the simoom-compress work).
pub mod codec;
/// The OS store of trusted root certificates (Windows), for TLS clients.
pub mod certstore;
pub mod cpu;
/// Per-thread CPU time (owned by the facade work, for the stall watchdog).
pub mod cputime;
pub mod driver;
pub mod mpsc;
pub mod net;
pub mod time;
pub mod udp;
/// SanitizerCoverage callbacks for the coverage-guided fuzzer (test-only, feature `sancov`).
#[cfg(feature = "sancov")]
pub mod sancov;
