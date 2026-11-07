//! Operating-system layer of simoom: epoll, io_uring, kqueue, IOCP, sockets, SIMD scanning and
//! hardware crypto intrinsics. This is the only simoom crate that contains `unsafe` code; every
//! `unsafe` block carries a `// SAFETY:` comment.

/// SIMD byte scanning for the HTTP parsers (owned by the simoom-http1 work).
pub mod scan;

/// Hardware crypto intrinsics behind safe wrappers: AES-NI, PCLMULQDQ, SHA-NI, ARMv8 AES/PMULL
/// (owned by the simoom-tls work).
pub mod arch;
