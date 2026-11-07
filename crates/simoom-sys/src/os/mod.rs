//! Raw operating-system declarations. Declaring a foreign function is safe; every call site
//! elsewhere in this crate is an `unsafe` block with a `// SAFETY:` comment.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as sys;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows as sys;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
pub mod bsd;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
pub use bsd as sys;
