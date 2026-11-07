//! Raw macOS and FreeBSD declarations for kqueue and BSD sockets.

#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_int, c_void};

pub type socklen_t = u32;

pub const AF_INET: c_int = 2;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const AF_INET6: c_int = 30;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub const AF_INET6: c_int = 28;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;

pub const SOL_SOCKET: c_int = 0xffff;
pub const SO_REUSEADDR: c_int = 0x0004;
pub const SO_REUSEPORT: c_int = 0x0200;
pub const SO_SNDBUF: c_int = 0x1001;
pub const SO_RCVBUF: c_int = 0x1002;
pub const SO_ERROR: c_int = 0x1007;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const SO_NOSIGPIPE: c_int = 0x1022;

pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IPV6: c_int = 41;
pub const TCP_NODELAY: c_int = 1;
pub const IP_TOS: c_int = 3;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const IPV6_V6ONLY: c_int = 27;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub const IPV6_V6ONLY: c_int = 27;
pub const IPV6_TCLASS: c_int = 36;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const MSG_NOSIGNAL: c_int = 0;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub const MSG_NOSIGNAL: c_int = 0x20000;

pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;
pub const SHUT_RDWR: c_int = 2;

pub const F_SETFD: c_int = 2;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const FD_CLOEXEC: c_int = 1;
pub const O_NONBLOCK: c_int = 0x0004;

pub const EVFILT_READ: i16 = -1;
pub const EVFILT_WRITE: i16 = -2;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const EVFILT_USER: i16 = -10;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub const EVFILT_USER: i16 = -11;
pub const EV_ADD: u16 = 0x0001;
pub const EV_DELETE: u16 = 0x0002;
pub const EV_ENABLE: u16 = 0x0004;
pub const EV_CLEAR: u16 = 0x0020;
pub const EV_RECEIPT: u16 = 0x0040;
pub const EV_ERROR: u16 = 0x4000;
pub const EV_EOF: u16 = 0x8000;
pub const NOTE_TRIGGER: u32 = 0x0100_0000;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const CLOCK_MONOTONIC: c_int = 6;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub const CLOCK_MONOTONIC: c_int = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in {
    pub sin_len: u8,
    pub sin_family: u8,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in6 {
    pub sin6_len: u8,
    pub sin6_family: u8,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: c_int,
    pub msg_control: *mut c_void,
    pub msg_controllen: socklen_t,
    pub msg_flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct kevent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: *mut c_void,
    #[cfg(target_os = "freebsd")]
    pub ext: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

extern "C" {
    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn bind(fd: c_int, addr: *const c_void, len: socklen_t) -> c_int;
    pub fn listen(fd: c_int, backlog: c_int) -> c_int;
    pub fn accept(fd: c_int, addr: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn connect(fd: c_int, addr: *const c_void, len: socklen_t) -> c_int;
    pub fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    pub fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    pub fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> isize;
    pub fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> isize;
    pub fn shutdown(fd: c_int, how: c_int) -> c_int;
    pub fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const c_void, len: socklen_t) -> c_int;
    pub fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn getsockname(fd: c_int, addr: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn getpeername(fd: c_int, addr: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub fn kqueue() -> c_int;
    pub fn kevent(kq: c_int, changes: *const kevent, nchanges: c_int, events: *mut kevent, nevents: c_int, timeout: *const timespec) -> c_int;
    pub fn clock_gettime(clock: c_int, ts: *mut timespec) -> c_int;
}
