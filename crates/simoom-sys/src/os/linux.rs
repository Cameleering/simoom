//! Raw Linux declarations: libc functions that std already links, constants and structures.
//! Values are for x86-64 and AArch64 (the generic syscall ABI); both share every number used
//! here except the layout of `epoll_event`, which is packed on x86-64.

#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_int, c_long, c_uint, c_void};

pub type socklen_t = u32;

pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 10;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_NONBLOCK: c_int = 0o4000;
pub const SOCK_CLOEXEC: c_int = 0o2000000;

pub const SOL_SOCKET: c_int = 1;
pub const SO_REUSEADDR: c_int = 2;
pub const SO_ERROR: c_int = 4;
pub const SO_SNDBUF: c_int = 7;
pub const SO_RCVBUF: c_int = 8;
pub const SO_REUSEPORT: c_int = 15;

pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IPV6: c_int = 41;
pub const TCP_NODELAY: c_int = 1;
pub const TCP_DEFER_ACCEPT: c_int = 9;
pub const IP_TOS: c_int = 1;
pub const IP_PKTINFO: c_int = 8;
pub const IP_MTU_DISCOVER: c_int = 10;
pub const IP_RECVTOS: c_int = 13;
pub const IP_PMTUDISC_PROBE: c_int = 3;
pub const IPV6_MTU_DISCOVER: c_int = 23;
pub const IPV6_V6ONLY: c_int = 26;
pub const IPV6_RECVPKTINFO: c_int = 49;
pub const IPV6_PKTINFO: c_int = 50;
pub const IPV6_RECVTCLASS: c_int = 66;
pub const IPV6_TCLASS: c_int = 67;
pub const UDP_SEGMENT: c_int = 103;
pub const UDP_GRO: c_int = 104;

pub const MSG_TRUNC: c_int = 0x20;
pub const MSG_CTRUNC: c_int = 0x8;
pub const MSG_DONTWAIT: c_int = 0x40;
pub const MSG_NOSIGNAL: c_int = 0x4000;
pub const MSG_WAITALL: c_int = 0x100;

pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;
pub const SHUT_RDWR: c_int = 2;

pub const EPOLL_CLOEXEC: c_int = 0o2000000;
pub const EPOLL_CTL_ADD: c_int = 1;
pub const EPOLL_CTL_DEL: c_int = 2;
pub const EPOLL_CTL_MOD: c_int = 3;
pub const EPOLLIN: u32 = 0x1;
pub const EPOLLOUT: u32 = 0x4;
pub const EPOLLERR: u32 = 0x8;
pub const EPOLLHUP: u32 = 0x10;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLET: u32 = 1 << 31;

pub const EFD_CLOEXEC: c_int = 0o2000000;
pub const EFD_NONBLOCK: c_int = 0o4000;

pub const CLOCK_MONOTONIC: c_int = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
pub const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
pub const CLOCK_MONOTONIC_COARSE: c_int = 6;

pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const MAP_SHARED: c_int = 1;
pub const MAP_PRIVATE: c_int = 2;
pub const MAP_ANONYMOUS: c_int = 0x20;
pub const MAP_POPULATE: c_int = 0x8000;
pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

pub const SYS_IO_URING_SETUP: c_long = 425;
pub const SYS_IO_URING_ENTER: c_long = 426;
pub const SYS_IO_URING_REGISTER: c_long = 427;

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EINTR: i32 = 4;
pub const EAGAIN: i32 = 11;
pub const EBUSY: i32 = 16;
pub const EINVAL: i32 = 22;
pub const ENOSYS: i32 = 38;
pub const ETIME: i32 = 62;
pub const ENOBUFS: i32 = 105;
pub const EALREADY: i32 = 114;
pub const ECANCELED: i32 = 125;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in_addr {
    pub s_addr: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
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
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct mmsghdr {
    pub msg_hdr: msghdr,
    pub msg_len: c_uint,
}

#[repr(C)]
pub struct cmsghdr {
    pub cmsg_len: usize,
    pub cmsg_level: c_int,
    pub cmsg_type: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in_pktinfo {
    pub ipi_ifindex: c_int,
    pub ipi_spec_dst: [u8; 4],
    pub ipi_addr: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in6_pktinfo {
    pub ipi6_addr: [u8; 16],
    pub ipi6_ifindex: c_uint,
}

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
pub struct epoll_event {
    pub events: u32,
    pub data: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

pub const RLIMIT_NOFILE: c_int = 7;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

extern "C" {
    pub fn getrlimit(resource: c_int, rlim: *mut rlimit) -> c_int;
    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn bind(fd: c_int, addr: *const c_void, len: socklen_t) -> c_int;
    pub fn listen(fd: c_int, backlog: c_int) -> c_int;
    pub fn accept4(fd: c_int, addr: *mut c_void, len: *mut socklen_t, flags: c_int) -> c_int;
    pub fn connect(fd: c_int, addr: *const c_void, len: socklen_t) -> c_int;
    pub fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    pub fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    pub fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> isize;
    pub fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> isize;
    pub fn recvmmsg(fd: c_int, msgs: *mut mmsghdr, n: c_uint, flags: c_int, timeout: *mut timespec) -> c_int;
    pub fn sendmmsg(fd: c_int, msgs: *mut mmsghdr, n: c_uint, flags: c_int) -> c_int;
    pub fn shutdown(fd: c_int, how: c_int) -> c_int;
    pub fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const c_void, len: socklen_t) -> c_int;
    pub fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn getsockname(fd: c_int, addr: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn getpeername(fd: c_int, addr: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    pub fn write(fd: c_int, buf: *const c_void, len: usize) -> isize;
    pub fn epoll_create1(flags: c_int) -> c_int;
    pub fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut epoll_event) -> c_int;
    pub fn epoll_wait(epfd: c_int, evs: *mut epoll_event, max: c_int, timeout: c_int) -> c_int;
    pub fn eventfd(init: c_uint, flags: c_int) -> c_int;
    pub fn syscall(n: c_long, ...) -> c_long;
    pub fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void;
    pub fn munmap(addr: *mut c_void, len: usize) -> c_int;
    pub fn clock_gettime(clock: c_int, ts: *mut timespec) -> c_int;
    pub fn sched_getaffinity(pid: c_int, size: usize, mask: *mut u8) -> c_int;
    pub fn sched_setaffinity(pid: c_int, size: usize, mask: *const u8) -> c_int;
}
