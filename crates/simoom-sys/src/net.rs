//! Non-blocking TCP and UDP sockets on raw file descriptors (Unix) and `SOCKET`s (Windows).
//!
//! [`Socket`] owns the descriptor and closes it on drop (through std's `OwnedFd` /
//! `OwnedSocket`). Every socket this module creates is non-blocking and close-on-exec
//! (not inheritable on Windows), and on Windows it is created overlapped so IOCP can drive it.
//! Operations that would block return an error of kind [`io::ErrorKind::WouldBlock`].

use crate::os::sys;
use core::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket, OwnedSocket};

/// The raw OS handle of a socket: a file descriptor on Unix, a `SOCKET` on Windows.
#[cfg(unix)]
pub type RawSock = i32;
/// The raw OS handle of a socket: a file descriptor on Unix, a `SOCKET` on Windows.
#[cfg(windows)]
pub type RawSock = usize;

/// An owned, non-blocking socket. Closed on drop.
#[derive(Debug)]
pub struct Socket {
    #[cfg(unix)]
    fd: OwnedFd,
    #[cfg(windows)]
    fd: OwnedSocket,
}

/// Options for [`Socket::tcp_listen`].
#[derive(Clone, Debug)]
pub struct ListenOptions {
    /// Length of the kernel accept queue. The default is [`default_backlog`]: the system's
    /// maximum (`net.core.somaxconn` on Linux, capped at 65535; `SOMAXCONN` on Windows), so a
    /// burst of connections, or 100k idle ones arriving together, isn't dropped.
    pub backlog: i32,
    /// `SO_REUSEPORT` (Linux, BSD): several sockets may bind the same address and the kernel
    /// spreads connections over them. Ignored on Windows.
    pub reuse_port: bool,
    /// Set `TCP_NODELAY` on the listener (Linux and Windows hand it down to accepted sockets).
    pub nodelay: bool,
    /// `IPV6_V6ONLY` for IPv6 addresses; `None` leaves the OS default.
    pub v6_only: Option<bool>,
    /// `SO_RCVBUF`, inherited by accepted sockets.
    pub recv_buffer: Option<usize>,
    /// `SO_SNDBUF`, inherited by accepted sockets.
    pub send_buffer: Option<usize>,
    /// `TCP_DEFER_ACCEPT` (Linux) in seconds: the kernel hands over a connection only once its
    /// first data has arrived (or this long after the handshake), so accepting and reading the
    /// first request take one turn. Only for protocols where the client speaks first (HTTP,
    /// TLS). `None` (the default here) leaves it off; ignored on other systems.
    pub defer_accept: Option<u32>,
}

impl Default for ListenOptions {
    fn default() -> Self {
        ListenOptions { backlog: default_backlog(), reuse_port: false, nodelay: true, v6_only: None, recv_buffer: None, send_buffer: None, defer_accept: None }
    }
}

/// The default listen backlog: the system's maximum accept queue. On Linux that is
/// `/proc/sys/net/core/somaxconn` (read once), capped at 65535, or 4096 if it can't be read; on
/// Windows `SOMAXCONN` (the provider's maximum); elsewhere 65535, which the kernel clamps to its
/// own `somaxconn`.
pub fn default_backlog() -> i32 {
    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::{AtomicI32, Ordering};
        static CACHED: AtomicI32 = AtomicI32::new(0);
        let c = CACHED.load(Ordering::Relaxed);
        if c > 0 {
            return c;
        }
        // A plain read and digit loop: `read_to_string` and `str::parse` cost about 2.5 KB.
        let mut b = [0u8; 24];
        let mut v: i64 = 0;
        for &c in crate::cpu::read_small_bytes("/proc/sys/net/core/somaxconn", &mut b).iter().take_while(|c| c.is_ascii_digit()) {
            v = (v * 10 + i64::from(c - b'0')).min(1 << 20);
        }
        let v = if v > 0 { v.min(65535) as i32 } else { 4096 };
        CACHED.store(v, Ordering::Relaxed);
        v
    }
    #[cfg(windows)]
    {
        sys::SOMAXCONN
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        65535
    }
}

/// Options for [`Socket::udp_bind`].
#[derive(Clone, Debug, Default)]
pub struct UdpOptions {
    /// `SO_REUSEPORT` (Linux, BSD): one socket per loop on the same address.
    pub reuse_port: bool,
    /// Generic receive offload: the kernel may hand over several datagrams from one peer as
    /// one buffer with a segment size (Linux `UDP_GRO`, Windows URO). Off by default.
    pub gro: bool,
    /// Report the local destination address of each datagram (`IP_PKTINFO`/`IPV6_RECVPKTINFO`).
    pub pktinfo: bool,
    /// Report the ECN bits of each datagram (`IP_RECVTOS`/`IPV6_RECVTCLASS`, Windows `IP_ECN`).
    pub ecn: bool,
    /// Set the don't-fragment bit (path MTU probing, as QUIC requires).
    pub dont_fragment: bool,
    /// `IPV6_V6ONLY` for IPv6 addresses.
    pub v6_only: Option<bool>,
    /// `SO_RCVBUF`.
    pub recv_buffer: Option<usize>,
    /// `SO_SNDBUF`.
    pub send_buffer: Option<usize>,
}

// ---------------------------------------------------------------------------------------------
// Socket addresses
// ---------------------------------------------------------------------------------------------

/// Storage big enough for any socket address (`sockaddr_storage`).
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct SockAddrBuf {
    pub bytes: [u8; 128],
}

impl SockAddrBuf {
    pub(crate) const fn new() -> SockAddrBuf {
        SockAddrBuf { bytes: [0; 128] }
    }
    pub(crate) fn as_ptr(&self) -> *const c_void {
        self.bytes.as_ptr().cast()
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut c_void {
        self.bytes.as_mut_ptr().cast()
    }
}

/// Encodes `addr` into `out` and returns the address length.
pub(crate) fn encode_addr(addr: &SocketAddr, out: &mut SockAddrBuf) -> u32 {
    out.bytes = [0; 128];
    match addr {
        SocketAddr::V4(a) => {
            let sa = sys::sockaddr_in {
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin_len: core::mem::size_of::<sys::sockaddr_in>() as u8,
                sin_family: sys::AF_INET as _,
                sin_port: a.port().to_be(),
                sin_addr: a.ip().octets(),
                sin_zero: [0; 8],
            };
            let n = core::mem::size_of::<sys::sockaddr_in>();
            // SAFETY: `out` holds 128 bytes and `sa` is a plain C struct of `n` <= 128 bytes; the
            // regions don't overlap.
            unsafe { core::ptr::copy_nonoverlapping((&sa as *const sys::sockaddr_in).cast::<u8>(), out.bytes.as_mut_ptr(), n) };
            n as u32
        }
        SocketAddr::V6(a) => {
            let sa = sys::sockaddr_in6 {
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin6_len: core::mem::size_of::<sys::sockaddr_in6>() as u8,
                sin6_family: sys::AF_INET6 as _,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo().to_be(),
                sin6_addr: a.ip().octets(),
                sin6_scope_id: a.scope_id(),
            };
            let n = core::mem::size_of::<sys::sockaddr_in6>();
            // SAFETY: as above, `n` <= 128.
            unsafe { core::ptr::copy_nonoverlapping((&sa as *const sys::sockaddr_in6).cast::<u8>(), out.bytes.as_mut_ptr(), n) };
            n as u32
        }
    }
}

/// Decodes a socket address written by the OS. Returns `None` for other families.
pub(crate) fn decode_addr(buf: &SockAddrBuf, len: usize) -> Option<SocketAddr> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    let family = buf.bytes[1] as i32;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    let family = u16::from_ne_bytes([buf.bytes[0], buf.bytes[1]]) as i32;
    if family == sys::AF_INET && len >= core::mem::size_of::<sys::sockaddr_in>() {
        let port = u16::from_be_bytes([buf.bytes[2], buf.bytes[3]]);
        let ip = Ipv4Addr::new(buf.bytes[4], buf.bytes[5], buf.bytes[6], buf.bytes[7]);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if family == sys::AF_INET6 && len >= core::mem::size_of::<sys::sockaddr_in6>() {
        let port = u16::from_be_bytes([buf.bytes[2], buf.bytes[3]]);
        let flow = u32::from_be_bytes([buf.bytes[4], buf.bytes[5], buf.bytes[6], buf.bytes[7]]);
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&buf.bytes[8..24]);
        let scope = u32::from_ne_bytes([buf.bytes[24], buf.bytes[25], buf.bytes[26], buf.bytes[27]]);
        Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, flow, scope)))
    } else {
        None
    }
}

pub(crate) fn family_of(addr: &SocketAddr) -> i32 {
    if addr.is_ipv4() {
        sys::AF_INET
    } else {
        sys::AF_INET6
    }
}

// ---------------------------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) fn last_error() -> io::Error {
    io::Error::last_os_error()
}

#[cfg(windows)]
pub(crate) fn last_error() -> io::Error {
    // SAFETY: reads the calling thread's last Winsock error; no arguments.
    io::Error::from_raw_os_error(unsafe { sys::WSAGetLastError() })
}

#[cfg(unix)]
fn cvt(r: i32) -> io::Result<i32> {
    if r < 0 {
        Err(last_error())
    } else {
        Ok(r)
    }
}

#[cfg(unix)]
fn cvt_size(r: isize) -> io::Result<usize> {
    if r < 0 {
        Err(last_error())
    } else {
        Ok(r as usize)
    }
}

#[cfg(windows)]
fn cvt(r: i32) -> io::Result<i32> {
    if r == sys::SOCKET_ERROR {
        Err(last_error())
    } else {
        Ok(r)
    }
}

/// Makes sure Winsock is initialised (std does this lazily for its own sockets only).
#[cfg(windows)]
pub(crate) fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: WSADATA is a plain output struct; WSAStartup may be called any number of times.
        unsafe {
            let mut data: sys::WSADATA = core::mem::zeroed();
            sys::WSAStartup(0x202, &mut data);
        }
    });
}

// ---------------------------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------------------------

impl Socket {
    /// Creates a raw non-blocking socket.
    pub fn new(family: i32, ty: i32) -> io::Result<Socket> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: plain syscall with integer arguments; the result is checked.
            let fd = cvt(unsafe { sys::socket(family, ty | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC, 0) })?;
            // SAFETY: `fd` is a fresh descriptor that nothing else owns.
            Ok(Socket { fd: unsafe { OwnedFd::from_raw_fd(fd) } })
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        {
            // SAFETY: plain syscall with integer arguments; the result is checked.
            let fd = cvt(unsafe { sys::socket(family, ty, 0) })?;
            // SAFETY: `fd` is a fresh descriptor that nothing else owns.
            let s = Socket { fd: unsafe { OwnedFd::from_raw_fd(fd) } };
            // SAFETY: fcntl on a descriptor we own.
            cvt(unsafe { sys::fcntl(fd, sys::F_SETFD, sys::FD_CLOEXEC) })?;
            s.set_nonblocking(true)?;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_NOSIGPIPE, 1)?;
            Ok(s)
        }
        #[cfg(windows)]
        {
            init();
            // SAFETY: plain Winsock call; the result is checked against INVALID_SOCKET.
            let raw = unsafe {
                sys::WSASocketW(family, ty, 0, core::ptr::null_mut(), 0, sys::WSA_FLAG_OVERLAPPED | sys::WSA_FLAG_NO_HANDLE_INHERIT)
            };
            if raw == sys::INVALID_SOCKET {
                return Err(last_error());
            }
            // SAFETY: `raw` is a fresh socket that nothing else owns.
            let s = Socket { fd: unsafe { OwnedSocket::from_raw_socket(raw as u64) } };
            s.set_nonblocking(true)?;
            Ok(s)
        }
    }

    /// A non-blocking TCP listener bound to `addr`.
    pub fn tcp_listen(addr: SocketAddr, opts: &ListenOptions) -> io::Result<Socket> {
        let s = Socket::new(family_of(&addr), sys::SOCK_STREAM)?;
        #[cfg(unix)]
        s.setsockopt_int(sys::SOL_SOCKET, sys::SO_REUSEADDR, 1)?;
        #[cfg(unix)]
        if opts.reuse_port {
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_REUSEPORT, 1)?;
        }
        #[cfg(windows)]
        s.setsockopt_int(sys::SOL_SOCKET, sys::SO_EXCLUSIVEADDRUSE, 1)?;
        if let (Some(v6), true) = (opts.v6_only, addr.is_ipv6()) {
            s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_V6ONLY, v6 as i32)?;
        }
        if let Some(n) = opts.recv_buffer {
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_RCVBUF, n as i32)?;
        }
        if let Some(n) = opts.send_buffer {
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_SNDBUF, n as i32)?;
        }
        if opts.nodelay {
            s.set_nodelay(true)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(secs) = opts.defer_accept {
            s.setsockopt_int(sys::IPPROTO_TCP, sys::TCP_DEFER_ACCEPT, secs.min(i32::MAX as u32) as i32)?;
        }
        s.bind(&addr)?;
        // SAFETY: listen on a bound socket we own.
        cvt(unsafe { sys::listen(s.raw() as _, opts.backlog) })?;
        Ok(s)
    }

    /// A non-blocking UDP socket bound to `addr`.
    pub fn udp_bind(addr: SocketAddr, opts: &UdpOptions) -> io::Result<Socket> {
        let s = Socket::new(family_of(&addr), sys::SOCK_DGRAM)?;
        #[cfg(unix)]
        if opts.reuse_port {
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_REUSEADDR, 1)?;
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_REUSEPORT, 1)?;
        }
        if let (Some(v6), true) = (opts.v6_only, addr.is_ipv6()) {
            s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_V6ONLY, v6 as i32)?;
        }
        if let Some(n) = opts.recv_buffer {
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_RCVBUF, n as i32)?;
        }
        if let Some(n) = opts.send_buffer {
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_SNDBUF, n as i32)?;
        }
        crate::udp::configure(&s, addr.is_ipv6(), opts)?;
        s.bind(&addr)?;
        Ok(s)
    }

    /// Connects a TCP socket to `addr`, waiting for the handshake, and returns it non-blocking
    /// with `TCP_NODELAY` set. Meant for clients and tests.
    pub fn tcp_connect(addr: SocketAddr) -> io::Result<Socket> {
        let std = std::net::TcpStream::connect(addr)?;
        std.set_nodelay(true)?;
        std.set_nonblocking(true)?;
        Ok(Socket::from(std))
    }

    fn bind(&self, addr: &SocketAddr) -> io::Result<()> {
        let mut buf = SockAddrBuf::new();
        let len = encode_addr(addr, &mut buf);
        // SAFETY: `buf` holds a valid socket address of `len` bytes.
        cvt(unsafe { sys::bind(self.raw() as _, buf.as_ptr(), len as _) })?;
        Ok(())
    }

    /// Accepts one pending connection without blocking. The new socket is non-blocking.
    pub fn accept(&self) -> io::Result<(Socket, Option<SocketAddr>)> {
        let mut buf = SockAddrBuf::new();
        #[cfg(target_os = "linux")]
        {
            let mut len: sys::socklen_t = 128;
            // SAFETY: `buf` has room for 128 bytes and `len` says so.
            let fd = cvt(unsafe { sys::accept4(self.raw(), buf.as_mut_ptr(), &mut len, sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC) })?;
            // SAFETY: `fd` is a fresh descriptor that nothing else owns.
            let s = Socket { fd: unsafe { OwnedFd::from_raw_fd(fd) } };
            Ok((s, decode_addr(&buf, len as usize)))
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        {
            let mut len: sys::socklen_t = 128;
            // SAFETY: `buf` has room for 128 bytes and `len` says so.
            let fd = cvt(unsafe { sys::accept(self.raw(), buf.as_mut_ptr(), &mut len) })?;
            // SAFETY: `fd` is a fresh descriptor that nothing else owns.
            let s = Socket { fd: unsafe { OwnedFd::from_raw_fd(fd) } };
            // SAFETY: fcntl on a descriptor we own.
            cvt(unsafe { sys::fcntl(fd, sys::F_SETFD, sys::FD_CLOEXEC) })?;
            s.set_nonblocking(true)?;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            s.setsockopt_int(sys::SOL_SOCKET, sys::SO_NOSIGPIPE, 1)?;
            Ok((s, decode_addr(&buf, len as usize)))
        }
        #[cfg(windows)]
        {
            let mut len: i32 = 128;
            // SAFETY: `buf` has room for 128 bytes and `len` says so.
            let raw = unsafe { sys::accept(self.raw(), buf.as_mut_ptr(), &mut len) };
            if raw == sys::INVALID_SOCKET {
                return Err(last_error());
            }
            // SAFETY: `raw` is a fresh socket that nothing else owns.
            let s = Socket { fd: unsafe { OwnedSocket::from_raw_socket(raw as u64) } };
            s.set_nonblocking(true)?;
            Ok((s, decode_addr(&buf, len as usize)))
        }
    }

    /// Receives into `buf` without blocking. `Ok(0)` means the peer closed its side.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            // SAFETY: `buf` is a valid writable region of `buf.len()` bytes.
            cvt_size(unsafe { sys::recv(self.raw(), buf.as_mut_ptr().cast(), buf.len(), 0) })
        }
        #[cfg(windows)]
        {
            let len = buf.len().min(i32::MAX as usize) as i32;
            // SAFETY: `buf` is a valid writable region of at least `len` bytes.
            let n = unsafe { sys::recv(self.raw(), buf.as_mut_ptr(), len, 0) };
            if n < 0 {
                Err(last_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    /// Receives into the spare capacity of `buf` and extends its length by the bytes read.
    pub fn recv_into(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let spare = buf.capacity() - buf.len();
        if spare == 0 {
            return Ok(0);
        }
        let n;
        #[cfg(unix)]
        {
            // SAFETY: the spare capacity is allocated memory owned by `buf`; recv writes at most
            // `spare` bytes into it.
            n = cvt_size(unsafe { sys::recv(self.raw(), buf.as_mut_ptr().add(buf.len()).cast(), spare, 0) })?;
        }
        #[cfg(windows)]
        {
            let len = spare.min(i32::MAX as usize) as i32;
            // SAFETY: as above.
            let r = unsafe { sys::recv(self.raw(), buf.as_mut_ptr().add(buf.len()), len, 0) };
            if r < 0 {
                return Err(last_error());
            }
            n = r as usize;
        }
        // SAFETY: the OS initialised `n` <= spare bytes after the old length.
        unsafe { buf.set_len(buf.len() + n) };
        Ok(n)
    }

    /// Sends from `buf` without blocking (never raises `SIGPIPE`).
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            // SAFETY: `buf` is a valid readable region.
            cvt_size(unsafe { sys::send(self.raw(), buf.as_ptr().cast(), buf.len(), sys::MSG_NOSIGNAL) })
        }
        #[cfg(windows)]
        {
            let len = buf.len().min(i32::MAX as usize) as i32;
            // SAFETY: `buf` is a valid readable region of at least `len` bytes.
            let n = unsafe { sys::send(self.raw(), buf.as_ptr(), len, 0) };
            if n < 0 {
                Err(last_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    /// Sends several buffers with one call (`sendmsg` / `WSASend`) without blocking. At most
    /// 64 buffers are sent per call.
    pub fn send_vectored(&self, bufs: &[&[u8]]) -> io::Result<usize> {
        const MAX: usize = 64;
        let n = bufs.len().min(MAX);
        #[cfg(unix)]
        {
            let mut iov = [sys::iovec { iov_base: core::ptr::null_mut(), iov_len: 0 }; MAX];
            for (v, b) in iov.iter_mut().zip(bufs) {
                *v = sys::iovec { iov_base: b.as_ptr() as *mut c_void, iov_len: b.len() };
            }
            // SAFETY: an all-zero msghdr is valid (no name, no control).
            let mut msg: sys::msghdr = unsafe { core::mem::zeroed() };
            msg.msg_iov = iov.as_mut_ptr();
            msg.msg_iovlen = n as _;
            // SAFETY: `msg` points at `n` iovecs that describe live, readable slices.
            cvt_size(unsafe { sys::sendmsg(self.raw(), &msg, sys::MSG_NOSIGNAL) })
        }
        #[cfg(windows)]
        {
            let mut wb = [sys::WSABUF { len: 0, buf: core::ptr::null_mut() }; MAX];
            for (v, b) in wb.iter_mut().zip(bufs) {
                *v = sys::WSABUF { len: b.len().min(u32::MAX as usize) as u32, buf: b.as_ptr() as *mut u8 };
            }
            let mut sent = 0u32;
            // SAFETY: `wb` describes `n` live slices; a null OVERLAPPED makes this a plain
            // non-blocking call that completes before returning.
            let r = unsafe { sys::WSASend(self.raw(), wb.as_ptr(), n as u32, &mut sent, 0, core::ptr::null_mut(), core::ptr::null_mut()) };
            if r != 0 {
                Err(last_error())
            } else {
                Ok(sent as usize)
            }
        }
    }

    /// Shuts down one or both directions.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        #[cfg(unix)]
        let h = match how {
            Shutdown::Read => sys::SHUT_RD,
            Shutdown::Write => sys::SHUT_WR,
            Shutdown::Both => sys::SHUT_RDWR,
        };
        #[cfg(windows)]
        let h = match how {
            Shutdown::Read => sys::SD_RECEIVE,
            Shutdown::Write => sys::SD_SEND,
            Shutdown::Both => sys::SD_BOTH,
        };
        // SAFETY: shutdown on a socket we own.
        cvt(unsafe { sys::shutdown(self.raw() as _, h) })?;
        Ok(())
    }

    /// Sets or clears `TCP_NODELAY`.
    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.setsockopt_int(sys::IPPROTO_TCP, sys::TCP_NODELAY, on as i32)
    }

    /// Whether `TCP_NODELAY` is set.
    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(self.getsockopt_int(sys::IPPROTO_TCP, sys::TCP_NODELAY)? != 0)
    }

    /// Switches non-blocking mode.
    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            const FIONBIO: core::ffi::c_ulong = 0x5421;
            extern "C" {
                fn ioctl(fd: i32, req: core::ffi::c_ulong, ...) -> i32;
            }
            let mut v: i32 = on as i32;
            // SAFETY: FIONBIO takes a pointer to an int.
            cvt(unsafe { ioctl(self.raw(), FIONBIO, &mut v as *mut i32) })?;
            Ok(())
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        {
            // SAFETY: fcntl on a descriptor we own.
            let fl = cvt(unsafe { sys::fcntl(self.raw(), sys::F_GETFL) })?;
            let nfl = if on { fl | sys::O_NONBLOCK } else { fl & !sys::O_NONBLOCK };
            // SAFETY: as above.
            cvt(unsafe { sys::fcntl(self.raw(), sys::F_SETFL, nfl) })?;
            Ok(())
        }
        #[cfg(windows)]
        {
            let mut v: u32 = on as u32;
            // SAFETY: FIONBIO takes a pointer to a u_long.
            cvt(unsafe { sys::ioctlsocket(self.raw(), sys::FIONBIO, &mut v) })?;
            Ok(())
        }
    }

    /// The local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut buf = SockAddrBuf::new();
        let mut len = 128;
        // SAFETY: `buf` has room for `len` bytes.
        cvt(unsafe { sys::getsockname(self.raw() as _, buf.as_mut_ptr(), &mut len) })?;
        decode_addr(&buf, len as usize).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown address family"))
    }

    /// The peer address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        let mut buf = SockAddrBuf::new();
        let mut len = 128;
        // SAFETY: `buf` has room for `len` bytes.
        cvt(unsafe { sys::getpeername(self.raw() as _, buf.as_mut_ptr(), &mut len) })?;
        decode_addr(&buf, len as usize).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown address family"))
    }

    /// Reads and clears the pending socket error (`SO_ERROR`).
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let e = self.getsockopt_int(sys::SOL_SOCKET, sys::SO_ERROR)?;
        Ok(if e == 0 { None } else { Some(io::Error::from_raw_os_error(e)) })
    }

    /// Sets an integer socket option.
    pub fn setsockopt_int(&self, level: i32, name: i32, value: i32) -> io::Result<()> {
        // SAFETY: passes a pointer to a live i32 and its size.
        cvt(unsafe { sys::setsockopt(self.raw() as _, level, name, (&value as *const i32).cast(), 4) })?;
        Ok(())
    }

    /// Reads an integer socket option.
    pub fn getsockopt_int(&self, level: i32, name: i32) -> io::Result<i32> {
        let mut v: i32 = 0;
        let mut len = 4;
        // SAFETY: passes a pointer to a live i32 and its size.
        cvt(unsafe { sys::getsockopt(self.raw() as _, level, name, (&mut v as *mut i32).cast(), &mut len) })?;
        Ok(v)
    }

    /// The raw handle (still owned by this `Socket`).
    pub fn raw(&self) -> RawSock {
        #[cfg(unix)]
        {
            self.fd.as_raw_fd()
        }
        #[cfg(windows)]
        {
            self.fd.as_raw_socket() as usize
        }
    }

    /// Takes ownership of a raw handle.
    ///
    /// # Safety
    /// `raw` must be an open socket that nothing else owns or will close.
    pub unsafe fn from_raw(raw: RawSock) -> Socket {
        #[cfg(unix)]
        {
            // SAFETY: guaranteed by the caller.
            Socket { fd: unsafe { OwnedFd::from_raw_fd(raw) } }
        }
        #[cfg(windows)]
        {
            // SAFETY: guaranteed by the caller.
            Socket { fd: unsafe { OwnedSocket::from_raw_socket(raw as u64) } }
        }
    }

    /// Gives up ownership of the raw handle.
    pub fn into_raw(self) -> RawSock {
        #[cfg(unix)]
        {
            self.fd.into_raw_fd()
        }
        #[cfg(windows)]
        {
            self.fd.into_raw_socket() as usize
        }
    }

    /// Converts into a std TCP stream (it stays non-blocking).
    pub fn into_tcp_stream(self) -> std::net::TcpStream {
        std::net::TcpStream::from(self.fd)
    }

    /// Converts into a std TCP listener (it stays non-blocking).
    pub fn into_tcp_listener(self) -> std::net::TcpListener {
        std::net::TcpListener::from(self.fd)
    }

    /// Converts into a std UDP socket (it stays non-blocking).
    pub fn into_udp_socket(self) -> std::net::UdpSocket {
        std::net::UdpSocket::from(self.fd)
    }

    /// An independent handle to the same socket (`dup` / `WSADuplicateSocket`).
    pub fn try_clone(&self) -> io::Result<Socket> {
        Ok(Socket { fd: self.fd.try_clone()? })
    }
}

macro_rules! from_std {
    ($t:ty) => {
        impl From<$t> for Socket {
            /// Takes over a std socket. Call `set_nonblocking(true)` on it first if it will be
            /// driven by an event loop.
            fn from(s: $t) -> Socket {
                #[cfg(unix)]
                {
                    Socket { fd: OwnedFd::from(s) }
                }
                #[cfg(windows)]
                {
                    Socket { fd: OwnedSocket::from(s) }
                }
            }
        }
    };
}
from_std!(std::net::TcpStream);
from_std!(std::net::TcpListener);
from_std!(std::net::UdpSocket);

/// The unspecified address of the same family as `addr` (port 0).
/// Grows the process's file descriptor table to hold at least `n` descriptors (capped at the
/// soft `RLIMIT_NOFILE`), by duplicating a descriptor to slot `n - 1` and closing it again.
///
/// Linux grows the table in steps (64, 128, 256...), and once the process has more than one
/// thread each step waits for an RCU grace period (`synchronize_rcu` in `expand_fdtable`):
/// 10-30 ms on a VM, on whichever thread opens the descriptor that crosses the step. Called
/// before the loop threads exist, the growth is a plain reallocation. The table costs 8 bytes a
/// slot of kernel memory (8 KiB for 1024). Returns the size reserved; elsewhere a no-op that
/// returns 0.
pub fn reserve_descriptors(n: usize) -> usize {
    #[cfg(target_os = "linux")]
    {
        let mut lim = sys::rlimit::default();
        // SAFETY: getrlimit writes one rlimit.
        let soft = if unsafe { sys::getrlimit(sys::RLIMIT_NOFILE, &mut lim) } == 0 { lim.rlim_cur } else { 1024 };
        let n = (n as u64).min(soft).min(i32::MAX as u64) as i32;
        if n < 2 {
            return 0;
        }
        // SAFETY: duplicates standard error (or, if it is closed, fails harmlessly) to the
        // lowest free slot at or above n - 1; the result is a fresh descriptor we own.
        let fd = unsafe { sys::fcntl(2, sys::F_DUPFD_CLOEXEC, n - 1) };
        if fd < 0 {
            return 0;
        }
        // SAFETY: `fd` is the fresh descriptor from above; nothing else owns it.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
        n as usize
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = n;
        0
    }
}

pub fn unspecified_like(addr: &SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bug 19: the descriptor table is grown before the loop threads exist (no RCU stall on a
    // loop thread later); the next descriptors still come from the bottom of the table.
    #[cfg(target_os = "linux")]
    #[test]
    fn reserve_descriptors_grows_the_table() {
        let got = reserve_descriptors(512);
        assert!(got == 0 || got >= 256, "{got}");
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!((s.as_raw_fd() as usize) < 256, "a fresh descriptor went to the top: {}", s.as_raw_fd());
        assert_eq!(reserve_descriptors(0), 0);
    }
    use std::io::{Read, Write};

    #[test]
    fn address_round_trip() {
        for a in ["127.0.0.1:8080", "[::1]:443", "[fe80::1%3]:9", "0.0.0.0:0"] {
            let addr: SocketAddr = a.parse().unwrap();
            let mut buf = SockAddrBuf::new();
            let len = encode_addr(&addr, &mut buf);
            assert_eq!(decode_addr(&buf, len as usize), Some(addr));
        }
    }

    #[test]
    fn listen_accept_send_recv_v4_and_v6() {
        for host in ["127.0.0.1:0", "[::1]:0"] {
            let l = match Socket::tcp_listen(host.parse().unwrap(), &ListenOptions::default()) {
                Ok(l) => l,
                Err(_) if host.starts_with('[') => continue, // no IPv6 loopback on this machine
                Err(e) => panic!("{e}"),
            };
            assert!(matches!(l.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
            let addr = l.local_addr().unwrap();
            let mut c = std::net::TcpStream::connect(addr).unwrap();
            let (s, peer) = loop {
                match l.accept() {
                    Ok(x) => break x,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                    Err(e) => panic!("{e}"),
                }
            };
            assert_eq!(peer, Some(c.local_addr().unwrap()));
            assert_eq!(s.peer_addr().unwrap(), c.local_addr().unwrap());
            assert!(s.nodelay().unwrap(), "TCP_NODELAY is handed down from the listener");
            c.write_all(b"hello").unwrap();
            let mut buf = Vec::with_capacity(64);
            loop {
                match s.recv_into(&mut buf) {
                    Ok(_) if buf.len() >= 5 => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                    Err(e) => panic!("{e}"),
                }
            }
            assert_eq!(buf, b"hello");
            assert_eq!(s.send_vectored(&[b"wor", b"ld", b"!"]).unwrap(), 6);
            let mut got = [0u8; 6];
            c.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"world!");
            s.shutdown(Shutdown::Write).unwrap();
            assert_eq!(c.read(&mut got).unwrap(), 0);
            drop(c);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn reuse_port_lets_two_listeners_share_an_address() {
        let o = ListenOptions { reuse_port: true, ..Default::default() };
        let a = Socket::tcp_listen("127.0.0.1:0".parse().unwrap(), &o).unwrap();
        let b = Socket::tcp_listen(a.local_addr().unwrap(), &o).unwrap();
        assert_eq!(a.local_addr().unwrap(), b.local_addr().unwrap());
    }

    #[test]
    fn std_conversions() {
        let l = Socket::tcp_listen("127.0.0.1:0".parse().unwrap(), &ListenOptions::default()).unwrap();
        let addr = l.local_addr().unwrap();
        let std_l = l.into_tcp_listener();
        assert_eq!(std_l.local_addr().unwrap(), addr);
        let back = Socket::from(std_l);
        assert_eq!(back.local_addr().unwrap(), addr);
        let c = Socket::tcp_connect(addr).unwrap();
        assert!(c.nodelay().unwrap());
        assert!(c.take_error().unwrap().is_none());
    }
}
