//! Batched UDP I/O with per-datagram metadata: `recvmmsg`/`sendmmsg` on Linux with GRO/GSO
//! (`UDP_GRO`/`UDP_SEGMENT`), ECN and packet-info control messages; `WSARecvMsg`/`WSASendMsg`
//! on Windows with URO/USO, ECN and packet info; plain `recvmsg`/`sendmsg` on macOS and BSD
//! (no control messages there yet).

use crate::net::{decode_addr, encode_addr, SockAddrBuf, Socket, UdpOptions};
use crate::os::sys;
#[cfg(not(windows))]
use core::ffi::c_void;
use std::io;
#[cfg(any(target_os = "linux", windows))]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// What the OS reported about one received datagram (or one GRO batch of datagrams).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvMeta {
    /// The sender.
    pub peer: SocketAddr,
    /// Bytes received into the buffer.
    pub len: usize,
    /// With GRO, the buffer holds several datagrams of this size (the last may be shorter).
    /// Equal to `len` when the buffer holds one datagram.
    pub segment_size: usize,
    /// The ECN bits (0..=3) when ECN reporting is on, else 0.
    pub ecn: u8,
    /// The local address the datagram was sent to, when packet info is on.
    pub local_ip: Option<IpAddr>,
    /// The datagram did not fit the buffer and was cut.
    pub truncated: bool,
}

impl RecvMeta {
    fn empty() -> RecvMeta {
        RecvMeta {
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            len: 0,
            segment_size: 0,
            ecn: 0,
            local_ip: None,
            truncated: false,
        }
    }
}

impl Default for RecvMeta {
    fn default() -> Self {
        RecvMeta::empty()
    }
}

/// One datagram (or, with `segment_size`, a GSO batch of datagrams) to send.
#[derive(Clone, Copy, Debug)]
pub struct Transmit<'a> {
    /// The destination.
    pub peer: SocketAddr,
    /// The payload. With `segment_size` set it is cut into datagrams of that size by the
    /// kernel (Linux GSO, Windows USO); elsewhere this module cuts it itself.
    pub data: &'a [u8],
    /// Segment size for GSO, or 0 for one datagram.
    pub segment_size: usize,
    /// ECN bits to set (0..=3).
    pub ecn: u8,
    /// Source address to send from (multi-homed hosts), when packet info is on.
    pub src_ip: Option<IpAddr>,
}

/// How many datagrams one batched call handles at most.
pub const BATCH: usize = 32;

#[cfg(any(target_os = "linux", windows))]
const CONTROL: usize = 128;

#[cfg(any(target_os = "linux", windows))]
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct Control([u8; CONTROL]);

/// Applies the receive options of `opts` to a fresh UDP socket.
pub(crate) fn configure(s: &Socket, v6: bool, opts: &UdpOptions) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if opts.gro {
            // UDP_GRO is 5.0+; ignore failure on older kernels.
            let _ = s.setsockopt_int(sys::IPPROTO_UDP, sys::UDP_GRO, 1);
        }
        if opts.pktinfo {
            s.setsockopt_int(sys::IPPROTO_IP, sys::IP_PKTINFO, 1).ok();
            if v6 {
                s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_RECVPKTINFO, 1)?;
            }
        }
        if opts.ecn {
            s.setsockopt_int(sys::IPPROTO_IP, sys::IP_RECVTOS, 1).ok();
            if v6 {
                s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_RECVTCLASS, 1)?;
            }
        }
        if opts.dont_fragment {
            s.setsockopt_int(sys::IPPROTO_IP, sys::IP_MTU_DISCOVER, sys::IP_PMTUDISC_PROBE).ok();
            if v6 {
                s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_MTU_DISCOVER, sys::IP_PMTUDISC_PROBE)?;
            }
        }
    }
    #[cfg(windows)]
    {
        // A UDP socket on Windows reports an ICMP "port unreachable" for an earlier send as an
        // error on the next receive (WSAECONNRESET); a server must not see that.
        let mut off: u32 = 0;
        let mut ret = 0u32;
        // SAFETY: SIO_UDP_CONNRESET takes a BOOL input; no output, no overlapped.
        unsafe {
            sys::WSAIoctl(s.raw(), sys::SIO_UDP_CONNRESET, (&mut off as *mut u32).cast(), 4, core::ptr::null_mut(), 0, &mut ret, core::ptr::null_mut(), core::ptr::null_mut());
        }
        if opts.gro {
            let _ = s.setsockopt_int(sys::IPPROTO_UDP, sys::UDP_RECV_MAX_COALESCED_SIZE, 65527);
        }
        if opts.pktinfo {
            s.setsockopt_int(sys::IPPROTO_IP, sys::IP_PKTINFO, 1).ok();
            if v6 {
                s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_PKTINFO, 1)?;
            }
        }
        if opts.ecn {
            s.setsockopt_int(sys::IPPROTO_IP, sys::IP_ECN, 1).ok();
            if v6 {
                s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_ECN, 1).ok();
            }
        }
        if opts.dont_fragment {
            s.setsockopt_int(sys::IPPROTO_IP, sys::IP_DONTFRAGMENT, 1).ok();
            if v6 {
                s.setsockopt_int(sys::IPPROTO_IPV6, sys::IPV6_DONTFRAG, 1).ok();
            }
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (s, v6, opts);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Control messages (Linux and Windows share the 64-bit layout: a 16-byte header, 8-byte align)
// ---------------------------------------------------------------------------------------------

#[cfg(any(target_os = "linux", windows))]
mod cmsg {
    pub const HDR: usize = 16;
    pub const fn align(n: usize) -> usize {
        (n + 7) & !7
    }
    pub const fn space(n: usize) -> usize {
        HDR + align(n)
    }

    /// Walks the control buffer and calls `f(level, type, data)` for each message.
    pub fn parse(buf: &[u8], mut f: impl FnMut(i32, i32, &[u8])) {
        let mut off = 0;
        while off + HDR <= buf.len() {
            let len = usize::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
            let level = i32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
            let ty = i32::from_ne_bytes(buf[off + 12..off + 16].try_into().unwrap());
            if len < HDR || off + len > buf.len() {
                break;
            }
            f(level, ty, &buf[off + HDR..off + len]);
            off += align(len);
        }
    }

    /// Appends one control message; returns the new used length.
    pub fn push(buf: &mut [u8], used: usize, level: i32, ty: i32, data: &[u8]) -> usize {
        let total = space(data.len());
        if used + total > buf.len() {
            return used;
        }
        let b = &mut buf[used..used + total];
        b.fill(0);
        b[0..8].copy_from_slice(&(HDR + data.len()).to_ne_bytes());
        b[8..12].copy_from_slice(&level.to_ne_bytes());
        b[12..16].copy_from_slice(&ty.to_ne_bytes());
        b[HDR..HDR + data.len()].copy_from_slice(data);
        used + total
    }
}

#[cfg(target_os = "linux")]
fn apply_cmsg(meta: &mut RecvMeta, level: i32, ty: i32, data: &[u8]) {
    let int = |d: &[u8]| if d.len() >= 4 { i32::from_ne_bytes(d[..4].try_into().unwrap()) } else { d.first().copied().unwrap_or(0) as i32 };
    match (level, ty) {
        (sys::IPPROTO_UDP, sys::UDP_GRO) => meta.segment_size = int(data) as usize,
        (sys::IPPROTO_IP, sys::IP_TOS) => meta.ecn = (data.first().copied().unwrap_or(0)) & 3,
        (sys::IPPROTO_IPV6, sys::IPV6_TCLASS) => meta.ecn = (int(data) & 3) as u8,
        (sys::IPPROTO_IP, sys::IP_PKTINFO) if data.len() >= 12 => {
            meta.local_ip = Some(IpAddr::V4(Ipv4Addr::new(data[8], data[9], data[10], data[11])));
        }
        (sys::IPPROTO_IPV6, sys::IPV6_PKTINFO) if data.len() >= 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&data[..16]);
            meta.local_ip = Some(IpAddr::V6(Ipv6Addr::from(a)));
        }
        _ => {}
    }
}

#[cfg(windows)]
fn apply_cmsg(meta: &mut RecvMeta, level: i32, ty: i32, data: &[u8]) {
    let int = |d: &[u8]| if d.len() >= 4 { i32::from_ne_bytes(d[..4].try_into().unwrap()) } else { 0 };
    match (level, ty) {
        (sys::IPPROTO_UDP, sys::UDP_COALESCED_INFO) => meta.segment_size = int(data) as usize,
        (sys::IPPROTO_IP, sys::IP_ECN) | (sys::IPPROTO_IPV6, sys::IPV6_ECN) => meta.ecn = (int(data) & 3) as u8,
        (sys::IPPROTO_IP, sys::IP_PKTINFO) if data.len() >= 4 => {
            meta.local_ip = Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])));
        }
        (sys::IPPROTO_IPV6, sys::IPV6_PKTINFO) if data.len() >= 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&data[..16]);
            meta.local_ip = Some(IpAddr::V6(Ipv6Addr::from(a)));
        }
        _ => {}
    }
}

/// Builds the control messages for one transmit; returns the used length.
#[cfg(any(target_os = "linux", windows))]
fn build_cmsg(t: &Transmit<'_>, ctl: &mut [u8]) -> usize {
    let mut used = 0;
    if t.segment_size > 0 && t.segment_size < t.data.len() {
        #[cfg(target_os = "linux")]
        {
            used = cmsg::push(ctl, used, sys::IPPROTO_UDP, sys::UDP_SEGMENT, &(t.segment_size as u16).to_ne_bytes());
        }
        #[cfg(windows)]
        {
            used = cmsg::push(ctl, used, sys::IPPROTO_UDP, sys::UDP_SEND_MSG_SIZE, &(t.segment_size as u32).to_ne_bytes());
        }
    }
    if t.ecn != 0 {
        let v = (t.ecn & 3) as i32;
        #[cfg(target_os = "linux")]
        let (l4, t4, l6, t6) = (sys::IPPROTO_IP, sys::IP_TOS, sys::IPPROTO_IPV6, sys::IPV6_TCLASS);
        #[cfg(windows)]
        let (l4, t4, l6, t6) = (sys::IPPROTO_IP, sys::IP_ECN, sys::IPPROTO_IPV6, sys::IPV6_ECN);
        used = if t.peer.is_ipv4() { cmsg::push(ctl, used, l4, t4, &v.to_ne_bytes()) } else { cmsg::push(ctl, used, l6, t6, &v.to_ne_bytes()) };
    }
    match t.src_ip {
        #[cfg(target_os = "linux")]
        Some(IpAddr::V4(a)) => {
            let mut d = [0u8; 12];
            d[4..8].copy_from_slice(&a.octets());
            used = cmsg::push(ctl, used, sys::IPPROTO_IP, sys::IP_PKTINFO, &d);
        }
        #[cfg(windows)]
        Some(IpAddr::V4(a)) => {
            let mut d = [0u8; 8];
            d[..4].copy_from_slice(&a.octets());
            used = cmsg::push(ctl, used, sys::IPPROTO_IP, sys::IP_PKTINFO, &d);
        }
        Some(IpAddr::V6(a)) => {
            let mut d = [0u8; 20];
            d[..16].copy_from_slice(&a.octets());
            used = cmsg::push(ctl, used, sys::IPPROTO_IPV6, sys::IPV6_PKTINFO, &d);
        }
        None => {}
    }
    used
}

// ---------------------------------------------------------------------------------------------
// Windows extension function
// ---------------------------------------------------------------------------------------------

#[cfg(windows)]
pub(crate) fn wsa_recvmsg(s: &Socket) -> io::Result<sys::LPFN_WSARECVMSG> {
    use std::sync::OnceLock;
    static FN: OnceLock<usize> = OnceLock::new();
    if let Some(&f) = FN.get() {
        // SAFETY: the value was produced by WSAIoctl for WSAID_WSARECVMSG below.
        return Ok(unsafe { core::mem::transmute::<usize, sys::LPFN_WSARECVMSG>(f) });
    }
    let mut f: usize = 0;
    let mut ret = 0u32;
    let guid = sys::WSAID_WSARECVMSG;
    // SAFETY: SIO_GET_EXTENSION_FUNCTION_POINTER reads the GUID and writes one pointer.
    let r = unsafe {
        sys::WSAIoctl(
            s.raw(),
            sys::SIO_GET_EXTENSION_FUNCTION_POINTER,
            (&guid as *const sys::GUID).cast(),
            core::mem::size_of::<sys::GUID>() as u32,
            (&mut f as *mut usize).cast(),
            core::mem::size_of::<usize>() as u32,
            &mut ret,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if r != 0 || f == 0 {
        return Err(crate::net::last_error());
    }
    let _ = FN.set(f);
    // SAFETY: `f` is the WSARecvMsg entry point returned by Winsock.
    Ok(unsafe { core::mem::transmute::<usize, sys::LPFN_WSARECVMSG>(f) })
}

/// Parses the result of a `WSARecvMsg` into `meta` (shared with the IOCP driver).
#[cfg(windows)]
pub(crate) fn finish_meta_windows(name: &SockAddrBuf, namelen: i32, control: &[u8], flags: u32, len: usize) -> RecvMeta {
    let mut meta = RecvMeta::empty();
    if let Some(p) = decode_addr(name, namelen.max(0) as usize) {
        meta.peer = p;
    }
    meta.len = len;
    cmsg::parse(control, |l, t, d| apply_cmsg(&mut meta, l, t, d));
    if meta.segment_size == 0 {
        meta.segment_size = len;
    }
    meta.truncated = flags & sys::MSG_TRUNC != 0;
    meta
}

// ---------------------------------------------------------------------------------------------
// Batched calls
// ---------------------------------------------------------------------------------------------

impl Socket {
    /// Receives up to `bufs.len()` (at most [`BATCH`]) datagrams without blocking. Each buffer
    /// is cleared and filled up to its capacity; `meta[i]` describes `bufs[i]`. Returns how many
    /// were received, or a `WouldBlock` error when none was waiting.
    pub fn recv_msgs(&self, bufs: &mut [Vec<u8>], meta: &mut [RecvMeta]) -> io::Result<usize> {
        let n = bufs.len().min(meta.len()).min(BATCH);
        if n == 0 {
            return Ok(0);
        }
        #[cfg(target_os = "linux")]
        {
            let mut names = [SockAddrBuf::new(); BATCH];
            let mut ctls = [Control([0; CONTROL]); BATCH];
            let mut iovs = [sys::iovec { iov_base: core::ptr::null_mut(), iov_len: 0 }; BATCH];
            // SAFETY: an all-zero mmsghdr is valid.
            let mut hdrs: [sys::mmsghdr; BATCH] = unsafe { core::mem::zeroed() };
            for i in 0..n {
                bufs[i].clear();
                iovs[i] = sys::iovec { iov_base: bufs[i].as_mut_ptr().cast(), iov_len: bufs[i].capacity() };
                let h = &mut hdrs[i].msg_hdr;
                h.msg_name = names[i].as_mut_ptr();
                h.msg_namelen = 128;
                h.msg_iov = &mut iovs[i];
                h.msg_iovlen = 1;
                h.msg_control = ctls[i].0.as_mut_ptr().cast();
                h.msg_controllen = CONTROL;
            }
            // SAFETY: every header points at live name, iovec and control storage on this stack
            // frame, and each iovec at a buffer's spare capacity.
            let got = unsafe { sys::recvmmsg(self.raw(), hdrs.as_mut_ptr(), n as u32, sys::MSG_DONTWAIT, core::ptr::null_mut()) };
            if got < 0 {
                return Err(crate::net::last_error());
            }
            let got = got as usize;
            for i in 0..got {
                let h = &hdrs[i].msg_hdr;
                let len = (hdrs[i].msg_len as usize).min(bufs[i].capacity());
                // SAFETY: the kernel wrote `len` bytes into the buffer's capacity.
                unsafe { bufs[i].set_len(len) };
                let mut m = RecvMeta::empty();
                if let Some(p) = decode_addr(&names[i], h.msg_namelen as usize) {
                    m.peer = p;
                }
                m.len = len;
                cmsg::parse(&ctls[i].0[..h.msg_controllen.min(CONTROL)], |l, t, d| apply_cmsg(&mut m, l, t, d));
                if m.segment_size == 0 {
                    m.segment_size = len;
                }
                m.truncated = h.msg_flags & sys::MSG_TRUNC != 0;
                meta[i] = m;
            }
            Ok(got)
        }
        #[cfg(windows)]
        {
            let f = wsa_recvmsg(self)?;
            let mut got = 0;
            while got < n {
                let mut name = SockAddrBuf::new();
                let mut ctl = Control([0; CONTROL]);
                bufs[got].clear();
                let mut wb = sys::WSABUF { len: bufs[got].capacity().min(u32::MAX as usize) as u32, buf: bufs[got].as_mut_ptr() };
                let mut msg = sys::WSAMSG {
                    name: name.as_mut_ptr(),
                    namelen: 128,
                    lpBuffers: &mut wb,
                    dwBufferCount: 1,
                    Control: sys::WSABUF { len: CONTROL as u32, buf: ctl.0.as_mut_ptr() },
                    dwFlags: 0,
                };
                let mut len = 0u32;
                // SAFETY: `msg` points at live name, buffer and control storage; a null
                // OVERLAPPED makes this a non-blocking call that completes before returning.
                let r = unsafe { f(self.raw(), &mut msg, &mut len, core::ptr::null_mut(), core::ptr::null_mut()) };
                if r != 0 {
                    let e = crate::net::last_error();
                    if e.raw_os_error() == Some(sys::WSAEMSGSIZE) {
                        msg.dwFlags |= sys::MSG_TRUNC;
                        len = wb.len;
                    } else if got > 0 && e.kind() == io::ErrorKind::WouldBlock {
                        break;
                    } else {
                        return Err(e);
                    }
                }
                // SAFETY: Winsock wrote `len` bytes into the buffer's capacity.
                unsafe { bufs[got].set_len((len as usize).min(bufs[got].capacity())) };
                meta[got] = finish_meta_windows(&name, msg.namelen, &ctl.0[..(msg.Control.len as usize).min(CONTROL)], msg.dwFlags, len as usize);
                got += 1;
            }
            Ok(got)
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let mut got = 0;
            while got < n {
                let mut name = SockAddrBuf::new();
                bufs[got].clear();
                let mut iov = sys::iovec { iov_base: bufs[got].as_mut_ptr().cast(), iov_len: bufs[got].capacity() };
                // SAFETY: an all-zero msghdr is valid.
                let mut h: sys::msghdr = unsafe { core::mem::zeroed() };
                h.msg_name = name.as_mut_ptr();
                h.msg_namelen = 128;
                h.msg_iov = &mut iov;
                h.msg_iovlen = 1;
                // SAFETY: `h` points at live name and buffer storage.
                let r = unsafe { sys::recvmsg(self.raw(), &mut h, 0) };
                if r < 0 {
                    let e = crate::net::last_error();
                    if got > 0 && e.kind() == io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(e);
                }
                let len = (r as usize).min(bufs[got].capacity());
                // SAFETY: the kernel wrote `len` bytes.
                unsafe { bufs[got].set_len(len) };
                let mut m = RecvMeta::empty();
                if let Some(p) = decode_addr(&name, h.msg_namelen as usize) {
                    m.peer = p;
                }
                m.len = len;
                m.segment_size = len;
                meta[got] = m;
                got += 1;
            }
            Ok(got)
        }
    }

    /// Sends up to [`BATCH`] transmits without blocking. Returns how many were handed to the
    /// kernel; a `WouldBlock` error means none was (the socket buffer is full).
    pub fn send_msgs(&self, msgs: &[Transmit<'_>]) -> io::Result<usize> {
        let n = msgs.len().min(BATCH);
        if n == 0 {
            return Ok(0);
        }
        #[cfg(target_os = "linux")]
        {
            let mut names = [SockAddrBuf::new(); BATCH];
            let mut ctls = [Control([0; CONTROL]); BATCH];
            let mut iovs = [sys::iovec { iov_base: core::ptr::null_mut(), iov_len: 0 }; BATCH];
            // SAFETY: an all-zero mmsghdr is valid.
            let mut hdrs: [sys::mmsghdr; BATCH] = unsafe { core::mem::zeroed() };
            for (i, t) in msgs[..n].iter().enumerate() {
                let nl = encode_addr(&t.peer, &mut names[i]);
                let cl = build_cmsg(t, &mut ctls[i].0);
                iovs[i] = sys::iovec { iov_base: t.data.as_ptr() as *mut c_void, iov_len: t.data.len() };
                let h = &mut hdrs[i].msg_hdr;
                h.msg_name = names[i].as_mut_ptr();
                h.msg_namelen = nl;
                h.msg_iov = &mut iovs[i];
                h.msg_iovlen = 1;
                if cl > 0 {
                    h.msg_control = ctls[i].0.as_mut_ptr().cast();
                    h.msg_controllen = cl;
                }
            }
            // SAFETY: every header points at live storage on this frame and at the payloads.
            let r = unsafe { sys::sendmmsg(self.raw(), hdrs.as_mut_ptr(), n as u32, sys::MSG_DONTWAIT | sys::MSG_NOSIGNAL) };
            if r < 0 {
                Err(crate::net::last_error())
            } else {
                Ok(r as usize)
            }
        }
        #[cfg(windows)]
        {
            for (i, t) in msgs[..n].iter().enumerate() {
                let mut name = SockAddrBuf::new();
                let nl = encode_addr(&t.peer, &mut name);
                let mut ctl = Control([0; CONTROL]);
                let cl = build_cmsg(t, &mut ctl.0);
                let mut wb = sys::WSABUF { len: t.data.len() as u32, buf: t.data.as_ptr() as *mut u8 };
                let msg = sys::WSAMSG {
                    name: name.as_mut_ptr(),
                    namelen: nl as i32,
                    lpBuffers: &mut wb,
                    dwBufferCount: 1,
                    Control: sys::WSABUF { len: cl as u32, buf: if cl > 0 { ctl.0.as_mut_ptr() } else { core::ptr::null_mut() } },
                    dwFlags: 0,
                };
                let mut sent = 0u32;
                // SAFETY: `msg` points at live storage; a null OVERLAPPED makes this a
                // non-blocking call that completes before returning.
                let r = unsafe { sys::WSASendMsg(self.raw(), &msg, 0, &mut sent, core::ptr::null_mut(), core::ptr::null_mut()) };
                if r != 0 {
                    let e = crate::net::last_error();
                    if i > 0 && e.kind() == io::ErrorKind::WouldBlock {
                        return Ok(i);
                    }
                    return Err(e);
                }
            }
            Ok(n)
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            for (i, t) in msgs[..n].iter().enumerate() {
                let seg = if t.segment_size > 0 { t.segment_size } else { t.data.len().max(1) };
                for chunk in t.data.chunks(seg) {
                    let mut name = SockAddrBuf::new();
                    let nl = encode_addr(&t.peer, &mut name);
                    let mut iov = sys::iovec { iov_base: chunk.as_ptr() as *mut c_void, iov_len: chunk.len() };
                    // SAFETY: an all-zero msghdr is valid.
                    let mut h: sys::msghdr = unsafe { core::mem::zeroed() };
                    h.msg_name = name.as_mut_ptr();
                    h.msg_namelen = nl;
                    h.msg_iov = &mut iov;
                    h.msg_iovlen = 1;
                    // SAFETY: `h` points at live storage.
                    let r = unsafe { sys::sendmsg(self.raw(), &h, sys::MSG_NOSIGNAL) };
                    if r < 0 {
                        let e = crate::net::last_error();
                        if i > 0 && e.kind() == io::ErrorKind::WouldBlock {
                            return Ok(i);
                        }
                        return Err(e);
                    }
                }
            }
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recv_wait(s: &Socket, bufs: &mut [Vec<u8>], meta: &mut [RecvMeta], want: usize) -> usize {
        let mut total = 0;
        let start = std::time::Instant::now();
        while total < want && start.elapsed() < std::time::Duration::from_secs(5) {
            match s.recv_msgs(&mut bufs[total..], &mut meta[total..]) {
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(1)),
                Err(e) => panic!("{e}"),
            }
        }
        total
    }

    #[test]
    fn batch_send_and_receive_with_metadata() {
        let opts = UdpOptions { pktinfo: true, ecn: true, ..Default::default() };
        let a = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
        let b = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
        let to = a.local_addr().unwrap();
        let payloads: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 100 + i as usize]).collect();
        let tx: Vec<Transmit<'_>> = payloads.iter().map(|p| Transmit { peer: to, data: p, segment_size: 0, ecn: 2, src_ip: None }).collect();
        assert_eq!(b.send_msgs(&tx).unwrap(), 5);
        let mut bufs: Vec<Vec<u8>> = (0..8).map(|_| Vec::with_capacity(2048)).collect();
        let mut meta = [RecvMeta::default(); 8];
        assert_eq!(recv_wait(&a, &mut bufs, &mut meta, 5), 5);
        for i in 0..5 {
            assert_eq!(bufs[i], payloads[i]);
            assert_eq!(meta[i].peer, b.local_addr().unwrap());
            assert_eq!(meta[i].len, 100 + i);
            assert!(!meta[i].truncated);
            #[cfg(target_os = "linux")]
            {
                assert_eq!(meta[i].ecn, 2, "ECN bits reported");
                assert_eq!(meta[i].local_ip, Some("127.0.0.1".parse().unwrap()));
            }
            #[cfg(windows)]
            assert_eq!(meta[i].local_ip, Some("127.0.0.1".parse().unwrap()));
        }
        assert!(matches!(a.recv_msgs(&mut bufs, &mut meta), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    }

    #[test]
    fn segmented_send_arrives_as_separate_datagrams() {
        // GSO where the kernel supports it, else cut in user space; without GRO the receiver
        // sees one datagram per segment either way.
        let a = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions::default()).unwrap();
        let b = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions::default()).unwrap();
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let t = Transmit { peer: a.local_addr().unwrap(), data: &data, segment_size: 400, ecn: 0, src_ip: None };
        match b.send_msgs(&[t]) {
            Ok(1) => {}
            // Kernels or drivers without segmentation offload refuse the control message.
            Err(e) if cfg!(any(target_os = "linux", windows)) => {
                eprintln!("segmentation offload unavailable: {e}");
                return;
            }
            other => panic!("{other:?}"),
        }
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| Vec::with_capacity(2048)).collect();
        let mut meta = [RecvMeta::default(); 4];
        assert_eq!(recv_wait(&a, &mut bufs, &mut meta, 3), 3);
        assert_eq!(bufs[0], data[..400]);
        assert_eq!(bufs[1], data[400..800]);
        assert_eq!(bufs[2], data[800..]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gro_coalesces_or_reports_single_segments() {
        let a = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions { gro: true, ..Default::default() }).unwrap();
        let b = Socket::udp_bind("127.0.0.1:0".parse().unwrap(), &UdpOptions::default()).unwrap();
        let data = vec![7u8; 1200];
        let t = Transmit { peer: a.local_addr().unwrap(), data: &data, segment_size: 300, ecn: 0, src_ip: None };
        assert_eq!(b.send_msgs(&[t]).unwrap(), 1);
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| Vec::with_capacity(65536)).collect();
        let mut meta = [RecvMeta::default(); 4];
        let mut total = 0;
        let start = std::time::Instant::now();
        let mut got = 0;
        while total < 1200 && start.elapsed() < std::time::Duration::from_secs(5) {
            match a.recv_msgs(&mut bufs[got..], &mut meta[got..]) {
                Ok(n) => {
                    for m in &meta[got..got + n] {
                        assert_eq!(m.segment_size, 300);
                        total += m.len;
                    }
                    got += n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(1)),
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(total, 1200);
    }

    #[test]
    fn ipv6_datagrams() {
        let Ok(a) = Socket::udp_bind("[::1]:0".parse().unwrap(), &UdpOptions { pktinfo: true, ..Default::default() }) else { return };
        let b = Socket::udp_bind("[::1]:0".parse().unwrap(), &UdpOptions::default()).unwrap();
        let t = Transmit { peer: a.local_addr().unwrap(), data: b"six", segment_size: 0, ecn: 0, src_ip: None };
        assert_eq!(b.send_msgs(&[t]).unwrap(), 1);
        let mut bufs = vec![Vec::with_capacity(64)];
        let mut meta = [RecvMeta::default()];
        assert_eq!(recv_wait(&a, &mut bufs, &mut meta, 1), 1);
        assert_eq!(bufs[0], b"six");
        assert_eq!(meta[0].peer, b.local_addr().unwrap());
        #[cfg(any(target_os = "linux", windows))]
        assert_eq!(meta[0].local_ip, Some("::1".parse().unwrap()));
    }
}
