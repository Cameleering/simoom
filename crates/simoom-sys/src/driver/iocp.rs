//! Windows I/O completion port driver.
//!
//! - One completion port per driver; sockets are associated with it and set to
//!   `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`, so an operation that completes at once is handled
//!   inline without a trip through the port.
//! - Receives use the **zero-byte `WSARecv`** idiom: the pending operation holds no buffer; when
//!   it completes (data is waiting), a non-blocking `recv` reads into a stock buffer. So an idle
//!   connection holds no buffer, only a small `OVERLAPPED`.
//! - Sends are one overlapped `WSASend` per connection in flight with every queued buffer.
//! - Listeners keep `accepts_outstanding` `AcceptEx` calls posted.
//! - UDP sockets keep `udp_recvs_outstanding` overlapped `WSARecvMsg` calls posted, each with a
//!   buffer (a datagram socket can't use the zero-byte idiom).
//! - The waker posts a completion packet with `PostQueuedCompletionStatus`.
//!
//! Memory safety: every `OVERLAPPED` lives in a `Box` owned by the driver together with the
//! buffers and descriptors the operation uses, and is freed only after its completion was
//! dequeued (or it completed inline). Closing a socket aborts its pending operations, whose
//! completions still arrive; the entry is freed once all have.

use super::{DriverConfig, DriverStats, Event, Id, OutBuf, Slab, Waker};
use crate::net::{decode_addr, last_error, SockAddrBuf, Socket};
use crate::os::windows as sys;
use crate::udp::{finish_meta_windows, wsa_recvmsg, Transmit};
use core::ffi::c_void;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

const WAKE_KEY: usize = usize::MAX;
const ADDR_SLOT: usize = core::mem::size_of::<sys::sockaddr_in6>() + 16;

struct Port(sys::HANDLE);
// SAFETY: a completion port handle may be used from any thread.
unsafe impl Send for Port {}
// SAFETY: as above; PostQueuedCompletionStatus is thread-safe.
unsafe impl Sync for Port {}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: closes the port handle this struct owns, once.
        unsafe { sys::CloseHandle(self.0) };
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum OpKind {
    Recv = 1,
    Send = 2,
    Accept = 3,
    Udp = 4,
}

/// The header of every operation: the OVERLAPPED the kernel sees, then what it belongs to.
#[repr(C)]
struct Ov {
    ov: sys::OVERLAPPED,
    kind: OpKind,
    id: u64,
}

impl Ov {
    fn new(kind: OpKind, id: Id) -> Ov {
        Ov { ov: sys::OVERLAPPED::zeroed(), kind, id: id.0 }
    }
}

#[repr(C)]
struct SendOp {
    head: Ov,
    wsabufs: Vec<sys::WSABUF>,
    bufs: Vec<OutBuf>,
    off: usize,
}

#[repr(C)]
struct AcceptOp {
    head: Ov,
    sock: Option<Socket>,
    addrs: [u8; 2 * ADDR_SLOT],
}

#[repr(C)]
struct UdpOp {
    head: Ov,
    buf: Option<Vec<u8>>,
    name: SockAddrBuf,
    ctl: [u8; 128],
    wsabuf: sys::WSABUF,
    msg: sys::WSAMSG,
    pending: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Listener,
    Stream,
    Udp,
}

struct Entry {
    sock: Option<Socket>,
    key: u64,
    kind: Kind,
    family: i32,
    armed: bool,
    readable: bool,
    recv_pending: bool,
    in_read: bool,
    in_flush: bool,
    failed: bool,
    closing: bool,
    inflight: u32,
    recv_ov: Option<Box<Ov>>,
    /// Eager mode: the buffer of the pending receive.
    recv_buf: Option<Vec<u8>>,
    send: Option<Box<SendOp>>,
    out: VecDeque<OutBuf>,
    off: usize,
    accepts: Vec<Box<AcceptOp>>,
    udps: Vec<Box<UdpOp>>,
}

impl Entry {
    fn raw(&self) -> usize {
        self.sock.as_ref().map_or(sys::INVALID_SOCKET, |s| s.raw())
    }
}

pub(crate) struct Driver {
    port: Arc<Port>,
    waker: Waker,
    slab: Slab<Entry>,
    stash: Vec<Vec<u8>>,
    target: usize,
    read_list: Vec<Id>,
    flush_list: Vec<Id>,
    repost: Vec<Id>,
    closing: Vec<Id>,
    pending: Vec<Event>,
    entries: Vec<sys::OVERLAPPED_ENTRY>,
    send_pool: Vec<Box<SendOp>>,
    accept_ex: sys::LPFN_ACCEPTEX,
    accept_addrs: sys::LPFN_GETACCEPTEXSOCKADDRS,
    stats: DriverStats,
    budget: usize,
    accepts: usize,
    udp_recvs: usize,
    eager: bool,
}

fn ext_fn(s: &Socket, guid: sys::GUID) -> io::Result<usize> {
    let mut f: usize = 0;
    let mut ret = 0u32;
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
        return Err(last_error());
    }
    Ok(f)
}

/// The error of a completed operation, from the NTSTATUS in `Internal`.
fn status_error(entry: &sys::OVERLAPPED_ENTRY) -> Option<io::Error> {
    // SAFETY: the OVERLAPPED is one of ours and its operation has completed.
    let status = unsafe { (*entry.lpOverlapped).Internal } as i32;
    if status == 0 {
        None
    } else {
        // SAFETY: pure conversion function.
        Some(io::Error::from_raw_os_error(unsafe { sys::RtlNtStatusToDosError(status) } as i32))
    }
}

fn is_pending(e: &io::Error) -> bool {
    e.raw_os_error() == Some(sys::WSA_IO_PENDING)
}

impl Driver {
    pub(crate) fn new(cfg: &DriverConfig) -> io::Result<Driver> {
        crate::net::init();
        // SAFETY: creates a new completion port; checked for null.
        let h = unsafe { sys::CreateIoCompletionPort(sys::INVALID_HANDLE_VALUE, core::ptr::null_mut(), 0, 1) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let port = Arc::new(Port(h));
        let p2 = port.clone();
        let waker = Waker::new(Box::new(move || {
            // SAFETY: posts a packet to a port kept open by this closure's Arc.
            unsafe { sys::PostQueuedCompletionStatus(p2.0, 0, WAKE_KEY, core::ptr::null_mut()) };
        }));
        let probe = Socket::new(sys::AF_INET, sys::SOCK_STREAM)?;
        let ax = ext_fn(&probe, sys::WSAID_ACCEPTEX)?;
        let aa = ext_fn(&probe, sys::WSAID_GETACCEPTEXSOCKADDRS)?;
        Ok(Driver {
            port,
            waker,
            slab: Slab::new(),
            stash: Vec::new(),
            target: 16,
            read_list: Vec::new(),
            flush_list: Vec::new(),
            repost: Vec::new(),
            closing: Vec::new(),
            pending: Vec::new(),
            entries: vec![sys::OVERLAPPED_ENTRY { lpCompletionKey: 0, lpOverlapped: core::ptr::null_mut(), Internal: 0, dwNumberOfBytesTransferred: 0 }; cfg.events.max(16)],
            send_pool: Vec::new(),
            // SAFETY: both values are the Winsock entry points for these GUIDs.
            accept_ex: unsafe { core::mem::transmute::<usize, sys::LPFN_ACCEPTEX>(ax) },
            // SAFETY: as above.
            accept_addrs: unsafe { core::mem::transmute::<usize, sys::LPFN_GETACCEPTEXSOCKADDRS>(aa) },
            stats: DriverStats::default(),
            budget: cfg.recv_budget.max(1),
            accepts: cfg.accepts_outstanding.max(1),
            udp_recvs: cfg.udp_recvs_outstanding.max(1),
            eager: cfg.iocp_eager_recv,
        })
    }

    pub(crate) fn waker(&self) -> Waker {
        self.waker.clone()
    }

    fn associate(&mut self, sock: &Socket, id: Id) -> io::Result<()> {
        self.stats.other_calls += 2;
        // SAFETY: associates a socket we own with our port, keyed by its id.
        let r = unsafe { sys::CreateIoCompletionPort(sock.raw() as sys::HANDLE, self.port.0, id.0 as usize, 0) };
        if r.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: plain call on a socket we own.
        if unsafe { sys::SetFileCompletionNotificationModes(sock.raw() as sys::HANDLE, sys::FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | sys::FILE_SKIP_SET_EVENT_ON_HANDLE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn add(&mut self, sock: Socket, key: u64, kind: Kind) -> io::Result<Id> {
        let family = match sock.local_addr() {
            Ok(a) if a.is_ipv6() => sys::AF_INET6,
            _ => sys::AF_INET,
        };
        let id = self.slab.insert(Entry {
            sock: None,
            key,
            kind,
            family,
            armed: false,
            readable: false,
            recv_pending: false,
            in_read: false,
            in_flush: false,
            failed: false,
            closing: false,
            inflight: 0,
            recv_ov: None,
            recv_buf: None,
            send: None,
            out: VecDeque::new(),
            off: 0,
            accepts: Vec::new(),
            udps: Vec::new(),
        });
        if let Err(e) = self.associate(&sock, id) {
            self.slab.remove(id);
            return Err(e);
        }
        let e = self.slab.get_mut(id).unwrap();
        e.sock = Some(sock);
        match kind {
            Kind::Stream => e.recv_ov = Some(Box::new(Ov::new(OpKind::Recv, id))),
            Kind::Listener => {
                for _ in 0..self.accepts {
                    e.accepts.push(Box::new(AcceptOp { head: Ov::new(OpKind::Accept, id), sock: None, addrs: [0; 2 * ADDR_SLOT] }));
                }
                for i in 0..self.accepts {
                    self.post_accept(id, i);
                }
            }
            Kind::Udp => {
                for _ in 0..self.udp_recvs {
                    e.udps.push(Box::new(UdpOp {
                        head: Ov::new(OpKind::Udp, id),
                        buf: None,
                        name: SockAddrBuf::new(),
                        ctl: [0; 128],
                        wsabuf: sys::WSABUF { len: 0, buf: core::ptr::null_mut() },
                        // SAFETY: an all-zero WSAMSG is valid.
                        msg: unsafe { core::mem::zeroed() },
                        pending: false,
                    }));
                }
            }
        }
        Ok(id)
    }

    pub(crate) fn listen(&mut self, sock: Socket, key: u64) -> io::Result<Id> {
        self.add(sock, key, Kind::Listener)
    }

    pub(crate) fn stream(&mut self, sock: Socket, key: u64) -> io::Result<Id> {
        self.add(sock, key, Kind::Stream)
    }

    pub(crate) fn udp(&mut self, sock: Socket, key: u64) -> io::Result<Id> {
        self.add(sock, key, Kind::Udp)
    }

    /// Posts AcceptEx number `i` of a listener, handling inline completions.
    fn post_accept(&mut self, id: Id, i: usize) {
        loop {
            let Some(e) = self.slab.get_mut(id) else { return };
            if e.closing {
                return;
            }
            let acc = match Socket::new(e.family, sys::SOCK_STREAM) {
                Ok(s) => s,
                Err(error) => {
                    self.pending.push(Event::Error { key: e.key, error });
                    return;
                }
            };
            let listen = e.raw();
            let op = &mut e.accepts[i];
            op.head.ov = sys::OVERLAPPED::zeroed();
            let acc_raw = acc.raw();
            op.sock = Some(acc);
            let mut got = 0u32;
            self.stats.accept_calls += 1;
            // SAFETY: `op` is boxed and owned by the entry until its completion; the address
            // buffer has room for both addresses plus the 16 bytes AcceptEx requires each.
            let ok = unsafe {
                (self.accept_ex)(listen, acc_raw, op.addrs.as_mut_ptr().cast(), 0, ADDR_SLOT as u32, ADDR_SLOT as u32, &mut got, &mut op.head.ov)
            };
            if ok != 0 {
                // Completed inline (skip-on-success): handle it and post again.
                self.finish_accept(id, i, None);
                continue;
            }
            let err = last_error();
            if is_pending(&err) {
                e.inflight += 1;
                return;
            }
            op.sock = None;
            if err.raw_os_error() == Some(sys::WSAECONNRESET) {
                continue; // the client gave up before we accepted; try again
            }
            self.pending.push(Event::Error { key: e.key, error: err });
            return;
        }
    }

    fn finish_accept(&mut self, id: Id, i: usize, error: Option<io::Error>) {
        let Some(e) = self.slab.get_mut(id) else { return };
        let key = e.key;
        let listen = e.raw();
        let op = &mut e.accepts[i];
        let Some(acc) = op.sock.take() else { return };
        if e.closing {
            return;
        }
        if let Some(error) = error {
            if error.raw_os_error() != Some(sys::WSAECONNRESET) && error.raw_os_error() != Some(sys::ERROR_NETNAME_DELETED) {
                self.pending.push(Event::Error { key, error });
            }
            return;
        }
        self.stats.other_calls += 1;
        // SAFETY: SO_UPDATE_ACCEPT_CONTEXT takes the listening SOCKET by value in a buffer.
        unsafe {
            sys::setsockopt(acc.raw(), sys::SOL_SOCKET, sys::SO_UPDATE_ACCEPT_CONTEXT, (&listen as *const usize).cast(), core::mem::size_of::<usize>() as i32);
        }
        let mut local: *mut c_void = core::ptr::null_mut();
        let mut remote: *mut c_void = core::ptr::null_mut();
        let (mut ll, mut rl) = (0i32, 0i32);
        // SAFETY: parses the buffer AcceptEx filled; the returned pointers point into it.
        unsafe {
            (self.accept_addrs)(op.addrs.as_mut_ptr().cast(), 0, ADDR_SLOT as u32, ADDR_SLOT as u32, &mut local, &mut ll, &mut remote, &mut rl);
        }
        let peer = if remote.is_null() || rl <= 0 {
            None
        } else {
            let mut b = SockAddrBuf::new();
            let n = (rl as usize).min(128);
            // SAFETY: `remote` points at `rl` valid bytes inside `op.addrs`.
            unsafe { core::ptr::copy_nonoverlapping(remote.cast::<u8>(), b.bytes.as_mut_ptr(), n) };
            decode_addr(&b, n)
        };
        self.pending.push(Event::Accepted { key, socket: acc, peer });
    }

    pub(crate) fn recv(&mut self, id: Id, on: bool) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.kind == Kind::Listener || e.closing {
            return;
        }
        e.armed = on;
        if !on {
            return;
        }
        match e.kind {
            Kind::Stream => {
                if e.readable {
                    if !e.in_read {
                        e.in_read = true;
                        self.read_list.push(id);
                    }
                } else if !e.recv_pending {
                    // Data may already be waiting: try a read first, which posts the
                    // zero-byte receive when nothing is there.
                    e.readable = true;
                    e.in_read = true;
                    self.read_list.push(id);
                }
            }
            Kind::Udp => self.repost.push(id),
            Kind::Listener => {}
        }
    }

    /// Posts the zero-byte receive; inline completion marks the socket readable.
    fn post_recv(&mut self, id: Id) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.recv_pending || e.closing || !e.armed {
            return;
        }
        if self.eager {
            return self.post_recv_eager(id);
        }
        let raw = e.raw();
        let ov = e.recv_ov.as_mut().unwrap();
        ov.ov = sys::OVERLAPPED::zeroed();
        let mut wb = sys::WSABUF { len: 0, buf: core::ptr::null_mut() };
        let (mut got, mut flags) = (0u32, 0u32);
        self.stats.recv_calls += 1;
        // SAFETY: the OVERLAPPED is boxed in the entry and outlives the operation; the
        // zero-length WSABUF is read during the call only.
        let r = unsafe { sys::WSARecv(raw, &mut wb, 1, &mut got, &mut flags, &mut ov.ov, core::ptr::null_mut()) };
        if r == 0 {
            e.readable = true;
            if !e.in_read {
                e.in_read = true;
                self.read_list.push(id);
            }
            return;
        }
        let err = last_error();
        if is_pending(&err) {
            e.recv_pending = true;
            e.inflight += 1;
        } else {
            e.armed = false;
            self.pending.push(Event::Error { key: e.key, error: err });
        }
    }

    /// Eager mode: posts a receive with a stock buffer, so arriving data completes it in one
    /// call (the buffer stays with the connection while it waits).
    fn post_recv_eager(&mut self, id: Id) {
        for _ in 0..self.budget {
            let Some(e) = self.slab.get_mut(id) else { return };
            if e.recv_pending || e.closing || !e.armed {
                return;
            }
            let Some(mut buf) = e.recv_buf.take().or_else(|| self.stash.pop()) else {
                // Starved: the read list retries once buffers are back.
                e.readable = true;
                if !e.in_read {
                    e.in_read = true;
                    self.read_list.push(id);
                }
                return;
            };
            buf.clear();
            let raw = e.raw();
            let ov = e.recv_ov.as_mut().unwrap();
            ov.ov = sys::OVERLAPPED::zeroed();
            let mut wb = sys::WSABUF { len: buf.capacity().min(u32::MAX as usize) as u32, buf: buf.as_mut_ptr() };
            let (mut got, mut flags) = (0u32, 0u32);
            self.stats.recv_calls += 1;
            // SAFETY: the OVERLAPPED is boxed in the entry, and the buffer is kept in the entry
            // (`recv_buf`) until the completion when the call pends.
            let r = unsafe { sys::WSARecv(raw, &mut wb, 1, &mut got, &mut flags, &mut ov.ov, core::ptr::null_mut()) };
            if r == 0 {
                if !Self::deliver_recv(e, buf, got as usize, &mut self.stash, &mut self.pending) {
                    return;
                }
                continue;
            }
            let err = last_error();
            if is_pending(&err) {
                e.recv_buf = Some(buf);
                e.recv_pending = true;
                e.inflight += 1;
            } else {
                self.stash.push(buf);
                e.armed = false;
                self.pending.push(Event::Error { key: e.key, error: err });
            }
            return;
        }
        // Budget used up with data still flowing: continue next turn.
        if let Some(e) = self.slab.get_mut(id) {
            e.readable = true;
            if !e.in_read {
                e.in_read = true;
                self.read_list.push(id);
            }
        }
    }

    /// Reports a completed eager receive; returns whether to keep receiving.
    fn deliver_recv(e: &mut Entry, mut buf: Vec<u8>, n: usize, stash: &mut Vec<Vec<u8>>, out: &mut Vec<Event>) -> bool {
        if n == 0 {
            stash.push(buf);
            e.armed = false;
            out.push(Event::Eof { key: e.key });
            return false;
        }
        buf_set_len(&mut buf, n);
        out.push(Event::Data { key: e.key, buf });
        true
    }

    /// Posts the outstanding UDP receives.
    fn post_udp(&mut self, id: Id) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.closing || !e.armed {
            return;
        }
        let raw = e.raw();
        let Some(sock) = e.sock.as_ref() else { return };
        let f = match wsa_recvmsg(sock) {
            Ok(f) => f,
            Err(error) => {
                self.pending.push(Event::Error { key: e.key, error });
                return;
            }
        };
        let mut inline_budget = self.budget;
        let mut i = 0;
        while i < e.udps.len() {
            let op = &mut e.udps[i];
            if op.pending {
                i += 1;
                continue;
            }
            if op.buf.is_none() {
                match self.stash.pop() {
                    Some(b) => op.buf = Some(b),
                    None => {
                        self.repost.push(id); // starved: try again next turn
                        return;
                    }
                }
            }
            let buf = op.buf.as_mut().unwrap();
            buf.clear();
            op.head.ov = sys::OVERLAPPED::zeroed();
            op.wsabuf = sys::WSABUF { len: buf.capacity().min(u32::MAX as usize) as u32, buf: buf.as_mut_ptr() };
            op.msg = sys::WSAMSG {
                name: op.name.as_mut_ptr(),
                namelen: 128,
                lpBuffers: &mut op.wsabuf,
                dwBufferCount: 1,
                Control: sys::WSABUF { len: op.ctl.len() as u32, buf: op.ctl.as_mut_ptr() },
                dwFlags: 0,
            };
            let mut got = 0u32;
            self.stats.recv_calls += 1;
            // SAFETY: the op (OVERLAPPED, WSAMSG, name, control and buffer) is boxed in the
            // entry and stays until the completion is handled.
            let r = unsafe { f(raw, &mut op.msg, &mut got, &mut op.head.ov, core::ptr::null_mut()) };
            if r == 0 {
                // Inline completion.
                let b = op.buf.take().unwrap();
                let meta_ctl = (op.msg.Control.len as usize).min(op.ctl.len());
                let item = Self::udp_done(e.key, b, &op.name, op.msg.namelen, &op.ctl[..meta_ctl], op.msg.dwFlags, got as usize);
                self.pending.push(item);
                inline_budget -= 1;
                if inline_budget == 0 {
                    self.repost.push(id);
                    return;
                }
                continue; // post this slot again
            }
            let err = last_error();
            if is_pending(&err) {
                op.pending = true;
                e.inflight += 1;
                i += 1;
            } else if err.raw_os_error() == Some(sys::WSAEMSGSIZE) {
                let b = op.buf.take().unwrap();
                let n = b.capacity();
                let item = Self::udp_done(e.key, b, &op.name, op.msg.namelen, &[], sys::MSG_TRUNC, n);
                self.pending.push(item);
            } else {
                self.pending.push(Event::Error { key: e.key, error: err });
                return;
            }
        }
    }

    fn udp_done(key: u64, mut buf: Vec<u8>, name: &SockAddrBuf, namelen: i32, ctl: &[u8], flags: u32, len: usize) -> Event {
        let len = len.min(buf.capacity());
        // SAFETY: Winsock wrote `len` bytes into the buffer's capacity.
        unsafe { buf.set_len(len) };
        let meta = finish_meta_windows(name, namelen, ctl, flags, len);
        Event::Datagram { key, buf, meta }
    }

    pub(crate) fn send(&mut self, id: Id, buf: OutBuf) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.failed || e.closing {
            let key = e.key;
            self.pending.push(Event::Sent { key, buf });
            return;
        }
        e.out.push_back(buf);
        if !e.in_flush && e.send.is_none() {
            e.in_flush = true;
            self.flush_list.push(id);
        }
    }

    pub(crate) fn send_to(&mut self, id: Id, msgs: &[Transmit<'_>]) -> io::Result<usize> {
        let e = self.slab.get(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown socket"))?;
        let s = e.sock.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "closed"))?;
        self.stats.send_calls += 1;
        s.send_msgs(msgs)
    }

    pub(crate) fn close(&mut self, id: Id) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.closing {
            return;
        }
        e.closing = true;
        e.armed = false;
        let key = e.key;
        for buf in e.out.drain(..) {
            self.pending.push(Event::Sent { key, buf });
        }
        // Closing the socket aborts its pending operations; their completions still arrive.
        // Winsock closes gracefully only if no receive is pending or the send side is shut down
        // first (as libuv does); otherwise the peer gets a reset and may lose our last bytes.
        if let Some(s) = e.sock.take() {
            if e.recv_pending {
                self.stats.other_calls += 1;
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
            self.stats.other_calls += 1;
            drop(s);
        }
        self.closing.push(id);
    }

    fn finish_closing(&mut self) {
        let mut i = 0;
        while i < self.closing.len() {
            let id = self.closing[i];
            let done = self.slab.get(id).is_none_or(|e| e.inflight == 0);
            if !done {
                i += 1;
                continue;
            }
            self.closing.swap_remove(i);
            if let Some(mut e) = self.slab.remove(id) {
                if let Some(op) = e.send.take() {
                    self.send_pool.push(op);
                }
                if let Some(b) = e.recv_buf.take() {
                    self.stash.push(b);
                }
                for mut op in e.udps.drain(..) {
                    if let Some(b) = op.buf.take() {
                        self.stash.push(b);
                    }
                }
                self.pending.push(Event::Closed { key: e.key });
            }
        }
    }

    pub(crate) fn socket(&self, id: Id) -> Option<&Socket> {
        self.slab.get(id).and_then(|e| e.sock.as_ref())
    }

    pub(crate) fn provide(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        self.stash.push(buf);
    }

    pub(crate) fn buffers_wanted(&self) -> usize {
        self.target.saturating_sub(self.stash.len())
    }

    pub(crate) fn set_buffer_target(&mut self, n: usize) {
        self.target = n;
    }

    pub(crate) fn stats(&self) -> DriverStats {
        self.stats
    }

    pub(crate) fn len(&self) -> usize {
        self.slab.len()
    }

    fn flush(&mut self, out: &mut Vec<Event>) {
        if self.flush_list.is_empty() {
            return;
        }
        let list = std::mem::take(&mut self.flush_list);
        for id in list {
            let Some(e) = self.slab.get_mut(id) else { continue };
            e.in_flush = false;
            if e.send.is_some() || e.out.is_empty() || e.closing || e.failed {
                continue;
            }
            let mut op = self.send_pool.pop().unwrap_or_else(|| {
                Box::new(SendOp { head: Ov::new(OpKind::Send, id), wsabufs: Vec::with_capacity(64), bufs: Vec::with_capacity(64), off: 0 })
            });
            op.head = Ov::new(OpKind::Send, id);
            op.off = e.off;
            e.off = 0;
            while op.bufs.len() < 64 {
                match e.out.pop_front() {
                    Some(b) => op.bufs.push(b),
                    None => break,
                }
            }
            op.wsabufs.clear();
            for (i, b) in op.bufs.iter().enumerate() {
                let s = if i == 0 { &b.as_slice()[op.off..] } else { b.as_slice() };
                op.wsabufs.push(sys::WSABUF { len: s.len() as u32, buf: s.as_ptr() as *mut u8 });
            }
            let mut sent = 0u32;
            self.stats.send_calls += 1;
            // SAFETY: the op box (OVERLAPPED, WSABUFs and the buffers they point at) is kept in
            // the entry until the completion is handled.
            let r = unsafe { sys::WSASend(e.raw(), op.wsabufs.as_ptr(), op.wsabufs.len() as u32, &mut sent, 0, &mut op.head.ov, core::ptr::null_mut()) };
            if r == 0 {
                // Completed inline (skip-on-success): no packet will be queued.
                Self::send_done(e, &mut op, Ok(sent as usize), out, &mut self.flush_list, id);
                self.send_pool.push(op);
                continue;
            }
            let err = last_error();
            if is_pending(&err) {
                e.inflight += 1;
                e.send = Some(op);
            } else {
                Self::send_done(e, &mut op, Err(err), out, &mut self.flush_list, id);
                self.send_pool.push(op);
            }
        }
    }

    fn send_done(e: &mut Entry, op: &mut SendOp, res: io::Result<usize>, out: &mut Vec<Event>, flush: &mut Vec<Id>, id: Id) {
        let key = e.key;
        match res {
            Err(error) => {
                for buf in op.bufs.drain(..) {
                    out.push(Event::Sent { key, buf });
                }
                if !e.closing {
                    e.failed = true;
                    out.push(Event::Error { key, error });
                    for buf in e.out.drain(..) {
                        out.push(Event::Sent { key, buf });
                    }
                }
            }
            Ok(mut w) => {
                let mut off = op.off;
                let mut rest = Vec::new();
                for buf in op.bufs.drain(..) {
                    let left = buf.len() - off;
                    if w >= left {
                        w -= left;
                        off = 0;
                        out.push(Event::Sent { key, buf });
                    } else {
                        off += w;
                        w = 0;
                        rest.push(buf);
                    }
                }
                if !rest.is_empty() {
                    for b in rest.into_iter().rev() {
                        e.out.push_front(b);
                    }
                    e.off = off;
                }
                if !e.out.is_empty() && !e.closing && !e.in_flush {
                    e.in_flush = true;
                    flush.push(id);
                }
            }
        }
    }

    fn read(&mut self, out: &mut Vec<Event>) {
        let list = std::mem::take(&mut self.read_list);
        let mut keep = Vec::new();
        let mut post = Vec::new();
        for id in list {
            let Some(e) = self.slab.get_mut(id) else { continue };
            if !e.armed || !e.readable || e.closing {
                e.in_read = false;
                continue;
            }
            if self.stash.is_empty() {
                keep.push(id);
                continue;
            }
            let Some(sock) = e.sock.as_ref() else { continue };
            let mut done = false;
            for _ in 0..self.budget {
                let Some(mut buf) = self.stash.pop() else { break };
                self.stats.recv_calls += 1;
                match sock.recv_into(&mut buf) {
                    Ok(0) => {
                        self.stash.push(buf);
                        e.armed = false;
                        out.push(Event::Eof { key: e.key });
                        done = true;
                        break;
                    }
                    Ok(n) => {
                        let full = n == buf.capacity();
                        out.push(Event::Data { key: e.key, buf });
                        if !full {
                            done = true;
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        self.stash.push(buf);
                        done = true;
                        break;
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => self.stash.push(buf),
                    Err(error) => {
                        self.stash.push(buf);
                        e.armed = false;
                        out.push(Event::Error { key: e.key, error });
                        done = true;
                        break;
                    }
                }
            }
            if done {
                e.readable = false;
                e.in_read = false;
                if e.armed {
                    post.push(id);
                }
            } else {
                keep.push(id);
            }
        }
        self.read_list = keep;
        for id in post {
            self.post_recv(id);
        }
    }

    fn complete(&mut self, ent: sys::OVERLAPPED_ENTRY, out: &mut Vec<Event>) {
        if ent.lpCompletionKey == WAKE_KEY && ent.lpOverlapped.is_null() {
            self.waker.clear();
            out.push(Event::Wake);
            return;
        }
        if ent.lpOverlapped.is_null() {
            return;
        }
        let err = status_error(&ent);
        // SAFETY: every OVERLAPPED we post starts an `Ov` header inside a live box.
        let (kind, raw_id) = unsafe {
            let h = ent.lpOverlapped.cast::<Ov>();
            ((*h).kind, (*h).id)
        };
        let id = Id(raw_id);
        let Some(e) = self.slab.get_mut(id) else { return };
        e.inflight = e.inflight.saturating_sub(1);
        match kind {
            OpKind::Recv if self.eager => {
                e.recv_pending = false;
                let buf = e.recv_buf.take();
                if e.closing {
                    if let Some(b) = buf {
                        self.stash.push(b);
                    }
                    return;
                }
                match (err, buf) {
                    (Some(error), b) => {
                        if let Some(b) = b {
                            self.stash.push(b);
                        }
                        e.armed = false;
                        out.push(Event::Error { key: e.key, error });
                    }
                    (None, Some(b)) => {
                        if Self::deliver_recv(e, b, ent.dwNumberOfBytesTransferred as usize, &mut self.stash, out) {
                            self.post_recv_eager(id);
                        }
                    }
                    (None, None) => {}
                }
            }
            OpKind::Recv => {
                e.recv_pending = false;
                if e.closing {
                    return;
                }
                match err {
                    Some(error) => {
                        e.armed = false;
                        out.push(Event::Error { key: e.key, error });
                    }
                    None => {
                        e.readable = true;
                        if e.armed && !e.in_read {
                            e.in_read = true;
                            self.read_list.push(id);
                        }
                    }
                }
            }
            OpKind::Send => {
                let Some(mut op) = e.send.take() else { return };
                let res = match err {
                    Some(error) => Err(error),
                    None => Ok(ent.dwNumberOfBytesTransferred as usize),
                };
                Self::send_done(e, &mut op, res, out, &mut self.flush_list, id);
                self.send_pool.push(op);
            }
            OpKind::Accept => {
                let i = e.accepts.iter().position(|op| core::ptr::eq(&op.head.ov, ent.lpOverlapped)).unwrap_or(0);
                if e.closing {
                    e.accepts[i].sock = None;
                    return;
                }
                self.finish_accept(id, i, err);
                self.post_accept(id, i);
            }
            OpKind::Udp => {
                let i = e.udps.iter().position(|op| core::ptr::eq(&op.head.ov, ent.lpOverlapped)).unwrap_or(0);
                let op = &mut e.udps[i];
                op.pending = false;
                if e.closing {
                    return;
                }
                match err {
                    None => {
                        let b = op.buf.take().unwrap();
                        let ctl_len = (op.msg.Control.len as usize).min(op.ctl.len());
                        out.push(Self::udp_done(e.key, b, &op.name, op.msg.namelen, &op.ctl[..ctl_len], op.msg.dwFlags, ent.dwNumberOfBytesTransferred as usize));
                    }
                    Some(error) if error.raw_os_error() == Some(sys::WSAEMSGSIZE) || error.raw_os_error() == Some(234) => {
                        let b = op.buf.take().unwrap();
                        let n = ent.dwNumberOfBytesTransferred as usize;
                        out.push(Self::udp_done(e.key, b, &op.name, op.msg.namelen, &[], sys::MSG_TRUNC, n));
                    }
                    Some(_) => {} // ICMP noise and the like: just post again
                }
                if e.armed {
                    self.repost.push(id);
                }
            }
        }
    }

    pub(crate) fn turn(&mut self, timeout: Option<Duration>, out: &mut Vec<Event>) -> io::Result<()> {
        self.finish_closing();
        out.append(&mut self.pending);
        let repost = std::mem::take(&mut self.repost);
        for id in repost {
            self.post_udp(id);
        }
        out.append(&mut self.pending);
        self.flush(out);
        let busy = !out.is_empty() || (!self.read_list.is_empty() && !self.stash.is_empty()) || !self.repost.is_empty() && !self.stash.is_empty();
        let ms = if busy {
            0
        } else {
            match timeout {
                None => sys::INFINITE,
                Some(d) => d.as_nanos().div_ceil(1_000_000).min(u32::MAX as u128 - 1) as u32,
            }
        };
        let mut n = 0u32;
        self.stats.waits += 1;
        // SAFETY: `entries` has room for its length.
        let ok = unsafe { sys::GetQueuedCompletionStatusEx(self.port.0, self.entries.as_mut_ptr(), self.entries.len() as u32, &mut n, ms, 0) };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(sys::WAIT_TIMEOUT as i32) {
                return Err(e);
            }
            n = 0;
        }
        self.stats.os_events += n as u64;
        for i in 0..n as usize {
            let ent = self.entries[i];
            self.complete(ent, out);
        }
        out.append(&mut self.pending);
        self.read(out);
        self.flush(out);
        self.finish_closing();
        out.append(&mut self.pending);
        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        for id in self.slab.ids() {
            self.close(id);
        }
        // Wait (bounded) for the aborted operations so their memory is not freed under the OS.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut sink = Vec::new();
        while self.slab.ids().iter().any(|&id| self.slab.get(id).is_some_and(|e| e.inflight > 0)) && Instant::now() < deadline {
            let mut n = 0u32;
            // SAFETY: `entries` has room for its length.
            let ok = unsafe { sys::GetQueuedCompletionStatusEx(self.port.0, self.entries.as_mut_ptr(), self.entries.len() as u32, &mut n, 50, 0) };
            if ok == 0 {
                continue;
            }
            for i in 0..n as usize {
                let ent = self.entries[i];
                self.complete(ent, &mut sink);
            }
            sink.clear();
        }
        for id in self.slab.ids() {
            if let Some(e) = self.slab.get_mut(id) {
                if e.inflight > 0 {
                    // Still owned by the OS: leak rather than free.
                    std::mem::forget(e.recv_ov.take());
                    std::mem::forget(e.recv_buf.take());
                    std::mem::forget(e.send.take());
                    std::mem::forget(std::mem::take(&mut e.accepts));
                    std::mem::forget(std::mem::take(&mut e.udps));
                }
            }
        }
    }
}

/// Sets the length of a buffer whose first `n` bytes the OS has written.
fn buf_set_len(buf: &mut Vec<u8>, n: usize) {
    let n = n.min(buf.capacity());
    // SAFETY: called only after Winsock reported writing `n` bytes into this buffer's capacity.
    unsafe { buf.set_len(n) };
}
