//! Linux io_uring driver, reached through `syscall(2)` and `mmap(2)`.
//!
//! - Ring set up with `IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN` (Linux 6.1+):
//!   completions run only when this thread asks for them, inside `io_uring_enter`.
//! - Multishot accept (5.19) per listener.
//! - Multishot receive with a provided-buffer ring (6.0): no buffer is tied to a connection
//!   while it waits; the kernel picks one from the ring when data arrives.
//! - One send per connection in flight (`IORING_OP_SEND`, or `IORING_OP_SENDMSG` for several
//!   buffers) with `MSG_WAITALL`, so sends stay in order.
//! - Connections use registered (fixed) file descriptors when there is room in the table.
//! - UDP sockets and the waker's eventfd use multishot `POLL_ADD`; UDP datagrams are then read
//!   with `recvmmsg` (GRO, ECN and packet info work the same as on epoll).
//!
//! [`available`] probes all of this. [`super::Driver::new`] falls back to epoll when the probe
//! fails (`ENOSYS` without io_uring, `EPERM` under seccomp or with `io_uring_disabled`,
//! `EINVAL` on kernels older than 6.1).
//!
//! Memory safety: a buffer the kernel may write or read (ring buffers, buffers of a send in
//! flight, `msghdr`s) is owned by the driver until the completion that ends the operation is
//! reaped. Closing a socket cancels its operations and waits for their completions before the
//! buffers are returned. If the driver is dropped with operations still in flight after a
//! cancellation round, their memory is leaked rather than freed under the kernel.

use super::epoll::{drain_eventfd, eventfd, eventfd_waker};
use super::{DriverConfig, DriverStats, Event, Id, LargeBufs, OutBuf, Slab, Waker, LARGE_BATCH};
use crate::net::Socket;
use crate::os::linux as sys;
use crate::udp::{RecvMeta, Transmit, BATCH};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

// --- ABI constants (include/uapi/linux/io_uring.h) --------------------------------------------

const SETUP_CQSIZE: u32 = 1 << 3;
const SETUP_CLAMP: u32 = 1 << 4;
const SETUP_SUBMIT_ALL: u32 = 1 << 7;
const SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const SETUP_DEFER_TASKRUN: u32 = 1 << 13;

const FEAT_SINGLE_MMAP: u32 = 1 << 0;
const FEAT_NODROP: u32 = 1 << 1;
const FEAT_EXT_ARG: u32 = 1 << 8;

const ENTER_GETEVENTS: u32 = 1 << 0;
const ENTER_EXT_ARG: u32 = 1 << 3;

const OFF_SQ_RING: i64 = 0;
const OFF_SQES: i64 = 0x1000_0000;

const OP_POLL_ADD: u8 = 6;
const OP_SENDMSG: u8 = 9;
const OP_ACCEPT: u8 = 13;
const OP_ASYNC_CANCEL: u8 = 14;
const OP_SEND: u8 = 26;
const OP_RECV: u8 = 27;
const OP_PROVIDE_BUFFERS: u8 = 31;

const SQE_FIXED_FILE: u8 = 1 << 0;
const SQE_BUFFER_SELECT: u8 = 1 << 5;
const SQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

const CQE_F_BUFFER: u32 = 1 << 0;
const CQE_F_MORE: u32 = 1 << 1;
const CQE_BUFFER_SHIFT: u32 = 16;

const ACCEPT_MULTISHOT: u16 = 1 << 0;
const RECV_MULTISHOT: u16 = 1 << 1;
const POLL_ADD_MULTI: u32 = 1 << 0;
const POLLIN: u32 = 0x1;
const CANCEL_ANY: u32 = 1 << 2;

const REGISTER_FILES: u32 = 2;
const REGISTER_FILES_UPDATE: u32 = 6;
const REGISTER_PROBE: u32 = 8;
const REGISTER_FILES2: u32 = 13;
const REGISTER_PBUF_RING: u32 = 22;
const RSRC_REGISTER_SPARSE: u32 = 1 << 0;
const PROBE_OP_SUPPORTED: u16 = 1 << 0;

const BGID: u16 = 0;

// --- ABI structures ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Default)]
struct SqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct CqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqOffsets,
    cq_off: CqOffsets,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    file_index: u32,
    addr3: u64,
    pad: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

#[repr(C)]
struct BufReg {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [u64; 3],
}

#[repr(C)]
struct RingBuf {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16, // the ring tail lives here in entry 0
}

#[repr(C)]
struct FilesUpdate {
    offset: u32,
    resv: u32,
    fds: u64,
}

#[repr(C)]
struct RsrcRegister {
    nr: u32,
    flags: u32,
    resv2: u64,
    data: u64,
    tags: u64,
}

#[repr(C)]
struct GeteventsArg {
    sigmask: u64,
    sigmask_sz: u32,
    min_wait_usec: u32,
    ts: u64,
}

#[repr(C)]
struct ProbeOp {
    op: u8,
    resv: u8,
    flags: u16,
    resv2: u32,
}

#[repr(C)]
struct Probe {
    last_op: u8,
    ops_len: u8,
    resv: u16,
    resv2: [u32; 3],
    ops: [ProbeOp; 64],
}

fn setup(entries: u32, p: &mut Params) -> io::Result<OwnedFd> {
    #[cfg(test)]
    if p.flags & REFUSE_SETUP.with(|r| r.get()) != 0 {
        return Err(io::Error::from_raw_os_error(sys::EINVAL));
    }
    // SAFETY: io_uring_setup reads and writes the params struct we pass.
    let r = unsafe { sys::syscall(sys::SYS_IO_URING_SETUP, entries, p as *mut Params) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh ring descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
}

fn register(fd: i32, op: u32, arg: *const c_void, nr: u32) -> io::Result<i32> {
    // SAFETY: the caller passes an argument valid for `op`; the kernel copies it before returning.
    let r = unsafe { sys::syscall(sys::SYS_IO_URING_REGISTER, fd, op, arg, nr) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r as i32)
}

struct Mmap {
    ptr: *mut u8,
    len: usize,
}

impl Mmap {
    fn ring(fd: i32, len: usize, off: i64) -> io::Result<Mmap> {
        // SAFETY: maps a region of the ring descriptor; checked against MAP_FAILED.
        let p = unsafe { sys::mmap(core::ptr::null_mut(), len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_SHARED | sys::MAP_POPULATE, fd, off) };
        if p == sys::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Mmap { ptr: p.cast(), len })
    }
    fn anon(len: usize) -> io::Result<Mmap> {
        // SAFETY: anonymous private mapping; checked against MAP_FAILED.
        let p = unsafe { sys::mmap(core::ptr::null_mut(), len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0) };
        if p == sys::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Mmap { ptr: p.cast(), len })
    }
    /// Leaves the mapping in place forever (the kernel may still use it).
    fn leak(mut self) {
        self.len = 0;
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len > 0 {
            // SAFETY: unmaps a region this struct mapped and nothing references any more.
            unsafe { sys::munmap(self.ptr.cast(), self.len) };
        }
    }
}

/// The raw submission and completion rings.
struct Ring {
    // Field order matters for Drop: the mappings go before the descriptor closes.
    _sq_map: Mmap,
    _sqe_map: Mmap,
    fd: OwnedFd,
    sq_head: *const AtomicU32,
    sq_tail: *const AtomicU32,
    sq_mask: u32,
    sq_entries: u32,
    sqes: *mut Sqe,
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const Cqe,
    tail: u32,
}

/// Optional set-up flags with their names. `CQSIZE` and `CLAMP` (5.5) are always asked for.
const OPTIONAL_SETUP: [(u32, &str); 3] = [(SETUP_SUBMIT_ALL, "SUBMIT_ALL"), (SETUP_DEFER_TASKRUN, "DEFER_TASKRUN"), (SETUP_SINGLE_ISSUER, "SINGLE_ISSUER")];

/// The optional flags to leave out, tried in this order while the kernel answers `EINVAL` (a
/// flag it doesn't know, or a combination it refuses): one flag at a time first, so a kernel
/// gets the best subset it accepts. `DEFER_TASKRUN` needs `SINGLE_ISSUER`.
const SETUP_DROPS: [u32; 6] = [
    0,
    SETUP_SUBMIT_ALL,
    SETUP_DEFER_TASKRUN,
    SETUP_DEFER_TASKRUN | SETUP_SUBMIT_ALL,
    SETUP_DEFER_TASKRUN | SETUP_SINGLE_ISSUER,
    SETUP_DEFER_TASKRUN | SETUP_SINGLE_ISSUER | SETUP_SUBMIT_ALL,
];

#[cfg(test)]
thread_local! {
    /// Tests: set-up flags `io_uring_setup` pretends not to know (answers `EINVAL`).
    pub(crate) static REFUSE_SETUP: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
    /// Tests: act as if a provided-buffer ring in user memory were refused (as on 6.8).
    pub(crate) static FORCE_PBUF_MMAP: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Tests: act as if provided-buffer rings were refused altogether (Ubuntu's 6.8).
    pub(crate) static FORCE_PBUF_LEGACY: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Annotates a set-up error with the step that failed, keeping its kind.
#[cold]
#[inline(never)]
fn step(what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

impl Ring {
    /// Sets up a ring with the best set-up flags the kernel accepts; `dropped` collects the
    /// names of the optional flags it refused.
    fn new(entries: u32, dropped: &mut Vec<&'static str>) -> io::Result<Ring> {
        let all = SETUP_CQSIZE | SETUP_CLAMP | SETUP_SUBMIT_ALL | SETUP_DEFER_TASKRUN | SETUP_SINGLE_ISSUER;
        let mut found = None;
        let mut last = None;
        for drop in SETUP_DROPS {
            let mut p = Params { flags: all & !drop, cq_entries: entries * 4, ..Default::default() };
            match setup(entries, &mut p) {
                Ok(fd) => {
                    found = Some((fd, p, drop));
                    break;
                }
                Err(e) if e.raw_os_error() == Some(sys::EINVAL) => last = Some(e),
                Err(e) => return Err(step("io_uring_setup", e)),
            }
        }
        let Some((fd, p, drop)) = found else {
            return Err(step("io_uring_setup", last.unwrap_or_else(|| io::Error::from_raw_os_error(sys::EINVAL))));
        };
        for (f, name) in OPTIONAL_SETUP {
            if drop & f != 0 {
                dropped.push(name);
            }
        }
        let need = FEAT_SINGLE_MMAP | FEAT_NODROP | FEAT_EXT_ARG;
        if p.features & need != need {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "io_uring lacks SINGLE_MMAP, NODROP or EXT_ARG"));
        }
        let sq_len = p.sq_off.array as usize + p.sq_entries as usize * 4;
        let cq_len = p.cq_off.cqes as usize + p.cq_entries as usize * core::mem::size_of::<Cqe>();
        let sq_map = Mmap::ring(fd.as_raw_fd(), sq_len.max(cq_len), OFF_SQ_RING).map_err(|e| step("mmap of the rings", e))?;
        let sqe_map = Mmap::ring(fd.as_raw_fd(), p.sq_entries as usize * core::mem::size_of::<Sqe>(), OFF_SQES).map_err(|e| step("mmap of the SQEs", e))?;
        // One mapping holds both rings (FEAT_SINGLE_MMAP).
        let base = sq_map.ptr;
        // SAFETY: every offset comes from the kernel and lies inside the mapping; the rings are
        // aligned for the u32 atomics and entries they hold.
        unsafe {
            let array = base.add(p.sq_off.array as usize).cast::<u32>();
            // The SQ index array never changes: slot i always holds SQE i.
            for i in 0..p.sq_entries {
                *array.add(i as usize) = i;
            }
            Ok(Ring {
                sq_head: base.add(p.sq_off.head as usize).cast(),
                sq_tail: base.add(p.sq_off.tail as usize).cast(),
                sq_mask: *base.add(p.sq_off.ring_mask as usize).cast::<u32>(),
                sq_entries: p.sq_entries,
                sqes: sqe_map.ptr.cast(),
                cq_head: base.add(p.cq_off.head as usize).cast(),
                cq_tail: base.add(p.cq_off.tail as usize).cast(),
                cq_mask: *base.add(p.cq_off.ring_mask as usize).cast::<u32>(),
                cqes: base.add(p.cq_off.cqes as usize).cast(),
                tail: (*base.add(p.sq_off.tail as usize).cast::<AtomicU32>()).load(Ordering::Relaxed),
                _sq_map: sq_map,
                _sqe_map: sqe_map,
                fd,
            })
        }
    }

    fn sq_head(&self) -> u32 {
        // SAFETY: points into the live SQ ring mapping.
        unsafe { (*self.sq_head).load(Ordering::Acquire) }
    }

    /// Entries written but not yet consumed by the kernel.
    fn pending(&self) -> u32 {
        self.tail.wrapping_sub(self.sq_head())
    }

    /// Writes an SQE; `false` when the queue is full (submit first).
    fn push(&mut self, sqe: Sqe) -> bool {
        if self.pending() >= self.sq_entries {
            return false;
        }
        // SAFETY: the index is masked into the SQE array, and the slot is free because fewer
        // than `sq_entries` entries are pending.
        unsafe { *self.sqes.add((self.tail & self.sq_mask) as usize) = sqe };
        self.tail = self.tail.wrapping_add(1);
        true
    }

    /// Publishes written SQEs and calls `io_uring_enter`.
    fn enter(&mut self, min_complete: u32, timeout: Option<Duration>) -> io::Result<()> {
        // SAFETY: points into the live SQ ring mapping; Release makes the SQEs visible first.
        unsafe { (*self.sq_tail).store(self.tail, Ordering::Release) };
        let to_submit = self.pending();
        let ts = timeout.map(|d| sys::timespec { tv_sec: d.as_secs() as i64, tv_nsec: d.subsec_nanos() as i64 });
        let arg = GeteventsArg { sigmask: 0, sigmask_sz: 8, min_wait_usec: 0, ts: ts.as_ref().map_or(0, |t| t as *const sys::timespec as u64) };
        // SAFETY: `arg` and `ts` live across the call; EXT_ARG tells the kernel their layout.
        let r = unsafe {
            sys::syscall(
                sys::SYS_IO_URING_ENTER,
                self.fd.as_raw_fd(),
                to_submit,
                min_complete,
                ENTER_GETEVENTS | ENTER_EXT_ARG,
                &arg as *const GeteventsArg,
                core::mem::size_of::<GeteventsArg>(),
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(sys::ETIME) | Some(sys::EINTR) | Some(sys::EBUSY) | Some(sys::EAGAIN) => return Ok(()),
                _ => return Err(e),
            }
        }
        Ok(())
    }

    /// Takes every available CQE.
    fn reap(&mut self, out: &mut Vec<Cqe>) {
        // SAFETY: both pointers lie in the live CQ ring; the CQE slots between head and tail
        // were written by the kernel before its Release store of the tail.
        unsafe {
            let head = (*self.cq_head).load(Ordering::Relaxed);
            let tail = (*self.cq_tail).load(Ordering::Acquire);
            let mut i = head;
            while i != tail {
                out.push(*self.cqes.add((i & self.cq_mask) as usize));
                i = i.wrapping_add(1);
            }
            (*self.cq_head).store(tail, Ordering::Release);
        }
    }
}

// --- probing ----------------------------------------------------------------------------------

/// Checks that this kernel offers what the driver needs: a 6.1+ ring with single-issuer and
/// deferred task running, the opcodes used here, and provided-buffer rings.
pub fn available() -> io::Result<()> {
    let ring = Ring::new(8, &mut Vec::new())?;
    let provide_ok = probe_ops(&ring)?;
    let pb = BufRing::new(ring.fd.as_raw_fd(), 8, provide_ok, &mut Vec::new())?;
    drop(pb);
    Ok(())
}

/// Checks the opcodes the driver needs; returns whether `IORING_OP_PROVIDE_BUFFERS` (the
/// fallback for kernels that refuse provided-buffer rings) is there too.
fn probe_ops(ring: &Ring) -> io::Result<bool> {
    // SAFETY: an all-zero probe is what the kernel expects as input.
    let mut probe: Probe = unsafe { core::mem::zeroed() };
    register(ring.fd.as_raw_fd(), REGISTER_PROBE, (&mut probe as *mut Probe).cast(), 64).map_err(|e| step("IORING_REGISTER_PROBE", e))?;
    for op in [OP_POLL_ADD, OP_SENDMSG, OP_ACCEPT, OP_ASYNC_CANCEL, OP_SEND, OP_RECV] {
        let ok = (op as usize) < probe.ops_len as usize && probe.ops[op as usize].flags & PROBE_OP_SUPPORTED != 0;
        if !ok {
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("io_uring opcode {op} not supported")));
        }
    }
    let op = OP_PROVIDE_BUFFERS as usize;
    Ok(op < probe.ops_len as usize && probe.ops[op].flags & PROBE_OP_SUPPORTED != 0)
}

// --- provided-buffer ring ---------------------------------------------------------------------

struct BufRing {
    map: Mmap,
    entries: u16,
    mask: u16,
    tail: u16,
    /// No ring: buffers are handed over with `IORING_OP_PROVIDE_BUFFERS` (5.7), one SQE each.
    /// Ubuntu's 6.8 kernels refuse every `IORING_REGISTER_PBUF_RING` with `EINVAL`.
    legacy: bool,
}

/// `IOU_PBUF_RING_MMAP` (6.4): the kernel allocates the provided-buffer ring and the
/// application maps it from the ring descriptor.
const PBUF_RING_MMAP: u16 = 1;
const OFF_PBUF_RING: i64 = 0x8000_0000;
const OFF_PBUF_SHIFT: u32 = 16;

impl BufRing {
    /// Registers the ring in our own memory; where the kernel refuses that (6.8 refuses a ring
    /// in user memory larger than one page with `EINVAL`), asks the kernel to allocate it
    /// (`IOU_PBUF_RING_MMAP`). `notes` records the second case.
    fn new(ring_fd: i32, entries: u16, provide_ok: bool, notes: &mut Vec<&'static str>) -> io::Result<BufRing> {
        let entries = entries.next_power_of_two().clamp(1, 32768);
        let len = entries as usize * core::mem::size_of::<RingBuf>();
        let map = Mmap::anon(len)?;
        let reg = BufReg { ring_addr: map.ptr as u64, ring_entries: entries as u32, bgid: BGID, flags: 0, resv: [0; 3] };
        #[cfg(test)]
        let user = if FORCE_PBUF_MMAP.with(|f| f.get()) { Err(io::Error::from_raw_os_error(sys::EINVAL)) } else { register(ring_fd, REGISTER_PBUF_RING, (&reg as *const BufReg).cast(), 1) };
        #[cfg(not(test))]
        let user = register(ring_fd, REGISTER_PBUF_RING, (&reg as *const BufReg).cast(), 1);
        match user {
            Ok(_) => return Ok(BufRing { map, entries, mask: entries - 1, tail: 0, legacy: false }),
            Err(e) if e.raw_os_error() != Some(sys::EINVAL) => return Err(step("IORING_REGISTER_PBUF_RING", e)),
            Err(_) => drop(map),
        }
        let reg = BufReg { ring_addr: 0, ring_entries: entries as u32, bgid: BGID, flags: PBUF_RING_MMAP, resv: [0; 3] };
        #[cfg(test)]
        let r = if FORCE_PBUF_LEGACY.with(|f| f.get()) { Err(io::Error::from_raw_os_error(sys::EINVAL)) } else { register(ring_fd, REGISTER_PBUF_RING, (&reg as *const BufReg).cast(), 1) };
        #[cfg(not(test))]
        let r = register(ring_fd, REGISTER_PBUF_RING, (&reg as *const BufReg).cast(), 1);
        match r {
            Ok(_) => {
                let off = OFF_PBUF_RING | ((BGID as i64) << OFF_PBUF_SHIFT);
                let map = Mmap::ring(ring_fd, len, off).map_err(|e| step("mmap of the provided-buffer ring", e))?;
                notes.push("provided-buffer ring in user memory (kernel-allocated ring used)");
                Ok(BufRing { map, entries, mask: entries - 1, tail: 0, legacy: false })
            }
            Err(e) if e.raw_os_error() == Some(sys::EINVAL) && provide_ok => {
                notes.push("provided-buffer rings (IORING_REGISTER_PBUF_RING refused; IORING_OP_PROVIDE_BUFFERS used)");
                Ok(BufRing { map: Mmap { ptr: core::ptr::null_mut(), len: 0 }, entries, mask: entries - 1, tail: 0, legacy: true })
            }
            Err(e) => Err(step("IORING_REGISTER_PBUF_RING", e)),
        }
    }

    /// Adds a buffer (not yet visible to the kernel until `publish`).
    fn add(&mut self, addr: *mut u8, len: u32, bid: u16) {
        let i = (self.tail & self.mask) as usize;
        // SAFETY: `i` is masked into the ring mapping, which holds `entries` RingBufs. Only the
        // first 14 bytes are written so the tail stored in entry 0 is left alone.
        unsafe {
            let e = self.map.ptr.cast::<RingBuf>().add(i);
            core::ptr::addr_of_mut!((*e).addr).write(addr as u64);
            core::ptr::addr_of_mut!((*e).len).write(len);
            core::ptr::addr_of_mut!((*e).bid).write(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    fn publish(&self) {
        if self.legacy {
            return;
        }
        // SAFETY: the tail is the u16 at offset 14 of entry 0; Release orders the entries first.
        unsafe { (*self.map.ptr.add(14).cast::<AtomicU16>()).store(self.tail, Ordering::Release) };
    }
}

// --- the driver -------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Op {
    Accept = 1,
    Recv = 2,
    Send = 3,
    Poll = 4,
    Cancel = 5,
    Wake = 6,
}

fn user_data(op: Op, id: Id) -> u64 {
    (op as u64) << 56 | ((id.gen() as u64) & 0xFF_FFFF) << 32 | id.idx() as u64
}

fn decode(ud: u64) -> (u8, u32, u32) {
    ((ud >> 56) as u8, ((ud >> 32) & 0xFF_FFFF) as u32, ud as u32)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Listener,
    Stream,
    Udp,
}

struct SendOp {
    msg: sys::msghdr,
    iov: Vec<sys::iovec>,
    bufs: Vec<OutBuf>,
    off: usize,
    total: usize,
}

struct Entry {
    sock: Socket,
    key: u64,
    kind: Kind,
    slot: Option<u32>,
    armed: bool,
    active: bool, // the multishot accept / recv / poll is outstanding
    readable: bool,
    in_flush: bool,
    in_read: bool,
    failed: bool,
    closing: bool,
    send: Option<Box<SendOp>>,
    out: VecDeque<OutBuf>,
    off: usize,
    /// A UDP socket receiving into large buffers (GRO).
    large: bool,
}

impl Entry {
    fn ops(&self) -> u32 {
        self.active as u32 + self.send.is_some() as u32
    }
}

pub(crate) struct Driver {
    ring: Ring,
    bufring: BufRing,
    bufs: Vec<Option<Vec<u8>>>,
    free_bids: Vec<u16>,
    stash: Vec<Vec<u8>>,
    target: usize,
    slab: Slab<Entry>,
    slots_free: Vec<u32>,
    fixed: bool,
    efd: Arc<OwnedFd>,
    waker: Waker,
    wake_armed: bool,
    flush_list: Vec<Id>,
    read_list: Vec<Id>,
    rearm: Vec<Id>,
    closing: Vec<Id>,
    starved: Vec<Id>,
    pending: Vec<Event>,
    cqes: Vec<Cqe>,
    send_pool: Vec<Box<SendOp>>,
    scratch: Vec<Vec<u8>>,
    large: LargeBufs,
    udp_count: usize,
    stats: DriverStats,
    budget: usize,
    /// Optional features the kernel refused (set-up flags, registered files).
    dropped: Vec<&'static str>,
}

impl Driver {
    /// The optional io_uring features this kernel refused, if any.
    pub(crate) fn degraded(&self) -> Option<String> {
        if self.dropped.is_empty() {
            None
        } else {
            let mut s = String::from("io_uring without ");
            for (i, d) in self.dropped.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(d);
            }
            Some(s)
        }
    }

    #[inline(never)]
    pub(crate) fn new(cfg: &DriverConfig) -> io::Result<Driver> {
        let fail = cfg.uring_simulate_failure.or_else(|| std::env::var("SIMOOM_IO_URING_FAIL").ok().and_then(|v| v.parse().ok()));
        if let Some(errno) = fail {
            return Err(io::Error::from_raw_os_error(errno));
        }
        let mut dropped = Vec::new();
        let ring = Ring::new(cfg.uring_entries.clamp(8, 32768), &mut dropped)?;
        let provide_ok = probe_ops(&ring)?;
        let bufring = BufRing::new(ring.fd.as_raw_fd(), cfg.uring_buffers.max(8), provide_ok, &mut dropped)?;
        let entries = bufring.entries;
        let mut stats = DriverStats::default();
        let mut fixed = false;
        let mut slots_free = Vec::new();
        if cfg.uring_fixed_files && cfg.uring_max_files > 0 {
            // The kernel refuses a table larger than RLIMIT_NOFILE (EMFILE); shells default the
            // soft limit to 1024, so ask for at most that many.
            let mut lim = sys::rlimit::default();
            // SAFETY: getrlimit writes one rlimit.
            let soft = if unsafe { sys::getrlimit(sys::RLIMIT_NOFILE, &mut lim) } == 0 { lim.rlim_cur } else { 1024 };
            let n = cfg.uring_max_files.min(1 << 20).min(soft.min(u32::MAX as u64) as u32);
            let reg = RsrcRegister { nr: n, flags: RSRC_REGISTER_SPARSE, resv2: 0, data: 0, tags: 0 };
            stats.other_calls += 1;
            let ok = register(ring.fd.as_raw_fd(), REGISTER_FILES2, (&reg as *const RsrcRegister).cast(), core::mem::size_of::<RsrcRegister>() as u32).is_ok() || {
                let fds = vec![-1i32; n as usize];
                stats.other_calls += 1;
                register(ring.fd.as_raw_fd(), REGISTER_FILES, fds.as_ptr().cast(), n).is_ok()
            };
            if ok {
                fixed = true;
                slots_free = (0..n).rev().collect();
            } else {
                dropped.push("registered files");
            }
        }
        let efd = Arc::new(eventfd()?);
        let waker = eventfd_waker(efd.clone());
        let mut d = Driver {
            ring,
            bufring,
            bufs: (0..entries).map(|_| None).collect(),
            free_bids: (0..entries).rev().collect(),
            stash: Vec::new(),
            target: (entries as usize / 2).max(8),
            slab: Slab::new(),
            slots_free,
            fixed,
            efd,
            waker,
            wake_armed: false,
            flush_list: Vec::new(),
            read_list: Vec::new(),
            rearm: Vec::new(),
            closing: Vec::new(),
            starved: Vec::new(),
            pending: Vec::new(),
            cqes: Vec::with_capacity(cfg.events.max(64)),
            send_pool: Vec::new(),
            scratch: Vec::with_capacity(BATCH),
            large: LargeBufs::default(),
            udp_count: 0,
            stats,
            budget: cfg.recv_budget.max(1),
            dropped,
        };
        d.arm_wake();
        Ok(d)
    }

    fn push(&mut self, sqe: Sqe) {
        self.stats.sqes += 1;
        while !self.ring.push(sqe) {
            // Queue full: submit what is there without waiting.
            self.stats.waits += 1;
            let _ = self.ring.enter(0, Some(Duration::ZERO));
        }
    }

    fn arm_wake(&mut self) {
        let sqe = Sqe { opcode: OP_POLL_ADD, fd: self.efd.as_raw_fd(), len: POLL_ADD_MULTI, op_flags: POLLIN, user_data: (Op::Wake as u64) << 56, ..Default::default() };
        self.push(sqe);
        self.wake_armed = true;
    }

    /// fd and flags for an SQE on this entry.
    fn target(e: &Entry) -> (i32, u8) {
        match e.slot {
            Some(s) => (s as i32, SQE_FIXED_FILE),
            None => (e.sock.raw(), 0),
        }
    }

    fn arm(&mut self, id: Id) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.active || e.closing {
            return;
        }
        let (fd, ff) = Self::target(e);
        let sqe = match e.kind {
            Kind::Listener => Sqe {
                opcode: OP_ACCEPT,
                fd,
                flags: ff,
                ioprio: ACCEPT_MULTISHOT,
                op_flags: (sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC) as u32,
                user_data: user_data(Op::Accept, id),
                ..Default::default()
            },
            Kind::Stream => {
                if !e.armed {
                    return;
                }
                Sqe { opcode: OP_RECV, fd, flags: ff | SQE_BUFFER_SELECT, ioprio: RECV_MULTISHOT, buf_index: BGID, user_data: user_data(Op::Recv, id), ..Default::default() }
            }
            Kind::Udp => Sqe { opcode: OP_POLL_ADD, fd, flags: ff, len: POLL_ADD_MULTI, op_flags: POLLIN, user_data: user_data(Op::Poll, id), ..Default::default() },
        };
        e.active = true;
        self.push(sqe);
    }

    fn cancel(&mut self, op: Op, id: Id) {
        let sqe = Sqe { opcode: OP_ASYNC_CANCEL, flags: SQE_CQE_SKIP_SUCCESS, addr: user_data(op, id), user_data: (Op::Cancel as u64) << 56, ..Default::default() };
        self.push(sqe);
    }

    pub(crate) fn waker(&self) -> Waker {
        self.waker.clone()
    }

    fn add(&mut self, sock: Socket, key: u64, kind: Kind) -> io::Result<Id> {
        let mut slot = None;
        if self.fixed && kind == Kind::Stream {
            if let Some(s) = self.slots_free.pop() {
                let fd = sock.raw();
                let up = FilesUpdate { offset: s, resv: 0, fds: &fd as *const i32 as u64 };
                self.stats.other_calls += 1;
                match register(self.ring.fd.as_raw_fd(), REGISTER_FILES_UPDATE, (&up as *const FilesUpdate).cast(), 1) {
                    Ok(_) => slot = Some(s),
                    Err(_) => self.slots_free.push(s),
                }
            }
        }
        let id = self.slab.insert(Entry {
            sock,
            key,
            kind,
            slot,
            armed: false,
            active: false,
            readable: false,
            in_flush: false,
            in_read: false,
            failed: false,
            closing: false,
            send: None,
            out: VecDeque::new(),
            off: 0,
            large: false,
        });
        if kind == Kind::Udp {
            self.udp_count += 1;
        }
        if kind != Kind::Stream {
            self.arm(id);
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

    pub(crate) fn udp_large(&mut self, sock: Socket, key: u64, size: usize) -> io::Result<Id> {
        let id = self.add(sock, key, Kind::Udp)?;
        self.large.size = self.large.size.max(size);
        if let Some(e) = self.slab.get_mut(id) {
            e.large = true;
        }
        Ok(id)
    }

    pub(crate) fn recv(&mut self, id: Id, on: bool) {
        let Some(e) = self.slab.get_mut(id) else { return };
        if e.kind == Kind::Listener || e.closing || e.armed == on {
            return;
        }
        e.armed = on;
        match (e.kind, on) {
            (Kind::Stream, true) => self.arm(id),
            (Kind::Stream, false) => {
                if e.active {
                    self.cancel(Op::Recv, id);
                }
            }
            (Kind::Udp, true) => {
                if e.readable && !e.in_read {
                    e.in_read = true;
                    self.read_list.push(id);
                }
            }
            _ => {}
        }
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
        self.stats.send_calls += 1;
        e.sock.send_msgs(msgs)
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
        let (active, sending, kind) = (e.active, e.send.is_some(), e.kind);
        if active {
            let op = match kind {
                Kind::Listener => Op::Accept,
                Kind::Stream => Op::Recv,
                Kind::Udp => Op::Poll,
            };
            self.cancel(op, id);
        }
        if sending {
            self.cancel(Op::Send, id);
        }
        self.closing.push(id);
    }

    /// Frees closed entries whose operations have all completed.
    fn finish_closing(&mut self) {
        let mut i = 0;
        while i < self.closing.len() {
            let id = self.closing[i];
            let done = self.slab.get(id).is_none_or(|e| e.ops() == 0);
            if !done {
                i += 1;
                continue;
            }
            self.closing.swap_remove(i);
            if let Some(e) = self.slab.remove(id) {
                if let Some(s) = e.slot {
                    let fd: i32 = -1;
                    let up = FilesUpdate { offset: s, resv: 0, fds: &fd as *const i32 as u64 };
                    self.stats.other_calls += 1;
                    if register(self.ring.fd.as_raw_fd(), REGISTER_FILES_UPDATE, (&up as *const FilesUpdate).cast(), 1).is_ok() {
                        self.slots_free.push(s);
                    }
                }
                if e.kind == Kind::Udp {
                    self.udp_count -= 1;
                }
                self.pending.push(Event::Closed { key: e.key });
            }
        }
    }

    pub(crate) fn socket(&self, id: Id) -> Option<&Socket> {
        self.slab.get(id).map(|e| &e.sock)
    }

    pub(crate) fn provide(&mut self, buf: Vec<u8>) {
        let Some(mut buf) = self.large.keep(buf) else { return };
        buf.clear();
        // UDP sockets read with recvmmsg, from the stash; streams use the ring.
        if self.udp_count > 0 && self.stash.len() < BATCH {
            self.stash.push(buf);
            return;
        }
        match self.free_bids.pop() {
            Some(bid) if buf.capacity() > 0 => {
                let cap = buf.capacity().min(u32::MAX as usize) as u32;
                let ptr = buf.as_mut_ptr();
                self.bufs[bid as usize] = Some(buf);
                self.give(ptr, cap, bid);
                self.bufring.publish();
            }
            Some(bid) => self.free_bids.push(bid),
            None => self.stash.push(buf),
        }
    }

    /// Hands one buffer to the kernel: into the ring, or with a `PROVIDE_BUFFERS` SQE (submitted
    /// with the next `io_uring_enter`, before anything that could pick it).
    fn give(&mut self, ptr: *mut u8, cap: u32, bid: u16) {
        if self.bufring.legacy {
            let sqe = Sqe {
                opcode: OP_PROVIDE_BUFFERS,
                flags: SQE_CQE_SKIP_SUCCESS,
                fd: 1, // one buffer
                addr: ptr as u64,
                len: cap,
                off: bid as u64,
                buf_index: BGID,
                user_data: (Op::Cancel as u64) << 56, // completions (errors only) are ignored
                ..Default::default()
            };
            self.push(sqe);
            self.stats.sqes -= 1; // a buffer hand-over, not I/O: kept out of the SQE count
        } else {
            self.bufring.add(ptr, cap, bid);
        }
    }

    /// Moves stock buffers into the ring when bids are free (keeping a UDP reserve).
    fn refill_ring(&mut self) {
        let reserve = if self.udp_count > 0 { BATCH } else { 0 };
        let mut moved = false;
        while self.stash.len() > reserve && !self.free_bids.is_empty() {
            let mut buf = self.stash.pop().unwrap();
            if buf.capacity() == 0 {
                continue;
            }
            let bid = self.free_bids.pop().unwrap();
            let cap = buf.capacity().min(u32::MAX as usize) as u32;
            let ptr = buf.as_mut_ptr();
            self.bufs[bid as usize] = Some(buf);
            self.give(ptr, cap, bid);
            moved = true;
        }
        if moved {
            self.bufring.publish();
        }
    }

    fn in_ring(&self) -> usize {
        self.bufs.len() - self.free_bids.len()
    }

    pub(crate) fn buffers_wanted(&self) -> usize {
        let have = self.in_ring() + self.stash.len();
        let target = self.target.min(self.bufs.len()) + if self.udp_count > 0 { BATCH } else { 0 };
        target.saturating_sub(have)
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

    fn flush(&mut self) {
        let list = std::mem::take(&mut self.flush_list);
        for id in list {
            let Some(e) = self.slab.get_mut(id) else { continue };
            e.in_flush = false;
            if e.send.is_some() || e.out.is_empty() || e.closing || e.failed {
                continue;
            }
            let mut op = self.send_pool.pop().unwrap_or_else(|| {
                Box::new(SendOp {
                    // SAFETY: an all-zero msghdr is valid.
                    msg: unsafe { core::mem::zeroed() },
                    iov: Vec::with_capacity(64),
                    bufs: Vec::with_capacity(64),
                    off: 0,
                    total: 0,
                })
            });
            op.off = e.off;
            e.off = 0;
            while op.bufs.len() < 64 {
                match e.out.pop_front() {
                    Some(b) => op.bufs.push(b),
                    None => break,
                }
            }
            op.iov.clear();
            for (i, b) in op.bufs.iter().enumerate() {
                let s = if i == 0 { &b.as_slice()[op.off..] } else { b.as_slice() };
                op.iov.push(sys::iovec { iov_base: s.as_ptr() as *mut c_void, iov_len: s.len() });
            }
            op.total = op.iov.iter().map(|v| v.iov_len).sum();
            let (fd, ff) = Self::target(e);
            let flags = (sys::MSG_NOSIGNAL | sys::MSG_WAITALL) as u32;
            let sqe = if op.iov.len() == 1 {
                Sqe { opcode: OP_SEND, fd, flags: ff, addr: op.iov[0].iov_base as u64, len: op.iov[0].iov_len as u32, op_flags: flags, user_data: user_data(Op::Send, id), ..Default::default() }
            } else {
                op.msg.msg_iov = op.iov.as_mut_ptr();
                op.msg.msg_iovlen = op.iov.len();
                Sqe { opcode: OP_SENDMSG, fd, flags: ff, addr: &op.msg as *const sys::msghdr as u64, op_flags: flags, user_data: user_data(Op::Send, id), ..Default::default() }
            };
            // The boxed op (msghdr, iovecs and buffers) stays put until the completion.
            e.send = Some(op);
            self.push(sqe);
        }
    }

    fn complete(&mut self, c: Cqe, out: &mut Vec<Event>) {
        let (op, gen, idx) = decode(c.user_data);
        if op == Op::Cancel as u8 {
            return;
        }
        if op == Op::Wake as u8 {
            self.stats.other_calls += 1;
            drain_eventfd(&self.efd);
            self.waker.clear();
            out.push(Event::Wake);
            if c.flags & CQE_F_MORE == 0 {
                self.wake_armed = false;
            }
            return;
        }
        // A buffer the kernel picked is ours again whatever happens to the entry.
        let picked = if c.flags & CQE_F_BUFFER != 0 {
            let bid = (c.flags >> CQE_BUFFER_SHIFT) as u16;
            let b = self.bufs.get_mut(bid as usize).and_then(|s| s.take());
            if b.is_some() {
                self.free_bids.push(bid);
            }
            b
        } else {
            None
        };
        let Some(id) = self.slab.id_at(idx) else { return };
        if id.gen() & 0xFF_FFFF != gen {
            return;
        }
        let more = c.flags & CQE_F_MORE != 0;
        let e = self.slab.get_mut(id).unwrap();
        let key = e.key;
        match op {
            x if x == Op::Accept as u8 => {
                if !more {
                    e.active = false;
                    if !e.closing {
                        self.rearm.push(id);
                    }
                }
                if c.res >= 0 {
                    // SAFETY: a successful accept returns a fresh descriptor that we now own.
                    let socket = unsafe { Socket::from_raw(c.res) };
                    if e.closing {
                        drop(socket);
                    } else {
                        out.push(Event::Accepted { key, socket, peer: None });
                    }
                } else if c.res != -sys::ECANCELED && !e.closing {
                    out.push(Event::Error { key, error: io::Error::from_raw_os_error(-c.res) });
                }
            }
            x if x == Op::Recv as u8 => {
                if !more {
                    e.active = false;
                }
                if c.res > 0 {
                    if let Some(mut b) = picked {
                        // SAFETY: the kernel wrote `res` bytes into this buffer's capacity.
                        unsafe { b.set_len((c.res as usize).min(b.capacity())) };
                        out.push(Event::Data { key, buf: b });
                    }
                    if !more && e.armed && !e.closing {
                        self.rearm.push(id);
                    }
                } else {
                    if let Some(b) = picked {
                        self.stash.push(b);
                    }
                    match -c.res {
                        0 => {
                            if !e.closing {
                                e.armed = false;
                                out.push(Event::Eof { key });
                            }
                        }
                        sys::ENOBUFS => {
                            if e.armed && !e.closing {
                                self.starved.push(id);
                            }
                        }
                        sys::ECANCELED => {
                            // Paused, then perhaps resumed before the cancellation landed.
                            if e.armed && !e.closing {
                                self.rearm.push(id);
                            }
                        }
                        errno => {
                            if !e.closing {
                                e.armed = false;
                                out.push(Event::Error { key, error: io::Error::from_raw_os_error(errno) });
                            }
                        }
                    }
                }
            }
            x if x == Op::Poll as u8 => {
                if !more {
                    e.active = false;
                    if !e.closing {
                        self.rearm.push(id);
                    }
                }
                if c.res > 0 && !e.closing {
                    e.readable = true;
                    if e.armed && !e.in_read {
                        e.in_read = true;
                        self.read_list.push(id);
                    }
                }
            }
            x if x == Op::Send as u8 => {
                let Some(mut sop) = e.send.take() else { return };
                if c.res < 0 {
                    for buf in sop.bufs.drain(..) {
                        out.push(Event::Sent { key, buf });
                    }
                    if !e.closing && c.res != -sys::ECANCELED {
                        e.failed = true;
                        out.push(Event::Error { key, error: io::Error::from_raw_os_error(-c.res) });
                        for buf in e.out.drain(..) {
                            out.push(Event::Sent { key, buf });
                        }
                    }
                } else {
                    let mut w = c.res as usize;
                    let mut off = sop.off;
                    let mut rest: Vec<OutBuf> = Vec::new();
                    for buf in sop.bufs.drain(..) {
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
                        // A short send: put the rest back in front, keeping the order.
                        let first_off = off;
                        for b in rest.into_iter().rev() {
                            e.out.push_front(b);
                        }
                        e.off = first_off;
                    }
                    if !e.out.is_empty() && !e.closing && !e.in_flush {
                        e.in_flush = true;
                        self.flush_list.push(id);
                    }
                }
                sop.total = 0;
                self.send_pool.push(sop);
            }
            _ => {}
        }
    }

    fn read_udp(&mut self, out: &mut Vec<Event>) {
        let list = std::mem::take(&mut self.read_list);
        let mut keep = Vec::new();
        for id in list {
            let Some(e) = self.slab.get_mut(id) else { continue };
            if !e.armed || !e.readable || e.closing {
                e.in_read = false;
                continue;
            }
            let mut done = false;
            for _ in 0..self.budget {
                let n = if e.large {
                    let large = &mut self.large;
                    self.scratch.extend((0..LARGE_BATCH).map(|_| large.take()));
                    LARGE_BATCH
                } else {
                    let n = self.stash.len().min(BATCH);
                    if n == 0 {
                        break;
                    }
                    let at = self.stash.len() - n;
                    self.scratch.extend(self.stash.drain(at..));
                    n
                };
                let mut meta = [RecvMeta::default(); BATCH];
                self.stats.recv_calls += 1;
                let r = e.sock.recv_msgs(&mut self.scratch, &mut meta);
                let got = match r {
                    Ok(got) => got,
                    Err(err) => {
                        if err.kind() != io::ErrorKind::WouldBlock && err.kind() != io::ErrorKind::Interrupted {
                            out.push(Event::Error { key: e.key, error: err });
                        }
                        0
                    }
                };
                for (i, buf) in self.scratch.drain(..got).enumerate() {
                    out.push(Event::Datagram { key: e.key, buf, meta: meta[i] });
                }
                for b in self.scratch.drain(..) {
                    if let Some(mut b) = self.large.keep(b) {
                        b.clear();
                        self.stash.push(b);
                    }
                }
                if got < n {
                    done = true;
                    break;
                }
            }
            if done {
                e.readable = false;
                e.in_read = false;
            } else {
                keep.push(id);
            }
        }
        self.read_list = keep;
    }

    pub(crate) fn turn(&mut self, timeout: Option<Duration>, out: &mut Vec<Event>) -> io::Result<()> {
        self.finish_closing();
        out.append(&mut self.pending);
        self.refill_ring();
        // Re-arm what stopped: ended multishots, and receives that ran out of ring buffers.
        if self.in_ring() > 0 {
            let starved = std::mem::take(&mut self.starved);
            self.rearm.extend(starved);
        }
        let rearm = std::mem::take(&mut self.rearm);
        for id in rearm {
            self.arm(id);
        }
        if !self.wake_armed {
            self.arm_wake();
        }
        self.flush();
        let busy = !out.is_empty() || (!self.read_list.is_empty() && !self.stash.is_empty());
        let t = if busy { Some(Duration::ZERO) } else { timeout };
        let min = if t == Some(Duration::ZERO) { 0 } else { 1 };
        self.stats.waits += 1;
        self.ring.enter(min, t)?;
        self.ring.reap(&mut self.cqes);
        self.stats.os_events += self.cqes.len() as u64;
        let cqes = std::mem::take(&mut self.cqes);
        for c in &cqes {
            self.complete(*c, out);
        }
        self.cqes = cqes;
        self.cqes.clear();
        self.read_udp(out);
        self.finish_closing();
        out.append(&mut self.pending);
        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Cancel everything still in flight and wait (bounded) for the completions, so no
        // buffer is freed while the kernel may use it.
        let sqe = Sqe { opcode: OP_ASYNC_CANCEL, op_flags: CANCEL_ANY, user_data: (Op::Cancel as u64) << 56, ..Default::default() };
        for id in self.slab.ids() {
            if let Some(e) = self.slab.get_mut(id) {
                e.closing = true;
                e.armed = false;
            }
        }
        self.push(sqe);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut sink = Vec::new();
        loop {
            let busy = self.slab.ids().iter().any(|&id| self.slab.get(id).is_some_and(|e| e.ops() > 0));
            if !busy || Instant::now() > deadline {
                break;
            }
            let _ = self.ring.enter(1, Some(Duration::from_millis(50)));
            self.ring.reap(&mut self.cqes);
            let cqes = std::mem::take(&mut self.cqes);
            for c in &cqes {
                self.complete(*c, &mut sink);
            }
            // Ring buffers taken by those completions are dropped with the events.
            sink.clear();
        }
        let busy = self.slab.ids().iter().any(|&id| self.slab.get(id).is_some_and(|e| e.ops() > 0));
        if busy {
            // The kernel may still touch these: leak them instead of freeing them.
            for id in self.slab.ids() {
                if let Some(e) = self.slab.get_mut(id) {
                    if let Some(op) = e.send.take() {
                        std::mem::forget(op);
                    }
                }
            }
            for b in self.bufs.drain(..).flatten() {
                std::mem::forget(b);
            }
            let map = std::mem::replace(&mut self.bufring.map, Mmap { ptr: core::ptr::null_mut(), len: 0 });
            map.leak();
        }
        // The ring buffers stay registered until the ring descriptor closes; closing it tears
        // the buffer ring down, after which the remaining Vecs are freed by their own drops.
    }
}
