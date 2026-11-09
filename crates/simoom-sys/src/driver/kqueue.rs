//! macOS and BSD kqueue poller (`EV_CLEAR`, edge-triggered) with an `EVFILT_USER` waker.

use super::readiness::{Poller as PollerTrait, Ready, WAKE};
use super::{DriverStats, Waker, EVENTS_START};
use crate::net::RawSock;
use crate::os::bsd as sys;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct Poller {
    kq: Arc<OwnedFd>,
    events: Vec<sys::kevent>,
    max_events: usize,
}

fn kev(ident: usize, filter: i16, flags: u16, fflags: u32, udata: u64) -> sys::kevent {
    // SAFETY: an all-zero kevent is valid.
    let mut k: sys::kevent = unsafe { core::mem::zeroed() };
    k.ident = ident;
    k.filter = filter;
    k.flags = flags;
    k.fflags = fflags;
    k.udata = udata as usize as *mut core::ffi::c_void;
    k
}

fn apply(kq: i32, changes: &[sys::kevent]) -> io::Result<()> {
    // SAFETY: `changes` is a valid array; no events are requested back.
    let r = unsafe { sys::kevent(kq, changes.as_ptr(), changes.len() as i32, core::ptr::null_mut(), 0, core::ptr::null()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl PollerTrait for Poller {
    fn new(events: usize) -> io::Result<(Self, Waker)> {
        // SAFETY: plain syscall; the result is checked.
        let kq = unsafe { sys::kqueue() };
        if kq < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `kq` is a fresh descriptor that nothing else owns.
        let kq = Arc::new(unsafe { OwnedFd::from_raw_fd(kq) });
        apply(kq.as_raw_fd(), &[kev(0, sys::EVFILT_USER, sys::EV_ADD | sys::EV_CLEAR, 0, WAKE)])?;
        let k2 = kq.clone();
        let waker = Waker::new(Box::new(move || {
            let _ = apply(k2.as_raw_fd(), &[kev(0, sys::EVFILT_USER, 0, sys::NOTE_TRIGGER, WAKE)]);
        }));
        // SAFETY: an all-zero kevent is valid.
        Ok((Poller { kq, events: vec![unsafe { core::mem::zeroed() }; EVENTS_START.min(events)], max_events: events }, waker))
    }

    fn add(&mut self, sock: RawSock, token: u64, listener: bool, stats: &mut DriverStats) -> io::Result<()> {
        stats.other_calls += 1;
        let r = kev(sock as usize, sys::EVFILT_READ, sys::EV_ADD | sys::EV_CLEAR, 0, token);
        if listener {
            apply(self.kq.as_raw_fd(), &[r])
        } else {
            apply(self.kq.as_raw_fd(), &[r, kev(sock as usize, sys::EVFILT_WRITE, sys::EV_ADD | sys::EV_CLEAR, 0, token)])
        }
    }

    fn wait(&mut self, out: &mut Vec<Ready>, timeout: Option<Duration>, stats: &mut DriverStats) -> io::Result<()> {
        stats.waits += 1;
        let ts = timeout.map(|d| sys::timespec { tv_sec: d.as_secs() as i64, tv_nsec: d.subsec_nanos() as i64 });
        let tsp = ts.as_ref().map_or(core::ptr::null(), |t| t as *const sys::timespec);
        // SAFETY: `events` has room for `len` entries; `tsp` is null or points at `ts`.
        let n = unsafe { sys::kevent(self.kq.as_raw_fd(), core::ptr::null(), 0, self.events.as_mut_ptr(), self.events.len() as i32, tsp) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(e);
        }
        let full = n as usize == self.events.len();
        for k in &self.events[..n as usize] {
            let token = k.udata as usize as u64;
            out.push(Ready {
                token,
                readable: k.filter == sys::EVFILT_READ || k.filter == sys::EVFILT_USER,
                writable: k.filter == sys::EVFILT_WRITE,
                closed: k.flags & sys::EV_ERROR != 0,
                hup: k.filter == sys::EVFILT_READ && k.flags & sys::EV_EOF != 0,
            });
        }
        if full && self.events.len() < self.max_events {
            let len = (self.events.len() * 2).min(self.max_events);
            // SAFETY: an all-zero kevent is valid.
            self.events.resize(len, unsafe { core::mem::zeroed() });
        }
        Ok(())
    }
}
