//! Linux epoll poller (edge-triggered) with an eventfd waker.

use super::readiness::{Poller as PollerTrait, Ready, WAKE};
use super::{timeout_ms, DriverStats, Waker, EVENTS_START};
use crate::net::RawSock;
use crate::os::linux as sys;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct Poller {
    ep: OwnedFd,
    efd: Arc<OwnedFd>,
    events: Vec<sys::epoll_event>,
    max_events: usize,
}

pub(crate) fn eventfd() -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the result is checked.
    let fd = unsafe { sys::eventfd(0, sys::EFD_CLOEXEC | sys::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A waker that writes to an eventfd. The eventfd stays open while any waker clone lives.
pub(crate) fn eventfd_waker(efd: Arc<OwnedFd>) -> Waker {
    Waker::new(Box::new(move || {
        let one: u64 = 1;
        // SAFETY: writes 8 bytes from a live u64 to an eventfd we keep open.
        unsafe { sys::write(efd.as_raw_fd(), (&one as *const u64).cast(), 8) };
    }))
}

/// Resets an eventfd after a wake (one `read`).
pub(crate) fn drain_eventfd(fd: &OwnedFd) {
    let mut v: u64 = 0;
    // SAFETY: reads at most 8 bytes into a live u64; non-blocking.
    unsafe { sys::read(fd.as_raw_fd(), (&mut v as *mut u64).cast(), 8) };
}

impl PollerTrait for Poller {
    fn new(events: usize) -> io::Result<(Self, Waker)> {
        // SAFETY: plain syscall; the result is checked.
        let ep = unsafe { sys::epoll_create1(sys::EPOLL_CLOEXEC) };
        if ep < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `ep` is a fresh descriptor that nothing else owns.
        let ep = unsafe { OwnedFd::from_raw_fd(ep) };
        let efd = Arc::new(eventfd()?);
        let mut ev = sys::epoll_event { events: sys::EPOLLIN | sys::EPOLLET, data: WAKE };
        // SAFETY: registers a descriptor we own with a valid event struct.
        if unsafe { sys::epoll_ctl(ep.as_raw_fd(), sys::EPOLL_CTL_ADD, efd.as_raw_fd(), &mut ev) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let waker = eventfd_waker(efd.clone());
        Ok((Poller { ep, efd, events: vec![sys::epoll_event { events: 0, data: 0 }; EVENTS_START.min(events)], max_events: events }, waker))
    }

    fn add(&mut self, sock: RawSock, token: u64, listener: bool, stats: &mut DriverStats) -> io::Result<()> {
        let flags = if listener { sys::EPOLLIN | sys::EPOLLET } else { sys::EPOLLIN | sys::EPOLLOUT | sys::EPOLLRDHUP | sys::EPOLLET };
        let mut ev = sys::epoll_event { events: flags, data: token };
        stats.other_calls += 1;
        // SAFETY: registers a live descriptor with a valid event struct.
        if unsafe { sys::epoll_ctl(self.ep.as_raw_fd(), sys::EPOLL_CTL_ADD, sock, &mut ev) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait(&mut self, out: &mut Vec<Ready>, timeout: Option<Duration>, stats: &mut DriverStats) -> io::Result<()> {
        stats.waits += 1;
        // SAFETY: `events` has room for `len` entries.
        let n = unsafe { sys::epoll_wait(self.ep.as_raw_fd(), self.events.as_mut_ptr(), self.events.len() as i32, timeout_ms(timeout)) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(e);
        }
        let full = n as usize == self.events.len();
        for ev in &self.events[..n as usize] {
            let (flags, token) = (ev.events, ev.data);
            if token == WAKE {
                stats.other_calls += 1;
                drain_eventfd(&self.efd);
            }
            out.push(Ready {
                token,
                readable: flags & (sys::EPOLLIN | sys::EPOLLRDHUP) != 0,
                writable: flags & sys::EPOLLOUT != 0,
                closed: flags & (sys::EPOLLHUP | sys::EPOLLERR) != 0,
                hup: flags & sys::EPOLLRDHUP != 0,
            });
        }
        if full && self.events.len() < self.max_events {
            let len = (self.events.len() * 2).min(self.max_events);
            self.events.resize(len, sys::epoll_event { events: 0, data: 0 });
        }
        Ok(())
    }
}
