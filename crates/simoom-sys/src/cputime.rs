//! Per-thread CPU time, for telling a slow handler from a preempted thread.
//!
//! [`thread_times`] reads the calling thread's CPU time and, on Linux, its count of voluntary
//! context switches (the thread blocked: sleep, I/O, a contended lock). A loop thread that was
//! only preempted shows wall time but neither CPU time nor voluntary switches.
//!
//! - Linux (64-bit): `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` for the CPU time and
//!   `getrusage(RUSAGE_THREAD)` for the switches. `getrusage`'s CPU times are only as fresh as
//!   the last scheduler tick for a running thread, so they miss most of a short call.
//! - Other Unix: `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`, CPU time only.
//! - Windows: `QueryThreadCycleTime`, converted to nanoseconds with a cycle rate measured once
//!   (about 1.5 ms of spinning on the first call).
//!
//! This file is owned by the facade work (the stall watchdog in `simoom`).

/// CPU time used by the calling thread so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadTimes {
    /// User plus system CPU time, nanoseconds.
    pub cpu_ns: u64,
    /// Voluntary context switches so far, where the platform counts them per thread (Linux).
    pub voluntary_switches: Option<u64>,
}

/// The calling thread's CPU time, or `None` where it can't be read.
pub fn thread_times() -> Option<ThreadTimes> {
    imp::thread_times()
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod imp {
    use super::ThreadTimes;
    use crate::os::sys;
    use core::ffi::{c_int, c_long};

    const RUSAGE_THREAD: c_int = 1;
    const CLOCK_THREAD_CPUTIME_ID: c_int = 3;

    /// `struct rusage` on 64-bit Linux: two timevals (four longs: ru_utime, ru_stime) and
    /// fourteen longs.
    #[repr(C)]
    struct Rusage([c_long; 18]);

    extern "C" {
        fn getrusage(who: c_int, usage: *mut Rusage) -> c_int;
    }

    pub(super) fn thread_times() -> Option<ThreadTimes> {
        let mut r = Rusage([0; 18]);
        // SAFETY: `r` is a writable `struct rusage` with the 64-bit Linux layout; RUSAGE_THREAD
        // exists since Linux 2.6.26.
        if unsafe { getrusage(RUSAGE_THREAD, &mut r) } != 0 {
            return None;
        }
        // The CPU time comes from the thread CPU clock, not from ru_utime + ru_stime: those come
        // from the scheduler's runtime sum, which for a running thread is brought up to date only
        // at a scheduler tick or a context switch, so a 3 ms call read as anything from 0 to 3 ms
        // (4 ms ticks at HZ=250) and a CPU-bound route under the budget's few ticks often went
        // unseen. The thread CPU clock updates the sum first, so it is exact.
        let mut ts = sys::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid output struct; CLOCK_THREAD_CPUTIME_ID exists since Linux 2.6.12.
        if unsafe { sys::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
            return None;
        }
        // Long 16 is ru_nvcsw (after the two timevals and maxrss, ixrss, idrss, isrss, minflt,
        // majflt, nswap, inblock, oublock, msgsnd, msgrcv, nsignals); switch counts are exact.
        Some(ThreadTimes { cpu_ns: ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64, voluntary_switches: Some(r.0[16] as u64) })
    }
}

#[cfg(all(unix, not(all(target_os = "linux", target_pointer_width = "64"))))]
mod imp {
    use super::ThreadTimes;
    use core::ffi::c_int;

    #[cfg(target_os = "linux")]
    const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const CLOCK_THREAD_CPUTIME_ID: c_int = 16;
    #[cfg(target_os = "freebsd")]
    const CLOCK_THREAD_CPUTIME_ID: c_int = 14;

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    pub(super) fn thread_times() -> Option<ThreadTimes> {
        use crate::os::sys;
        let mut ts = sys::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid output struct; an unknown clock id only returns an error.
        if unsafe { sys::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
            return None;
        }
        Some(ThreadTimes { cpu_ns: ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64, voluntary_switches: None })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    pub(super) fn thread_times() -> Option<ThreadTimes> {
        None
    }
}

#[cfg(windows)]
mod imp {
    use super::ThreadTimes;
    use crate::os::sys;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[link(name = "kernel32")]
    extern "system" {
        fn QueryThreadCycleTime(thread: sys::HANDLE, cycles: *mut u64) -> sys::BOOL;
    }

    fn cycles() -> Option<u64> {
        let mut c = 0u64;
        // SAFETY: the pseudo handle of the current thread is always valid; `c` is writable.
        (unsafe { QueryThreadCycleTime(sys::GetCurrentThread(), &mut c) } != 0).then_some(c)
    }

    /// Cycles per microsecond times 1024, measured once (0: not yet).
    static RATE: AtomicU64 = AtomicU64::new(0);

    /// Spins about 500 us three times and keeps the highest cycles-per-wall-time ratio: a
    /// preempted run only lowers it.
    fn rate() -> Option<u64> {
        let r = RATE.load(Ordering::Relaxed);
        if r != 0 {
            return Some(r);
        }
        let mut best = 0u64;
        for _ in 0..3 {
            let (c0, t0) = (cycles()?, crate::time::now_ns());
            let mut t1 = t0;
            while t1 - t0 < 500_000 {
                std::hint::spin_loop();
                t1 = crate::time::now_ns();
            }
            let c1 = cycles()?;
            best = best.max((c1 - c0) * 1024 * 1000 / (t1 - t0).max(1));
        }
        let best = best.max(1);
        RATE.store(best, Ordering::Relaxed);
        Some(best)
    }

    pub(super) fn thread_times() -> Option<ThreadTimes> {
        let r = rate()?;
        let c = cycles()?;
        Some(ThreadTimes { cpu_ns: (c as u128 * 1024 * 1000 / r as u128) as u64, voluntary_switches: None })
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn thread_times() -> Option<super::ThreadTimes> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_time_counts_work_but_not_sleep() {
        let Some(a) = thread_times() else { return };
        std::thread::sleep(std::time::Duration::from_millis(30));
        let b = thread_times().unwrap();
        assert!(b.cpu_ns - a.cpu_ns < 15_000_000, "sleeping used {} ns of CPU", b.cpu_ns - a.cpu_ns);
        if let (Some(x), Some(y)) = (a.voluntary_switches, b.voluntary_switches) {
            assert!(y > x, "a sleep is a voluntary switch");
        }
        let t = crate::time::now_ns();
        let mut x = 0u64;
        while crate::time::now_ns() - t < 20_000_000 {
            x = x.wrapping_add(std::hint::black_box(1));
        }
        let c = thread_times().unwrap();
        assert!(c.cpu_ns - b.cpu_ns > 10_000_000, "20 ms of spinning counted {} ns ({x})", c.cpu_ns - b.cpu_ns);
        let n = 100_000;
        let t = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(thread_times());
        }
        eprintln!("thread_times: {:.0} ns per read", t.elapsed().as_nanos() as f64 / n as f64);
    }

    /// Short calls count in full: `getrusage`'s CPU times on Linux lag to the last scheduler
    /// tick, so about half of these 3 ms spins (just after a sleep, as a loop thread runs a call
    /// after a wait) read as 1 ms or less, and the watchdog missed CPU-bound routes.
    #[test]
    fn a_short_spin_after_a_sleep_counts_in_full() {
        if thread_times().is_none() {
            return;
        }
        let (n, mut low) = (20, Vec::new());
        for i in 0..n {
            // Uneven sleeps, so the spins don't lock to one phase of the tick.
            std::thread::sleep(std::time::Duration::from_micros(5000 + i * 370));
            let a = thread_times().unwrap();
            let t = crate::time::now_ns();
            while crate::time::now_ns() - t < 3_000_000 {
                std::hint::spin_loop();
            }
            let us = (thread_times().unwrap().cpu_ns - a.cpu_ns) / 1000;
            if us <= 1500 {
                low.push(us);
            }
        }
        // A preempted spin may use less CPU than its wall time; a few, not half.
        assert!(low.len() <= 3, "{} of {n} 3 ms spins counted 1.5 ms or less: {low:?} us", low.len());
    }
}
