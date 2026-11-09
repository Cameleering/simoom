//! Cheap monotonic clocks.
//!
//! [`now_ns`] is the precise monotonic clock (`CLOCK_MONOTONIC` through the vDSO on Linux,
//! `QueryPerformanceCounter` on Windows). [`coarse_ns`] is cheaper and has the resolution of
//! the kernel tick: `CLOCK_MONOTONIC_COARSE` on Linux (same epoch as [`now_ns`]); elsewhere it
//! is the precise clock. Both count nanoseconds from an arbitrary fixed point.

use crate::os::sys;

/// Nanoseconds on the precise monotonic clock.
#[inline]
pub fn now_ns() -> u64 {
    #[cfg(unix)]
    {
        let mut ts = sys::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid output struct; CLOCK_MONOTONIC always exists.
        unsafe { sys::clock_gettime(sys::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    #[cfg(windows)]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static FREQ: AtomicU64 = AtomicU64::new(0);
        let mut f = FREQ.load(Ordering::Relaxed);
        if f == 0 {
            let mut v = 0i64;
            // SAFETY: writes one i64; never fails on XP and later.
            unsafe { sys::QueryPerformanceFrequency(&mut v) };
            f = v.max(1) as u64;
            FREQ.store(f, Ordering::Relaxed);
        }
        let mut c = 0i64;
        // SAFETY: writes one i64; never fails on XP and later.
        unsafe { sys::QueryPerformanceCounter(&mut c) };
        let c = c as u64;
        // Split to avoid overflow: whole seconds, then the remainder.
        (c / f) * 1_000_000_000 + (c % f) * 1_000_000_000 / f
    }
}

/// Nanoseconds on the cheapest monotonic clock (kernel-tick resolution on Linux).
#[inline]
pub fn coarse_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut ts = sys::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid output struct; CLOCK_MONOTONIC_COARSE exists since 2.6.32.
        unsafe { sys::clock_gettime(sys::CLOCK_MONOTONIC_COARSE, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    #[cfg(not(target_os = "linux"))]
    {
        now_ns()
    }
}

/// CPU time (user and system) used by the whole process so far, in nanoseconds:
/// `CLOCK_PROCESS_CPUTIME_ID` on Unix, `GetProcessTimes` on Windows (100 ns steps, updated at
/// the scheduler tick). For measurements such as "an idle server uses no CPU".
pub fn process_cpu_ns() -> u64 {
    #[cfg(unix)]
    {
        let mut ts = sys::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid output struct; the clock exists on every supported system.
        unsafe { sys::clock_gettime(sys::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    #[cfg(windows)]
    {
        let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
        // SAFETY: the pseudo handle of the current process; four writable FILETIME-sized slots.
        unsafe { sys::GetProcessTimes(sys::GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) };
        (k + u) * 100
    }
}

/// CPU time of the calling thread in nanoseconds (tests only).
#[cfg(test)]
pub(crate) fn thread_cpu_ns_for_tests() -> u64 {
    #[cfg(unix)]
    {
        let mut ts = sys::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `ts` is a valid output struct; the clock exists on every supported system.
        unsafe { sys::clock_gettime(sys::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    #[cfg(windows)]
    {
        let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
        // SAFETY: the pseudo handle of the current thread; four writable FILETIME-sized slots.
        unsafe { sys::GetThreadTimes(sys::GetCurrentThread(), &mut c, &mut e, &mut k, &mut u) };
        (k + u) * 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_clocks_count_work_not_sleep() {
        let (p0, t0) = (process_cpu_ns(), thread_cpu_ns_for_tests());
        std::thread::sleep(std::time::Duration::from_millis(50));
        let t1 = thread_cpu_ns_for_tests();
        assert!(t1 - t0 < 30_000_000, "sleeping used {} ns of thread CPU", t1 - t0);
        let end = now_ns() + 60_000_000;
        let mut x = 0u64;
        while now_ns() < end {
            x = x.wrapping_add(1);
        }
        let (p2, t2) = (process_cpu_ns(), thread_cpu_ns_for_tests());
        assert!(t2 - t1 >= 20_000_000, "spinning 60 ms counted {} ns ({x})", t2 - t1);
        assert!(p2 - p0 >= t2 - t1 - 16_000_000);
    }

    #[test]
    fn clocks_are_monotonic_and_track_real_time() {
        let a = now_ns();
        let c0 = coarse_ns();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let b = now_ns();
        let c1 = coarse_ns();
        assert!(b >= a + 25_000_000, "{a} {b}");
        assert!(b < a + 5_000_000_000);
        assert!(c1 >= c0 + 10_000_000);
        // Cost of a read, printed for the record.
        let n = 1_000_000;
        let t = std::time::Instant::now();
        let mut x = 0u64;
        for _ in 0..n {
            x = x.wrapping_add(now_ns());
        }
        let precise = t.elapsed().as_nanos() as f64 / n as f64;
        let t = std::time::Instant::now();
        for _ in 0..n {
            x = x.wrapping_add(coarse_ns());
        }
        let coarse = t.elapsed().as_nanos() as f64 / n as f64;
        eprintln!("now_ns {precise:.1} ns, coarse_ns {coarse:.1} ns per read ({x})");
    }
}
