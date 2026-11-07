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

#[cfg(test)]
mod tests {
    use super::*;

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
