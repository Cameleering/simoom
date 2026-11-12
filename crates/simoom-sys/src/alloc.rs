//! A counting global allocator for memory measurements in tests and benchmarks.
//!
//! ```ignore
//! #[global_allocator]
//! static A: simoom_sys::alloc::Counting = simoom_sys::alloc::Counting;
//! ```
//!
//! It forwards to the system allocator and keeps the net number of live heap bytes, in total
//! and per thread (bytes freed on another thread than the one that allocated them count against
//! the freeing thread).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicI64, Ordering};

/// The counting allocator. See the [module docs](self).
#[derive(Debug, Clone, Copy, Default)]
pub struct Counting;

static TOTAL: AtomicI64 = AtomicI64::new(0);
/// Calls to `alloc`, `alloc_zeroed` and `realloc`.
static CALLS: AtomicI64 = AtomicI64::new(0);
/// Allocations not freed yet.
static LIVE: AtomicI64 = AtomicI64::new(0);

thread_local! {
    static LOCAL: Cell<i64> = const { Cell::new(0) };
    /// The highest value `LOCAL` reached since the last [`reset_thread_peak`].
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

fn add(n: i64) {
    TOTAL.fetch_add(n, Ordering::Relaxed);
    if n > 0 {
        CALLS.fetch_add(1, Ordering::Relaxed);
    }
    let _ = LOCAL.try_with(|c| {
        let v = c.get() + n;
        c.set(v);
        let _ = PEAK.try_with(|p| p.set(p.get().max(v)));
    });
}

// SAFETY: every method forwards to `System` with the same arguments and only updates counters,
// which never allocate (the thread-local is const-initialised and has no destructor).
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::alloc`'s contract.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            add(layout.size() as i64);
            LIVE.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            add(layout.size() as i64);
            LIVE.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; `ptr` came from this allocator, so from `System`.
        unsafe { System.dealloc(ptr, layout) };
        add(-(layout.size() as i64));
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            add(new_size as i64 - layout.size() as i64);
        }
        p
    }
}

/// Net live heap bytes of the whole process (when [`Counting`] is the global allocator).
pub fn total_bytes() -> i64 {
    TOTAL.load(Ordering::Relaxed)
}

/// Heap allocations of the whole process not freed yet (when [`Counting`] is the global
/// allocator).
pub fn live_allocations() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

/// Allocation calls so far (allocations, and reallocations that grow), process-wide.
pub fn allocation_calls() -> i64 {
    CALLS.load(Ordering::Relaxed)
}

/// Net heap bytes allocated minus freed by the calling thread.
pub fn thread_bytes() -> i64 {
    LOCAL.try_with(|c| c.get()).unwrap_or(0)
}

/// The highest [`thread_bytes`] of the calling thread since its last [`reset_thread_peak`]
/// (or since it started): what a piece of code needs at its peak, scratch included.
pub fn thread_peak_bytes() -> i64 {
    PEAK.try_with(|c| c.get()).unwrap_or(0)
}

/// Starts a new peak for [`thread_peak_bytes`] at the calling thread's current
/// [`thread_bytes`].
pub fn reset_thread_peak() {
    let now = thread_bytes();
    let _ = PEAK.try_with(|c| c.set(now));
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
extern "C" {
    fn malloc_trim(pad: usize) -> core::ffi::c_int;
}

/// Asks the C allocator to give memory it holds free back to the operating system (glibc's
/// `malloc_trim`; elsewhere nothing). The event loops call it once after a burst, when they
/// have been idle for a while (K2): glibc keeps what a thread freed in that thread's arena, so a
/// burst of large responses otherwise left tens of MB resident.
pub fn release_free_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `malloc_trim` takes no pointers and is thread-safe (it locks each arena in turn).
    unsafe {
        malloc_trim(0);
    }
}
