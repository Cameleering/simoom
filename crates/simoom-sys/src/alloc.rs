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

thread_local! {
    static LOCAL: Cell<i64> = const { Cell::new(0) };
}

fn add(n: i64) {
    TOTAL.fetch_add(n, Ordering::Relaxed);
    let _ = LOCAL.try_with(|c| c.set(c.get() + n));
}

// SAFETY: every method forwards to `System` with the same arguments and only updates counters,
// which never allocate (the thread-local is const-initialised and has no destructor).
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::alloc`'s contract.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            add(layout.size() as i64);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            add(layout.size() as i64);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; `ptr` came from this allocator, so from `System`.
        unsafe { System.dealloc(ptr, layout) };
        add(-(layout.size() as i64));
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

/// Net heap bytes allocated minus freed by the calling thread.
pub fn thread_bytes() -> i64 {
    LOCAL.try_with(|c| c.get()).unwrap_or(0)
}
