//! SanitizerCoverage edge counters for the std-only coverage-guided fuzzer (plan §7.3 F2).
//! Test-only: compiled with the `sancov` feature, and useful only when the fuzz target is built
//! with
//!
//! ```text
//! RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 \
//!            -C llvm-args=-sanitizer-coverage-trace-pc-guard"
//! ```
//!
//! (Linux; on Windows the MSVC COFF back end rejects the instrumented COMDATs). LLVM calls
//! `__sanitizer_cov_trace_pc_guard_init` once per instrumented module and
//! `__sanitizer_cov_trace_pc_guard` on every edge; each edge bumps one byte of a 64 KiB map.

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

/// Edge map size (a power of two).
pub const MAP_SIZE: usize = 1 << 16;

static MAP: [AtomicU8; MAP_SIZE] = [const { AtomicU8::new(0) }; MAP_SIZE];
static NEXT_GUARD: AtomicU32 = AtomicU32::new(1);

/// Clears the edge counters.
pub fn reset() {
    for b in MAP.iter() {
        b.store(0, Ordering::Relaxed);
    }
}

/// Copies the edge counters into `out` (resized to [`MAP_SIZE`]).
pub fn snapshot(out: &mut Vec<u8>) {
    out.clear();
    out.extend(MAP.iter().map(|b| b.load(Ordering::Relaxed)));
}

/// Guards (instrumented edges) registered so far; 0 means the build is not instrumented.
pub fn guards() -> u32 {
    NEXT_GUARD.load(Ordering::Relaxed) - 1
}

/// Called by LLVM with each module's guard array; numbers the guards.
///
/// # Safety
/// `start..stop` must be a valid, writable array of `u32` guards (LLVM guarantees it).
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, stop: *mut u32) {
    if start.is_null() || start == stop {
        return;
    }
    // SAFETY: LLVM passes the bounds of this module's guard section; `start < stop`, both in
    // the same allocation, and nothing else writes it while the module initialises.
    unsafe {
        if *start != 0 {
            return; // already numbered
        }
        let mut p = start;
        while p < stop {
            *p = NEXT_GUARD.fetch_add(1, Ordering::Relaxed);
            p = p.add(1);
        }
    }
}

/// Called by LLVM on every instrumented edge.
///
/// # Safety
/// `guard` must point at a guard numbered by [`__sanitizer_cov_trace_pc_guard_init`].
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    // SAFETY: LLVM passes a pointer into a guard array registered through the init callback.
    let g = unsafe { *guard } as usize;
    if g != 0 {
        let b = &MAP[g & (MAP_SIZE - 1)];
        b.store(b.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    }
}
