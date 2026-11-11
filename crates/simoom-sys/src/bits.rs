//! Codec kernels with CPU features picked at run time (owned by the simoom-compress work).
//!
//! [`bmi2`] says whether the CPU has BMI1, BMI2 and LZCNT (x86-64); the loops in
//! [`crate::codec`] then run a copy compiled with them (`shlx`/`shrx`/`tzcnt`: no shift-count
//! moves), as libzstd's `DYNAMIC_BMI2` builds do. [`set_scalar_only`] forces the base-target copy
//! on a thread, so tests can compare the two.

use std::cell::Cell;
use std::sync::atomic::{AtomicU8, Ordering};

/// 0: not checked yet, 1: absent, 2: present.
static BMI2: AtomicU8 = AtomicU8::new(0);

thread_local! {
    static SCALAR_ONLY: Cell<bool> = const { Cell::new(false) };
}

/// The CPU has BMI1, BMI2 and LZCNT (checked once), and [`set_scalar_only`] is off.
#[inline]
pub fn bmi2() -> bool {
    if SCALAR_ONLY.with(Cell::get) {
        return false;
    }
    match BMI2.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => {
            let yes = detect();
            BMI2.store(if yes { 2 } else { 1 }, Ordering::Relaxed);
            yes
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn detect() -> bool {
    std::arch::is_x86_feature_detected!("bmi1") && std::arch::is_x86_feature_detected!("bmi2") && std::arch::is_x86_feature_detected!("lzcnt")
}

#[cfg(not(target_arch = "x86_64"))]
fn detect() -> bool {
    false
}

/// Makes the codec loops on this thread use the base-target code from now on (`true`) or pick by
/// CPU again (`false`): for tests and fuzzing that check both paths give the same results.
pub fn set_scalar_only(on: bool) {
    SCALAR_ONLY.with(|c| c.set(on));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_switch() {
        set_scalar_only(true);
        assert!(!bmi2());
        set_scalar_only(false);
    }
}
