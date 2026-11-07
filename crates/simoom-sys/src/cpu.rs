//! CPU count and thread affinity.

use std::io;

/// The CPUs this process may run on, as indices (the affinity mask on Linux and Windows).
/// Falls back to `0..available_parallelism` where the mask can't be read.
pub fn allowed_cpus() -> Vec<usize> {
    #[cfg(target_os = "linux")]
    {
        let mut mask = [0u8; 128]; // 1024 CPUs
        // SAFETY: the kernel writes at most `mask.len()` bytes; pid 0 is the calling thread.
        let r = unsafe { crate::os::sys::sched_getaffinity(0, mask.len(), mask.as_mut_ptr()) };
        if r == 0 {
            let v: Vec<usize> = (0..mask.len() * 8).filter(|&i| mask[i / 8] & (1 << (i % 8)) != 0).collect();
            if !v.is_empty() {
                return v;
            }
        }
    }
    #[cfg(windows)]
    {
        use crate::os::sys;
        let (mut p, mut s) = (0usize, 0usize);
        // SAFETY: two output words; the pseudo handle needs no closing.
        if unsafe { sys::GetProcessAffinityMask(sys::GetCurrentProcess(), &mut p, &mut s) } != 0 && p != 0 {
            return (0..usize::BITS as usize).filter(|&i| p & (1 << i) != 0).collect();
        }
    }
    (0..cpu_count()).collect()
}

/// The number of CPUs this process may use (at least 1).
pub fn cpu_count() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Pins the calling thread to one CPU. Returns `Unsupported` on macOS, which has no hard
/// affinity.
pub fn pin_current_thread(cpu: usize) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if cpu >= 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "CPU index too large"));
        }
        let mut mask = [0u8; 128];
        mask[cpu / 8] |= 1 << (cpu % 8);
        // SAFETY: passes a mask of `mask.len()` bytes; pid 0 is the calling thread.
        if unsafe { crate::os::sys::sched_setaffinity(0, mask.len(), mask.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use crate::os::sys;
        if cpu >= usize::BITS as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "CPU index beyond the first processor group"));
        }
        // SAFETY: the pseudo handle of the current thread and a one-bit mask.
        if unsafe { sys::SetThreadAffinityMask(sys::GetCurrentThread(), 1usize << cpu) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = cpu;
        Err(io::Error::new(io::ErrorKind::Unsupported, "thread affinity is not supported on this OS"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_and_pin() {
        let cpus = allowed_cpus();
        assert!(!cpus.is_empty());
        assert!(cpu_count() >= 1);
        let last = *cpus.last().unwrap();
        std::thread::spawn(move || {
            let _ = last;
            #[cfg(any(target_os = "linux", windows))]
            pin_current_thread(last).unwrap();
            #[cfg(target_os = "linux")]
            assert_eq!(allowed_cpus(), vec![last]);
        })
        .join()
        .unwrap();
    }
}
