//! CPU count and thread affinity.

use std::io;

/// The CPUs this process may run on, as indices (the affinity mask on Linux and Windows).
/// Falls back to `0..cpu_count()` (or one CPU) where the mask can't be read.
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
    #[cfg(any(target_os = "linux", windows))]
    {
        vec![0]
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        (0..cpu_count()).collect()
    }
}

/// The number of CPUs this process may use (at least 1): the affinity mask, capped on Linux by
/// a cgroup v2 CPU quota (`cpu.max`, as containers set it), like
/// `std::thread::available_parallelism` but without its cgroup v1 code.
pub fn cpu_count() -> usize {
    #[cfg(any(target_os = "linux", windows))]
    {
        let n = allowed_cpus().len().max(1);
        #[cfg(target_os = "linux")]
        if let Some(q) = cgroup_quota() {
            return n.min(q).max(1);
        }
        n
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    }
}

/// The CPU quota of this process's cgroup v2 (and its parents), rounded up, if one is set.
#[cfg(target_os = "linux")]
#[inline(never)]
fn cgroup_quota() -> Option<usize> {
    let mut buf = [0u8; 4096];
    let groups = read_small("/proc/self/cgroup", &mut buf)?;
    let path = groups.lines().find_map(|l| l.strip_prefix("0::"))?;
    let mut dir = format!("/sys/fs/cgroup{}", path.trim_end_matches('/'));
    let mut best: Option<usize> = None;
    loop {
        let mut b = [0u8; 64];
        if let Some(q) = read_small(&format!("{dir}/cpu.max"), &mut b).and_then(parse_cpu_max) {
            best = Some(best.map_or(q, |b| b.min(q)));
        }
        if dir.len() <= "/sys/fs/cgroup".len() {
            return best;
        }
        match dir.rfind('/') {
            Some(i) => dir.truncate(i),
            None => return best,
        }
    }
}

/// Reads a small file into `buf` (one read: these kernel files are produced whole).
#[cfg(target_os = "linux")]
fn read_small<'b>(path: &str, buf: &'b mut [u8]) -> Option<&'b str> {
    use std::io::Read;
    let n = std::fs::File::open(path).ok()?.read(buf).ok()?;
    std::str::from_utf8(&buf[..n]).ok()
}

/// Parses a cgroup v2 `cpu.max` (`"max 100000"` or `"<quota> <period>"`) into whole CPUs.
#[cfg(target_os = "linux")]
fn parse_cpu_max(s: &str) -> Option<usize> {
    let mut it = s.split_ascii_whitespace();
    let quota: u64 = it.next()?.parse().ok()?;
    let period: u64 = it.next().map_or(Some(100_000), |p| p.parse().ok())?;
    if quota == 0 || period == 0 {
        return None;
    }
    Some(quota.div_ceil(period) as usize)
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

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_max_parsing() {
        assert_eq!(parse_cpu_max("max 100000
"), None);
        assert_eq!(parse_cpu_max("200000 100000
"), Some(2));
        assert_eq!(parse_cpu_max("150000 100000"), Some(2));
        assert_eq!(parse_cpu_max("50000 100000"), Some(1));
        assert_eq!(parse_cpu_max(""), None);
        assert!(cpu_count() <= allowed_cpus().len());
    }

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
