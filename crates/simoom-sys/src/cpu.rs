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
    // The affinity mask and the cgroup quota (a few file reads) are read once per process.
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(cpu_count_now)
}

fn cpu_count_now() -> usize {
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
    // Bytes, not `str` and `format!`: start-up code, kept small.
    const ROOT: &str = "/sys/fs/cgroup";
    let mut buf = [0u8; 4096];
    let groups = read_small_bytes("/proc/self/cgroup", &mut buf);
    let path = groups.split(|&b| b == b'\n').find_map(|l| l.strip_prefix(b"0::"))?;
    let path = std::str::from_utf8(path).ok()?.trim_end_matches('/');
    let mut dir = String::with_capacity(ROOT.len() + path.len() + 8);
    dir.push_str(ROOT);
    dir.push_str(path);
    let mut best: Option<usize> = None;
    loop {
        let len = dir.len();
        dir.push_str("/cpu.max");
        let mut b = [0u8; 64];
        if let Some(q) = parse_cpu_max(read_small_bytes(&dir, &mut b)) {
            best = Some(best.map_or(q, |b| b.min(q)));
        }
        dir.truncate(len);
        if len <= ROOT.len() {
            return best;
        }
        match dir.rfind('/') {
            Some(i) => dir.truncate(i),
            None => return best,
        }
    }
}

/// Whether the network's receive processing concentrates on one CPU (K12): a NIC with a single
/// receive queue and no RPS runs every packet's softirq on the CPU that takes its interrupt, as on
/// DigitalOcean's 4-vCPU droplets (about 65% of that CPU at 165k packets/s). Read from the
/// softirq time per CPU in `/proc/stat`: true when one CPU spent at least half of all the
/// softirq time since boot, and there was some (2 s). Network receive dominates softirq time on
/// a busy server; timers and the rest are spread over the CPUs. Linux only; false elsewhere or
/// when the file can't be read.
///
/// When true, it also records that CPU for [`keep_current_thread_off_net_rx`]. (The `NET_RX`
/// counts of `/proc/softirqs` can't tell it: a NIC's transmit completions are counted there too,
/// often more often than its receives, but they cost far less: on the K12 droplet 590k on CPU 3
/// against 342k on CPU 2 in 12 s, with CPU 2 in softirq 65% of the time and CPU 3 10%.)
#[inline(never)]
pub fn net_rx_concentrated() -> bool {
    #[cfg(target_os = "linux")]
    {
        // 4 KiB holds the per-CPU lines up to about 40 CPUs (a cut line is not counted)
        let mut buf = [0u8; 4096];
        match softirq_concentrated(read_small_bytes("/proc/stat", &mut buf)) {
            Some(cpu) => {
                RX_CPU.store(cpu, std::sync::atomic::Ordering::Relaxed);
                true
            }
            None => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// The receive-interrupt CPU [`net_rx_concentrated`] found (`usize::MAX`: none).
#[cfg(target_os = "linux")]
static RX_CPU: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

/// The parsing half of [`net_rx_concentrated`]: the CPU of a `/proc/stat` that spent at least
/// half of all the softirq time (of each `cpuN` line, N and the seventh number after it: user,
/// nice, system, idle, iowait, irq, softirq), if the total is at least 2 s (200 ticks).
#[cfg(target_os = "linux")]
fn softirq_concentrated(stat: &[u8]) -> Option<usize> {
    let (mut best, mut most, mut total) = (0, 0u64, 0u64);
    // the numbers of the current line: number 0 is the CPU's index on a `cpuN` line (the only
    // lines whose first digit follows a `u`), number 7 its softirq time
    let (mut n, mut cur, mut cpu, mut digits, mut on, mut prev) = (0, 0u64, 0u64, false, false, 0u8);
    for &b in stat {
        if b.is_ascii_digit() {
            if !digits && n == 0 {
                on = prev == b'u';
            }
            cur = cur.wrapping_mul(10).wrapping_add(u64::from(b - b'0'));
            digits = true;
        } else {
            if digits {
                if on && n == 0 {
                    cpu = cur;
                } else if on && n == 7 {
                    total = total.wrapping_add(cur);
                    if cur > most {
                        (best, most) = (cpu as usize, cur);
                    }
                }
                (n, cur, digits) = (n + 1, 0, false);
            }
            if b == b'\n' {
                n = 0;
            }
        }
        prev = b;
    }
    (total >= 200 && most * 2 >= total).then_some(best)
}

/// Takes the receive-interrupt CPU recorded by [`net_rx_concentrated`] out of the calling
/// thread's affinity mask (Linux; elsewhere, or when none was recorded, it does nothing).
/// Nothing changes when the thread may not run there anyway or it is the only CPU left.
pub fn keep_current_thread_off_net_rx() {
    #[cfg(target_os = "linux")]
    keep_current_thread_off(RX_CPU.load(std::sync::atomic::Ordering::Relaxed));
}

#[cfg(target_os = "linux")]
fn keep_current_thread_off(cpu: usize) {
    let mut mask = [0u8; 128];
    let (byte, bit) = (cpu / 8, 1u8 << (cpu % 8));
    // SAFETY: the kernel writes at most `mask.len()` bytes; pid 0 is the calling thread.
    if byte >= mask.len() || unsafe { crate::os::sys::sched_getaffinity(0, mask.len(), mask.as_mut_ptr()) } != 0 || mask[byte] & bit == 0 {
        return;
    }
    mask[byte] &= !bit;
    if mask.iter().any(|&b| b != 0) {
        // SAFETY: passes a mask of `mask.len()` bytes; pid 0 is the calling thread.
        unsafe { crate::os::sys::sched_setaffinity(0, mask.len(), mask.as_ptr()) };
    }
}

/// Reads a small file into `buf` (one read: these kernel files are produced whole); empty when
/// the file can't be read.
#[cfg(target_os = "linux")]
#[inline(never)]
pub(crate) fn read_small_bytes<'b>(path: &str, buf: &'b mut [u8]) -> &'b [u8] {
    use std::io::Read;
    let n = std::fs::File::open(path).and_then(|mut f| f.read(buf)).unwrap_or(0);
    &buf[..n]
}

/// Parses a cgroup v2 `cpu.max` (`"max 100000"` or `"<quota> <period>"`) into whole CPUs.
#[cfg(target_os = "linux")]
fn parse_cpu_max(s: &[u8]) -> Option<usize> {
    let mut it = s.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty());
    let quota = parse_u64(it.next()?)?;
    let period = it.next().map_or(Some(100_000), parse_u64)?;
    if quota == 0 || period == 0 {
        return None;
    }
    Some(quota.div_ceil(period) as usize)
}

/// A decimal number of at most 19 digits.
#[cfg(target_os = "linux")]
fn parse_u64(d: &[u8]) -> Option<u64> {
    if d.is_empty() || d.len() > 19 || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(d.iter().fold(0, |n, &c| n * 10 + u64::from(c - b'0')))
}

/// x86-64 instruction-set extensions, bits of [`x86_features`].
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86 {
    pub const SSSE3: u32 = 1 << 0;
    pub const SSE41: u32 = 1 << 1;
    pub const SSE42: u32 = 1 << 2;
    pub const AES: u32 = 1 << 3;
    pub const PCLMULQDQ: u32 = 1 << 4;
    pub const SHA: u32 = 1 << 5;
    pub const AVX2: u32 = 1 << 6;
    pub const BMI2: u32 = 1 << 7;
    pub const ADX: u32 = 1 << 8;
    pub(super) const DONE: u32 = 1 << 31;
}

/// The x86-64 extensions this CPU and OS support (bits of [`x86`]), read once with `cpuid`
/// (and `xgetbv` for AVX state). Replaces `std::is_x86_feature_detected!`, whose detection code
/// covers every extension std knows (about 1.7 KB) when the parsers and crypto need nine.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn x86_features() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static F: AtomicU32 = AtomicU32::new(0);
    let f = F.load(Ordering::Relaxed);
    if f != 0 {
        return f;
    }
    let f = detect_x86() | x86::DONE;
    F.store(f, Ordering::Relaxed);
    f
}

#[cfg(target_arch = "x86_64")]
#[cold]
#[inline(never)]
// `__cpuid` is a safe function on newer compilers and `unsafe` on the oldest supported one.
#[allow(unused_unsafe)]
fn detect_x86() -> u32 {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    let bit = |r: u32, b: u32, v: u32| if r & (1 << b) != 0 { v } else { 0 };
    // SAFETY: `cpuid` exists on every x86-64 CPU; leaf 7 is read only when leaf 0 lists it.
    let (max, l1) = unsafe { (__cpuid(0).eax, __cpuid(1)) };
    let mut f = bit(l1.ecx, 9, x86::SSSE3) | bit(l1.ecx, 19, x86::SSE41) | bit(l1.ecx, 20, x86::SSE42) | bit(l1.ecx, 25, x86::AES) | bit(l1.ecx, 1, x86::PCLMULQDQ);
    if max >= 7 {
        // SAFETY: as above, leaf 7 is supported.
        let l7 = unsafe { __cpuid_count(7, 0) };
        f |= bit(l7.ebx, 29, x86::SHA) | bit(l7.ebx, 8, x86::BMI2) | bit(l7.ebx, 19, x86::ADX);
        // AVX2 also needs AVX and the OS saving the YMM registers (OSXSAVE, then XCR0 bits 1-2).
        if l7.ebx & (1 << 5) != 0 && l1.ecx & (1 << 27) != 0 && l1.ecx & (1 << 28) != 0 && xcr0() & 6 == 6 {
            f |= x86::AVX2;
        }
    }
    f
}

#[cfg(target_arch = "x86_64")]
fn xcr0() -> u64 {
    #[target_feature(enable = "xsave")]
    unsafe fn read() -> u64 {
        // SAFETY: the caller checked OSXSAVE, so `xgetbv` is enabled.
        unsafe { core::arch::x86_64::_xgetbv(0) }
    }
    // SAFETY: called only after CPUID reported OSXSAVE (see `detect_x86`).
    unsafe { read() }
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
        assert_eq!(parse_cpu_max(b"max 100000
"), None);
        assert_eq!(parse_cpu_max(b"200000 100000
"), Some(2));
        assert_eq!(parse_cpu_max(b"150000 100000"), Some(2));
        assert_eq!(parse_cpu_max(b"50000 100000"), Some(1));
        assert_eq!(parse_cpu_max(b"300000"), Some(3));
        assert_eq!(parse_cpu_max(b"0 100000"), None);
        assert_eq!(parse_cpu_max(b""), None);
        assert!(cpu_count() <= allowed_cpus().len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn net_rx_concentration() {
        // the K12 droplet: CPU 2 takes the private NIC's receive interrupts, CPU 3 its transmit
        // completions (more NET_RX softirqs there, much less time)
        let k12 = b"cpu  53911 675 72359 206845 12924 0 29173 141 0 0\ncpu0 15347 395 22098 54484 3504 0 159 36 0 0\ncpu1 15620 280 23352 52153 4305 0 105 38 0 0\ncpu2 9220 0 8644 44155 1482 0 24987 36 0 0\ncpu3 13724 0 18265 56053 3633 0 3922 31 0 0\nintr 123 0 0\n";
        assert_eq!(softirq_concentrated(k12), Some(2));
        let spread = b"cpu  1 2 3 4 5 6 4000\ncpu0 1 2 3 4 5 6 1000\ncpu1 1 2 3 4 5 6 900\ncpu2 1 2 3 4 5 6 1100\ncpu3 1 2 3 4 5 6 1000\n";
        assert_eq!(softirq_concentrated(spread), None);
        assert_eq!(softirq_concentrated(b"cpu  0 0 0 0 0 0 0\ncpu0 1 2 3 4 5 6 5\ncpu1 1 2 3 4 5 6 150\n"), None, "too little to tell");
        assert_eq!(softirq_concentrated(b"cpu  9\ncpu0 1 2 3 4 5 6 10\ncpu1 1 2 3 4 5 6 900\ncpu2 1 2 3\n"), Some(1), "a cut line is not counted");
        assert_eq!(softirq_concentrated(b"cpu  1 2 3 4 5 6 9000\ncpu0 1 2 3 4 5 6 1000\ncpu1 1 2 3 4 5 6 1000\n"), Some(0), "not the total line");
        assert_eq!(softirq_concentrated(b""), None);
        let _ = net_rx_concentrated(); // reads the real file without failing
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_thread_can_be_kept_off_one_cpu() {
        let cpus = allowed_cpus();
        std::thread::spawn(move || {
            keep_current_thread_off(100_000); // out of range: nothing changes
            assert_eq!(allowed_cpus(), cpus);
            keep_current_thread_off(cpus[0]);
            if cpus.len() > 1 {
                assert_eq!(allowed_cpus(), cpus[1..], "the first CPU left");
                for &c in &cpus[2..] {
                    keep_current_thread_off(c);
                }
                assert_eq!(allowed_cpus(), [cpus[1]]);
                keep_current_thread_off(cpus[1]);
                assert_eq!(allowed_cpus(), [cpus[1]], "never the last CPU");
            } else {
                assert_eq!(allowed_cpus(), cpus, "never the last CPU");
            }
        })
        .join()
        .unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_features_match_std() {
        let f = x86_features();
        let checks = [
            (x86::SSSE3, std::is_x86_feature_detected!("ssse3")),
            (x86::SSE41, std::is_x86_feature_detected!("sse4.1")),
            (x86::SSE42, std::is_x86_feature_detected!("sse4.2")),
            (x86::AES, std::is_x86_feature_detected!("aes")),
            (x86::PCLMULQDQ, std::is_x86_feature_detected!("pclmulqdq")),
            (x86::SHA, std::is_x86_feature_detected!("sha")),
            (x86::AVX2, std::is_x86_feature_detected!("avx2")),
            (x86::BMI2, std::is_x86_feature_detected!("bmi2")),
            (x86::ADX, std::is_x86_feature_detected!("adx")),
        ];
        for (i, (bit, std)) in checks.into_iter().enumerate() {
            assert_eq!(f & bit != 0, std, "feature {i}");
        }
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
