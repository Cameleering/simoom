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
/// DigitalOcean's 4-vCPU droplets (about 65% of that CPU at 165k packets/s). Read from the `NET_RX`
/// line of `/proc/softirqs`: true when at most half of the CPUs did the receive work since boot
/// (a CPU counts when it did at least half of an even share), and there was some. A droplet
/// with two NICs (public and private, a queue each) shows two such CPUs out of four. Linux only;
/// false elsewhere or when the file can't be read.
#[inline(never)]
pub fn net_rx_concentrated() -> bool {
    #[cfg(target_os = "linux")]
    {
        // The NET_RX line is the fifth: 4 KiB holds it whole up to about 70 CPUs (a cut line has
        // no newline and is not counted).
        let mut buf = [0u8; 4096];
        rx_concentrated(read_small_bytes("/proc/softirqs", &mut buf))
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// The parsing half of [`net_rx_concentrated`].
#[cfg(target_os = "linux")]
fn rx_concentrated(softirqs: &[u8]) -> bool {
    // the first `RX:` is NET_RX's (NET_TX comes before it, BLOCK and the rest after)
    let Some(at) = (2..softirqs.len()).find(|&i| softirqs[i] == b':' && softirqs[i - 1] == b'X' && softirqs[i - 2] == b'R') else { return false };
    let rest = &softirqs[at + 1..];
    let Some(end) = rest.iter().position(|&b| b == b'\n') else { return false };
    let line = &rest[..=end];
    let (total, cpus) = scan(line, 0);
    // a CPU counts as busy when it did at least half of an even share of the receive work
    let (busy, _) = scan(line, total.div_ceil(2 * cpus.max(1)).max(1));
    total >= 10_000 && busy * 2 <= cpus
}

/// The numbers of a `/proc/softirqs` line (ending in a newline): with `min` 0 their sum and
/// count; otherwise how many are at least `min`, and the count.
#[cfg(target_os = "linux")]
fn scan(line: &[u8], min: u64) -> (u64, u64) {
    let (mut acc, mut n, mut cur, mut digits) = (0u64, 0u64, 0u64, false);
    for &b in line {
        if b.is_ascii_digit() {
            cur = cur.saturating_mul(10).saturating_add(u64::from(b - b'0'));
            digits = true;
        } else if digits {
            acc += if min == 0 { cur } else { u64::from(cur >= min) };
            n += 1;
            (cur, digits) = (0, false);
        }
    }
    (acc, n)
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
        // a DigitalOcean c-4: one receive queue, its interrupt on CPU 2
        let one = b"                    CPU0       CPU1       CPU2       CPU3\n          HI:          1          0          0          0\n      NET_TX:        120        300         90        410\n      NET_RX:       5521       8012    3082311      10022\n       BLOCK:          0          0          0          0\n";
        assert!(rx_concentrated(one));
        // the same droplet after boot: the public NIC's queue (CPU 3) and set-up traffic
        assert!(rx_concentrated(b"      NET_RX:      15924         52       1618      14372\n"));
        assert!(!rx_concentrated(b"      NET_RX:      15924         52       1618"), "a cut line");
        let spread = b"      NET_RX:     810221     790112     802311     799022\n";
        assert!(!rx_concentrated(spread));
        assert!(!rx_concentrated(b"      NET_RX:        12         0       900         3\n"), "too little traffic to tell");
        assert!(!rx_concentrated(b"no such line\n"));
        let _ = net_rx_concentrated(); // reads the real file without failing
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
