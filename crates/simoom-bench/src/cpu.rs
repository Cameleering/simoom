//! CPU accounting for the load generator itself, so a run can show that the generator was not
//! the bottleneck. Linux reads `/proc`; elsewhere the numbers are absent.

use std::time::Instant;

/// One sample of process and machine CPU counters.
#[derive(Clone, Debug)]
pub struct Sample {
    at: Instant,
    /// Process CPU time in ns, summed over threads.
    proc_ns: Option<u64>,
    /// Per-thread CPU time in ns, by thread id, for threads whose name starts with the prefix.
    threads: Vec<(u32, u64)>,
    /// Machine-wide `/proc/stat` jiffies: (busy, total, softirq).
    node: Option<(u64, u64, u64)>,
}

/// CPU use between two samples.
#[derive(Clone, Debug, Default)]
pub struct Usage {
    pub wall_s: f64,
    /// Generator process CPU, as a percentage of the whole machine (all CPUs).
    pub proc_pct: Option<f64>,
    /// Generator CPU seconds.
    pub proc_s: Option<f64>,
    /// The busiest generator loop thread, as a percentage of one CPU.
    pub max_thread_pct: Option<f64>,
    /// Machine-wide busy share (everything, softirq included), percentage of all CPUs.
    pub node_pct: Option<f64>,
    /// Machine-wide softirq share (network receive processing), percentage of all CPUs.
    pub softirq_pct: Option<f64>,
    pub cpus: usize,
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn task_ns(tid: &str) -> Option<u64> {
    // schedstat: "<run time ns> <wait ns> <slices>"
    read(&format!("/proc/self/task/{tid}/schedstat"))?.split_whitespace().next()?.parse().ok()
}

/// Takes a sample; `thread_prefix` selects the loop threads whose CPU is tracked one by one.
pub fn sample(thread_prefix: &str) -> Sample {
    let at = Instant::now();
    let mut proc_ns = None;
    let mut threads = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc/self/task") {
        let mut sum = 0u64;
        for e in dir.flatten() {
            let tid = e.file_name().to_string_lossy().to_string();
            if let Some(ns) = task_ns(&tid) {
                sum += ns;
                let comm = read(&format!("/proc/self/task/{tid}/comm")).unwrap_or_default();
                if !thread_prefix.is_empty() && comm.trim_end().starts_with(thread_prefix) {
                    threads.push((tid.parse().unwrap_or(0), ns));
                }
            }
        }
        proc_ns = Some(sum);
    }
    let node = read("/proc/stat").and_then(|s| {
        let line = s.lines().next()?.to_string();
        let v: Vec<u64> = line.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
        if v.len() < 8 {
            return None;
        }
        // user nice system idle iowait irq softirq steal
        let total: u64 = v[..8].iter().sum();
        let idle = v[3] + v[4];
        Some((total - idle, total, v[6]))
    });
    Sample { at, proc_ns, threads, node }
}

/// CPU use from `a` to `b`.
pub fn usage(a: &Sample, b: &Sample) -> Usage {
    let wall = b.at.duration_since(a.at).as_secs_f64().max(1e-9);
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let mut u = Usage { wall_s: wall, cpus, ..Usage::default() };
    if let (Some(x), Some(y)) = (a.proc_ns, b.proc_ns) {
        let s = y.saturating_sub(x) as f64 / 1e9;
        u.proc_s = Some(s);
        u.proc_pct = Some(100.0 * s / wall / cpus as f64);
    }
    let mut max_t = None::<f64>;
    for (tid, ns) in &b.threads {
        if let Some((_, ns0)) = a.threads.iter().find(|(t, _)| t == tid) {
            let pct = 100.0 * ns.saturating_sub(*ns0) as f64 / 1e9 / wall;
            max_t = Some(max_t.map_or(pct, |m: f64| m.max(pct)));
        }
    }
    u.max_thread_pct = max_t;
    if let (Some((b0, t0, s0)), Some((b1, t1, s1))) = (a.node, b.node) {
        let dt = t1.saturating_sub(t0).max(1) as f64;
        u.node_pct = Some(100.0 * b1.saturating_sub(b0) as f64 / dt);
        u.softirq_pct = Some(100.0 * s1.saturating_sub(s0) as f64 / dt);
    }
    u
}

/// Peak and current resident memory of the generator in KB (Linux).
pub fn rss_kb() -> Option<(u64, u64)> {
    let s = read("/proc/self/status")?;
    let get = |k: &str| s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)?.parse().ok());
    Some((get("VmHWM:")?, get("VmRSS:")?))
}

#[cfg(test)]
mod tests {
    #[test]
    fn samples_do_not_fail() {
        let a = super::sample("x");
        let mut v = 0u64;
        for i in 0..2_000_000u64 {
            v = v.wrapping_add(i * i);
        }
        assert!(v > 0);
        let b = super::sample("x");
        let u = super::usage(&a, &b);
        assert!(u.wall_s > 0.0);
        #[cfg(target_os = "linux")]
        assert!(u.proc_s.is_some() && u.node_pct.is_some());
    }
}
