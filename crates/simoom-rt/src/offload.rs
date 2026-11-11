//! A bounded, shared worker pool for blocking work (the M/M/c side of the hybrid design).
//!
//! - **Bounded queue.** [`OffloadPool::try_submit`] fails at once with [`Rejected::Full`]
//!   when `max_queue` jobs are waiting; nothing grows without bound.
//! - **Workers on demand.** A worker thread is started only when a job arrives and no worker is
//!   idle, up to `max_threads`; idle workers exit after `idle_timeout`.
//! - **CoDel admission.** Each job's sojourn time (from submission until a worker takes it) is
//!   measured. When it stays above `target` for a whole `interval`, the pool reports overload
//!   and refuses new jobs with [`Rejected::Overloaded`] until a job is taken faster than `target`
//!   again (Nichols and Jacobson, "Controlling Queue Delay", 2012). A server answers those with a
//!   fast 503 instead of queueing. The effective target is the larger of `target` and four times
//!   the jobs' recent mean run time, so a pool of slow blocking jobs (100 ms calls to a database)
//!   does not shed because a job waits a few run times behind a burst: only a queue that keeps
//!   growing past what the workers can absorb is overload (K10: at the old one-run-time target,
//!   500 clients of 100 ms jobs on 192 workers had nearly every request shed).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// A unit of offloaded work.
pub type Job = Box<dyn FnOnce() + Send + 'static>;

/// Why [`OffloadPool::try_submit`] refused a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejected {
    /// `max_queue` jobs are already waiting.
    Full,
    /// Jobs have been waiting longer than the CoDel target for a whole interval.
    Overloaded,
    /// The pool is shutting down.
    Stopped,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Rejected::Full => "offload queue full",
            Rejected::Overloaded => "offload queue overloaded",
            Rejected::Stopped => "offload pool stopped",
        })
    }
}

impl std::error::Error for Rejected {}

/// Settings of an [`OffloadPool`].
#[derive(Clone, Debug)]
pub struct OffloadConfig {
    /// Most worker threads (0 = [`default_threads`]: 32 per CPU, between 512 and 1024). Threads
    /// start on demand and exit when idle, so a high cap costs nothing until jobs block.
    pub max_threads: usize,
    /// Most jobs waiting.
    pub max_queue: usize,
    /// How long an idle worker waits before it exits.
    pub idle_timeout: Duration,
    /// CoDel sojourn target (raised to four times the jobs' recent mean run time when that is
    /// longer).
    pub target: Duration,
    /// CoDel interval.
    pub interval: Duration,
    /// Worker thread name.
    pub name: String,
}

impl Default for OffloadConfig {
    fn default() -> Self {
        OffloadConfig {
            max_threads: 0,
            max_queue: 4096,
            idle_timeout: Duration::from_secs(10),
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
            name: "simoom-offload".into(),
        }
    }
}

/// Counters of an [`OffloadPool`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OffloadStats {
    /// Jobs accepted.
    pub submitted: u64,
    /// Jobs finished.
    pub completed: u64,
    /// Jobs refused because the queue was full.
    pub rejected_full: u64,
    /// Jobs refused by CoDel.
    pub rejected_overload: u64,
    /// Jobs waiting now.
    pub queued: usize,
    /// Worker threads alive now.
    pub threads: usize,
    /// Sojourn time of the last job taken, in microseconds.
    pub last_sojourn_us: u64,
    /// Whether CoDel currently reports overload.
    pub overloaded: bool,
}

struct State {
    queue: VecDeque<(Instant, Job)>,
    idle: usize,
    threads: usize,
    stop: bool,
    first_above: Option<Instant>,
}

struct Inner {
    cfg: OffloadConfig,
    /// `cfg.max_threads`, or twice the CPU count resolved on the first job (reading the
    /// cgroup quota costs file reads that start-up need not pay).
    max_threads: std::sync::OnceLock<usize>,
    state: Mutex<State>,
    cv: Condvar,
    overloaded: AtomicBool,
    submitted: AtomicU64,
    completed: AtomicU64,
    rejected_full: AtomicU64,
    rejected_overload: AtomicU64,
    last_sojourn_us: AtomicU64,
    alive: AtomicUsize,
    /// Mean run time of recent jobs, ns (exponentially weighted, 1/8).
    run_ns: AtomicU64,
}

/// The worker cap for `max_threads: 0`: 32 per CPU, at least 512 and at most 1024. Sized for
/// blocking integration calls like a thread-per-request server's pool (a 100 ms handler needs
/// about 10 threads per 100 requests per second; Cameleer's pool is 1024); workers start on
/// demand and exit after `idle_timeout`, so the cap costs nothing until jobs block (K10).
pub fn default_threads() -> usize {
    (simoom_sys::cpu::cpu_count() * 32).clamp(512, 1024)
}

/// A bounded shared worker pool. Cheap to clone. See the [module docs](self).
#[derive(Clone)]
pub struct OffloadPool {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for OffloadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OffloadPool").field("stats", &self.stats()).finish()
    }
}

impl OffloadPool {
    /// Creates a pool. No thread starts until the first job.
    pub fn new(cfg: OffloadConfig) -> OffloadPool {
        let max_threads = std::sync::OnceLock::new();
        if cfg.max_threads != 0 {
            let _ = max_threads.set(cfg.max_threads);
        }
        OffloadPool {
            inner: Arc::new(Inner {
                max_threads,
                state: Mutex::new(State { queue: VecDeque::new(), idle: 0, threads: 0, stop: false, first_above: None }),
                cv: Condvar::new(),
                overloaded: AtomicBool::new(false),
                submitted: AtomicU64::new(0),
                completed: AtomicU64::new(0),
                rejected_full: AtomicU64::new(0),
                rejected_overload: AtomicU64::new(0),
                last_sojourn_us: AtomicU64::new(0),
                alive: AtomicUsize::new(0),
                run_ns: AtomicU64::new(0),
                cfg,
            }),
        }
    }

    /// Queues a job, or refuses it at once.
    pub fn try_submit(&self, job: Job) -> Result<(), Rejected> {
        let inner = &self.inner;
        if inner.overloaded.load(Ordering::Relaxed) {
            inner.rejected_overload.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::Overloaded);
        }
        let mut st = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.stop {
            return Err(Rejected::Stopped);
        }
        if st.queue.len() >= inner.cfg.max_queue {
            inner.rejected_full.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::Full);
        }
        st.queue.push_back((Instant::now(), job));
        inner.submitted.fetch_add(1, Ordering::Relaxed);
        if st.idle > 0 {
            drop(st);
            inner.cv.notify_one();
        } else if st.threads < *inner.max_threads.get_or_init(default_threads) {
            st.threads += 1;
            drop(st);
            let inner2 = self.inner.clone();
            let spawned = crate::spawn(std::thread::Builder::new().name(inner.cfg.name.clone()), Box::new(move || worker(inner2)));
            if spawned.is_err() {
                self.inner.state.lock().unwrap_or_else(PoisonError::into_inner).threads -= 1;
            }
        }
        Ok(())
    }

    /// Counters.
    pub fn stats(&self) -> OffloadStats {
        let st = self.inner.state.lock().unwrap_or_else(PoisonError::into_inner);
        OffloadStats {
            submitted: self.inner.submitted.load(Ordering::Relaxed),
            completed: self.inner.completed.load(Ordering::Relaxed),
            rejected_full: self.inner.rejected_full.load(Ordering::Relaxed),
            rejected_overload: self.inner.rejected_overload.load(Ordering::Relaxed),
            queued: st.queue.len(),
            threads: self.inner.alive.load(Ordering::Relaxed),
            last_sojourn_us: self.inner.last_sojourn_us.load(Ordering::Relaxed),
            overloaded: self.inner.overloaded.load(Ordering::Relaxed),
        }
    }

    /// Stops taking jobs; workers finish what is queued and exit. Waits up to `deadline` for
    /// them and returns whether all exited.
    pub fn shutdown(&self, deadline: Duration) -> bool {
        self.inner.state.lock().unwrap_or_else(PoisonError::into_inner).stop = true;
        self.inner.cv.notify_all();
        let end = simoom_sys::time::now_ns().saturating_add(deadline.as_nanos().min(u64::MAX as u128) as u64);
        while self.inner.alive.load(Ordering::Acquire) > 0 {
            if simoom_sys::time::now_ns() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }
}

fn worker(inner: Arc<Inner>) {
    inner.alive.fetch_add(1, Ordering::AcqRel);
    let mut st = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        if let Some((at, job)) = st.queue.pop_front() {
            let now = Instant::now();
            let sojourn = now - at;
            inner.last_sojourn_us.store(sojourn.as_micros() as u64, Ordering::Relaxed);
            // CoDel: overloaded once the sojourn stays above target for a whole interval. The
            // target is at least four times the jobs' mean run time: waiting a few jobs' length
            // is normal for a pool of slow jobs, not overload.
            let target = inner.cfg.target.max(Duration::from_nanos(inner.run_ns.load(Ordering::Relaxed).saturating_mul(4)));
            if sojourn > target {
                match st.first_above {
                    None => st.first_above = Some(now + inner.cfg.interval),
                    Some(t) if now >= t => inner.overloaded.store(true, Ordering::Relaxed),
                    _ => {}
                }
            } else {
                st.first_above = None;
                inner.overloaded.store(false, Ordering::Relaxed);
            }
            if st.queue.is_empty() {
                st.first_above = None;
                inner.overloaded.store(false, Ordering::Relaxed);
            }
            drop(st);
            job();
            let ran = now.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let m = inner.run_ns.load(Ordering::Relaxed);
            // The first job sets the mean (from zero, the first slow jobs looked like a queue
            // far above target).
            inner.run_ns.store(if m == 0 { ran.max(1) } else { m - m / 8 + ran / 8 }, Ordering::Relaxed);
            inner.completed.fetch_add(1, Ordering::Relaxed);
            st = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            continue;
        }
        if st.stop {
            break;
        }
        st.idle += 1;
        let (g, to) = inner.cv.wait_timeout(st, inner.cfg.idle_timeout).unwrap_or_else(PoisonError::into_inner);
        st = g;
        st.idle -= 1;
        if to.timed_out() && st.queue.is_empty() {
            break;
        }
    }
    st.threads -= 1;
    drop(st);
    inner.alive.fetch_sub(1, Ordering::AcqRel);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn runs_jobs_and_starts_threads_on_demand() {
        let p = OffloadPool::new(OffloadConfig { max_threads: 3, ..Default::default() });
        assert_eq!(p.stats().threads, 0, "no thread before the first job");
        let (tx, rx) = mpsc::channel();
        for i in 0..50 {
            let tx = tx.clone();
            p.try_submit(Box::new(move || tx.send(i).unwrap())).unwrap();
        }
        let mut got: Vec<i32> = (0..50).map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
        got.sort();
        assert_eq!(got, (0..50).collect::<Vec<_>>());
        assert!(p.stats().threads <= 3);
        assert!(p.shutdown(Duration::from_secs(5)));
        assert_eq!(p.try_submit(Box::new(|| {})), Err(Rejected::Stopped));
    }

    #[test]
    fn bounded_queue_rejects_when_full() {
        let p = OffloadPool::new(OffloadConfig { max_threads: 1, max_queue: 2, ..Default::default() });
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = mpsc::channel();
        p.try_submit(Box::new(move || {
            started_tx.send(()).unwrap();
            gate_rx.recv().unwrap();
        }))
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        p.try_submit(Box::new(|| {})).unwrap();
        p.try_submit(Box::new(|| {})).unwrap();
        assert_eq!(p.try_submit(Box::new(|| {})), Err(Rejected::Full));
        assert_eq!(p.stats().rejected_full, 1);
        gate_tx.send(()).unwrap();
        assert!(p.shutdown(Duration::from_secs(5)));
        assert_eq!(p.stats().completed, 3);
    }

    #[test]
    fn codel_sheds_when_sojourn_stays_high() {
        let p = OffloadPool::new(OffloadConfig {
            max_threads: 1,
            max_queue: 1000,
            target: Duration::from_millis(1),
            interval: Duration::from_millis(20),
            ..Default::default()
        });
        // Slow jobs keep the queue's sojourn time above target.
        for _ in 0..40 {
            if p.try_submit(Box::new(|| std::thread::sleep(Duration::from_millis(5)))).is_err() {
                break;
            }
        }
        let start = Instant::now();
        let mut shed = false;
        while start.elapsed() < Duration::from_secs(5) {
            if p.try_submit(Box::new(|| std::thread::sleep(Duration::from_millis(5)))) == Err(Rejected::Overloaded) {
                shed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(shed, "CoDel should report overload: {:?}", p.stats());
        // Once the queue drains, admission resumes.
        let start = Instant::now();
        while p.stats().overloaded && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!p.stats().overloaded);
        p.try_submit(Box::new(|| {})).unwrap();
        p.shutdown(Duration::from_secs(10));
    }

    // U10: slow blocking jobs whose waits stay near their own run time are not overload.
    #[test]
    fn slow_jobs_waiting_one_job_length_are_not_shed() {
        let p = OffloadPool::new(OffloadConfig { max_threads: 2, target: Duration::from_millis(1), interval: Duration::from_millis(10), ..Default::default() });
        for _ in 0..6 {
            for _ in 0..4 {
                // two run at once, two wait about one run time (30 ms, far above the 1 ms target)
                assert_eq!(p.try_submit(Box::new(|| std::thread::sleep(Duration::from_millis(30)))), Ok(()), "{:?}", p.stats());
            }
            std::thread::sleep(Duration::from_millis(80));
        }
        assert_eq!(p.stats().rejected_overload, 0);
        assert!(p.shutdown(Duration::from_secs(5)));
    }

    #[test]
    fn default_thread_cap_suits_blocking_calls() {
        let n = default_threads();
        assert!((512..=1024).contains(&n), "{n}");
        let p = OffloadPool::new(OffloadConfig::default());
        let (tx, rx) = mpsc::channel();
        // 64 concurrent blocking calls all run at once with the default cap
        let gate = Arc::new((Mutex::new(0usize), Condvar::new()));
        for _ in 0..64 {
            let (tx, gate) = (tx.clone(), gate.clone());
            p.try_submit(Box::new(move || {
                let (m, cv) = &*gate;
                let mut g = m.lock().unwrap();
                *g += 1;
                cv.notify_all();
                let _ = cv.wait_timeout_while(g, Duration::from_secs(10), |c| *c < 64).unwrap();
                tx.send(()).unwrap();
            }))
            .unwrap();
        }
        for _ in 0..64 {
            rx.recv_timeout(Duration::from_secs(10)).expect("all 64 run concurrently");
        }
        assert!(p.shutdown(Duration::from_secs(5)));
    }

    // K10: closed-loop clients of slow jobs, more of them than workers: a standing queue of a
    // couple of run times, which used to be shed almost entirely, is served.
    #[test]
    fn more_clients_than_workers_of_slow_jobs_are_queued_not_shed() {
        let p = OffloadPool::new(OffloadConfig { max_threads: 4, target: Duration::from_millis(1), interval: Duration::from_millis(10), ..Default::default() });
        let (tx, rx) = mpsc::channel::<()>();
        // 10 clients, each submitting its next 20 ms job when the last one finished.
        let submit = |p: &OffloadPool, tx: &mpsc::Sender<()>| {
            let tx = tx.clone();
            p.try_submit(Box::new(move || {
                std::thread::sleep(Duration::from_millis(20));
                let _ = tx.send(());
            }))
        };
        for _ in 0..10 {
            submit(&p, &tx).unwrap();
        }
        for _ in 0..100 {
            rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(submit(&p, &tx), Ok(()), "{:?}", p.stats());
        }
        assert_eq!(p.stats().rejected_overload, 0);
        assert!(p.shutdown(Duration::from_secs(5)));
    }

    #[test]
    fn idle_workers_exit() {
        let p = OffloadPool::new(OffloadConfig { max_threads: 2, idle_timeout: Duration::from_millis(30), ..Default::default() });
        let (tx, rx) = mpsc::channel();
        p.try_submit(Box::new(move || tx.send(()).unwrap())).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let start = Instant::now();
        while p.stats().threads > 0 && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(p.stats().threads, 0);
    }
}
