//! The stall watchdog: finds inline handlers that hold a loop thread (CPU-bound work or
//! blocking calls) and moves them, one route at a time, to the offload pool.
//!
//! Wall time alone is a poor witness on a busy machine: a loop thread that is preempted for a
//! few milliseconds makes a 13-byte handler look slow. So the wall clock only raises suspicion;
//! the next calls of a suspect route are measured with the thread's own clocks
//! (`simoom_sys::cputime`), and a call counts as a stall only when it used more CPU than the
//! budget, or blocked (a voluntary context switch on Linux; elsewhere, off-CPU time far above
//! the budget). A route moves to the offload pool after [`crate::Limits::stalls_before_offload`]
//! stalls within [`crate::Limits::stall_window`], and back after
//! [`crate::Limits::stall_recovery`] consecutive fast calls there (twice as many each time it
//! moves back, so a borderline route does not flap).

use simoom_sys::cputime::{thread_times, ThreadTimes};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const R: Ordering = Ordering::Relaxed;

/// Calls of a suspect route that are measured with the thread clocks before suspicion lapses.
const SUSPECT_CALLS: u32 = 16;
/// Without a per-thread count of voluntary switches, off-CPU time above `budget * this` counts
/// as blocking (a preemption is rarely that long; a blocking call often is).
const BLOCKED_FACTOR: u64 = 8;
/// The most stalls remembered per route (bounds [`crate::Limits::stalls_before_offload`]).
const MAX_RING: usize = 256;
/// The most fast calls ever required to move a route back.
const MAX_BACK_AFTER: u32 = 1 << 20;

/// The watchdog settings, from [`crate::Limits`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Policy {
    /// 0: the watchdog is off.
    pub(crate) budget_ns: u64,
    pub(crate) stalls: u32,
    pub(crate) window_ns: u64,
    pub(crate) recover: u32,
}

/// What one handler call cost its thread, between two reads of the thread clocks.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub(crate) cpu_ns: u64,
    pub(crate) voluntary: Option<u64>,
}

impl Sample {
    fn between(a: ThreadTimes, b: ThreadTimes) -> Sample {
        let voluntary = match (a.voluntary_switches, b.voluntary_switches) {
            (Some(x), Some(y)) => Some(y.saturating_sub(x)),
            _ => None,
        };
        Sample { cpu_ns: b.cpu_ns.saturating_sub(a.cpu_ns), voluntary }
    }
}

/// A first read of the thread clocks ([`since`] takes the second).
pub(crate) type Mark = Option<ThreadTimes>;

pub(crate) fn mark() -> Mark {
    thread_times()
}

/// What the thread spent since `a`.
pub(crate) fn since(a: Mark) -> Option<Sample> {
    match (a, thread_times()) {
        (Some(a), Some(b)) => Some(Sample::between(a, b)),
        _ => None,
    }
}

/// Runs `f` between two reads of the thread clocks.
pub(crate) fn measured<T>(f: impl FnOnce() -> T) -> (T, Option<Sample>) {
    let a = mark();
    let r = f();
    (r, since(a))
}

/// Whether a call that took `wall_ns` and cost `s` held its thread past the budget.
pub(crate) fn is_stall(wall_ns: u64, s: Sample, budget_ns: u64) -> bool {
    if s.cpu_ns > budget_ns {
        return true;
    }
    if wall_ns <= budget_ns {
        return false;
    }
    match s.voluntary {
        Some(v) => v > 0,
        None => wall_ns.saturating_sub(s.cpu_ns) > budget_ns.saturating_mul(BLOCKED_FACTOR),
    }
}

/// What a measured call changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    None,
    /// A confirmed stall.
    Stall,
    /// A confirmed stall that moved the route to the offload pool.
    Offloaded,
}

/// The watchdog state of one route (or, for a service without routes, of one slot of paths).
pub(crate) struct Watch {
    offload: AtomicBool,
    /// Measured calls left while the route is suspect (0: not suspect).
    suspect: AtomicU32,
    /// Times of recent confirmed stalls (loop clock, ns).
    ring: Mutex<VecDeque<u64>>,
    /// Consecutive fast calls on the offload pool.
    fast: AtomicU32,
    /// Fast calls needed to move back (0: not set yet).
    back_after: AtomicU32,
    /// The budget, set when the route moves to the pool (the workers judge calls by it).
    budget_ns: AtomicU64,
    recover: AtomicU32,
    pub(crate) logged: AtomicBool,
    /// Counts the watches of a group that are suspect or offloaded, so the server checks a
    /// group's watches only when one of them is.
    group: Option<Arc<AtomicU32>>,
}

impl Watch {
    pub(crate) fn new(group: Option<Arc<AtomicU32>>) -> Watch {
        Watch {
            offload: AtomicBool::new(false),
            suspect: AtomicU32::new(0),
            ring: Mutex::new(VecDeque::new()),
            fast: AtomicU32::new(0),
            back_after: AtomicU32::new(0),
            budget_ns: AtomicU64::new(0),
            recover: AtomicU32::new(0),
            logged: AtomicBool::new(false),
            group,
        }
    }

    fn group_add(&self, up: bool) {
        if let Some(g) = &self.group {
            if up {
                g.fetch_add(1, R);
            } else {
                g.fetch_sub(1, R);
            }
        }
    }

    #[inline]
    pub(crate) fn offloaded(&self) -> bool {
        self.offload.load(R)
    }

    #[inline]
    pub(crate) fn suspect(&self) -> bool {
        self.suspect.load(R) != 0
    }

    /// An unmeasured call overran the budget on the wall clock: measure the next calls.
    /// Returns true when this made the route suspect.
    pub(crate) fn wall_overrun(&self) -> bool {
        if self.offloaded() {
            return false;
        }
        let was = self.suspect.swap(SUSPECT_CALLS, R);
        if was == 0 {
            self.group_add(true);
        }
        was == 0
    }

    fn end_suspicion(&self) {
        if self.suspect.swap(0, R) != 0 {
            self.group_add(false);
        }
    }

    /// A call measured with the thread clocks.
    pub(crate) fn measured(&self, wall_ns: u64, s: Sample, p: &Policy, stalls: u32, now: u64) -> Event {
        if !is_stall(wall_ns, s, p.budget_ns) {
            // Fast: one fewer measured call left.
            let mut x = self.suspect.load(R);
            while x != 0 {
                match self.suspect.compare_exchange_weak(x, x - 1, R, R) {
                    Ok(_) => {
                        if x == 1 {
                            self.group_add(false);
                        }
                        break;
                    }
                    Err(y) => x = y,
                }
            }
            return Event::None;
        }
        if self.suspect.swap(SUSPECT_CALLS, R) == 0 {
            self.group_add(true);
        }
        if stalls == 0 {
            return Event::Stall;
        }
        let k = (stalls as usize).min(MAX_RING);
        let full = {
            let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
            ring.push_back(now);
            while ring.len() > k {
                ring.pop_front();
            }
            ring.len() == k && now.saturating_sub(ring[0]) <= p.window_ns
        };
        if !full {
            return Event::Stall;
        }
        self.budget_ns.store(p.budget_ns, R);
        self.recover.store(p.recover, R);
        if self.back_after.load(R) == 0 {
            self.back_after.store(p.recover, R);
        }
        self.fast.store(0, R);
        let moved = !self.offload.swap(true, R);
        if moved {
            self.group_add(true);
        }
        self.end_suspicion();
        if moved {
            Event::Offloaded
        } else {
            Event::Stall
        }
    }

    /// A call of an offloaded route finished on a worker. Returns true when it moved back.
    pub(crate) fn offloaded_call(&self, wall_ns: u64, s: Option<Sample>) -> bool {
        let budget = self.budget_ns.load(R);
        let fast = match s {
            Some(s) => !is_stall(wall_ns, s, budget),
            None => wall_ns <= budget,
        };
        if !fast {
            self.fast.store(0, R);
            return false;
        }
        let need = self.back_after.load(R);
        if self.recover.load(R) == 0 || need == 0 {
            return false;
        }
        if self.fast.fetch_add(1, R) + 1 < need {
            return false;
        }
        self.fast.store(0, R);
        if !self.offload.swap(false, R) {
            return false;
        }
        self.back_after.store(need.saturating_mul(2).min(MAX_BACK_AFTER), R);
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.group_add(false);
        true
    }
}

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch").field("offload", &self.offloaded()).field("suspect", &self.suspect.load(R)).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Policy = Policy { budget_ns: 1_000_000, stalls: 3, window_ns: 1_000_000_000, recover: 4 };
    const BUSY: Sample = Sample { cpu_ns: 5_000_000, voluntary: Some(0) };
    const IDLE: Sample = Sample { cpu_ns: 10_000, voluntary: Some(0) };

    #[test]
    fn preemption_is_not_a_stall_but_cpu_and_blocking_are() {
        // Preempted: long wall time, little CPU, no voluntary switch.
        assert!(!is_stall(9_000_000, IDLE, P.budget_ns));
        assert!(is_stall(9_000_000, BUSY, P.budget_ns));
        assert!(is_stall(2_000_000, Sample { cpu_ns: 10_000, voluntary: Some(1) }, P.budget_ns), "blocked");
        assert!(!is_stall(500_000, Sample { cpu_ns: 10_000, voluntary: Some(1) }, P.budget_ns), "short block");
        // Without switch counts: only off-CPU time far above the budget.
        assert!(!is_stall(5_000_000, Sample { cpu_ns: 10_000, voluntary: None }, P.budget_ns));
        assert!(is_stall(20_000_000, Sample { cpu_ns: 10_000, voluntary: None }, P.budget_ns));
    }

    #[test]
    fn stalls_must_fall_in_the_window_and_the_route_comes_back() {
        let g = Arc::new(AtomicU32::new(0));
        let w = Watch::new(Some(g.clone()));
        assert!(w.wall_overrun());
        assert_eq!(g.load(R), 1);
        // Spread-out stalls never trip it.
        for i in 0..10u64 {
            assert_eq!(w.measured(5_000_000, BUSY, &P, 3, i * 2_000_000_000), Event::Stall);
        }
        assert!(!w.offloaded());
        // Three within a second do.
        let t = 100_000_000_000;
        assert_eq!(w.measured(5_000_000, BUSY, &P, 3, t), Event::Stall);
        assert_eq!(w.measured(5_000_000, BUSY, &P, 3, t + 1), Event::Stall);
        assert_eq!(w.measured(5_000_000, BUSY, &P, 3, t + 2), Event::Offloaded);
        assert!(w.offloaded() && !w.suspect());
        assert_eq!(g.load(R), 1, "offloaded, no longer suspect");
        // Back after `recover` fast calls; a slow one restarts the count.
        for _ in 0..3 {
            assert!(!w.offloaded_call(100_000, Some(IDLE)));
        }
        assert!(!w.offloaded_call(5_000_000, Some(BUSY)));
        for _ in 0..3 {
            assert!(!w.offloaded_call(100_000, Some(IDLE)));
        }
        assert!(w.offloaded_call(100_000, Some(IDLE)));
        assert!(!w.offloaded());
        assert_eq!(g.load(R), 0);
        // Next time it needs twice as many.
        w.wall_overrun();
        for i in 0..3 {
            w.measured(5_000_000, BUSY, &P, 3, t + 10 + i);
        }
        assert!(w.offloaded());
        for _ in 0..7 {
            assert!(!w.offloaded_call(100_000, Some(IDLE)));
        }
        assert!(w.offloaded_call(100_000, Some(IDLE)));
    }

    #[test]
    fn suspicion_lapses_after_fast_measured_calls() {
        let g = Arc::new(AtomicU32::new(0));
        let w = Watch::new(Some(g.clone()));
        w.wall_overrun();
        for _ in 0..SUSPECT_CALLS {
            assert!(w.suspect());
            assert_eq!(w.measured(9_000_000, IDLE, &P, 3, 0), Event::None);
        }
        assert!(!w.suspect());
        assert_eq!(g.load(R), 0);
    }
}
