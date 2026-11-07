//! The rate sweep that finds the **SLO throughput**: the highest open-loop rate whose p99 stays
//! at or under the limit (1 ms by default), with no errors and the offered rate actually
//! achieved (plan §6.5).
//!
//! 1. A closed-loop probe at the same connection count gives the capacity `C`.
//! 2. A binary search over `(0, 1.05·C]` keeps the highest passing rate, to 2% precision.
//! 3. Latency is then measured at 50%, 80% and 95% of the SLO throughput with longer runs.

use crate::load::{Report, Spec};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Plan {
    pub p99_limit_us: f64,
    pub probe: Duration,
    pub step_warmup: Duration,
    pub step: Duration,
    pub point_warmup: Duration,
    pub point: Duration,
    pub max_steps: usize,
    pub precision: f64,
    pub points: Vec<f64>,
}

impl Default for Plan {
    fn default() -> Self {
        Plan {
            p99_limit_us: 1000.0,
            probe: Duration::from_secs(5),
            step_warmup: Duration::from_secs(3),
            step: Duration::from_secs(10),
            point_warmup: Duration::from_secs(5),
            point: Duration::from_secs(30),
            max_steps: 8,
            precision: 0.02,
            points: vec![0.5, 0.8, 0.95],
        }
    }
}

/// Why a step failed, or `None` if it passed.
pub fn verdict(r: &Report, rate: f64, p99_limit_us: f64) -> Option<String> {
    let p99 = r.hist.percentile(99.0) as f64 / 1000.0;
    if r.errors() > 0 {
        return Some(format!("{} errors", r.errors()));
    }
    if r.incomplete as f64 > 0.001 * r.completed.max(1) as f64 {
        return Some(format!("{} incomplete", r.incomplete));
    }
    if r.achieved() < 0.98 * rate {
        return Some(format!("achieved {:.0} < 98% of {rate:.0}", r.achieved()));
    }
    if p99 > p99_limit_us {
        return Some(format!("p99 {p99:.0} us > {p99_limit_us:.0} us"));
    }
    None
}

/// The sweep's outcome.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub probe_rps: f64,
    pub slo_rps: f64,
    /// The search's upper bound passed: the SLO throughput is at least `slo_rps`, limited by
    /// the closed-loop capacity at this connection count.
    pub capped: bool,
    pub points: Vec<(f64, Report)>,
}

/// Runs the sweep with `run` (a local or a distributed runner); `emit` gets every result.
pub fn sweep(base: &Spec, plan: &Plan, run: &mut dyn FnMut(&Spec) -> Result<Report, String>, emit: &mut dyn FnMut(&str, &Report)) -> Result<Outcome, String> {
    let mut probe = base.clone();
    probe.rate = 0.0;
    probe.depth = 1;
    probe.warmup = plan.step_warmup.min(Duration::from_secs(2));
    probe.duration = plan.probe;
    let pr = run(&probe)?;
    emit("phase=probe ", &pr);
    let cap = pr.achieved();
    if cap <= 0.0 {
        return Err("the probe completed no requests".into());
    }
    let mut out = Outcome { probe_rps: cap, ..Outcome::default() };
    let step = |rate: f64| {
        let mut s = base.clone();
        s.rate = rate.round().max(1.0);
        s.warmup = plan.step_warmup;
        s.duration = plan.step;
        s
    };
    let mut lo = 0.0f64;
    let mut hi = (cap * 1.05).round();
    // the top first: if it passes, the closed-loop capacity is the bound
    let r = run(&step(hi))?;
    let v = verdict(&r, hi, plan.p99_limit_us);
    emit(&format!("phase=step verdict={} ", if v.is_none() { "pass" } else { "fail" }), &r);
    if v.is_none() {
        lo = hi;
        out.capped = true;
    } else {
        let mut first = true;
        for _ in 0..plan.max_steps {
            if lo > 0.0 && (hi - lo) / hi < plan.precision {
                break;
            }
            // start at 60% of the capacity, then bisect
            let mid = if first { (cap * 0.6).round() } else { ((lo + hi) / 2.0).round() };
            first = false;
            let r = run(&step(mid))?;
            let v = verdict(&r, mid, plan.p99_limit_us);
            emit(&format!("phase=step verdict={} ", if v.is_none() { "pass" } else { "fail" }), &r);
            if let Some(why) = v {
                eprintln!("sweep: {mid:.0} req/s fails: {why}");
                hi = mid;
            } else {
                lo = mid;
            }
        }
    }
    out.slo_rps = lo;
    if lo > 0.0 {
        for &pct in &plan.points {
            let mut s = base.clone();
            s.rate = (lo * pct).round().max(1.0);
            s.warmup = plan.point_warmup;
            s.duration = plan.point;
            let r = run(&s)?;
            emit(&format!("phase=point pct={:.0} ", pct * 100.0), &r);
            out.points.push((pct, r));
        }
    }
    Ok(out)
}
