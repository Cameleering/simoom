//! Sliding-window frame budgets per connection (plan §2.7, research §5).
//!
//! Each budget is an approximate sliding window built from two fixed buckets: the estimate is
//! the current bucket plus the previous bucket weighted by how much of it still overlaps the
//! window. It costs two counters and a timestamp, and never under-counts a burst by more than
//! one bucket's worth of decay.

/// Limits per window. `u32::MAX` disables a budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    /// Window length in milliseconds.
    pub window_ms: u64,
    /// RST_STREAM frames received (Rapid Reset, CVE-2023-44487; reset flood, CVE-2019-9514).
    pub rst_received: u32,
    /// RST_STREAM frames the peer made us send: protocol errors on streams and refused streams
    /// (MadeYouReset, CVE-2025-8671; CVE-2019-9514). Resets the application asks for do not
    /// count.
    pub rst_sent: u32,
    /// PING frames received (ping flood, CVE-2019-9512).
    pub ping: u32,
    /// SETTINGS frames received (settings flood, CVE-2019-9515).
    pub settings: u32,
    /// Empty DATA, HEADERS and CONTINUATION frames without END_STREAM or END_HEADERS (empty
    /// frames flood, CVE-2019-9518).
    pub empty_frames: u32,
    /// PRIORITY frames received (resource loop, CVE-2019-9513).
    pub priority: u32,
    /// WINDOW_UPDATE frames with an increment under 1024 bytes (data dribble, CVE-2019-9511).
    pub small_window_updates: u32,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            window_ms: 10_000,
            rst_received: 200,
            rst_sent: 200,
            ping: 100,
            settings: 100,
            empty_frames: 200,
            priority: 1000,
            small_window_updates: 500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    RstReceived = 0,
    RstSent,
    Ping,
    Settings,
    Empty,
    Priority,
    SmallWindowUpdate,
}

#[derive(Clone, Copy, Debug, Default)]
struct Counter {
    prev: u32,
    cur: u32,
    start: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct Meter {
    limits: [u32; 7],
    window: u64,
    counters: [Counter; 7],
}

impl Meter {
    pub(crate) fn new(b: &Budgets) -> Meter {
        Meter {
            limits: [b.rst_received, b.rst_sent, b.ping, b.settings, b.empty_frames, b.priority, b.small_window_updates],
            window: b.window_ms.max(1),
            counters: [Counter { prev: 0, cur: 0, start: 0 }; 7],
        }
    }

    /// Counts one event at `now`; true when the budget is exceeded.
    #[inline(never)]
    pub(crate) fn hit(&mut self, kind: Kind, now: u64) -> bool {
        let limit = self.limits[kind as usize];
        if limit == u32::MAX {
            return false;
        }
        let w = self.window;
        let c = &mut self.counters[kind as usize];
        let elapsed = now.saturating_sub(c.start);
        if elapsed >= w {
            c.prev = if elapsed >= 2 * w { 0 } else { c.cur };
            c.cur = 0;
            c.start = now - elapsed % w;
        }
        c.cur = c.cur.saturating_add(1);
        let into = now.saturating_sub(c.start).min(w);
        let estimate = (c.prev as u64 * (w - into)).div_ceil(w) + c.cur as u64;
        estimate > limit as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window() {
        let b = Budgets { window_ms: 1000, rst_received: 10, ..Budgets::default() };
        let mut m = Meter::new(&b);
        for i in 0..10 {
            assert!(!m.hit(Kind::RstReceived, 5000 + i), "{i}");
        }
        assert!(m.hit(Kind::RstReceived, 5010));
        // just after the bucket turns the previous one still weighs in
        let mut m = Meter::new(&b);
        for _ in 0..10 {
            assert!(!m.hit(Kind::RstReceived, 999));
        }
        assert!(m.hit(Kind::RstReceived, 1001));
        // after two windows it is forgotten
        let mut m = Meter::new(&b);
        for _ in 0..10 {
            m.hit(Kind::RstReceived, 0);
        }
        assert!(!m.hit(Kind::RstReceived, 2500));
        // a steady rate under the limit never trips
        let mut m = Meter::new(&b);
        for t in 0..10_000u64 {
            if t % 125 == 0 {
                assert!(!m.hit(Kind::RstReceived, t), "{t}");
            }
        }
        // disabled
        let mut m = Meter::new(&Budgets { ping: u32::MAX, ..b });
        for _ in 0..100_000 {
            assert!(!m.hit(Kind::Ping, 0));
        }
    }
}
