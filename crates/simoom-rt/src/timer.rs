//! A hierarchical timing wheel (Varghese and Lauck, SOSP 1987).
//!
//! Four levels of 64 slots; level `l` slots are `64^l` ticks wide, so the wheel spans `64^4`
//! ticks (about 4.6 hours at the default 1 ms tick) and later deadlines wait in the last level
//! and are re-filed as time approaches. Insert and cancel are O(1) (nodes live in a slab and form
//! doubly linked lists per slot); finding the next deadline is a few bitmap operations; advancing
//! touches only slots that hold timers, never every tick in between.

const LEVELS: usize = 4;
const SLOTS: usize = 64;
const NIL: u32 = u32::MAX;
/// The list of timers beyond the wheel's span, re-filed whenever the clock enters a new span.
const OVERFLOW: usize = LEVELS * SLOTS;
const SPAN_BITS: u32 = 6 * LEVELS as u32;
/// Expired timers waiting to be popped, in deadline order; still cancellable.
const READY: usize = OVERFLOW + 1;

/// A handle to a scheduled timer, for [`TimerWheel::cancel`]. Stale handles are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TimerId {
    idx: u32,
    gen: u32,
}

struct Node<T> {
    deadline: u64,
    prev: u32,
    next: u32,
    slot: u32,
    gen: u32,
    payload: Option<T>,
}

/// A hierarchical timing wheel holding payloads of type `T`. Time is in ticks; the owner
/// decides what a tick is. See the [module docs](self).
pub struct TimerWheel<T> {
    now: u64,
    nodes: Vec<Node<T>>,
    free: Vec<u32>,
    heads: [u32; LEVELS * SLOTS + 2],
    ready_tail: u32,
    occupied: [u64; LEVELS],
    len: usize,
}

impl<T> std::fmt::Debug for TimerWheel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimerWheel").field("now", &self.now).field("len", &self.len).finish()
    }
}

impl<T> Default for TimerWheel<T> {
    fn default() -> Self {
        TimerWheel::new(0)
    }
}

impl<T> TimerWheel<T> {
    /// An empty wheel whose clock reads `now`.
    pub fn new(now: u64) -> TimerWheel<T> {
        TimerWheel { now, nodes: Vec::new(), free: Vec::new(), heads: [NIL; LEVELS * SLOTS + 2], ready_tail: NIL, occupied: [0; LEVELS], len: 0 }
    }

    /// The wheel's current tick.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Scheduled timers.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no timer is scheduled.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn slot_for(&self, deadline: u64) -> u32 {
        let d = deadline.max(self.now);
        let diff = (d ^ self.now) | (SLOTS as u64 - 1);
        let level = ((63 - diff.leading_zeros()) / 6) as usize;
        if level >= LEVELS {
            return OVERFLOW as u32;
        }
        let slot = (d >> (6 * level)) as usize & (SLOTS - 1);
        (level * SLOTS + slot) as u32
    }

    fn link(&mut self, idx: u32) {
        let slot = self.slot_for(self.nodes[idx as usize].deadline);
        let head = self.heads[slot as usize];
        {
            let n = &mut self.nodes[idx as usize];
            n.slot = slot;
            n.prev = NIL;
            n.next = head;
        }
        if head != NIL {
            self.nodes[head as usize].prev = idx;
        }
        self.heads[slot as usize] = idx;
        if (slot as usize) < OVERFLOW {
            self.occupied[slot as usize / SLOTS] |= 1 << (slot as usize % SLOTS);
        }
    }

    fn unlink(&mut self, idx: u32) {
        let (prev, next, slot) = {
            let n = &self.nodes[idx as usize];
            (n.prev, n.next, n.slot)
        };
        if prev != NIL {
            self.nodes[prev as usize].next = next;
        } else {
            self.heads[slot as usize] = next;
            if next == NIL && (slot as usize) < OVERFLOW {
                self.occupied[slot as usize / SLOTS] &= !(1 << (slot as usize % SLOTS));
            }
        }
        if next != NIL {
            self.nodes[next as usize].prev = prev;
        } else if slot as usize == READY {
            self.ready_tail = prev;
        }
    }

    fn link_ready(&mut self, idx: u32) {
        let tail = self.ready_tail;
        {
            let n = &mut self.nodes[idx as usize];
            n.slot = READY as u32;
            n.prev = tail;
            n.next = NIL;
        }
        if tail != NIL {
            self.nodes[tail as usize].next = idx;
        } else {
            self.heads[READY] = idx;
        }
        self.ready_tail = idx;
    }

    /// Schedules `payload` to expire at tick `deadline` (a deadline in the past expires at the
    /// next [`TimerWheel::advance`]).
    pub fn insert(&mut self, deadline: u64, payload: T) -> TimerId {
        let idx = match self.free.pop() {
            Some(i) => {
                let n = &mut self.nodes[i as usize];
                n.deadline = deadline;
                n.payload = Some(payload);
                i
            }
            None => {
                self.nodes.push(Node { deadline, prev: NIL, next: NIL, slot: 0, gen: 0, payload: Some(payload) });
                self.nodes.len() as u32 - 1
            }
        };
        self.link(idx);
        self.len += 1;
        TimerId { idx, gen: self.nodes[idx as usize].gen }
    }

    /// Whether a timer is still scheduled (not expired and popped, not cancelled).
    pub fn is_pending(&self, id: TimerId) -> bool {
        self.nodes.get(id.idx as usize).is_some_and(|n| n.gen == id.gen && n.payload.is_some())
    }

    /// Cancels a timer and returns its payload, or `None` if it already expired or was
    /// cancelled.
    pub fn cancel(&mut self, id: TimerId) -> Option<T> {
        let n = self.nodes.get(id.idx as usize)?;
        if n.gen != id.gen || n.payload.is_none() {
            return None;
        }
        self.unlink(id.idx);
        Some(self.release(id.idx))
    }

    fn release(&mut self, idx: u32) -> T {
        let n = &mut self.nodes[idx as usize];
        n.gen = n.gen.wrapping_add(1);
        self.free.push(idx);
        self.len -= 1;
        n.payload.take().unwrap()
    }

    /// The earliest tick at which something may need doing: a deadline, or the start of a
    /// slot whose timers must be re-filed. `None` when the wheel is empty.
    pub fn next_deadline(&self) -> Option<u64> {
        if self.heads[READY] != NIL {
            return Some(self.now);
        }
        self.next_due().map(|(t, _)| t)
    }

    /// The next tick that needs work and the slot (or the overflow list) to take then.
    fn next_due(&self) -> Option<(u64, usize)> {
        let mut best: Option<(u64, usize)> = None;
        for level in 0..LEVELS {
            let occ = self.occupied[level];
            if occ == 0 {
                continue;
            }
            let shift = 6 * level as u32;
            let cur = (self.now >> shift) as usize & (SLOTS - 1);
            let ahead = occ.rotate_right(cur as u32).trailing_zeros() as usize;
            let slot = (cur + ahead) % SLOTS;
            let level_span = 1u64 << (shift + 6);
            let mut t = (self.now & !(level_span - 1)) + ((slot as u64) << shift);
            if slot < cur {
                t += level_span;
            }
            // A past-due timer sits in the current level-0 slot, which reads as `now`.
            best = Some((t.max(self.now), level * SLOTS + slot));
            break;
        }
        if self.heads[OVERFLOW] != NIL {
            let next_span = (self.now | ((1u64 << SPAN_BITS) - 1)).saturating_add(1);
            if best.is_none_or(|(t, _)| next_span < t) {
                best = Some((next_span, OVERFLOW));
            }
        }
        best
    }

    /// Moves the clock to `now` and appends every expired payload to `out`, in deadline order.
    pub fn advance(&mut self, now: u64, out: &mut Vec<T>) {
        self.collect(now);
        while let Some(p) = self.pop_ready() {
            out.push(p);
        }
    }

    /// Moves the clock to `now` and sets every expired timer aside, in deadline order, for
    /// [`TimerWheel::pop_ready`]. Until popped they can still be cancelled, so a callback that
    /// cancels a timer due in the same batch stops it from firing.
    pub fn collect(&mut self, now: u64) {
        if now < self.now {
            return;
        }
        while let Some((t, slot)) = self.next_due() {
            if t > now {
                break;
            }
            self.now = t;
            let mut idx = self.heads[slot];
            self.heads[slot] = NIL;
            if slot < OVERFLOW {
                self.occupied[slot / SLOTS] &= !(1 << (slot % SLOTS));
            }
            while idx != NIL {
                let next = self.nodes[idx as usize].next;
                if self.nodes[idx as usize].deadline <= self.now {
                    self.link_ready(idx);
                } else {
                    self.link(idx); // cascade to a finer level
                }
                idx = next;
            }
        }
        self.now = now;
    }

    /// Takes the next expired timer set aside by [`TimerWheel::collect`]. Timers inserted after
    /// the collect, even ones already due, wait for the next collect.
    pub fn pop_ready(&mut self) -> Option<T> {
        let idx = self.heads[READY];
        if idx == NIL {
            return None;
        }
        self.unlink(idx);
        Some(self.release(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(w: &mut TimerWheel<u64>, to: u64) -> Vec<u64> {
        let mut out = Vec::new();
        w.advance(to, &mut out);
        out.sort();
        out
    }

    #[test]
    fn fires_at_the_deadline_never_early() {
        let mut w = TimerWheel::new(0);
        for d in [1u64, 5, 63, 64, 65, 100, 4095, 4096, 4097, 300_000, 20_000_000, 1u64 << 40] {
            w.insert(d, d);
        }
        assert_eq!(w.next_deadline(), Some(1));
        assert!(drain(&mut w, 0).is_empty());
        assert_eq!(drain(&mut w, 1), vec![1]);
        assert_eq!(drain(&mut w, 63), vec![5, 63]);
        assert_eq!(drain(&mut w, 64), vec![64]);
        assert_eq!(drain(&mut w, 4096), vec![65, 100, 4095, 4096]);
        assert!(drain(&mut w, 299_999).iter().all(|&d| d <= 299_999));
        assert_eq!(drain(&mut w, 300_000), vec![300_000]);
        assert!(drain(&mut w, 19_999_999).is_empty());
        assert_eq!(drain(&mut w, 20_000_000), vec![20_000_000]);
        assert_eq!(w.len(), 1);
        assert!(drain(&mut w, (1u64 << 40) - 1).is_empty());
        assert_eq!(drain(&mut w, 1u64 << 40), vec![1u64 << 40]);
        assert!(w.is_empty());
        assert_eq!(w.next_deadline(), None);
    }

    #[test]
    fn cancel_and_reuse() {
        let mut w = TimerWheel::new(1000);
        let a = w.insert(1010, 1);
        let b = w.insert(1010, 2);
        let c = w.insert(5000, 3);
        assert_eq!(w.cancel(b), Some(2));
        assert_eq!(w.cancel(b), None, "a stale id is ignored");
        assert_eq!(w.cancel(c), Some(3));
        let d = w.insert(1005, 4);
        assert_ne!(d, b, "a reused node gets a new generation");
        assert_eq!(drain(&mut w, 2000), vec![1, 4]);
        assert_eq!(w.cancel(a), None);
        assert!(w.is_empty());
    }

    #[test]
    fn collected_timers_stay_cancellable_and_pop_in_order() {
        let mut w = TimerWheel::new(0);
        let a = w.insert(5, 'a');
        let b = w.insert(15, 'b');
        let c = w.insert(3, 'c');
        w.collect(20);
        assert_eq!(w.next_deadline(), Some(20));
        assert_eq!(w.pop_ready(), Some('c'));
        assert_eq!(w.cancel(b), Some('b'), "due but not popped: still cancellable");
        let d = w.insert(1, 'd'); // due already, but waits for the next collect
        assert_eq!(w.pop_ready(), Some('a'));
        assert_eq!(w.pop_ready(), None);
        assert_eq!(w.cancel(a), None);
        w.collect(20);
        assert_eq!(w.pop_ready(), Some('d'));
        let _ = (c, d);
        assert!(w.is_empty());
    }

    #[test]
    fn past_deadlines_fire_on_the_next_advance() {
        let mut w = TimerWheel::new(500);
        w.insert(10, 7);
        assert_eq!(w.next_deadline(), Some(500));
        assert_eq!(drain(&mut w, 500), vec![7]);
    }

    #[test]
    fn randomized_against_a_sorted_list() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut w = TimerWheel::new(0);
        let mut live: Vec<(u64, u64, TimerId)> = Vec::new();
        let mut now = 0u64;
        for step in 0..20_000u64 {
            match rnd() % 4 {
                0 | 1 => {
                    let d = now + rnd() % [10, 1000, 100_000, 30_000_000][(rnd() % 4) as usize];
                    let id = w.insert(d, step);
                    live.push((d, step, id));
                }
                2 if !live.is_empty() => {
                    let i = (rnd() % live.len() as u64) as usize;
                    let (_, v, id) = live.swap_remove(i);
                    assert_eq!(w.cancel(id), Some(v));
                }
                _ => {
                    now += rnd() % 5000;
                    let mut got = Vec::new();
                    w.advance(now, &mut got);
                    got.sort();
                    let mut want: Vec<u64> = live.iter().filter(|x| x.0 <= now).map(|x| x.1).collect();
                    want.sort();
                    live.retain(|x| x.0 > now);
                    assert_eq!(got, want, "at {now}");
                    if let Some(next) = w.next_deadline() {
                        assert!(next >= now);
                        assert!(live.iter().all(|x| x.0 >= next), "nothing is due before next_deadline");
                    }
                }
            }
            assert_eq!(w.len(), live.len());
        }
    }

    #[test]
    fn insert_and_cancel_cost() {
        let mut w = TimerWheel::new(0);
        let n = 200_000u64;
        let t = std::time::Instant::now();
        let ids: Vec<TimerId> = (0..n).map(|i| w.insert(i % 60_000 + 1, i)).collect();
        for id in &ids {
            w.cancel(*id);
        }
        let per = t.elapsed().as_nanos() as f64 / n as f64;
        eprintln!("timer insert+cancel: {per:.1} ns");
    }
}
