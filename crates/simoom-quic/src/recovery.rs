//! Loss detection, PTO and congestion control (RFC 9002), with a token-bucket pacer.

use crate::error::{TransportError, PROTOCOL_VIOLATION};
use crate::frame::AckRanges;
use crate::stream::Control;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

pub const PACKET_THRESHOLD: u64 = 3;
pub const GRANULARITY: Duration = Duration::from_millis(1);
pub const INITIAL_RTT: Duration = Duration::from_millis(333);
pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// What a sent packet carried, for acknowledgement and retransmission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentFrame {
    Stream { id: u64, off: u64, len: u32, fin: bool },
    Crypto { off: u64, len: u32 },
    Control(Control),
    NewConnectionId(u64),
    RetireConnectionId(u64),
    HandshakeDone,
    NewToken,
    /// An ACK frame whose largest acknowledged was this packet number.
    Ack(u64),
    Ping,
    /// A PMTU probe of this size: its loss is not a congestion signal (RFC 9000 §14.4).
    MtuProbe(u16),
}

#[derive(Debug)]
pub struct SentPacket {
    pub pn: u64,
    pub time: Instant,
    pub size: u16,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub frames: Vec<SentFrame>,
}

#[derive(Clone, Copy, Debug)]
pub struct Rtt {
    pub latest: Duration,
    pub smoothed: Duration,
    pub var: Duration,
    pub min: Duration,
    pub has_sample: bool,
}

impl Default for Rtt {
    fn default() -> Self {
        Rtt { latest: Duration::ZERO, smoothed: INITIAL_RTT, var: INITIAL_RTT / 2, min: Duration::ZERO, has_sample: false }
    }
}

impl Rtt {
    /// RFC 9002 §5.3.
    pub fn update(&mut self, latest: Duration, mut ack_delay: Duration, max_ack_delay: Duration, confirmed: bool) {
        self.latest = latest;
        if !self.has_sample {
            self.has_sample = true;
            self.min = latest;
            self.smoothed = latest;
            self.var = latest / 2;
            return;
        }
        self.min = self.min.min(latest);
        if confirmed {
            ack_delay = ack_delay.min(max_ack_delay);
        }
        let mut adjusted = latest;
        if latest >= self.min + ack_delay {
            adjusted = latest - ack_delay;
        }
        let diff = if self.smoothed > adjusted { self.smoothed - adjusted } else { adjusted - self.smoothed };
        self.var = (self.var * 3 + diff) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }
    pub fn pto_base(&self) -> Duration {
        self.smoothed + (self.var * 4).max(GRANULARITY)
    }
}

/// NewReno (RFC 9002 §7).
#[derive(Debug)]
pub struct NewReno {
    pub mds: u64,
    pub cwnd: u64,
    pub ssthresh: u64,
    pub in_flight: u64,
    recovery_start: Option<Instant>,
    acked_accum: u64,
}

impl NewReno {
    pub fn new(mds: u64) -> Self {
        NewReno {
            mds,
            cwnd: Self::initial_window(mds),
            ssthresh: u64::MAX,
            in_flight: 0,
            recovery_start: None,
            acked_accum: 0,
        }
    }
    pub fn initial_window(mds: u64) -> u64 {
        (10 * mds).min((2 * mds).max(14720))
    }
    pub fn min_window(&self) -> u64 {
        2 * self.mds
    }
    pub fn available(&self) -> u64 {
        self.cwnd.saturating_sub(self.in_flight)
    }
    pub fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|r| sent <= r)
    }
    pub fn on_acked(&mut self, size: u64, sent: Instant, app_limited: bool) {
        self.in_flight = self.in_flight.saturating_sub(size);
        if self.in_recovery(sent) || app_limited {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd += size;
        } else {
            self.acked_accum += size;
            if self.acked_accum >= self.cwnd {
                self.acked_accum -= self.cwnd;
                self.cwnd += self.mds;
            }
        }
    }
    pub fn on_congestion_event(&mut self, now: Instant, sent: Instant) {
        if self.in_recovery(sent) {
            return;
        }
        self.recovery_start = Some(now);
        self.ssthresh = (self.cwnd / 2).max(self.min_window());
        self.cwnd = self.ssthresh;
        self.acked_accum = 0;
    }
    pub fn on_persistent_congestion(&mut self) {
        self.cwnd = self.min_window();
        self.recovery_start = None;
    }
    /// A new path (migration): back to the initial window.
    pub fn reset(&mut self) {
        let f = self.in_flight;
        *self = NewReno::new(self.mds);
        self.in_flight = f;
    }
}

/// Token-bucket pacer (RFC 9002 §7.7): rate 1.25 × cwnd / srtt, burst up to 10 datagrams.
#[derive(Debug)]
pub struct Pacer {
    tokens: u64,
    last: Option<Instant>,
}

impl Pacer {
    pub fn new() -> Self {
        Pacer { tokens: 0, last: None }
    }
    fn capacity(mds: u64, cwnd: u64) -> u64 {
        (cwnd / 4).clamp(2 * mds, 10 * mds)
    }
    /// When a packet of `size` may be sent; `None` means now.
    pub fn delay(&mut self, now: Instant, size: u64, rtt: Duration, cwnd: u64, mds: u64) -> Option<Instant> {
        let cap = Self::capacity(mds, cwnd);
        let rtt_ns = rtt.as_nanos().max(1) as u64;
        match self.last {
            None => {
                self.tokens = cap;
                self.last = Some(now);
            }
            Some(l) if now > l => {
                let ns = (now - l).as_nanos() as u64;
                // tokens += elapsed × 1.25 × cwnd / rtt; keep the clock when nothing accrued
                // so fractions are not lost.
                let add = (ns as u128 * cwnd as u128 * 5 / (4 * rtt_ns as u128)) as u64;
                if add > 0 {
                    self.tokens = (self.tokens.saturating_add(add)).min(cap);
                    self.last = Some(now);
                }
            }
            _ => {}
        }
        if self.tokens >= size.min(cap) {
            return None;
        }
        let need = size.min(cap) - self.tokens;
        let ns = (need as u128 * 4 * rtt_ns as u128).div_ceil(5 * cwnd.max(1) as u128) as u64;
        Some(now + Duration::from_nanos(ns.max(1)))
    }
    pub fn on_sent(&mut self, size: u64) {
        self.tokens = self.tokens.saturating_sub(size);
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

/// Sent-packet bookkeeping for one packet number space.
#[derive(Default, Debug)]
pub struct SentSpace {
    pub sent: BTreeMap<u64, SentPacket>,
    pub next_pn: u64,
    pub largest_acked: Option<u64>,
    pub loss_time: Option<Instant>,
    pub last_ack_eliciting: Option<Instant>,
    pub eliciting_in_flight: u64,
    /// Packet numbers deliberately left unused (RFC 9000 §21.4): an ACK covering one comes from
    /// an optimistic acker. The most recent few are kept.
    pub skipped: VecDeque<u64>,
    /// The packet number to skip next (0 means not scheduled yet).
    pub skip_at: u64,
}

pub struct AckResult {
    pub acked: Vec<SentPacket>,
    pub lost: Vec<SentPacket>,
}

/// Loss-detection state for a connection.
pub struct Recovery {
    pub rtt: Rtt,
    pub cc: NewReno,
    pub pacer: Pacer,
    pub spaces: [SentSpace; 3],
    pub pto_count: u32,
    pub max_ack_delay: Duration,
    /// The last time the connection had no more to send though the window allowed it.
    pub app_limited: bool,
}

impl Recovery {
    pub fn new(mds: u64) -> Self {
        Recovery {
            rtt: Rtt::default(),
            cc: NewReno::new(mds),
            pacer: Pacer::new(),
            spaces: Default::default(),
            pto_count: 0,
            max_ack_delay: Duration::from_millis(25),
            app_limited: false,
        }
    }

    pub fn on_sent(&mut self, space: usize, p: SentPacket) {
        let s = &mut self.spaces[space];
        if p.in_flight {
            if p.ack_eliciting {
                s.last_ack_eliciting = Some(p.time);
                s.eliciting_in_flight += 1;
            }
            self.cc.in_flight += p.size as u64;
            self.pacer.on_sent(p.size as u64);
        }
        s.sent.insert(p.pn, p);
    }

    fn remove_in_flight(&mut self, space: usize, p: &SentPacket) {
        if p.in_flight {
            self.cc.in_flight = self.cc.in_flight.saturating_sub(p.size as u64);
            if p.ack_eliciting {
                let s = &mut self.spaces[space];
                s.eliciting_in_flight = s.eliciting_in_flight.saturating_sub(1);
            }
        }
    }

    /// Processes an ACK frame (RFC 9002 §6, Appendix A.7).
    pub fn on_ack(
        &mut self,
        space: usize,
        ranges: &AckRanges<'_>,
        ack_delay: Duration,
        now: Instant,
        confirmed: bool,
    ) -> Result<AckResult, TransportError> {
        let s = &mut self.spaces[space];
        if s.next_pn == 0 || ranges.largest >= s.next_pn {
            return Err(TransportError::frame(PROTOCOL_VIOLATION, 0x02, "ACK of an unsent packet"));
        }
        if s.skipped.iter().any(|&pn| ranges.iter().any(|(lo, hi)| lo <= pn && pn <= hi)) {
            return Err(TransportError::frame(PROTOCOL_VIOLATION, 0x02, "ACK of a skipped packet number"));
        }
        let new_largest = s.largest_acked.is_none_or(|l| ranges.largest > l);
        if new_largest {
            s.largest_acked = Some(ranges.largest);
        }
        let mut acked = Vec::new();
        for (lo, hi) in ranges.iter() {
            let keys: Vec<u64> = s.sent.range(lo..=hi).map(|(&k, _)| k).collect();
            for k in keys {
                acked.push(s.sent.remove(&k).unwrap());
            }
        }
        if acked.is_empty() {
            return Ok(AckResult { acked, lost: Vec::new() });
        }
        // acked is in descending range order; the first entry is the highest.
        let largest_newly = acked.iter().max_by_key(|p| p.pn).unwrap();
        if largest_newly.pn == ranges.largest && acked.iter().any(|p| p.ack_eliciting) {
            let sample = now.saturating_duration_since(largest_newly.time);
            let delay = if space == 2 { ack_delay } else { Duration::ZERO };
            self.rtt.update(sample, delay, self.max_ack_delay, confirmed);
        }
        for p in &acked {
            if p.in_flight {
                self.remove_in_flight_counts(space, p);
                self.cc.on_acked(p.size as u64, p.time, self.app_limited);
            }
        }
        let lost = self.detect_lost(space, now);
        self.pto_count = 0;
        Ok(AckResult { acked, lost })
    }

    fn remove_in_flight_counts(&mut self, space: usize, p: &SentPacket) {
        if p.ack_eliciting {
            let s = &mut self.spaces[space];
            s.eliciting_in_flight = s.eliciting_in_flight.saturating_sub(1);
        }
    }

    /// Declares packets lost by packet or time threshold (RFC 9002 §6.1) and reacts.
    pub fn detect_lost(&mut self, space: usize, now: Instant) -> Vec<SentPacket> {
        let loss_delay = (self.rtt.latest.max(self.rtt.smoothed) * 9 / 8).max(GRANULARITY);
        let s = &mut self.spaces[space];
        s.loss_time = None;
        let Some(largest) = s.largest_acked else { return Vec::new() };
        let mut lost_pns = Vec::new();
        for (&pn, p) in s.sent.range(..largest) {
            let time_lost = now.checked_duration_since(p.time).is_some_and(|d| d >= loss_delay);
            if pn + PACKET_THRESHOLD <= largest || time_lost {
                lost_pns.push(pn);
            } else {
                let t = p.time + loss_delay;
                s.loss_time = Some(s.loss_time.map_or(t, |x| x.min(t)));
            }
        }
        let mut lost = Vec::with_capacity(lost_pns.len());
        for pn in lost_pns {
            let p = self.spaces[space].sent.remove(&pn).unwrap();
            self.remove_in_flight(space, &p);
            lost.push(p);
        }
        let is_probe = |p: &SentPacket| p.frames.iter().any(|f| matches!(f, SentFrame::MtuProbe(_)));
        if let Some(last) = lost.iter().filter(|p| p.in_flight && !is_probe(p)).map(|p| p.time).max() {
            self.cc.on_congestion_event(now, last);
            // Persistent congestion (RFC 9002 §7.6), simplified: the lost ack-eliciting
            // packets span more than the persistent congestion duration.
            if self.rtt.has_sample {
                let first = lost.iter().filter(|p| p.ack_eliciting).map(|p| p.time).min();
                let dur = (self.rtt.pto_base() + self.max_ack_delay) * PERSISTENT_CONGESTION_THRESHOLD;
                if let Some(f) = first {
                    if last.saturating_duration_since(f) > dur {
                        self.cc.on_persistent_congestion();
                    }
                }
            }
        }
        lost
    }

    /// Drops a space's state when its keys are discarded (RFC 9002 §6.4).
    pub fn discard(&mut self, space: usize) {
        let sent = std::mem::take(&mut self.spaces[space].sent);
        for p in sent.values() {
            if p.in_flight {
                self.cc.in_flight = self.cc.in_flight.saturating_sub(p.size as u64);
            }
        }
        let s = &mut self.spaces[space];
        s.eliciting_in_flight = 0;
        s.loss_time = None;
        s.last_ack_eliciting = None;
        self.pto_count = 0;
    }

    /// PTO duration for a space (RFC 9002 §6.2.1), with exponential backoff.
    pub fn pto(&self, space: usize) -> Duration {
        let mut d = self.rtt.pto_base();
        if space == 2 {
            d += self.max_ack_delay;
        }
        d * (1u32 << self.pto_count.min(16))
    }

    /// The earliest loss time across spaces, if any.
    pub fn earliest_loss_time(&self) -> Option<(Instant, usize)> {
        (0..3).filter_map(|i| self.spaces[i].loss_time.map(|t| (t, i))).min_by_key(|x| x.0)
    }

    /// The PTO deadline and its space. `spaces` lists the spaces with keys; app data is
    /// skipped until the handshake is confirmed.
    pub fn pto_deadline(&self, now: Instant, active: [bool; 3], confirmed: bool, client_anti_deadlock: bool) -> Option<(Instant, usize)> {
        let in_flight: u64 = (0..3).filter(|&i| active[i]).map(|i| self.spaces[i].eliciting_in_flight).sum();
        if in_flight == 0 {
            if client_anti_deadlock {
                let space = if active[1] { 1 } else { 0 };
                return Some((now.max(self.spaces[space].last_ack_eliciting.unwrap_or(now)) + self.pto(space), space));
            }
            return None;
        }
        let mut best: Option<(Instant, usize)> = None;
        for i in 0..3 {
            if !active[i] || self.spaces[i].eliciting_in_flight == 0 {
                continue;
            }
            if i == 2 && !confirmed {
                continue;
            }
            let Some(t) = self.spaces[i].last_ack_eliciting else { continue };
            let d = t + self.pto(i);
            if best.is_none_or(|b| d < b.0) {
                best = Some((d, i));
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_estimator() {
        let mut r = Rtt::default();
        r.update(Duration::from_millis(100), Duration::ZERO, Duration::from_millis(25), true);
        assert_eq!(r.smoothed, Duration::from_millis(100));
        assert_eq!(r.var, Duration::from_millis(50));
        r.update(Duration::from_millis(120), Duration::from_millis(10), Duration::from_millis(25), true);
        // adjusted = 110; var = (150 + 10)/4 = 40; smoothed = (700 + 110)/8 = 101.25
        assert_eq!(r.var, Duration::from_millis(40));
        assert_eq!(r.smoothed, Duration::from_micros(101_250));
        assert_eq!(r.min, Duration::from_millis(100));
    }

    #[test]
    fn newreno_growth_and_halving() {
        let now = Instant::now();
        let mut c = NewReno::new(1200);
        assert_eq!(c.cwnd, 12000);
        c.in_flight = 12000;
        for _ in 0..10 {
            c.on_acked(1200, now, false);
        }
        assert_eq!(c.cwnd, 24000);
        let later = now + Duration::from_millis(10);
        c.on_congestion_event(later, now + Duration::from_millis(5));
        assert_eq!(c.cwnd, 12000);
        // A loss of a packet sent before recovery started does not halve again.
        c.on_congestion_event(later + Duration::from_millis(1), now + Duration::from_millis(6));
        assert_eq!(c.cwnd, 12000);
        // Congestion avoidance: one MDS per cwnd of acked bytes.
        c.in_flight = 100_000;
        for _ in 0..10 {
            c.on_acked(1200, later + Duration::from_millis(2), false);
        }
        assert_eq!(c.cwnd, 13200);
        c.on_persistent_congestion();
        assert_eq!(c.cwnd, 2400);
    }

    #[test]
    fn pacer_spreads_bursts() {
        let now = Instant::now();
        let mut p = Pacer::new();
        let rtt = Duration::from_millis(100);
        let mut sent = 0;
        while p.delay(now, 1200, rtt, 120_000, 1200).is_none() {
            p.on_sent(1200);
            sent += 1;
        }
        assert_eq!(sent, 10); // the burst capacity
        let t = p.delay(now, 1200, rtt, 120_000, 1200).unwrap();
        // 1.25 × 120000 B / 100 ms = 1.5 MB/s → 1200 B every 0.8 ms
        assert!(t - now <= Duration::from_micros(800) && t - now > Duration::from_micros(700), "{:?}", t - now);
        assert!(p.delay(t, 1200, rtt, 120_000, 1200).is_none());
    }
}
