//! Small helpers: response-head pieces, the per-thread `Date` cache, a fast hasher.

use std::cell::RefCell;
use std::hash::{BuildHasherDefault, Hasher};

/// True if the comma-separated list `value` contains `token` (case-insensitive).
pub(crate) fn has_token(value: &[u8], token: &[u8]) -> bool {
    value.split(|&b| b == b',').any(|t| {
        let t = t.trim_ascii();
        t.eq_ignore_ascii_case(token)
    })
}

/// Whether a response with this status carries a body (and `content-length`).
#[inline]
pub(crate) fn has_body(status: u16) -> bool {
    status >= 200 && status != 204 && status != 304
}

/// Pre-built status lines for the common codes.
#[inline]
fn common_status_line(status: u16) -> Option<&'static [u8]> {
    Some(match status {
        200 => b"HTTP/1.1 200 OK\r\n",
        201 => b"HTTP/1.1 201 Created\r\n",
        204 => b"HTTP/1.1 204 No Content\r\n",
        301 => b"HTTP/1.1 301 Moved Permanently\r\n",
        302 => b"HTTP/1.1 302 Found\r\n",
        304 => b"HTTP/1.1 304 Not Modified\r\n",
        400 => b"HTTP/1.1 400 Bad Request\r\n",
        404 => b"HTTP/1.1 404 Not Found\r\n",
        500 => b"HTTP/1.1 500 Internal Server Error\r\n",
        503 => b"HTTP/1.1 503 Service Unavailable\r\n",
        _ => return None,
    })
}

/// `HTTP/1.1 <status> <reason>\r\n`.
pub(crate) fn status_line(out: &mut Vec<u8>, status: u16) {
    if let Some(l) = common_status_line(status) {
        out.extend_from_slice(l);
        return;
    }
    out.extend_from_slice(b"HTTP/1.1 ");
    let d = [b'0' + (status / 100 % 10) as u8, b'0' + (status / 10 % 10) as u8, b'0' + (status % 10) as u8];
    out.extend_from_slice(&d);
    out.push(b' ');
    out.extend_from_slice(simoom_http1::write::reason(status).as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Decimal digits of `n`.
pub(crate) fn decimal(n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = 20;
    let mut n = n;
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

/// `content-length: <n>\r\n`.
pub(crate) fn content_length(out: &mut Vec<u8>, n: u64) {
    let mut d = [0u8; 20];
    out.extend_from_slice(b"content-length: ");
    out.extend_from_slice(decimal(n, &mut d));
    out.extend_from_slice(b"\r\n");
}

struct DateState {
    /// Monotonic ns and Unix seconds (as ns) sampled together.
    mono_base: u64,
    wall_base: u64,
    secs: u64,
    bytes: [u8; 29],
    /// `date: <bytes>\r\n`
    line: [u8; 37],
}

thread_local! {
    static DATE: RefCell<Option<DateState>> = const { RefCell::new(None) };
}

fn date_state<R>(now_ns: u64, f: impl FnOnce(&DateState) -> R) -> R {
    DATE.with(|d| {
        let mut d = d.borrow_mut();
        match d.as_ref() {
            Some(st) if now_ns.wrapping_sub(st.mono_base) < 60_000_000_000 && (st.wall_base + now_ns.saturating_sub(st.mono_base)) / 1_000_000_000 == st.secs => f(st),
            _ => f(date_refresh(&mut d, now_ns)),
        }
    })
}

/// A new second (or minute, for the wall clock): reformat. Out of line, as it runs once a second
/// and its code is inlined into every response writer otherwise.
#[cold]
#[inline(never)]
fn date_refresh(d: &mut Option<DateState>, now_ns: u64) -> &DateState {
    if !d.as_ref().is_some_and(|st| now_ns.wrapping_sub(st.mono_base) < 60_000_000_000) {
        *d = None;
    }
    let st = d.get_or_insert_with(|| DateState { mono_base: now_ns, wall_base: simoom_sys::time::wall_ns(), secs: u64::MAX, bytes: [b' '; 29], line: [b' '; 37] });
    let secs = (st.wall_base + now_ns.saturating_sub(st.mono_base)) / 1_000_000_000;
    if secs != st.secs {
        st.secs = secs;
        st.bytes = simoom_http1::write::http_date(secs);
        st.line[..6].copy_from_slice(b"date: ");
        st.line[6..35].copy_from_slice(&st.bytes);
        st.line[35..].copy_from_slice(b"\r\n");
    }
    st
}

/// Calls `f` with the IMF-fixdate for the loop clock `now_ns` (monotonic). The wall clock is
/// sampled once a minute per thread; formatting happens once a second.
pub(crate) fn with_date<R>(now_ns: u64, f: impl FnOnce(&[u8; 29]) -> R) -> R {
    date_state(now_ns, |st| f(&st.bytes))
}

/// Appends `date: <IMF-fixdate>\r\n` for the loop clock `now_ns`.
#[inline]
pub(crate) fn date_line(now_ns: u64, out: &mut Vec<u8>) {
    date_state(now_ns, |st| out.extend_from_slice(&st.line))
}

/// What to do with a request head that missed its deadline ([`head_timeout_action`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadTimeout {
    /// Answer 408 and close gracefully (the usual case).
    Answer,
    /// Reset the connection without an answer (many timeouts on this loop just now).
    Drop,
    /// Too many closes on this loop in this slot: try again this many ns later.
    Later(u64),
}

/// Head timeouts answered with a 408 per loop and window; more are reset.
const HEAD_408_PER_WINDOW: u32 = 8;
/// Head-timeout closes per loop and window; more are spread over the next second.
const HEAD_CLOSES_PER_WINDOW: u32 = 64;
const HEAD_WINDOW_NS: u64 = 10_000_000;

thread_local! {
    /// (window start, closes in it, PRNG state) of this loop thread.
    static HEAD_TIMEOUTS: std::cell::Cell<(u64, u32, u64)> = const { std::cell::Cell::new((0, 0, 0x9E37_79B9_7F4A_7C15)) };
}

/// Paces head-timeout closes per loop thread. Slowloris attackers time out in waves (all opened
/// together, all due together) and reconnect at once: closing thousands in one turn, each with a
/// 408 and a graceful shutdown, stalls the loop for everyone else. So past a few per 10 ms the
/// connection is reset without an answer, and past [`HEAD_CLOSES_PER_WINDOW`] the rest of the
/// wave is postponed by a random 10 ms to 1 s.
pub(crate) fn head_timeout_action(now: u64) -> HeadTimeout {
    HEAD_TIMEOUTS.with(|c| {
        let (mut start, mut n, mut rng) = c.get();
        if now.saturating_sub(start) >= HEAD_WINDOW_NS {
            start = now;
            n = 0;
        }
        let r = if n >= HEAD_CLOSES_PER_WINDOW {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            HeadTimeout::Later(HEAD_WINDOW_NS + rng % 990_000_000)
        } else {
            n += 1;
            if n > HEAD_408_PER_WINDOW {
                HeadTimeout::Drop
            } else {
                HeadTimeout::Answer
            }
        };
        c.set((start, n, rng));
        r
    })
}

/// FNV-1a: fast for the short keys of the router and stream maps.
#[derive(Default, Clone, Copy)]
pub(crate) struct Fnv(u64);

impl Hasher for Fnv {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.0 == 0 { 0xcbf2_9ce4_8422_2325 } else { self.0 };
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        self.0 = h;
    }
    #[inline]
    fn write_u32(&mut self, n: u32) {
        self.0 = (self.0 ^ u64::from(n)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    #[inline]
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0 ^ n).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
}

/// New connections per client IP as token buckets ([`crate::Limits::reconnect_rate`]): a
/// direct-mapped table of 64 Ki entries, made on first use; an address that lands on another's
/// entry takes it over with a full bucket (the table forgets, it never refuses wrongly).
#[cfg(feature = "guard")]
#[derive(Default)]
pub(crate) struct Reconnects {
    /// `(address, last refill ns, milli-tokens)`.
    slots: Vec<(u128, u64, u32)>,
    seed: u64,
}

#[cfg(feature = "guard")]
const RECONNECT_SLOTS: usize = 1 << 16;

#[cfg(feature = "guard")]
impl Reconnects {
    /// Takes a token for a connection from `ip` at `now_ns`; `false` when its bucket is empty.
    pub(crate) fn allow(&mut self, ip: std::net::IpAddr, rate: u32, now_ns: u64) -> bool {
        if self.slots.is_empty() {
            let mut b = [0u8; 8];
            let _ = simoom_sys::arch::os_random(&mut b);
            self.seed = u64::from_le_bytes(b) | 1;
            self.slots = vec![(0, 0, 0); RECONNECT_SLOTS];
        }
        let k = IpCounts::key(ip);
        let h = ((k as u64) ^ ((k >> 64) as u64) ^ self.seed).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let s = &mut self.slots[(h >> 48) as usize];
        let cap = u64::from(rate).saturating_mul(1000).min(u64::from(u32::MAX));
        let tokens = if s.0 != k || s.1 == 0 {
            cap
        } else {
            let refill = (now_ns.saturating_sub(s.1) as u128 * u128::from(rate) / 1_000_000) as u64;
            (u64::from(s.2) + refill.min(cap)).min(cap)
        };
        let ok = tokens >= 1000;
        *s = (k, now_ns.max(1), (if ok { tokens - 1000 } else { tokens }) as u32);
        ok
    }
}

/// Open connections per client IP ([`crate::Limits::max_connections_per_ip`]): an
/// open-addressing table (linear probing, backward-shift deletion) with a hash keyed by OS
/// randomness, so clients can't aim addresses at one bucket. std's `HashMap` costs about 4 KB
/// more code here (SipHash, its random keys, and hashbrown's growth path). IPv4 addresses are
/// stored in their IPv4-mapped IPv6 form.
#[derive(Default)]
pub(crate) struct IpCounts {
    /// `(address, open connections)`; a count of 0 marks a free slot. Empty or a power of two.
    slots: Vec<(u128, u32)>,
    len: usize,
    seed: [u64; 2],
}

impl IpCounts {
    fn key(ip: std::net::IpAddr) -> u128 {
        match ip {
            std::net::IpAddr::V4(a) => a.to_ipv6_mapped().to_bits(),
            std::net::IpAddr::V6(a) => a.to_bits(),
        }
    }

    fn home(&self, k: u128) -> usize {
        const M: u64 = 0x9E37_79B9_7F4A_7C15;
        let a = ((k as u64) ^ self.seed[0]).wrapping_mul(M);
        let b = ((a ^ (a >> 29)) ^ ((k >> 64) as u64) ^ self.seed[1]).wrapping_mul(M);
        let h = (b ^ (b >> 32)).wrapping_mul(M);
        (h >> (64 - self.slots.len().trailing_zeros())) as usize
    }

    fn find(&self, k: u128) -> Result<usize, usize> {
        let mask = self.slots.len() - 1;
        let mut i = self.home(k);
        loop {
            match self.slots[i] {
                (_, 0) => return Err(i),
                (x, _) if x == k => return Ok(i),
                _ => i = (i + 1) & mask,
            }
        }
    }

    /// Counts one more connection from `ip`; `false` (and no change) when it has `cap` open.
    pub(crate) fn take(&mut self, ip: std::net::IpAddr, cap: usize) -> bool {
        if self.slots.is_empty() {
            let mut b = [0u8; 16];
            if !simoom_sys::arch::os_random(&mut b) {
                // No OS randomness: the table still works, with a less secret hash.
                b = (u128::from(simoom_sys::time::now_ns()) << 64 | u128::from(simoom_sys::time::wall_ns()) ^ (&b as *const _ as usize as u128)).to_le_bytes();
            }
            let [s0, s1] = [&b[..8], &b[8..]].map(|h| h.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)));
            self.seed = [s0, s1];
            self.slots = vec![(0, 0); 16];
        } else if (self.len + 1) * 2 > self.slots.len() {
            let grown = vec![(0, 0); self.slots.len() * 2];
            let old = std::mem::replace(&mut self.slots, grown);
            for e in old.into_iter().filter(|e| e.1 != 0) {
                if let Err(i) = self.find(e.0) {
                    self.slots[i] = e;
                }
            }
        }
        let k = Self::key(ip);
        match self.find(k) {
            Ok(i) if self.slots[i].1 as usize >= cap => false,
            Ok(i) => {
                self.slots[i].1 += 1;
                true
            }
            Err(_) if cap == 0 => false,
            Err(i) => {
                self.slots[i] = (k, 1);
                self.len += 1;
                true
            }
        }
    }

    /// Counts one connection from `ip` fewer.
    pub(crate) fn release(&mut self, ip: std::net::IpAddr) {
        if self.slots.is_empty() {
            return;
        }
        let Ok(mut i) = self.find(Self::key(ip)) else { return };
        self.slots[i].1 -= 1;
        if self.slots[i].1 != 0 {
            return;
        }
        // Backward-shift deletion: pull later entries of the probe run into the hole.
        self.len -= 1;
        let mask = self.slots.len() - 1;
        let mut j = i;
        loop {
            j = (j + 1) & mask;
            let e = self.slots[j];
            if e.1 == 0 {
                break;
            }
            // `e` may move back to `i` unless its home lies cyclically in (i, j].
            let h = self.home(e.0);
            if (j.wrapping_sub(h) & mask) >= (j.wrapping_sub(i) & mask) {
                self.slots[i] = e;
                i = j;
            }
        }
        self.slots[i] = (0, 0);
    }

    #[cfg(test)]
    pub(crate) fn count(&self, ip: std::net::IpAddr) -> u32 {
        if self.slots.is_empty() {
            return 0;
        }
        self.find(Self::key(ip)).map_or(0, |i| self.slots[i].1)
    }
}

pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<Fnv>>;

/// Decodes `%XX` escapes; `None` for a malformed escape.
pub fn percent_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let h = |b: u8| (b as char).to_digit(16);
            let (a, b) = (h(*s.get(i + 1)?)?, h(*s.get(i + 2)?)?);
            out.push((a * 16 + b) as u8);
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_numbers() {
        assert!(has_token(b"keep-alive, Close", b"close"));
        assert!(!has_token(b"closed", b"close"));
        let mut b = [0u8; 20];
        assert_eq!(decimal(0, &mut b), b"0");
        assert_eq!(decimal(1234567890, &mut b), b"1234567890");
        assert_eq!(percent_decode(b"a%20b%2F"), Some(b"a b/".to_vec()));
        assert_eq!(percent_decode(b"%2"), None);
    }

    #[test]
    fn ip_counts_match_a_hash_map_model() {
        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let mut t = IpCounts::default();
        let mut model: HashMap<IpAddr, u32> = HashMap::new();
        let mut x: u64 = 0x1234_5678;
        let mut live: Vec<IpAddr> = Vec::new();
        for step in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let ip = if x % 3 == 0 { IpAddr::V4(Ipv4Addr::from((x >> 8) as u32 % 700)) } else { IpAddr::V6(Ipv6Addr::from(u128::from((x >> 8) % 900) << 64 | 1)) };
            if x % 5 < 3 || live.is_empty() {
                let n = model.entry(ip).or_insert(0);
                let ok = t.take(ip, 3);
                assert_eq!(ok, *n < 3, "step {step}");
                if ok {
                    *n += 1;
                    live.push(ip);
                }
            } else {
                let ip = live.swap_remove((x >> 20) as usize % live.len());
                t.release(ip);
                let n = model.get_mut(&ip).unwrap();
                *n -= 1;
                if *n == 0 {
                    model.remove(&ip);
                }
            }
            if step % 997 == 0 {
                for (ip, n) in &model {
                    assert_eq!(t.count(*ip), *n);
                }
                assert_eq!(t.len, model.len());
            }
        }
        for ip in live {
            t.release(ip);
        }
        assert_eq!(t.len, 0);
        assert!(t.slots.iter().all(|e| e.1 == 0));
        // A cap of 1 refuses the second; another address is unaffected.
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(t.take(a, 1) && !t.take(a, 1) && t.take(b, 1));
    }

    #[test]
    fn head_timeouts_are_paced_per_loop() {
        // A thread of its own: the pacing state is per thread.
        std::thread::spawn(|| {
            let t = 1_000_000_000_000u64;
            let acts: Vec<HeadTimeout> = (0..100).map(|_| head_timeout_action(t)).collect();
            assert!(acts[..8].iter().all(|a| *a == HeadTimeout::Answer));
            assert!(acts[8..64].iter().all(|a| *a == HeadTimeout::Drop));
            assert!(acts[64..].iter().all(|a| matches!(a, HeadTimeout::Later(d) if (10_000_000..1_000_000_000).contains(d))));
            // The next window starts over.
            assert_eq!(head_timeout_action(t + 10_000_000), HeadTimeout::Answer);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn date_is_formatted() {
        let now = simoom_rt_now();
        with_date(now, |d| assert!(d.ends_with(b" GMT")));
        let mut v = Vec::new();
        date_line(now, &mut v);
        assert!(v.starts_with(b"date: ") && v.ends_with(b" GMT\r\n") && v.len() == 37, "{v:?}");
        for s in [200, 201, 204, 301, 302, 304, 400, 404, 500, 503, 418, 999] {
            let mut a = Vec::new();
            status_line(&mut a, s);
            let r = simoom_http1::write::reason(s);
            assert_eq!(a, format!("HTTP/1.1 {s} {r}\r\n").into_bytes());
        }
    }

    fn simoom_rt_now() -> u64 {
        std::time::Instant::now().elapsed().as_nanos() as u64 + 1
    }
}

#[cfg(feature = "guard")]
thread_local! {
    /// Replies outstanding on this loop thread and the bound from the limits (K5).
    static PENDING: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
    /// Connections that stopped reading because of the bound, to wake when it is met again.
    static PARKED: RefCell<Vec<simoom_rt::ConnHandle>> = const { RefCell::new(Vec::new()) };
    static ANY_PARKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One reply outstanding (deferred, offloaded) on this loop thread, for admission control
/// ([`crate::Limits::max_pending_per_loop`], K5). Held in the connection's per-request state,
/// which lives and dies on the loop thread, so the count is a plain thread-local.
#[cfg(feature = "guard")]
pub(crate) struct Pending(());

#[cfg(feature = "guard")]
impl Pending {
    #[inline]
    pub(crate) fn new(max: usize) -> Pending {
        PENDING.with(|c| {
            let (n, _) = c.get();
            c.set((n + 1, max));
        });
        Pending(())
    }
}

#[cfg(feature = "guard")]
impl Drop for Pending {
    #[inline]
    fn drop(&mut self) {
        let (n, max) = PENDING.with(|c| {
            let (n, max) = c.get();
            let n = n.saturating_sub(1);
            c.set((n, max));
            (n, max)
        });
        if ANY_PARKED.with(|p| p.get()) && n <= max - max / 4 {
            wake_parked();
        }
    }
}

/// Whether this loop thread has reached its bound of outstanding replies.
#[cfg(feature = "guard")]
#[inline]
pub(crate) fn over_pending() -> bool {
    let (n, max) = PENDING.with(|c| c.get());
    max != 0 && n >= max
}

/// Remembers a connection that stopped reading because of the bound.
#[cfg(feature = "guard")]
pub(crate) fn park(h: simoom_rt::ConnHandle) {
    PARKED.with(|p| p.borrow_mut().push(h));
    ANY_PARKED.with(|p| p.set(true));
}

/// Nudges every parked connection (a message it ignores; the callback re-checks its pause).
#[cfg(feature = "guard")]
#[cold]
#[inline(never)]
fn wake_parked() {
    ANY_PARKED.with(|p| p.set(false));
    let parked = PARKED.with(|p| std::mem::take(&mut *p.borrow_mut()));
    for h in parked {
        let env = crate::handle::Envelope { conn: 0, token: u64::MAX, msg: crate::handle::Msg::Dropped };
        h.send(Box::new(env));
    }
}


/// Without the `guard` feature: no admission bound (K5).
#[cfg(not(feature = "guard"))]
pub(crate) struct Pending;

#[cfg(not(feature = "guard"))]
impl Pending {
    #[inline(always)]
    pub(crate) fn new(_max: usize) -> Pending {
        Pending
    }
}

#[cfg(not(feature = "guard"))]
#[inline(always)]
pub(crate) fn over_pending() -> bool {
    false
}

#[cfg(not(feature = "guard"))]
#[inline(always)]
pub(crate) fn park(_h: simoom_rt::ConnHandle) {}
