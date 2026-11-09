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

fn wall_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

fn date_state<R>(now_ns: u64, f: impl FnOnce(&DateState) -> R) -> R {
    DATE.with(|d| {
        let mut d = d.borrow_mut();
        let st = match d.as_mut() {
            Some(st) if now_ns.wrapping_sub(st.mono_base) < 60_000_000_000 => st,
            _ => {
                let wall = wall_ns();
                d.insert(DateState { mono_base: now_ns, wall_base: wall, secs: u64::MAX, bytes: [b' '; 29], line: [b' '; 37] })
            }
        };
        let secs = (st.wall_base + now_ns.saturating_sub(st.mono_base)) / 1_000_000_000;
        if secs != st.secs {
            st.secs = secs;
            st.bytes = simoom_http1::write::http_date(secs);
            st.line[..6].copy_from_slice(b"date: ");
            st.line[6..35].copy_from_slice(&st.bytes);
            st.line[35..].copy_from_slice(b"\r\n");
        }
        f(st)
    })
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
