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

/// `HTTP/1.1 <status> <reason>\r\n`.
pub(crate) fn status_line(out: &mut Vec<u8>, status: u16) {
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
}

thread_local! {
    static DATE: RefCell<Option<DateState>> = const { RefCell::new(None) };
}

fn wall_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

/// Calls `f` with the IMF-fixdate for the loop clock `now_ns` (monotonic). The wall clock is
/// sampled once a minute per thread; formatting happens once a second.
pub(crate) fn with_date<R>(now_ns: u64, f: impl FnOnce(&[u8; 29]) -> R) -> R {
    DATE.with(|d| {
        let mut d = d.borrow_mut();
        let st = match d.as_mut() {
            Some(st) if now_ns.wrapping_sub(st.mono_base) < 60_000_000_000 => st,
            _ => {
                let wall = wall_ns();
                d.insert(DateState { mono_base: now_ns, wall_base: wall, secs: u64::MAX, bytes: [b' '; 29] })
            }
        };
        let secs = (st.wall_base + now_ns.saturating_sub(st.mono_base)) / 1_000_000_000;
        if secs != st.secs {
            st.secs = secs;
            st.bytes = simoom_http1::write::http_date(secs);
        }
        f(&st.bytes)
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
    fn date_is_formatted() {
        let now = simoom_rt_now();
        with_date(now, |d| assert!(d.ends_with(b" GMT")));
    }

    fn simoom_rt_now() -> u64 {
        std::time::Instant::now().elapsed().as_nanos() as u64 + 1
    }
}
