//! HTTP dates (RFC 9110 §5.6.7): IMF-fixdate out; IMF-fixdate, RFC 850 and asctime in.
// cookies only format dates; parsing is for conditional requests
#![cfg_attr(not(feature = "conditional"), allow(dead_code))]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `t` as an IMF-fixdate, for example `Sun, 06 Nov 1994 08:49:37 GMT` (whole seconds; times
/// before 1970 are clamped to the epoch).
pub(crate) fn format(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT", DAYS[days.rem_euclid(7) as usize], d, MONTHS[m as usize - 1], y, rem / 3600, rem / 60 % 60, rem % 60)
}

fn month(s: &str) -> Option<u32> {
    MONTHS.iter().position(|&m| m.eq_ignore_ascii_case(s)).map(|i| i as u32 + 1)
}

fn hms(s: &str) -> Option<(u32, u32, u32)> {
    let mut p = s.split(':');
    let h = p.next()?.parse().ok()?;
    let m = p.next()?.parse().ok()?;
    let sec = p.next()?.parse().ok()?;
    if p.next().is_some() || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    Some((h, m, sec))
}

/// Parses an HTTP date in any of the three formats a recipient must accept.
pub(crate) fn parse(v: &[u8]) -> Option<SystemTime> {
    let s = std::str::from_utf8(v).ok()?.trim();
    let parts: Vec<&str> = s.split_whitespace().collect();
    let (y, m, d, t) = match parts.as_slice() {
        // Sun, 06 Nov 1994 08:49:37 GMT
        [_, d, mo, y, t, "GMT"] => (y.parse::<i64>().ok()?, month(mo)?, d.parse().ok()?, hms(t)?),
        // Sunday, 06-Nov-94 08:49:37 GMT
        [_, dmy, t, "GMT"] => {
            let mut p = dmy.split('-');
            let d = p.next()?.parse().ok()?;
            let mo = month(p.next()?)?;
            let yy: i64 = p.next()?.parse().ok()?;
            // two-digit years: within 50 years of now (RFC 9110 §5.6.7), approximated as 1970-2069
            (if yy < 70 { 2000 + yy } else if yy < 100 { 1900 + yy } else { yy }, mo, d, hms(t)?)
        }
        // Sun Nov  6 08:49:37 1994
        [_, mo, d, t, y] => (y.parse().ok()?, month(mo)?, d.parse().ok()?, hms(t)?),
        _ => return None,
    };
    if !(1..=31).contains(&d) || y < 1970 {
        return None;
    }
    let secs = days_from_civil(y, m, d) * 86_400 + (t.0 * 3600 + t.1 * 60 + t.2) as i64;
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Whole seconds since the epoch (HTTP dates have second resolution).
pub(crate) fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses() {
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(format(t), "Sun, 06 Nov 1994 08:49:37 GMT");
        for s in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
            assert_eq!(parse(s.as_bytes()), Some(t), "{s}");
        }
        for s in ["", "yesterday", "Sun, 06 Nov 1994 25:49:37 GMT", "Sun, 32 Nov 1994 08:49:37 GMT", "Sun, 06 Foo 1994 08:49:37 GMT"] {
            assert_eq!(parse(s.as_bytes()), None, "{s}");
        }
        assert_eq!(format(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(format(leap), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(parse(format(leap).as_bytes()), Some(leap));
    }
}
