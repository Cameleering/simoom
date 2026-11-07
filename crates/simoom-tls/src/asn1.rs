//! Minimal ASN.1 DER reader and writer (single-byte tags; definite lengths).

use std::fmt;

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_T61_STRING: u8 = 0x14;
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_UNIVERSAL_STRING: u8 = 0x1c;
pub const TAG_BMP_STRING: u8 = 0x1e;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerError(pub String);

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DER error: {}", self.0)
    }
}

impl std::error::Error for DerError {}

pub type DerResult<T> = Result<T, DerError>;

fn err<T>(msg: &str) -> DerResult<T> {
    Err(DerError(msg.to_string()))
}

/// One decoded TLV element.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    /// The complete encoding including tag and length.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Reader over the contents of a constructed element.
    pub fn reader(&self) -> Der<'a> {
        Der::new(self.value)
    }
}

/// Sequential reader over concatenated DER elements.
#[derive(Clone, Debug)]
pub struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    pub fn new(data: &'a [u8]) -> Der<'a> {
        Der { data, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub fn read(&mut self) -> DerResult<Tlv<'a>> {
        let start = self.pos;
        let d = self.data;
        if start + 2 > d.len() {
            return err("truncated element");
        }
        let tag = d[start];
        if tag & 0x1f == 0x1f {
            return err("multi-byte tags not supported");
        }
        let mut p = start + 1;
        let first = d[p];
        p += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return err("unsupported length encoding");
            }
            if p + n > d.len() {
                return err("truncated length");
            }
            let mut l = 0usize;
            for i in 0..n {
                l = (l << 8) | d[p + i] as usize;
            }
            p += n;
            l
        };
        if p + len > d.len() {
            return err("element exceeds input");
        }
        self.pos = p + len;
        Ok(Tlv { tag, value: &d[p..p + len], raw: &d[start..p + len] })
    }

    /// Reads an element and checks its tag.
    pub fn expect(&mut self, tag: u8) -> DerResult<Tlv<'a>> {
        let t = self.read()?;
        if t.tag != tag {
            return Err(DerError(format!("expected tag {:#04x}, found {:#04x}", tag, t.tag)));
        }
        Ok(t)
    }

    /// Reads the element only if the next tag matches.
    pub fn optional(&mut self, tag: u8) -> DerResult<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.read()?))
        } else {
            Ok(None)
        }
    }

    pub fn sequence(&mut self) -> DerResult<Der<'a>> {
        Ok(self.expect(TAG_SEQUENCE)?.reader())
    }

    pub fn oid(&mut self) -> DerResult<String> {
        decode_oid(self.expect(TAG_OID)?.value)
    }

    /// INTEGER as unsigned big-endian bytes (leading zero stripped); rejects negatives.
    pub fn uint(&mut self) -> DerResult<&'a [u8]> {
        let v = self.expect(TAG_INTEGER)?.value;
        if v.is_empty() {
            return err("empty integer");
        }
        if v[0] & 0x80 != 0 {
            return err("negative integer");
        }
        let mut s = v;
        while s.len() > 1 && s[0] == 0 {
            s = &s[1..];
        }
        Ok(s)
    }

    pub fn small_uint(&mut self) -> DerResult<u64> {
        let v = self.uint()?;
        if v.len() > 8 {
            return err("integer too large");
        }
        Ok(v.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
    }

    pub fn octet_string(&mut self) -> DerResult<&'a [u8]> {
        Ok(self.expect(TAG_OCTET_STRING)?.value)
    }

    /// BIT STRING contents; requires zero unused bits.
    pub fn bit_string(&mut self) -> DerResult<&'a [u8]> {
        let v = self.expect(TAG_BIT_STRING)?.value;
        if v.is_empty() || v[0] != 0 {
            return err("bit string with unused bits");
        }
        Ok(&v[1..])
    }
}

pub fn decode_oid(v: &[u8]) -> DerResult<String> {
    if v.is_empty() {
        return err("empty OID");
    }
    let mut arcs: Vec<u64> = Vec::new();
    let mut cur: u64 = 0;
    for (i, b) in v.iter().enumerate() {
        if cur > (u64::MAX >> 7) {
            return err("OID arc too large");
        }
        cur = (cur << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, b2) = if cur < 40 {
                    (0, cur)
                } else if cur < 80 {
                    (1, cur - 40)
                } else {
                    (2, cur - 80)
                };
                arcs.push(a);
                arcs.push(b2);
            } else {
                arcs.push(cur);
            }
            cur = 0;
        } else if i == v.len() - 1 {
            return err("truncated OID");
        }
    }
    Ok(arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("."))
}

pub fn encode_oid(oid: &str) -> Vec<u8> {
    let arcs: Vec<u64> = oid.split('.').map(|a| a.parse().expect("bad OID")).collect();
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        out.extend(tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    out
}

/// Decodes an ASN.1 string type to UTF-8 (lossy for odd encodings).
pub fn decode_string(tlv: &Tlv) -> Option<String> {
    match tlv.tag {
        TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING => Some(String::from_utf8_lossy(tlv.value).into_owned()),
        TAG_T61_STRING => Some(tlv.value.iter().map(|b| *b as char).collect()),
        TAG_BMP_STRING => {
            let units: Vec<u16> = tlv.value.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
            Some(String::from_utf16_lossy(&units))
        }
        TAG_UNIVERSAL_STRING => Some(
            tlv.value
                .chunks(4)
                .filter_map(|c| if c.len() == 4 { char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])) } else { None })
                .collect(),
        ),
        _ => None,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// (year, month, day) for days since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parses UTCTime / GeneralizedTime (Z form) to Unix seconds.
pub fn parse_time(tlv: &Tlv) -> DerResult<i64> {
    let s = std::str::from_utf8(tlv.value).map_err(|_| DerError("bad time".into()))?;
    let digits = |r: std::ops::Range<usize>| -> DerResult<i64> {
        s.get(r).and_then(|x| if x.bytes().all(|c| c.is_ascii_digit()) { x.parse().ok() } else { None }).ok_or(DerError("bad time digits".into()))
    };
    let (year, rest) = match tlv.tag {
        TAG_UTC_TIME => {
            let yy = digits(0..2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        TAG_GENERALIZED_TIME => (digits(0..4)?, 4),
        _ => return err("not a time"),
    };
    let mon = digits(rest..rest + 2)?;
    let day = digits(rest + 2..rest + 4)?;
    let hour = digits(rest + 4..rest + 6)?;
    let min = digits(rest + 6..rest + 8)?;
    let sec = if s.len() > rest + 8 && s.as_bytes()[rest + 8].is_ascii_digit() { digits(rest + 8..rest + 10)? } else { 0 };
    if !s.ends_with('Z') || !(1..=12).contains(&mon) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return err("unsupported time format");
    }
    Ok(days_from_civil(year, mon as u32, day as u32) * 86400 + hour * 3600 + min * 60 + sec)
}

// ------------------------------------------------------------------ writer

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &parts.concat())
}

pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SET, &parts.concat())
}

/// INTEGER from unsigned big-endian bytes.
pub fn uint(bytes: &[u8]) -> Vec<u8> {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let mut c = Vec::new();
    if b.is_empty() || b[0] & 0x80 != 0 {
        c.push(0);
    }
    c.extend_from_slice(b);
    tlv(TAG_INTEGER, &c)
}

pub fn oid(o: &str) -> Vec<u8> {
    tlv(TAG_OID, &encode_oid(o))
}

pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut c = vec![0u8];
    c.extend_from_slice(bytes);
    tlv(TAG_BIT_STRING, &c)
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, bytes)
}

/// Context-specific constructed tag `[n]`.
pub fn explicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// UTCTime for years 1950..2049, GeneralizedTime otherwise.
pub fn time(unix: i64) -> Vec<u8> {
    let days = unix.div_euclid(86400);
    let secs = unix.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs / 60) % 60, secs % 60);
    if (1950..2050).contains(&y) {
        tlv(TAG_UTC_TIME, format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, m, d, hh, mm, ss).as_bytes())
    } else {
        tlv(TAG_GENERALIZED_TIME, format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", y, m, d, hh, mm, ss).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        for o in ["1.2.840.113549.1.1.11", "2.5.29.17", "1.3.6.1.5.5.7.3.1", "1.2.840.10045.3.1.7", "2.999.3"] {
            assert_eq!(decode_oid(&encode_oid(o)).unwrap(), o);
        }
        assert_eq!(encode_oid("1.2.840.113549"), vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]);
    }

    #[test]
    fn dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        for z in [-1000i64, 0, 11016, 11017, 19000, 47482, 2932896] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        let t = time(1_700_000_000);
        let tl = Der::new(&t).read().unwrap();
        assert_eq!(parse_time(&tl).unwrap(), 1_700_000_000);
        let t = time(4_102_444_800 + 5); // 2100-01-01
        let tl = Der::new(&t).read().unwrap();
        assert_eq!(tl.tag, TAG_GENERALIZED_TIME);
        assert_eq!(parse_time(&tl).unwrap(), 4_102_444_805);
    }

    #[test]
    fn integers_and_lengths() {
        let big = vec![0xffu8; 300];
        let enc = uint(&big);
        let mut r = Der::new(&enc);
        assert_eq!(r.uint().unwrap(), &big[..]);
        assert!(r.is_empty());
        assert_eq!(uint(&[0x7f]), vec![2, 1, 0x7f]);
        assert_eq!(uint(&[0x80]), vec![2, 2, 0, 0x80]);
        assert!(Der::new(&[0x30, 0x05, 0x01]).read().is_err());
    }
}
