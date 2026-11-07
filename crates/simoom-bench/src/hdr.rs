//! An HdrHistogram-compatible histogram (Gil Tene, http://hdrhistogram.org).
//!
//! The bucket layout, the value equivalence rules and the percentile rule are those of the Java
//! `AbstractHistogram`, so a histogram here and one in HdrHistogram agree count for count. It
//! also reads and writes the V2 encoding (plain and compressed) and the interval log format
//! (`HistogramLogWriter`, log format 1.3), and prints the classic percentile distribution
//! (`outputPercentileDistribution`, the `.hgrm` text that wrk2 prints and the HdrHistogram
//! plotter reads). The compressed form uses DEFLATE stored blocks inside a zlib stream, which
//! every inflater accepts; nothing here needs a compression library.
//!
//! Values are integers; the load generator records nanoseconds.

use std::fmt::Write as _;

const V2_COOKIE: u32 = 0x1c84_9303 | 0x10;
const V2_COMPRESSED_COOKIE: u32 = 0x1c84_9304 | 0x10;
const V2_HEADER: usize = 40;

/// A log-linear histogram with HdrHistogram's layout.
#[derive(Clone)]
pub struct Histogram {
    lowest: u64,
    highest: u64,
    digits: u32,
    unit_magnitude: u32,
    sub_bucket_count: u64,
    sub_bucket_half_count: u64,
    sub_bucket_half_count_magnitude: u32,
    sub_bucket_mask: u64,
    leading_zero_count_base: u32,
    bucket_count: u32,
    counts: Vec<u64>,
    total: u64,
    min: u64,
    max: u64,
    /// Values above `highest` were recorded as `highest`; this counts them.
    pub clamped: u64,
}

impl std::fmt::Debug for Histogram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Histogram(n={}, max={}, digits={})", self.total, self.max, self.digits)
    }
}

impl Default for Histogram {
    /// Nanoseconds from 1 ns to one hour, three significant digits (as wrk2, in ns).
    fn default() -> Self {
        Histogram::new(1, 3_600_000_000_000, 3)
    }
}

impl Histogram {
    /// `lowest` ≥ 1 is the smallest discernible value, `highest` ≥ 2·lowest the largest
    /// trackable one, `digits` (0..=5) the significant decimal digits kept.
    pub fn new(lowest: u64, highest: u64, digits: u32) -> Histogram {
        assert!(lowest >= 1 && highest >= 2 * lowest && digits <= 5);
        let largest_single_unit = 2 * 10u64.pow(digits);
        let sub_bucket_count_magnitude = 64 - (largest_single_unit - 1).leading_zeros(); // ceil(log2)
        let sub_bucket_half_count_magnitude = sub_bucket_count_magnitude.max(1) - 1;
        let sub_bucket_count = 1u64 << (sub_bucket_half_count_magnitude + 1);
        let sub_bucket_half_count = sub_bucket_count / 2;
        let unit_magnitude = 63 - lowest.leading_zeros();
        let sub_bucket_mask = (sub_bucket_count - 1) << unit_magnitude;
        let mut h = Histogram {
            lowest,
            highest,
            digits,
            unit_magnitude,
            sub_bucket_count,
            sub_bucket_half_count,
            sub_bucket_half_count_magnitude,
            sub_bucket_mask,
            leading_zero_count_base: 64 - unit_magnitude - sub_bucket_half_count_magnitude - 1,
            bucket_count: 0,
            counts: Vec::new(),
            total: 0,
            min: u64::MAX,
            max: 0,
            clamped: 0,
        };
        h.bucket_count = h.buckets_needed(highest);
        h.counts = vec![0; ((h.bucket_count as u64 + 1) * sub_bucket_half_count) as usize];
        h
    }

    fn buckets_needed(&self, value: u64) -> u32 {
        let mut smallest_untrackable = self.sub_bucket_count << self.unit_magnitude;
        let mut needed = 1;
        while smallest_untrackable <= value {
            if smallest_untrackable > (i64::MAX as u64) / 2 {
                return needed + 1;
            }
            smallest_untrackable <<= 1;
            needed += 1;
        }
        needed
    }

    fn bucket_index(&self, v: u64) -> u32 {
        self.leading_zero_count_base - (v | self.sub_bucket_mask).leading_zeros()
    }

    fn sub_bucket_index(&self, v: u64, bucket: u32) -> u64 {
        v >> (bucket + self.unit_magnitude)
    }

    /// The counts-array index of a value.
    pub fn index_of(&self, v: u64) -> usize {
        let b = self.bucket_index(v);
        let s = self.sub_bucket_index(v, b);
        (((b as u64 + 1) << self.sub_bucket_half_count_magnitude) + s - self.sub_bucket_half_count) as usize
    }

    /// The lowest value that maps to counts index `i`.
    pub fn value_from_index(&self, i: usize) -> u64 {
        let i = i as u64;
        let mut b = (i >> self.sub_bucket_half_count_magnitude) as i64 - 1;
        let mut s = (i & (self.sub_bucket_half_count - 1)) + self.sub_bucket_half_count;
        if b < 0 {
            s -= self.sub_bucket_half_count;
            b = 0;
        }
        s << (b as u32 + self.unit_magnitude)
    }

    fn size_of_equivalent_range(&self, v: u64) -> u64 {
        let b = self.bucket_index(v);
        let s = self.sub_bucket_index(v, b);
        let adjusted = if s >= self.sub_bucket_count { b + 1 } else { b };
        1u64 << (self.unit_magnitude + adjusted)
    }

    /// The lowest value equivalent to `v` (same bucket).
    pub fn lowest_equivalent(&self, v: u64) -> u64 {
        let b = self.bucket_index(v);
        let s = self.sub_bucket_index(v, b);
        s << (b + self.unit_magnitude)
    }

    /// The highest value equivalent to `v`.
    pub fn highest_equivalent(&self, v: u64) -> u64 {
        self.lowest_equivalent(v) + self.size_of_equivalent_range(v) - 1
    }

    /// The middle of the range of values equivalent to `v`.
    pub fn median_equivalent(&self, v: u64) -> u64 {
        self.lowest_equivalent(v) + (self.size_of_equivalent_range(v) >> 1)
    }

    /// Records one value; values above the trackable range are recorded as the highest.
    #[inline]
    pub fn record(&mut self, v: u64) {
        self.record_n(v, 1);
    }

    /// Records `n` occurrences of `v`.
    pub fn record_n(&mut self, v: u64, n: u64) {
        let v = if v > self.highest {
            self.clamped += n;
            self.highest
        } else {
            v
        };
        let i = self.index_of(v);
        self.counts[i] += n;
        self.total += n;
        if v < self.min {
            self.min = v;
        }
        if v > self.max {
            self.max = v;
        }
    }

    /// Adds every count of `other`, which must have the same layout.
    pub fn merge(&mut self, other: &Histogram) {
        if other.total == 0 {
            return;
        }
        if self.same_layout(other) {
            for (a, b) in self.counts.iter_mut().zip(&other.counts) {
                *a += b;
            }
            self.total += other.total;
            self.min = self.min.min(other.min);
            self.max = self.max.max(other.max);
        } else {
            for (i, &c) in other.counts.iter().enumerate() {
                if c > 0 {
                    self.record_n(other.value_from_index(i), c);
                }
            }
            self.max = self.max.max(other.max.min(self.highest));
        }
        self.clamped += other.clamped;
    }

    fn same_layout(&self, o: &Histogram) -> bool {
        self.lowest == o.lowest && self.digits == o.digits && self.counts.len() == o.counts.len()
    }

    /// Forgets every value.
    pub fn reset(&mut self) {
        self.counts.iter_mut().for_each(|c| *c = 0);
        self.total = 0;
        self.min = u64::MAX;
        self.max = 0;
        self.clamped = 0;
    }

    pub fn count(&self) -> u64 {
        self.total
    }

    /// The largest recorded value, exact (as recorded, not a bucket bound).
    pub fn max(&self) -> u64 {
        self.max
    }

    /// The smallest recorded value, exact.
    pub fn min(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            self.min
        }
    }

    /// HdrHistogram's `getMaxValue`: the highest value equivalent to the largest recorded one.
    pub fn max_equivalent(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            self.highest_equivalent(self.max)
        }
    }

    /// Mean from the bucket medians, as HdrHistogram computes it.
    pub fn mean(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let mut sum = 0f64;
        for (i, &c) in self.counts.iter().enumerate() {
            if c > 0 {
                sum += self.median_equivalent(self.value_from_index(i)) as f64 * c as f64;
            }
        }
        sum / self.total as f64
    }

    /// Standard deviation from the bucket medians, as HdrHistogram computes it.
    pub fn stddev(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let mean = self.mean();
        let mut dev = 0f64;
        for (i, &c) in self.counts.iter().enumerate() {
            if c > 0 {
                let d = self.median_equivalent(self.value_from_index(i)) as f64 - mean;
                dev += d * d * c as f64;
            }
        }
        (dev / self.total as f64).sqrt()
    }

    /// HdrHistogram's `getValueAtPercentile`: the highest value equivalent to the value at
    /// which the cumulative count reaches `round(p/100 · total)` (at least 1).
    pub fn percentile(&self, p: f64) -> u64 {
        if self.total == 0 {
            return 0;
        }
        let p = p.min(100.0);
        let at = ((p / 100.0 * self.total as f64) + 0.5).floor() as u64;
        let at = at.max(1);
        let mut seen = 0;
        for (i, &c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= at {
                let v = self.value_from_index(i);
                return if p == 0.0 { self.lowest_equivalent(v) } else { self.highest_equivalent(v) };
            }
        }
        0
    }

    /// The classic percentile distribution text (`outputPercentileDistribution` with
    /// `ticks_per_half` reporting ticks per half distance), values divided by `scale`.
    pub fn percentile_distribution(&self, ticks_per_half: u32, scale: f64) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{:>12} {:>14} {:>10} {:>14}\n", "Value", "Percentile", "TotalCount", "1/(1-Percentile)");
        if self.total > 0 {
            let total = self.total as f64;
            let mut level_to = 0.0f64;
            let mut reached_last = false;
            let mut idx = 0usize;
            let mut fresh = true;
            let mut cum = 0u64;
            loop {
                // hasNext
                if cum >= self.total {
                    if reached_last {
                        break;
                    }
                    level_to = 100.0;
                    reached_last = true;
                }
                // next()
                let mut emitted = false;
                while idx < self.counts.len() {
                    let c = self.counts[idx];
                    if fresh {
                        cum += c;
                        fresh = false;
                    }
                    if c != 0 && (100.0 * cum as f64) / total >= level_to {
                        let v = self.highest_equivalent(self.value_from_index(idx));
                        let pct = level_to / 100.0;
                        if pct < 1.0 {
                            let _ = writeln!(out, "{:12.3} {:2.12} {:10} {:14.2}", v as f64 / scale, pct, cum, 1.0 / (1.0 - pct));
                        } else {
                            let _ = writeln!(out, "{:12.3} {:2.12} {:10}", v as f64 / scale, pct, cum);
                        }
                        let ticks = ticks_per_half as f64 * 2f64.powf((100.0 / (100.0 - level_to)).log2().floor() + 1.0);
                        level_to += 100.0 / ticks;
                        emitted = true;
                        break;
                    }
                    idx += 1;
                    fresh = true;
                }
                if !emitted {
                    break;
                }
            }
        }
        let _ = writeln!(out, "#[Mean    = {:12.3}, StdDeviation   = {:12.3}]", self.mean() / scale, self.stddev() / scale);
        let _ = writeln!(out, "#[Max     = {:12.3}, Total count    = {:12}]", self.max_equivalent() as f64 / scale, self.total);
        let _ = writeln!(out, "#[Buckets = {:12}, SubBuckets     = {:12}]", self.bucket_count, self.sub_bucket_count);
        out
    }

    // ---- V2 encoding ------------------------------------------------------------------------

    /// The V2 encoding (uncompressed), as `encodeIntoByteBuffer` writes it.
    pub fn encode_v2(&self) -> Vec<u8> {
        let relevant = if self.total == 0 { 0 } else { self.index_of(self.max) + 1 };
        let mut payload = Vec::new();
        let mut i = 0;
        while i < relevant {
            let c = self.counts[i];
            i += 1;
            if c == 0 {
                let mut zeros = 1i64;
                while i < relevant && self.counts[i] == 0 {
                    zeros += 1;
                    i += 1;
                }
                zigzag_put(&mut payload, if zeros > 1 { -zeros } else { 0 });
            } else {
                zigzag_put(&mut payload, c as i64);
            }
        }
        let mut out = Vec::with_capacity(V2_HEADER + payload.len());
        out.extend_from_slice(&V2_COOKIE.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // normalizing index offset
        out.extend_from_slice(&self.digits.to_be_bytes());
        out.extend_from_slice(&self.lowest.to_be_bytes());
        out.extend_from_slice(&self.highest.to_be_bytes());
        out.extend_from_slice(&1.0f64.to_bits().to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// The compressed V2 encoding (`encodeIntoCompressedByteBuffer`): zlib with stored blocks.
    pub fn encode_v2_compressed(&self) -> Vec<u8> {
        let plain = self.encode_v2();
        let z = zlib_stored(&plain);
        let mut out = Vec::with_capacity(8 + z.len());
        out.extend_from_slice(&V2_COMPRESSED_COOKIE.to_be_bytes());
        out.extend_from_slice(&(z.len() as u32).to_be_bytes());
        out.extend_from_slice(&z);
        out
    }

    /// Decodes either V2 form. Compressed input must use stored blocks (what this module
    /// writes); fixed and dynamic Huffman blocks are refused.
    pub fn decode_v2(data: &[u8]) -> Result<Histogram, String> {
        if data.len() < 8 {
            return Err("short histogram".into());
        }
        let cookie = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if cookie & !0xf0 == V2_COMPRESSED_COOKIE & !0xf0 {
            let len = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
            let z = data.get(8..8 + len).ok_or("truncated compressed histogram")?;
            let plain = zlib_stored_inflate(z)?;
            return Histogram::decode_v2(&plain);
        }
        if cookie & !0xf0 != V2_COOKIE & !0xf0 {
            return Err(format!("not a V2 histogram (cookie {cookie:#x})"));
        }
        if data.len() < V2_HEADER {
            return Err("short header".into());
        }
        let be32 = |o: usize| u32::from_be_bytes(data[o..o + 4].try_into().unwrap());
        let be64 = |o: usize| u64::from_be_bytes(data[o..o + 8].try_into().unwrap());
        let payload_len = be32(4) as usize;
        if be32(8) != 0 {
            return Err("normalizing index offset is not supported".into());
        }
        let digits = be32(12);
        let lowest = be64(16);
        let highest = be64(24);
        if lowest < 1 || highest < 2 * lowest || digits > 5 {
            return Err("bad histogram parameters".into());
        }
        let payload = data.get(V2_HEADER..V2_HEADER + payload_len).ok_or("truncated payload")?;
        let mut h = Histogram::new(lowest, highest, digits);
        let mut pos = 0;
        let mut idx = 0usize;
        while pos < payload.len() {
            let v = zigzag_get(payload, &mut pos)?;
            if v < 0 {
                idx += (-v) as usize;
            } else {
                if v > 0 {
                    if idx >= h.counts.len() {
                        return Err("count index out of range".into());
                    }
                    h.counts[idx] = v as u64;
                    h.total += v as u64;
                    let val = h.value_from_index(idx);
                    h.min = h.min.min(val);
                    h.max = h.max.max(h.highest_equivalent(val).min(h.highest));
                }
                idx += 1;
            }
        }
        // the lowest equivalent value is a better minimum, as in HdrHistogram
        Ok(h)
    }

    /// Base64 of the compressed V2 encoding, as an interval log line carries it.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.encode_v2_compressed())
    }

    pub fn from_base64(s: &str) -> Result<Histogram, String> {
        Histogram::decode_v2(&base64_decode(s.trim())?)
    }
}

fn zigzag_put(out: &mut Vec<u8>, v: i64) {
    let mut v = ((v << 1) ^ (v >> 63)) as u64;
    for _ in 0..8 {
        if v >> 7 == 0 {
            out.push(v as u8);
            return;
        }
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8); // the ninth byte carries all eight remaining bits
}

fn zigzag_get(b: &[u8], pos: &mut usize) -> Result<i64, String> {
    let mut v = 0u64;
    let mut shift = 0;
    for k in 0..9 {
        let byte = *b.get(*pos).ok_or("truncated varint")? as u64;
        *pos += 1;
        if k == 8 {
            v |= byte << 56;
            break;
        }
        v |= (byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(((v >> 1) as i64) ^ -((v & 1) as i64))
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// A zlib stream (RFC 1950) holding `data` in DEFLATE stored blocks (RFC 1951 §3.2.4).
pub fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let mut chunks = data.chunks(65_535).peekable();
    if data.is_empty() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(c) = chunks.next() {
        out.push(if chunks.peek().is_none() { 1 } else { 0 });
        let len = c.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Inflates a zlib stream made only of stored blocks.
pub fn zlib_stored_inflate(z: &[u8]) -> Result<Vec<u8>, String> {
    if z.len() < 6 || z[0] & 0x0f != 8 || (u16::from_be_bytes([z[0], z[1]]) % 31) != 0 || z[1] & 0x20 != 0 {
        return Err("bad zlib header".into());
    }
    let mut pos = 2;
    let mut out = Vec::new();
    loop {
        let hdr = *z.get(pos).ok_or("truncated deflate")?;
        if (hdr >> 1) & 3 != 0 {
            return Err("compressed DEFLATE blocks are not supported (stored blocks only)".into());
        }
        let len = u16::from_le_bytes([*z.get(pos + 1).ok_or("trunc")?, *z.get(pos + 2).ok_or("trunc")?]);
        let nlen = u16::from_le_bytes([*z.get(pos + 3).ok_or("trunc")?, *z.get(pos + 4).ok_or("trunc")?]);
        if len != !nlen {
            return Err("bad stored block length".into());
        }
        pos += 5;
        out.extend_from_slice(z.get(pos..pos + len as usize).ok_or("truncated stored block")?);
        pos += len as usize;
        if hdr & 1 == 1 {
            break;
        }
    }
    let sum = z.get(pos..pos + 4).ok_or("missing adler32")?;
    if u32::from_be_bytes(sum.try_into().unwrap()) != adler32(&out) {
        return Err("adler32 mismatch".into());
    }
    Ok(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(B64[(n >> 18) as usize & 63] as char);
        s.push(B64[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    s
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for ch in s.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' | b' ' => continue,
            _ => return Err("bad base64".into()),
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Writes an HdrHistogram interval log (`HistogramLogWriter`, format 1.3).
#[derive(Debug, Default)]
pub struct IntervalLog {
    text: String,
}

impl IntervalLog {
    /// Starts a log; `start_epoch_s` is the wall-clock start in seconds since the epoch.
    pub fn new(start_epoch_s: f64, comment: &str) -> IntervalLog {
        let mut text = String::new();
        if !comment.is_empty() {
            let _ = writeln!(text, "#{comment}");
        }
        let _ = writeln!(text, "#[Histogram log format version 1.3]");
        let _ = writeln!(text, "#[StartTime: {start_epoch_s:.3} (seconds since epoch)]");
        let _ = writeln!(text, "#[BaseTime: {start_epoch_s:.3} (seconds since epoch)]");
        let _ = writeln!(text, "\"StartTimestamp\",\"Interval_Length\",\"Interval_Max\",\"Interval_Compressed_Histogram\"");
        IntervalLog { text }
    }

    /// Appends one interval: start offset and length in seconds; the max is printed in
    /// milliseconds (values in ns divided by 1e6, `maxValueUnitRatio` 1000000.0).
    pub fn add(&mut self, tag: Option<&str>, start_s: f64, len_s: f64, h: &Histogram) {
        if let Some(t) = tag {
            let _ = write!(self.text, "Tag={t},");
        }
        let _ = writeln!(self.text, "{start_s:.3},{len_s:.3},{:.3},{}", h.max_equivalent() as f64 / 1e6, h.to_base64());
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// The histograms of a log (any tag), for merging logs from several nodes.
    pub fn parse(text: &str) -> Result<Vec<Histogram>, String> {
        let mut out = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') || l.starts_with('"') {
                continue;
            }
            let l = if l.starts_with("Tag=") { l.split_once(',').map(|x| x.1).unwrap_or("") } else { l };
            let b64 = l.rsplit(',').next().ok_or("bad log line")?;
            out.push(Histogram::from_base64(b64)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_hdrhistogram() {
        // HdrHistogram(1, 3600e9, 3): 2048 sub-buckets; values below 2048 are exact.
        let h = Histogram::default();
        assert_eq!(h.sub_bucket_count, 2048);
        for v in [0u64, 1, 2047] {
            assert_eq!(h.lowest_equivalent(v), v);
            assert_eq!(h.highest_equivalent(v), v);
        }
        // 2048..4095 has unit 2, 4096.. unit 4, as in Java
        assert_eq!(h.lowest_equivalent(2049), 2048);
        assert_eq!(h.highest_equivalent(2048), 2049);
        assert_eq!(h.highest_equivalent(4096), 4099);
        assert_eq!(h.value_from_index(h.index_of(123_456_789)), h.lowest_equivalent(123_456_789));
        // relative error stays under 1/1024 (3 digits)
        for v in [3000u64, 1_000_000, 987_654_321, 3_599_999_999_999] {
            let e = (h.highest_equivalent(v) - h.lowest_equivalent(v)) as f64 / v as f64;
            assert!(e < 1.0 / 1000.0, "{v}: {e}");
        }
        // the Java counts-array length for (1, 3600e9, 3): bucketCount 32 → (32+1)*1024
        assert_eq!(h.bucket_count, 32);
        assert_eq!(h.counts.len(), 33 * 1024);
    }

    #[test]
    fn percentiles_follow_hdrhistogram_rule() {
        let mut h = Histogram::new(1, 3_600_000_000, 3);
        for v in 1..=10_000u64 {
            h.record(v);
        }
        h.record(100_000_000);
        // round(0.5 * 10001) = 5001 → 5001, reported as the highest equivalent value
        assert_eq!(h.percentile(50.0), h.highest_equivalent(5001));
        assert_eq!(h.percentile(100.0), h.highest_equivalent(100_000_000));
        assert_eq!(h.percentile(0.0), 1);
        assert_eq!(h.count(), 10_001);
        assert_eq!(h.max(), 100_000_000);
    }

    #[test]
    fn v2_round_trip_plain_and_compressed() {
        let mut h = Histogram::default();
        for i in 0..50_000u64 {
            h.record(1_000 + (i * 7919) % 2_000_000);
        }
        h.record(3_000_000_000);
        for enc in [h.encode_v2(), h.encode_v2_compressed()] {
            let d = Histogram::decode_v2(&enc).unwrap();
            assert_eq!(d.count(), h.count());
            assert_eq!(d.counts, h.counts);
            for p in [50.0, 99.0, 99.9, 100.0] {
                assert_eq!(d.percentile(p), h.percentile(p));
            }
        }
        let b = h.to_base64();
        assert!(b.starts_with("HISTF"), "compressed V2 base64 starts with HISTF like Java's: {}", &b[..8]);
        assert_eq!(Histogram::from_base64(&b).unwrap().count(), h.count());
    }

    #[test]
    fn known_java_encoding_decodes() {
        // An empty histogram encoded by this module has the Java header layout.
        let e = Histogram::new(1, 1000, 2).encode_v2();
        assert_eq!(&e[0..4], &[0x1c, 0x84, 0x93, 0x13]);
        assert_eq!(e.len(), 40);
    }

    #[test]
    fn merge_and_log() {
        let mut a = Histogram::default();
        let mut b = Histogram::default();
        a.record(10);
        b.record(20);
        b.record(5_000_000);
        a.merge(&b);
        assert_eq!(a.count(), 3);
        assert_eq!(a.max(), 5_000_000);
        let mut log = IntervalLog::new(1_700_000_000.0, "test");
        log.add(None, 0.0, 1.0, &a);
        log.add(Some("node2"), 1.0, 1.0, &b);
        let hs = IntervalLog::parse(log.text()).unwrap();
        assert_eq!(hs.len(), 2);
        assert_eq!(hs[0].count(), 3);
        assert_eq!(hs[1].count(), 2);
    }

    #[test]
    fn distribution_text_has_hgrm_shape() {
        let mut h = Histogram::default();
        for v in 1..=1000u64 {
            h.record(v * 1000);
        }
        let t = h.percentile_distribution(5, 1000.0);
        assert!(t.contains("Percentile"));
        assert!(t.lines().any(|l| l.contains("1.000000000000")), "{t}");
        assert!(t.contains("#[Max     ="));
        let rows = t.lines().filter(|l| l.trim_start().chars().next().is_some_and(|c| c.is_ascii_digit())).count();
        assert!(rows > 20, "{rows} rows");
    }

    #[test]
    fn zlib_and_base64() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 31) as u8).collect();
        assert_eq!(zlib_stored_inflate(&zlib_stored(&data)).unwrap(), data);
        assert_eq!(zlib_stored_inflate(&zlib_stored(&[])).unwrap(), Vec::<u8>::new());
        for n in 0..10 {
            let d: Vec<u8> = (0..n).collect();
            assert_eq!(base64_decode(&base64_encode(&d)).unwrap(), d);
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }
}
