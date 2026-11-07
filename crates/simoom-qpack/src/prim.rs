//! Static table (RFC 9204 Appendix A), prefixed integers and string literals.

use crate::huffman;

/// The QPACK static table, 99 entries (RFC 9204 Appendix A).
pub static STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Finds `(exact match, name match)` indexes in the static table.
pub(crate) fn static_find(name: &[u8], value: &[u8]) -> (Option<u8>, Option<u8>) {
    let mut name_idx = None;
    for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
        if n.len() == name.len() && n.as_bytes() == name {
            if v.as_bytes() == value {
                return (Some(i as u8), Some(i as u8));
            }
            name_idx.get_or_insert(i as u8);
        }
    }
    (None, name_idx)
}

/// Parse failure: more bytes needed, or the input is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Short {
    Incomplete,
    Invalid,
}

/// Largest integer QPACK accepts (62 bits, the QUIC varint range).
pub const MAX_INT: u64 = (1 << 62) - 1;

/// Decodes an `n`-bit prefixed integer (RFC 7541 5.1) at `*pos`, rejecting values over 62 bits.
pub(crate) fn get_int(buf: &[u8], pos: &mut usize, n: u8) -> Result<u64, Short> {
    let b = *buf.get(*pos).ok_or(Short::Incomplete)?;
    *pos += 1;
    let max = (1u64 << n) - 1;
    let mut v = b as u64 & max;
    if v < max {
        return Ok(v);
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or(Short::Incomplete)?;
        *pos += 1;
        if shift > 56 {
            return Err(Short::Invalid);
        }
        v += ((b & 0x7f) as u64) << shift;
        if v > MAX_INT {
            return Err(Short::Invalid);
        }
        if b & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
    }
}

/// Appends an `n`-bit prefixed integer whose first byte carries `flags` in the high bits.
pub fn put_int(out: &mut Vec<u8>, flags: u8, n: u8, mut v: u64) {
    let max = (1u64 << n) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A string literal located in a buffer: Huffman flag and byte span.
#[derive(Clone, Copy)]
pub(crate) struct Span {
    pub huff: bool,
    pub start: usize,
    pub end: usize,
}

/// Reads a string literal header whose length has an `n`-bit prefix and whose Huffman flag is
/// the bit just above it, and checks that the bytes are all present.
pub(crate) fn get_span(buf: &[u8], pos: &mut usize, n: u8) -> Result<Span, Short> {
    let huff = *buf.get(*pos).ok_or(Short::Incomplete)? & (1 << n) != 0;
    let len = get_int(buf, pos, n)?;
    let start = *pos;
    let avail = (buf.len() - start) as u64;
    if len > avail {
        return Err(Short::Incomplete);
    }
    *pos = start + len as usize;
    Ok(Span { huff, start, end: *pos })
}

/// Decodes a located string literal into an owned vector.
pub(crate) fn span_bytes(buf: &[u8], s: Span) -> Result<Vec<u8>, Short> {
    let raw = &buf[s.start..s.end];
    if s.huff {
        let mut out = Vec::new();
        huffman::decode(raw, &mut out).map_err(|_| Short::Invalid)?;
        Ok(out)
    } else {
        Ok(raw.to_vec())
    }
}

/// Appends a string literal with an `n`-bit length prefix, the Huffman flag just above it and
/// `flags` above that; Huffman is used when it is shorter.
pub(crate) fn put_str(out: &mut Vec<u8>, flags: u8, n: u8, s: &[u8]) {
    let hlen = huffman::encoded_len(s);
    if hlen < s.len() {
        put_int(out, flags | (1 << n), n, hlen as u64);
        huffman::encode(s, out);
    } else {
        put_int(out, flags, n, s.len() as u64);
        out.extend_from_slice(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_lookup() {
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(static_find(b":path", b"/"), (Some(1), Some(1)));
        assert_eq!(static_find(b":path", b"/x"), (None, Some(1)));
        assert_eq!(static_find(b":status", b"500"), (Some(71), Some(71)));
        assert_eq!(static_find(b"x-frame-options", b"sameorigin"), (Some(98), Some(98)));
        assert_eq!(static_find(b"x-unknown", b""), (None, None));
    }

    #[test]
    fn integers() {
        // RFC 7541 C.1
        let mut out = Vec::new();
        put_int(&mut out, 0, 5, 10);
        assert_eq!(out, [10]);
        out.clear();
        put_int(&mut out, 0, 5, 1337);
        assert_eq!(out, [31, 154, 10]);
        let mut p = 0;
        assert_eq!(get_int(&out, &mut p, 5), Ok(1337));
        out.clear();
        put_int(&mut out, 0, 8, 42);
        assert_eq!(out, [42]);
        for &v in &[0u64, 1, 30, 31, 127, 128, 255, 16383, 1 << 40, MAX_INT] {
            for n in 1..=8u8 {
                let mut o = vec![];
                put_int(&mut o, 0, n, v);
                let mut p = 0;
                assert_eq!(get_int(&o, &mut p, n), Ok(v));
                assert_eq!(p, o.len());
                let mut p = 0;
                if o.len() > 1 {
                    assert_eq!(get_int(&o[..o.len() - 1], &mut p, n), Err(Short::Incomplete));
                }
            }
        }
        // 2^62 overflows
        let mut o = vec![];
        put_int(&mut o, 0, 6, MAX_INT + 1);
        let mut p = 0;
        assert_eq!(get_int(&o, &mut p, 6), Err(Short::Invalid));
        // endless continuation bytes
        let o = [0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let mut p = 0;
        assert_eq!(get_int(&o, &mut p, 6), Err(Short::Invalid));
    }
}
