//! h2c upgrade from HTTP/1.1 (RFC 7540 §3.2; deprecated by RFC 9113 but still used): the
//! `HTTP2-Settings` header value is a base64url SETTINGS payload without padding.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes bytes as unpadded base64url.
pub fn base64url_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            s.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

/// Decodes base64url, with or without padding. Whitespace around the value is ignored; any
/// other byte outside the alphabet is an error.
pub fn base64url_decode(s: &[u8]) -> Option<Vec<u8>> {
    let s = s.trim_ascii();
    let s = match s.iter().position(|&c| c == b'=') {
        Some(p) if s[p..].iter().all(|&c| c == b'=') && s[p..].len() <= 2 => &s[..p],
        Some(_) => return None,
        None => s,
    };
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for n in 0..40usize {
            let b: Vec<u8> = (0..n).map(|i| (i * 89 + 7) as u8).collect();
            let e = base64url_encode(&b);
            assert!(!e.contains('=') && !e.contains('+') && !e.contains('/'));
            assert_eq!(base64url_decode(e.as_bytes()).unwrap(), b);
        }
        assert_eq!(base64url_encode(b"\xfb\xff"), "-_8");
        assert_eq!(base64url_decode(b"AAMAAABkAAQAAP__").unwrap(), [0, 3, 0, 0, 0, 100, 0, 4, 0, 0, 255, 255]);
        assert_eq!(base64url_decode(b" QQ== ").unwrap(), b"A");
        assert!(base64url_decode(b"Q").is_none());
        assert!(base64url_decode(b"Q=Q=").is_none());
        assert!(base64url_decode(b"QQ!!").is_none());
    }
}
