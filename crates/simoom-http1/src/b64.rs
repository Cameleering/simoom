//! Base64 (RFC 4648), strict: canonical encodings only.

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Appends the padded standard base64 encoding of `input` to `out`.
pub fn base64_encode(input: &[u8], out: &mut Vec<u8>) {
    for c in input.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            out.push(if k <= c.len() { STD[(n >> (18 - 6 * k) & 63) as usize] } else { b'=' });
        }
    }
}

fn value(b: u8, url: bool) -> Option<u32> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' if !url => 62,
        b'/' if !url => 63,
        b'-' if url => 62,
        b'_' if url => 63,
        _ => return None,
    } as u32)
}

fn decode(input: &[u8], url: bool, out: &mut Vec<u8>) -> bool {
    let body = if url {
        if input.len() % 4 == 1 {
            return false;
        }
        input
    } else {
        if input.len() % 4 != 0 {
            return false;
        }
        let pad = input.iter().rev().take(2).take_while(|&&b| b == b'=').count();
        &input[..input.len() - pad]
    };
    let start = out.len();
    for c in body.chunks(4) {
        let mut n = 0u32;
        for (k, &b) in c.iter().enumerate() {
            let Some(v) = value(b, url) else {
                out.truncate(start);
                return false;
            };
            n |= v << (18 - 6 * k);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = c.len() - 1;
        if c.len() == 1 || (keep < 3 && n & (0xff_ffff >> (8 * keep)) != 0) {
            // A lone character, or non-zero bits after the last whole byte: not canonical.
            out.truncate(start);
            return false;
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    true
}

/// Decodes padded standard base64 into `out`; false (and `out` unchanged) if it is not
/// canonical base64.
pub fn base64_decode(input: &[u8], out: &mut Vec<u8>) -> bool {
    decode(input, false, out)
}

/// Decodes unpadded base64url (as in `HTTP2-Settings`) into `out`; false (and `out`
/// unchanged) if it is not canonical.
pub fn base64url_decode(input: &[u8], out: &mut Vec<u8>) -> bool {
    decode(input, true, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_round_trip() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            let mut out = Vec::new();
            base64_encode(plain.as_bytes(), &mut out);
            assert_eq!(out, enc.as_bytes());
            let mut back = Vec::new();
            assert!(base64_decode(enc.as_bytes(), &mut back), "{enc}");
            assert_eq!(back, plain.as_bytes());
            let mut url = Vec::new();
            assert!(base64url_decode(enc.trim_end_matches('=').as_bytes(), &mut url));
            assert_eq!(url, plain.as_bytes());
        }
    }

    #[test]
    fn rejects_non_canonical_input() {
        for bad in ["Zg", "Zh==", "Zm9=", "Z===", "Zm9v=", "Zm 9v", "Zm9v\n", "Zg=a", "-_==", "===="] {
            let mut out = Vec::new();
            assert!(!base64_decode(bad.as_bytes(), &mut out), "{bad}");
            assert!(out.is_empty());
        }
        for bad in ["Z", "Zh", "+/", "Zg=="] {
            assert!(!base64url_decode(bad.as_bytes(), &mut Vec::new()), "{bad}");
        }
        let mut out = Vec::new();
        assert!(base64url_decode(b"-_8", &mut out));
        assert_eq!(out, [0xfb, 0xff]);
    }
}
