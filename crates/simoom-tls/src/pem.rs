//! PEM (RFC 7468) and base64 encoding/decoding.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Decodes standard base64, ignoring whitespace. Returns None on invalid input.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    let mut pad = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        if pad > 0 {
            return None;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if pad > 2 {
        return None;
    }
    Some(out)
}

/// One PEM block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PemBlock {
    pub label: String,
    pub der: Vec<u8>,
}

/// Parses every PEM block in `input` (text outside blocks is ignored; blocks
/// with headers such as encrypted keys are rejected).
pub fn parse_pem(input: &[u8]) -> Result<Vec<PemBlock>, String> {
    let text = String::from_utf8_lossy(input);
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                current = Some((label.to_string(), String::new()));
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix("-----END ") {
            if let Some(label) = rest.strip_suffix("-----") {
                match current.take() {
                    Some((l, body)) if l == label => {
                        let der = base64_decode(&body).ok_or_else(|| format!("invalid base64 in PEM block {l}"))?;
                        blocks.push(PemBlock { label: l, der });
                    }
                    _ => return Err(format!("mismatched PEM END {label}")),
                }
                continue;
            }
        }
        if let Some((label, body)) = current.as_mut() {
            if line.contains(':') {
                return Err(format!("PEM block {label} has headers (encrypted keys are not supported)"));
            }
            body.push_str(line);
        }
    }
    if let Some((l, _)) = current {
        return Err(format!("unterminated PEM block {l}"));
    }
    Ok(blocks)
}

pub fn encode_pem(label: &str, der: &[u8]) -> String {
    let b = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648() {
        let cases = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")];
        for (plain, enc) in cases {
            assert_eq!(base64_encode(plain.as_bytes()), enc);
            assert_eq!(base64_decode(enc).unwrap(), plain.as_bytes());
        }
        assert!(base64_decode("Zm9v!").is_none());
    }

    #[test]
    fn pem_roundtrip() {
        let data: Vec<u8> = (0..200u8).collect();
        let p = encode_pem("CERTIFICATE", &data) + "junk\n" + &encode_pem("PRIVATE KEY", &[1, 2, 3]);
        let blocks = parse_pem(p.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].der, data);
        assert_eq!(blocks[1].label, "PRIVATE KEY");
    }
}
