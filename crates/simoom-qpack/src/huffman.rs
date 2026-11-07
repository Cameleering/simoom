//! Huffman coding (RFC 7541 section 5.2 and Appendix B), shared with HPACK: this is
//! simoom-hpack's code table, encoder and table-driven decoder, so a build with both HTTP/2
//! and HTTP/3 carries one copy.

pub use simoom_hpack::huffman::{encode, encoded_len};

/// Decodes a Huffman-encoded string, appending to `out`. Rejects EOS, padding longer
/// than 7 bits and padding that is not all ones.
#[allow(clippy::result_unit_err)]
pub fn decode(data: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    simoom_hpack::huffman::decode(data, out).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn dec(d: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        decode(d, &mut out).map(|_| out)
    }

    #[test]
    fn rfc7541_c4_vectors() {
        let mut out = Vec::new();
        encode(b"www.example.com", &mut out);
        assert_eq!(out, hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"));
        assert_eq!(dec(&out).unwrap(), b"www.example.com");
        assert_eq!(encoded_len(b"www.example.com"), 12);
        assert_eq!(dec(&hex("a8eb 1064 9cbf")).unwrap(), b"no-cache");
        assert_eq!(dec(&hex("25a8 49e9 5ba9 7d7f")).unwrap(), b"custom-key");
        assert_eq!(dec(&hex("25a8 49e9 5bb8 e8b4 bf")).unwrap(), b"custom-value");
        assert_eq!(dec(&hex("6402")).unwrap(), b"302");
        assert_eq!(dec(&hex("aec3 771a 4b")).unwrap(), b"private");
        assert_eq!(
            dec(&hex("d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff")).unwrap(),
            b"Mon, 21 Oct 2013 20:13:21 GMT"
        );
        assert_eq!(dec(&hex("9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3")).unwrap(), b"https://www.example.com");
    }

    #[test]
    fn all_bytes_round_trip() {
        let data: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        let mut out = Vec::new();
        encode(&data, &mut out);
        assert_eq!(out.len(), encoded_len(&data));
        assert_eq!(dec(&out).unwrap(), data);
        assert_eq!(dec(&[]).unwrap(), b"");
    }

    #[test]
    fn invalid_padding_and_eos() {
        assert!(dec(&[0b0001_1000]).is_err());
        assert_eq!(dec(&[0b0001_1111]).unwrap(), b"a");
        assert!(dec(&[0b0001_1111, 0xff]).is_err());
        // EOS (30 ones) followed by padding
        assert!(dec(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }
}
