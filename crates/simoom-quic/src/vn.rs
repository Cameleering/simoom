//! Compatible version negotiation (RFC 9368) between QUIC v1 and v2 (RFC 9369).
//!
//! The server reads the client's `version_information` transport parameter out of the
//! ClientHello before it starts its TLS session, so that the session (and the transport
//! parameters it sends) already uses the negotiated version.

use crate::coding::Reader;
use crate::packet::{VERSION_1, VERSION_2};

/// Transport parameter `version_information` (RFC 9368 §3).
pub const VERSION_INFORMATION: u64 = 0x11;

/// Whether a connection that started in `from` may continue in `to` (RFC 9368 §2.3: the
/// versions must be compatible; v1 and v2 are, in both directions).
pub fn compatible(from: u32, to: u32) -> bool {
    from == to || matches!((from, to), (VERSION_1, VERSION_2) | (VERSION_2, VERSION_1))
}

/// Encodes `version_information`: the chosen version, then the available versions.
pub fn encode(chosen: u32, available: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 4 * available.len());
    v.extend_from_slice(&chosen.to_be_bytes());
    for a in available {
        v.extend_from_slice(&a.to_be_bytes());
    }
    v
}

/// Decodes `version_information`: (chosen, available). `None` if malformed (RFC 9368 §3: a
/// length that is not a multiple of 4, or a zero chosen version).
pub fn decode(v: &[u8]) -> Option<(u32, Vec<u32>)> {
    if v.len() < 4 || v.len() % 4 != 0 {
        return None;
    }
    let mut r = Reader::new(v);
    let chosen = r.u32()?;
    if chosen == 0 {
        return None;
    }
    let mut available = Vec::new();
    while let Some(x) = r.u32() {
        available.push(x);
    }
    Some((chosen, available))
}

/// Length of the complete ClientHello handshake message at the start of `buf`, once its
/// header has arrived.
pub fn hello_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    Some(4 + ((buf[1] as usize) << 16 | (buf[2] as usize) << 8 | buf[3] as usize))
}

/// The client's `version_information` from a complete ClientHello, if it has one.
pub fn client_versions(hello: &[u8]) -> Option<(u32, Vec<u32>)> {
    let mut r = Reader::new(hello);
    if r.u8()? != 1 {
        return None;
    }
    let len = (r.u8()? as usize) << 16 | (r.u16()? as usize);
    let mut r = Reader::new(r.bytes(len)?);
    r.bytes(2 + 32)?; // legacy_version, random
    let n = r.u8()? as usize;
    r.bytes(n)?; // legacy_session_id
    let n = r.u16()? as usize;
    r.bytes(n)?; // cipher_suites
    let n = r.u8()? as usize;
    r.bytes(n)?; // legacy_compression_methods
    let n = r.u16()? as usize;
    let mut ext = Reader::new(r.bytes(n)?);
    while !ext.is_empty() {
        let ty = ext.u16()?;
        let n = ext.u16()? as usize;
        let body = ext.bytes(n)?;
        if ty != 0x39 {
            continue;
        }
        let mut tp = Reader::new(body);
        while !tp.is_empty() {
            let id = tp.varint()?;
            let v = tp.vbytes()?;
            if id == VERSION_INFORMATION {
                return decode(v);
            }
        }
        return None;
    }
    None
}

/// The version a server continues in: the first of its `preferred` versions that the client
/// lists as available and that is compatible with the version the client started in.
pub fn choose(started: u32, preferred: &[u32], client: Option<&(u32, Vec<u32>)>) -> u32 {
    let Some((_, available)) = client else { return started };
    preferred.iter().copied().find(|&v| compatible(started, v) && available.contains(&v)).unwrap_or(started)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(tp: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0010u16.to_be_bytes()); // ALPN, skipped
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.extend_from_slice(&[0, 1, b'h']);
        ext.extend_from_slice(&0x39u16.to_be_bytes());
        ext.extend_from_slice(&(tp.len() as u16).to_be_bytes());
        ext.extend_from_slice(tp);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut m = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        m.extend_from_slice(&body);
        m
    }

    #[test]
    fn reads_version_information_from_a_client_hello() {
        let vi = encode(VERSION_1, &[VERSION_1, VERSION_2]);
        let mut tp = vec![0x0f, 0x01, 0x07, VERSION_INFORMATION as u8, vi.len() as u8];
        tp.extend_from_slice(&vi);
        let h = hello(&tp);
        assert_eq!(hello_len(&h), Some(h.len()));
        let got = client_versions(&h).unwrap();
        assert_eq!(got, (VERSION_1, vec![VERSION_1, VERSION_2]));
        assert_eq!(choose(VERSION_1, &[VERSION_2, VERSION_1], Some(&got)), VERSION_2);
        assert_eq!(choose(VERSION_1, &[VERSION_1, VERSION_2], Some(&got)), VERSION_1);
        assert_eq!(choose(VERSION_1, &[VERSION_2, VERSION_1], None), VERSION_1);
        // A client that does not list v2 stays in v1.
        let only = (VERSION_1, vec![VERSION_1]);
        assert_eq!(choose(VERSION_1, &[VERSION_2, VERSION_1], Some(&only)), VERSION_1);
        // No version_information, truncated or malformed: nothing.
        assert_eq!(client_versions(&hello(&[0x0f, 0x01, 0x07])), None);
        assert_eq!(client_versions(&h[..h.len() - 1]), None);
        assert_eq!(decode(&[0, 0, 0, 1, 2]), None);
        assert_eq!(decode(&[0, 0, 0, 0]), None);
    }
}
