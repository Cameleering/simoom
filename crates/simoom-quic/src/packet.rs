//! Packet headers, packet numbers, header protection, Version Negotiation, Retry and
//! stateless reset (RFC 9000 §17, RFC 9001 §5).

use crate::coding::{put_varint, Reader};
use crate::crypto::{CryptoProvider, HeaderKey};
use std::ops::Range;

pub const VERSION_1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369).
pub const VERSION_2: u32 = 0x6b33_43cf;
pub const MAX_CID_LEN: usize = 20;
/// Smallest datagram that may carry a client Initial (RFC 9000 §14.1).
pub const MIN_INITIAL_SIZE: usize = 1200;
/// Smallest stateless reset (RFC 9000 §10.3).
pub const MIN_RESET_SIZE: usize = 21;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
    VersionNegotiation,
}

/// Long-header type bits for `version` (they differ in QUIC v2, RFC 9369 §3.2).
pub fn long_type_bits(version: u32, ty: PacketType) -> u8 {
    let v1 = match ty {
        PacketType::Initial => 0,
        PacketType::ZeroRtt => 1,
        PacketType::Handshake => 2,
        _ => 3,
    };
    if version == VERSION_2 {
        (v1 + 1) & 3
    } else {
        v1
    }
}

fn long_type_from_bits(version: u32, bits: u8) -> PacketType {
    let v1 = if version == VERSION_2 { (bits + 3) & 3 } else { bits };
    match v1 {
        0 => PacketType::Initial,
        1 => PacketType::ZeroRtt,
        2 => PacketType::Handshake,
        _ => PacketType::Retry,
    }
}

/// A header parsed before header protection is removed. Ranges index the datagram.
#[derive(Clone, Debug)]
pub struct Header {
    pub ty: PacketType,
    pub version: u32,
    pub dcid: Range<usize>,
    pub scid: Range<usize>,
    /// Initial: the token; Retry: the token; VN: the version list.
    pub token: Range<usize>,
    /// Offset of the packet number (protected).
    pub pn_offset: usize,
    /// End of this packet in the datagram (coalesced packets follow).
    pub end: usize,
}

/// Parses the header starting at `start`. `short_dcid_len` is the length of this
/// endpoint's connection IDs (short headers do not carry it).
pub fn parse_header(buf: &[u8], start: usize, short_dcid_len: usize) -> Option<Header> {
    let mut r = Reader::new(&buf[start..]);
    let first = r.u8()?;
    if first & 0x80 == 0 {
        // Short header (fixed bit checked by the caller after decryption fails, RFC 9000 §17.3).
        let dcid = start + 1..start + 1 + short_dcid_len;
        if dcid.end > buf.len() {
            return None;
        }
        return Some(Header {
            ty: PacketType::OneRtt,
            version: 0,
            dcid: dcid.clone(),
            scid: 0..0,
            token: 0..0,
            pn_offset: dcid.end,
            end: buf.len(),
        });
    }
    let version = r.u32()?;
    let dlen = r.u8()? as usize;
    let d0 = start + r.position();
    r.bytes(dlen)?;
    let slen = r.u8()? as usize;
    let s0 = start + r.position();
    r.bytes(slen)?;
    let dcid = d0..d0 + dlen;
    let scid = s0..s0 + slen;
    // Versions other than 1 and 2 may use longer IDs (RFC 8999); we neither route nor
    // answer those.
    if dlen > MAX_CID_LEN || slen > MAX_CID_LEN {
        return None;
    }
    if version == 0 {
        let t0 = start + r.position();
        return Some(Header {
            ty: PacketType::VersionNegotiation,
            version,
            dcid,
            scid,
            token: t0..buf.len(),
            pn_offset: buf.len(),
            end: buf.len(),
        });
    }
    if !is_supported(version) {
        // Unknown version: only the invariant fields are meaningful.
        return Some(Header {
            ty: PacketType::Initial,
            version,
            dcid,
            scid,
            token: 0..0,
            pn_offset: buf.len(),
            end: buf.len(),
        });
    }
    let ty = long_type_from_bits(version, (first >> 4) & 3);
    let mut token = 0..0;
    if ty == PacketType::Retry {
        let t0 = start + r.position();
        if buf.len() < t0 + 16 {
            return None;
        }
        return Some(Header { ty, version, dcid, scid, token: t0..buf.len() - 16, pn_offset: buf.len(), end: buf.len() });
    }
    if ty == PacketType::Initial {
        let t = r.vbytes()?;
        let t0 = start + r.position() - t.len();
        token = t0..t0 + t.len();
    }
    let len = r.varint()? as usize;
    let pn_offset = start + r.position();
    if len > buf.len() - pn_offset {
        return None;
    }
    Some(Header { ty, version, dcid, scid, token, pn_offset, end: pn_offset + len })
}

pub fn is_supported(version: u32) -> bool {
    version == VERSION_1 || version == VERSION_2
}

/// Removes header protection in place; returns (truncated packet number, its length).
pub fn unprotect(buf: &mut [u8], start: usize, pn_offset: usize, end: usize, hp: &dyn HeaderKey) -> Option<(u64, usize)> {
    let sample_at = pn_offset + 4;
    if sample_at + 16 > end {
        return None;
    }
    let mask = hp.mask(&buf[sample_at..sample_at + 16]);
    let long = buf[start] & 0x80 != 0;
    buf[start] ^= mask[0] & if long { 0x0f } else { 0x1f };
    let pn_len = (buf[start] & 3) as usize + 1;
    let mut pn = 0u64;
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | buf[pn_offset + i] as u64;
    }
    Some((pn, pn_len))
}

/// Applies header protection to a sealed packet `buf[start..end]`.
pub fn protect(buf: &mut [u8], start: usize, pn_offset: usize, pn_len: usize, hp: &dyn HeaderKey) {
    let sample_at = pn_offset + 4;
    let mask = hp.mask(&buf[sample_at..sample_at + 16]);
    let long = buf[start] & 0x80 != 0;
    buf[start] ^= mask[0] & if long { 0x0f } else { 0x1f };
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
    }
}

/// Recovers a full packet number (RFC 9000 Appendix A.3).
pub fn decode_pn(largest: Option<u64>, truncated: u64, pn_len: usize) -> u64 {
    let expected = largest.map_or(0, |l| l + 1);
    let win = 1u64 << (pn_len * 8);
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + hwin <= expected && candidate < (1 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

/// Bytes needed to encode `pn` given the largest acknowledged (RFC 9000 Appendix A.2).
pub fn pn_len(pn: u64, largest_acked: Option<u64>) -> usize {
    let unacked = match largest_acked {
        Some(l) => pn - l,
        None => pn + 1,
    };
    let range = unacked.saturating_mul(2);
    if range < 1 << 8 {
        1
    } else if range < 1 << 16 {
        2
    } else if range < 1 << 24 {
        3
    } else {
        4
    }
}

/// Writes a Version Negotiation packet answering a packet with `dcid`/`scid`.
pub fn version_negotiation(out: &mut Vec<u8>, random: u8, dcid: &[u8], scid: &[u8], versions: &[u32]) {
    out.push(0x80 | (random & 0x7f) | 0x40);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    for v in versions {
        out.extend_from_slice(&v.to_be_bytes());
    }
    // A reserved version (RFC 9000 §15) exercises the peer's handling of unknown versions.
    out.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes());
}

/// Writes a Retry packet with its integrity tag (RFC 9001 §5.8).
#[allow(clippy::too_many_arguments)]
pub fn retry(
    out: &mut Vec<u8>,
    provider: &dyn CryptoProvider,
    version: u32,
    random: u8,
    odcid: &[u8],
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
) {
    let start = out.len();
    out.push(0xc0 | (long_type_bits(version, PacketType::Retry) << 4) | (random & 0x0f));
    out.extend_from_slice(&version.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    out.extend_from_slice(token);
    let tag = retry_tag(provider, version, odcid, &out[start..]);
    out.extend_from_slice(&tag);
}

/// The Retry integrity tag for a Retry packet (without its tag) sent in reply to `odcid`.
pub fn retry_tag(provider: &dyn CryptoProvider, version: u32, odcid: &[u8], packet: &[u8]) -> [u8; 16] {
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + packet.len());
    pseudo.push(odcid.len() as u8);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(packet);
    provider.retry_tag(version, &pseudo)
}

/// Writes the long header up to and including the packet number; returns
/// (offset of the 2-byte length field, packet number offset).
#[allow(clippy::too_many_arguments)]
pub fn put_long_header(
    out: &mut Vec<u8>,
    version: u32,
    ty: PacketType,
    dcid: &[u8],
    scid: &[u8],
    token: Option<&[u8]>,
    pn: u64,
    pn_len: usize,
) -> (usize, usize) {
    out.push(0xc0 | (long_type_bits(version, ty) << 4) | (pn_len as u8 - 1));
    out.extend_from_slice(&version.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    if let Some(t) = token {
        put_varint(out, t.len() as u64);
        out.extend_from_slice(t);
    }
    let len_at = out.len();
    out.extend_from_slice(&[0x40, 0]);
    let pn_at = out.len();
    out.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
    (len_at, pn_at)
}

/// Writes a short header; returns the packet number offset.
pub fn put_short_header(out: &mut Vec<u8>, spin: bool, key_phase: bool, dcid: &[u8], pn: u64, pn_len: usize) -> usize {
    out.push(0x40 | (spin as u8) << 5 | (key_phase as u8) << 2 | (pn_len as u8 - 1));
    out.extend_from_slice(dcid);
    let pn_at = out.len();
    out.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
    pn_at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_appendix_a_packet_numbers() {
        // A.2: full 0xac5c02 with largest acked 0xabe8b3 needs 2 bytes; 0xace8fe needs 3.
        assert_eq!(pn_len(0xac5c02, Some(0xabe8b3)), 2);
        assert_eq!(pn_len(0xace8fe, Some(0xabe8b3)), 3);
        // A.3: largest 0xa82f30ea, truncated 0x9b32 (16 bits) decodes to 0xa82f9b32.
        assert_eq!(decode_pn(Some(0xa82f30ea), 0x9b32, 2), 0xa82f9b32);
        assert_eq!(decode_pn(None, 0, 1), 0);
        assert_eq!(decode_pn(Some(0xff), 0x00, 1), 0x100);
        assert_eq!(decode_pn(Some(0x100), 0xff, 1), 0xff);
        assert_eq!(pn_len(0, None), 1);
    }

    #[test]
    fn header_roundtrip_and_types() {
        for v in [VERSION_1, VERSION_2] {
            let mut out = Vec::new();
            let (len_at, pn_at) =
                put_long_header(&mut out, v, PacketType::Handshake, &[1, 2, 3], &[4, 5], None, 7, 2);
            out.extend_from_slice(&[0; 20]);
            let n = out.len() - pn_at;
            crate::coding::put_varint_fixed(&mut out[len_at..], n as u64, 2);
            let h = parse_header(&out, 0, 0).unwrap();
            assert_eq!(h.ty, PacketType::Handshake);
            assert_eq!(&out[h.dcid.clone()], &[1, 2, 3]);
            assert_eq!(&out[h.scid.clone()], &[4, 5]);
            assert_eq!(h.pn_offset, pn_at);
            assert_eq!(h.end, out.len());
        }
        assert_eq!(long_type_bits(VERSION_2, PacketType::Initial), 1);
        assert_eq!(long_type_bits(VERSION_2, PacketType::Retry), 0);
        // Truncated Initial length.
        let mut out = Vec::new();
        put_long_header(&mut out, VERSION_1, PacketType::Initial, &[1; 8], &[], Some(b"t"), 0, 1);
        assert!(parse_header(&out, 0, 0).is_some());
        out[17] = 0x7f;
        out[18] = 0xff;
        assert!(parse_header(&out, 0, 0).is_none());
    }
}
