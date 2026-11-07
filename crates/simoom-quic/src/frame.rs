//! QUIC frames (RFC 9000 §19): zero-copy parsing and encoding.

use crate::coding::{put_varint, varint_len, Reader, VARINT_MAX};
use crate::error::{TransportError, FRAME_ENCODING_ERROR, PROTOCOL_VIOLATION};
use crate::ranges::RangeSet;

pub const PADDING: u64 = 0x00;
pub const PING: u64 = 0x01;
pub const ACK: u64 = 0x02;
pub const ACK_ECN: u64 = 0x03;
pub const RESET_STREAM: u64 = 0x04;
pub const STOP_SENDING: u64 = 0x05;
pub const CRYPTO: u64 = 0x06;
pub const NEW_TOKEN: u64 = 0x07;
pub const STREAM: u64 = 0x08;
pub const MAX_DATA: u64 = 0x10;
pub const MAX_STREAM_DATA: u64 = 0x11;
pub const MAX_STREAMS_BIDI: u64 = 0x12;
pub const MAX_STREAMS_UNI: u64 = 0x13;
pub const DATA_BLOCKED: u64 = 0x14;
pub const STREAM_DATA_BLOCKED: u64 = 0x15;
pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
pub const NEW_CONNECTION_ID: u64 = 0x18;
pub const RETIRE_CONNECTION_ID: u64 = 0x19;
pub const PATH_CHALLENGE: u64 = 0x1a;
pub const PATH_RESPONSE: u64 = 0x1b;
pub const CONNECTION_CLOSE: u64 = 0x1c;
pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
pub const HANDSHAKE_DONE: u64 = 0x1e;

/// Streams per direction may not exceed 2^60 (RFC 9000 §4.6).
pub const MAX_STREAMS_LIMIT: u64 = 1 << 60;

/// The ACK ranges of an ACK frame, decoded lazily (descending, inclusive).
#[derive(Clone, Copy, Debug)]
pub struct AckRanges<'a> {
    pub largest: u64,
    pub first: u64,
    count: u64,
    raw: &'a [u8],
}

impl<'a> AckRanges<'a> {
    /// Iterates `(smallest, largest)` pairs, highest first. Already validated by parsing.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + 'a {
        let mut r = Reader::new(self.raw);
        let mut hi = self.largest;
        let mut lo = self.largest - self.first;
        let mut left = self.count;
        let mut first = true;
        std::iter::from_fn(move || {
            if first {
                first = false;
                return Some((lo, hi));
            }
            if left == 0 {
                return None;
            }
            left -= 1;
            let gap = r.varint()?;
            let len = r.varint()?;
            hi = lo - gap - 2;
            lo = hi - len;
            Some((lo, hi))
        })
    }
    pub fn smallest(&self) -> u64 {
        self.iter().last().map(|x| x.0).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Frame<'a> {
    Padding,
    Ping,
    Ack { ranges: AckRanges<'a>, delay: u64, ecn: Option<[u64; 3]> },
    ResetStream { id: u64, code: u64, final_size: u64 },
    StopSending { id: u64, code: u64 },
    Crypto { offset: u64, data: &'a [u8] },
    NewToken { token: &'a [u8] },
    Stream { id: u64, offset: u64, data: &'a [u8], fin: bool },
    MaxData(u64),
    MaxStreamData { id: u64, max: u64 },
    MaxStreams { bidi: bool, max: u64 },
    DataBlocked(u64),
    StreamDataBlocked { id: u64, limit: u64 },
    StreamsBlocked { bidi: bool, limit: u64 },
    NewConnectionId { seq: u64, retire_prior_to: u64, cid: &'a [u8], reset_token: [u8; 16] },
    RetireConnectionId { seq: u64 },
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose { code: u64, frame_type: Option<u64>, reason: &'a [u8] },
    HandshakeDone,
}

impl Frame<'_> {
    /// True for frames that require an acknowledgement (RFC 9002 §2).
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Padding | Frame::Ack { .. } | Frame::ConnectionClose { .. })
    }
    /// Probing frames (RFC 9000 §9.1).
    pub fn is_probing(&self) -> bool {
        matches!(self, Frame::Padding | Frame::PathChallenge(_) | Frame::PathResponse(_) | Frame::NewConnectionId { .. })
    }
}

fn enc(ty: u64) -> TransportError {
    TransportError::frame(FRAME_ENCODING_ERROR, ty, "malformed frame")
}

/// Parses one frame. Returns the frame type with the frame.
pub fn parse<'a>(r: &mut Reader<'a>) -> Result<(u64, Frame<'a>), TransportError> {
    let (ty, tlen) = r.varint_with_len().ok_or(enc(0))?;
    if tlen != varint_len(ty) {
        return Err(TransportError::frame(PROTOCOL_VIOLATION, ty, "non-minimal frame type"));
    }
    let e = || enc(ty);
    let v = |r: &mut Reader<'a>| r.varint().ok_or_else(e);
    let f = match ty {
        PADDING => {
            // Consume a run of padding in one go.
            let rest = r.rest();
            let n = rest.iter().position(|&b| b != 0).unwrap_or(rest.len());
            r.bytes(n);
            Frame::Padding
        }
        PING => Frame::Ping,
        ACK | ACK_ECN => {
            let largest = v(r)?;
            let delay = v(r)?;
            let count = v(r)?;
            let first = v(r)?;
            if first > largest {
                return Err(e());
            }
            let start = r.position();
            let raw_all = r.rest();
            let mut lo = largest - first;
            for _ in 0..count {
                let gap = v(r)?;
                let len = v(r)?;
                // hi = lo - gap - 2 must not underflow; lo' = hi - len likewise.
                if lo < gap + 2 || lo - gap - 2 < len {
                    return Err(e());
                }
                lo = lo - gap - 2 - len;
            }
            let raw = &raw_all[..r.position() - start];
            let ecn = if ty == ACK_ECN { Some([v(r)?, v(r)?, v(r)?]) } else { None };
            Frame::Ack { ranges: AckRanges { largest, first, count, raw }, delay, ecn }
        }
        RESET_STREAM => Frame::ResetStream { id: v(r)?, code: v(r)?, final_size: v(r)? },
        STOP_SENDING => Frame::StopSending { id: v(r)?, code: v(r)? },
        CRYPTO => {
            let offset = v(r)?;
            let data = r.vbytes().ok_or_else(e)?;
            if offset + data.len() as u64 > VARINT_MAX {
                return Err(TransportError::frame(FRAME_ENCODING_ERROR, ty, "crypto offset overflow"));
            }
            Frame::Crypto { offset, data }
        }
        NEW_TOKEN => {
            let token = r.vbytes().ok_or_else(e)?;
            if token.is_empty() {
                return Err(e());
            }
            Frame::NewToken { token }
        }
        0x08..=0x0f => {
            let id = v(r)?;
            let offset = if ty & 0x04 != 0 { v(r)? } else { 0 };
            let data = if ty & 0x02 != 0 {
                r.vbytes().ok_or_else(e)?
            } else {
                let d = r.rest();
                r.bytes(d.len());
                d
            };
            if offset + data.len() as u64 > VARINT_MAX {
                return Err(TransportError::frame(FRAME_ENCODING_ERROR, ty, "stream offset overflow"));
            }
            Frame::Stream { id, offset, data, fin: ty & 0x01 != 0 }
        }
        MAX_DATA => Frame::MaxData(v(r)?),
        MAX_STREAM_DATA => Frame::MaxStreamData { id: v(r)?, max: v(r)? },
        MAX_STREAMS_BIDI | MAX_STREAMS_UNI => {
            let max = v(r)?;
            if max > MAX_STREAMS_LIMIT {
                return Err(e());
            }
            Frame::MaxStreams { bidi: ty == MAX_STREAMS_BIDI, max }
        }
        DATA_BLOCKED => Frame::DataBlocked(v(r)?),
        STREAM_DATA_BLOCKED => Frame::StreamDataBlocked { id: v(r)?, limit: v(r)? },
        STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => {
            let limit = v(r)?;
            if limit > MAX_STREAMS_LIMIT {
                return Err(e());
            }
            Frame::StreamsBlocked { bidi: ty == STREAMS_BLOCKED_BIDI, limit }
        }
        NEW_CONNECTION_ID => {
            let seq = v(r)?;
            let retire_prior_to = v(r)?;
            let len = r.u8().ok_or_else(e)? as usize;
            if len == 0 || len > 20 || retire_prior_to > seq {
                return Err(e());
            }
            let cid = r.bytes(len).ok_or_else(e)?;
            let reset_token = r.bytes(16).ok_or_else(e)?.try_into().unwrap();
            Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token }
        }
        RETIRE_CONNECTION_ID => Frame::RetireConnectionId { seq: v(r)? },
        PATH_CHALLENGE => Frame::PathChallenge(r.bytes(8).ok_or_else(e)?.try_into().unwrap()),
        PATH_RESPONSE => Frame::PathResponse(r.bytes(8).ok_or_else(e)?.try_into().unwrap()),
        CONNECTION_CLOSE | CONNECTION_CLOSE_APP => {
            let code = v(r)?;
            let frame_type = if ty == CONNECTION_CLOSE { Some(v(r)?) } else { None };
            let reason = r.vbytes().ok_or_else(e)?;
            Frame::ConnectionClose { code, frame_type, reason }
        }
        HANDSHAKE_DONE => Frame::HandshakeDone,
        _ => return Err(TransportError::frame(FRAME_ENCODING_ERROR, ty, "unknown frame type")),
    };
    Ok((ty, f))
}

// ---- encoding ----

/// Encodes an ACK frame for `ranges` (ascending set of received packet numbers), keeping
/// at most `max_ranges` of the highest ranges. Returns false if the set is empty.
pub fn put_ack(out: &mut Vec<u8>, ranges: &RangeSet, delay: u64, max_ranges: usize) -> bool {
    let mut it = ranges.iter().rev().take(max_ranges.max(1));
    let Some((s, e)) = it.next() else { return false };
    let n = ranges.len().min(max_ranges.max(1)) - 1;
    put_varint(out, ACK);
    put_varint(out, e - 1);
    put_varint(out, delay);
    put_varint(out, n as u64);
    put_varint(out, e - 1 - s);
    let mut lo = s;
    for (s2, e2) in it {
        // gap: number of missing packets minus one; hi = e2 - 1.
        put_varint(out, lo - e2 - 1);
        put_varint(out, e2 - 1 - s2);
        lo = s2;
    }
    true
}

pub fn put_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
    put_varint(out, CRYPTO);
    put_varint(out, offset);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Overhead of a CRYPTO frame header for this offset and length.
pub fn crypto_overhead(offset: u64, len: usize) -> usize {
    1 + varint_len(offset) + varint_len(len as u64)
}

/// STREAM frame header (always with an explicit length); the caller appends the data.
pub fn put_stream_header(out: &mut Vec<u8>, id: u64, offset: u64, len: usize, fin: bool) {
    let mut ty = STREAM | 0x02;
    if offset != 0 {
        ty |= 0x04;
    }
    if fin {
        ty |= 0x01;
    }
    out.push(ty as u8);
    put_varint(out, id);
    if offset != 0 {
        put_varint(out, offset);
    }
    put_varint(out, len as u64);
}

pub fn stream_overhead(id: u64, offset: u64, len: usize) -> usize {
    1 + varint_len(id) + if offset != 0 { varint_len(offset) } else { 0 } + varint_len(len as u64)
}

pub fn put_simple(out: &mut Vec<u8>, ty: u64, vals: &[u64]) {
    put_varint(out, ty);
    for &v in vals {
        put_varint(out, v);
    }
}

pub fn put_new_connection_id(out: &mut Vec<u8>, seq: u64, retire_prior_to: u64, cid: &[u8], token: &[u8; 16]) {
    put_varint(out, NEW_CONNECTION_ID);
    put_varint(out, seq);
    put_varint(out, retire_prior_to);
    out.push(cid.len() as u8);
    out.extend_from_slice(cid);
    out.extend_from_slice(token);
}

pub fn put_path(out: &mut Vec<u8>, response: bool, data: &[u8; 8]) {
    out.push(if response { PATH_RESPONSE } else { PATH_CHALLENGE } as u8);
    out.extend_from_slice(data);
}

pub fn put_new_token(out: &mut Vec<u8>, token: &[u8]) {
    put_varint(out, NEW_TOKEN);
    put_varint(out, token.len() as u64);
    out.extend_from_slice(token);
}

/// CONNECTION_CLOSE; `frame_type` is `None` for the application variant.
pub fn put_close(out: &mut Vec<u8>, code: u64, frame_type: Option<u64>, reason: &[u8]) {
    match frame_type {
        Some(t) => {
            put_varint(out, CONNECTION_CLOSE);
            put_varint(out, code);
            put_varint(out, t);
        }
        None => {
            put_varint(out, CONNECTION_CLOSE_APP);
            put_varint(out, code);
        }
    }
    put_varint(out, reason.len() as u64);
    out.extend_from_slice(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(b: &[u8]) -> Result<Frame<'_>, TransportError> {
        let mut r = Reader::new(b);
        let (_, f) = parse(&mut r)?;
        assert!(r.is_empty(), "trailing bytes");
        Ok(f)
    }

    #[test]
    fn ack_roundtrip() {
        let mut s = RangeSet::new();
        s.insert(0, 3);
        s.insert(5, 6);
        s.insert(10, 20);
        let mut out = Vec::new();
        assert!(put_ack(&mut out, &s, 7, 32));
        match one(&out).unwrap() {
            Frame::Ack { ranges, delay, ecn } => {
                assert_eq!(delay, 7);
                assert!(ecn.is_none());
                assert_eq!(ranges.iter().collect::<Vec<_>>(), vec![(10, 19), (5, 5), (0, 2)]);
                assert_eq!(ranges.smallest(), 0);
            }
            _ => panic!(),
        }
        // Range underflow is a FRAME_ENCODING_ERROR.
        assert_eq!(one(&[0x02, 5, 0, 1, 2, 5, 0]).unwrap_err().code, FRAME_ENCODING_ERROR);
        assert!(one(&[0x02, 1, 0, 0, 2]).is_err());
    }

    #[test]
    fn all_frames_roundtrip() {
        let mut out = Vec::new();
        put_simple(&mut out, PING, &[]);
        put_simple(&mut out, RESET_STREAM, &[4, 9, 100]);
        put_simple(&mut out, STOP_SENDING, &[4, 9]);
        put_crypto(&mut out, 7, b"abc");
        put_new_token(&mut out, b"tok");
        put_stream_header(&mut out, 8, 0, 2, false);
        out.extend_from_slice(b"hi");
        put_stream_header(&mut out, 8, 2, 1, true);
        out.push(b'!');
        put_simple(&mut out, MAX_DATA, &[1000]);
        put_simple(&mut out, MAX_STREAM_DATA, &[4, 1000]);
        put_simple(&mut out, MAX_STREAMS_BIDI, &[10]);
        put_simple(&mut out, MAX_STREAMS_UNI, &[3]);
        put_simple(&mut out, DATA_BLOCKED, &[5]);
        put_simple(&mut out, STREAM_DATA_BLOCKED, &[4, 5]);
        put_simple(&mut out, STREAMS_BLOCKED_BIDI, &[2]);
        put_simple(&mut out, STREAMS_BLOCKED_UNI, &[2]);
        put_new_connection_id(&mut out, 1, 0, &[1, 2, 3, 4], &[7; 16]);
        put_simple(&mut out, RETIRE_CONNECTION_ID, &[1]);
        put_path(&mut out, false, &[1; 8]);
        put_path(&mut out, true, &[2; 8]);
        put_close(&mut out, 0xa, Some(0x08), b"bad");
        put_close(&mut out, 0x100, None, b"");
        put_simple(&mut out, HANDSHAKE_DONE, &[]);
        out.extend_from_slice(&[0, 0, 0]);
        let mut r = Reader::new(&out);
        let mut n = 0;
        while !r.is_empty() {
            parse(&mut r).unwrap();
            n += 1;
        }
        assert_eq!(n, 23);
        // Spot checks.
        assert!(matches!(one(&[0x0b, 4, 2, b'x', b'y']).unwrap(), Frame::Stream { id: 4, offset: 0, fin: true, .. }));
        assert!(matches!(one(&[0x0c, 4, 9]).unwrap(), Frame::Stream { id: 4, offset: 9, fin: false, data: &[] }));
        // Malformed.
        assert!(one(&[0x18, 1, 2, 4, 1, 2, 3, 4]).is_err()); // retire_prior_to > seq
        assert!(one(&[0x18, 1, 0, 21]).is_err()); // CID too long
        assert!(one(&[0x07, 0]).is_err()); // empty token
        assert!(one(&[0x12, 0xd0, 0, 0, 0, 0, 0, 0, 1]).is_err()); // > 2^60 streams
        assert!(one(&[0x1f]).is_err()); // unknown
        assert_eq!(one(&[0x40, 0x01]).unwrap_err().code, PROTOCOL_VIOLATION); // non-minimal type
        assert!(one(&[0x06, 0, 5, 1]).is_err()); // truncated
        assert!(one(&[0x0e, 0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0]).is_err()); // overflow
    }
}
