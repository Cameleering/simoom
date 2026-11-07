//! HTTP/2 frame layout (RFC 9113 §4, §6): constants, the 9-byte header, and writers that append
//! frames to an output buffer.

use std::fmt;

/// The client connection preface (RFC 9113 §3.4).
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame header length.
pub const HEADER_LEN: usize = 9;

/// Frame types.
pub mod kind {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// Frame flags.
pub mod flag {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// SETTINGS identifiers.
pub mod setting {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
    pub const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
}

/// Largest flow-control window (RFC 9113 §6.9.1).
pub const MAX_WINDOW: u32 = (1 << 31) - 1;
/// The protocol's initial window (RFC 9113 §6.9.2).
pub const DEFAULT_WINDOW: u32 = 65_535;
/// Smallest and largest SETTINGS_MAX_FRAME_SIZE.
pub const MIN_FRAME_SIZE: u32 = 16_384;
pub const MAX_FRAME_SIZE: u32 = (1 << 24) - 1;

/// HTTP/2 error codes (RFC 9113 §7).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u32);

impl ErrorCode {
    pub const NO_ERROR: ErrorCode = ErrorCode(0x0);
    pub const PROTOCOL_ERROR: ErrorCode = ErrorCode(0x1);
    pub const INTERNAL_ERROR: ErrorCode = ErrorCode(0x2);
    pub const FLOW_CONTROL_ERROR: ErrorCode = ErrorCode(0x3);
    pub const SETTINGS_TIMEOUT: ErrorCode = ErrorCode(0x4);
    pub const STREAM_CLOSED: ErrorCode = ErrorCode(0x5);
    pub const FRAME_SIZE_ERROR: ErrorCode = ErrorCode(0x6);
    pub const REFUSED_STREAM: ErrorCode = ErrorCode(0x7);
    pub const CANCEL: ErrorCode = ErrorCode(0x8);
    pub const COMPRESSION_ERROR: ErrorCode = ErrorCode(0x9);
    pub const CONNECT_ERROR: ErrorCode = ErrorCode(0xa);
    pub const ENHANCE_YOUR_CALM: ErrorCode = ErrorCode(0xb);
    pub const INADEQUATE_SECURITY: ErrorCode = ErrorCode(0xc);
    pub const HTTP_1_1_REQUIRED: ErrorCode = ErrorCode(0xd);

    /// The RFC name of the code.
    pub fn name(self) -> &'static str {
        const NAMES: [&str; 14] = [
            "NO_ERROR",
            "PROTOCOL_ERROR",
            "INTERNAL_ERROR",
            "FLOW_CONTROL_ERROR",
            "SETTINGS_TIMEOUT",
            "STREAM_CLOSED",
            "FRAME_SIZE_ERROR",
            "REFUSED_STREAM",
            "CANCEL",
            "COMPRESSION_ERROR",
            "CONNECT_ERROR",
            "ENHANCE_YOUR_CALM",
            "INADEQUATE_SECURITY",
            "HTTP_1_1_REQUIRED",
        ];
        NAMES.get(self.0 as usize).copied().unwrap_or("UNKNOWN")
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:x})", self.name(), self.0)
    }
}

/// A parsed frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub len: usize,
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
}

impl FrameHeader {
    /// Parses the first 9 bytes of `b` (the reserved bit is ignored, RFC 9113 §4.1).
    #[inline]
    pub fn parse(b: &[u8]) -> FrameHeader {
        FrameHeader {
            len: ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize,
            kind: b[3],
            flags: b[4],
            stream: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
        }
    }

    #[inline]
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// Appends a frame header.
#[inline]
pub fn write_header(out: &mut Vec<u8>, len: usize, kind: u8, flags: u8, stream: u32) {
    let s = (stream & 0x7fff_ffff).to_be_bytes();
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags, s[0], s[1], s[2], s[3]]);
}

/// Rewrites the length and flags of a header written earlier at `at`.
#[inline]
pub(crate) fn patch_header(out: &mut [u8], at: usize, len: usize, flags: u8) {
    out[at] = (len >> 16) as u8;
    out[at + 1] = (len >> 8) as u8;
    out[at + 2] = len as u8;
    out[at + 4] = flags;
}

/// Appends a DATA frame.
pub fn write_data(out: &mut Vec<u8>, stream: u32, data: &[u8], end_stream: bool) {
    write_header(out, data.len(), kind::DATA, if end_stream { flag::END_STREAM } else { 0 }, stream);
    out.extend_from_slice(data);
}

/// Appends a SETTINGS frame.
pub fn write_settings(out: &mut Vec<u8>, values: &[(u16, u32)]) {
    write_header(out, values.len() * 6, kind::SETTINGS, 0, 0);
    for (id, v) in values {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Appends a SETTINGS ACK.
pub fn write_settings_ack(out: &mut Vec<u8>) {
    write_header(out, 0, kind::SETTINGS, flag::ACK, 0);
}

/// Appends a PING.
pub fn write_ping(out: &mut Vec<u8>, data: [u8; 8], ack: bool) {
    write_header(out, 8, kind::PING, if ack { flag::ACK } else { 0 }, 0);
    out.extend_from_slice(&data);
}

/// Appends a GOAWAY.
pub fn write_goaway(out: &mut Vec<u8>, last_stream: u32, code: ErrorCode, debug: &[u8]) {
    write_header(out, 8 + debug.len(), kind::GOAWAY, 0, 0);
    out.extend_from_slice(&(last_stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(&code.0.to_be_bytes());
    out.extend_from_slice(debug);
}

/// Appends a RST_STREAM.
pub fn write_rst(out: &mut Vec<u8>, stream: u32, code: ErrorCode) {
    write_header(out, 4, kind::RST_STREAM, 0, stream);
    out.extend_from_slice(&code.0.to_be_bytes());
}

/// Appends a WINDOW_UPDATE.
pub fn write_window_update(out: &mut Vec<u8>, stream: u32, increment: u32) {
    write_header(out, 4, kind::WINDOW_UPDATE, 0, stream);
    out.extend_from_slice(&(increment & 0x7fff_ffff).to_be_bytes());
}

/// Appends a HEADERS frame and as many CONTINUATION frames as `block` needs at `max_frame`.
pub fn write_headers(out: &mut Vec<u8>, stream: u32, block: &[u8], end_stream: bool, max_frame: usize) {
    let mut chunks = block.chunks(max_frame.max(1));
    let first = chunks.next().unwrap_or(&[]);
    let mut rest = chunks.peekable();
    let mut fl = if end_stream { flag::END_STREAM } else { 0 };
    if rest.peek().is_none() {
        fl |= flag::END_HEADERS;
    }
    write_header(out, first.len(), kind::HEADERS, fl, stream);
    out.extend_from_slice(first);
    while let Some(c) = rest.next() {
        let fl = if rest.peek().is_none() { flag::END_HEADERS } else { 0 };
        write_header(out, c.len(), kind::CONTINUATION, fl, stream);
        out.extend_from_slice(c);
    }
}

/// Reads a big-endian u32.
#[inline]
pub(crate) fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Splits `buf` into complete frames (header, payload); the rest is ignored. For tests and
/// tools.
pub fn split_frames(buf: &[u8]) -> Vec<(FrameHeader, &[u8])> {
    let mut v = Vec::new();
    let mut pos = 0;
    while buf.len() - pos >= HEADER_LEN {
        let h = FrameHeader::parse(&buf[pos..]);
        if buf.len() - pos - HEADER_LEN < h.len {
            break;
        }
        v.push((h, &buf[pos + HEADER_LEN..pos + HEADER_LEN + h.len]));
        pos += HEADER_LEN + h.len;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        let mut o = Vec::new();
        write_data(&mut o, 3, b"hello", true);
        assert_eq!(o, [0, 0, 5, 0, 1, 0, 0, 0, 3, b'h', b'e', b'l', b'l', b'o']);
        let h = FrameHeader::parse(&o);
        assert_eq!(h, FrameHeader { len: 5, kind: kind::DATA, flags: 1, stream: 3 });
        assert!(h.has(flag::END_STREAM));
        o.clear();
        write_window_update(&mut o, 5, 1000);
        assert_eq!(o, [0, 0, 4, 8, 0, 0, 0, 0, 5, 0, 0, 0x03, 0xe8]);
        o.clear();
        write_settings_ack(&mut o);
        assert_eq!(o, [0, 0, 0, 4, 1, 0, 0, 0, 0]);
        o.clear();
        write_goaway(&mut o, 7, ErrorCode::PROTOCOL_ERROR, b"bad");
        assert_eq!(&o[9..], &[0, 0, 0, 7, 0, 0, 0, 1, b'b', b'a', b'd']);
        assert_eq!(ErrorCode::CANCEL.to_string(), "CANCEL (0x8)");
        assert_eq!(format!("{:?}", ErrorCode(99)), "UNKNOWN");
        // the reserved bit is masked
        assert_eq!(FrameHeader::parse(&[0, 0, 0, 0, 0, 0x80, 0, 0, 1]).stream, 1);
    }

    #[test]
    fn headers_split_into_continuations() {
        let block: Vec<u8> = (0..25u8).collect();
        let mut o = Vec::new();
        write_headers(&mut o, 1, &block, true, 10);
        let f = split_frames(&o);
        assert_eq!(f.len(), 3);
        assert_eq!((f[0].0.kind, f[0].0.flags), (kind::HEADERS, flag::END_STREAM));
        assert_eq!((f[1].0.kind, f[1].0.flags), (kind::CONTINUATION, 0));
        assert_eq!((f[2].0.kind, f[2].0.flags), (kind::CONTINUATION, flag::END_HEADERS));
        let joined: Vec<u8> = f.iter().flat_map(|x| x.1.to_vec()).collect();
        assert_eq!(joined, block);
        o.clear();
        write_headers(&mut o, 1, &[1, 2], false, 10);
        assert_eq!(split_frames(&o)[0].0.flags, flag::END_HEADERS);
    }
}
