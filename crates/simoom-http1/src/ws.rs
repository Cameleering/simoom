//! WebSocket (RFC 6455): handshake validation and a sans-io frame codec.
//!
//! The decoder unmasks in place and streams data-frame payloads as they arrive (no frame is
//! buffered whole except control frames, at most 131 bytes). It checks reserved bits, opcodes,
//! masking direction, minimal length encoding, control-frame rules, fragmentation order,
//! close codes, UTF-8 of text messages across fragments, and frame and message size limits.
//! Extensions: permessage-deflate (RFC 7692) with the `permessage-deflate` feature
//! ([`deflate`]); without a negotiated extension the RSV bits must be zero.

use crate::parse::has_token;
use crate::sha1::sha1;
use crate::write::HeadWriter;
use crate::{base64_decode, base64_encode, Error, Framing, Request, Response, Version};

/// The GUID from RFC 6455 §1.3.
pub const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The `426` reply for an unsupported `Sec-WebSocket-Version`.
pub const VERSION_REQUIRED: &[u8] =
    b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n";

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key`.
pub fn accept_key(key: &[u8]) -> [u8; 28] {
    let mut out = Vec::with_capacity(28);
    base64_encode(&sha1(&[key, GUID]), &mut out);
    let mut a = [0u8; 28];
    a.copy_from_slice(&out);
    a
}

/// Why an upgrade request is not a valid WebSocket opening handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// Not a GET.
    NotGet,
    /// Not HTTP/1.1.
    NotHttp11,
    /// No `Upgrade: websocket` with `Connection: upgrade`.
    NotUpgrade,
    /// `Sec-WebSocket-Version` missing, repeated or not 13: reply with [`VERSION_REQUIRED`].
    BadVersion,
    /// `Sec-WebSocket-Key` missing, repeated, or not 16 bytes of base64.
    BadKey,
    /// The request has a body.
    HasBody,
}

impl HandshakeError {
    /// The reply status: 426 for a version mismatch, 400 otherwise.
    pub fn status(self) -> u16 {
        if self == HandshakeError::BadVersion {
            426
        } else {
            400
        }
    }
}

/// A valid opening handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handshake<'b> {
    /// `Sec-WebSocket-Key` as sent.
    pub key: &'b [u8],
    /// `Sec-WebSocket-Protocol` (first field), if any.
    pub protocols: Option<&'b [u8]>,
    /// `Sec-WebSocket-Extensions` (first field), if any; none are supported.
    pub extensions: Option<&'b [u8]>,
    /// The `Sec-WebSocket-Accept` value.
    pub accept: [u8; 28],
}

fn single<'b>(req: &Request<'b, '_>, name: &[u8]) -> Option<&'b [u8]> {
    let mut it = req.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    match (it.next(), it.next()) {
        (Some(h), None) => Some(h.value),
        _ => None,
    }
}

/// Checks a request against RFC 6455 §4.2.1.
pub fn validate_handshake<'b>(req: &Request<'b, '_>) -> Result<Handshake<'b>, HandshakeError> {
    if req.method != b"GET" {
        return Err(HandshakeError::NotGet);
    }
    if req.version != Version::Http11 {
        return Err(HandshakeError::NotHttp11);
    }
    if !req.upgrade.is_some_and(|u| has_token(u, b"websocket")) {
        return Err(HandshakeError::NotUpgrade);
    }
    if single(req, b"sec-websocket-version") != Some(b"13") {
        return Err(HandshakeError::BadVersion);
    }
    let key = single(req, b"sec-websocket-key").ok_or(HandshakeError::BadKey)?;
    let mut raw = Vec::with_capacity(18);
    if key.len() != 24 || !base64_decode(key, &mut raw) || raw.len() != 16 {
        return Err(HandshakeError::BadKey);
    }
    if req.framing != Framing::None {
        return Err(HandshakeError::HasBody);
    }
    Ok(Handshake {
        key,
        protocols: req.header(b"sec-websocket-protocol"),
        extensions: req.header(b"sec-websocket-extensions"),
        accept: accept_key(key),
    })
}

/// Appends the `101` reply, choosing `protocol` (which must be one the client offered).
pub fn write_accept(out: &mut Vec<u8>, hs: &Handshake<'_>, protocol: Option<&[u8]>) -> Result<(), Error> {
    write_accept_with(out, hs, protocol, None)
}

/// [`write_accept`] with a `Sec-WebSocket-Extensions` value (from [`deflate::negotiate`]).
pub fn write_accept_with(out: &mut Vec<u8>, hs: &Handshake<'_>, protocol: Option<&[u8]>, extensions: Option<&[u8]>) -> Result<(), Error> {
    let mut w = HeadWriter::response(out, 101);
    w.header(b"Upgrade", b"websocket")?.header(b"Connection", b"Upgrade")?.header(b"Sec-WebSocket-Accept", &hs.accept)?;
    if let Some(p) = protocol {
        w.header(b"Sec-WebSocket-Protocol", p)?;
    }
    if let Some(e) = extensions {
        w.header(b"Sec-WebSocket-Extensions", e)?;
    }
    w.finish();
    Ok(())
}

/// Client side: true if `resp` accepts the handshake started with `key`.
pub fn validate_response(resp: &Response<'_, '_>, key: &[u8]) -> bool {
    let has = |name: &[u8], token: &[u8]| {
        resp.headers.iter().any(|h| h.name.eq_ignore_ascii_case(name) && has_token(h.value, token))
    };
    resp.status == 101
        && has(b"upgrade", b"websocket")
        && has(b"connection", b"upgrade")
        && resp.header(b"sec-websocket-accept") == Some(&accept_key(key)[..])
}

/// Frame opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    /// Continuation of a fragmented message.
    Continuation = 0,
    /// Text (UTF-8).
    Text = 1,
    /// Binary.
    Binary = 2,
    /// Close.
    Close = 8,
    /// Ping.
    Ping = 9,
    /// Pong.
    Pong = 10,
}

/// Which end this codec is: a server expects masked frames, a client unmasked ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Receives frames from a client.
    Server,
    /// Receives frames from a server.
    Client,
}

/// Size limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsLimits {
    /// Largest frame payload. Default 16 MiB.
    pub max_frame: u64,
    /// Largest message (all fragments). Default 16 MiB.
    pub max_message: u64,
}

impl Default for WsLimits {
    fn default() -> Self {
        WsLimits { max_frame: 16 << 20, max_message: 16 << 20 }
    }
}

/// A protocol violation; the connection must be closed with [`WsError::close_code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsError {
    /// RSV1-3 set without a negotiated extension.
    ReservedBits,
    /// A reserved opcode.
    BadOpcode,
    /// A frame from a client without a mask.
    Unmasked,
    /// A frame from a server with a mask.
    Masked,
    /// A control frame without FIN.
    FragmentedControl,
    /// A control frame payload over 125 bytes.
    ControlTooLong,
    /// A length not in its shortest encoding, or with the top bit set.
    BadLength,
    /// A frame over [`WsLimits::max_frame`].
    FrameTooLarge,
    /// A message over [`WsLimits::max_message`].
    MessageTooLarge,
    /// A continuation frame with no message in progress.
    UnexpectedContinuation,
    /// A new data frame while a fragmented message is in progress.
    ExpectedContinuation,
    /// Text that is not UTF-8.
    InvalidUtf8,
    /// A close payload of one byte, or a code that may not be sent.
    InvalidClose,
    /// A frame after a Close.
    AfterClose,
    /// A compressed message that doesn't inflate (permessage-deflate).
    Compression,
}

impl WsError {
    /// The close code to send: 1007 for UTF-8, 1009 for size, 1002 for the rest.
    pub fn close_code(self) -> u16 {
        match self {
            WsError::InvalidUtf8 | WsError::Compression => 1007,
            WsError::FrameTooLarge | WsError::MessageTooLarge => 1009,
            _ => 1002,
        }
    }
}

/// One decoded event.
#[derive(Debug, PartialEq, Eq)]
pub enum WsEvent<'a> {
    /// A piece of a data message, unmasked. `fin` marks the message's last piece; `text` tells
    /// the message type. Pieces of a text message may split a UTF-8 sequence; the message as a
    /// whole is checked.
    Data {
        /// Text (true) or binary message.
        text: bool,
        /// The bytes.
        payload: &'a [u8],
        /// Last piece of the message.
        fin: bool,
    },
    /// A ping; answer with a pong carrying the same payload.
    Ping(&'a [u8]),
    /// A pong.
    Pong(&'a [u8]),
    /// A close, with the code and reason if present; answer with a close and stop.
    Close {
        /// The status code.
        code: Option<u16>,
        /// The reason, UTF-8.
        reason: &'a str,
    },
    /// More bytes are needed.
    NeedMore,
}

/// Incremental UTF-8 validation that can stop mid-sequence.
#[derive(Clone, Copy, Debug, Default)]
struct Utf8 {
    need: u8,
    lo: u8,
    hi: u8,
}

impl Utf8 {
    fn feed(&mut self, bytes: &[u8]) -> bool {
        let mut i = 0;
        while i < bytes.len() {
            if self.need == 0 {
                if i + 8 <= bytes.len() {
                    let w = u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap_or([0; 8]));
                    if w & 0x8080_8080_8080_8080 == 0 {
                        i += 8;
                        continue;
                    }
                }
                let b = bytes[i];
                let (need, lo, hi) = match b {
                    0x00..=0x7f => (0, 0x80, 0xbf),
                    0xc2..=0xdf => (1, 0x80, 0xbf),
                    0xe0 => (2, 0xa0, 0xbf),
                    0xe1..=0xec | 0xee | 0xef => (2, 0x80, 0xbf),
                    0xed => (2, 0x80, 0x9f),
                    0xf0 => (3, 0x90, 0xbf),
                    0xf1..=0xf3 => (3, 0x80, 0xbf),
                    0xf4 => (3, 0x80, 0x8f),
                    _ => return false,
                };
                *self = Utf8 { need, lo, hi };
            } else {
                let b = bytes[i];
                if b < self.lo || b > self.hi {
                    return false;
                }
                *self = Utf8 { need: self.need - 1, lo: 0x80, hi: 0xbf };
            }
            i += 1;
        }
        true
    }
}

/// XORs `data` with the mask `key`, starting at byte `offset` of the key stream.
pub fn apply_mask(data: &mut [u8], key: [u8; 4], offset: usize) {
    let k = [key[offset & 3], key[(offset + 1) & 3], key[(offset + 2) & 3], key[(offset + 3) & 3]];
    let k8 = u64::from_ne_bytes([k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3]]);
    let mut chunks = data.chunks_exact_mut(8);
    for c in &mut chunks {
        let v = u64::from_ne_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) ^ k8;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= k[i & 3];
    }
}

fn close_code_ok(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// The frame decoder for one connection.
#[derive(Clone, Debug)]
pub struct FrameDecoder {
    role: Role,
    limits: WsLimits,
    /// Payload bytes left in the current data frame (0 between frames).
    remaining: u64,
    frame_fin: bool,
    mask: Option<[u8; 4]>,
    mask_pos: u8,
    in_message: bool,
    text: bool,
    message_len: u64,
    utf8: Utf8,
    closed: bool,
    /// permessage-deflate is in use: RSV1 marks a compressed message.
    rsv1_ok: bool,
    /// The current message is compressed (its text is checked after inflating).
    compressed: bool,
}

impl FrameDecoder {
    /// Accepts RSV1 on the first frame of a data message (permessage-deflate negotiated).
    pub fn set_permessage_deflate(&mut self, on: bool) {
        self.rsv1_ok = on;
    }

    /// The message whose pieces are being returned has RSV1 set: inflate it (RFC 7692 §6.2).
    /// UTF-8 is then not checked here: check the inflated text.
    pub fn message_compressed(&self) -> bool {
        self.compressed
    }

    /// A decoder for `role` with `limits`.
    pub fn new(role: Role, limits: WsLimits) -> Self {
        FrameDecoder {
            role,
            limits,
            remaining: 0,
            frame_fin: false,
            mask: None,
            mask_pos: 0,
            in_message: false,
            text: false,
            message_len: 0,
            utf8: Utf8::default(),
            closed: false,
            rsv1_ok: false,
            compressed: false,
        }
    }

    /// Decodes from `buf`, unmasking in place; returns the bytes used and the event. With
    /// `NeedMore`, keep the unused bytes and call again with more.
    pub fn decode<'a>(&mut self, buf: &'a mut [u8]) -> Result<(usize, WsEvent<'a>), WsError> {
        if self.closed {
            return if buf.is_empty() { Ok((0, WsEvent::NeedMore)) } else { Err(WsError::AfterClose) };
        }
        if self.remaining > 0 {
            return self.payload(buf, 0);
        }
        let [b0, b1, ..] = *buf else { return Ok((0, WsEvent::NeedMore)) };
        let fin = b0 & 0x80 != 0;
        let rsv1 = b0 & 0x40 != 0;
        if b0 & 0x30 != 0 || (rsv1 && (!self.rsv1_ok || !matches!(b0 & 0x0f, 1 | 2))) {
            return Err(WsError::ReservedBits);
        }
        let opcode = match b0 & 0x0f {
            0 => Opcode::Continuation,
            1 => Opcode::Text,
            2 => Opcode::Binary,
            8 => Opcode::Close,
            9 => Opcode::Ping,
            10 => Opcode::Pong,
            _ => return Err(WsError::BadOpcode),
        };
        let masked = b1 & 0x80 != 0;
        match (self.role, masked) {
            (Role::Server, false) => return Err(WsError::Unmasked),
            (Role::Client, true) => return Err(WsError::Masked),
            _ => {}
        }
        let len7 = b1 & 0x7f;
        let control = (opcode as u8) & 0x08 != 0;
        if control {
            if !fin {
                return Err(WsError::FragmentedControl);
            }
            if len7 > 125 {
                return Err(WsError::ControlTooLong);
            }
        }
        let ext = match len7 {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let hlen = 2 + ext + if masked { 4 } else { 0 };
        if buf.len() < hlen {
            return Ok((0, WsEvent::NeedMore));
        }
        let len = match ext {
            2 => {
                let n = u64::from(u16::from_be_bytes([buf[2], buf[3]]));
                if n < 126 {
                    return Err(WsError::BadLength);
                }
                n
            }
            8 => {
                let n = u64::from_be_bytes([buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]]);
                if n <= 0xffff || n >> 63 != 0 {
                    return Err(WsError::BadLength);
                }
                n
            }
            _ => u64::from(len7),
        };
        let mask = masked.then(|| [buf[hlen - 4], buf[hlen - 3], buf[hlen - 2], buf[hlen - 1]]);
        if control {
            let end = hlen + len as usize;
            if buf.len() < end {
                return Ok((0, WsEvent::NeedMore));
            }
            let payload = &mut buf[hlen..end];
            if let Some(k) = mask {
                apply_mask(payload, k, 0);
            }
            let payload = &*payload;
            let ev = match opcode {
                Opcode::Ping => WsEvent::Ping(payload),
                Opcode::Pong => WsEvent::Pong(payload),
                _ => {
                    self.closed = true;
                    match payload {
                        [] => WsEvent::Close { code: None, reason: "" },
                        [_] => return Err(WsError::InvalidClose),
                        [hi, lo, reason @ ..] => {
                            let code = u16::from_be_bytes([*hi, *lo]);
                            if !close_code_ok(code) {
                                return Err(WsError::InvalidClose);
                            }
                            let reason = std::str::from_utf8(reason).map_err(|_| WsError::InvalidUtf8)?;
                            WsEvent::Close { code: Some(code), reason }
                        }
                    }
                }
            };
            return Ok((end, ev));
        }
        if len > self.limits.max_frame {
            return Err(WsError::FrameTooLarge);
        }
        match (opcode, self.in_message) {
            (Opcode::Continuation, false) => return Err(WsError::UnexpectedContinuation),
            (Opcode::Text | Opcode::Binary, true) => return Err(WsError::ExpectedContinuation),
            (Opcode::Continuation, true) => {}
            _ => {
                self.in_message = true;
                self.text = opcode == Opcode::Text;
                self.message_len = 0;
                self.utf8 = Utf8::default();
                self.compressed = rsv1;
            }
        }
        self.message_len += len;
        if self.message_len > self.limits.max_message {
            return Err(WsError::MessageTooLarge);
        }
        self.remaining = len;
        self.frame_fin = fin;
        self.mask = mask;
        self.mask_pos = 0;
        if len == 0 {
            return self.finish_piece(hlen, &buf[..0]);
        }
        self.payload(buf, hlen)
    }

    fn payload<'a>(&mut self, buf: &'a mut [u8], at: usize) -> Result<(usize, WsEvent<'a>), WsError> {
        let avail = buf.len() - at;
        if avail == 0 {
            return Ok((at, WsEvent::NeedMore));
        }
        let n = self.remaining.min(avail as u64) as usize;
        let piece = &mut buf[at..at + n];
        if let Some(k) = self.mask {
            apply_mask(piece, k, usize::from(self.mask_pos));
            self.mask_pos = ((usize::from(self.mask_pos) + n) & 3) as u8;
        }
        if self.text && !self.compressed && !self.utf8.feed(piece) {
            return Err(WsError::InvalidUtf8);
        }
        self.remaining -= n as u64;
        self.finish_piece(at + n, piece)
    }

    fn finish_piece<'a>(&mut self, used: usize, piece: &'a [u8]) -> Result<(usize, WsEvent<'a>), WsError> {
        let fin = self.remaining == 0 && self.frame_fin;
        if fin {
            if self.text && !self.compressed && self.utf8.need != 0 {
                return Err(WsError::InvalidUtf8);
            }
            self.in_message = false;
        }
        Ok((used, WsEvent::Data { text: self.text, payload: piece, fin }))
    }
}

/// Writes a frame header into `out`; returns its length (2 to 14 bytes). Clients must pass a
/// fresh random `mask` per frame and mask the payload with [`apply_mask`]; servers pass `None`.
pub fn encode_header(out: &mut [u8; 14], fin: bool, opcode: Opcode, len: u64, mask: Option<[u8; 4]>) -> usize {
    out[0] = (u8::from(fin) << 7) | opcode as u8;
    let m = if mask.is_some() { 0x80 } else { 0 };
    let mut n = if len < 126 {
        out[1] = m | len as u8;
        2
    } else if len <= 0xffff {
        out[1] = m | 126;
        out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        4
    } else {
        out[1] = m | 127;
        out[2..10].copy_from_slice(&len.to_be_bytes());
        10
    };
    if let Some(k) = mask {
        out[n..n + 4].copy_from_slice(&k);
        n += 4;
    }
    n
}

/// Appends a whole frame (masked when `mask` is given).
pub fn write_frame(out: &mut Vec<u8>, fin: bool, opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>) {
    let mut h = [0u8; 14];
    let n = encode_header(&mut h, fin, opcode, payload.len() as u64, mask);
    out.extend_from_slice(&h[..n]);
    let start = out.len();
    out.extend_from_slice(payload);
    if let Some(k) = mask {
        apply_mask(&mut out[start..], k, 0);
    }
}

/// Appends a Close frame; `reason` must fit (at most 123 bytes) and `code` must be sendable.
pub fn write_close(out: &mut Vec<u8>, code: u16, reason: &str, mask: Option<[u8; 4]>) -> bool {
    if reason.len() > 123 || !close_code_ok(code) {
        return false;
    }
    let mut p = [0u8; 125];
    p[..2].copy_from_slice(&code.to_be_bytes());
    p[2..2 + reason.len()].copy_from_slice(reason.as_bytes());
    write_frame(out, true, Opcode::Close, &p[..2 + reason.len()], mask);
    true
}

/// [`write_frame`] for a compressed (permessage-deflate) message: RSV1 set on this, its first
/// frame.
pub fn write_frame_compressed(out: &mut Vec<u8>, fin: bool, opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>) {
    let at = out.len();
    write_frame(out, fin, opcode, payload, mask);
    out[at] |= 0x40;
}

#[cfg(feature = "permessage-deflate")]
pub mod deflate;
