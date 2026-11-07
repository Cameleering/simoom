//! Transport error codes (RFC 9000 §20).

use std::fmt;

pub const NO_ERROR: u64 = 0x0;
pub const INTERNAL_ERROR: u64 = 0x1;
pub const CONNECTION_REFUSED: u64 = 0x2;
pub const FLOW_CONTROL_ERROR: u64 = 0x3;
pub const STREAM_LIMIT_ERROR: u64 = 0x4;
pub const STREAM_STATE_ERROR: u64 = 0x5;
pub const FINAL_SIZE_ERROR: u64 = 0x6;
pub const FRAME_ENCODING_ERROR: u64 = 0x7;
pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x8;
pub const CONNECTION_ID_LIMIT_ERROR: u64 = 0x9;
pub const PROTOCOL_VIOLATION: u64 = 0xa;
pub const INVALID_TOKEN: u64 = 0xb;
pub const APPLICATION_ERROR: u64 = 0xc;
pub const CRYPTO_BUFFER_EXCEEDED: u64 = 0xd;
pub const KEY_UPDATE_ERROR: u64 = 0xe;
pub const AEAD_LIMIT_REACHED: u64 = 0xf;
pub const NO_VIABLE_PATH: u64 = 0x10;
/// `CRYPTO_ERROR` base: the TLS alert is added to it.
pub const CRYPTO_ERROR: u64 = 0x100;

/// A connection error: the code, the frame type that caused it (if any) and a reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    pub code: u64,
    pub frame_type: u64,
    pub reason: &'static str,
}

impl TransportError {
    pub const fn new(code: u64, reason: &'static str) -> Self {
        TransportError { code, frame_type: 0, reason }
    }
    pub const fn frame(code: u64, frame_type: u64, reason: &'static str) -> Self {
        TransportError { code, frame_type, reason }
    }
    pub const fn proto(reason: &'static str) -> Self {
        Self::new(PROTOCOL_VIOLATION, reason)
    }
    pub const fn encoding(reason: &'static str) -> Self {
        Self::new(FRAME_ENCODING_ERROR, reason)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport error 0x{:x}: {}", self.code, self.reason)
    }
}

impl std::error::Error for TransportError {}

/// Errors returned by the stream API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The stream does not exist or was already closed.
    UnknownStream,
    /// The operation does not apply to this stream's direction.
    InvalidDirection,
    /// Flow control or the send buffer is full; wait for `Event::StreamWritable`.
    Blocked,
    /// No data available yet; wait for `Event::StreamReadable`.
    WouldBlock,
    /// The peer sent STOP_SENDING with this code.
    Stopped(u64),
    /// The peer reset the stream with this code.
    Reset(u64),
    /// The send side was already finished.
    Finished,
    /// The peer's stream limit is reached; wait for `Event::StreamsAvailable`.
    LimitReached,
    /// The connection is closed.
    ConnectionClosed,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for StreamError {}
