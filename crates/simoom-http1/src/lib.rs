//! Sans-io, strict HTTP/1.1 parser and serializer (RFC 9112) for simoom.
//!
//! - [`parse_request`] / [`RequestParser`]: zero-copy request heads (borrowed slices, caller-owned
//!   header storage, no allocation), resumable over partial input, strict per RFC 9112.
//! - [`parse_response`]: the same for responses (client side and test tools).
//! - [`BodyDecoder`]: Content-Length, chunked (strict grammar, capped extensions, trailers) and
//!   close-delimited bodies, incremental and zero-copy.
//! - [`write`]: cached `Date`, pre-serialized heads, a head writer, the chunked encoder.
//! - [`h2c`]: the HTTP/2 preface and the `Upgrade: h2c` request.
//! - `ws` (feature `websocket`): the RFC 6455 handshake and frame codec.
//!
//! Pipelining: a parsed head reports its length, the body decoder reports what it consumed, and
//! the next request starts right after; nothing is buffered inside the codec except while a
//! trailer section is incomplete.
#![forbid(unsafe_code)]

mod b64;
mod body;
pub mod h2c;
mod parse;
pub mod write;
#[cfg(feature = "websocket")]
mod sha1;
#[cfg(feature = "websocket")]
pub mod ws;

pub use b64::{base64_decode, base64_encode, base64url_decode};
pub use body::{BodyDecoder, BodyEvent};
pub use parse::{has_token, parse_request, parse_response, parse_trailers, RequestParser};

/// The HTTP version of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
}

/// A header field: borrowed name and value (OWS trimmed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header<'b> {
    /// Field name, as sent.
    pub name: &'b [u8],
    /// Field value without leading and trailing whitespace.
    pub value: &'b [u8],
}

/// An empty header, to initialise header storage: `[EMPTY_HEADER; 100]`.
pub const EMPTY_HEADER: Header<'static> = Header { name: b"", value: b"" };

/// How the message body is delimited (RFC 9112 §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    /// Exactly this many bytes (never zero: a zero length is [`Framing::None`]).
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Until the connection closes (responses only).
    Close,
}

/// The form of a request target (RFC 9112 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetForm {
    /// `/path?query`
    Origin,
    /// `scheme://authority/path?query`
    Absolute,
    /// `host:port`, CONNECT only.
    Authority,
    /// `*`, OPTIONS only.
    Asterisk,
}

/// Result of parsing input that may be incomplete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status<T> {
    /// A whole message head.
    Complete(T),
    /// More bytes are needed.
    Partial,
}

/// A parsed request head. Everything borrows from the receive buffer (`'b`) and the header
/// storage (`'h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'b, 'h> {
    /// The method token.
    pub method: &'b [u8],
    /// The request target, as sent.
    pub target: &'b [u8],
    /// The target's form.
    pub form: TargetForm,
    /// The version.
    pub version: Version,
    /// All header fields in order.
    pub headers: &'h [Header<'b>],
    /// How the body is delimited.
    pub framing: Framing,
    /// Whether the connection may be reused after this exchange (version and `Connection`).
    pub keep_alive: bool,
    /// `Expect: 100-continue` on an HTTP/1.1 request (RFC 9110 §10.1.1).
    pub expect_continue: bool,
    /// The `Upgrade` value when `Connection` names `upgrade` (HTTP/1.1 only).
    pub upgrade: Option<&'b [u8]>,
    /// The `Host` value.
    pub host: Option<&'b [u8]>,
    /// Bytes taken by the head, including leading empty lines and the final CRLF.
    pub head_len: usize,
}

impl<'b> Request<'b, '_> {
    /// The value of the first header named `name` (case-insensitive).
    pub fn header(&self, name: &[u8]) -> Option<&'b [u8]> {
        self.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
    }

    /// True when a `100 Continue` should be sent before reading the body.
    pub fn wants_continue(&self) -> bool {
        self.expect_continue && self.framing != Framing::None
    }
}

/// A parsed response head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'b, 'h> {
    /// The version.
    pub version: Version,
    /// The status code, 100 to 599.
    pub status: u16,
    /// The reason phrase (possibly empty).
    pub reason: &'b [u8],
    /// All header fields in order.
    pub headers: &'h [Header<'b>],
    /// How the body is delimited, given the request method.
    pub framing: Framing,
    /// Whether the connection may be reused.
    pub keep_alive: bool,
    /// The connection now carries another protocol: `101 Switching Protocols`, or a 2xx reply
    /// to CONNECT (a tunnel).
    pub upgraded: bool,
    /// Bytes taken by the head.
    pub head_len: usize,
}

impl<'b> Response<'b, '_> {
    /// The value of the first header named `name` (case-insensitive).
    pub fn header(&self, name: &[u8]) -> Option<&'b [u8]> {
        self.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
    }
}

/// Parser limits (plan §7.1). Exceeding one gives a specific [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Request line (or status line) in bytes, CRLF included. Default 8 KiB.
    pub max_request_line: usize,
    /// Whole head in bytes. Default 16 KiB.
    pub max_head: usize,
    /// Header fields. Default 100.
    pub max_headers: usize,
    /// One header line in bytes, CRLF included. Default 8 KiB.
    pub max_header_line: usize,
    /// Body in bytes; a larger Content-Length is refused before any body byte is read.
    /// Default 10 MiB.
    pub max_body: u64,
    /// A chunk-size line (size, extensions and CRLF) in bytes. Default 1 KiB.
    pub max_chunk_line: usize,
    /// The trailer section in bytes. Default 8 KiB.
    pub max_trailers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_request_line: 8 * 1024,
            max_head: 16 * 1024,
            max_headers: 100,
            max_header_line: 8 * 1024,
            max_body: 10 * 1024 * 1024,
            max_chunk_line: 1024,
            max_trailers: 8 * 1024,
        }
    }
}

/// Why a message was refused. Every error means the connection must close after the error
/// response (if any) is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The method is empty or has a byte outside `tchar`, or is not followed by one SP.
    InvalidMethod,
    /// The request target has a forbidden byte, bad percent-encoding, or the wrong form for the
    /// method.
    InvalidTarget,
    /// The version is not `HTTP/` digit `.` digit, or the start line has extra bytes.
    InvalidVersion,
    /// A well-formed version other than 1.0 and 1.1.
    VersionNotSupported,
    /// The request line passed [`Limits::max_request_line`].
    RequestLineTooLong,
    /// The head passed [`Limits::max_head`].
    HeadTooLarge,
    /// More than [`Limits::max_headers`] fields, or more than the header storage holds.
    TooManyHeaders,
    /// A header line passed [`Limits::max_header_line`].
    HeaderLineTooLong,
    /// A field name is empty or has a byte outside `tchar`.
    InvalidHeaderName,
    /// A field value has a control byte other than HTAB.
    InvalidHeaderValue,
    /// Whitespace between a field name and the colon (RFC 9112 §5.1).
    WhitespaceBeforeColon,
    /// A line starting with whitespace: obs-fold, or whitespace after the start line.
    ObsFold,
    /// CR not followed by LF.
    BareCr,
    /// LF not preceded by CR.
    BareLf,
    /// An HTTP/1.1 request without `Host`.
    MissingHost,
    /// More than one `Host`.
    DuplicateHost,
    /// A `Host` value that is not `uri-host [":" port]`.
    InvalidHost,
    /// Both `Transfer-Encoding` and `Content-Length`.
    TeWithContentLength,
    /// More than one `Content-Length` value, equal or not.
    DuplicateContentLength,
    /// A `Content-Length` that is not 1*DIGIT within 64 bits.
    InvalidContentLength,
    /// A malformed `Transfer-Encoding` list (empty elements, non-token codings, parameters).
    InvalidTransferEncoding,
    /// `Transfer-Encoding` whose final coding is not `chunked`, or `chunked` twice.
    ChunkedNotFinal,
    /// Codings before the final `chunked` (they are not implemented).
    UnsupportedTransferCoding,
    /// `Transfer-Encoding` in an HTTP/1.0 request.
    TransferEncodingHttp10,
    /// The body passed [`Limits::max_body`].
    BodyTooLarge,
    /// An `Expect` value other than `100-continue`.
    ExpectationFailed,
    /// A duplicate `Upgrade` field.
    DuplicateUpgrade,
    /// A chunk size that is not 1*HEXDIG.
    InvalidChunkSize,
    /// A chunk size beyond 64 bits.
    ChunkSizeOverflow,
    /// A chunk extension that breaks the RFC 9112 §7.1.1 grammar.
    InvalidChunkExtension,
    /// A chunk-size line longer than [`Limits::max_chunk_line`].
    ChunkLineTooLong,
    /// Chunk data not followed by CRLF.
    MissingChunkCrlf,
    /// The trailer section passed [`Limits::max_trailers`].
    TrailersTooLarge,
    /// A trailer field that may not be a trailer (`Content-Length`, `Transfer-Encoding`,
    /// `Host`).
    ForbiddenTrailer,
    /// The connection closed inside a body.
    UnexpectedEof,
    /// A status code that is not three digits from 100 to 599.
    InvalidStatus,
    /// A reason phrase with a control byte.
    InvalidReason,
    /// A writer was asked to emit `Content-Length` or `Transfer-Encoding` as a plain field;
    /// use the framing methods instead.
    FramingHeader,
}

impl Error {
    /// The response status for this error, when it happens on a request.
    pub fn status(self) -> u16 {
        use Error::*;
        match self {
            RequestLineTooLong => 414,
            HeadTooLarge | TooManyHeaders | HeaderLineTooLong => 431,
            VersionNotSupported => 505,
            UnsupportedTransferCoding => 501,
            BodyTooLarge => 413,
            ExpectationFailed => 417,
            _ => 400,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}
