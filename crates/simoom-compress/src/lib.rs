//! DEFLATE (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952) for simoom: std-only, no `unsafe`,
//! streaming in both directions with bounded memory.
//!
//! - [`Decoder`]: table-driven inflate, resumable at any input boundary; output into a `Vec`
//!   ([`Decoder::decode`]) or a slice ([`Decoder::decode_into`]); a total output limit against
//!   decompression bombs ([`Decoder::with_limit`]); multi-member gzip; checksums verified.
//! - [`Encoder`]: hash-chain LZ77 with lazy matching and zlib's levels 0-9, stored, fixed or
//!   dynamic Huffman blocks (whichever is smallest), sync flush for streamed bodies.
//! - One-shot helpers: [`compress`] and [`decompress`].
//! - Checksums: [`crc32`], [`adler32`], incremental [`Crc32`] and [`Adler32`].
//!
//! ```
//! use simoom_compress::{compress, decompress, Decoder, Encoder, Format};
//! let text = b"hello hello hello hello hello hello".repeat(100);
//! let gz = compress(&text, Format::Gzip, 6);
//! assert!(gz.len() < 100);
//! assert_eq!(decompress(&gz, Format::Gzip, 1 << 20).unwrap(), text);
//!
//! // Streaming, in pieces.
//! let mut enc = Encoder::new(Format::Zlib, 6);
//! let mut z = Vec::new();
//! for part in text.chunks(100) {
//!     enc.encode(part, &mut z);
//! }
//! enc.finish(&mut z);
//! let mut dec = Decoder::with_limit(Format::Zlib, 1 << 20);
//! let mut plain = Vec::new();
//! for part in z.chunks(7) {
//!     dec.decode(part, &mut plain).unwrap();
//! }
//! dec.finish().unwrap();
//! assert_eq!(plain, text);
//! ```
//!
//! Brotli and zstd are not implemented: Cameleer supports neither for HTTP (its HTTP producer
//! negotiates `gzip, deflate`, and its Kafka client refuses zstd), so nothing needs them yet.
#![forbid(unsafe_code)]

mod checksum;
mod deflate;
mod inflate;
mod tables;

pub use checksum::{adler32, crc32, Adler32, Crc32};
pub use deflate::Encoder;
pub use inflate::Decoder;

use std::fmt;

/// The container around the DEFLATE data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// Raw DEFLATE, no header or checksum.
    Raw,
    /// zlib: a 2-byte header and an Adler-32 trailer (HTTP's `deflate` coding).
    Zlib,
    /// gzip: a 10-byte (or longer) header and a CRC-32 and length trailer.
    Gzip,
    /// Decoding: zlib if the data starts with a valid zlib header, else raw DEFLATE (some
    /// servers send raw DEFLATE as `Content-Encoding: deflate`). Encoding: zlib.
    ZlibOrRaw,
}

impl Format {
    /// The decoding format for an HTTP content-coding token: `gzip` and `x-gzip` are
    /// [`Format::Gzip`], `deflate` is [`Format::ZlibOrRaw`]. Case-insensitive.
    pub fn from_content_encoding(token: &[u8]) -> Option<Format> {
        if token.eq_ignore_ascii_case(b"gzip") || token.eq_ignore_ascii_case(b"x-gzip") {
            Some(Format::Gzip)
        } else if token.eq_ignore_ascii_case(b"deflate") {
            Some(Format::ZlibOrRaw)
        } else {
            None
        }
    }

    /// The HTTP content-coding token for data in this format (`raw` has none; it is sent as
    /// `deflate` by some servers, but RFC 9110 §8.4.1.2 means zlib).
    pub fn content_encoding(self) -> &'static str {
        match self {
            Format::Gzip => "gzip",
            _ => "deflate",
        }
    }
}

/// What went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The data is not valid for the format.
    Invalid,
    /// A checksum or length in the trailer does not match.
    Checksum,
    /// The data ended before the stream was complete.
    Truncated,
    /// The output would exceed the configured limit.
    LimitExceeded,
}

/// A decoding error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    msg: &'static str,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, msg: &'static str) -> Error {
        Error { kind, msg }
    }

    pub(crate) fn invalid(msg: &'static str) -> Error {
        Error::new(ErrorKind::Invalid, msg)
    }

    /// The kind of error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for Error {}

/// Compresses `data` in one go.
pub fn compress(data: &[u8], format: Format, level: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 3 + 64);
    let mut enc = Encoder::new(format, level);
    enc.encode(data, &mut out);
    enc.finish(&mut out);
    out
}

/// Decompresses `data` in one go; fails if the output would exceed `limit` bytes, if the data
/// is invalid or truncated, or if a checksum does not match.
pub fn decompress(data: &[u8], format: Format, limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(data.len().saturating_mul(3).clamp(256, 1 << 20).min(limit.max(1)));
    Decoder::new(format).decode_all(data, &mut out, limit)?;
    Ok(out)
}

/// Decompresses `data` in one go, appending to `out` (see [`decompress`]).
pub fn decompress_into(data: &[u8], format: Format, limit: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    Decoder::new(format).decode_all(data, out, limit)
}
