//! QPACK (RFC 9204) for simoom.
//!
//! - [`Decoder`]: bounded dynamic table, blocked streams with a limit, encoder-stream input and
//!   decoder-stream output.
//! - [`Encoder`]: static table only by default; [`Encoder::with_dynamic_table`] enables a
//!   dynamic table that never evicts unacknowledged or referenced entries and respects the
//!   peer's blocked-streams limit.
//! - [`huffman`]: the RFC 7541 Huffman code.
#![forbid(unsafe_code)]

mod decoder;
mod encoder;
pub mod huffman;
mod prim;

pub use decoder::{Decoded, Decoder};
pub use encoder::Encoder;
pub use prim::{put_int, MAX_INT, STATIC_TABLE};

/// One field line: a name and a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Field {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Field { name: name.into(), value: value.into() }
    }

    /// Size of the field for limits and the dynamic table: name + value + 32.
    pub fn size(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64 + 32
    }
}

/// QPACK errors. [`Error::code`] gives the HTTP/3 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// QPACK_DECOMPRESSION_FAILED (0x200).
    DecompressionFailed,
    /// QPACK_ENCODER_STREAM_ERROR (0x201).
    EncoderStream,
    /// QPACK_DECODER_STREAM_ERROR (0x202).
    DecoderStream,
    /// The decoded field section exceeds the configured maximum (RFC 9114 4.2.2). HTTP/3
    /// treats it as a malformed request or response, not a QPACK failure.
    FieldSectionTooLarge,
    /// The section needs dynamic-table entries that have not arrived yet (internal).
    Blocked,
}

impl Error {
    /// HTTP/3 error code for this error.
    pub fn code(&self) -> u64 {
        match self {
            Error::EncoderStream => 0x201,
            Error::DecoderStream => 0x202,
            _ => 0x200,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Error::DecompressionFailed => "QPACK decompression failed",
            Error::EncoderStream => "QPACK encoder stream error",
            Error::DecoderStream => "QPACK decoder stream error",
            Error::FieldSectionTooLarge => "field section too large",
            Error::Blocked => "QPACK field section blocked",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}
