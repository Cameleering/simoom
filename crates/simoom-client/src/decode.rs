//! Response decompression (`Content-Encoding`).
//!
//! The client advertises `Accept-Encoding` and decodes response bodies through a
//! [`ContentDecoder`]. With the `compress` feature (on by default) the built-in decoder handles
//! `gzip`, `x-gzip` and `deflate` (zlib, or raw DEFLATE as some servers send it) with
//! simoom-compress, streaming and bounded by [`crate::Config::max_body`]. Any other decoder can
//! be installed with [`crate::ClientBuilder::content_decoder`].

#[cfg(feature = "compress")]
use std::io;
use std::io::Read;
use std::sync::Arc;

/// Decodes response bodies by content coding.
pub trait ContentDecoder: Send + Sync {
    /// The `Accept-Encoding` value to send, for example `gzip, deflate`.
    fn accept_encoding(&self) -> &str;
    /// Wraps `body` (bytes in `encoding`, lower case) in a decoding reader, or `None` when the
    /// coding is not supported (the body is then returned undecoded, with its
    /// `Content-Encoding` header). `limit` caps the decoded size (decompression bombs).
    fn decoder(&self, encoding: &str, body: Box<dyn Read + Send>, limit: u64) -> Option<Box<dyn Read + Send>>;
}

/// The built-in decoder, if this build has one.
pub fn builtin() -> Option<Arc<dyn ContentDecoder>> {
    #[cfg(feature = "compress")]
    {
        Some(Arc::new(Gzip))
    }
    #[cfg(not(feature = "compress"))]
    {
        None
    }
}

/// gzip and deflate through simoom-compress.
#[cfg(feature = "compress")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Gzip;

#[cfg(feature = "compress")]
impl ContentDecoder for Gzip {
    fn accept_encoding(&self) -> &str {
        "gzip, deflate"
    }

    fn decoder(&self, encoding: &str, body: Box<dyn Read + Send>, limit: u64) -> Option<Box<dyn Read + Send>> {
        let f = simoom_compress::Format::from_content_encoding(encoding.as_bytes())?;
        Some(Box::new(Inflate { inner: body, dec: simoom_compress::Decoder::with_limit(f, limit), buf: vec![0u8; 16 * 1024], pos: 0, len: 0, eof: false }))
    }
}

/// A streaming inflater over a body reader.
#[cfg(feature = "compress")]
struct Inflate {
    inner: Box<dyn Read + Send>,
    dec: simoom_compress::Decoder,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    eof: bool,
}

#[cfg(feature = "compress")]
impl Read for Inflate {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let bad = |e: simoom_compress::Error| io::Error::new(io::ErrorKind::InvalidData, format!("{e}"));
        loop {
            let (used, written) = self.dec.decode_into(&self.buf[self.pos..self.len], out).map_err(bad)?;
            self.pos += used;
            if written > 0 {
                return Ok(written);
            }
            if self.dec.is_done() && !self.dec.has_pending() {
                return Ok(0);
            }
            if self.pos < self.len {
                if used == 0 {
                    // input left that the decoder does not take: data after the end
                    return if self.dec.is_done() { Ok(0) } else { Err(io::Error::new(io::ErrorKind::InvalidData, "compressed body: no progress")) };
                }
                continue;
            }
            if self.eof {
                self.dec.finish().map_err(bad)?;
                return Ok(0);
            }
            self.pos = 0;
            self.len = self.inner.read(&mut self.buf)?;
            if self.len == 0 {
                self.eof = true;
            }
        }
    }
}
