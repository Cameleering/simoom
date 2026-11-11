//! The public [`Decoder`] and [`Encoder`]: one API over DEFLATE (raw, zlib, gzip), Brotli
//! (feature `brotli`) and zstd (feature `zstd`).

use crate::deflate::Deflate;
use crate::inflate::Inflate;
use crate::{Error, ErrorKind, Format};

#[cfg(any(feature = "brotli", feature = "zstd"))]
use crate::window::{Flow, Window};

/// A decoder that carries input between calls and decodes into a [`Window`].
#[cfg(any(feature = "brotli", feature = "zstd"))]
trait Streamed {
    fn win(&mut self) -> &mut Window;
    fn win_ref(&self) -> &Window;
    fn run(&mut self, input: &[u8]) -> Result<Flow, Error>;
    fn done(&self) -> bool;
    fn carried(&self) -> usize;
    fn input_total(&self) -> u64;
}

#[cfg(feature = "brotli")]
impl Streamed for crate::brotli::decode::BrotliDecoder {
    fn win(&mut self) -> &mut Window {
        &mut self.win
    }
    fn win_ref(&self) -> &Window {
        &self.win
    }
    fn run(&mut self, input: &[u8]) -> Result<Flow, Error> {
        crate::brotli::decode::BrotliDecoder::run(self, input)
    }
    fn done(&self) -> bool {
        self.is_done()
    }
    fn carried(&self) -> usize {
        crate::brotli::decode::BrotliDecoder::carried(self)
    }
    fn input_total(&self) -> u64 {
        self.total_in
    }
}

#[cfg(feature = "zstd")]
impl Streamed for crate::zstd::decode::ZstdDecoder {
    fn win(&mut self) -> &mut Window {
        &mut self.win
    }
    fn win_ref(&self) -> &Window {
        &self.win
    }
    fn run(&mut self, input: &[u8]) -> Result<Flow, Error> {
        crate::zstd::decode::ZstdDecoder::run(self, input)
    }
    fn done(&self) -> bool {
        self.is_done()
    }
    fn carried(&self) -> usize {
        crate::zstd::decode::ZstdDecoder::carried(self)
    }
    fn input_total(&self) -> u64 {
        self.total_in
    }
}

/// Decodes into a `Vec`; returns the input bytes consumed.
#[cfg(any(feature = "brotli", feature = "zstd"))]
fn drive_vec(s: &mut dyn Streamed, full: &mut bool, input: &[u8], out: &mut Vec<u8>, exact: bool) -> Result<usize, Error> {
    let mut inp = input;
    loop {
        s.win().hand_out(usize::MAX, |b| out.extend_from_slice(b))?;
        s.win().slide();
        let f = s.run(inp)?;
        inp = &[];
        if f != Flow::Full {
            s.win().hand_out(usize::MAX, |b| out.extend_from_slice(b))?;
            *full = false;
            break;
        }
    }
    Ok(if exact && s.done() { input.len().saturating_sub(s.carried()) } else { input.len() })
}

/// One-shot decoding of a whole stream: the decoder's window is `out` itself (decoded in place,
/// no hand-out copies). `out` may hold earlier bytes; streams never refer to them. Only for a
/// fresh decoder without dictionaries.
#[cfg(any(feature = "brotli", feature = "zstd"))]
fn drive_oneshot(s: &mut dyn Streamed, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let w = s.win();
    debug_assert!(w.buf.is_empty() && w.total_out == 0);
    std::mem::swap(&mut w.buf, out);
    let start = w.buf.len();
    w.flushed = start;
    w.oneshot = true;
    let r = s.run(input);
    let w = s.win();
    let r = r.and_then(|_| w.check());
    std::mem::swap(&mut w.buf, out);
    w.oneshot = false;
    w.total_out = (out.len() - start) as u64;
    w.flushed = 0;
    r?;
    if s.done() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Truncated, "compressed data ended early"))
    }
}

/// Decodes into a slice; returns (consumed, written).
#[cfg(any(feature = "brotli", feature = "zstd"))]
fn drive_slice(s: &mut dyn Streamed, full: &mut bool, input: &[u8], out: &mut [u8], exact: bool) -> Result<(usize, usize), Error> {
    let mut inp = input;
    let mut written = 0;
    let mut ran = false;
    loop {
        let room = out.len() - written;
        let n = s.win().hand_out(room, |b| {
            out[written..written + b.len()].copy_from_slice(b);
        })?;
        written += n;
        if s.win_ref().has_pending() || (ran && !*full) {
            break;
        }
        s.win().slide();
        let f = s.run(inp)?;
        inp = &[];
        ran = true;
        *full = f == Flow::Full;
    }
    let used = if exact && s.done() { input.len().saturating_sub(s.carried()) } else { input.len() };
    Ok((used, written))
}

enum DecInner {
    Deflate(Inflate),
    #[cfg(feature = "brotli")]
    Brotli(Box<crate::brotli::decode::BrotliDecoder>),
    #[cfg(feature = "zstd")]
    Zstd(Box<crate::zstd::decode::ZstdDecoder>),
}

/// A streaming decompressor for raw DEFLATE, zlib, gzip, Brotli (feature `brotli`) or zstd
/// (feature `zstd`).
///
/// Feed input with [`Decoder::decode`] (output appended to a `Vec`) or
/// [`Decoder::decode_into`] (output into a slice, for a fixed per-call bound), then call
/// [`Decoder::finish`] once the input has ended to check that the stream was complete.
/// [`Decoder::with_limit`] caps the total output (decompression bombs) and
/// [`Decoder::window_limit`] the history a Brotli or zstd stream may ask for (memory).
///
/// gzip streams may hold several members and zstd streams several frames (and skippable
/// frames), decoded one after another. Bytes after the end that start no member or frame are
/// ignored.
///
/// Memory: DEFLATE keeps a 64 KiB window; Brotli and zstd keep up to twice the stream's window
/// (as it fills: small outputs use little), plus up to one unfinished unit of input (a zstd
/// block, at most 128 KiB; a Brotli prefix code or context map).
pub struct Decoder {
    inner: DecInner,
    format: Format,
    limit: u64,
    window: usize,
    full: bool,
    #[cfg(feature = "zstd")]
    dicts: Vec<crate::zstd::decode::Dict>,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder").field("format", &self.format).field("total_in", &self.total_in()).field("total_out", &self.total_out()).finish()
    }
}

impl Decoder {
    /// A decoder for `format`, without an output limit.
    pub fn new(format: Format) -> Decoder {
        Decoder::with_limit(format, u64::MAX)
    }

    /// A decoder that fails with [`ErrorKind::LimitExceeded`] once the output would pass `limit`
    /// bytes.
    pub fn with_limit(format: Format, limit: u64) -> Decoder {
        let window = match format {
            #[cfg(feature = "brotli")]
            Format::Brotli => crate::brotli::DEFAULT_MAX_WINDOW,
            #[cfg(feature = "zstd")]
            Format::Zstd => crate::zstd::DEFAULT_MAX_WINDOW,
            _ => 32 * 1024,
        };
        Decoder {
            inner: Self::make(format, limit, window),
            format,
            limit,
            window,
            full: false,
            #[cfg(feature = "zstd")]
            dicts: Vec::new(),
        }
    }

    fn make(format: Format, limit: u64, window: usize) -> DecInner {
        let _ = window;
        match format {
            #[cfg(feature = "brotli")]
            Format::Brotli => DecInner::Brotli(Box::new(crate::brotli::decode::BrotliDecoder::new(limit, window))),
            #[cfg(feature = "zstd")]
            Format::Zstd => DecInner::Zstd(Box::new(crate::zstd::decode::ZstdDecoder::new(limit, window))),
            _ => DecInner::Deflate(Inflate::with_limit(format, limit)),
        }
    }

    /// The largest window (history) a Brotli or zstd stream may declare; larger ones fail with
    /// [`ErrorKind::LimitExceeded`]. Defaults: 16 MiB for Brotli (every valid stream), 8 MiB for
    /// zstd (RFC 9659's limit for HTTP). The decoder holds up to twice this. No effect on
    /// DEFLATE (32 KiB by definition).
    pub fn window_limit(mut self, bytes: usize) -> Decoder {
        self.window = bytes;
        self.reset();
        self
    }

    /// Makes a zstd dictionary available: a dictionary in zstd's format (used by frames that
    /// name its id) or raw content (used by frames without a dictionary id).
    #[cfg(feature = "zstd")]
    pub fn add_dictionary(&mut self, dict: &[u8]) -> Result<(), Error> {
        let d = crate::zstd::decode::Dict::parse(dict)?;
        self.dicts.retain(|x| x.id != d.id);
        self.dicts.push(d.clone());
        if let DecInner::Zstd(z) = &mut self.inner {
            z.add_dict(d);
        }
        Ok(())
    }

    /// Starts over with a new stream of the same format and limits.
    pub fn reset(&mut self) {
        match &mut self.inner {
            DecInner::Deflate(d) => d.reset(),
            #[allow(unreachable_patterns)]
            _ => {
                self.inner = Self::make(self.format, self.limit, self.window);
                #[cfg(feature = "zstd")]
                if let DecInner::Zstd(z) = &mut self.inner {
                    for d in &self.dicts {
                        z.add_dict(d.clone());
                    }
                }
            }
        }
        self.full = false;
    }

    /// The format. A [`Format::ZlibOrRaw`] decoder reports [`Format::Zlib`] or [`Format::Raw`]
    /// once it has seen the first bytes.
    pub fn format(&self) -> Format {
        match &self.inner {
            DecInner::Deflate(d) => d.format(),
            #[allow(unreachable_patterns)]
            _ => self.format,
        }
    }

    /// The stream is complete (for gzip and zstd: at least one member or frame is).
    pub fn is_done(&self) -> bool {
        match &self.inner {
            DecInner::Deflate(d) => d.is_done(),
            #[cfg(feature = "brotli")]
            DecInner::Brotli(d) => d.done(),
            #[cfg(feature = "zstd")]
            DecInner::Zstd(d) => d.done(),
        }
    }

    /// Decoded bytes not yet returned by [`Decoder::decode_into`], or carried input that can
    /// produce more without new input.
    pub fn has_pending(&self) -> bool {
        match &self.inner {
            DecInner::Deflate(d) => d.has_pending(),
            #[cfg(feature = "brotli")]
            DecInner::Brotli(d) => d.win_ref().has_pending() || self.full,
            #[cfg(feature = "zstd")]
            DecInner::Zstd(d) => d.win_ref().has_pending() || self.full,
        }
    }

    /// Compressed bytes taken so far.
    pub fn total_in(&self) -> u64 {
        match &self.inner {
            DecInner::Deflate(d) => d.total_in(),
            #[cfg(feature = "brotli")]
            DecInner::Brotli(d) => d.input_total(),
            #[cfg(feature = "zstd")]
            DecInner::Zstd(d) => d.input_total(),
        }
    }

    /// Decompressed bytes returned so far.
    pub fn total_out(&self) -> u64 {
        match &self.inner {
            DecInner::Deflate(d) => d.total_out(),
            #[cfg(feature = "brotli")]
            DecInner::Brotli(d) => d.win_ref().total_out,
            #[cfg(feature = "zstd")]
            DecInner::Zstd(d) => d.win_ref().total_out,
        }
    }

    /// Decodes `input`, appending the output to `out`. Returns the number of input bytes
    /// consumed: all of them, unless the stream ended before.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, Error> {
        match &mut self.inner {
            DecInner::Deflate(d) => d.decode(input, out),
            #[cfg(feature = "brotli")]
            DecInner::Brotli(d) => drive_vec(&mut **d, &mut self.full, input, out, true),
            #[cfg(feature = "zstd")]
            DecInner::Zstd(d) => drive_vec(&mut **d, &mut self.full, input, out, false),
        }
    }

    /// Decodes `input` into `output`. Returns `(consumed, written)`. Stops when `output` is
    /// full; call again with the rest of the input (and with an empty input, while
    /// [`Decoder::has_pending`], to collect the remaining output). Brotli and zstd take all of
    /// the input at once and keep what they can't decode yet.
    pub fn decode_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize), Error> {
        match &mut self.inner {
            DecInner::Deflate(d) => d.decode_into(input, output),
            #[cfg(feature = "brotli")]
            DecInner::Brotli(d) => drive_slice(&mut **d, &mut self.full, input, output, true),
            #[cfg(feature = "zstd")]
            DecInner::Zstd(d) => drive_slice(&mut **d, &mut self.full, input, output, false),
        }
    }

    /// Checks that the stream ended properly: [`ErrorKind::Truncated`] if more input was
    /// expected.
    #[allow(irrefutable_let_patterns)]
    pub fn finish(&mut self) -> Result<(), Error> {
        if let DecInner::Deflate(d) = &mut self.inner {
            return d.finish();
        }
        if self.is_done() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Truncated, "compressed data ended early"))
        }
    }

    /// One-shot DEFLATE decoding into `out` (the output buffer is the history).
    pub(crate) fn decode_all(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
        match &mut self.inner {
            DecInner::Deflate(d) => d.decode_all(input, out, limit),
            #[cfg(feature = "brotli")]
            DecInner::Brotli(d) => drive_oneshot(&mut **d, input, out),
            #[cfg(feature = "zstd")]
            DecInner::Zstd(d) if self.dicts.is_empty() => drive_oneshot(&mut **d, input, out),
            #[allow(unreachable_patterns)]
            _ => {
                let start = out.len();
                self.decode(input, out)?;
                self.finish()?;
                debug_assert!(out.len() - start <= limit);
                Ok(())
            }
        }
    }
}

enum EncInner {
    Deflate(Deflate),
    #[cfg(feature = "brotli")]
    Brotli(Box<crate::brotli::encode::BrotliEncoder>),
    #[cfg(feature = "zstd")]
    Zstd(Box<crate::zstd::encode::ZstdEncoder>),
}

/// A streaming compressor producing raw DEFLATE, zlib, gzip, Brotli (feature `brotli`) or zstd
/// (feature `zstd`).
///
/// [`Encoder::encode`] buffers input and appends compressed bytes to `out` as blocks fill;
/// [`Encoder::flush`] makes everything given so far decodable (DEFLATE: a sync flush; Brotli:
/// the meta-block ends and an empty metadata block byte-aligns; zstd: the block ends);
/// [`Encoder::finish`] ends the stream.
///
/// Levels: DEFLATE 0 (stored) to 9, default 6; Brotli 0 to 11 (its "quality"); zstd 1 to 22
/// (0 means 3, zstd's default). Out-of-range values are clamped.
pub struct Encoder {
    inner: EncInner,
    format: Format,
    level: u32,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder").field("format", &self.format).field("level", &self.level).field("total_in", &self.total_in()).finish()
    }
}

impl Encoder {
    /// An encoder for `format` at `level`. [`Format::ZlibOrRaw`] produces zlib.
    pub fn new(format: Format, level: u32) -> Encoder {
        let format = if format == Format::ZlibOrRaw { Format::Zlib } else { format };
        let inner = match format {
            #[cfg(feature = "brotli")]
            Format::Brotli => EncInner::Brotli(Box::new(crate::brotli::encode::BrotliEncoder::new(level))),
            #[cfg(feature = "zstd")]
            Format::Zstd => EncInner::Zstd(Box::new(crate::zstd::encode::ZstdEncoder::new(if level == 0 { 3 } else { level }))),
            _ => EncInner::Deflate(Deflate::new(format, level)),
        };
        Encoder { inner, format, level }
    }

    /// A DEFLATE encoder (raw, zlib or gzip) whose back-references reach at most `2^bits`
    /// bytes, `bits` 8 to 15: what a peer with a smaller window (WebSocket permessage-deflate's
    /// `max_window_bits`) can decode. Other formats ignore `bits`.
    #[allow(irrefutable_let_patterns)]
    pub fn with_window_bits(format: Format, level: u32, bits: u32) -> Encoder {
        let mut e = Encoder::new(format, level);
        if let EncInner::Deflate(d) = &mut e.inner {
            d.set_window_bits(bits);
        }
        e
    }

    /// Starts a new stream with the same format and level.
    pub fn reset(&mut self) {
        match &mut self.inner {
            EncInner::Deflate(d) => d.reset(),
            #[allow(unreachable_patterns)]
            _ => *self = Encoder::new(self.format, self.level),
        }
    }

    /// The format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Uncompressed bytes taken so far.
    pub fn total_in(&self) -> u64 {
        match &self.inner {
            EncInner::Deflate(d) => d.total_in(),
            #[cfg(feature = "brotli")]
            EncInner::Brotli(e) => e.total_in,
            #[cfg(feature = "zstd")]
            EncInner::Zstd(e) => e.total_in,
        }
    }

    /// [`Encoder::finish`] has been called.
    pub fn is_finished(&self) -> bool {
        match &self.inner {
            EncInner::Deflate(d) => d.is_finished(),
            #[cfg(feature = "brotli")]
            EncInner::Brotli(e) => e.is_finished(),
            #[cfg(feature = "zstd")]
            EncInner::Zstd(e) => e.is_finished(),
        }
    }

    /// Compresses `input`, appending any completed output to `out`.
    pub fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        match &mut self.inner {
            EncInner::Deflate(d) => d.encode(input, out),
            #[cfg(feature = "brotli")]
            EncInner::Brotli(e) => e.encode(input, out),
            #[cfg(feature = "zstd")]
            EncInner::Zstd(e) => e.encode(input, out),
        }
    }

    /// Makes everything given so far decodable from `out`.
    pub fn flush(&mut self, out: &mut Vec<u8>) {
        match &mut self.inner {
            EncInner::Deflate(d) => d.flush(out),
            #[cfg(feature = "brotli")]
            EncInner::Brotli(e) => e.flush(out),
            #[cfg(feature = "zstd")]
            EncInner::Zstd(e) => e.flush(out),
        }
    }

    /// Ends the stream (last block, trailer, checksum). The encoder is then finished until
    /// [`Encoder::reset`].
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        match &mut self.inner {
            EncInner::Deflate(d) => d.finish(out),
            #[cfg(feature = "brotli")]
            EncInner::Brotli(e) => e.finish(out),
            #[cfg(feature = "zstd")]
            EncInner::Zstd(e) => e.finish(out),
        }
    }
}
