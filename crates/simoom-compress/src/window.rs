//! The output window shared by the Brotli and zstd decoders: decoded bytes are appended, handed
//! out to the caller, and the buffer slides once it holds two windows, keeping one window of
//! history for back-references.

use crate::{Error, ErrorKind};

/// Why a streamed decoder returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Flow {
    /// It needs more input.
    Need,
    /// The window reached its high-water mark: hand out output, then call again.
    Full,
    /// The stream is complete.
    Done,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Window {
    pub(crate) buf: Vec<u8>,
    /// Bytes of `buf` already handed out.
    pub(crate) flushed: usize,
    /// History to keep when sliding (the format's window size).
    pub(crate) hist: usize,
    /// Bytes handed out so far.
    pub(crate) total_out: u64,
    pub(crate) limit: u64,
    /// One-shot decoding: `buf` is the caller's output, never handed out or slid.
    pub(crate) oneshot: bool,
}

impl Window {
    pub(crate) fn new(limit: u64) -> Window {
        Window { buf: Vec::new(), flushed: 0, hist: 0, total_out: 0, limit, oneshot: false }
    }

    /// Decoding may append until the buffer holds this many bytes.
    pub(crate) fn stop(&self) -> usize {
        if self.oneshot {
            usize::MAX
        } else {
            (2 * self.hist).max(64 * 1024)
        }
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.flushed < self.buf.len()
    }

    /// Fails once the output would pass the limit.
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.total_out + (self.buf.len() - self.flushed) as u64 > self.limit {
            return Err(Error::new(ErrorKind::LimitExceeded, "decompressed data exceeds the limit"));
        }
        Ok(())
    }

    /// Hands out at most `room` pending bytes through `f`.
    pub(crate) fn hand_out(&mut self, room: usize, mut f: impl FnMut(&[u8])) -> Result<usize, Error> {
        self.check()?;
        let n = (self.buf.len() - self.flushed).min(room);
        if n > 0 {
            f(&self.buf[self.flushed..self.flushed + n]);
            self.flushed += n;
            self.total_out += n as u64;
        }
        Ok(n)
    }

    /// Drops all but the last `hist` bytes once everything was handed out and the buffer is
    /// full.
    pub(crate) fn slide(&mut self) {
        if self.buf.len() >= self.stop() && self.flushed == self.buf.len() {
            let d = self.buf.len() - self.hist;
            self.buf.drain(..d);
            self.flushed -= d;
        }
    }
}

/// Copies `len` bytes from `dist` back, overlapping allowed (the caller checked the distance).
#[cfg(feature = "brotli")]
#[inline(always)]
pub(crate) fn copy_back(out: &mut Vec<u8>, dist: usize, len: usize) {
    let start = out.len() - dist;
    if dist >= len {
        out.extend_from_within(start..start + len);
    } else if dist == 1 {
        let b = out[start];
        out.resize(out.len() + len, b);
    } else {
        let mut left = len;
        while left > 0 {
            let n = left.min(out.len() - start);
            out.extend_from_within(start..start + n);
            left -= n;
        }
    }
}

/// Input not yet consumed between calls, for decoders that need whole units (a zstd block, a
/// Brotli step) before they can go on.
#[derive(Clone, Debug, Default)]
pub(crate) struct Carry {
    pub(crate) buf: Vec<u8>,
}

impl Carry {
    /// Runs `f` over the carried bytes followed by `input`; `f` returns how many bytes it used.
    /// Unused bytes are kept for the next call. Returns `f`'s result.
    pub(crate) fn run<T>(&mut self, input: &[u8], f: impl FnOnce(&[u8]) -> (usize, T)) -> T {
        if self.buf.is_empty() {
            let (used, r) = f(input);
            self.buf.extend_from_slice(&input[used..]);
            r
        } else {
            self.buf.extend_from_slice(input);
            let b = std::mem::take(&mut self.buf);
            let (used, r) = f(&b);
            let mut b = b;
            b.drain(..used);
            self.buf = b;
            r
        }
    }
}
