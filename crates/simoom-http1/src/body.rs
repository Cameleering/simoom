//! Incremental, zero-copy body decoding: Content-Length, chunked (RFC 9112 §7.1) and
//! close-delimited.

use crate::parse::check_trailers;
use crate::{Error, Framing, Limits};
use simoom_sys::scan::{find_byte, TCHAR};

/// One step of body decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyEvent<'a> {
    /// Body bytes, borrowed from the input.
    Data(&'a [u8]),
    /// The body is complete. For a chunked body with trailers this is the raw trailer section
    /// (field lines and the final empty line), ready for [`parse_trailers`](crate::parse_trailers);
    /// otherwise it is empty.
    End(&'a [u8]),
    /// All input was used; call again with more.
    NeedMore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Length,
    Close,
    Done,
    Size0,
    Size,
    ExtPreSemi,
    ExtNameStart,
    ExtName,
    ExtNameEnd,
    ExtValStart,
    ExtTok,
    ExtQuoted,
    ExtQuotedEsc,
    ExtAfterQuote,
    SizeLf,
    Data,
    DataCr,
    DataLf,
    Trailers,
}

/// Decodes one message body from successive pieces of input.
///
/// Each call returns how many input bytes it used and one event. Data comes back as slices of
/// the input; chunk-size lines are consumed as they arrive (no buffering), and only an
/// incomplete trailer section is left in the input (`consumed` stops before it) until it is
/// whole, up to [`Limits::max_trailers`].
#[derive(Clone, Debug)]
pub struct BodyDecoder {
    state: St,
    remaining: u64,
    received: u64,
    limit: u64,
    line: u32,
    max_line: u32,
    scanned: u32,
    max_trailers: u32,
    max_headers: u32,
    max_header_line: u32,
}

#[inline]
fn hexval(b: u8) -> Option<u64> {
    match b {
        b'0'..=b'9' => Some(u64::from(b - b'0')),
        b'a'..=b'f' => Some(u64::from(b - b'a' + 10)),
        b'A'..=b'F' => Some(u64::from(b - b'A' + 10)),
        _ => None,
    }
}

#[inline]
fn ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn clamp(n: usize) -> u32 {
    n.min(u32::MAX as usize) as u32
}

impl BodyDecoder {
    /// A decoder for a body with this framing; `lim` gives the body, chunk-line and trailer
    /// limits.
    pub fn new(framing: Framing, lim: &Limits) -> Self {
        let (state, remaining) = match framing {
            Framing::None => (St::Done, 0),
            Framing::Length(n) => (St::Length, n),
            Framing::Chunked => (St::Size0, 0),
            Framing::Close => (St::Close, 0),
        };
        BodyDecoder {
            state,
            remaining,
            received: 0,
            limit: lim.max_body,
            line: 0,
            max_line: clamp(lim.max_chunk_line),
            scanned: 0,
            max_trailers: clamp(lim.max_trailers),
            max_headers: clamp(lim.max_headers),
            max_header_line: clamp(lim.max_header_line),
        }
    }

    /// True once the whole body (and any trailers) was decoded.
    pub fn is_done(&self) -> bool {
        self.state == St::Done
    }

    /// The connection closed: fine for a close-delimited body, an error inside any other.
    pub fn eof(&mut self) -> Result<(), Error> {
        match self.state {
            St::Close | St::Done => {
                self.state = St::Done;
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
    }

    /// Decodes from `input`; returns the bytes used and what they produced.
    pub fn decode<'a>(&mut self, input: &'a [u8]) -> Result<(usize, BodyEvent<'a>), Error> {
        match self.state {
            St::Done => return Ok((0, BodyEvent::End(&[]))),
            St::Length => {
                if self.remaining > self.limit {
                    return Err(Error::BodyTooLarge);
                }
                if input.is_empty() {
                    return Ok((0, BodyEvent::NeedMore));
                }
                let n = self.remaining.min(input.len() as u64) as usize;
                self.remaining -= n as u64;
                if self.remaining == 0 {
                    self.state = St::Done;
                }
                return Ok((n, BodyEvent::Data(&input[..n])));
            }
            St::Close => {
                if input.is_empty() {
                    return Ok((0, BodyEvent::NeedMore));
                }
                self.received += input.len() as u64;
                if self.received > self.limit {
                    return Err(Error::BodyTooLarge);
                }
                return Ok((input.len(), BodyEvent::Data(input)));
            }
            _ => {}
        }
        let mut i = 0;
        loop {
            match self.state {
                St::Data => {
                    if i == input.len() {
                        return Ok((i, BodyEvent::NeedMore));
                    }
                    let n = self.remaining.min((input.len() - i) as u64) as usize;
                    self.remaining -= n as u64;
                    if self.remaining == 0 {
                        self.state = St::DataCr;
                    }
                    return Ok((i + n, BodyEvent::Data(&input[i..i + n])));
                }
                St::Trailers => return self.trailers(input, i),
                St::Done => return Ok((i, BodyEvent::End(&[]))),
                _ => {}
            }
            let Some(&b) = input.get(i) else { return Ok((i, BodyEvent::NeedMore)) };
            i += 1;
            self.step(b)?;
        }
    }

    fn step(&mut self, b: u8) -> Result<(), Error> {
        use St::*;
        if !matches!(self.state, DataCr | DataLf) {
            self.line += 1;
            if self.line > self.max_line {
                return Err(Error::ChunkLineTooLong);
            }
        }
        let ext = Error::InvalidChunkExtension;
        let tchar = TCHAR.contains(b);
        self.state = match self.state {
            Size0 => {
                self.remaining = hexval(b).ok_or(Error::InvalidChunkSize)?;
                Size
            }
            Size => match (hexval(b), b) {
                (Some(v), _) => {
                    if self.remaining >> 60 != 0 {
                        return Err(Error::ChunkSizeOverflow);
                    }
                    self.remaining = self.remaining << 4 | v;
                    Size
                }
                (_, b';') => ExtNameStart,
                (_, b'\r') => SizeLf,
                (_, b) if ws(b) => ExtPreSemi,
                _ => return Err(Error::InvalidChunkSize),
            },
            ExtPreSemi => match b {
                b';' => ExtNameStart,
                b if ws(b) => ExtPreSemi,
                _ => return Err(ext),
            },
            ExtNameStart => match b {
                b if ws(b) => ExtNameStart,
                _ if tchar => ExtName,
                _ => return Err(ext),
            },
            ExtName => match b {
                _ if tchar => ExtName,
                b';' => ExtNameStart,
                b'=' => ExtValStart,
                b'\r' => SizeLf,
                b if ws(b) => ExtNameEnd,
                _ => return Err(ext),
            },
            ExtNameEnd => match b {
                b'=' => ExtValStart,
                b';' => ExtNameStart,
                b if ws(b) => ExtNameEnd,
                _ => return Err(ext),
            },
            ExtValStart => match b {
                b'"' => ExtQuoted,
                b if ws(b) => ExtValStart,
                _ if tchar => ExtTok,
                _ => return Err(ext),
            },
            ExtTok => match b {
                _ if tchar => ExtTok,
                b';' => ExtNameStart,
                b'\r' => SizeLf,
                b if ws(b) => ExtPreSemi,
                _ => return Err(ext),
            },
            ExtQuoted => match b {
                b'"' => ExtAfterQuote,
                b'\\' => ExtQuotedEsc,
                b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => ExtQuoted,
                _ => return Err(ext),
            },
            ExtQuotedEsc => match b {
                b'\t' | 0x20..=0x7e | 0x80..=0xff => ExtQuoted,
                _ => return Err(ext),
            },
            ExtAfterQuote => match b {
                b';' => ExtNameStart,
                b'\r' => SizeLf,
                b if ws(b) => ExtPreSemi,
                _ => return Err(ext),
            },
            SizeLf => {
                if b != b'\n' {
                    return Err(Error::BareCr);
                }
                self.line = 0;
                if self.remaining == 0 {
                    Trailers
                } else {
                    self.received = self.received.saturating_add(self.remaining);
                    if self.received > self.limit {
                        return Err(Error::BodyTooLarge);
                    }
                    Data
                }
            }
            DataCr if b == b'\r' => DataLf,
            DataLf if b == b'\n' => Size0,
            DataCr | DataLf => return Err(Error::MissingChunkCrlf),
            Length | Close | Done | Data | Trailers => unreachable!("not a chunk-line state"),
        };
        Ok(())
    }

    fn trailers<'a>(&mut self, input: &'a [u8], i: usize) -> Result<(usize, BodyEvent<'a>), Error> {
        let rest = &input[i..];
        match rest {
            [] | [b'\r'] => return Ok((i, BodyEvent::NeedMore)),
            [b'\r', b'\n', ..] => {
                self.state = St::Done;
                return Ok((i + 2, BodyEvent::End(&[])));
            }
            [b'\r', ..] => return Err(Error::BareCr),
            _ => {}
        }
        let mut k = (self.scanned as usize).saturating_sub(3);
        while let Some(off) = find_byte(&rest[k..], b'\n') {
            let at = k + off;
            if at >= 3 && &rest[at - 3..=at] == b"\r\n\r\n" {
                let section = &rest[..=at];
                let lim = Limits {
                    max_headers: self.max_headers as usize,
                    max_header_line: self.max_header_line as usize,
                    max_trailers: self.max_trailers as usize,
                    ..Limits::default()
                };
                check_trailers(section, &lim)?;
                self.state = St::Done;
                return Ok((i + section.len(), BodyEvent::End(section)));
            }
            k = at + 1;
        }
        if rest.len() > self.max_trailers as usize {
            return Err(Error::TrailersTooLarge);
        }
        self.scanned = clamp(rest.len());
        Ok((i, BodyEvent::NeedMore))
    }
}
