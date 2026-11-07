//! TLS presentation-language encoding.

use super::{alert, Error, Result};

/// A cursor over received bytes; every accessor fails with decode_error when data is short.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], what: &'static str) -> Reader<'a> {
        Reader { data, pos: 0, what }
    }
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() - self.pos < n {
            return Err(Error::decode(self.what));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn vec8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    pub fn vec16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    pub fn vec24(&mut self) -> Result<&'a [u8]> {
        let b = self.take(3)?;
        let n = (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize;
        self.take(n)
    }
    /// Fails unless everything was consumed.
    pub fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::decode(self.what))
        }
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u24(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
}

pub(crate) fn put_vec8(out: &mut Vec<u8>, data: &[u8]) {
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

pub(crate) fn put_vec16(out: &mut Vec<u8>, data: &[u8]) {
    put_u16(out, data.len() as u16);
    out.extend_from_slice(data);
}

pub(crate) fn put_vec24(out: &mut Vec<u8>, data: &[u8]) {
    put_u24(out, data.len());
    out.extend_from_slice(data);
}

/// A handshake message with its 4-byte header.
pub(crate) fn handshake_msg(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(typ);
    put_vec24(&mut m, body);
    m
}

/// An extensions block (u16 length, then type/data pairs).
pub(crate) fn extensions(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (t, d) in exts {
        put_u16(&mut body, *t);
        put_vec16(&mut body, d);
    }
    let mut out = Vec::with_capacity(2 + body.len());
    put_vec16(&mut out, &body);
    out
}

/// Parses the body of an extensions block, rejecting duplicates.
pub(crate) fn parse_extensions(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut r = Reader::new(data, "extensions");
    let mut out: Vec<(u16, &[u8])> = Vec::new();
    while !r.is_empty() {
        let t = r.u16()?;
        let d = r.vec16()?;
        if out.iter().any(|(x, _)| *x == t) {
            return Err(Error::proto(alert::ILLEGAL_PARAMETER, format!("duplicate extension {t}")));
        }
        out.push((t, d));
    }
    Ok(out)
}

pub(crate) fn find_ext<'a>(exts: &[(u16, &'a [u8])], t: u16) -> Option<&'a [u8]> {
    exts.iter().find(|(x, _)| *x == t).map(|(_, d)| *d)
}

/// Parses `uint16 list<2..2^16-2>`.
pub(crate) fn parse_u16_list(data: &[u8], what: &'static str) -> Result<Vec<u16>> {
    let mut r = Reader::new(data, what);
    let body = r.vec16()?;
    r.finish()?;
    if body.is_empty() || body.len() % 2 != 0 {
        return Err(Error::decode(what));
    }
    Ok(body.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
}

pub(crate) fn u16_list(vals: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 2 * vals.len());
    put_u16(&mut out, 2 * vals.len() as u16);
    for v in vals {
        put_u16(&mut out, *v);
    }
    out
}

/// An ALPN `ProtocolNameList`.
pub(crate) fn alpn_list(protos: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in protos {
        put_vec8(&mut body, p);
    }
    let mut out = Vec::new();
    put_vec16(&mut out, &body);
    out
}

pub(crate) fn parse_alpn_list(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut r = Reader::new(data, "ALPN extension");
    let body = r.vec16()?;
    r.finish()?;
    let mut lr = Reader::new(body, "ALPN extension");
    let mut out = Vec::new();
    while !lr.is_empty() {
        let p = lr.vec8()?;
        if p.is_empty() {
            return Err(Error::decode("ALPN extension"));
        }
        out.push(p);
    }
    if out.is_empty() {
        return Err(Error::decode("ALPN extension"));
    }
    Ok(out)
}
