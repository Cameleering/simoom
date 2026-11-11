//! permessage-deflate (RFC 7692) for both ends: negotiation ([`negotiate`] on servers,
//! [`offer`] and [`accept_response`] on clients) and the per-message codec ([`PerMessage`]).
//!
//! Messages are DEFLATE-compressed with a sync flush and the trailing `00 00 FF FF` removed
//! (§7.2.1); with context takeover the LZ77 window carries over between messages, without it
//! each message starts afresh. Inflated messages are bounded by a size limit, checked as they
//! inflate (decompression bombs).

use super::WsError;
use simoom_compress::{Decoder, Encoder, Format};

/// What this end is willing to do.
#[derive(Clone, Debug)]
pub struct DeflateConfig {
    /// DEFLATE level, 1 to 9. Default 6.
    pub level: u32,
    /// Messages smaller than this are sent uncompressed. Default 64.
    pub min_size: usize,
    /// Ask for (client) or impose (server) no context takeover on the server's messages:
    /// less memory kept between messages, a worse ratio. Default off.
    pub server_no_context_takeover: bool,
    /// The same for the client's messages. Default off.
    pub client_no_context_takeover: bool,
    /// The largest inflated message. Default 16 MiB.
    pub max_message: u64,
}

impl Default for DeflateConfig {
    fn default() -> Self {
        DeflateConfig { level: 6, min_size: 64, server_no_context_takeover: false, client_no_context_takeover: false, max_message: 16 << 20 }
    }
}

/// The agreed parameters (RFC 7692 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeflateParams {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    /// The server's LZ77 window, 8 to 15.
    pub server_max_window_bits: u8,
    /// The client's LZ77 window, 8 to 15.
    pub client_max_window_bits: u8,
}

/// One extension offer: its parameters, or `None` when malformed.
fn parse_offer(ext: &str) -> Option<(DeflateParams, bool, Option<u8>)> {
    let mut parts = ext.split(';').map(str::trim);
    if !parts.next()?.eq_ignore_ascii_case("permessage-deflate") {
        return None;
    }
    let mut p = DeflateParams { server_no_context_takeover: false, client_no_context_takeover: false, server_max_window_bits: 15, client_max_window_bits: 15 };
    let (mut seen_s, mut seen_c, mut seen_sw, mut seen_cw) = (false, false, false, false);
    let mut client_bits_offered = false;
    let mut client_bits_value = None;
    for param in parts.filter(|x| !x.is_empty()) {
        let (k, v) = match param.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim().trim_matches('"'))),
            None => (param, None),
        };
        let bits = |v: Option<&str>| -> Option<u8> { v?.parse::<u8>().ok().filter(|b| (8..=15).contains(b)) };
        match k.to_ascii_lowercase().as_str() {
            "server_no_context_takeover" if v.is_none() && !seen_s => {
                seen_s = true;
                p.server_no_context_takeover = true;
            }
            "client_no_context_takeover" if v.is_none() && !seen_c => {
                seen_c = true;
                p.client_no_context_takeover = true;
            }
            "server_max_window_bits" if !seen_sw => {
                seen_sw = true;
                p.server_max_window_bits = bits(v)?;
            }
            "client_max_window_bits" if !seen_cw => {
                seen_cw = true;
                client_bits_offered = true;
                if v.is_some() {
                    let b = bits(v)?;
                    client_bits_value = Some(b);
                    p.client_max_window_bits = b;
                }
            }
            _ => return None,
        }
    }
    Some((p, client_bits_offered, client_bits_value))
}

/// Server side: the first acceptable permessage-deflate offer in a `Sec-WebSocket-Extensions`
/// value (several fields may be joined with commas). Returns the parameters and the response
/// header value; `None` declines (the connection goes on uncompressed).
pub fn negotiate(offers: &[u8], cfg: &DeflateConfig) -> Option<(DeflateParams, String)> {
    let s = std::str::from_utf8(offers).ok()?;
    for ext in s.split(',') {
        let Some((mut p, _client_bits_offered, _)) = parse_offer(ext) else { continue };
        p.server_no_context_takeover |= cfg.server_no_context_takeover;
        p.client_no_context_takeover |= cfg.client_no_context_takeover;
        let mut resp = String::from("permessage-deflate");
        if p.server_no_context_takeover {
            resp.push_str("; server_no_context_takeover");
        }
        if p.client_no_context_takeover {
            resp.push_str("; client_no_context_takeover");
        }
        if p.server_max_window_bits < 15 {
            resp.push_str(&format!("; server_max_window_bits={}", p.server_max_window_bits));
        }
        return Some((p, resp));
    }
    None
}

/// Client side: the `Sec-WebSocket-Extensions` value to send.
pub fn offer(cfg: &DeflateConfig) -> String {
    let mut s = String::from("permessage-deflate; client_max_window_bits");
    if cfg.server_no_context_takeover {
        s.push_str("; server_no_context_takeover");
    }
    if cfg.client_no_context_takeover {
        s.push_str("; client_no_context_takeover");
    }
    s
}

/// Client side: the server's answer to [`offer`]. `Ok(None)`: no extension; `Err`: the server
/// answered with something not offered (the client must fail the connection, §7.1).
pub fn accept_response(value: Option<&[u8]>, cfg: &DeflateConfig) -> Result<Option<DeflateParams>, WsError> {
    let Some(v) = value else { return Ok(None) };
    let s = std::str::from_utf8(v).map_err(|_| WsError::ReservedBits)?.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if s.contains(',') {
        return Err(WsError::ReservedBits);
    }
    let (mut p, _, bits) = parse_offer(s).ok_or(WsError::ReservedBits)?;
    if cfg.server_no_context_takeover && !p.server_no_context_takeover {
        // we asked; a server may not refuse silently, but treat it as the stricter setting
        p.server_no_context_takeover = true;
    }
    p.client_no_context_takeover |= cfg.client_no_context_takeover;
    if let Some(b) = bits {
        p.client_max_window_bits = b;
    }
    Ok(Some(p))
}

/// Which end this codec runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Server,
    Client,
}

/// The per-message codec of one connection.
pub struct PerMessage {
    enc: Encoder,
    dec: Decoder,
    reset_enc: bool,
    reset_dec: bool,
    min_size: usize,
    max_message: u64,
}

impl std::fmt::Debug for PerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerMessage").field("reset_enc", &self.reset_enc).field("reset_dec", &self.reset_dec).finish()
    }
}

const TAIL: [u8; 4] = [0, 0, 0xFF, 0xFF];

impl PerMessage {
    pub fn new(side: Side, p: &DeflateParams, cfg: &DeflateConfig) -> PerMessage {
        let (own_bits, reset_enc, reset_dec) = match side {
            Side::Server => (p.server_max_window_bits, p.server_no_context_takeover, p.client_no_context_takeover),
            Side::Client => (p.client_max_window_bits, p.client_no_context_takeover, p.server_no_context_takeover),
        };
        PerMessage {
            enc: Encoder::with_window_bits(Format::Raw, cfg.level, own_bits as u32),
            dec: Decoder::new(Format::Raw),
            reset_enc,
            reset_dec,
            min_size: cfg.min_size,
            max_message: cfg.max_message,
        }
    }

    /// Whether to compress a message of `len` bytes.
    pub fn worth(&self, len: usize) -> bool {
        len >= self.min_size
    }

    /// The compressed payload of one message (send with RSV1:
    /// [`super::write_frame_compressed`]).
    pub fn compress(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(msg.len() / 2 + 16);
        self.enc.encode(msg, &mut out);
        self.enc.flush(&mut out);
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - 4);
        }
        if out.is_empty() {
            out.push(0);
        }
        if self.reset_enc {
            self.enc.reset();
        }
        out
    }

    /// Inflates one received message (all its frames' payloads, joined) into `out`; fails
    /// with `MessageTooLarge` past the limit, `InvalidData`-like errors as `Protocol`.
    pub fn decompress(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), WsError> {
        let start = out.len();
        let mut buf = [0u8; 16 * 1024];
        for input in [payload, &TAIL[..]] {
            let mut inp = input;
            loop {
                let (used, n) = self.dec.decode_into(inp, &mut buf).map_err(|_| WsError::Compression)?;
                out.extend_from_slice(&buf[..n]);
                if (out.len() - start) as u64 > self.max_message {
                    return Err(WsError::MessageTooLarge);
                }
                inp = &inp[used..];
                if inp.is_empty() && !self.dec.has_pending() {
                    break;
                }
                if used == 0 && n == 0 {
                    break;
                }
            }
        }
        if self.reset_dec || self.dec.is_done() {
            // a final block in a message (allowed) ends the stream; start a new one
            self.dec.reset();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        let cfg = DeflateConfig::default();
        let (p, r) = negotiate(b"permessage-deflate; client_max_window_bits", &cfg).unwrap();
        assert_eq!(r, "permessage-deflate");
        assert_eq!((p.server_max_window_bits, p.client_max_window_bits), (15, 15));
        let (p, r) = negotiate(b"x-webkit-deflate-frame, permessage-deflate; server_max_window_bits=10; server_no_context_takeover", &cfg).unwrap();
        assert_eq!(r, "permessage-deflate; server_no_context_takeover; server_max_window_bits=10");
        assert!(p.server_no_context_takeover && p.server_max_window_bits == 10);
        assert!(negotiate(b"permessage-deflate; server_max_window_bits=16", &cfg).is_none());
        assert!(negotiate(b"permessage-deflate; foo", &cfg).is_none());
        assert!(negotiate(b"permessage-deflate; server_no_context_takeover; server_no_context_takeover", &cfg).is_none());
        // the second offer is taken when the first is malformed
        assert!(negotiate(b"permessage-deflate; bad=1, permessage-deflate", &cfg).is_some());
        let strict = DeflateConfig { client_no_context_takeover: true, ..cfg.clone() };
        assert_eq!(negotiate(b"permessage-deflate", &strict).unwrap().1, "permessage-deflate; client_no_context_takeover");
        // client side
        assert_eq!(offer(&cfg), "permessage-deflate; client_max_window_bits");
        let p = accept_response(Some(b"permessage-deflate; client_max_window_bits=9"), &cfg).unwrap().unwrap();
        assert_eq!(p.client_max_window_bits, 9);
        assert_eq!(accept_response(None, &cfg), Ok(None));
        assert!(accept_response(Some(b"permessage-deflate; nope"), &cfg).is_err());
    }

    #[test]
    fn messages_round_trip_with_and_without_context_takeover() {
        for (snct, cnct, sbits) in [(false, false, 15u8), (true, true, 15), (false, false, 9)] {
            let p = DeflateParams { server_no_context_takeover: snct, client_no_context_takeover: cnct, server_max_window_bits: sbits, client_max_window_bits: 15 };
            let cfg = DeflateConfig::default();
            let mut server = PerMessage::new(Side::Server, &p, &cfg);
            let mut client = PerMessage::new(Side::Client, &p, &cfg);
            let mut first = 0;
            for i in 0..20 {
                let msg = format!("message {i}: the same words again and again, the same words again and again").repeat(3);
                let c = server.compress(msg.as_bytes());
                if i == 0 {
                    first = c.len();
                } else if !snct && sbits == 15 {
                    assert!(c.len() < first, "context takeover makes later messages smaller");
                }
                let mut out = Vec::new();
                client.decompress(&c, &mut out).unwrap();
                assert_eq!(out, msg.as_bytes());
                let c = client.compress(msg.as_bytes());
                let mut out = Vec::new();
                server.decompress(&c, &mut out).unwrap();
                assert_eq!(out, msg.as_bytes());
            }
        }
        // the RFC 7692 §7.2.3.1 example: "Hello" compressed
        let p = DeflateParams { server_no_context_takeover: false, client_no_context_takeover: false, server_max_window_bits: 15, client_max_window_bits: 15 };
        let mut d = PerMessage::new(Side::Client, &p, &DeflateConfig::default());
        let mut out = Vec::new();
        d.decompress(&[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], &mut out).unwrap();
        assert_eq!(out, b"Hello");
        // §7.2.3.2: the same message again, referencing the first
        let mut out = Vec::new();
        d.decompress(&[0xf2, 0x00, 0x11, 0x00, 0x00], &mut out).unwrap();
        assert_eq!(out, b"Hello");
        // a bomb is stopped at the limit
        let mut big = PerMessage::new(Side::Server, &p, &DeflateConfig::default());
        let c = big.compress(&vec![0u8; 1 << 20]);
        let mut small = PerMessage::new(Side::Client, &p, &DeflateConfig { max_message: 1000, ..DeflateConfig::default() });
        assert_eq!(small.decompress(&c, &mut Vec::new()), Err(WsError::MessageTooLarge));
    }
}
