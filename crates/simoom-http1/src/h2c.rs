//! HTTP/2 over cleartext: prior-knowledge preface detection and the `Upgrade: h2c` request
//! (RFC 9113 §3.3, RFC 7540 §3.2).

use crate::parse::has_token;
use crate::{base64url_decode, Framing, Request, Version};

/// The HTTP/2 connection preface.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The `101` reply that accepts an h2c upgrade; HTTP/2 frames follow it.
pub const SWITCHING_PROTOCOLS: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";

/// What the first bytes of a connection are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preface {
    /// The HTTP/2 preface: hand the connection to the HTTP/2 codec, preface included.
    H2,
    /// Anything else: parse as HTTP/1.
    Http1,
    /// Too few bytes to tell (a prefix of the preface, or nothing).
    Partial,
}

/// Classifies the start of a connection.
pub fn detect_preface(buf: &[u8]) -> Preface {
    let n = buf.len().min(PREFACE.len());
    if buf[..n] != PREFACE[..n] {
        Preface::Http1
    } else if n == PREFACE.len() {
        Preface::H2
    } else {
        Preface::Partial
    }
}

/// If `req` asks to upgrade to h2c, appends the decoded `HTTP2-Settings` payload to `settings`
/// and returns true.
///
/// The request must be HTTP/1.1, have `Upgrade` listing `h2c`, `Connection` listing both
/// `Upgrade` and `HTTP2-Settings`, exactly one `HTTP2-Settings` field holding canonical
/// base64url whose length is a multiple of 6 bytes, and no body (a server may ignore an
/// upgrade on a request with a body, and this one does, which keeps the switch simple).
pub fn upgrade_settings(req: &Request<'_, '_>, settings: &mut Vec<u8>) -> bool {
    let Some(up) = req.upgrade else { return false };
    if req.version != Version::Http11 || req.framing != Framing::None || !has_token(up, b"h2c") {
        return false;
    }
    let names_settings =
        req.headers.iter().any(|h| h.name.eq_ignore_ascii_case(b"connection") && has_token(h.value, b"http2-settings"));
    let mut fields = req.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(b"http2-settings"));
    let (Some(field), None) = (fields.next(), fields.next()) else { return false };
    if !names_settings {
        return false;
    }
    let start = settings.len();
    if !base64url_decode(field.value, settings) || (settings.len() - start) % 6 != 0 {
        settings.truncate(start);
        return false;
    }
    true
}
