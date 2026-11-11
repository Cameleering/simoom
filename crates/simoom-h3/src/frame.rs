//! HTTP/3 frame types and SETTINGS (RFC 9114 §7).

use crate::{code, H3Error};
use simoom_quic::coding::{put_varint, Reader};

pub const DATA: u64 = 0x00;
pub const HEADERS: u64 = 0x01;
pub const CANCEL_PUSH: u64 = 0x03;
pub const SETTINGS: u64 = 0x04;
pub const PUSH_PROMISE: u64 = 0x05;
pub const GOAWAY: u64 = 0x07;
pub const MAX_PUSH_ID: u64 = 0x0d;

/// HTTP/2 frame types that have no HTTP/3 meaning (RFC 9114 §11.2.1).
pub fn is_reserved_h2(t: u64) -> bool {
    matches!(t, 0x02 | 0x06 | 0x08 | 0x09)
}

/// A frame payload that must be exactly one varint.
pub fn single_varint(p: &[u8]) -> Result<u64, H3Error> {
    let mut r = Reader::new(p);
    match r.varint() {
        Some(v) if r.is_empty() => Ok(v),
        _ => Err(H3Error::new(code::FRAME_ERROR, "malformed frame")),
    }
}

const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 §3, the same identifier as in HTTP/2).
const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

/// The settings simoom understands; others are ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub qpack_max_table_capacity: Option<u64>,
    pub max_field_section_size: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    /// 1: the sender (a server) accepts extended CONNECT (RFC 9220).
    pub enable_connect_protocol: Option<u64>,
}

impl Settings {
    /// Appends a SETTINGS frame, with one reserved (grease) setting.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut p = Vec::with_capacity(24);
        for (id, v) in [
            (QPACK_MAX_TABLE_CAPACITY, self.qpack_max_table_capacity),
            (MAX_FIELD_SECTION_SIZE, self.max_field_section_size),
            (QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams),
            (ENABLE_CONNECT_PROTOCOL, self.enable_connect_protocol),
        ] {
            if let Some(v) = v {
                put_varint(&mut p, id);
                put_varint(&mut p, v);
            }
        }
        // 0x1f * N + 0x21 is reserved for greasing (RFC 9114 §7.2.4.1).
        put_varint(&mut p, 0x1f * 3 + 0x21);
        put_varint(&mut p, 0);
        put_varint(out, SETTINGS);
        put_varint(out, p.len() as u64);
        out.extend_from_slice(&p);
    }

    pub fn decode(p: &[u8]) -> Result<Self, H3Error> {
        let err = |r| H3Error::new(code::SETTINGS_ERROR, r);
        let mut s = Settings::default();
        let mut r = Reader::new(p);
        let mut seen: Vec<u64> = Vec::new();
        while !r.is_empty() {
            let (Some(id), Some(v)) = (r.varint(), r.varint()) else {
                return Err(H3Error::new(code::FRAME_ERROR, "malformed SETTINGS"));
            };
            if seen.contains(&id) {
                return Err(err("duplicate setting"));
            }
            if seen.len() >= 256 {
                return Err(H3Error::new(code::EXCESSIVE_LOAD, "too many settings"));
            }
            seen.push(id);
            match id {
                QPACK_MAX_TABLE_CAPACITY => s.qpack_max_table_capacity = Some(v),
                MAX_FIELD_SECTION_SIZE => s.max_field_section_size = Some(v),
                QPACK_BLOCKED_STREAMS => s.qpack_blocked_streams = Some(v),
                ENABLE_CONNECT_PROTOCOL => {
                    if v > 1 {
                        return Err(err("invalid SETTINGS_ENABLE_CONNECT_PROTOCOL"));
                    }
                    s.enable_connect_protocol = Some(v);
                }
                // HTTP/2 settings are an error in HTTP/3 (RFC 9114 §7.2.4.1).
                0x00 | 0x02 | 0x03 | 0x04 | 0x05 => return Err(err("HTTP/2 setting")),
                _ => {}
            }
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip_and_errors() {
        let s = Settings { qpack_max_table_capacity: Some(4096), max_field_section_size: Some(16384), qpack_blocked_streams: Some(16), enable_connect_protocol: Some(1) };
        let mut b = Vec::new();
        s.encode(&mut b);
        let mut r = Reader::new(&b);
        assert_eq!(r.varint(), Some(SETTINGS));
        let len = r.varint().unwrap() as usize;
        assert_eq!(Settings::decode(r.bytes(len).unwrap()).unwrap(), s);
        assert_eq!(Settings::decode(&[0x06, 0x01, 0x06, 0x02]).unwrap_err().code, code::SETTINGS_ERROR);
        assert_eq!(Settings::decode(&[0x02, 0x01]).unwrap_err().code, code::SETTINGS_ERROR);
        assert_eq!(Settings::decode(&[0x06]).unwrap_err().code, code::FRAME_ERROR);
        assert!(Settings::decode(&[0x21, 0x05]).is_ok());
        assert_eq!(Settings::decode(&[0x08, 0x02]).unwrap_err().code, code::SETTINGS_ERROR);
        assert_eq!(single_varint(&[0x05, 0x00]).unwrap_err().code, code::FRAME_ERROR);
    }
}
