//! Transport parameters (RFC 9000 §18): encoding, decoding and validation.

use crate::coding::{put_varint, varint_len, Reader};
use crate::error::{TransportError, TRANSPORT_PARAMETER_ERROR};
use crate::frame::MAX_STREAMS_LIMIT;

/// A connection ID of up to 20 bytes, stored inline.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Cid {
    len: u8,
    b: [u8; 20],
}

impl Cid {
    /// Panics if `s` is longer than 20 bytes.
    pub fn new(s: &[u8]) -> Self {
        let mut b = [0u8; 20];
        b[..s.len()].copy_from_slice(s);
        Cid { len: s.len() as u8, b }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.b[..self.len as usize]
    }
    pub fn len(&self) -> usize {
        self.len as usize
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl std::ops::Deref for Cid {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::fmt::Debug for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferredAddress {
    pub v4: [u8; 6],
    pub v6: [u8; 18],
    pub cid: Cid,
    pub reset_token: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParams {
    pub original_destination_connection_id: Option<Cid>,
    /// Milliseconds; 0 means no idle timeout.
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    /// Milliseconds.
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub preferred_address: Option<PreferredAddress>,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<Cid>,
    pub retry_source_connection_id: Option<Cid>,
}

impl Default for TransportParams {
    /// The protocol defaults (what an absent parameter means).
    fn default() -> Self {
        TransportParams {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }
}

fn put_int(out: &mut Vec<u8>, id: u64, v: u64, default: u64) {
    if v != default {
        put_varint(out, id);
        put_varint(out, varint_len(v) as u64);
        put_varint(out, v);
    }
}

fn put_bytes(out: &mut Vec<u8>, id: u64, b: &[u8]) {
    put_varint(out, id);
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

impl TransportParams {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let d = TransportParams::default();
        if let Some(c) = &self.original_destination_connection_id {
            put_bytes(out, 0x00, c);
        }
        put_int(out, 0x01, self.max_idle_timeout, 0);
        if let Some(t) = &self.stateless_reset_token {
            put_bytes(out, 0x02, t);
        }
        put_int(out, 0x03, self.max_udp_payload_size, d.max_udp_payload_size);
        put_int(out, 0x04, self.initial_max_data, 0);
        put_int(out, 0x05, self.initial_max_stream_data_bidi_local, 0);
        put_int(out, 0x06, self.initial_max_stream_data_bidi_remote, 0);
        put_int(out, 0x07, self.initial_max_stream_data_uni, 0);
        put_int(out, 0x08, self.initial_max_streams_bidi, 0);
        put_int(out, 0x09, self.initial_max_streams_uni, 0);
        put_int(out, 0x0a, self.ack_delay_exponent, 3);
        put_int(out, 0x0b, self.max_ack_delay, 25);
        if self.disable_active_migration {
            put_bytes(out, 0x0c, &[]);
        }
        if let Some(p) = &self.preferred_address {
            let mut b = Vec::with_capacity(61);
            b.extend_from_slice(&p.v4);
            b.extend_from_slice(&p.v6);
            b.push(p.cid.len() as u8);
            b.extend_from_slice(&p.cid);
            b.extend_from_slice(&p.reset_token);
            put_bytes(out, 0x0d, &b);
        }
        put_int(out, 0x0e, self.active_connection_id_limit, 2);
        if let Some(c) = &self.initial_source_connection_id {
            put_bytes(out, 0x0f, c);
        }
        if let Some(c) = &self.retry_source_connection_id {
            put_bytes(out, 0x10, c);
        }
    }

    /// Decodes and validates parameters sent by a peer; `from_server` says who sent them.
    pub fn decode(buf: &[u8], from_server: bool) -> Result<Self, TransportError> {
        let err = |r: &'static str| TransportError::new(TRANSPORT_PARAMETER_ERROR, r);
        let mut p = TransportParams::default();
        let mut seen = 0u32;
        let mut r = Reader::new(buf);
        while !r.is_empty() {
            let id = r.varint().ok_or(err("truncated parameter"))?;
            let v = r.vbytes().ok_or(err("truncated parameter"))?;
            if id <= 0x10 {
                if seen & (1 << id) != 0 {
                    return Err(err("duplicate parameter"));
                }
                seen |= 1 << id;
                if !from_server && matches!(id, 0x00 | 0x02 | 0x0d | 0x10) {
                    return Err(err("server-only parameter from a client"));
                }
            }
            let int = || -> Result<u64, TransportError> {
                let mut vr = Reader::new(v);
                let x = vr.varint().ok_or(err("bad integer"))?;
                if !vr.is_empty() {
                    return Err(err("bad integer"));
                }
                Ok(x)
            };
            let cid = || -> Result<Cid, TransportError> {
                if v.len() > 20 {
                    return Err(err("connection ID too long"));
                }
                Ok(Cid::new(v))
            };
            match id {
                0x00 => p.original_destination_connection_id = Some(cid()?),
                0x01 => p.max_idle_timeout = int()?,
                0x02 => p.stateless_reset_token = Some(v.try_into().map_err(|_| err("bad reset token"))?),
                0x03 => {
                    p.max_udp_payload_size = int()?;
                    if p.max_udp_payload_size < 1200 {
                        return Err(err("max_udp_payload_size below 1200"));
                    }
                }
                0x04 => p.initial_max_data = int()?,
                0x05 => p.initial_max_stream_data_bidi_local = int()?,
                0x06 => p.initial_max_stream_data_bidi_remote = int()?,
                0x07 => p.initial_max_stream_data_uni = int()?,
                0x08 | 0x09 => {
                    let n = int()?;
                    if n > MAX_STREAMS_LIMIT {
                        return Err(err("stream limit above 2^60"));
                    }
                    if id == 0x08 {
                        p.initial_max_streams_bidi = n
                    } else {
                        p.initial_max_streams_uni = n
                    }
                }
                0x0a => {
                    p.ack_delay_exponent = int()?;
                    if p.ack_delay_exponent > 20 {
                        return Err(err("ack_delay_exponent above 20"));
                    }
                }
                0x0b => {
                    p.max_ack_delay = int()?;
                    if p.max_ack_delay >= 1 << 14 {
                        return Err(err("max_ack_delay too large"));
                    }
                }
                0x0c => {
                    if !v.is_empty() {
                        return Err(err("disable_active_migration not empty"));
                    }
                    p.disable_active_migration = true;
                }
                0x0d => {
                    let mut pr = Reader::new(v);
                    let v4 = pr.bytes(6).ok_or(err("bad preferred_address"))?.try_into().unwrap();
                    let v6 = pr.bytes(18).ok_or(err("bad preferred_address"))?.try_into().unwrap();
                    let n = pr.u8().ok_or(err("bad preferred_address"))? as usize;
                    if n == 0 || n > 20 {
                        return Err(err("bad preferred_address"));
                    }
                    let c = Cid::new(pr.bytes(n).ok_or(err("bad preferred_address"))?);
                    let t = pr.bytes(16).ok_or(err("bad preferred_address"))?.try_into().unwrap();
                    if !pr.is_empty() {
                        return Err(err("bad preferred_address"));
                    }
                    p.preferred_address = Some(PreferredAddress { v4, v6, cid: c, reset_token: t });
                }
                0x0e => {
                    p.active_connection_id_limit = int()?;
                    if p.active_connection_id_limit < 2 {
                        return Err(err("active_connection_id_limit below 2"));
                    }
                }
                0x0f => p.initial_source_connection_id = Some(cid()?),
                0x10 => p.retry_source_connection_id = Some(cid()?),
                _ => {} // Unknown and reserved parameters are ignored (RFC 9000 §18.1).
            }
        }
        if p.initial_source_connection_id.is_none() {
            return Err(err("missing initial_source_connection_id"));
        }
        if from_server && p.original_destination_connection_id.is_none() {
            return Err(err("missing original_destination_connection_id"));
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_validation() {
        let p = TransportParams {
            original_destination_connection_id: Some(Cid::new(&[1, 2, 3, 4, 5, 6, 7, 8])),
            max_idle_timeout: 30_000,
            stateless_reset_token: Some([9; 16]),
            max_udp_payload_size: 1452,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 16,
            initial_max_stream_data_bidi_remote: 1 << 16,
            initial_max_stream_data_uni: 1 << 16,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 3,
            ack_delay_exponent: 5,
            max_ack_delay: 20,
            disable_active_migration: true,
            preferred_address: Some(PreferredAddress {
                v4: [127, 0, 0, 1, 1, 187],
                v6: [0; 18],
                cid: Cid::new(&[7; 8]),
                reset_token: [3; 16],
            }),
            active_connection_id_limit: 4,
            initial_source_connection_id: Some(Cid::new(&[5; 8])),
            retry_source_connection_id: Some(Cid::new(&[6; 8])),
        };
        let mut b = Vec::new();
        p.encode(&mut b);
        assert_eq!(TransportParams::decode(&b, true).unwrap(), p);
        // A client may not send server-only parameters.
        assert_eq!(TransportParams::decode(&b, false).unwrap_err().code, TRANSPORT_PARAMETER_ERROR);

        let bad = |extra: &[u8]| {
            let mut b = vec![0x0f, 0x01, 0x07];
            b.extend_from_slice(extra);
            TransportParams::decode(&b, false)
        };
        assert!(bad(&[]).is_ok());
        assert!(bad(&[0x03, 0x02, 0x44, 0xaf]).is_err()); // 1199
        assert!(bad(&[0x0a, 0x01, 21]).is_err());
        assert!(bad(&[0x0b, 0x04, 0x80, 0, 0x40, 0]).is_err());
        assert!(bad(&[0x0e, 0x01, 1]).is_err());
        assert!(bad(&[0x01, 0x02, 0x40]).is_err()); // truncated value
        assert!(bad(&[0x01, 0x02, 5, 5]).is_err()); // trailing bytes in an integer
        assert!(bad(&[0x0f, 0x00]).is_err()); // duplicate
        assert!(bad(&[0x0c, 0x01, 0]).is_err());
        assert!(bad(&[0x7f, 0xff, 0x02, 1, 2]).is_ok()); // unknown ignored
        assert!(TransportParams::decode(&[], false).is_err()); // no initial_source_connection_id
    }
}
