//! Address-validation tokens for Retry and NEW_TOKEN (RFC 9000 §8.1), authenticated with
//! HMAC-SHA256 under the endpoint's token key.
//!
//! Layout: `type(1) | age_base_ms(8) | odcid_len(1) odcid | rscid_len(1) rscid | mac(16)`.
//! The MAC also covers the client address (IP and port for Retry, IP only for NEW_TOKEN, so
//! a client keeps its token across port changes).

use crate::config::Config;
use crate::crypto::ct_eq;
use crate::params::Cid;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const RETRY: u8 = 1;
const NEW_TOKEN: u8 = 2;
const MAC_LEN: usize = 16;

fn addr_bytes(a: &SocketAddr, with_port: bool, out: &mut Vec<u8>) {
    match a {
        SocketAddr::V4(v) => out.extend_from_slice(&v.ip().octets()),
        SocketAddr::V6(v) => out.extend_from_slice(&v.ip().octets()),
    }
    if with_port {
        out.extend_from_slice(&a.port().to_be_bytes());
    }
}

fn millis(cfg: &Config, now: Instant) -> u64 {
    let epoch = *cfg.epoch.get_or_init(|| now);
    now.saturating_duration_since(epoch).as_millis() as u64
}

fn mac(cfg: &Config, body: &[u8], addr: &SocketAddr, with_port: bool) -> [u8; 32] {
    let mut a = Vec::with_capacity(18);
    addr_bytes(addr, with_port, &mut a);
    cfg.provider.hmac(&cfg.token_key, &[b"token", body, &a])
}

fn seal(cfg: &Config, ty: u8, now: Instant, odcid: &[u8], rscid: &[u8], addr: &SocketAddr) -> Vec<u8> {
    let mut t = Vec::with_capacity(11 + odcid.len() + rscid.len() + MAC_LEN);
    t.push(ty);
    t.extend_from_slice(&millis(cfg, now).to_be_bytes());
    t.push(odcid.len() as u8);
    t.extend_from_slice(odcid);
    t.push(rscid.len() as u8);
    t.extend_from_slice(rscid);
    let m = mac(cfg, &t, addr, ty == RETRY);
    t.extend_from_slice(&m[..MAC_LEN]);
    t
}

/// A Retry token binding the client address and the original and Retry connection IDs.
pub fn retry_token(cfg: &Config, addr: SocketAddr, now: Instant, odcid: &[u8], rscid: &[u8]) -> Vec<u8> {
    seal(cfg, RETRY, now, odcid, rscid, &addr)
}

/// A NEW_TOKEN token for future connections from the same IP address.
pub fn new_token(cfg: &Config, addr: SocketAddr, now: Instant) -> Vec<u8> {
    seal(cfg, NEW_TOKEN, now, &[], &[], &addr)
}

/// A token that passed validation.
#[derive(Debug, PartialEq, Eq)]
pub enum Validated {
    /// From a Retry: the original destination CID and the Retry source CID.
    Retry { odcid: Cid, rscid: Cid },
    NewToken,
}

/// Validates a token received in a client Initial.
pub fn validate(cfg: &Config, token: &[u8], addr: SocketAddr, now: Instant) -> Option<Validated> {
    if token.len() < 11 + MAC_LEN {
        return None;
    }
    let (body, m) = token.split_at(token.len() - MAC_LEN);
    let ty = body[0];
    if ty != RETRY && ty != NEW_TOKEN {
        return None;
    }
    let expect = mac(cfg, body, &addr, ty == RETRY);
    if !ct_eq(&expect[..MAC_LEN], m) {
        return None;
    }
    let issued = u64::from_be_bytes(body[1..9].try_into().unwrap());
    let lifetime = if ty == RETRY {
        cfg.retry_token_lifetime
    } else {
        cfg.new_token_lifetime.unwrap_or(Duration::ZERO)
    };
    let age = millis(cfg, now).checked_sub(issued)?;
    if age > lifetime.as_millis() as u64 {
        return None;
    }
    if ty == NEW_TOKEN {
        return Some(Validated::NewToken);
    }
    let rest = &body[9..];
    let ol = *rest.first()? as usize;
    if ol > 20 || rest.len() < 1 + ol + 1 {
        return None;
    }
    let odcid = Cid::new(&rest[1..1 + ol]);
    let rl = rest[1 + ol] as usize;
    if rl > 20 || rest.len() != 2 + ol + rl {
        return None;
    }
    let rscid = Cid::new(&rest[2 + ol..]);
    Some(Validated::Retry { odcid, rscid })
}
