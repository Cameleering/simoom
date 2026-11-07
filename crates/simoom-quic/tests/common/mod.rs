#![allow(dead_code)]

use simoom_quic::crypto::null::NullProvider;
use simoom_quic::sim::{Link, Pair};
use simoom_quic::{ConnHandle, Config, Event};
use std::sync::Arc;
use std::time::Duration;

pub fn config(seed: u64, f: impl FnOnce(&mut Config)) -> Arc<Config> {
    config_with(seed, |_| {}, f)
}

pub fn config_with(seed: u64, prov: impl FnOnce(&mut NullProvider), f: impl FnOnce(&mut Config)) -> Arc<Config> {
    let mut np = NullProvider::new(seed);
    prov(&mut np);
    let mut c = Config::new(Arc::new(np));
    f(&mut c);
    Arc::new(c)
}

/// Runs a client→server upload and echo of `size` bytes on one stream; returns
/// (client, server) handles. Panics if it does not finish within `limit` of virtual time.
pub fn echo_on(p: &mut Pair, c: ConnHandle, s: ConnHandle, size: usize, limit: Duration) {
    let data = pattern(size, size as u8);
    let id = p.client.conn_mut(c).unwrap().open_bi().unwrap();
    let mut off = 0;
    let mut got = Vec::new();
    let mut back = Vec::new();
    let mut back_off = 0;
    let mut server_done = false;
    let ok = p.run_until(limit, |p| {
        write_some(&mut p.client, c, id, &data, &mut off);
        if !server_done {
            server_done = read_all(&mut p.server, s, id, &mut got);
        }
        if server_done {
            write_some(&mut p.server, s, id, &got, &mut back_off);
        }
        read_all(&mut p.client, c, id, &mut back)
    });
    assert!(ok, "echo did not finish: sent {off}, server got {}, back {}", got.len(), back.len());
    assert!(got == data, "server received corrupted data");
    assert!(back == data, "client received corrupted data");
}

pub fn pair(link: Link, seed: u64) -> Pair {
    Pair::new(config(seed, |_| {}), config(seed + 1, |_| {}), link, seed)
}

/// Connects and runs until both sides report Connected. Returns (client, server) handles.
pub fn handshake(p: &mut Pair) -> (ConnHandle, ConnHandle) {
    let c = p.connect();
    let ok = p.run_until(Duration::from_secs(30), |p| {
        p.client.conn(c).is_some_and(|x| x.is_established())
            && p.server_conn().and_then(|s| p.server.conn(s)).is_some_and(|x| x.is_established())
    });
    assert!(ok, "handshake did not complete");
    (c, p.server_conn().unwrap())
}

/// Drains events from both sides into vectors.
pub fn events(p: &mut Pair, c: ConnHandle, s: ConnHandle) -> (Vec<Event>, Vec<Event>) {
    let mut ce = Vec::new();
    while let Some(e) = p.client.poll_event(c) {
        ce.push(e);
    }
    let mut se = Vec::new();
    while let Some(e) = p.server.poll_event(s) {
        se.push(e);
    }
    (ce, se)
}

/// Reads everything available from a stream into `out`; returns true at fin.
pub fn read_all(p: &mut simoom_quic::Endpoint, h: ConnHandle, id: u64, out: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 16384];
    let Some(c) = p.conn_mut(h) else { return false };
    loop {
        match c.stream_recv(id, &mut buf) {
            Ok((n, fin)) => {
                out.extend_from_slice(&buf[..n]);
                if fin {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
}

/// Writes as much of `data[*off..]` as accepted; finishes when everything is written.
pub fn write_some(p: &mut simoom_quic::Endpoint, h: ConnHandle, id: u64, data: &[u8], off: &mut usize) {
    let Some(c) = p.conn_mut(h) else { return };
    while *off < data.len() {
        match c.stream_send(id, &data[*off..], true) {
            Ok(n) => *off += n,
            Err(_) => break,
        }
    }
    if data.is_empty() && *off == 0 {
        let _ = c.stream_finish(id);
        *off = usize::MAX;
    }
}

pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}
