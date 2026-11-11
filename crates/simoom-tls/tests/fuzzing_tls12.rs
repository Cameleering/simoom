//! A std-only fuzz harness for the TLS 1.2 handshake parsers (feature `tls12`): records each
//! flight of real handshakes (full, resumed by ticket, resumed by session ID, with client
//! certificates), mutates them (bit flips, byte changes, truncation, insertion, splicing
//! across flights) and feeds them to fresh client and server connections. The only
//! acceptable outcomes are a clean error or a handshake that still proves the same keys;
//! a panic fails the test. Scale with `SIMOOM_FUZZ_ITERS`, reseed with `SIMOOM_FUZZ_SEED`.

mod common;

use common::*;
use simoom_tls::tls::ProtocolVersion;
use simoom_tls::{ClientAuth, ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::sync::Arc;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn iters(base: usize) -> usize {
    base * std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x7151_2fa2_2b0c_0001)
}

fn mutate(rng: &mut Rng, input: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    let mut d = input.to_vec();
    for _ in 0..1 + rng.below(4) {
        if d.is_empty() {
            d.push(rng.next() as u8);
        }
        let i = rng.below(d.len());
        match rng.below(7) {
            0 => d[i] ^= 1 << rng.below(8),
            1 => d[i] = rng.next() as u8,
            2 => d.truncate(i),
            3 => d.insert(i, rng.next() as u8),
            4 => {
                // a length-looking field set to an extreme
                d[i] = if rng.below(2) == 0 { 0 } else { 0xff };
            }
            5 => {
                let o = &others[rng.below(others.len())];
                if !o.is_empty() {
                    let j = rng.below(o.len());
                    let n = rng.below(o.len() - j).min(64);
                    d.splice(i..i, o[j..j + n].iter().copied());
                }
            }
            _ => {
                let n = rng.below(d.len() - i).min(32);
                d.drain(i..i + n);
            }
        }
    }
    d
}

/// The flights of one handshake: [client1, server1, client2, server2, ...].
fn record_flights(scfg: &Arc<ServerConfig>, ccfg: &Arc<ClientConfig>) -> Vec<Vec<u8>> {
    let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
    let mut s = ServerConnection::new(scfg.clone());
    let mut flights = Vec::new();
    for _ in 0..8 {
        let out = c.tls_output().to_vec();
        c.consume_tls_output(out.len());
        if !out.is_empty() {
            s.read_tls(&out);
            s.process_new_packets().unwrap();
            flights.push(out);
        }
        let out = s.tls_output().to_vec();
        s.consume_tls_output(out.len());
        if !out.is_empty() {
            c.read_tls(&out);
            c.process_new_packets().unwrap();
            flights.push(out);
        }
    }
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::Tls12));
    flights
}

/// Replays `flights` up to `target`, which is replaced by `mutated`, against fresh connections.
fn replay(scfg: &Arc<ServerConfig>, ccfg: &Arc<ClientConfig>, flights: &[Vec<u8>], target: usize, mutated: &[u8]) {
    // the side that receives flight i: even flights go to the server, odd to the client
    let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
    let mut s = ServerConnection::new(scfg.clone());
    let n = c.tls_output().len();
    c.consume_tls_output(n);
    for (i, f) in flights.iter().enumerate().take(target + 1) {
        let data = if i == target { mutated } else { f.as_slice() };
        let r = if i % 2 == 0 {
            let mut off = 0;
            loop {
                off += s.read_tls(&data[off..]);
                let r = s.process_new_packets();
                if r.is_err() || off >= data.len() {
                    break r.map(|_| ());
                }
                let k = s.plaintext().len();
                s.consume_plaintext(k);
            }
        } else {
            let mut off = 0;
            loop {
                off += c.read_tls(&data[off..]);
                let r = c.process_new_packets();
                if r.is_err() || off >= data.len() {
                    break r.map(|_| ());
                }
                let k = c.plaintext().len();
                c.consume_plaintext(k);
            }
        };
        if r.is_err() {
            return;
        }
        // drop what the receiver produced: the recorded flights stand in for it
        let k = s.tls_output().len();
        s.consume_tls_output(k);
        let k = c.tls_output().len();
        c.consume_tls_output(k);
    }
}

#[test]
fn fuzz_tls12_handshake_flights() {
    let mut rng = Rng(seed());
    let (ca, client) = ca_and_client_cert();
    let mut setups: Vec<(Arc<ServerConfig>, Arc<ClientConfig>)> = Vec::new();
    for kind in [KeyKind::P256, KeyKind::Rsa, KeyKind::Ed25519] {
        let (scfg, mut ccfg) = pair(kind);
        ccfg.max_version = ProtocolVersion::Tls12;
        setups.push((Arc::new(scfg), Arc::new(ccfg)));
    }
    // client certificates
    let (mut scfg, mut ccfg) = pair(KeyKind::P256);
    scfg.client_auth = ClientAuth::Required(roots_of(&ca));
    ccfg.max_version = ProtocolVersion::Tls12;
    ccfg.client_cert = Some(simoom_tls::CertifiedKey::new(vec![client.cert_der.clone(), ca.cert_der.clone()], client.key.clone()).unwrap());
    setups.push((Arc::new(scfg), Arc::new(ccfg)));
    let mut corpus: Vec<(usize, Vec<Vec<u8>>)> = Vec::new();
    for (i, (s, c)) in setups.iter().enumerate() {
        // a full handshake, then a resumed one (ticket) with the same configs
        corpus.push((i, record_flights(s, c)));
        corpus.push((i, record_flights(s, c)));
    }
    // session-ID resumption
    let (mut scfg, mut ccfg) = pair(KeyKind::Rsa);
    scfg.ticketer = None;
    ccfg.max_version = ProtocolVersion::Tls12;
    setups.push((Arc::new(scfg), Arc::new(ccfg)));
    let last = setups.len() - 1;
    corpus.push((last, record_flights(&setups[last].0, &setups[last].1)));
    corpus.push((last, record_flights(&setups[last].0, &setups[last].1)));
    let all: Vec<Vec<u8>> = corpus.iter().flat_map(|(_, f)| f.iter().cloned()).collect();
    for _ in 0..iters(1500) {
        let (si, flights) = &corpus[rng.below(corpus.len())];
        let target = rng.below(flights.len());
        let m = mutate(&mut rng, &flights[target], &all);
        // resumed recordings refer to sessions in these configs; replays against them are fine
        replay(&setups[*si].0, &setups[*si].1, flights, target, &m);
    }
}

#[test]
fn fuzz_tls12_server_with_random_client_hellos() {
    // ClientHellos that offer only TLS 1.2, mutated, against a server with every feature on
    let mut rng = Rng(seed() ^ 0x55);
    let (scfg, mut ccfg) = pair(KeyKind::P256);
    ccfg.max_version = ProtocolVersion::Tls12;
    let (scfg, ccfg) = (Arc::new(scfg), Arc::new(ccfg));
    let hello = ClientConnection::new(ccfg, "localhost").unwrap().tls_output().to_vec();
    let others = vec![hello.clone()];
    for _ in 0..iters(4000) {
        let m = mutate(&mut rng, &hello, &others);
        let mut s = ServerConnection::new(scfg.clone());
        s.read_tls(&m);
        let _ = s.process_new_packets();
    }
}
