//! A std-only mutation fuzzer for the TLS record layer, the handshake message parsers and the
//! X.509 and key parsers (plan option F2, without coverage feedback). Seeds are real handshake
//! transcripts; mutations are bit flips, byte and length-field overwrites with boundary values,
//! insertions, deletions, duplication, truncation and splicing. The invariant is "no panic, no
//! hang, bounded buffers"; any panic is a bug.
//!
//! Used by `tests/fuzz.rs` (short run) and `examples/fuzz_tls.rs` (long runs).

#![allow(dead_code)]

use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::quic::{Level, QuicConnection};
use simoom_tls::x509::{self, Certificate, RootStore};
use simoom_tls::{CertifiedKey, ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::sync::Arc;

/// xorshift64* generator.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const INTERESTING: [u16; 10] = [0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x4000, 0xffff];

/// One to four stacked mutations of `input`.
pub fn mutate(rng: &mut Rng, input: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    let mut d = input.to_vec();
    for _ in 0..1 + rng.below(4) {
        let n = d.len();
        match rng.below(10) {
            0 if n > 0 => {
                let i = rng.below(n);
                d[i] ^= 1 << rng.below(8);
            }
            1 if n > 0 => {
                let i = rng.below(n);
                d[i] = rng.next() as u8;
            }
            2 if n > 1 => {
                // a 16-bit field set to a boundary value (lengths are everywhere in TLS)
                let i = rng.below(n - 1);
                let v = INTERESTING[rng.below(INTERESTING.len())].to_be_bytes();
                d[i..i + 2].copy_from_slice(&v);
            }
            3 => {
                let i = rng.below(n + 1);
                let k = 1 + rng.below(16);
                for _ in 0..k {
                    d.insert(i, rng.next() as u8);
                }
            }
            4 if n > 0 => {
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(32));
                d.drain(i..i + k);
            }
            5 if n > 0 => {
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(64));
                let chunk = d[i..i + k].to_vec();
                let j = rng.below(n + 1);
                d.splice(j..j, chunk);
            }
            6 if n > 0 => d.truncate(rng.below(n)),
            7 if !others.is_empty() => {
                let o = &others[rng.below(others.len())];
                if !o.is_empty() {
                    let i = rng.below(o.len());
                    let k = 1 + rng.below((o.len() - i).min(64));
                    let j = rng.below(n + 1);
                    d.splice(j..j, o[i..i + k].iter().copied());
                }
            }
            8 if n > 0 => {
                let i = rng.below(n);
                d[i] = d[i].wrapping_add(1 + rng.below(3) as u8);
            }
            _ if n > 2 => {
                // 24-bit handshake length field
                let i = rng.below(n - 2);
                let v = (rng.next() as u32 & 0x01ff_ffff).to_be_bytes();
                d[i..i + 3].copy_from_slice(&v[1..]);
            }
            _ => {}
        }
        if d.len() > 1 << 17 {
            d.truncate(1 << 17);
        }
    }
    d
}

/// Seeds and configurations shared by the targets.
pub struct Corpus {
    pub scfg: Arc<ServerConfig>,
    pub ccfg: Arc<ClientConfig>,
    /// TLS byte streams client -> server: ClientHello record, ClientHello + CCS + garbage.
    pub to_server: Vec<Vec<u8>>,
    /// Server -> client first flight (SH, CCS, encrypted records).
    pub to_client: Vec<Vec<u8>>,
    /// Raw handshake messages: ClientHello (QUIC flavour), server Handshake-level flight.
    pub ch_msg: Vec<u8>,
    pub server_hs_flight: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

pub fn corpus() -> Corpus {
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let mut roots = RootStore::empty();
    roots.add_der(&ss.cert_der).unwrap();
    let scfg = Arc::new(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()).with_alpn(&[b"h3", b"http/1.1"]));
    let mut cc = ClientConfig::new(roots).with_alpn(&[b"h3", b"http/1.1"]);
    cc.sessions = None;
    let ccfg = Arc::new(cc);
    // a TLS handshake transcript
    let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
    let mut s = ServerConnection::new(scfg.clone());
    let ch = c.tls_output().to_vec();
    c.consume_tls_output(ch.len());
    s.read_tls(&ch);
    s.process_new_packets().unwrap();
    let flight = s.tls_output().to_vec();
    let mut ch_plus = ch.clone();
    ch_plus.extend_from_slice(&[20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 20]);
    ch_plus.extend(std::iter::repeat_n(0xaa, 20));
    // a QUIC handshake: the ClientHello message and the server's Handshake-level flight
    let mut qc = QuicConnection::new_client(ccfg.clone(), "localhost", vec![1, 2, 3]).unwrap();
    let mut qs = QuicConnection::new_server(scfg.clone(), vec![4, 5, 6]);
    let mut ch_msg = Vec::new();
    qc.write_handshake(&mut ch_msg);
    qs.read_handshake(Level::Initial, &ch_msg).unwrap();
    let mut sh = Vec::new();
    qs.write_handshake(&mut sh);
    let mut hs = Vec::new();
    qs.write_handshake(&mut hs);
    Corpus {
        scfg,
        ccfg,
        to_server: vec![ch, ch_plus],
        to_client: vec![flight],
        ch_msg,
        server_hs_flight: hs,
        key_der: ss.key_der.clone(),
        cert_der: ss.cert_der,
    }
}

/// Feeds `data` in random-sized pieces and processes after each; checks that errors stick.
fn feed(rng: &mut Rng, conn: &mut simoom_tls::Connection, data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let k = 1 + rng.below(data.len() - off);
        let taken = conn.read_tls(&data[off..off + k]);
        off += taken;
        let r = conn.process_new_packets();
        if let Err(e) = r {
            assert_eq!(conn.process_new_packets().unwrap_err(), e, "errors must stick");
            assert!(conn.tls_output().len() < 64 * 1024, "output stays bounded");
            assert!(conn.write_plaintext(b"x").is_err(), "a failed connection refuses writes");
            return;
        }
        if taken == 0 {
            // buffer full: the application reads plaintext
            let n = conn.plaintext().len();
            if n == 0 {
                return;
            }
            conn.consume_plaintext(n);
        }
    }
}

pub fn server_records(rng: &mut Rng, c: &Corpus, iters: usize) {
    for _ in 0..iters {
        let seed = &c.to_server[rng.below(c.to_server.len())];
        let data = mutate(rng, seed, &c.to_client);
        let mut s = ServerConnection::new(c.scfg.clone());
        feed(rng, &mut s, &data);
    }
}

pub fn client_records(rng: &mut Rng, c: &Corpus, iters: usize) {
    for _ in 0..iters {
        let data = mutate(rng, &c.to_client[0], &c.to_server);
        let mut cl = ClientConnection::new(c.ccfg.clone(), "localhost").unwrap();
        let n = cl.tls_output().len();
        cl.consume_tls_output(n);
        feed(rng, &mut cl, &data);
    }
}

/// ClientHello parsing (and everything the server does with it) without the record layer.
pub fn quic_server_messages(rng: &mut Rng, c: &Corpus, iters: usize) {
    for _ in 0..iters {
        let m = mutate(rng, &c.ch_msg, &[]);
        let mut s = QuicConnection::new_server(c.scfg.clone(), vec![9]);
        if s.read_handshake(Level::Initial, &m).is_err() {
            assert!(s.tls_alert().is_some());
        }
        let mut out = Vec::new();
        while s.write_handshake(&mut out).is_some() {}
    }
}

/// EncryptedExtensions, Certificate (X.509), CertificateVerify and Finished parsing on the
/// client: a real ServerHello, then a mutated Handshake-level flight.
pub fn quic_client_messages(rng: &mut Rng, c: &Corpus, iters: usize) {
    for _ in 0..iters {
        let mut qc = QuicConnection::new_client(c.ccfg.clone(), "localhost", vec![1]).unwrap();
        let mut qs = QuicConnection::new_server(c.scfg.clone(), vec![2]);
        let mut ch = Vec::new();
        qc.write_handshake(&mut ch);
        qs.read_handshake(Level::Initial, &ch).unwrap();
        let mut sh = Vec::new();
        qs.write_handshake(&mut sh);
        let mut hs = Vec::new();
        qs.write_handshake(&mut hs);
        qc.read_handshake(Level::Initial, &sh).unwrap();
        let mut ignore = Vec::new();
        qc.write_handshake(&mut ignore);
        let m = mutate(rng, &hs, &[c.cert_der.clone()]);
        let _ = qc.read_handshake(Level::Handshake, &m);
    }
}

pub fn x509_and_keys(rng: &mut Rng, c: &Corpus, iters: usize) {
    let mut roots = RootStore::empty();
    roots.add_der(&c.cert_der).unwrap();
    for _ in 0..iters {
        let d = mutate(rng, &c.cert_der, &[]);
        if let Ok(cert) = Certificate::from_der(&d) {
            let _ = cert.matches_hostname("localhost");
        }
        let _ = x509::verify_chain(&[d], Some("localhost"), &roots, 1_800_000_000, x509::OID_EKU_SERVER_AUTH);
        let k = mutate(rng, &c.key_der, &[]);
        let _ = PrivateKey::from_der(&k);
        let pem = simoom_tls::pem::encode_pem("PRIVATE KEY", &k);
        let p = mutate(rng, pem.as_bytes(), &[]);
        let _ = PrivateKey::from_pem(&p);
    }
}
