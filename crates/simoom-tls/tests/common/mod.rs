#![allow(dead_code)]

use simoom_tls::certgen::{self, CertParams, SelfSigned};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::{CertifiedKey, ClientConfig, Connection, Error, ServerConfig, TimeSource};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// A settable clock for tests.
pub struct TestClock(pub AtomicU64);

impl TimeSource for TestClock {
    fn unix_millis(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

pub enum KeyKind {
    P256,
    P384,
    Ed25519,
    Rsa,
}

pub fn rsa_key() -> PrivateKey {
    PrivateKey::from_pem(include_bytes!("../../testdata/rsa2048.pkcs1.pem")).unwrap()
}

/// A self-signed server certificate for `localhost` with the given key type (cached).
pub fn server_cert(kind: KeyKind) -> SelfSigned {
    static CACHE: OnceLock<Vec<SelfSigned>> = OnceLock::new();
    let all = CACHE.get_or_init(|| {
        let p = CertParams::server(&["localhost", "127.0.0.1"]);
        vec![
            certgen::issue(&p, PrivateKey::generate_ec(EcCurve::P256), None),
            certgen::issue(&p, PrivateKey::generate_ec(EcCurve::P384), None),
            certgen::issue(&p, PrivateKey::generate_ed25519(), None),
            certgen::issue(&p, rsa_key(), None),
        ]
    });
    all[kind as usize].clone()
}

pub fn certified(ss: &SelfSigned) -> CertifiedKey {
    CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()
}

pub fn roots_of(ss: &SelfSigned) -> RootStore {
    let mut r = RootStore::empty();
    r.add_der(&ss.cert_der).unwrap();
    r
}

pub fn pair(kind: KeyKind) -> (ServerConfig, ClientConfig) {
    let ss = server_cert(kind);
    (ServerConfig::new(certified(&ss)), ClientConfig::new(roots_of(&ss)))
}

/// Moves bytes both ways until neither side has output. Errors carry the side that failed.
pub fn pump(c: &mut Connection, s: &mut Connection) -> Result<(), (char, Error)> {
    for _ in 0..1000 {
        let mut moved = false;
        if c.wants_write() {
            let n = s.read_tls(c.tls_output());
            c.consume_tls_output(n);
            s.process_new_packets().map_err(|e| ('s', e))?;
            moved = true;
        }
        if s.wants_write() {
            let n = c.read_tls(s.tls_output());
            s.consume_tls_output(n);
            c.process_new_packets().map_err(|e| ('c', e))?;
            moved = true;
        }
        if !moved {
            return Ok(());
        }
    }
    panic!("pump did not settle");
}

/// Like `pump`, but feeds one byte at a time.
pub fn pump_bytewise(c: &mut Connection, s: &mut Connection) -> Result<(), (char, Error)> {
    for _ in 0..100_000 {
        let mut moved = false;
        if c.wants_write() {
            let n = s.read_tls(&c.tls_output()[..1]);
            c.consume_tls_output(n);
            s.process_new_packets().map_err(|e| ('s', e))?;
            moved = true;
        }
        if s.wants_write() {
            let n = c.read_tls(&s.tls_output()[..1]);
            s.consume_tls_output(n);
            c.process_new_packets().map_err(|e| ('c', e))?;
            moved = true;
        }
        if !moved {
            return Ok(());
        }
    }
    panic!("pump did not settle");
}

/// Sends `data` from `a` to `b` and returns what `b` read.
pub fn transfer(a: &mut Connection, b: &mut Connection, data: &[u8]) -> Vec<u8> {
    a.write_plaintext(data).unwrap();
    let mut got = Vec::new();
    let mut buf = vec![0u8; 8192];
    for _ in 0..100_000 {
        if a.wants_write() {
            let n = b.read_tls(a.tls_output());
            a.consume_tls_output(n);
        }
        b.process_new_packets().unwrap();
        let n = b.read_plaintext(&mut buf);
        got.extend_from_slice(&buf[..n]);
        if got.len() >= data.len() && !a.wants_write() {
            break;
        }
        // let b answer KeyUpdates and the like
        if b.wants_write() {
            let n = a.read_tls(b.tls_output());
            b.consume_tls_output(n);
            a.process_new_packets().unwrap();
        }
    }
    got
}

pub fn ca_and_client_cert() -> (SelfSigned, SelfSigned) {
    static CACHE: OnceLock<(SelfSigned, SelfSigned)> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let ca = certgen::issue(&CertParams::ca("Test Client CA"), PrivateKey::generate_ec(EcCurve::P256), None);
            let client = certgen::issue(&CertParams::client("client-1"), PrivateKey::generate_ed25519(), Some(&ca));
            (ca, client)
        })
        .clone()
}

pub fn arc<T>(t: T) -> Arc<T> {
    Arc::new(t)
}
