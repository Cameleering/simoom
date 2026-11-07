//! simoom-tls benchmarks: AEAD throughput at 16 KiB and 1.4 KiB records, primitive costs, and
//! TLS 1.3 handshakes per second (full X25519 + ECDSA P-256, and PSK resumption), single core.
//!
//! `cargo run --release -p simoom-tls --example bench_tls [-- --openssl]`
//!
//! With `--openssl` it also runs `openssl speed` for the same algorithms (if `openssl` is on
//! PATH) and prints its numbers next to ours.

use simoom_tls::certgen::{self, CertParams};
use simoom_tls::crypto::chacha::ChaCha20Poly1305;
use simoom_tls::crypto::gcm::AesGcm;
use simoom_tls::crypto::{p256, x25519};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::{CertifiedKey, ClientConfig, ClientConnection, Connection, NamedGroup, ServerConfig, ServerConnection};
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Runs `f` repeatedly for about `dur` and returns operations per second.
fn rate(dur: Duration, mut f: impl FnMut()) -> f64 {
    // warm up
    let t = Instant::now();
    while t.elapsed() < dur / 10 {
        f();
    }
    let t = Instant::now();
    let mut n = 0u64;
    while t.elapsed() < dur {
        for _ in 0..8 {
            f();
        }
        n += 8;
    }
    n as f64 / t.elapsed().as_secs_f64()
}

fn gbps(ops: f64, size: usize) -> f64 {
    ops * size as f64 / 1e9
}

fn pump(c: &mut Connection, s: &mut Connection) {
    loop {
        let mut moved = false;
        if c.wants_write() {
            let n = s.read_tls(c.tls_output());
            c.consume_tls_output(n);
            s.process_new_packets().unwrap();
            moved = true;
        }
        if s.wants_write() {
            let n = c.read_tls(s.tls_output());
            s.consume_tls_output(n);
            c.process_new_packets().unwrap();
            moved = true;
        }
        if !moved {
            return;
        }
    }
}

fn main() {
    let openssl = std::env::args().any(|a| a == "--openssl");
    let d = Duration::from_millis(if std::env::args().any(|a| a == "--quick") { 300 } else { 1500 });
    println!("simoom-tls benchmarks (single thread), hardware AES: {}, CLMUL: {}, SHA-NI: {}", simoom_sys::arch::has_aes(), simoom_sys::arch::has_clmul(), simoom_sys::arch::has_sha256());
    println!();
    println!("{:<34} {:>12} {:>12}", "AEAD seal (encrypt + tag)", "16384 B", "1400 B");
    let aad = [0u8; 13];
    let mut buf = vec![0x5au8; 16384];
    let gcm128 = AesGcm::new(&[1u8; 16]);
    let gcm256 = AesGcm::new(&[1u8; 32]);
    let gcm128s = AesGcm::new_soft(&[1u8; 16]);
    let chacha = ChaCha20Poly1305::new(&[2u8; 32]);
    let mut seq = 0u64;
    let mut nonce = || {
        seq += 1;
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        n
    };
    let f1 = |n: &[u8; 12], b: &mut [u8]| gcm128.seal(n, &aad, b);
    let f2 = |n: &[u8; 12], b: &mut [u8]| gcm256.seal(n, &aad, b);
    let f3 = |n: &[u8; 12], b: &mut [u8]| gcm128s.seal(n, &aad, b);
    let f4 = |n: &[u8; 12], b: &mut [u8]| chacha.seal(n, &aad, b);
    let algs: [(&str, &dyn Fn(&[u8; 12], &mut [u8]) -> [u8; 16]); 4] =
        [("AES-128-GCM", &f1), ("AES-256-GCM", &f2), ("AES-128-GCM (portable, bitsliced)", &f3), ("ChaCha20-Poly1305", &f4)];
    for (name, f) in algs {
        let size_d = if name.contains("portable") { d / 3 } else { d };
        let a = rate(size_d, || {
            black_box(f(&nonce(), &mut buf));
        });
        let b = rate(size_d, || {
            black_box(f(&nonce(), &mut buf[..1400]));
        });
        println!("{:<34} {:>9.2} GB/s {:>7.2} GB/s", name, gbps(a, 16384), gbps(b, 1400));
    }
    let mut tag = [0u8; 16];
    let n12 = [0u8; 12];
    tag.copy_from_slice(&gcm128.seal(&n12, &aad, &mut buf));
    let o = rate(d, || {
        // open fails (buffer changed) but does the full work: GHASH, CTR, tag compare
        black_box(gcm128.open(&n12, &aad, &mut buf, &tag));
    });
    println!("{:<34} {:>9.2} GB/s", "AES-128-GCM open", gbps(o, 16384));

    println!();
    println!("{:<34} {:>12}", "Primitive", "ops/s");
    let sk = [7u8; 32];
    let pk = x25519::x25519_base(&[9u8; 32]);
    println!("{:<34} {:>12.0}", "X25519 key generation (table)", rate(d, || {
        black_box(x25519::x25519_base(black_box(&sk)));
    }));
    println!("{:<34} {:>12.0}", "X25519 shared secret (ladder)", rate(d, || {
        black_box(x25519::x25519(black_box(&sk), &pk));
    }));
    let d256 = p256::generate_private();
    let q256 = p256::public_key(&p256::generate_private()).unwrap();
    let h = [3u8; 32];
    println!("{:<34} {:>12.0}", "P-256 key generation", rate(d, || {
        black_box(p256::public_key(black_box(&d256)));
    }));
    println!("{:<34} {:>12.0}", "P-256 ECDH", rate(d, || {
        black_box(p256::ecdh(black_box(&d256), &q256));
    }));
    let (r, s) = p256::sign(&d256, &h, simoom_tls::crypto::sha2::HashAlg::Sha256).unwrap();
    let pub256 = p256::public_key(&d256).unwrap();
    println!("{:<34} {:>12.0}", "ECDSA P-256 sign", rate(d, || {
        black_box(p256::sign(black_box(&d256), &h, simoom_tls::crypto::sha2::HashAlg::Sha256));
    }));
    println!("{:<34} {:>12.0}", "ECDSA P-256 verify", rate(d, || {
        black_box(p256::verify(&pub256, &h, &r, &s));
    }));
    let seed = [5u8; 32];
    println!("{:<34} {:>12.0}", "Ed25519 sign", rate(d, || {
        black_box(simoom_tls::crypto::ed25519::sign(&seed, b"message"));
    }));
    let rsa = PrivateKey::from_pem(include_bytes!("../testdata/rsa2048.pkcs1.pem")).unwrap();
    if let PrivateKey::Rsa(k) = &rsa {
        let dg = [1u8; 32];
        println!("{:<34} {:>12.0}", "RSA-2048 PSS sign", rate(d, || {
            black_box(k.sign_pss(simoom_tls::crypto::sha2::HashAlg::Sha256, &dg));
        }));
        let sig = k.sign_pss(simoom_tls::crypto::sha2::HashAlg::Sha256, &dg).unwrap();
        println!("{:<34} {:>12.0}", "RSA-2048 PSS verify", rate(d, || {
            black_box(k.public.verify_pss(simoom_tls::crypto::sha2::HashAlg::Sha256, &dg, &sig, Some(32)));
        }));
    }

    // handshakes
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let mut roots = RootStore::empty();
    roots.add_der(&ss.cert_der).unwrap();
    let mut scfg = ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap());
    scfg.groups = vec![NamedGroup::X25519];
    let scfg = Arc::new(scfg);
    let mut cfull = ClientConfig::new(roots.clone());
    cfull.sessions = None;
    cfull.groups = vec![NamedGroup::X25519];
    let cfull = Arc::new(cfull);
    let mut cres = ClientConfig::new(roots);
    cres.groups = vec![NamedGroup::X25519];
    let cres = Arc::new(cres);

    println!();
    println!("{:<44} {:>12}", "TLS 1.3 handshake (X25519, ECDSA P-256 cert)", "per second");
    let full = rate(d, || {
        let mut c = ClientConnection::new(cfull.clone(), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        pump(&mut c, &mut s);
        assert!(!s.is_handshaking());
    });
    println!("{:<44} {:>12.0}", "full, client + server", full);
    // server side only: replay a fresh ClientHello per iteration and time the server's work
    let mut server_time = Duration::ZERO;
    let mut n = 0u32;
    let t0 = Instant::now();
    while t0.elapsed() < d {
        let mut c = ClientConnection::new(cfull.clone(), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        let ch = c.tls_output().to_vec();
        c.consume_tls_output(ch.len());
        let t = Instant::now();
        s.read_tls(&ch);
        s.process_new_packets().unwrap();
        server_time += t.elapsed();
        let flight = s.tls_output().to_vec();
        s.consume_tls_output(flight.len());
        c.read_tls(&flight);
        c.process_new_packets().unwrap();
        let fin = c.tls_output().to_vec();
        let t = Instant::now();
        s.read_tls(&fin);
        s.process_new_packets().unwrap();
        server_time += t.elapsed();
        n += 1;
    }
    println!("{:<44} {:>12.0}", "full, server side only", n as f64 / server_time.as_secs_f64());
    // resumption: prime the cache, then each connection uses one ticket and stores a new one
    let mut c = ClientConnection::new(cres.clone(), "localhost").unwrap();
    let mut s = ServerConnection::new(scfg.clone());
    pump(&mut c, &mut s);
    let resumed = rate(d, || {
        let mut c = ClientConnection::new(cres.clone(), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg.clone());
        pump(&mut c, &mut s);
        assert!(c.is_resumed());
    });
    println!("{:<44} {:>12.0}", "PSK-DHE resumption, client + server", resumed);

    if openssl {
        println!();
        println!("openssl speed (same machine, single thread):");
        for args in [
            &["speed", "-seconds", "2", "-bytes", "16384", "-evp", "aes-128-gcm"][..],
            &["speed", "-seconds", "2", "-bytes", "1400", "-evp", "aes-128-gcm"][..],
            &["speed", "-seconds", "2", "-bytes", "16384", "-evp", "chacha20-poly1305"][..],
            &["speed", "-seconds", "2", "-bytes", "1400", "-evp", "chacha20-poly1305"][..],
            &["speed", "-seconds", "2", "ecdhx25519", "ecdhp256", "ecdsap256", "ed25519", "rsa2048"][..],
        ] {
            match std::process::Command::new("openssl").args(args).output() {
                Ok(o) => {
                    let out = String::from_utf8_lossy(&o.stdout);
                    for line in out.lines().filter(|l| {
                        l.starts_with("AES-128-GCM") || l.starts_with("ChaCha20-Poly1305") || l.contains(" sign ") || l.contains("op/s") || l.starts_with("rsa") || l.contains("ecdh") || l.contains("ecdsa") || l.contains("Ed25519") || l.contains("type")
                    }) {
                        println!("  {line}");
                    }
                }
                Err(e) => println!("  openssl not available: {e}"),
            }
        }
    }
}
