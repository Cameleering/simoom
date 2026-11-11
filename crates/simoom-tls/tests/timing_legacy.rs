//! dudect checks (see `timing.rs`) for the constant-time code added with the key store and
//! TLS 1.2 features: the bitsliced AES inverse cipher and key schedule in `crypto::legacy`
//! (PBES2 AES-CBC decryption of key stores, keyed by password-derived secrets), and the TLS 1.2
//! PRF-based Finished check path (HMAC over secret keys, compared with `ct_eq`), and P-384
//! ECDH, which TLS 1.2 (and TLS 1.3, when configured) now uses as a key-exchange group.

use simoom_tls::crypto::legacy::Aes;
use simoom_tls::crypto::md::Md;
use simoom_tls::crypto::rng;
use simoom_tls::util::ct_eq;
use std::hint::black_box;
use std::sync::Mutex;
use std::time::Instant;

/// The tests run one at a time: measurements are cleaner, and some turn the hardware paths
/// off (process-wide) to measure the portable code.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const THRESHOLD: f64 = 10.0;

fn scale() -> usize {
    if std::env::var("SIMOOM_DUDECT").is_ok() {
        50
    } else {
        1
    }
}

/// Welch's t statistic of two samples.
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    let var = |x: &[f64], m: f64| x.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / (x.len() as f64 - 1.0);
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    let d = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if d == 0.0 {
        // every sample identical (all below the timer resolution, say): no difference
        return if ma == mb { 0.0 } else { f64::INFINITY };
    }
    (ma - mb) / d
}

/// Times `op` on prepared inputs: `inputs[i]` belongs to class `classes[i]`. Each measurement
/// runs the operation `reps` times so it is well above the timer resolution.
fn dudect<T>(name: &str, n: usize, reps: usize, mut gen: impl FnMut(bool) -> T, mut op: impl FnMut(&T)) -> f64 {
    let mut classes = vec![false; n];
    let bits = rng::bytes(n);
    for (c, b) in classes.iter_mut().zip(bits) {
        *c = b & 1 == 1;
    }
    let inputs: Vec<T> = classes.iter().map(|&c| gen(c)).collect();
    // warm-up
    for x in inputs.iter().take(n / 10 + 1) {
        op(x);
    }
    let mut times = vec![0f64; n];
    for (i, x) in inputs.iter().enumerate() {
        let t = Instant::now();
        for _ in 0..reps {
            op(x);
        }
        times[i] = t.elapsed().as_nanos() as f64;
    }
    // crop the slowest 10% (interrupts, frequency changes)
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let cut = sorted[n * 9 / 10];
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for (t, c) in times.iter().zip(&classes) {
        if *t <= cut {
            if *c {
                b.push(*t)
            } else {
                a.push(*t)
            }
        }
    }
    let t = welch(&a, &b);
    println!("dudect {name}: n = {n}, t = {t:.2}");
    t
}

fn check(name: &str, t: f64) {
    assert!(t.abs() < THRESHOLD, "{name}: |t| = {:.2} suggests data-dependent timing", t.abs());
}

#[test]
fn legacy_aes_inverse_cipher_is_constant_time() {
    let _g = serial();
    let aes = Aes::new(&[0x2b; 32]);
    let t = dudect("legacy AES-256 decrypt_block (data classes)", 20_000 * scale(), 4, |c| if c { rng::array::<16>() } else { [0u8; 16] }, |x| {
        let mut b = *x;
        aes.decrypt_block(&mut b);
        black_box(b);
    });
    check("legacy AES decrypt (data)", t);
    let t = dudect("legacy AES-256 key schedule + decrypt (key classes)", 4_000 * scale(), 1, |c| if c { rng::array::<32>() } else { [0u8; 32] }, |k| {
        let a = Aes::new(k);
        let mut b = [0x5a; 16];
        a.decrypt_block(&mut b);
        black_box(b);
    });
    check("legacy AES decrypt (key)", t);
    let t = dudect("legacy AES-256 encrypt_block (data classes)", 20_000 * scale(), 4, |c| if c { rng::array::<16>() } else { [0u8; 16] }, |x| {
        let mut b = *x;
        aes.encrypt_block(&mut b);
        black_box(b);
    });
    check("legacy AES encrypt (data)", t);
}

#[test]
fn hmac_sha1_is_constant_time_in_the_key() {
    let _g = serial();
    // HMAC-SHA1 (PKCS#12 MACs, JKS digest) and its comparison: secret key classes
    let msg = [0x11u8; 64];
    let expect = Md::Sha1.hmac(&[0u8; 20], &[&msg]);
    let t = dudect("HMAC-SHA1 + ct_eq (key classes)", 20_000 * scale(), 2, |c| if c { rng::array::<20>() } else { [0u8; 20] }, |k| {
        let m = Md::Sha1.hmac(k, &[&msg]);
        black_box(ct_eq(&m, &expect));
    });
    check("HMAC-SHA1", t);
}

#[cfg(feature = "p384")]
#[test]
fn p384_ecdh_is_constant_time_in_the_scalar() {
    use simoom_tls::crypto::ec::p384;
    let _g = serial();
    let peer = p384::public_key(&p384::generate_private()).unwrap();
    // fixed small scalar (1) against random scalars
    let mut one = [0u8; 48];
    one[47] = 1;
    let t = dudect("P-384 ECDH (scalar classes)", 1_500 * scale(), 1, |c| if c { p384::generate_private() } else { one.to_vec() }, |k| {
        black_box(p384::ecdh(k, &peer));
    });
    check("P-384 ECDH", t);
}
