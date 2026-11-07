//! dudect-style constant-time checks (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant
//! time?", 2017): inputs of two classes (fixed and random) are processed in random order, each
//! call is timed, the slowest measurements are cropped, and Welch's t-test compares the
//! classes. A |t| far above 4.5 means the timing depends on the data.
//!
//! The default run is quick (a few seconds). `SIMOOM_DUDECT=1` runs about 50x more samples.
//! Shared and noisy machines produce occasional large t values, so the failure threshold is 10;
//! every run prints its t statistics.

use simoom_tls::crypto::aes::{expand_key, AesSoft};
use simoom_tls::crypto::gcm::GhashSoft;
use simoom_tls::crypto::{p256, rng, x25519};
use simoom_sys::arch::{AesHw, GhashHw};
use std::hint::black_box;
use std::time::Instant;

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
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
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
fn aes_bitsliced_is_constant_time() {
    let (rk, n) = expand_key(&[0x2b; 16]);
    let aes = AesSoft::new(&rk[..n]);
    let t = dudect("AES-128 bitsliced (4 blocks)", 20_000 * scale(), 4, |c| if c { rng::array::<64>() } else { [0u8; 64] }, |x| {
        let mut b = *x;
        aes.encrypt4(&mut b);
        black_box(b);
    });
    check("AES bitsliced", t);
    // secret key classes too
    let fixed = AesSoft::new(&expand_key(&[0u8; 16]).0[..11]);
    let t = dudect("AES-128 bitsliced key schedule + block", 4_000 * scale(), 1, |c| if c { rng::array::<16>() } else { [0u8; 16] }, |k| {
        let (rk, n) = expand_key(k);
        let a = AesSoft::new(&rk[..n]);
        let mut b = [0u8; 64];
        a.encrypt4(&mut b);
        black_box((b, &fixed));
    });
    check("AES bitsliced key", t);
}

#[test]
fn aes_hardware_is_constant_time() {
    let (rk, n) = expand_key(&[0x2b; 16]);
    let Some(aes) = AesHw::new(&rk[..n]) else {
        println!("NOTE: no AES instructions; hardware dudect skipped");
        return;
    };
    let t = dudect("AES-128 hardware", 20_000 * scale(), 64, |c| if c { rng::array::<16>() } else { [0u8; 16] }, |x| {
        let mut b = *x;
        aes.encrypt_block(&mut b);
        black_box(b);
    });
    check("AES hardware", t);
}

#[test]
fn ghash_is_constant_time() {
    let h = rng::array::<16>();
    let soft = GhashSoft::new(&h);
    let t = dudect("GHASH portable (256 B)", 20_000 * scale(), 2, |c| if c { rng::array::<256>() } else { [0u8; 256] }, |x| {
        let mut y = [0u8; 16];
        soft.update(&mut y, x);
        black_box(y);
    });
    check("GHASH portable", t);
    // the key class: H = 0 against random H
    let t = dudect("GHASH portable (key)", 10_000 * scale(), 2, |c| if c { rng::array::<16>() } else { [0u8; 16] }, |k| {
        let g = GhashSoft::new(k);
        let mut y = [0u8; 16];
        g.update(&mut y, &[0x55; 64]);
        black_box(y);
    });
    check("GHASH portable key", t);
    if let Some(hw) = GhashHw::new(&h) {
        let t = dudect("GHASH CLMUL (1 KiB)", 20_000 * scale(), 4, |c| if c { rng::bytes(1024) } else { vec![0u8; 1024] }, |x| {
            let mut y = [0u8; 16];
            hw.update(&mut y, x);
            black_box(y);
        });
        check("GHASH CLMUL", t);
    }
}

#[test]
fn x25519_is_constant_time() {
    let peer = x25519::x25519_base(&rng::array());
    let t = dudect("X25519 ladder (scalar)", 3_000 * scale(), 1, |c| if c { rng::array::<32>() } else { [0u8; 32] }, |k| {
        black_box(x25519::x25519(k, &peer));
    });
    check("X25519 ladder", t);
    let t = dudect("X25519 fixed-base (scalar)", 5_000 * scale(), 1, |c| if c { rng::array::<32>() } else { [1u8; 32] }, |k| {
        black_box(x25519::x25519_base(k));
    });
    check("X25519 fixed-base", t);
}

#[test]
fn p256_scalar_multiplication_is_constant_time() {
    let peer = p256::public_key(&p256::generate_private()).unwrap();
    // a fixed small scalar (many zero windows) against random scalars
    let mut one = [0u8; 32];
    one[31] = 1;
    let t = dudect("P-256 variable-base mul (scalar)", 2_000 * scale(), 1, |c| if c { p256::generate_private() } else { one }, |k| {
        black_box(p256::ecdh(k, &peer));
    });
    check("P-256 ECDH", t);
    let t = dudect("P-256 fixed-base mul (scalar)", 4_000 * scale(), 1, |c| if c { p256::generate_private() } else { one }, |k| {
        black_box(p256::public_key(k));
    });
    check("P-256 base mul", t);
}
