//! A short run of the std-only fuzz harness (see `tests/fuzzing/mod.rs`). Scale it with
//! `SIMOOM_FUZZ_ITERS=<multiplier>`; long runs: `cargo run --release --example fuzz_tls`.

#![cfg(feature = "client")]

mod fuzzing;

use fuzzing::*;

fn iters(base: usize) -> usize {
    let k: usize = std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    base * k
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_1234_abcd_0001)
}

#[test]
fn fuzz_record_layer_server() {
    let c = corpus();
    server_records(&mut Rng(seed()), &c, iters(2000));
}

#[test]
fn fuzz_record_layer_client() {
    let c = corpus();
    client_records(&mut Rng(seed() ^ 1), &c, iters(1000));
}

#[test]
fn fuzz_client_hello_parser() {
    let c = corpus();
    quic_server_messages(&mut Rng(seed() ^ 2), &c, iters(2000));
}

#[test]
fn fuzz_server_flight_parsers() {
    let c = corpus();
    quic_client_messages(&mut Rng(seed() ^ 3), &c, iters(150));
}

#[test]
fn fuzz_x509_and_key_parsers() {
    let c = corpus();
    x509_and_keys(&mut Rng(seed() ^ 4), &c, iters(2000));
}
