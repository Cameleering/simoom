//! Long runs of the std-only fuzz harness.
//!
//! `cargo run --release -p simoom-tls --example fuzz_tls -- [iterations-per-target] [seed]`
//!
//! A panic stops the run and prints the seed and target, which reproduce it with
//! `SIMOOM_FUZZ_SEED=<seed>` in `tests/fuzz.rs` (same mutation sequence).

#[path = "../tests/fuzzing/mod.rs"]
mod fuzzing;

use fuzzing::*;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(100_000);
    let seed: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 | 1
    });
    println!("fuzz_tls: {iters} iterations per target, seed {seed}");
    let c = corpus();
    type Target = fn(&mut Rng, &Corpus, usize);
    let targets: [(&str, Target, usize); 5] = [
        ("record layer (server)", server_records, 1),
        ("record layer (client)", client_records, 2),
        ("ClientHello parser", quic_server_messages, 1),
        ("server flight parsers", quic_client_messages, 20),
        ("X.509 and key parsers", x509_and_keys, 1),
    ];
    for (i, (name, f, div)) in targets.iter().enumerate() {
        let t = Instant::now();
        let s = seed ^ i as u64;
        println!("  {name} (seed {s}) ...");
        f(&mut Rng(s), &c, iters / div);
        println!("  {name}: {} iterations in {:.1} s, no failures", iters / div, t.elapsed().as_secs_f64());
    }
}
