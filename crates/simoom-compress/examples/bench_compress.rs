//! Speed and ratio of simoom-compress against Cameleer's compress.rs (copied in
//! `reference/cameleer_compress.rs`), on the same inputs.
//!
//! ```text
//! cargo run --release -p simoom-compress --example bench_compress            # the table
//! cargo run --release -p simoom-compress --example bench_compress -- --write-corpus DIR
//! python3 crates/simoom-compress/examples/zlib_baseline.py DIR                # zlib, same files
//! ```
//!
//! Compression speed is input MB/s, decompression speed is output MB/s, ratio is
//! compressed / original. Each figure is the best of several timed runs.

#[path = "reference/cameleer_compress.rs"]
mod cameleer;

use simoom_compress::{compress, decompress, Format};
use std::time::Instant;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

const MB: usize = 1 << 20;

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut r = Rng(1);
    // JSON API responses.
    let mut json = String::from("[");
    let mut i = 0u64;
    while json.len() < MB {
        let n = r.next();
        json.push_str(&format!(
            "{{\"id\":{i},\"sku\":\"SKU-{:06}\",\"name\":\"Product {}\",\"price\":{}.{:02},\"stock\":{},\"active\":{},\"tags\":[\"t{}\",\"t{}\"]}},",
            n % 1_000_000,
            n % 977,
            n % 500,
            n % 100,
            (n >> 20) % 1000,
            n & 1 == 0,
            (n >> 8) % 20,
            (n >> 16) % 20
        ));
        i += 1;
    }
    json.push(']');
    // Access log lines.
    let mut log = String::new();
    let paths = ["/api/orders", "/api/products?page=2", "/health", "/static/app.js", "/q/metrics", "/api/customers/42"];
    let agents = ["curl/8.5.0", "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0", "python-requests/2.32.3", "Go-http-client/2.0"];
    while log.len() < MB {
        let n = r.next();
        log.push_str(&format!(
            "10.0.{}.{} - - [09/Nov/2026:12:{:02}:{:02} +0000] \"GET {} HTTP/1.1\" {} {} \"-\" \"{}\"\n",
            n % 256,
            (n >> 8) % 256,
            (n >> 16) % 60,
            (n >> 24) % 60,
            paths[(n >> 32) as usize % paths.len()],
            [200, 200, 200, 304, 404, 500][(n >> 40) as usize % 6],
            (n >> 44) % 50_000,
            agents[(n >> 56) as usize % agents.len()]
        ));
    }
    // Rust source of this repository (real text).
    let mut src = Vec::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for c in ["simoom-h2", "simoom-tls", "simoom-quic", "simoom", "simoom-http1"] {
        collect(&root.join(c).join("src"), &mut src);
    }
    src.truncate(MB);
    // This program's executable (real machine code and data).
    let mut bin = std::fs::read(std::env::current_exe().unwrap()).unwrap_or_default();
    bin.truncate(MB);
    let random: Vec<u8> = (0..MB).map(|_| r.next() as u8).collect();
    vec![("json", json.into_bytes()), ("log", log.into_bytes()), ("source", src), ("binary", bin), ("random", random)]
}

fn collect(dir: &std::path::Path, out: &mut Vec<u8>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.extend(std::fs::read(&p).unwrap_or_default());
        }
    }
}

/// Best seconds per call of `f`.
fn time(mut f: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        let mut n = 0;
        while t.elapsed().as_secs_f64() < 0.15 {
            f();
            n += 1;
        }
        best = best.min(t.elapsed().as_secs_f64() / n as f64);
    }
    best
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let corpus = corpus();
    if let Some(i) = args.iter().position(|a| a == "--write-corpus") {
        let dir = std::path::PathBuf::from(&args[i + 1]);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, data) in &corpus {
            std::fs::write(dir.join(name), data).unwrap();
        }
        println!("wrote {} files to {}", corpus.len(), dir.display());
        return;
    }
    println!("| input | size | impl | level | ratio | compress MB/s | decompress MB/s |");
    println!("|---|---:|---|---:|---:|---:|---:|");
    for (name, data) in &corpus {
        let mbs = |secs: f64| data.len() as f64 / secs / 1e6;
        for level in [1u32, 6, 9] {
            let ours = compress(data, Format::Gzip, level);
            let theirs = cameleer::gzip_compress(data, level);
            // Each decodes the other's output.
            assert!(decompress(&theirs, Format::Gzip, data.len()).unwrap() == *data);
            assert!(cameleer::gzip_decompress(&ours).unwrap() == *data);
            let c_ours = time(|| {
                std::hint::black_box(compress(data, Format::Gzip, level));
            });
            let d_ours = time(|| {
                std::hint::black_box(decompress(&ours, Format::Gzip, data.len()).unwrap());
            });
            let c_theirs = time(|| {
                std::hint::black_box(cameleer::gzip_compress(data, level));
            });
            let d_theirs = time(|| {
                std::hint::black_box(cameleer::gzip_decompress(&theirs).unwrap());
            });
            let ratio = |c: &[u8]| c.len() as f64 / data.len() as f64;
            println!("| {name} | {} | simoom | {level} | {:.3} | {:.1} | {:.1} |", data.len(), ratio(&ours), mbs(c_ours), mbs(d_ours));
            println!("| {name} | {} | cameleer | {level} | {:.3} | {:.1} | {:.1} |", data.len(), ratio(&theirs), mbs(c_theirs), mbs(d_theirs));
        }
    }
}
