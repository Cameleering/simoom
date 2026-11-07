//! The baseline for `size_server`: the same file and stdin/stdout handling without TLS, built
//! the same way, so the difference is what simoom-tls adds (see that example).

use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: size_empty CERT.pem KEY.pem < input");
        std::process::exit(2);
    }
    let cert = std::fs::read(&args[1]).expect("certificate");
    let key = std::fs::read(&args[2]).expect("key");
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("stdin");
    let out: Vec<u8> = cert.iter().chain(&key).chain(&input).copied().collect();
    std::io::stdout().write_all(&out).expect("stdout");
}
