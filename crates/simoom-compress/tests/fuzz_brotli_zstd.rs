//! Seeded mutation fuzzing for the Brotli and zstd decoders (plan §7.3 option F2), seeded with
//! the reference implementations' streams and our own.
//!
//! `SIMOOM_FUZZ_ITERS=200000 cargo test -p simoom-compress --release --features brotli,zstd
//! --test fuzz_brotli_zstd -- --nocapture`; `SIMOOM_FUZZ_SEED=<n>` replays a run.
//!
//! Invariants: no panic; the output never passes the limit; decoding in random pieces gives
//! the same output, or an error of the same kind (a limit error may come at another point),
//! as decoding in one go; a valid stream decodes to its input; the kernels built without BMI2
//! (`simoom_sys::bits::set_scalar_only`) and the safe reference loops
//! (`simoom_sys::codec::set_safe_only`) give the same results as the default ones.

#![cfg(any(feature = "brotli", feature = "zstd"))]

use simoom_compress::{compress, decompress, Decoder, ErrorKind, Format};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn iterations(default: usize) -> usize {
    std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_b207_0000_0001)
}

fn seeds(f: Format, dir: &str) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let base = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors"));
    let mut v = Vec::new();
    for e in std::fs::read_dir(base.join(dir)).unwrap() {
        let c = std::fs::read(e.unwrap().path()).unwrap();
        if c.len() < 4096 {
            v.push((c, None));
        }
    }
    let text = std::fs::read(base.join("text.txt")).unwrap();
    for (i, part) in [&text[..200], &text[..2000], &text[..9000]].into_iter().enumerate() {
        for level in [1, 3, 5, 9] {
            v.push((compress(part, f, level + i as u32), Some(part.to_vec())));
        }
    }
    v
}

fn mutate(r: &mut Rng, d: &mut Vec<u8>) {
    for _ in 0..1 + r.below(4) {
        if d.is_empty() {
            d.push(r.next() as u8);
            continue;
        }
        let i = r.below(d.len());
        match r.below(6) {
            0 => d[i] ^= 1 << r.below(8),
            1 => d[i] = r.next() as u8,
            2 => d.truncate(i),
            3 => {
                for _ in 0..r.below(8) {
                    d.insert(i, r.next() as u8);
                }
            }
            4 => {
                let n = r.below(16).min(d.len() - i);
                d.drain(i..i + n);
            }
            _ => {
                let n = r.below(64).min(d.len() - i);
                let s = d[i..i + n].to_vec();
                let j = r.below(d.len());
                d.splice(j..j, s);
            }
        }
    }
}

fn streamed(r: &mut Rng, f: Format, data: &[u8], limit: usize) -> Result<Vec<u8>, ErrorKind> {
    let mut d = Decoder::with_limit(f, limit as u64);
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let n = (1 + r.below(300)).min(data.len() - i);
        d.decode(&data[i..i + n], &mut out).map_err(|e| e.kind())?;
        assert!(out.len() <= limit);
        i += n;
    }
    d.finish().map_err(|e| e.kind())?;
    Ok(out)
}

fn fuzz(f: Format, dir: &str, salt: u64) {
    let mut r = Rng((seed() ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1);
    let seeds = seeds(f, dir);
    let iters = iterations(3000);
    let mut ok = 0;
    for it in 0..iters {
        let (base, plain) = &seeds[r.below(seeds.len())];
        let mut data = base.clone();
        let mutated = r.below(8) != 0;
        if mutated {
            mutate(&mut r, &mut data);
        }
        let limit = if r.below(4) == 0 { r.below(20_000) } else { 1 << 20 };
        let one = decompress(&data, f, limit).map_err(|e| e.kind());
        if let Ok(o) = &one {
            assert!(o.len() <= limit);
            ok += 1;
        }
        if let (false, Some(p)) = (mutated, plain) {
            if p.len() <= limit {
                assert_eq!(one.as_ref().ok(), Some(p), "{f:?} iteration {it}: a valid stream must decode");
            }
        }
        // the safe reference loops must agree with the pointer-code ones (every input), and
        // the base-target build of the kernels with the BMI2 one (every fourth)
        simoom_sys::codec::set_safe_only(true);
        let safe = decompress(&data, f, limit).map_err(|e| e.kind());
        simoom_sys::codec::set_safe_only(false);
        assert!(safe == one, "{f:?} iteration {it}: safe and fast loops differ");
        if it % 4 == 0 {
            simoom_sys::bits::set_scalar_only(true);
            let scalar = decompress(&data, f, limit).map_err(|e| e.kind());
            simoom_sys::bits::set_scalar_only(false);
            assert!(scalar == one, "{f:?} iteration {it}: scalar and BMI2 kernels differ");
        }
        let got = streamed(&mut r, f, &data, limit);
        match (&one, &got) {
            (Ok(a), Ok(b)) => assert!(a == b, "{f:?} iteration {it}: outputs differ"),
            (Err(a), Err(b)) if a == b => {}
            (Err(ErrorKind::LimitExceeded), _) | (_, Err(ErrorKind::LimitExceeded)) => {}
            (a, b) => panic!("{f:?} iteration {it}: one-shot {:?} vs streamed {:?}", a.as_ref().map(|v| v.len()), b.as_ref().map(|v| v.len())),
        }
    }
    eprintln!("{f:?}: {iters} inputs, {ok} decoded");
}

#[cfg(feature = "brotli")]
#[test]
fn fuzz_brotli() {
    fuzz(Format::Brotli, "brotli", 1);
}

#[cfg(feature = "zstd")]
#[test]
fn fuzz_zstd() {
    fuzz(Format::Zstd, "zstd", 2);
}

#[test]
fn fuzz_random_bytes() {
    let mut r = Rng((seed() ^ 0xA5A5_5A5A_1234_5678) | 1);
    for _ in 0..iterations(3000) {
        let mut d: Vec<u8> = (0..r.below(500)).map(|_| r.next() as u8).collect();
        if d.len() > 4 && r.below(2) == 0 {
            d[..4].copy_from_slice(&0xFD2F_B528u32.to_le_bytes());
        }
        #[cfg(feature = "brotli")]
        let _ = decompress(&d, Format::Brotli, 50_000);
        #[cfg(feature = "zstd")]
        let _ = decompress(&d, Format::Zstd, 50_000);
    }
}
