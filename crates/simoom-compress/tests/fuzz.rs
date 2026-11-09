//! A std-only seeded mutation fuzzer for the decoder (plan §7.3 option F2).
//!
//! Quick by default. For a long run:
//! `SIMOOM_FUZZ_ITERS=2000000 cargo test -p simoom-compress --release --test fuzz -- --nocapture`;
//! `SIMOOM_FUZZ_SEED=<n>` replays a run.
//!
//! Invariants on every input: no panic; the output never passes the limit; decoding in random
//! pieces (into a `Vec` and into small slices) gives the same output and the same error kind
//! as decoding in one go; consumed counts never exceed the input; a successful decode of a
//! valid stream returns the original data.

use simoom_compress::{compress, decompress, Decoder, Encoder, ErrorKind, Format};

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
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_c0de_0000_0001)
}

fn seeds(r: &mut Rng) -> Vec<(Format, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let texts: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"x".to_vec(),
        b"hello hello hello world".to_vec(),
        "abcdefghij".repeat(300).into_bytes(),
        (0..3000).map(|_| r.next() as u8).collect(),
        (0..5000u32).map(|i| b"GET /index.html HTTP/1.1\r\n"[(i % 26) as usize] ^ (i / 1000) as u8).collect(),
        vec![0; 40_000],
    ];
    for t in &texts {
        for f in [Format::Raw, Format::Zlib, Format::Gzip] {
            for level in [0, 1, 6, 9] {
                out.push((f, compress(t, f, level), t.clone()));
            }
            // with sync flushes in the middle
            let mut e = Encoder::new(f, 6);
            let mut c = Vec::new();
            for part in t.chunks(700) {
                e.encode(part, &mut c);
                e.flush(&mut c);
            }
            e.finish(&mut c);
            out.push((f, c, t.clone()));
        }
    }
    out
}

fn mutate(r: &mut Rng, data: &mut Vec<u8>) {
    for _ in 0..1 + r.below(4) {
        if data.is_empty() {
            data.push(r.next() as u8);
            continue;
        }
        let i = r.below(data.len());
        match r.below(7) {
            0 => data[i] ^= 1 << r.below(8),
            1 => data[i] = r.next() as u8,
            2 => {
                data.truncate(i);
            }
            3 => {
                let n = r.below(16);
                for _ in 0..n {
                    data.insert(i, r.next() as u8);
                }
            }
            4 => {
                let n = r.below(16).min(data.len() - i);
                data.drain(i..i + n);
            }
            5 => {
                // duplicate a slice (repeats blocks and headers)
                let n = r.below(64).min(data.len() - i);
                let s: Vec<u8> = data[i..i + n].to_vec();
                let j = r.below(data.len());
                data.splice(j..j, s);
            }
            _ => data[i] = [0, 0xFF, 0x1F, 0x8B, 0x78, 0x9C][r.below(6)],
        }
    }
}

/// Decodes in random pieces both ways; returns the output or the error kind.
fn streamed(r: &mut Rng, f: Format, data: &[u8], limit: usize) -> Result<Vec<u8>, ErrorKind> {
    let mut d = Decoder::with_limit(f, limit as u64);
    let mut out = Vec::new();
    let mut i = 0;
    let mut stalls = 0;
    while i < data.len() {
        let n = (1 + r.below(200)).min(data.len() - i);
        let used = d.decode(&data[i..i + n], &mut out).map_err(|e| e.kind())?;
        assert!(used <= n);
        assert!(out.len() <= limit, "output passed the limit");
        if used < n {
            // only after the end of the stream
            assert!(d.is_done());
            break;
        }
        i += used;
        stalls += (used == 0) as usize;
        assert!(stalls < 10_000);
    }
    d.finish().map_err(|e| e.kind())?;
    Ok(out)
}

fn sliced(r: &mut Rng, f: Format, data: &[u8], limit: usize) -> Result<Vec<u8>, ErrorKind> {
    let mut d = Decoder::with_limit(f, limit as u64);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 + r.below(5000)];
    let mut i = 0;
    let mut idle = 0;
    loop {
        let n = (1 + r.below(300)).min(data.len() - i);
        let (used, w) = d.decode_into(&data[i..i + n], &mut buf).map_err(|e| e.kind())?;
        assert!(used <= n && w <= buf.len());
        out.extend_from_slice(&buf[..w]);
        assert!(out.len() <= limit);
        i += used;
        if used == 0 && w == 0 {
            idle += 1;
            if i >= data.len() || d.is_done() || idle > 3 {
                break;
            }
        } else {
            idle = 0;
        }
    }
    d.finish().map_err(|e| e.kind())?;
    Ok(out)
}

#[test]
fn fuzz_decoder() {
    let mut r = Rng(seed());
    let seeds = seeds(&mut r);
    let iters = iterations(4000);
    let mut ok = 0;
    for it in 0..iters {
        let (f, base, plain) = &seeds[r.below(seeds.len())];
        let mut data = base.clone();
        let mutated = r.below(10) != 0;
        if mutated {
            mutate(&mut r, &mut data);
        }
        let f = if r.below(8) == 0 { Format::ZlibOrRaw } else { *f };
        let limit = if r.below(4) == 0 { r.below(50_000) } else { 1 << 20 };
        let one = decompress(&data, f, limit).map_err(|e| e.kind());
        if let Ok(o) = &one {
            assert!(o.len() <= limit);
            ok += 1;
        }
        if !mutated && f != Format::ZlibOrRaw && plain.len() <= limit {
            assert_eq!(one.as_ref().ok(), Some(plain), "iteration {it}: a valid stream must decode");
        }
        // The streaming paths agree with the one-shot result, except that a limit error may come
        // earlier or later relative to other errors (it depends on how much is buffered), and a
        // gzip stream with bytes after the last member may be judged differently once split.
        for (path, got) in [("vec", streamed(&mut r, f, &data, limit)), ("slice", sliced(&mut r, f, &data, limit))] {
            match (&one, &got) {
                (Ok(a), Ok(b)) => assert!(a == b, "iteration {it} ({path}): outputs differ"),
                (Err(a), Err(b)) if a == b => {}
                (Err(ErrorKind::LimitExceeded), _) | (_, Err(ErrorKind::LimitExceeded)) => {}
                (a, b) => panic!("iteration {it} ({path}): one-shot {:?} vs streamed {:?}", a.as_ref().map(|v| v.len()), b.as_ref().map(|v| v.len())),
            }
        }
    }
    eprintln!("fuzz_decoder: {iters} inputs, {ok} decoded");
}

#[test]
fn fuzz_random_bytes() {
    let mut r = Rng(seed() ^ 0xABCD);
    for _ in 0..iterations(4000) {
        let n = r.below(600);
        let mut data: Vec<u8> = (0..n).map(|_| r.next() as u8).collect();
        // give some inputs a valid header so the block decoder is reached
        match r.below(4) {
            0 if data.len() > 2 => {
                data[0] = 0x78;
                data[1] = 0x9C;
            }
            1 if data.len() > 10 => data[..10].copy_from_slice(&[0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3]),
            _ => {}
        }
        for f in [Format::Raw, Format::Zlib, Format::Gzip, Format::ZlibOrRaw] {
            if let Ok(o) = decompress(&data, f, 100_000) {
                assert!(o.len() <= 100_000);
            }
        }
    }
}

#[test]
fn fuzz_encoder_round_trips() {
    let mut r = Rng(seed() ^ 0x1234);
    for _ in 0..iterations(300) {
        // structured data: runs, repeats at random distances, noise
        let mut data = Vec::new();
        let target = r.below(150_000);
        while data.len() < target {
            match r.below(4) {
                0 => {
                    let b = r.next() as u8;
                    data.extend(std::iter::repeat_n(b, r.below(400)));
                }
                1 if !data.is_empty() => {
                    let d = 1 + r.below(data.len().min(40_000));
                    let n = r.below(300);
                    for _ in 0..n {
                        let b = data[data.len() - d];
                        data.push(b);
                    }
                }
                _ => data.extend((0..r.below(200)).map(|_| (r.next() % 16) as u8 + b'a')),
            }
        }
        let f = [Format::Raw, Format::Zlib, Format::Gzip][r.below(3)];
        let level = r.below(10) as u32;
        let mut e = Encoder::new(f, level);
        let mut c = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let n = (1 + r.below(40_000)).min(data.len() - i);
            e.encode(&data[i..i + n], &mut c);
            if r.below(10) == 0 {
                e.flush(&mut c);
            }
            i += n;
        }
        e.finish(&mut c);
        assert!(decompress(&c, f, data.len()).unwrap() == data, "{f:?} level {level}");
    }
}
