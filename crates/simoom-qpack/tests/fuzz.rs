//! Std-only seeded mutation fuzzing of the QPACK decoder, the encoder's decoder-stream parser and
//! the Huffman decoder. Iterations: `SIMOOM_FUZZ_ITERS` (default 20000), seed:
//! `SIMOOM_FUZZ_SEED`.
//!
//! Valid inputs are produced by the encoder, then mutated (bit flips, byte changes, truncation,
//! insertion, deletion, splicing, integer-boundary bytes). Every mutant must be handled without
//! a panic, with the dynamic table within its capacity and decoded sections within the limit.

use simoom_qpack::{huffman, Decoded, Decoder, Encoder};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

const CAP: u64 = 512;
const SECTION: u64 = 4096;

/// A corpus of (encoder stream, sections, decoder stream) from real encoder sessions.
type Case = (Vec<u8>, Vec<Vec<u8>>, Vec<u8>);

fn corpus(rng: &mut Rng) -> Vec<Case> {
    let names: [&[u8]; 8] = [b":path", b":authority", b"x-a", b"content-type", b"cookie", b"authorization", b"", b"x-long-header-name"];
    let mut out = Vec::new();
    for s in 0..24 {
        let mut e = if s % 3 == 0 { Encoder::new() } else { Encoder::with_dynamic_table(CAP) };
        e.set_peer_settings(CAP, 4);
        let mut d = Decoder::new(CAP, 4, SECTION);
        let mut es = Vec::new();
        let mut sections = Vec::new();
        let mut ds = Vec::new();
        for i in 0..6u64 {
            let mut fields: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            for _ in 0..rng.below(6) + 1 {
                let n = names[rng.below(names.len())].to_vec();
                let v: Vec<u8> = (0..rng.below(40)).map(|_| (rng.next() % 256) as u8).collect();
                fields.push((n, v));
            }
            let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
            let mut block = Vec::new();
            e.encode(i * 4, &pairs, &mut block);
            let start = es.len();
            e.take_encoder_stream(&mut es);
            d.on_encoder_stream(&es[start..]).unwrap();
            assert!(matches!(d.decode(i * 4, &block), Ok(Decoded::Fields(_))));
            let start = ds.len();
            d.take_decoder_stream(&mut ds);
            e.on_decoder_stream(&ds[start..]).unwrap();
            sections.push(block);
        }
        out.push((es, sections, ds));
    }
    out
}

fn mutate(rng: &mut Rng, data: &mut Vec<u8>, other: &[u8]) {
    for _ in 0..rng.below(4) + 1 {
        match rng.below(8) {
            0 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] ^= 1 << rng.below(8);
            }
            1 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] = (rng.next() % 256) as u8;
            }
            2 => {
                let n = rng.below(data.len() + 1);
                data.truncate(n);
            }
            3 => {
                let i = rng.below(data.len() + 1);
                let b = [0x00, 0x7f, 0x80, 0xff, 0x3f, 0x1f, 0x0f][rng.below(7)];
                data.insert(i, b);
            }
            4 if !data.is_empty() => {
                let i = rng.below(data.len());
                data.remove(i);
            }
            5 if !other.is_empty() => {
                let a = rng.below(other.len());
                let b = a + rng.below(other.len() - a + 1);
                let i = rng.below(data.len() + 1);
                data.splice(i..i, other[a..b].iter().copied());
            }
            6 => {
                // a long run of continuation bytes, testing integer overflow
                let i = rng.below(data.len() + 1);
                let n = rng.below(12);
                data.splice(i..i, std::iter::repeat_n(0xff, n));
            }
            _ => {
                let i = rng.below(data.len() + 1);
                data.insert(i, (rng.next() % 256) as u8);
            }
        }
    }
}

fn check_decoder(d: &Decoder) {
    assert!(d.table_size() <= CAP);
    assert!(d.blocked_streams() <= 4);
}

#[test]
fn fuzz_qpack() {
    let iters = env("SIMOOM_FUZZ_ITERS", 20000);
    let seed = env("SIMOOM_FUZZ_SEED", 0x5eed_9204);
    let mut rng = Rng(seed | 1);
    let corpus = corpus(&mut rng);
    let mut accepted = 0u64;
    for _ in 0..iters {
        let (es, sections, ds) = &corpus[rng.below(corpus.len())];
        let (_, other_sections, other_ds) = &corpus[rng.below(corpus.len())];
        let other = &other_sections[rng.below(other_sections.len())];
        let mut d = Decoder::new(CAP, 4, SECTION);
        let target = rng.below(4);
        // encoder stream: mutated or intact, delivered in random pieces
        let mut stream = es.clone();
        if target == 0 {
            mutate(&mut rng, &mut stream, other);
        }
        let mut pos = 0;
        let mut ok = true;
        while pos < stream.len() && ok {
            let n = (rng.below(64) + 1).min(stream.len() - pos);
            match d.on_encoder_stream(&stream[pos..pos + n]) {
                Ok(done) => {
                    for (_, r) in done {
                        if let Ok(f) = r {
                            assert!(f.iter().map(|x| x.size()).sum::<u64>() <= SECTION);
                        }
                    }
                }
                Err(_) => ok = false,
            }
            check_decoder(&d);
            pos += n;
        }
        // sections: mutated or intact, some before and some after the encoder stream
        for (i, s) in sections.iter().enumerate() {
            let mut block = s.clone();
            if target == 1 || (target == 3 && rng.below(2) == 0) {
                mutate(&mut rng, &mut block, other);
            }
            match d.decode(i as u64 * 4 + 1000, &block) {
                Ok(Decoded::Fields(f)) => {
                    accepted += 1;
                    assert!(f.iter().map(|x| x.size()).sum::<u64>() <= SECTION);
                }
                Ok(Decoded::Blocked) => {
                    if rng.below(2) == 0 {
                        d.cancel_stream(i as u64 * 4 + 1000);
                    }
                }
                Err(_) => {}
            }
            check_decoder(&d);
        }
        let mut out = Vec::new();
        d.take_decoder_stream(&mut out);
        // decoder stream into an encoder that has state to acknowledge
        if target == 2 {
            let mut e = Encoder::with_dynamic_table(CAP);
            e.set_peer_settings(CAP, 4);
            for i in 0..4u64 {
                let v = format!("{i}");
                let mut b = Vec::new();
                e.encode(i * 4, &[(b"x-a", v.as_bytes())], &mut b);
            }
            let mut m = ds.clone();
            mutate(&mut rng, &mut m, other_ds);
            let _ = e.on_decoder_stream(&m);
            assert!(e.known_received_count() <= e.insert_count());
        }
        // Huffman on raw mutated bytes
        let mut h = other.clone();
        mutate(&mut rng, &mut h, es);
        let mut out = Vec::new();
        if huffman::decode(&h, &mut out).is_ok() {
            let mut re = Vec::new();
            huffman::encode(&out, &mut re);
            let mut back = Vec::new();
            huffman::decode(&re, &mut back).unwrap();
            assert_eq!(back, out);
        }
    }
    assert!(accepted > 0);
}

/// The decoder gives the same result however the encoder stream is split.
#[test]
fn split_invariance() {
    let mut rng = Rng(0x1234_5678);
    let corpus = corpus(&mut rng);
    for (es, sections, _) in &corpus {
        let mut whole = Decoder::new(CAP, 4, SECTION);
        whole.on_encoder_stream(es).unwrap();
        for _ in 0..20 {
            let mut d = Decoder::new(CAP, 4, SECTION);
            let mut pos = 0;
            while pos < es.len() {
                let n = (rng.below(8) + 1).min(es.len() - pos);
                d.on_encoder_stream(&es[pos..pos + n]).unwrap();
                pos += n;
            }
            assert_eq!(d.insert_count(), whole.insert_count());
            assert_eq!(d.table_size(), whole.table_size());
            for (i, s) in sections.iter().enumerate().rev().take(1) {
                assert_eq!(d.decode(i as u64, s), whole.decode(i as u64, s));
            }
        }
    }
}
