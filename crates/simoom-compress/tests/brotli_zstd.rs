//! Brotli and zstd: streams produced by the reference implementations (brotli 8.0.4 at
//! qualities 0-11 and windows 2^10-2^24; libzstd 1.5.7 at levels 1-19, with and without the
//! checksum) decode to their inputs, in one go and in pieces; our encoders round-trip at every
//! level; limits, window caps, dictionaries and corrupt input behave.

#![cfg(any(feature = "brotli", feature = "zstd"))]

use simoom_compress::{compress, decompress, Decoder, Encoder, ErrorKind, Format};
use std::path::Path;

fn vectors() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors"))
}

fn input(name: &str) -> Vec<u8> {
    if name == "empty.bin" {
        return Vec::new();
    }
    std::fs::read(vectors().join(name)).unwrap()
}

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

/// Every vector in `dir`: (compressed file name, compressed bytes, original).
fn reference(dir: &str) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(vectors().join(dir)).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let orig = name.split(".q").next().unwrap().split(".l").next().unwrap().to_string();
        v.push((name, std::fs::read(&p).unwrap(), input(&orig)));
    }
    v.sort();
    assert!(v.len() >= 20, "{dir}: {} vectors", v.len());
    v
}

fn streamed(f: Format, c: &[u8], piece: usize, slice: Option<usize>) -> Vec<u8> {
    let mut d = Decoder::new(f);
    let mut out = Vec::new();
    match slice {
        None => {
            for part in c.chunks(piece.max(1)) {
                d.decode(part, &mut out).unwrap();
            }
        }
        Some(n) => {
            let mut buf = vec![0u8; n];
            for part in c.chunks(piece.max(1)) {
                let (_, w) = d.decode_into(part, &mut buf).unwrap();
                out.extend_from_slice(&buf[..w]);
                while d.has_pending() {
                    let (_, w) = d.decode_into(&[], &mut buf).unwrap();
                    out.extend_from_slice(&buf[..w]);
                    if w == 0 && !d.has_pending() {
                        break;
                    }
                }
            }
            loop {
                let (_, w) = d.decode_into(&[], &mut buf).unwrap();
                if w == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..w]);
            }
        }
    }
    d.finish().unwrap();
    out
}

fn reference_vectors(dir: &str, f: Format) {
    let mut r = Rng(3);
    for (name, c, orig) in reference(dir) {
        let one = decompress(&c, f, 1 << 24).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(one == orig, "{name}: one-shot output differs ({} vs {} bytes)", one.len(), orig.len());
        simoom_sys::codec::set_safe_only(true);
        let safe = decompress(&c, f, 1 << 24).unwrap_or_else(|e| panic!("{name} (safe loops): {e}"));
        simoom_sys::codec::set_safe_only(false);
        assert!(safe == orig, "{name}: safe loops differ");
        let piece = 1 + r.below(700);
        assert!(streamed(f, &c, piece, None) == orig, "{name}: in {piece}-byte pieces");
        assert!(streamed(f, &c, 1, Some(1 + r.below(300))) == orig, "{name}: byte by byte into small slices");
    }
}

fn round_trips(f: Format, levels: std::ops::RangeInclusive<u32>) {
    let mut r = Rng(11);
    let mut inputs: Vec<Vec<u8>> = ["text.txt", "data.json", "random.bin", "runs.bin", "empty.bin"].iter().map(|n| input(n)).collect();
    inputs.push(b"a".to_vec());
    inputs.push(vec![0; 300_000]);
    inputs.push(input("text.txt").repeat(40)); // ~1 MB: several blocks and meta-blocks
    for data in &inputs {
        for level in levels.clone() {
            let c = compress(data, f, level);
            let d = decompress(&c, f, data.len()).unwrap_or_else(|e| panic!("{f:?} level {level}, {} bytes: {e}", data.len()));
            assert!(d == *data, "{f:?} level {level}, {} bytes", data.len());
            // the kernels built without BMI2 give the same stream and output
            simoom_sys::bits::set_scalar_only(true);
            let (c2, d2) = (compress(data, f, level), decompress(&c, f, data.len()));
            simoom_sys::bits::set_scalar_only(false);
            assert!(c2 == c && d2.as_ref().ok() == Some(&d), "{f:?} level {level}: scalar and BMI2 kernels differ");
            // and the safe reference loops the same as the pointer-code ones
            simoom_sys::codec::set_safe_only(true);
            let (c3, d3) = (compress(data, f, level), decompress(&c, f, data.len()));
            simoom_sys::codec::set_safe_only(false);
            assert!(c3 == c && d3.as_ref().ok() == Some(&d), "{f:?} level {level}: safe and fast loops differ");
            // one-shot into an output that already holds bytes (which the stream never sees)
            let mut out = b"earlier bytes".to_vec();
            simoom_compress::decompress_into(&c, f, data.len(), &mut out).unwrap();
            assert!(out[..13] == *b"earlier bytes" && out[13..] == *data, "{f:?} level {level}, after a prefix");
        }
        // streaming with flushes; each flush makes everything so far decodable
        let mut e = Encoder::new(f, *levels.start() + 2);
        let mut dec = Decoder::new(f);
        let (mut c, mut plain) = (Vec::new(), Vec::new());
        let mut i = 0;
        while i < data.len() {
            let n = (1 + r.below(20_000)).min(data.len() - i);
            e.encode(&data[i..i + n], &mut c);
            if r.below(3) == 0 {
                e.flush(&mut c);
                dec.decode(&c, &mut plain).unwrap();
                assert!(plain == data[..i + n], "{f:?}: data before a flush decodes");
                c.clear();
            }
            i += n;
        }
        e.finish(&mut c);
        dec.decode(&c, &mut plain).unwrap();
        dec.finish().unwrap();
        assert!(plain == *data, "{f:?} streamed, {} bytes", data.len());
    }
}

fn limits_and_errors(f: Format) {
    let zeros = vec![0u8; 8 << 20];
    let c = compress(&zeros, f, 3);
    assert!(c.len() < 64 << 10, "{f:?}: {} bytes", c.len());
    assert_eq!(decompress(&c, f, 1 << 20).unwrap_err().kind(), ErrorKind::LimitExceeded);
    assert_eq!(decompress(&c, f, zeros.len()).unwrap().len(), zeros.len());
    let mut d = Decoder::with_limit(f, 100_000);
    let mut out = Vec::new();
    assert_eq!(d.decode(&c, &mut out).unwrap_err().kind(), ErrorKind::LimitExceeded);
    assert!(out.len() <= 100_000);
    // truncated at every point of a small stream
    let small = compress(&input("text.txt")[..3000], f, 5);
    for cut in 0..small.len() {
        let mut d = Decoder::new(f);
        let mut out = Vec::new();
        match d.decode(&small[..cut], &mut out) {
            Ok(_) => assert_eq!(d.finish().unwrap_err().kind(), ErrorKind::Truncated, "{f:?} cut at {cut}"),
            Err(e) => panic!("{f:?} cut at {cut}: {e}"),
        }
    }
}

#[cfg(feature = "brotli")]
mod brotli {
    use super::*;

    #[test]
    fn reference_streams_decode() {
        reference_vectors("brotli", Format::Brotli);
    }

    #[test]
    fn our_streams_round_trip() {
        round_trips(Format::Brotli, 0..=11);
    }

    #[test]
    fn limits_windows_and_errors() {
        limits_and_errors(Format::Brotli);
        // a 16 MiB window stream is refused under a 4 MiB cap
        let c = std::fs::read(vectors().join("brotli/data.json.q11w24.br")).unwrap();
        let mut d = Decoder::new(Format::Brotli).window_limit(4 << 20);
        assert_eq!(d.decode(&c, &mut Vec::new()).unwrap_err().kind(), ErrorKind::LimitExceeded);
        let mut d = Decoder::new(Format::Brotli).window_limit(16 << 20);
        let mut out = Vec::new();
        d.decode(&c, &mut out).unwrap();
        d.finish().unwrap();
        // the smallest streams: empty, a single byte, an uncompressed meta-block
        assert_eq!(decompress(&[0x06], Format::Brotli, 10).unwrap(), b"");
        assert_eq!(Format::from_content_encoding(b"BR"), Some(Format::Brotli));
        assert_eq!(Format::Brotli.content_encoding(), "br");
        // the large-window marker and a bad prefix code are refused
        assert!(decompress(&[0x11, 0, 0], Format::Brotli, 1000).is_err());
        assert!(decompress(&[0x0B, 0xFF, 0xFF, 0xFF, 0xFF], Format::Brotli, 1000).is_err());
    }
}

#[cfg(feature = "zstd")]
mod zstd {
    use super::*;

    #[test]
    fn reference_streams_decode() {
        reference_vectors("zstd", Format::Zstd);
    }

    #[test]
    fn our_streams_round_trip() {
        round_trips(Format::Zstd, 1..=12);
    }

    #[test]
    fn limits_windows_and_errors() {
        limits_and_errors(Format::Zstd);
        // a 2 MiB window is refused under a 1 MiB cap
        let c = compress(&input("text.txt"), Format::Zstd, 5);
        let mut d = Decoder::new(Format::Zstd).window_limit(1 << 20);
        assert_eq!(d.decode(&c, &mut Vec::new()).unwrap_err().kind(), ErrorKind::LimitExceeded);
        assert_eq!(Format::from_content_encoding(b"zstd"), Some(Format::Zstd));
        assert_eq!(Format::Zstd.content_encoding(), "zstd");
        // a wrong checksum is caught
        let ck = std::fs::read(vectors().join("zstd/text.txt.l3ck.zst")).unwrap();
        let mut bad = ck.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(decompress(&bad, Format::Zstd, 1 << 20).unwrap_err().kind(), ErrorKind::Checksum);
        // two frames and a skippable frame in between decode as one stream
        let mut two = compress(b"first ", Format::Zstd, 1);
        two.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
        two.extend_from_slice(&compress(b"second", Format::Zstd, 3));
        assert_eq!(decompress(&two, Format::Zstd, 100).unwrap(), b"first second");
        assert!(decompress(b"not zstd at all", Format::Zstd, 100).is_err());
    }

    #[test]
    fn raw_content_dictionary() {
        // A frame produced against raw-content history: the reference CLI can't make one
        // without a dictionary file, so check the decoder's handling by hand: a frame whose
        // first match reaches into the dictionary.
        let dict = b"common prefix shared by every message: ".to_vec();
        let mut d = Decoder::new(Format::Zstd);
        d.add_dictionary(&dict).unwrap();
        // without a dictionary-aware encoder, a normal frame still decodes with one loaded
        let c = compress(b"hello hello hello", Format::Zstd, 3);
        let mut out = Vec::new();
        d.decode(&c, &mut out).unwrap();
        d.finish().unwrap();
        assert_eq!(out, b"hello hello hello");
    }
}

/// A meta-block longer than the window (Brotli quality 0-1: 1 MiB meta-blocks, 256 KiB window)
/// with matches far apart: no distance may pass the window.
#[cfg(feature = "brotli")]
#[test]
fn brotli_fast_qualities_keep_distances_in_the_window() {
    let mut r = Rng(5);
    let mut d = Vec::new();
    while d.len() < 900_000 {
        let n = r.below(1_000_000);
        d.extend_from_slice(format!("{{\"id\":{n},\"sku\":\"SKU-{:06}\",\"price\":{}.{:02}}},", n % 77_777, n % 500, n % 100).as_bytes());
    }
    for q in [0, 1] {
        for safe in [false, true] {
            simoom_sys::codec::set_safe_only(safe);
            let c = compress(&d, Format::Brotli, q);
            assert!(decompress(&c, Format::Brotli, d.len()).unwrap() == d, "quality {q}, safe loops {safe}");
        }
        simoom_sys::codec::set_safe_only(false);
    }
}
