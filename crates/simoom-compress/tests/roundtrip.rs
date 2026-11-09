//! Test vectors from the RFCs and from zlib/gzip output, round trips at every level, streaming
//! in arbitrary pieces, limits, and error cases.

use simoom_compress::{compress, crc32, decompress, Decoder, Encoder, ErrorKind, Format};

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

/// Test inputs: empty, tiny, text, repetitive, random, long runs, and mixes.
fn corpus() -> Vec<Vec<u8>> {
    let mut r = Rng(42);
    let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let json: String = (0..2000).map(|i| format!("{{\"id\":{i},\"name\":\"item-{}\",\"tags\":[\"a\",\"b{}\"],\"price\":{}.{:02}}},", i * 7 % 13, i % 5, i * 3, i % 100)).collect();
    let random: Vec<u8> = (0..100_000).map(|_| r.next() as u8).collect();
    let mut mixed = Vec::new();
    for i in 0..300 {
        if i % 3 == 0 {
            mixed.extend((0..r.below(2000)).map(|_| r.next() as u8));
        } else {
            mixed.extend_from_slice(&json.as_bytes()[r.below(json.len() - 3000)..][..r.below(3000)]);
        }
    }
    vec![
        Vec::new(),
        b"a".to_vec(),
        b"ab".to_vec(),
        b"aaa".to_vec(),
        b"abcabcabc".to_vec(),
        text.repeat(200).into_bytes(),
        json.into_bytes(),
        random,
        vec![0u8; 300_000],
        vec![7u8; 65_537],
        (0..200_000u32).map(|i| (i % 251) as u8).collect(),
        (0..70_000u32).map(|i| (i / 300) as u8).collect(),
        mixed,
    ]
}

#[test]
fn round_trip_every_level_and_format() {
    for data in corpus() {
        for format in [Format::Raw, Format::Zlib, Format::Gzip] {
            for level in 0..=9 {
                let c = compress(&data, format, level);
                let d = decompress(&c, format, data.len()).unwrap_or_else(|e| panic!("{format:?} level {level} len {}: {e}", data.len()));
                assert!(d == data, "{format:?} level {level} len {}", data.len());
            }
        }
    }
}

#[test]
fn compression_ratio_is_reasonable() {
    let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(1000);
    let c6 = compress(text.as_bytes(), Format::Raw, 6);
    assert!(c6.len() < 400, "{}", c6.len());
    let random: Vec<u8> = {
        let mut r = Rng(7);
        (0..50_000).map(|_| r.next() as u8).collect()
    };
    // Incompressible data is stored: at most 5 bytes per 64 KiB block more.
    for level in [1, 6, 9] {
        let c = compress(&random, Format::Raw, level);
        assert!(c.len() <= random.len() + 5 * 2 + 64, "level {level}: {}", c.len());
    }
}

#[test]
fn streaming_in_pieces_matches_one_shot() {
    let mut r = Rng(9);
    for data in corpus() {
        for format in [Format::Raw, Format::Zlib, Format::Gzip] {
            let level = r.below(10) as u32;
            // encode in random pieces, with an occasional sync flush
            let mut enc = Encoder::new(format, level);
            let mut c = Vec::new();
            let mut i = 0;
            while i < data.len() {
                let n = (r.below(5000) + 1).min(data.len() - i);
                enc.encode(&data[i..i + n], &mut c);
                if r.below(8) == 0 {
                    enc.flush(&mut c);
                }
                i += n;
            }
            enc.finish(&mut c);
            assert_eq!(decompress(&c, format, data.len()).unwrap(), data);
            // decode in random pieces, as a Vec
            let mut dec = Decoder::with_limit(format, data.len() as u64);
            let mut out = Vec::new();
            let mut i = 0;
            while i < c.len() {
                let n = (r.below(300) + 1).min(c.len() - i);
                let used = dec.decode(&c[i..i + n], &mut out).unwrap();
                assert_eq!(used, n);
                i += n;
            }
            dec.finish().unwrap();
            assert!(out == data);
            assert_eq!(dec.total_out(), data.len() as u64);
            assert_eq!(dec.total_in(), c.len() as u64);
            // decode one byte at a time into a small slice
            let mut dec = Decoder::new(format);
            let mut out = Vec::new();
            let mut buf = [0u8; 61];
            let mut i = 0;
            loop {
                let inp = if i < c.len() { &c[i..i + 1] } else { &[][..] };
                let (used, n) = dec.decode_into(inp, &mut buf).unwrap();
                out.extend_from_slice(&buf[..n]);
                i += used;
                if i >= c.len() && !dec.has_pending() && n == 0 {
                    break;
                }
            }
            dec.finish().unwrap();
            assert!(out == data, "{format:?} level {level} len {}", data.len());
        }
    }
}

#[test]
fn sync_flush_makes_data_decodable() {
    let mut enc = Encoder::new(Format::Gzip, 6);
    let mut dec = Decoder::new(Format::Gzip);
    let mut c = Vec::new();
    let mut plain = Vec::new();
    for i in 0..50 {
        let msg = format!("data: event number {i} with some repeated text text text\n\n");
        c.clear();
        enc.encode(msg.as_bytes(), &mut c);
        enc.flush(&mut c);
        assert_eq!(&c[c.len() - 4..], &[0, 0, 0xFF, 0xFF]);
        let before = plain.len();
        dec.decode(&c, &mut plain).unwrap();
        assert_eq!(&plain[before..], msg.as_bytes(), "message {i} decodable after its flush");
    }
    c.clear();
    enc.finish(&mut c);
    dec.decode(&c, &mut plain).unwrap();
    dec.finish().unwrap();
}

#[test]
fn rfc1951_fixed_and_stored_vectors() {
    // A stored block "hello" (BFINAL=1, BTYPE=00).
    assert_eq!(decompress(&[0x01, 5, 0, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'], Format::Raw, 100).unwrap(), b"hello");
    // zlib.compress(b"hello", 9) with the header and Adler-32: a fixed-Huffman block.
    let z = [0x78, 0xDA, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00, 0x06, 0x2C, 0x02, 0x15];
    assert_eq!(decompress(&z, Format::Zlib, 100).unwrap(), b"hello");
    // The empty fixed block: 03 00.
    assert_eq!(decompress(&[0x03, 0x00], Format::Raw, 100).unwrap(), b"");
    // gzip of "hello\n" as produced by `gzip -n`.
    let g = [
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0xE7, 0x02, 0x00, 0x20, 0x30, 0x3A, 0x36, 0x06, 0x00,
        0x00, 0x00,
    ];
    assert_eq!(decompress(&g, Format::Gzip, 100).unwrap(), b"hello\n");
    // A match with distance 1 (run): "a" then length 9, distance 1 → ten 'a'.
    let run = compress(&[b'a'; 10], Format::Raw, 9);
    assert_eq!(decompress(&run, Format::Raw, 100).unwrap(), [b'a'; 10]);
}

#[test]
fn rfc1950_and_rfc1952_headers() {
    let data = b"header test header test header test";
    // gzip with FEXTRA, FNAME, FCOMMENT and FHCRC.
    let body = compress(data, Format::Raw, 6);
    let mut h = vec![0x1F, 0x8B, 8, 2 | 4 | 8 | 16, 1, 2, 3, 4, 0, 3];
    h.extend_from_slice(&[4, 0, b'a', b'b', 2, 0]); // XLEN = 4, one subfield
    h.extend_from_slice(b"file.txt\0");
    h.extend_from_slice(b"a comment\0");
    let hcrc = crc32(&h) as u16;
    h.extend_from_slice(&hcrc.to_le_bytes());
    h.extend_from_slice(&body);
    h.extend_from_slice(&crc32(data).to_le_bytes());
    h.extend_from_slice(&(data.len() as u32).to_le_bytes());
    assert_eq!(decompress(&h, Format::Gzip, 100).unwrap(), data);
    // and byte by byte
    let mut d = Decoder::new(Format::Gzip);
    let mut out = Vec::new();
    for b in &h {
        d.decode(std::slice::from_ref(b), &mut out).unwrap();
    }
    d.finish().unwrap();
    assert_eq!(out, data);
    // a wrong header CRC
    let mut bad = h.clone();
    let p = 10 + 6 + 9 + 10;
    bad[p] ^= 1;
    assert_eq!(decompress(&bad, Format::Gzip, 100).unwrap_err().kind(), ErrorKind::Checksum);
    // zlib: every valid FLEVEL; FDICT is refused; a bad check value is refused
    for level in 0..=9 {
        let z = compress(data, Format::Zlib, level);
        assert_eq!(((z[0] as u16) << 8 | z[1] as u16) % 31, 0);
    }
    assert!(decompress(&[0x78, 0xBB, 0, 0, 0, 1, 3, 0], Format::Zlib, 100).is_err());
    assert!(decompress(&[0x78, 0x9D, 3, 0], Format::Zlib, 100).is_err());
}

#[test]
fn multi_member_gzip_and_trailing_bytes() {
    let mut g = compress(b"first ", Format::Gzip, 6);
    g.extend_from_slice(&compress(b"second", Format::Gzip, 1));
    assert_eq!(decompress(&g, Format::Gzip, 100).unwrap(), b"first second");
    let mut d = Decoder::new(Format::Gzip);
    let mut out = Vec::new();
    for b in &g {
        d.decode(std::slice::from_ref(b), &mut out).unwrap();
    }
    d.finish().unwrap();
    assert_eq!(out, b"first second");
    // trailing zeros (padding some tools add) are ignored
    let mut padded = compress(b"x", Format::Gzip, 6);
    padded.extend_from_slice(&[0; 9]);
    assert_eq!(decompress(&padded, Format::Gzip, 100).unwrap(), b"x");
}

#[test]
fn zlib_or_raw_detects_both() {
    let data = b"detect me detect me detect me";
    for format in [Format::Zlib, Format::Raw] {
        let c = compress(data, format, 6);
        assert_eq!(decompress(&c, Format::ZlibOrRaw, 100).unwrap(), data);
        let mut d = Decoder::new(Format::ZlibOrRaw);
        let mut out = Vec::new();
        d.decode(&c, &mut out).unwrap();
        d.finish().unwrap();
        assert_eq!(d.format(), format);
    }
    assert_eq!(Format::from_content_encoding(b"GZip"), Some(Format::Gzip));
    assert_eq!(Format::from_content_encoding(b"x-gzip"), Some(Format::Gzip));
    assert_eq!(Format::from_content_encoding(b"deflate"), Some(Format::ZlibOrRaw));
    assert_eq!(Format::from_content_encoding(b"br"), None);
}

#[test]
fn decompression_bomb_is_stopped() {
    let zeros = vec![0u8; 10 << 20];
    let c = compress(&zeros, Format::Gzip, 9);
    assert!(c.len() < 20_000, "{}", c.len());
    assert_eq!(decompress(&c, Format::Gzip, 1 << 20).unwrap_err().kind(), ErrorKind::LimitExceeded);
    assert_eq!(decompress(&c, Format::Gzip, zeros.len()).unwrap().len(), zeros.len());
    assert_eq!(decompress(&c, Format::Gzip, zeros.len() - 1).unwrap_err().kind(), ErrorKind::LimitExceeded);
    // streaming: the limit holds, and never more than the limit reaches the caller
    let mut d = Decoder::with_limit(Format::Gzip, 100_000);
    let mut out = Vec::new();
    let err = d.decode(&c, &mut out).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert!(out.len() <= 100_000);
    // a slice-bounded decode makes progress in small steps with bounded output
    let mut d = Decoder::new(Format::Gzip);
    let mut buf = [0u8; 4096];
    let (used, n) = d.decode_into(&c, &mut buf).unwrap();
    assert_eq!(n, buf.len());
    assert!(used < c.len());
}

#[test]
fn errors_are_reported() {
    let good = compress(b"some data some data", Format::Gzip, 6);
    // truncated at every point
    for cut in 0..good.len() {
        let e = decompress(&good[..cut], Format::Gzip, 100).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Truncated, "cut {cut}");
        let mut d = Decoder::new(Format::Gzip);
        let mut out = Vec::new();
        d.decode(&good[..cut], &mut out).unwrap();
        assert_eq!(d.finish().unwrap_err().kind(), ErrorKind::Truncated);
    }
    // a wrong CRC and length
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 8] ^= 0x55;
    assert_eq!(decompress(&bad, Format::Gzip, 100).unwrap_err().kind(), ErrorKind::Checksum);
    let mut bad = good.clone();
    bad[n - 1] ^= 1;
    assert_eq!(decompress(&bad, Format::Gzip, 100).unwrap_err().kind(), ErrorKind::Checksum);
    // block type 3, a distance past the start, an over-subscribed code
    assert_eq!(decompress(&[0x07], Format::Raw, 100).unwrap_err().kind(), ErrorKind::Invalid);
    // fixed block: literal 'a', then length 3 distance 2 (only 1 byte of history)
    let mut bw = Bits::default();
    bw.put(1, 1);
    bw.put(1, 2);
    bw.code(0x30 + b'a' as u32, 8);
    bw.code(1, 7); // length symbol 257: length 3
    bw.code(1, 5); // distance symbol 1: distance 2
    bw.code(0, 7);
    let e = decompress(&bw.done(), Format::Raw, 100).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Invalid);
    assert_eq!(e.to_string(), "distance too far back");
    // a stored block with a bad NLEN
    assert_eq!(decompress(&[0x01, 5, 0, 0xFA, 0xFE, 1, 2, 3, 4, 5], Format::Raw, 100).unwrap_err().kind(), ErrorKind::Invalid);
    // a dynamic block whose code length code is over-subscribed (all 19 lengths = 1)
    let mut bw = Bits::default();
    bw.put(1, 1);
    bw.put(2, 2);
    bw.put(0, 5);
    bw.put(0, 5);
    bw.put(15, 4);
    for _ in 0..19 {
        bw.put(1, 3);
    }
    assert_eq!(decompress(&bw.done(), Format::Raw, 100).unwrap_err().kind(), ErrorKind::Invalid);
    // gzip magic
    assert_eq!(decompress(b"\x1f\x8c\x08\0\0\0\0\0\0\x03", Format::Gzip, 100).unwrap_err().kind(), ErrorKind::Invalid);
}

/// A small bit writer for hand-made streams.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    bb: u64,
    n: u32,
}
impl Bits {
    fn put(&mut self, v: u32, n: u32) {
        self.bb |= (v as u64) << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.bb as u8);
            self.bb >>= 8;
            self.n -= 8;
        }
    }
    /// A Huffman code, most significant bit first.
    fn code(&mut self, c: u32, n: u32) {
        self.put(c.reverse_bits() >> (32 - n), n);
    }
    fn done(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.bb as u8);
        }
        self.out
    }
}

#[test]
fn reset_reuses_the_codecs() {
    let mut enc = Encoder::new(Format::Gzip, 6);
    let mut dec = Decoder::new(Format::Gzip);
    for round in 0..3 {
        let data = format!("round {round} round {round} round {round}").into_bytes();
        let mut c = Vec::new();
        enc.encode(&data, &mut c);
        enc.finish(&mut c);
        assert!(enc.is_finished());
        let mut out = Vec::new();
        dec.decode(&c, &mut out).unwrap();
        dec.finish().unwrap();
        assert_eq!(out, data);
        enc.reset();
        dec.reset();
    }
}

/// Streams produced by zlib (Python `zlib.compress(data, 9)` and `gzip.compress(data, 9,
/// mtime=0)`) for a 4 KiB pattern: dynamic Huffman blocks from another encoder.
#[test]
fn zlib_produced_dynamic_blocks() {
    let data: Vec<u8> = (0..4096u32).map(|i| b"the quick brown fox jumps over the lazy dog "[(i as usize * 7 + i as usize / 50) % 44]).collect();
    let zlib_out = include_bytes!("vectors/pattern.zlib");
    let gzip_out = include_bytes!("vectors/pattern.gz");
    assert_eq!(decompress(zlib_out, Format::Zlib, 1 << 16).unwrap(), data);
    assert_eq!(decompress(gzip_out, Format::Gzip, 1 << 16).unwrap(), data);
}
