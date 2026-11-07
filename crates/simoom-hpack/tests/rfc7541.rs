//! RFC 7541 Appendix C vectors, limits and encoder behaviour.

use simoom_hpack::{encode_integer, Decoder, Encoder, Error, DEFAULT_TABLE_SIZE};

type List = Vec<(Vec<u8>, Vec<u8>)>;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn h(list: &[(&str, &str)]) -> List {
    list.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()
}

fn decode(d: &mut Decoder, block: &[u8]) -> Result<List, Error> {
    let mut out = Vec::new();
    d.decode(block, &mut |n: &[u8], v: &[u8]| out.push((n.to_vec(), v.to_vec()))).map(|_| out)
}

fn encode(e: &mut Encoder, list: &List) -> Vec<u8> {
    let fields: Vec<(&[u8], &[u8])> = list.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
    let mut out = Vec::new();
    e.encode(&fields, &mut out);
    out
}

fn table(d: &Decoder) -> Vec<(String, String)> {
    (0..d.table_len())
        .map(|i| {
            let (n, v) = d.table_entry(i).unwrap();
            (String::from_utf8_lossy(n).into_owned(), String::from_utf8_lossy(v).into_owned())
        })
        .collect()
}

#[test]
fn c2_literal_representations() {
    // C.2.1 literal with indexing
    let mut d = Decoder::new(4096, 1 << 20);
    let block = hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572");
    assert_eq!(decode(&mut d, &block).unwrap(), h(&[("custom-key", "custom-header")]));
    assert_eq!(d.table_size(), 55);
    assert_eq!(table(&d), [("custom-key".into(), "custom-header".into())]);
    // C.2.2 literal without indexing
    let mut d = Decoder::new(4096, 1 << 20);
    assert_eq!(decode(&mut d, &hex("040c 2f73 616d 706c 652f 7061 7468")).unwrap(), h(&[(":path", "/sample/path")]));
    assert_eq!(d.table_len(), 0);
    // C.2.3 never indexed
    let mut d = Decoder::new(4096, 1 << 20);
    assert_eq!(decode(&mut d, &hex("1008 7061 7373 776f 7264 0673 6563 7265 74")).unwrap(), h(&[("password", "secret")]));
    assert_eq!(d.table_len(), 0);
    // C.2.4 indexed
    assert_eq!(decode(&mut d, &hex("82")).unwrap(), h(&[(":method", "GET")]));
    assert_eq!(d.table_len(), 0);
}

fn requests() -> Vec<List> {
    vec![
        h(&[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]),
        h(&[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"), ("cache-control", "no-cache")]),
        h(&[(":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "www.example.com"), ("custom-key", "custom-value")]),
    ]
}

#[test]
fn c3_requests_without_huffman() {
    let blocks = [
        hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"),
        hex("8286 84be 5808 6e6f 2d63 6163 6865"),
        hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"),
    ];
    let tables: [&[(&str, &str)]; 3] = [
        &[(":authority", "www.example.com")],
        &[("cache-control", "no-cache"), (":authority", "www.example.com")],
        &[("custom-key", "custom-value"), ("cache-control", "no-cache"), (":authority", "www.example.com")],
    ];
    let mut d = Decoder::new(4096, 1 << 20);
    let mut e = Encoder::new(4096);
    e.huffman = false;
    let sizes = [57, 110, 164];
    for (i, req) in requests().iter().enumerate() {
        assert_eq!(&decode(&mut d, &blocks[i]).unwrap(), req);
        assert_eq!(d.table_size(), sizes[i]);
        let want: Vec<(String, String)> = tables[i].iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        assert_eq!(table(&d), want);
        assert_eq!(encode(&mut e, req), blocks[i], "request {}", i + 1);
        assert_eq!(e.table_size(), sizes[i]);
    }
}

#[test]
fn c4_requests_with_huffman() {
    let blocks = [
        hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"),
        hex("8286 84be 5886 a8eb 1064 9cbf"),
        hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"),
    ];
    let mut d = Decoder::new(4096, 1 << 20);
    let mut e = Encoder::new(4096);
    for (i, req) in requests().iter().enumerate() {
        assert_eq!(&decode(&mut d, &blocks[i]).unwrap(), req);
        assert_eq!(encode(&mut e, req), blocks[i], "request {}", i + 1);
    }
    assert_eq!(d.table_size(), 164);
}

fn responses() -> Vec<List> {
    vec![
        h(&[(":status", "302"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:21 GMT"), ("location", "https://www.example.com")]),
        h(&[(":status", "307"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:21 GMT"), ("location", "https://www.example.com")]),
        h(&[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ("location", "https://www.example.com"),
            ("content-encoding", "gzip"),
            ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
        ]),
    ]
}

#[test]
fn c5_responses_without_huffman() {
    let blocks = [
        hex("4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"),
        hex("4803 3330 37c1 c0bf"),
        hex("88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31"),
    ];
    let sizes = [222, 222, 215];
    let mut d = Decoder::new(256, 1 << 20);
    for (i, resp) in responses().iter().enumerate() {
        assert_eq!(&decode(&mut d, &blocks[i]).unwrap(), resp, "response {}", i + 1);
        assert_eq!(d.table_size(), sizes[i]);
    }
    assert_eq!(
        table(&d),
        [
            ("set-cookie".into(), "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".into()),
            ("content-encoding".into(), "gzip".into()),
            ("date".into(), "Mon, 21 Oct 2013 20:13:22 GMT".into()),
        ]
    );
}

#[test]
fn c6_responses_with_huffman() {
    let blocks = [
        hex("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3"),
        hex("4883 640e ffc1 c0bf"),
        hex("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07"),
    ];
    let mut d = Decoder::new(256, 1 << 20);
    for (i, resp) in responses().iter().enumerate() {
        assert_eq!(&decode(&mut d, &blocks[i]).unwrap(), resp, "response {}", i + 1);
    }
    assert_eq!(d.table_size(), 215);
    // our encoder with a 256-byte table round-trips the same lists
    let mut e = Encoder::new(256);
    let mut d2 = Decoder::new(4096, 1 << 20);
    for resp in responses() {
        let b = encode(&mut e, &resp);
        assert_eq!(decode(&mut d2, &b).unwrap(), resp);
    }
}

#[test]
fn table_size_updates() {
    let mut d = Decoder::new(4096, 1 << 20);
    assert_eq!(decode(&mut d, &[0x20, 0x82]).unwrap(), h(&[(":method", "GET")]));
    assert_eq!(d.table_max_size(), 0);
    // two updates at the start are fine
    assert!(decode(&mut d, &[0x20, 0x3f, 0xe1, 0x1f, 0x82]).is_ok());
    assert_eq!(d.table_max_size(), 4096);
    // after a field: error
    assert_eq!(decode(&mut d, &[0x82, 0x20]), Err(Error::InvalidTableSizeUpdate));
    // larger than allowed
    let mut d = Decoder::new(4096, 1 << 20);
    let mut block = Vec::new();
    encode_integer(4097, 5, 0x20, &mut block);
    assert_eq!(decode(&mut d, &block), Err(Error::InvalidTableSizeUpdate));
    // the encoder announces a smaller peer table, then the decoder follows it
    let mut e = Encoder::new(4096);
    e.set_peer_max_table_size(100);
    let b = encode(&mut e, &h(&[("a", "b")]));
    assert_eq!(b[0] & 0xe0, 0x20);
    let mut d = Decoder::new(4096, 1 << 20);
    assert_eq!(decode(&mut d, &b).unwrap(), h(&[("a", "b")]));
    assert_eq!(d.table_max_size(), 100);
    // shrinking to 0 and back up emits both updates (RFC 7541 §4.2)
    e.set_peer_max_table_size(0);
    e.set_peer_max_table_size(200);
    let b = encode(&mut e, &h(&[("c", "d")]));
    assert_eq!(&b[..2], &[0x20, 0x3f]);
    assert_eq!(decode(&mut d, &b).unwrap(), h(&[("c", "d")]));
    assert_eq!(d.table_len(), 1, "the old entry was evicted by the update to 0");
    // an encoder limited below the default announces it in its first block
    let mut e = Encoder::new(1024);
    let b = encode(&mut e, &h(&[("x", "y")]));
    let mut d = Decoder::new(4096, 1 << 20);
    decode(&mut d, &b).unwrap();
    assert_eq!(d.table_max_size(), 1024);
}

#[test]
fn invalid_blocks() {
    let mut d = Decoder::new(4096, 1 << 20);
    assert_eq!(decode(&mut d, &[0x80]), Err(Error::InvalidIndex), "index 0");
    assert_eq!(decode(&mut d, &[0xbe]), Err(Error::InvalidIndex), "empty dynamic table");
    assert_eq!(decode(&mut d, &[0xff, 0x00]), Err(Error::InvalidIndex));
    assert_eq!(decode(&mut d, &[0x7e, 0x01, b'a']), Err(Error::InvalidIndex), "literal with a dynamic name index");
    assert_eq!(decode(&mut d, &[0x40, 0x05, b'a']), Err(Error::Truncated));
    assert_eq!(decode(&mut d, &[0x40]), Err(Error::Truncated));
    assert_eq!(decode(&mut d, &[0x00, 0x81, 0xff, 0x00]), Err(Error::Huffman));
    assert_eq!(decode(&mut d, &[0x00, 0x01, b'a', 0x84, 0xff, 0xff, 0xff, 0xff]), Err(Error::Huffman), "EOS");
    let mut big = vec![0x00, 0x7f];
    big.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert_eq!(decode(&mut d, &big), Err(Error::IntegerOverflow));
}

#[test]
fn header_list_cap_keeps_state() {
    // a 4000-byte entry referenced repeatedly: the HPACK bomb
    let mut d = Decoder::new(4096, 16 * 1024);
    let mut block = vec![0x40, 0x01, b'x'];
    encode_integer(3900, 7, 0, &mut block);
    block.extend(std::iter::repeat_n(b'y', 3900));
    for _ in 0..100 {
        block.push(0xbe);
    }
    let mut emitted = 0usize;
    let r = d.decode(&block, &mut |n: &[u8], v: &[u8]| emitted += n.len() + v.len() + 32);
    assert_eq!(r, Err(Error::HeaderListTooLarge));
    assert!(emitted <= 16 * 1024, "{emitted}");
    // the table is still in step: a later block that refers to it decodes
    assert_eq!(decode(&mut d, &[0xbe]).unwrap()[0].1.len(), 3900);
    // and a later block that adds a field after the limit still indexes it
    let mut d = Decoder::new(4096, 40);
    let r = decode(&mut d, &hex("82 400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"));
    assert_eq!(r, Err(Error::HeaderListTooLarge));
    assert_eq!(d.table_len(), 1);
}

#[test]
fn oversized_entry_empties_table() {
    let mut d = Decoder::new(100, 1 << 20);
    decode(&mut d, &[0x40, 0x01, b'a', 0x01, b'b']).unwrap();
    assert_eq!(d.table_len(), 1);
    // literal with indexing, name from the dynamic table (index 62), value too big for the table
    let mut block = vec![0x7e];
    block.push(100);
    block.extend(std::iter::repeat_n(b'v', 100));
    let got = decode(&mut d, &block).unwrap();
    assert_eq!(got[0].0, b"a");
    assert_eq!(got[0].1.len(), 100);
    assert_eq!(d.table_len(), 0);
    assert_eq!(d.table_size(), 0);
}

#[test]
fn encoder_never_indexes_sensitive_fields() {
    let mut e = Encoder::new(4096);
    let list = h(&[("authorization", "Bearer abc"), ("cookie", "a=b"), ("set-cookie", "x=y"), ("proxy-authorization", "z")]);
    for _ in 0..2 {
        let b = encode(&mut e, &list);
        // every field is a never-indexed literal (0001xxxx)
        let mut d = Decoder::new(4096, 1 << 20);
        assert_eq!(decode(&mut d, &b).unwrap(), list);
        assert_eq!(d.table_len(), 0);
        assert_eq!(b[0] & 0xf0, 0x10);
    }
    assert_eq!(e.table_len(), 0);
    // unique-valued fields are not indexed; repeated ones become 1-byte indexed fields
    let b1 = encode(&mut e, &h(&[("content-length", "13"), ("content-type", "text/plain"), (":path", "/a?b=1")]));
    assert_eq!(e.table_len(), 1);
    let b2 = encode(&mut e, &h(&[("content-type", "text/plain")]));
    assert_eq!(b2, [0xbe]);
    assert!(b1.len() > 10);
    assert_eq!(DEFAULT_TABLE_SIZE, 4096);
}

#[test]
fn random_round_trips_with_eviction() {
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for table_size in [0usize, 64, 256, 4096] {
        let mut e = Encoder::new(table_size);
        let mut d = Decoder::new(4096, 1 << 20);
        for _ in 0..500 {
            let n = (rnd() % 8) as usize;
            let list: List = (0..n)
                .map(|_| {
                    let name = format!("x-h{}", rnd() % 20).into_bytes();
                    let vlen = (rnd() % 40) as usize;
                    let value: Vec<u8> = (0..vlen).map(|_| (rnd() % 256) as u8).collect();
                    (name, value)
                })
                .collect();
            let b = encode(&mut e, &list);
            assert_eq!(decode(&mut d, &b).unwrap(), list);
            assert_eq!(d.table_size(), e.table_size());
        }
    }
}
