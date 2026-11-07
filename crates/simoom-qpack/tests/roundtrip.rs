//! Encoder-to-decoder round trips: static only, dynamic, blocked streams, cancellation and
//! eviction under pressure with reordered delivery.

use simoom_qpack::{Decoded, Decoder, Encoder, Field};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn to_fields(pairs: &[(&[u8], &[u8])]) -> Vec<Field> {
    pairs.iter().map(|(n, v)| Field::new(*n, *v)).collect()
}

fn request(i: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b":method".to_vec(), if i % 3 == 0 { b"POST".to_vec() } else { b"GET".to_vec() }),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"api.example.com".to_vec()),
        (b":path".to_vec(), format!("/items/{}", i % 7).into_bytes()),
        (b"user-agent".to_vec(), b"simoom-test/1.0".to_vec()),
        (b"x-request-id".to_vec(), format!("{i:016x}").into_bytes()),
        (b"accept".to_vec(), b"*/*".to_vec()),
        (b"authorization".to_vec(), b"Bearer secret-token".to_vec()),
    ]
}

fn pairs(v: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    v.iter().map(|(n, x)| (n.as_slice(), x.as_slice())).collect()
}

#[test]
fn static_only_round_trip() {
    let mut e = Encoder::new();
    let mut d = Decoder::new(0, 0, 1 << 20);
    let long = vec![b'z'; 5000];
    let binary: Vec<u8> = (0..=255u8).collect();
    let cases: Vec<Vec<(&[u8], &[u8])>> = vec![
        vec![(b":status", b"200")],
        vec![(b":status", b"299"), (b"content-type", b"application/json"), (b"server", b"simoom")],
        vec![(b":method", b"GET"), (b":path", b"/"), (b"x-long", &long), (b"x-bin", &binary)],
        vec![(b"authorization", b"secret"), (b"proxy-authorization", b"secret2"), (b"", b"")],
        vec![],
    ];
    for (i, c) in cases.iter().enumerate() {
        let mut block = Vec::new();
        e.encode(i as u64 * 4, c, &mut block);
        assert_eq!(&block[..2], &[0, 0]);
        assert_eq!(d.decode(i as u64 * 4, &block).unwrap(), Decoded::Fields(to_fields(c)));
    }
    let mut es = Vec::new();
    e.take_encoder_stream(&mut es);
    assert!(es.is_empty(), "a static-only encoder writes nothing on the encoder stream");
    // exact static matches are one byte each
    let mut block = Vec::new();
    e.encode(0, &[(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"https")], &mut block);
    assert_eq!(block, [0, 0, 0xd1, 0xc1, 0xd7]);
    // never-indexed bit on sensitive literals: static name reference with N set
    let mut block = Vec::new();
    e.encode(0, &[(b"authorization", b"x")], &mut block);
    assert_eq!(block[2] & 0xf0, 0x70);
}

/// Runs a connection: requests encoded, the encoder stream delivered before or after each
/// section, acknowledgments fed back. Returns total section bytes.
fn session(cap: u64, blocked: u64, n: u64, seed: u64, distinct: bool) -> usize {
    let mut rng = Rng(seed);
    let mut e = Encoder::with_dynamic_table(cap);
    e.set_peer_settings(cap, blocked);
    let mut d = Decoder::new(cap, blocked, 1 << 20);
    let mut total = 0;
    let mut pending_es: Vec<u8> = Vec::new();
    let mut waiting: Vec<(u64, Vec<Field>)> = Vec::new();
    for i in 0..n {
        let stream = i * 4;
        let mut req = request(i);
        if distinct {
            req.push((format!("x-h{}", rng.below(40)).into_bytes(), format!("v{}", rng.below(5)).into_bytes()));
        }
        let mut block = Vec::new();
        e.encode(stream, &pairs(&req), &mut block);
        total += block.len();
        e.take_encoder_stream(&mut pending_es);
        let expected = to_fields(&pairs(&req));
        // deliver the encoder stream now or after the section
        let early = rng.below(2) == 0;
        if early {
            for (s, r) in d.on_encoder_stream(&std::mem::take(&mut pending_es)).unwrap() {
                let k = waiting.iter().position(|w| w.0 == s).unwrap();
                assert_eq!(r.unwrap(), waiting.remove(k).1);
            }
        }
        match d.decode(stream, &block).unwrap() {
            Decoded::Fields(f) => assert_eq!(f, expected),
            Decoded::Blocked => waiting.push((stream, expected)),
        }
        assert!(d.blocked_streams() as u64 <= blocked);
        if !early || rng.below(3) == 0 {
            // split the encoder stream at a random point
            let es = std::mem::take(&mut pending_es);
            let cut = if es.is_empty() { 0 } else { rng.below(es.len() as u64 + 1) as usize };
            for part in [&es[..cut], &es[cut..]] {
                for (s, r) in d.on_encoder_stream(part).unwrap() {
                    let k = waiting.iter().position(|w| w.0 == s).unwrap();
                    assert_eq!(r.unwrap(), waiting.remove(k).1);
                }
            }
        }
        if rng.below(2) == 0 {
            let mut ds = Vec::new();
            d.take_decoder_stream(&mut ds);
            e.on_decoder_stream(&ds).unwrap();
        }
        assert!(d.table_size() <= cap);
    }
    for (s, r) in d.on_encoder_stream(&pending_es).unwrap() {
        let k = waiting.iter().position(|w| w.0 == s).unwrap();
        assert_eq!(r.unwrap(), waiting.remove(k).1);
    }
    assert!(waiting.is_empty());
    total
}

#[test]
fn dynamic_round_trips() {
    for seed in 1..20 {
        session(4096, 16, 200, seed, false);
        session(4096, 0, 200, seed, true);
        session(256, 2, 300, seed, true);
        session(100, 1, 100, seed, true);
        session(0, 0, 50, seed, true);
    }
}

#[test]
fn dynamic_table_compresses_repeats() {
    let static_bytes = {
        let mut e = Encoder::new();
        let mut t = 0;
        for i in 0..100 {
            let mut b = Vec::new();
            e.encode(i * 4, &pairs(&request(i)), &mut b);
            t += b.len();
        }
        t
    };
    let dynamic_bytes = session(4096, 16, 100, 7, false);
    assert!(dynamic_bytes * 2 < static_bytes, "dynamic {dynamic_bytes} vs static {static_bytes}");
}

#[test]
fn blocked_then_unblocked() {
    let mut e = Encoder::with_dynamic_table(4096);
    e.set_peer_settings(4096, 8);
    let mut d = Decoder::new(4096, 8, 1 << 16);
    let req: Vec<(&[u8], &[u8])> = vec![(b":path", b"/a"), (b"x-custom", b"value")];
    let mut block = Vec::new();
    e.encode(0, &req, &mut block);
    assert_eq!(d.decode(0, &block).unwrap(), Decoded::Blocked);
    let mut es = Vec::new();
    e.take_encoder_stream(&mut es);
    let done = d.on_encoder_stream(&es).unwrap();
    assert_eq!(done, vec![(0, Ok(to_fields(&req)))]);
    let mut ds = Vec::new();
    d.take_decoder_stream(&mut ds);
    e.on_decoder_stream(&ds).unwrap();
    assert_eq!(e.known_received_count(), 2);
    // the same fields now reference acknowledged entries: two bytes plus the prefix
    let mut block = Vec::new();
    e.encode(4, &req, &mut block);
    assert_eq!(block.len(), 4);
    assert_eq!(d.decode(4, &block).unwrap(), Decoded::Fields(to_fields(&req)));
}

#[test]
fn encoder_respects_peer_blocked_streams() {
    let mut e = Encoder::with_dynamic_table(4096);
    e.set_peer_settings(4096, 1);
    let mut d = Decoder::new(4096, 1, 1 << 16);
    // without delivering the encoder stream, only one stream may block
    let mut blocked = 0;
    for i in 0..5u64 {
        let v = format!("v{i}");
        let req: Vec<(&[u8], &[u8])> = vec![(b"x-k", v.as_bytes())];
        let mut block = Vec::new();
        e.encode(i * 4, &req, &mut block);
        match d.decode(i * 4, &block).unwrap() {
            Decoded::Blocked => blocked += 1,
            Decoded::Fields(f) => assert_eq!(f, to_fields(&req)),
        }
    }
    assert_eq!(blocked, 1);
}

#[test]
fn cancellation_releases_references() {
    let mut e = Encoder::with_dynamic_table(128);
    e.set_peer_settings(128, 4);
    let mut d = Decoder::new(128, 4, 1 << 16);
    let mut block = Vec::new();
    e.encode(0, &[(b"x-aaaa", b"11111111111111111111111111111111")], &mut block);
    assert_eq!(d.decode(0, &block).unwrap(), Decoded::Blocked);
    d.cancel_stream(0);
    let mut es = Vec::new();
    e.take_encoder_stream(&mut es);
    assert!(d.on_encoder_stream(&es).unwrap().is_empty());
    let mut ds = Vec::new();
    d.take_decoder_stream(&mut ds);
    assert_eq!(ds, [0x40, 0x01], "Stream Cancellation, then Insert Count Increment");
    e.on_decoder_stream(&ds).unwrap();
    // the entry can now be evicted for a new one
    let mut block = Vec::new();
    e.encode(4, &[(b"x-bbbb", b"22222222222222222222222222222222")], &mut block);
    assert_eq!(e.insert_count(), 2);
    es.clear();
    e.take_encoder_stream(&mut es);
    assert!(d.on_encoder_stream(&es).unwrap().is_empty());
    assert_eq!(d.table_size(), 70, "the first entry was evicted");
    assert_eq!(
        d.decode(4, &block).unwrap(),
        Decoded::Fields(vec![Field::new("x-bbbb", "22222222222222222222222222222222")])
    );
}

#[test]
fn unacknowledged_entries_are_not_evicted() {
    // room for one entry; the first is referenced and never acknowledged
    let mut e = Encoder::with_dynamic_table(64);
    e.set_peer_settings(64, 10);
    let mut block = Vec::new();
    e.encode(0, &[(b"x-a", b"1")], &mut block);
    assert_eq!(e.insert_count(), 1);
    let mut block2 = Vec::new();
    e.encode(4, &[(b"x-b", b"2")], &mut block2);
    assert_eq!(e.insert_count(), 1, "the referenced entry stays; the field goes out as a literal");
    let mut d = Decoder::new(64, 10, 1 << 16);
    let mut es = Vec::new();
    e.take_encoder_stream(&mut es);
    d.on_encoder_stream(&es).unwrap();
    assert_eq!(d.decode(4, &block2).unwrap(), Decoded::Fields(vec![Field::new("x-b", "2")]));
    assert_eq!(d.decode(0, &block).unwrap(), Decoded::Fields(vec![Field::new("x-a", "1")]));
}
