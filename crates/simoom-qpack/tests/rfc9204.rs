//! RFC 9204 Appendix B examples and malformed-input checks.

use simoom_qpack::{Decoded, Decoder, Encoder, Error, Field};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn f(n: &str, v: &str) -> Field {
    Field::new(n, v)
}

fn fields(d: Decoded) -> Vec<Field> {
    match d {
        Decoded::Fields(f) => f,
        Decoded::Blocked => panic!("blocked"),
    }
}

fn take(d: &mut Decoder) -> Vec<u8> {
    let mut out = Vec::new();
    d.take_decoder_stream(&mut out);
    out
}

const B2_ENC: &str = "3fbd01 c00f7777772e6578616d706c652e636f6d c10c2f73616d706c652f70617468";
const B3_ENC: &str = "4a637573746f6d2d6b65790c637573746f6d2d76616c7565";
const B5_ENC: &str = "810d637573746f6d2d76616c756532";

#[test]
fn b1_literal_with_name_reference() {
    let mut d = Decoder::new(0, 0, 16 << 10);
    let out = d.decode(0, &hex("0000 510b 2f69 6e64 6578 2e68 746d 6c")).unwrap();
    assert_eq!(fields(out), vec![f(":path", "/index.html")]);
    assert!(take(&mut d).is_empty());
}

/// B.2 to B.5 as one decoder session, with the decoder-stream bytes the RFC shows.
#[test]
fn b2_to_b5_decoder_session() {
    let mut d = Decoder::new(220, 100, 16 << 10);
    // B.2
    assert!(d.on_encoder_stream(&hex(B2_ENC)).unwrap().is_empty());
    assert_eq!(d.table_size(), 106);
    let out = d.decode(4, &hex("0381 10 11")).unwrap();
    assert_eq!(fields(out), vec![f(":authority", "www.example.com"), f(":path", "/sample/path")]);
    assert_eq!(take(&mut d), hex("84"));
    // B.3
    d.on_encoder_stream(&hex(B3_ENC)).unwrap();
    assert_eq!(d.table_size(), 160);
    assert_eq!(take(&mut d), hex("01"));
    // B.4: the section arrives before the Duplicate, so it blocks; then the stream is cancelled
    assert_eq!(d.decode(8, &hex("0500 80 c1 81")).unwrap(), Decoded::Blocked);
    assert_eq!(d.blocked_streams(), 1);
    d.cancel_stream(8);
    assert_eq!(d.blocked_streams(), 0);
    assert_eq!(take(&mut d), hex("48"));
    assert!(d.on_encoder_stream(&hex("02")).unwrap().is_empty());
    assert_eq!(d.table_size(), 217);
    assert_eq!(take(&mut d), hex("01"));
    // B.5: the insert evicts entry 0
    d.on_encoder_stream(&hex(B5_ENC)).unwrap();
    assert_eq!(d.table_size(), 215);
    assert_eq!(d.insert_count(), 5);
    // a section that references the evicted entry 0 fails
    assert_eq!(d.decode(12, &hex("0200 80")), Err(Error::DecompressionFailed));
    // entry 4 (custom-key=custom-value2) is there: RIC 5 encodes as 6, base 5, relative 0
    assert_eq!(fields(d.decode(12, &hex("0600 80")).unwrap()), vec![f("custom-key", "custom-value2")]);
}

/// B.4 with the Duplicate arriving after the blocked section: the section unblocks.
#[test]
fn b4_blocked_section_unblocks() {
    let mut d = Decoder::new(220, 100, 16 << 10);
    d.on_encoder_stream(&hex(B2_ENC)).unwrap();
    d.on_encoder_stream(&hex(B3_ENC)).unwrap();
    take(&mut d);
    assert_eq!(d.decode(8, &hex("0500 80 c1 81")).unwrap(), Decoded::Blocked);
    let done = d.on_encoder_stream(&hex("02")).unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].0, 8);
    assert_eq!(
        done[0].1.as_ref().unwrap(),
        &vec![f(":authority", "www.example.com"), f(":path", "/"), f("custom-key", "custom-value")]
    );
    assert_eq!(take(&mut d), hex("88"));
}

/// The encoder stream may be split anywhere.
#[test]
fn encoder_stream_byte_by_byte() {
    let mut whole = hex(B2_ENC);
    whole.extend(hex(B3_ENC));
    whole.extend(hex("02"));
    whole.extend(hex(B5_ENC));
    let mut d = Decoder::new(220, 100, 16 << 10);
    for b in &whole {
        d.on_encoder_stream(std::slice::from_ref(b)).unwrap();
    }
    assert_eq!(d.insert_count(), 5);
    assert_eq!(d.table_size(), 215);
}

/// The encoder's parsing of the decoder-stream bytes of B.2 to B.4.
#[test]
fn encoder_parses_decoder_stream() {
    let mut e = Encoder::with_dynamic_table(220);
    e.set_peer_settings(220, 100);
    let mut es = Vec::new();
    e.take_encoder_stream(&mut es);
    assert_eq!(es, hex("3fbd01"), "Set Dynamic Table Capacity=220");
    let mut block = Vec::new();
    e.encode(4, &[(b":authority", b"www.example.com"), (b":path", b"/sample/path")], &mut block);
    assert_eq!(e.insert_count(), 2);
    // a decoder in step with it
    let mut d = Decoder::new(220, 100, 16 << 10);
    e.take_encoder_stream(&mut es);
    d.on_encoder_stream(&es).unwrap();
    assert_eq!(fields(d.decode(4, &block).unwrap()), vec![f(":authority", "www.example.com"), f(":path", "/sample/path")]);
    e.on_decoder_stream(&hex("84")).unwrap();
    assert_eq!(e.known_received_count(), 2);
    // a second Section Acknowledgment for stream 4 has no section
    assert_eq!(e.on_decoder_stream(&hex("84")), Err(Error::DecoderStream));

    let mut e = Encoder::with_dynamic_table(220);
    e.set_peer_settings(220, 100);
    let mut block = Vec::new();
    e.encode(4, &[(b":authority", b"www.example.com")], &mut block);
    e.encode(8, &[(b"custom-key", b"custom-value")], &mut block);
    e.on_decoder_stream(&hex("84")).unwrap();
    e.on_decoder_stream(&hex("01")).unwrap();
    assert_eq!(e.known_received_count(), 2);
    e.on_decoder_stream(&hex("48")).unwrap();
    // stream 8 was cancelled, so its acknowledgment is an error
    assert_eq!(e.on_decoder_stream(&hex("88")), Err(Error::DecoderStream));
    // increments beyond the insert count, and a zero increment, are errors
    let mut e2 = Encoder::with_dynamic_table(220);
    e2.set_peer_settings(220, 100);
    assert_eq!(e2.on_decoder_stream(&hex("01")), Err(Error::DecoderStream));
    assert_eq!(Encoder::new().on_decoder_stream(&hex("00")), Err(Error::DecoderStream));
    // instructions split across calls
    let mut e3 = Encoder::with_dynamic_table(4096);
    e3.set_peer_settings(4096, 100);
    let mut block = Vec::new();
    e3.encode(300, &[(b"x-a", b"1")], &mut block);
    e3.on_decoder_stream(&[0xff]).unwrap();
    e3.on_decoder_stream(&[0xad]).unwrap();
    e3.on_decoder_stream(&[0x01]).unwrap();
    assert_eq!(e3.known_received_count(), 1);
}

#[test]
fn malformed_encoder_stream() {
    // capacity above the maximum
    assert_eq!(Decoder::new(100, 0, 1 << 14).on_encoder_stream(&hex("3fbd01")), Err(Error::EncoderStream));
    // insert with capacity 0
    assert_eq!(Decoder::new(100, 0, 1 << 14).on_encoder_stream(&hex(B3_ENC)), Err(Error::EncoderStream));
    // entry larger than the capacity (capacity 40)
    assert_eq!(Decoder::new(100, 0, 1 << 14).on_encoder_stream(&[&hex("3f09")[..], &hex(B3_ENC)].concat()), Err(Error::EncoderStream));
    let mut cap220 = hex("3fbd01");
    // static index 99 does not exist
    cap220.extend(hex("ff24 00"));
    assert_eq!(Decoder::new(220, 0, 1 << 14).on_encoder_stream(&cap220), Err(Error::EncoderStream));
    // dynamic name reference and duplicate on an empty table
    assert_eq!(Decoder::new(220, 0, 1 << 14).on_encoder_stream(&hex("3fbd01 8000")), Err(Error::EncoderStream));
    assert_eq!(Decoder::new(220, 0, 1 << 14).on_encoder_stream(&hex("3fbd01 00")), Err(Error::EncoderStream));
    // invalid Huffman (EOS)
    assert_eq!(
        Decoder::new(220, 0, 1 << 14).on_encoder_stream(&hex("3fbd01 c084ffffffff")),
        Err(Error::EncoderStream)
    );
    // a partial instruction larger than any entry could be is refused
    let mut d = Decoder::new(64, 0, 1 << 14);
    d.on_encoder_stream(&hex("5f c907")).unwrap();
    assert_eq!(d.on_encoder_stream(&[b'a'; 400]), Err(Error::EncoderStream));
}

#[test]
fn malformed_sections() {
    let mut d = Decoder::new(220, 100, 16 << 10);
    d.on_encoder_stream(&hex(B2_ENC)).unwrap();
    let bad = |d: &mut Decoder, s: &str| d.decode(4, &hex(s)).unwrap_err();
    // encoded RIC above 2 * MaxEntries
    assert_eq!(bad(&mut d, "0d00"), Error::DecompressionFailed);
    // RIC larger than the references need
    assert_eq!(bad(&mut d, "0381 10"), Error::DecompressionFailed);
    // RIC larger than needed with no references at all
    assert_eq!(bad(&mut d, "0381 c1"), Error::DecompressionFailed);
    // post-base reference at or above RIC
    assert_eq!(bad(&mut d, "0280 11"), Error::DecompressionFailed);
    // relative index below zero
    assert_eq!(bad(&mut d, "0300 82"), Error::DecompressionFailed);
    // negative base below zero
    assert_eq!(bad(&mut d, "0283"), Error::DecompressionFailed);
    // truncated
    assert_eq!(bad(&mut d, "03"), Error::DecompressionFailed);
    assert_eq!(bad(&mut d, ""), Error::DecompressionFailed);
    assert_eq!(bad(&mut d, "0000 510b 2f69"), Error::DecompressionFailed);
    // static index out of range
    assert_eq!(bad(&mut d, "0000 ff24"), Error::DecompressionFailed);
    // a decoder with no dynamic table accepts no RIC
    assert_eq!(Decoder::new(0, 0, 1 << 14).decode(0, &hex("0200 80")), Err(Error::DecompressionFailed));
    // invalid Huffman in a value
    assert_eq!(bad(&mut d, "0000 5184ffffffff"), Error::DecompressionFailed);
    // nothing was acknowledged for failed sections
    assert_eq!(take(&mut d), hex("02"));
}

#[test]
fn field_section_size_limit() {
    // :path=/index.html is 5 + 11 + 32 = 48 bytes
    let block = hex("0000 510b 2f69 6e64 6578 2e68 746d 6c");
    assert_eq!(Decoder::new(0, 0, 47).decode(0, &block), Err(Error::FieldSectionTooLarge));
    assert!(Decoder::new(0, 0, 48).decode(0, &block).is_ok());
    // an encoded block much larger than the limit is refused before decoding
    let mut big = vec![0, 0];
    big.extend(std::iter::repeat_n(0xc1, 100));
    assert_eq!(Decoder::new(0, 0, 20).decode(0, &big), Err(Error::FieldSectionTooLarge));
    assert_eq!(Error::FieldSectionTooLarge.code(), 0x200);
    assert_eq!(Error::EncoderStream.code(), 0x201);
    assert_eq!(Error::DecoderStream.code(), 0x202);
}

#[test]
fn blocked_streams_limit() {
    let mut d = Decoder::new(220, 1, 16 << 10);
    assert_eq!(d.decode(4, &hex("0381 10 11")).unwrap(), Decoded::Blocked);
    // a second section on the same stream does not count again
    assert_eq!(d.decode(4, &hex("0381 10 11")).unwrap(), Decoded::Blocked);
    assert_eq!(d.decode(8, &hex("0381 10 11")), Err(Error::DecompressionFailed));
    let done = d.on_encoder_stream(&hex(B2_ENC)).unwrap();
    assert_eq!(done.len(), 2);
    assert!(done.iter().all(|(s, r)| *s == 4 && r.is_ok()));
    assert_eq!(take(&mut d), hex("8484"));
    // with no blocked streams allowed, any blocking section fails
    assert_eq!(Decoder::new(220, 0, 1 << 14).decode(4, &hex("0381 10 11")), Err(Error::DecompressionFailed));
    // a blocked section that turns out invalid reports its error when unblocked
    let mut d = Decoder::new(220, 4, 16 << 10);
    assert_eq!(d.decode(4, &hex("0381 10 15")).unwrap(), Decoded::Blocked);
    let done = d.on_encoder_stream(&hex(B2_ENC)).unwrap();
    assert_eq!(done, vec![(4, Err(Error::DecompressionFailed))]);
}

#[test]
fn insert_count_wraparound() {
    // capacity 64: MaxEntries 2, FullRange 4; insert many entries and reference the latest
    let mut d = Decoder::new(64, 0, 1 << 14);
    let mut es = hex("3f21"); // capacity 64
    for _ in 0..10 {
        es.extend(hex("c1 0161")); // :path=a (5+1+32 = 38): one entry fits
    }
    d.on_encoder_stream(&es).unwrap();
    assert_eq!(d.insert_count(), 10);
    // RIC 10 encodes as 10 % 4 + 1 = 3; base = RIC, relative 0
    assert_eq!(fields(d.decode(0, &hex("0300 80")).unwrap()), vec![f(":path", "a")]);
    // encoded 2 means RIC 9, which was evicted
    assert_eq!(d.decode(0, &hex("0200 80")), Err(Error::DecompressionFailed));
}
