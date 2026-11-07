//! WebSocket (RFC 6455): handshake and frame codec.
#![cfg(feature = "websocket")]

mod common;

use common::Rng;
use simoom_http1::ws::*;
use simoom_http1::*;

const RFC_REQUEST: &str = "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: http://example.com\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n";

fn handshake(s: &str) -> Result<[u8; 28], HandshakeError> {
    let mut hs = [EMPTY_HEADER; 16];
    let Ok(Status::Complete(r)) = parse_request(s.as_bytes(), &mut hs, &Limits::default()) else { panic!("{s}") };
    validate_handshake(&r).map(|h| h.accept)
}

#[test]
fn accept_key_matches_rfc_example() {
    assert_eq!(&accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn handshake_validation() {
    assert_eq!(&handshake(RFC_REQUEST).unwrap(), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    let mut hs = [EMPTY_HEADER; 16];
    let Ok(Status::Complete(r)) = parse_request(RFC_REQUEST.as_bytes(), &mut hs, &Limits::default()) else { panic!() };
    let h = validate_handshake(&r).unwrap();
    assert_eq!(h.protocols, Some(&b"chat, superchat"[..]));
    assert_eq!(h.extensions, None);
    let mut out = Vec::new();
    write_accept(&mut out, &h, Some(b"chat")).unwrap();
    assert_eq!(
        out,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
    );
    let mut hs2 = [EMPTY_HEADER; 8];
    let Ok(Status::Complete(resp)) = parse_response(&out, &mut hs2, &Limits::default(), b"GET") else { panic!() };
    assert!(resp.upgraded);
    assert!(validate_response(&resp, b"dGhlIHNhbXBsZSBub25jZQ=="));
    assert!(!validate_response(&resp, b"AAAAAAAAAAAAAAAAAAAAAA=="));

    let bad = |from: &str, to: &str| handshake(&RFC_REQUEST.replace(from, to)).unwrap_err();
    assert_eq!(bad("GET /chat", "POST /chat"), HandshakeError::NotGet);
    assert_eq!(bad("Upgrade: websocket", "Upgrade: h2c"), HandshakeError::NotUpgrade);
    assert_eq!(bad("Connection: Upgrade", "Connection: keep-alive"), HandshakeError::NotUpgrade);
    assert_eq!(bad("Version: 13", "Version: 8"), HandshakeError::BadVersion);
    assert_eq!(bad("Sec-WebSocket-Version: 13\r\n", ""), HandshakeError::BadVersion);
    assert_eq!(bad("Version: 13\r\n", "Version: 13\r\nSec-WebSocket-Version: 13\r\n"), HandshakeError::BadVersion);
    assert_eq!(HandshakeError::BadVersion.status(), 426);
    assert_eq!(HandshakeError::BadKey.status(), 400);
    assert_eq!(bad("dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25jZQ"), HandshakeError::BadKey);
    assert_eq!(bad("dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25jZQo="), HandshakeError::BadKey);
    assert_eq!(bad("dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25j!Q=="), HandshakeError::BadKey);
    assert_eq!(bad("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", ""), HandshakeError::BadKey);
    assert_eq!(bad("Origin", "Content-Length: 1\r\nOrigin"), HandshakeError::HasBody);
    assert_eq!(handshake(&RFC_REQUEST.replace("HTTP/1.1\r\nHost: server.example.com", "HTTP/1.0\r\nHost: s")), Err(HandshakeError::NotHttp11));
    assert!(VERSION_REQUIRED.starts_with(b"HTTP/1.1 426 "));
}

/// Decodes `input` in pieces cut at `cuts` (keeping unused bytes); returns owned events.
#[derive(Debug, PartialEq, Eq, Clone)]
enum E {
    Data(bool, Vec<u8>, bool),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<u16>, String),
}

fn decode_all(role: Role, lim: WsLimits, input: &[u8], cuts: &[usize]) -> Result<Vec<E>, WsError> {
    let mut d = FrameDecoder::new(role, lim);
    let mut evs = Vec::new();
    let mut buf = Vec::new();
    let mut fed = 0;
    let mut bounds = cuts.to_vec();
    bounds.push(input.len());
    for &b in &bounds {
        buf.extend_from_slice(&input[fed..b]);
        fed = b;
        loop {
            let (n, ev) = d.decode(&mut buf)?;
            let wait = matches!(ev, WsEvent::NeedMore);
            let owned = match ev {
                WsEvent::Data { text, payload, fin } => Some(E::Data(text, payload.to_vec(), fin)),
                WsEvent::Ping(p) => Some(E::Ping(p.to_vec())),
                WsEvent::Pong(p) => Some(E::Pong(p.to_vec())),
                WsEvent::Close { code, reason } => Some(E::Close(code, reason.to_string())),
                WsEvent::NeedMore => None,
            };
            buf.drain(..n);
            if let Some(e) = owned {
                evs.push(e);
            }
            if wait {
                break;
            }
        }
    }
    Ok(evs)
}

/// Joins data pieces into whole messages so results compare across splits.
fn messages(evs: &[E]) -> Vec<E> {
    let mut out = Vec::new();
    let mut cur: Option<(bool, Vec<u8>)> = None;
    for e in evs {
        match e {
            E::Data(t, p, fin) => {
                let c = cur.get_or_insert((*t, Vec::new()));
                c.1.extend_from_slice(p);
                if *fin {
                    let (t, p) = cur.take().unwrap();
                    out.push(E::Data(t, p, true));
                }
            }
            other => out.push(other.clone()),
        }
    }
    out
}

fn server(input: &[u8]) -> Result<Vec<E>, WsError> {
    decode_all(Role::Server, WsLimits::default(), input, &[]).map(|e| messages(&e))
}

fn client(input: &[u8]) -> Result<Vec<E>, WsError> {
    decode_all(Role::Client, WsLimits::default(), input, &[]).map(|e| messages(&e))
}

#[test]
fn rfc_examples() {
    // §5.7: an unmasked text frame, a masked one, a fragmented one, ping, pong, 256 and 64 KiB
    // binary frames.
    assert_eq!(client(&[0x81, 0x05, b'H', b'e', b'l', b'l', b'o']), Ok(vec![E::Data(true, b"Hello".to_vec(), true)]));
    assert_eq!(
        server(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]),
        Ok(vec![E::Data(true, b"Hello".to_vec(), true)])
    );
    assert_eq!(
        client(&[0x01, 0x03, b'H', b'e', b'l', 0x80, 0x02, b'l', b'o']),
        Ok(vec![E::Data(true, b"Hello".to_vec(), true)])
    );
    assert_eq!(client(&[0x89, 0x05, b'H', b'e', b'l', b'l', b'o']), Ok(vec![E::Ping(b"Hello".to_vec())]));
    assert_eq!(
        server(&[0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]),
        Ok(vec![E::Pong(b"Hello".to_vec())])
    );
    let mut f = vec![0x82, 0x7e, 0x01, 0x00];
    f.extend_from_slice(&[7; 256]);
    assert_eq!(client(&f), Ok(vec![E::Data(false, vec![7; 256], true)]));
    let mut f = vec![0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0];
    f.extend_from_slice(&[9; 65536]);
    assert_eq!(client(&f), Ok(vec![E::Data(false, vec![9; 65536], true)]));
}

#[test]
fn header_errors() {
    let e = |b: &[u8]| client(b).unwrap_err();
    assert_eq!(e(&[0xc1, 0x00]), WsError::ReservedBits);
    assert_eq!(e(&[0xa1, 0x00]), WsError::ReservedBits);
    assert_eq!(e(&[0x91, 0x00]), WsError::ReservedBits);
    for op in [3u8, 4, 5, 6, 7, 0xb, 0xc, 0xd, 0xe, 0xf] {
        assert_eq!(e(&[0x80 | op, 0x00]), WsError::BadOpcode, "{op}");
    }
    assert_eq!(server(&[0x81, 0x00]).unwrap_err(), WsError::Unmasked);
    assert_eq!(e(&[0x81, 0x80, 0, 0, 0, 0]), WsError::Masked);
    assert_eq!(e(&[0x09, 0x00]), WsError::FragmentedControl);
    assert_eq!(e(&[0x89, 0x7e, 0x00, 0x7e]), WsError::ControlTooLong);
    assert_eq!(e(&[0x82, 0x7e, 0x00, 0x05]), WsError::BadLength);
    assert_eq!(e(&[0x82, 0x7f, 0, 0, 0, 0, 0, 0, 0xff, 0xff]), WsError::BadLength);
    assert_eq!(e(&[0x82, 0x7f, 0x80, 0, 0, 0, 0, 1, 0, 0]), WsError::BadLength);
    assert_eq!(WsError::BadLength.close_code(), 1002);
    assert_eq!(WsError::InvalidUtf8.close_code(), 1007);
    assert_eq!(WsError::MessageTooLarge.close_code(), 1009);
}

#[test]
fn fragmentation_rules() {
    assert_eq!(client(&[0x80, 0x01, b'x']).unwrap_err(), WsError::UnexpectedContinuation);
    assert_eq!(client(&[0x01, 0x01, b'x', 0x81, 0x01, b'y']).unwrap_err(), WsError::ExpectedContinuation);
    assert_eq!(client(&[0x02, 0x01, b'x', 0x82, 0x01, b'y']).unwrap_err(), WsError::ExpectedContinuation);
    // Control frames may come between fragments.
    let evs = client(&[0x01, 0x02, b'H', b'e', 0x89, 0x01, b'p', 0x00, 0x01, b'l', 0x80, 0x02, b'l', b'o']).unwrap();
    assert_eq!(evs, vec![E::Ping(b"p".to_vec()), E::Data(true, b"Hello".to_vec(), true)]);
    // Empty frames.
    assert_eq!(client(&[0x81, 0x00]).unwrap(), vec![E::Data(true, vec![], true)]);
    assert_eq!(client(&[0x01, 0x00, 0x80, 0x00]).unwrap(), vec![E::Data(true, vec![], true)]);
}

#[test]
fn utf8_is_checked_across_fragments() {
    // "é" split between two fragments is fine.
    assert_eq!(client(&[0x01, 0x01, 0xc3, 0x80, 0x01, 0xa9]).unwrap(), vec![E::Data(true, "é".as_bytes().to_vec(), true)]);
    // Truncated at the end of the message.
    assert_eq!(client(&[0x81, 0x01, 0xc3]).unwrap_err(), WsError::InvalidUtf8);
    for bad in [&[0xc0u8, 0x80][..], &[0xed, 0xa0, 0x80], &[0xf4, 0x90, 0x80, 0x80], &[0xff], &[0x80], &[0xe0, 0x80, 0x80], &[0xf8, 0x88, 0x80, 0x80, 0x80]] {
        let mut f = vec![0x81, bad.len() as u8];
        f.extend_from_slice(bad);
        assert_eq!(client(&f).unwrap_err(), WsError::InvalidUtf8, "{bad:?}");
    }
    // Fails fast: the bad byte is reported in the first fragment, before the message ends.
    assert_eq!(client(&[0x01, 0x02, b'a', 0xff]).unwrap_err(), WsError::InvalidUtf8);
    // Binary is not checked; long ASCII runs take the fast path.
    assert!(client(&[0x82, 0x02, 0xff, 0xfe]).is_ok());
    let text = "plain ascii text that is longer than eight bytes, then ü and 𝄞 at the end".as_bytes();
    let mut f = vec![0x81, text.len() as u8];
    f.extend_from_slice(text);
    assert!(client(&f).is_ok());
}

#[test]
fn close_frames() {
    assert_eq!(client(&[0x88, 0x00]).unwrap(), vec![E::Close(None, String::new())]);
    assert_eq!(client(&[0x88, 0x02, 0x03, 0xe8]).unwrap(), vec![E::Close(Some(1000), String::new())]);
    assert_eq!(client(&[0x88, 0x04, 0x0f, 0xa0, b'o', b'k']).unwrap(), vec![E::Close(Some(4000), "ok".into())]);
    assert_eq!(client(&[0x88, 0x01, 0x03]).unwrap_err(), WsError::InvalidClose);
    for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535] {
        let [a, b] = code.to_be_bytes();
        assert_eq!(client(&[0x88, 0x02, a, b]).unwrap_err(), WsError::InvalidClose, "{code}");
    }
    for code in [1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 4999] {
        let [a, b] = code.to_be_bytes();
        assert!(client(&[0x88, 0x02, a, b]).is_ok(), "{code}");
    }
    assert_eq!(client(&[0x88, 0x03, 0x03, 0xe8, 0xff]).unwrap_err(), WsError::InvalidUtf8);
    assert_eq!(client(&[0x88, 0x00, 0x81, 0x00]).unwrap_err(), WsError::AfterClose);
}

#[test]
fn size_limits() {
    let lim = WsLimits { max_frame: 10, max_message: 15 };
    let run = |b: &[u8]| decode_all(Role::Client, lim, b, &[]);
    let mut f = vec![0x82, 10];
    f.extend_from_slice(&[0; 10]);
    assert!(run(&f).is_ok());
    let mut f = vec![0x82, 11];
    f.extend_from_slice(&[0; 11]);
    assert_eq!(run(&f).unwrap_err(), WsError::FrameTooLarge);
    // The frame header alone is enough to refuse: no payload needs to arrive.
    assert_eq!(run(&[0x82, 0x7f, 0, 0, 0, 1, 0, 0, 0, 0]).unwrap_err(), WsError::FrameTooLarge);
    let mut f = vec![0x02, 8];
    f.extend_from_slice(&[0; 8]);
    f.extend_from_slice(&[0x80, 8]);
    f.extend_from_slice(&[0; 8]);
    assert_eq!(run(&f).unwrap_err(), WsError::MessageTooLarge);
}

#[test]
fn encoder_round_trips_and_masks() {
    for len in [0usize, 1, 125, 126, 127, 65535, 65536, 70000] {
        let payload: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let mut out = Vec::new();
        write_frame(&mut out, true, Opcode::Binary, &payload, Some([1, 2, 3, 4]));
        let hlen = match len {
            0..=125 => 6,
            126..=65535 => 8,
            _ => 14,
        };
        assert_eq!(out.len(), hlen + len);
        assert_eq!(server(&out).unwrap(), vec![E::Data(false, payload.clone(), true)], "{len}");
        let mut out = Vec::new();
        write_frame(&mut out, true, Opcode::Binary, &payload, None);
        assert_eq!(client(&out).unwrap(), vec![E::Data(false, payload, true)]);
    }
    let mut h = [0u8; 14];
    assert_eq!(encode_header(&mut h, false, Opcode::Text, 5, None), 2);
    assert_eq!(&h[..2], &[0x01, 0x05]);
    let mut out = Vec::new();
    assert!(write_close(&mut out, 1000, "bye", None));
    assert_eq!(out, [0x88, 0x05, 0x03, 0xe8, b'b', b'y', b'e']);
    assert!(!write_close(&mut out, 1005, "", None));
    assert!(!write_close(&mut out, 1000, &"x".repeat(124), None));
    // Masking is its own inverse and honours the key offset.
    let mut d: Vec<u8> = (0..37).collect();
    let orig = d.clone();
    apply_mask(&mut d[..5], [9, 8, 7, 6], 0);
    apply_mask(&mut d[5..], [9, 8, 7, 6], 5);
    apply_mask(&mut d, [9, 8, 7, 6], 0);
    assert_eq!(d, orig);
}

#[test]
fn every_split_decodes_the_same() {
    let mut rng = Rng(5);
    let mut input = Vec::new();
    write_frame(&mut input, false, Opcode::Text, "héllo wörld, ".as_bytes(), Some([0xa1, 0xb2, 0xc3, 0xd4]));
    write_frame(&mut input, true, Opcode::Ping, b"ping", Some([1, 1, 1, 1]));
    write_frame(&mut input, true, Opcode::Continuation, "𝄞 done".as_bytes(), Some([5, 6, 7, 8]));
    write_frame(&mut input, true, Opcode::Binary, &[0u8; 300], Some([9, 9, 9, 9]));
    let mut close = Vec::new();
    write_close(&mut close, 1001, "away", Some([3, 4, 5, 6]));
    input.extend_from_slice(&close);
    let whole = messages(&decode_all(Role::Server, WsLimits::default(), &input, &[]).unwrap());
    assert_eq!(whole.len(), 4);
    assert_eq!(whole[1], E::Data(true, "héllo wörld, 𝄞 done".as_bytes().to_vec(), true));
    for k in 0..=input.len() {
        let got = decode_all(Role::Server, WsLimits::default(), &input, &[k]).unwrap();
        assert_eq!(messages(&got), whole, "{k}");
    }
    for _ in 0..300 {
        let mut cuts: Vec<usize> = (0..rng.below(10) + 1).map(|_| rng.below(input.len() + 1)).collect();
        cuts.sort_unstable();
        let got = decode_all(Role::Server, WsLimits::default(), &input, &cuts).unwrap();
        assert_eq!(messages(&got), whole);
    }
}
