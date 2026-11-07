//! Body decoding: Content-Length, the strict chunked grammar, trailers, limits and EOF.

mod common;

use common::Rng;
use simoom_http1::*;

#[derive(Debug, PartialEq, Eq)]
struct Out {
    data: Vec<u8>,
    trailers: Vec<u8>,
    used: usize,
}

/// Decodes `input` fed in pieces cut at `cuts`; returns the body, trailers and bytes used, or
/// the error. Unused input is kept and offered again, as a server's receive buffer would.
fn decode_cuts(framing: Framing, input: &[u8], cuts: &[usize], lim: &Limits) -> Result<Option<Out>, Error> {
    let mut d = BodyDecoder::new(framing, lim);
    let mut out = Out { data: Vec::new(), trailers: Vec::new(), used: 0 };
    let mut buf = Vec::new();
    let mut fed = 0;
    let mut bounds: Vec<usize> = cuts.to_vec();
    bounds.push(input.len());
    for &b in &bounds {
        buf.extend_from_slice(&input[fed..b]);
        fed = b;
        loop {
            let (n, ev) = d.decode(&buf)?;
            let mut wait = false;
            match ev {
                BodyEvent::Data(x) => out.data.extend_from_slice(x),
                BodyEvent::End(t) => {
                    out.trailers = t.to_vec();
                    out.used += n;
                    assert!(d.is_done());
                    return Ok(Some(out));
                }
                BodyEvent::NeedMore => wait = true,
            }
            out.used += n;
            buf.drain(..n);
            if wait {
                break;
            }
        }
    }
    Ok(None)
}

fn chunked(input: &str) -> Result<Option<Out>, Error> {
    decode_cuts(Framing::Chunked, input.as_bytes(), &[], &Limits::default())
}

fn body(input: &str) -> Vec<u8> {
    match chunked(input) {
        Ok(Some(o)) => o.data,
        other => panic!("{input:?}: {other:?}"),
    }
}

fn bad(input: &str) -> Error {
    match chunked(input) {
        Err(e) => e,
        other => panic!("{input:?}: expected an error, got {other:?}"),
    }
}

#[test]
fn content_length_bodies() {
    let lim = Limits::default();
    let o = decode_cuts(Framing::Length(5), b"helloGET /", &[], &lim).unwrap().unwrap();
    assert_eq!((o.data.as_slice(), o.used), (&b"hello"[..], 5));
    let o = decode_cuts(Framing::Length(5), b"hello", &[1, 2, 4], &lim).unwrap().unwrap();
    assert_eq!(o.data, b"hello");
    assert_eq!(decode_cuts(Framing::Length(5), b"hel", &[], &lim), Ok(None));
    let o = decode_cuts(Framing::None, b"GET /", &[], &lim).unwrap().unwrap();
    assert_eq!((o.data.len(), o.used), (0, 0));
    let mut d = BodyDecoder::new(Framing::Length(11), &Limits { max_body: 10, ..lim });
    assert_eq!(d.decode(b"x"), Err(Error::BodyTooLarge));
}

#[test]
fn close_delimited_bodies() {
    let lim = Limits { max_body: 8, ..Limits::default() };
    let mut d = BodyDecoder::new(Framing::Close, &lim);
    assert_eq!(d.decode(b""), Ok((0, BodyEvent::NeedMore)));
    assert_eq!(d.decode(b"abcd"), Ok((4, BodyEvent::Data(b"abcd"))));
    assert_eq!(d.eof(), Ok(()));
    assert!(d.is_done());
    let mut d = BodyDecoder::new(Framing::Close, &lim);
    assert_eq!(d.decode(b"abcdefghi"), Err(Error::BodyTooLarge));
}

#[test]
fn eof_inside_a_body_is_an_error() {
    let lim = Limits::default();
    let mut d = BodyDecoder::new(Framing::Length(3), &lim);
    d.decode(b"ab").unwrap();
    assert_eq!(d.eof(), Err(Error::UnexpectedEof));
    let mut d = BodyDecoder::new(Framing::Chunked, &lim);
    d.decode(b"5\r\nab").unwrap();
    assert_eq!(d.eof(), Err(Error::UnexpectedEof));
    let mut d = BodyDecoder::new(Framing::None, &lim);
    assert_eq!(d.eof(), Ok(()));
}

#[test]
fn chunked_basics() {
    assert_eq!(body("5\r\nhello\r\n0\r\n\r\n"), b"hello");
    assert_eq!(body("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), b"hello world");
    assert_eq!(body("A\r\n0123456789\r\na\r\nabcdefghij\r\n0\r\n\r\n").len(), 20);
    assert_eq!(body("0005\r\nhello\r\n000\r\n\r\n"), b"hello");
    assert_eq!(body("0\r\n\r\n"), b"");
    let o = chunked("3\r\nabc\r\n0\r\n\r\nGET / HTTP/1.1").unwrap().unwrap();
    assert_eq!(o.used, 13, "stops right after the body");
}

#[test]
fn chunk_extensions_follow_the_grammar() {
    for ok in [
        "5;a\r\nhello\r\n0\r\n\r\n",
        "5;a=b\r\nhello\r\n0\r\n\r\n",
        "5;a=b;c;d=e\r\nhello\r\n0;last\r\n\r\n",
        "5 ;a\r\nhello\r\n0\r\n\r\n",
        "5\t; a = b\r\nhello\r\n0\r\n\r\n",
        "5;a=\"q\"\r\nhello\r\n0\r\n\r\n",
        "5;a=\"x;y=\\\"z\\\\\"\r\nhello\r\n0\r\n\r\n",
        "5;a=\"\"\r\nhello\r\n0\r\n\r\n",
        "5;a=\"q\" ;b\r\nhello\r\n0\r\n\r\n",
        "5;!#$%&'*+-.^_`|~=v\r\nhello\r\n0\r\n\r\n",
    ] {
        assert_eq!(body(ok), b"hello", "{ok:?}");
    }
    for no in [
        "5 \r\nhello\r\n0\r\n\r\n",
        "5;\r\nhello\r\n0\r\n\r\n",
        "5;=b\r\nhello\r\n0\r\n\r\n",
        "5;a=\r\nhello\r\n0\r\n\r\n",
        "5;a=b \r\nhello\r\n0\r\n\r\n",
        "5;a \r\nhello\r\n0\r\n\r\n",
        "5;a=\"open\r\nhello\r\n0\r\n\r\n",
        "5;a=\"q\"x\r\nhello\r\n0\r\n\r\n",
        "5;a=b=c\r\nhello\r\n0\r\n\r\n",
        "5;a b\r\nhello\r\n0\r\n\r\n",
        "5;a=\x01\r\nhello\r\n0\r\n\r\n",
        "5;a=\"\x01\"\r\nhello\r\n0\r\n\r\n",
        "5;a=\"\\\x01\"\r\nhello\r\n0\r\n\r\n",
        "5 x\r\nhello\r\n0\r\n\r\n",
        "5;a(\r\nhello\r\n0\r\n\r\n",
    ] {
        assert_eq!(bad(no), Error::InvalidChunkExtension, "{no:?}");
    }
}

#[test]
fn chunk_size_rules() {
    for no in ["\r\nhello\r\n0\r\n\r\n", "-5\r\n", "+5\r\n", "0x5\r\n", "5g\r\n", " 5\r\n", "5\n", "g\r\n"] {
        assert_eq!(bad(no), Error::InvalidChunkSize, "{no:?}");
    }
    assert_eq!(bad("5\rx"), Error::BareCr);
    // Overflow (CVE-2021-32714 style): 17 hex digits do not fit, and are refused rather than
    // wrapped to a small size.
    assert_eq!(bad("10000000000000005\r\nhello\r\n0\r\n\r\n"), Error::ChunkSizeOverflow);
    assert_eq!(bad("fffffffffffffffff\r\n"), Error::ChunkSizeOverflow);
    // The largest size that fits is refused by the body limit before any data.
    assert_eq!(bad("ffffffffffffffff\r\n"), Error::BodyTooLarge);
    // Leading zeros are fine until the line limit.
    assert_eq!(body(&format!("{}5\r\nhello\r\n0\r\n\r\n", "0".repeat(100))), b"hello");
    assert_eq!(bad(&format!("{}5\r\nhello\r\n0\r\n\r\n", "0".repeat(2000))), Error::ChunkLineTooLong);
}

#[test]
fn chunk_line_limit_caps_extensions() {
    let lim = Limits { max_chunk_line: 16, ..Limits::default() };
    let line = |ext: &str| format!("5;{ext}\r\nhello\r\n0\r\n\r\n");
    // "5;" + 11 + CRLF = 15 bytes, then 16, then 17.
    assert!(decode_cuts(Framing::Chunked, line(&"a".repeat(11)).as_bytes(), &[], &lim).is_ok());
    assert!(decode_cuts(Framing::Chunked, line(&"a".repeat(12)).as_bytes(), &[], &lim).is_ok());
    assert_eq!(
        decode_cuts(Framing::Chunked, line(&"a".repeat(13)).as_bytes(), &[], &lim),
        Err(Error::ChunkLineTooLong)
    );
    // Each chunk line has its own budget.
    let many = format!("{}0\r\n\r\n", "1;aaaaaaaaaa\r\nx\r\n".repeat(50));
    assert_eq!(decode_cuts(Framing::Chunked, many.as_bytes(), &[], &lim).unwrap().unwrap().data.len(), 50);
}

#[test]
fn chunk_data_must_end_with_crlf() {
    // TE.CL style: the size understates the data.
    assert_eq!(bad("3\r\nabcdef\r\n0\r\n\r\n"), Error::MissingChunkCrlf);
    assert_eq!(bad("5\r\nhello\n0\r\n\r\n"), Error::MissingChunkCrlf);
    assert_eq!(bad("5\r\nhello\rX"), Error::MissingChunkCrlf);
    assert_eq!(bad("5\r\nhelloX"), Error::MissingChunkCrlf);
    // The size overstates it: the next "size line" is data, then CRLF is missing.
    assert_eq!(bad("7\r\nabc\r\n0\r\n\r\n"), Error::MissingChunkCrlf);
}

#[test]
fn trailers() {
    let lim = Limits::default();
    let o = chunked("5\r\nhello\r\n0\r\nX-A: 1\r\nX-B:  two  \r\n\r\nNEXT").unwrap().unwrap();
    assert_eq!(o.data, b"hello");
    assert_eq!(o.trailers, b"X-A: 1\r\nX-B:  two  \r\n\r\n");
    assert_eq!(o.used, "5\r\nhello\r\n0\r\nX-A: 1\r\nX-B:  two  \r\n\r\n".len());
    let mut hs = [EMPTY_HEADER; 4];
    let t = parse_trailers(&o.trailers, &mut hs, &lim).unwrap();
    assert_eq!(t.len(), 2);
    assert_eq!((t[1].name, t[1].value), (&b"X-B"[..], &b"two"[..]));
    assert_eq!(parse_trailers(b"", &mut hs, &lim).unwrap().len(), 0);
    assert!(parse_trailers(b"X: 1\r\n", &mut hs, &lim).is_err());
    for no in ["Content-Length: 5", "transfer-encoding: chunked", "Host: x"] {
        assert_eq!(bad(&format!("0\r\n{no}\r\n\r\n")), Error::ForbiddenTrailer, "{no}");
    }
    assert_eq!(bad("0\r\nX: a\r\n b\r\n\r\n"), Error::ObsFold);
    assert_eq!(bad("0\r\nX : a\r\n\r\n"), Error::WhitespaceBeforeColon);
    assert_eq!(bad("0\r\nX: a\x01\r\n\r\n"), Error::InvalidHeaderValue);
    assert_eq!(bad("0\r\nX: a\n\r\n\r\n"), Error::BareLf);
    assert_eq!(bad("0\r\n\rX"), Error::BareCr);
}

#[test]
fn trailer_limits() {
    let lim = Limits { max_trailers: 32, ..Limits::default() };
    let t = |s: &str| decode_cuts(Framing::Chunked, s.as_bytes(), &[], &lim);
    assert!(t("0\r\nX: 1234567890123456789012345\r\n\r\n").is_ok()); // 32 bytes
    assert_eq!(t("0\r\nX: 12345678901234567890123456\r\n\r\n"), Err(Error::TrailersTooLarge));
    // An endless trailer section is refused once it passes the limit.
    assert_eq!(t(&format!("0\r\nX: {}", "y".repeat(40))), Err(Error::TrailersTooLarge));
    let many = Limits { max_headers: 2, ..Limits::default() };
    assert_eq!(
        decode_cuts(Framing::Chunked, b"0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", &[], &many),
        Err(Error::TooManyHeaders)
    );
}

#[test]
fn body_limit_counts_all_chunks() {
    let lim = Limits { max_body: 10, ..Limits::default() };
    let t = |s: &str| decode_cuts(Framing::Chunked, s.as_bytes(), &[], &lim);
    assert!(t("5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n").is_ok());
    assert_eq!(t("5\r\nhello\r\n6\r\nworld!\r\n0\r\n\r\n"), Err(Error::BodyTooLarge));
}

#[test]
fn every_split_decodes_the_same() {
    let inputs = [
        "5;a=\"q\\\"\"\r\nhello\r\n1A\r\nabcdefghijklmnopqrstuvwxyz\r\n0;x\r\nT: 1\r\nU: 2\r\n\r\n",
        "3\r\nabc\r\n0\r\n\r\n",
        "0\r\n\r\n",
        "1\r\nx\r\n0\r\nA: b\r\n\r\n",
    ];
    let lim = Limits::default();
    let mut rng = Rng(77);
    for input in inputs {
        let whole = decode_cuts(Framing::Chunked, input.as_bytes(), &[], &lim);
        assert!(matches!(whole, Ok(Some(_))), "{input:?}");
        for k in 0..=input.len() {
            assert_eq!(decode_cuts(Framing::Chunked, input.as_bytes(), &[k], &lim), whole, "{input:?} at {k}");
        }
        let all: Vec<usize> = (1..input.len()).collect();
        assert_eq!(decode_cuts(Framing::Chunked, input.as_bytes(), &all, &lim), whole);
        for _ in 0..200 {
            let mut cuts: Vec<usize> = (0..rng.below(6) + 1).map(|_| rng.below(input.len() + 1)).collect();
            cuts.sort_unstable();
            assert_eq!(decode_cuts(Framing::Chunked, input.as_bytes(), &cuts, &lim), whole);
        }
    }
}

#[test]
fn data_is_borrowed_not_copied() {
    let input = b"5\r\nhello\r\n0\r\n\r\n";
    let mut d = BodyDecoder::new(Framing::Chunked, &Limits::default());
    let (n, ev) = d.decode(input).unwrap();
    let BodyEvent::Data(x) = ev else { panic!() };
    assert_eq!(n, 8);
    assert!(std::ptr::eq(x.as_ptr(), input[3..].as_ptr()));
    let (n2, ev) = d.decode(&input[n..]).unwrap();
    assert_eq!(ev, BodyEvent::End(b""));
    assert_eq!(n + n2, input.len());
    assert_eq!(d.decode(b"more"), Ok((0, BodyEvent::End(b""))));
}
