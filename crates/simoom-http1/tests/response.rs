//! Response parsing, serialization (Date, heads, chunked encoding) and h2c detection.

use simoom_http1::write::*;
use simoom_http1::*;

type Summary = (u16, Framing, bool, bool, usize);

fn resp(s: &[u8], method: &[u8]) -> Result<Status<Summary>, Error> {
    let mut hs = [EMPTY_HEADER; 32];
    Ok(match parse_response(s, &mut hs, &Limits::default(), method)? {
        Status::Complete(r) => Status::Complete((r.status, r.framing, r.keep_alive, r.upgraded, r.head_len)),
        Status::Partial => Status::Partial,
    })
}

fn framing(s: &str, method: &str) -> Framing {
    match resp(s.as_bytes(), method.as_bytes()) {
        Ok(Status::Complete((_, f, ..))) => f,
        other => panic!("{s:?}: {other:?}"),
    }
}

fn rerr(s: &str) -> Error {
    match resp(s.as_bytes(), b"GET") {
        Err(e) => e,
        other => panic!("{s:?}: {other:?}"),
    }
}

#[test]
fn response_head_fields() {
    let s = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\nX: y\r\n\r\nabc";
    let mut hs = [EMPTY_HEADER; 8];
    let Ok(Status::Complete(r)) = parse_response(s, &mut hs, &Limits::default(), b"GET") else { panic!() };
    assert_eq!((r.version, r.status, r.reason), (Version::Http11, 404, &b"Not Found"[..]));
    assert_eq!(r.framing, Framing::Length(3));
    assert_eq!(r.header(b"x"), Some(&b"y"[..]));
    assert_eq!(r.head_len, s.len() - 3);
    assert!(r.keep_alive && !r.upgraded);
    for k in 0..r.head_len {
        assert_eq!(resp(&s[..k], b"GET"), Ok(Status::Partial), "{k}");
    }
}

#[test]
fn response_framing_rules() {
    assert_eq!(framing("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "GET"), Framing::None);
    assert_eq!(framing("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "GET"), Framing::Chunked);
    assert_eq!(framing("HTTP/1.1 200 OK\r\n\r\n", "GET"), Framing::Close);
    assert_eq!(framing("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", "GET"), Framing::Close);
    assert_eq!(framing("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HEAD"), Framing::None);
    assert_eq!(framing("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "GET"), Framing::None);
    assert_eq!(framing("HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n", "GET"), Framing::None);
    assert_eq!(framing("HTTP/1.1 100 Continue\r\n\r\n", "POST"), Framing::None);
    assert_eq!(resp(b"HTTP/1.1 101 Switching Protocols\r\n\r\n", b"GET"), Ok(Status::Complete((101, Framing::None, true, true, 36))));
    let Ok(Status::Complete((_, f, _, up, _))) = resp(b"HTTP/1.1 200 OK\r\n\r\n", b"CONNECT") else { panic!() };
    assert_eq!((f, up), (Framing::None, true));
    let Ok(Status::Complete((_, f, _, up, _))) = resp(b"HTTP/1.1 407 Auth\r\nContent-Length: 1\r\n\r\n", b"CONNECT") else {
        panic!()
    };
    assert_eq!((f, up), (Framing::Length(1), false));
    assert_eq!(rerr("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"), Error::TeWithContentLength);
    assert_eq!(rerr("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"), Error::UnsupportedTransferCoding);
    assert_eq!(rerr("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n"), Error::ChunkedNotFinal);
    assert_eq!(rerr("HTTP/1.1 200 OK\r\nContent-Length: 1, 2\r\n\r\n"), Error::DuplicateContentLength);
}

#[test]
fn response_keep_alive() {
    let ka = |s: &str| match resp(s.as_bytes(), b"GET") {
        Ok(Status::Complete((_, _, k, ..))) => k,
        other => panic!("{other:?}"),
    };
    assert!(ka("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    assert!(!ka("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"));
    assert!(!ka("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"));
    assert!(ka("HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"));
    assert!(!ka("HTTP/1.1 200 OK\r\n\r\n"), "close-delimited");
}

#[test]
fn status_line_rules() {
    assert_eq!(resp(b"HTTP/1.1 200 \r\n\r\n", b"GET").map(|s| matches!(s, Status::Complete(_))), Ok(true));
    for s in ["HTTP/1.1 20 OK\r\n\r\n", "HTTP/1.1 2000 OK\r\n\r\n", "HTTP/1.1 099 X\r\n\r\n", "HTTP/1.1 600 X\r\n\r\n", "HTTP/1.1 2x0 X\r\n\r\n", "HTTP/1.1 200\r\n\r\n"] {
        assert_eq!(rerr(s), Error::InvalidStatus, "{s:?}");
    }
    assert_eq!(rerr("HTTP/1.1 200 O\x01K\r\n\r\n"), Error::InvalidReason);
    assert_eq!(rerr("HTTP/1.1 200 OK\nX: y\r\n\r\n"), Error::BareLf);
    assert_eq!(rerr("HTTP/1.1 200 OK\rX: y\r\n\r\n"), Error::BareCr);
    assert_eq!(rerr("HTTP/2.0 200 OK\r\n\r\n"), Error::VersionNotSupported);
    assert_eq!(rerr("HTTP/1.1_200 OK\r\n\r\n"), Error::InvalidVersion);
    assert_eq!(rerr("XTTP/1.1 200 OK\r\n\r\n"), Error::InvalidVersion);
    assert_eq!(rerr("HTTP/1.1 200 OK\r\nX : y\r\n\r\n"), Error::WhitespaceBeforeColon);
    let lim = Limits { max_request_line: 20, ..Limits::default() };
    let mut hs = [EMPTY_HEADER; 4];
    assert_eq!(parse_response(b"HTTP/1.1 200 OKOKOKOKOK", &mut hs, &lim, b"GET"), Err(Error::RequestLineTooLong));
}

#[test]
fn http_dates() {
    for (t, s) in [
        (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
        (784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT"),
        (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
        (1_700_000_000, "Tue, 14 Nov 2023 22:13:20 GMT"),
        (4_102_444_799, "Thu, 31 Dec 2099 23:59:59 GMT"),
        (253_402_300_799, "Fri, 31 Dec 9999 23:59:59 GMT"),
    ] {
        assert_eq!(&http_date(t), s.as_bytes(), "{t}");
    }
    let mut d = DateCache::new(0);
    assert!(!d.update(0));
    assert!(d.update(784_111_777));
    assert_eq!(d.bytes(), b"Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(d.secs(), 784_111_777);
}

#[test]
fn head_writer_output_parses_back() {
    let date = DateCache::new(784_111_777);
    let mut out = Vec::new();
    let mut w = HeadWriter::response(&mut out, 200);
    w.header(b"Content-Type", b"text/plain").unwrap().date(&date).content_length(13);
    w.finish();
    assert_eq!(
        out,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Length: 13\r\n\r\n"
    );
    out.extend_from_slice(b"Hello, World!");
    let mut hs = [EMPTY_HEADER; 8];
    let Ok(Status::Complete(r)) = parse_response(&out, &mut hs, &Limits::default(), b"GET") else { panic!() };
    assert_eq!(r.framing, Framing::Length(13));

    let mut out = Vec::new();
    let mut w = HeadWriter::response(&mut out, 299);
    w.chunked().close();
    w.finish();
    assert_eq!(out, b"HTTP/1.1 299 \r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");

    let mut out = Vec::new();
    let mut w = HeadWriter::request(&mut out, b"GET", b"/x?y").unwrap();
    w.header(b"Host", b"h").unwrap();
    w.finish();
    let mut hs = [EMPTY_HEADER; 8];
    let Ok(Status::Complete(r)) = parse_request(&out, &mut hs, &Limits::default()) else { panic!() };
    assert_eq!(r.target, b"/x?y");
    assert!(HeadWriter::request(&mut Vec::new(), b"G T", b"/").is_err());
    assert!(HeadWriter::request(&mut Vec::new(), b"GET", b"/a b").is_err());
}

#[test]
fn head_writer_refuses_splitting_and_framing_fields() {
    let mut out = Vec::new();
    let mut w = HeadWriter::response(&mut out, 200);
    assert_eq!(w.header(b"X", b"a\r\nSet-Cookie: evil").err(), Some(Error::InvalidHeaderValue));
    assert_eq!(w.header(b"X", b"a\nb").err(), Some(Error::InvalidHeaderValue));
    assert_eq!(w.header(b"X", b"a\x00").err(), Some(Error::InvalidHeaderValue));
    assert_eq!(w.header(b"X Y", b"a").err(), Some(Error::InvalidHeaderName));
    assert_eq!(w.header(b"", b"a").err(), Some(Error::InvalidHeaderName));
    assert_eq!(w.header(b"Content-Length", b"1").err(), Some(Error::FramingHeader));
    assert_eq!(w.header(b"transfer-encoding", b"chunked").err(), Some(Error::FramingHeader));
    assert!(w.header(b"X", b"caf\xc3\xa9\tok").is_ok());
}

#[test]
fn static_head_patches_the_date() {
    let mut h = StaticHead::new(200, &[(b"Content-Type", b"text/plain"), (b"Server", b"simoom")], b"Hello, World!").unwrap();
    let d1 = DateCache::new(0);
    let full = h.full(&d1).to_vec();
    assert!(full.ends_with(b"\r\n\r\nHello, World!"));
    assert!(full.windows(35).any(|w| w == b"Date: Thu, 01 Jan 1970 00:00:00 GMT"));
    let d2 = DateCache::new(784_111_777);
    let head = h.head(&d2).to_vec();
    assert!(head.ends_with(b"Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n\r\n"));
    assert_eq!(h.full(&d2).len(), full.len());
    let mut hs = [EMPTY_HEADER; 8];
    let full2 = h.full(&d2).to_vec();
    let Ok(Status::Complete(r)) = parse_response(&full2, &mut hs, &Limits::default(), b"GET") else { panic!() };
    assert_eq!((r.status, r.framing, r.head_len), (200, Framing::Length(13), head.len()));
    assert!(StaticHead::new(200, &[(b"Bad\n", b"x")], b"").is_err());
}

#[test]
fn chunk_encoder_round_trips() {
    assert_eq!(ChunkHeader::new(1).as_bytes(), b"1\r\n");
    assert_eq!(ChunkHeader::new(255).as_bytes(), b"ff\r\n");
    assert_eq!(ChunkHeader::new(4096).as_bytes(), b"1000\r\n");
    assert_eq!(ChunkHeader::new(usize::MAX).as_bytes().len(), usize::BITS as usize / 4 + 2);
    let mut out = Vec::new();
    write_chunk(&mut out, b"hello");
    write_chunk(&mut out, b"");
    write_chunk(&mut out, &[b'x'; 300]);
    write_last_chunk(&mut out, &[(b"X-Sum", b"abc")]).unwrap();
    let mut d = BodyDecoder::new(Framing::Chunked, &Limits::default());
    let mut data = Vec::new();
    let mut at = 0;
    loop {
        let (n, ev) = d.decode(&out[at..]).unwrap();
        at += n;
        match ev {
            BodyEvent::Data(x) => data.extend_from_slice(x),
            BodyEvent::End(t) => {
                assert_eq!(t, b"X-Sum: abc\r\n\r\n");
                break;
            }
            BodyEvent::NeedMore => panic!(),
        }
    }
    assert_eq!(at, out.len());
    assert_eq!(data.len(), 305);
    let mut out = Vec::new();
    write_last_chunk(&mut out, &[]).unwrap();
    assert_eq!(out, LAST_CHUNK);
    assert_eq!(write_last_chunk(&mut out, &[(b"Content-Length", b"1")]), Err(Error::FramingHeader));
    assert_eq!(write_last_chunk(&mut out, &[(b"Host", b"x")]), Err(Error::ForbiddenTrailer));
    assert_eq!(CONTINUE, b"HTTP/1.1 100 Continue\r\n\r\n");
    assert_eq!(reason(431), "Request Header Fields Too Large");
    assert_eq!(reason(299), "");
}

#[test]
fn h2_preface_detection() {
    use simoom_http1::h2c::*;
    assert_eq!(detect_preface(b""), Preface::Partial);
    assert_eq!(detect_preface(b"PRI * HTTP/2"), Preface::Partial);
    assert_eq!(detect_preface(PREFACE), Preface::H2);
    assert_eq!(detect_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04"), Preface::H2);
    assert_eq!(detect_preface(b"GET / HTTP/1.1\r\n"), Preface::Http1);
    assert_eq!(detect_preface(b"PRI * HTTP/1.1\r\n"), Preface::Http1);
    assert_eq!(detect_preface(b"P"), Preface::Partial);
    assert_eq!(detect_preface(b"X"), Preface::Http1);
    // The preface's request line followed by anything but the rest of the preface is a broken
    // HTTP/2 client (RFC 9113 §3.4), not an HTTP/1 request.
    assert_eq!(detect_preface(b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n"), Preface::Invalid);
    assert_eq!(detect_preface(b"PRI * HTTP/2.0\n"), Preface::Invalid);
    assert_eq!(detect_preface(b"PRI * HTTP/2.0 "), Preface::Invalid);
    assert_eq!(detect_preface(b"PRI * HTTP/2.0"), Preface::Partial);
    assert_eq!(detect_preface(b"PRI * HTTP/2.1\r\n"), Preface::Http1);
    assert_eq!(detect_preface(b"INVALID CONNECTION PREFACE\r\n\r\n"), Preface::Http1);
    // The HTTP/1 parser refuses the preface on its own (asterisk form is for OPTIONS only).
    let mut hs = [EMPTY_HEADER; 4];
    assert!(parse_request(PREFACE, &mut hs, &Limits::default()).is_err());
}

#[test]
fn h2c_upgrade_requests() {
    use simoom_http1::h2c::*;
    let check = |s: &str| {
        let mut hs = [EMPTY_HEADER; 16];
        let Ok(Status::Complete(r)) = parse_request(s.as_bytes(), &mut hs, &Limits::default()) else { panic!("{s}") };
        let mut out = Vec::new();
        upgrade_settings(&r, &mut out).then_some(out)
    };
    // SETTINGS_MAX_CONCURRENT_STREAMS = 100, SETTINGS_INITIAL_WINDOW_SIZE = 65535.
    let settings = "AAMAAABkAARAAAAAAAIAAAAA";
    let ok = format!("GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: {settings}\r\n\r\n");
    let raw = check(&ok).unwrap();
    assert_eq!(raw.len(), 18);
    assert_eq!(&raw[..6], &[0, 3, 0, 0, 0, 100]);
    assert!(check(&ok.replace("Upgrade, HTTP2-Settings", "Upgrade")).is_none());
    assert!(check(&ok.replace("Upgrade: h2c", "Upgrade: websocket")).is_none());
    assert!(check(&ok.replace(settings, "AAMAAABkAAR")).is_none(), "not a whole setting");
    assert!(check(&ok.replace(settings, "AAMA+ABk")).is_none(), "not base64url");
    assert!(check(&ok.replace("\r\n\r\n", "\r\nHTTP2-Settings: AAMAAABk\r\n\r\n")).is_none(), "two fields");
    assert!(check(&ok.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\n")).is_none(), "body");
    assert!(check(&ok.replace("HTTP2-Settings: ", "X: ")).is_none());
    assert!(check(&ok.replace(settings, "")).is_some(), "empty settings are allowed");
    assert!(SWITCHING_PROTOCOLS.starts_with(b"HTTP/1.1 101 "));
}

#[test]
fn short_status_line_with_empty_line_is_an_error_not_a_wait() {
    assert_eq!(rerr("HTTP/\r\n\r\n"), Error::InvalidVersion);
    assert_eq!(rerr("HTTP/1.1\r\n\r\n"), Error::InvalidVersion);
    assert_eq!(rerr("HTTP/1.1 2\r\n\r\n"), Error::InvalidStatus);
    assert_eq!(resp(b"HTTP/1.1 20", b"GET"), Ok(Status::Partial));
}
