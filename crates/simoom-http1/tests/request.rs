//! Request parsing: one test per RFC 9112 rule, the smuggling vectors, limits, pipelining and
//! split invariance.

mod common;

use common::*;
use simoom_http1::*;

fn lim() -> Limits {
    Limits::default()
}

fn ok(s: &str) -> Req {
    match parse_with(s.as_bytes(), &lim()) {
        Ok(Some(r)) => r,
        other => panic!("{s:?}: {other:?}"),
    }
}

fn err(s: &str) -> Error {
    err_b(s.as_bytes())
}

fn err_b(s: &[u8]) -> Error {
    match parse_with(s, &lim()) {
        Err(e) => e,
        other => panic!("{:?}: expected an error, got {other:?}", String::from_utf8_lossy(s)),
    }
}

fn partial(s: &str) {
    assert_eq!(parse_with(s.as_bytes(), &lim()), Ok(None), "{s:?}");
}

/// A request with the given extra header lines (each without CRLF).
fn with(lines: &[&str]) -> String {
    let mut s = String::from("POST / HTTP/1.1\r\nHost: h\r\n");
    for l in lines {
        s.push_str(l);
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    s
}

const CURL: &str = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n";

#[test]
fn minimal_request() {
    let r = ok(CURL);
    assert_eq!(r.method, b"GET");
    assert_eq!(r.target, b"/");
    assert_eq!(r.form, TargetForm::Origin);
    assert_eq!(r.version, Version::Http11);
    assert_eq!(r.headers.len(), 3);
    assert_eq!(r.headers[1], (b"User-Agent".to_vec(), b"curl/8.5.0".to_vec()));
    assert_eq!(r.framing, Framing::None);
    assert!(r.keep_alive);
    assert!(!r.expect);
    assert_eq!(r.upgrade, None);
    assert_eq!(r.host.as_deref(), Some(&b"localhost:8080"[..]));
    assert_eq!(r.head_len, CURL.len());
}

#[test]
fn header_lookup_and_trailing_bytes_left_alone() {
    let s = format!("{CURL}GET /next");
    let mut hs = [EMPTY_HEADER; 16];
    let Ok(Status::Complete(r)) = parse_request(s.as_bytes(), &mut hs, &lim()) else { panic!() };
    assert_eq!(r.header(b"user-agent"), Some(&b"curl/8.5.0"[..]));
    assert_eq!(r.header(b"x-missing"), None);
    assert_eq!(r.head_len, CURL.len());
}

#[test]
fn every_prefix_is_partial() {
    for k in 0..CURL.len() {
        partial(&CURL[..k]);
    }
}

#[test]
fn leading_empty_lines_are_skipped() {
    let s = format!("\r\n\r\n{CURL}");
    let r = ok(&s);
    assert_eq!(r.head_len, s.len());
    assert_eq!(err("\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"), Error::BareLf);
    assert_eq!(err("\rXGET / HTTP/1.1\r\nHost: h\r\n\r\n"), Error::BareCr);
}

#[test]
fn method_rules() {
    assert_eq!(ok("M-SEARCH / HTTP/1.1\r\nHost: h\r\n\r\n").method, b"M-SEARCH");
    // The asterisk form is for OPTIONS only (RFC 9112 §3.2.4), so SSDP-style M-SEARCH * is not.
    assert_eq!(err("M-SEARCH * HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidTarget);
    assert_eq!(ok("get / HTTP/1.1\r\nHost: h\r\n\r\n").method, b"get");
    assert_eq!(err(" / HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidMethod);
    assert_eq!(err("GE(T / HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidMethod);
    assert_eq!(err("GET\t/ HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidMethod);
    assert_eq!(err("GET\r\n\r\n"), Error::InvalidMethod);
    assert_eq!(err_b(b"G\xc3\x89T / HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidMethod);
}

#[test]
fn target_rules() {
    let t = |target: &str| ok(&format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n"));
    let bad = |target: &str| err(&format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n"));
    assert_eq!(t("/a/b;c?d=e&f=%20+g:@!$'()*,").form, TargetForm::Origin);
    assert_eq!(t("//double//slash").form, TargetForm::Origin);
    assert_eq!(t("/%41%7e").target, b"/%41%7e");
    assert_eq!(t("http://example.com/x?y").form, TargetForm::Absolute);
    assert_eq!(t("http://[::1]:8080/x").form, TargetForm::Absolute);
    assert_eq!(t("https://user@host:1/p").form, TargetForm::Absolute);
    for b in ["/%zz", "/%4", "/%", "/a#frag", "/a\"b", "/<x>", "/{x}", "/a\\b", "/a|b", "/a^b", "/a`b", "/[x]", "1http://x/", "http://h/[x]", "noscheme"] {
        assert_eq!(bad(b), Error::InvalidTarget, "{b}");
    }
    assert_eq!(err("GET  / HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidTarget);
    assert_eq!(err_b(b"GET /\xc3\xa9 HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidTarget);
    assert_eq!(err_b(b"GET /\x7f HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidTarget);
    assert_eq!(err_b(b"GET /\x00 HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidTarget);
    // A percent sign at the end of the input waits for its digits.
    partial("GET /%");
    partial("GET /%4");
    assert_eq!(err("GET /%g"), Error::InvalidTarget);
}

#[test]
fn asterisk_and_authority_forms_belong_to_their_methods() {
    assert_eq!(ok("OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n").form, TargetForm::Asterisk);
    assert_eq!(err("GET * HTTP/1.1\r\nHost: h\r\n\r\n"), Error::InvalidTarget);
    let c = ok("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
    assert_eq!(c.form, TargetForm::Authority);
    assert_eq!(ok("CONNECT [::1]:443 HTTP/1.1\r\nHost: h\r\n\r\n").form, TargetForm::Authority);
    for t in ["/", "example.com", "example.com:", "a@b:1", "http://x:1/", "*", "h:1/x", "h:x"] {
        assert_eq!(err(&format!("CONNECT {t} HTTP/1.1\r\nHost: h\r\n\r\n")), Error::InvalidTarget, "{t}");
    }
}

#[test]
fn version_rules() {
    assert_eq!(ok("GET / HTTP/1.0\r\n\r\n").version, Version::Http10);
    for v in ["HTTP/2.0", "HTTP/1.2", "HTTP/0.9", "HTTP/3.0"] {
        assert_eq!(err(&format!("GET / {v}\r\nHost: h\r\n\r\n")), Error::VersionNotSupported, "{v}");
    }
    for v in ["http/1.1", "HTTP/1.1 ", "HTTP/11", "HTTP/1.x", "HTTP/1.1x", "XTTP/1.1", "HTTP/1.10"] {
        assert_eq!(err(&format!("GET / {v}\r\nHost: h\r\n\r\n")), Error::InvalidVersion, "{v}");
    }
    assert_eq!(err("GET / HTTP/1.1\nHost: h\r\n\r\n"), Error::BareLf);
    assert_eq!(err("GET / HTTP/1.1\rHost: h\r\n\r\n"), Error::BareCr);
    assert_eq!(err("GET / X"), Error::InvalidVersion);
    partial("GET / HTTP/1.1");
    partial("GET / HTTP/1.1\r");
}

#[test]
fn field_name_rules() {
    assert_eq!(err(&with(&["Host : h"])), Error::WhitespaceBeforeColon);
    assert_eq!(err(&with(&["X-A\t: 1"])), Error::WhitespaceBeforeColon);
    assert_eq!(err(&with(&[": empty"])), Error::InvalidHeaderName);
    assert_eq!(err(&with(&["X(a): 1"])), Error::InvalidHeaderName);
    assert_eq!(err(&with(&["X@a: 1"])), Error::InvalidHeaderName);
    assert_eq!(err(&with(&["NoColon"])), Error::InvalidHeaderName);
    assert_eq!(err_b(b"GET / HTTP/1.1\r\nHost: h\r\nX\xc3\xa9: 1\r\n\r\n"), Error::InvalidHeaderName);
    assert_eq!(err_b(b"GET / HTTP/1.1\r\nHost: h\r\nX\x00: 1\r\n\r\n"), Error::InvalidHeaderName);
    let r = ok(&with(&["!#$%&'*+-.^_`|~09azAZ: v"]));
    assert_eq!(r.headers[1].0, b"!#$%&'*+-.^_`|~09azAZ");
}

#[test]
fn field_value_rules() {
    let r = ok(&with(&["A:  \t spaced \t value \t ", "B:", "C: \t", "D:x"]));
    assert_eq!(r.headers[1].1, b"spaced \t value");
    assert_eq!(r.headers[2].1, b"");
    assert_eq!(r.headers[3].1, b"");
    assert_eq!(r.headers[4].1, b"x");
    let r = parse_with(b"GET / HTTP/1.1\r\nHost: h\r\nX: caf\xc3\xa9 \x80\xff\r\n\r\n", &lim()).unwrap().unwrap();
    assert_eq!(r.headers[1].1, b"caf\xc3\xa9 \x80\xff");
    for v in [&b"a\x00b"[..], b"a\x01", b"\x7f", b"a\x0bb", b"\x0cx", b"a\x1fb"] {
        let mut s = b"GET / HTTP/1.1\r\nHost: h\r\nX: ".to_vec();
        s.extend_from_slice(v);
        s.extend_from_slice(b"\r\n\r\n");
        assert_eq!(err_b(&s), Error::InvalidHeaderValue, "{v:?}");
    }
    assert_eq!(err("GET / HTTP/1.1\r\nHost: h\r\nX: a\rb\r\n\r\n"), Error::BareCr);
    assert_eq!(err("GET / HTTP/1.1\r\nHost: h\r\nX: a\nY: b\r\n\r\n"), Error::BareLf);
    assert_eq!(err("GET / HTTP/1.1\r\nHost: h\r\n\n"), Error::BareLf);
    assert_eq!(err("GET / HTTP/1.1\r\nHost: h\r\n\rX"), Error::BareCr);
}

#[test]
fn obs_fold_and_whitespace_after_start_line_are_rejected() {
    assert_eq!(err("GET / HTTP/1.1\r\nHost: h\r\nX: a\r\n b\r\n\r\n"), Error::ObsFold);
    assert_eq!(err("GET / HTTP/1.1\r\nHost: h\r\nX: a\r\n\tb\r\n\r\n"), Error::ObsFold);
    assert_eq!(err("GET / HTTP/1.1\r\n Host: h\r\n\r\n"), Error::ObsFold);
}

#[test]
fn host_rules() {
    assert_eq!(err("GET / HTTP/1.1\r\n\r\n"), Error::MissingHost);
    assert_eq!(ok("GET / HTTP/1.0\r\n\r\n").host, None);
    assert_eq!(err("GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n"), Error::DuplicateHost);
    assert_eq!(err("GET / HTTP/1.1\r\nhost: a\r\nHOST: b\r\n\r\n"), Error::DuplicateHost);
    for h in ["", "h", "h:80", "h:", "1.2.3.4:5", "[::1]", "[::1]:8080", "a-b.c_d~e", "x%41"] {
        assert_eq!(ok(&format!("GET / HTTP/1.1\r\nHost: {h}\r\n\r\n")).host.unwrap(), h.as_bytes(), "{h}");
    }
    for h in ["a b", "a@b", "a/b", "h:8x", "h:1:2", "[::1", "[]", "[zz]", "x%4", ":80", "a?b"] {
        assert_eq!(err(&format!("GET / HTTP/1.1\r\nHost: {h}\r\n\r\n")), Error::InvalidHost, "{h}");
    }
}

#[test]
fn content_length_rules() {
    assert_eq!(ok(&with(&["Content-Length: 5"])).framing, Framing::Length(5));
    assert_eq!(ok(&with(&["Content-Length: 0"])).framing, Framing::None);
    assert_eq!(ok(&with(&["Content-Length:  007 "])).framing, Framing::Length(7));
    assert_eq!(ok(&with(&["content-length: 10485760"])).framing, Framing::Length(10 * 1024 * 1024));
    for v in ["+5", "-1", "0x5", "5 5", "5;", "", "1e3", "\u{663}"] {
        assert_eq!(err(&with(&[&format!("Content-Length: {v}")])), Error::InvalidContentLength, "{v:?}");
    }
    assert_eq!(err(&with(&["Content-Length: 99999999999999999999"])), Error::InvalidContentLength);
    assert_eq!(err(&with(&["Content-Length: 18446744073709551616"])), Error::InvalidContentLength);
    assert_eq!(err(&with(&["Content-Length: 18446744073709551615"])), Error::BodyTooLarge);
    assert_eq!(err(&with(&["Content-Length: 10485761"])), Error::BodyTooLarge);
    assert_eq!(err(&with(&["Content-Length: 5,5"])), Error::DuplicateContentLength);
    assert_eq!(err(&with(&["Content-Length: 5, 6"])), Error::DuplicateContentLength);
    assert_eq!(err(&with(&["Content-Length: 5", "Content-Length: 5"])), Error::DuplicateContentLength);
    assert_eq!(err(&with(&["Content-Length: 5", "content-length: 6"])), Error::DuplicateContentLength);
    assert_eq!(err(&with(&["Content-Length: 5,"])), Error::InvalidContentLength);
}

#[test]
fn transfer_encoding_rules() {
    assert_eq!(ok(&with(&["Transfer-Encoding: chunked"])).framing, Framing::Chunked);
    assert_eq!(ok(&with(&["transfer-encoding: CHUNKED"])).framing, Framing::Chunked);
    assert_eq!(ok(&with(&["Transfer-Encoding:\t chunked \t"])).framing, Framing::Chunked);
    for (v, e) in [
        ("gzip", Error::ChunkedNotFinal),
        ("identity", Error::ChunkedNotFinal),
        ("xchunked", Error::ChunkedNotFinal),
        ("chunked, gzip", Error::ChunkedNotFinal),
        ("chunked, chunked", Error::ChunkedNotFinal),
        ("gzip, chunked", Error::UnsupportedTransferCoding),
        ("chunked,", Error::InvalidTransferEncoding),
        (",chunked", Error::InvalidTransferEncoding),
        ("chunked;q=1", Error::InvalidTransferEncoding),
        ("\"chunked\"", Error::InvalidTransferEncoding),
        ("chun ked", Error::InvalidTransferEncoding),
        ("", Error::InvalidTransferEncoding),
    ] {
        assert_eq!(err(&with(&[&format!("Transfer-Encoding: {v}")])), e, "{v:?}");
    }
    assert_eq!(err(&with(&["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"])), Error::ChunkedNotFinal);
    assert_eq!(err(&with(&["Transfer-Encoding: chunked", "Transfer-Encoding: identity"])), Error::ChunkedNotFinal);
    assert_eq!(err(&with(&["Transfer-Encoding: gzip", "Transfer-Encoding: chunked"])), Error::UnsupportedTransferCoding);
    assert_eq!(
        err("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
        Error::TransferEncodingHttp10
    );
}

#[test]
fn expect_rules() {
    let r = ok(&with(&["Expect: 100-continue", "Content-Length: 3"]));
    assert!(r.expect);
    let mut hs = [EMPTY_HEADER; 8];
    let s = with(&["Expect: 100-Continue", "Content-Length: 3"]);
    let Ok(Status::Complete(req)) = parse_request(s.as_bytes(), &mut hs, &lim()) else { panic!() };
    assert!(req.wants_continue());
    let s = with(&["Expect: 100-continue"]);
    let Ok(Status::Complete(req)) = parse_request(s.as_bytes(), &mut hs, &lim()) else { panic!() };
    assert!(req.expect_continue && !req.wants_continue(), "no body, no 100");
    assert_eq!(err(&with(&["Expect: 100-continuex"])), Error::ExpectationFailed);
    assert_eq!(err(&with(&["Expect: 100-continue, foo"])), Error::ExpectationFailed);
    assert_eq!(err(&with(&["Expect: 100-continue", "Expect: x"])), Error::ExpectationFailed);
    // HTTP/1.0: a server must ignore 100-continue (RFC 9110 §10.1.1); other values too.
    assert!(!ok("POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n").expect);
    assert!(!ok("POST / HTTP/1.0\r\nExpect: other\r\n\r\n").expect);
}

#[test]
fn connection_rules() {
    assert!(ok(CURL).keep_alive);
    assert!(!ok(&with(&["Connection: close"])).keep_alive);
    assert!(!ok(&with(&["Connection: keep-alive, Close"])).keep_alive);
    assert!(!ok("GET / HTTP/1.0\r\n\r\n").keep_alive);
    assert!(ok("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n").keep_alive);
    assert!(!ok("GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n").keep_alive);
    assert!(ok(&with(&["Connection: keep-alive"])).keep_alive);
}

#[test]
fn upgrade_rules() {
    let r = ok("GET /ws HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n");
    assert_eq!(r.upgrade.as_deref(), Some(&b"websocket"[..]));
    assert_eq!(ok("GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n").upgrade, None);
    assert_eq!(ok("GET / HTTP/1.0\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").upgrade, None);
    assert_eq!(ok("GET / HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\n\r\n").upgrade, None);
    assert_eq!(
        err("GET / HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\nUpgrade: a\r\nUpgrade: b\r\n\r\n"),
        Error::DuplicateUpgrade
    );
}

#[test]
fn has_token_splits_and_trims() {
    assert!(has_token(b"a, B ,c", b"b"));
    assert!(has_token(b"\tclose\t", b"close"));
    assert!(!has_token(b"closed", b"close"));
    assert!(!has_token(b"", b"close"));
}

#[test]
fn limits_each_have_their_own_error() {
    let small = Limits { max_request_line: 32, max_head: 128, max_headers: 3, max_header_line: 24, ..Limits::default() };
    let p = |s: &str| parse_with(s.as_bytes(), &small);
    // Request line: exactly at the limit is fine, one more byte is not; also when incomplete.
    let line = format!("GET /{} HTTP/1.1\r\n", "a".repeat(32 - 16));
    assert_eq!(line.len(), 32);
    assert!(p(&format!("{line}Host: h\r\n\r\n")).unwrap().is_some());
    let long = format!("GET /{} HTTP/1.1\r\n", "a".repeat(17));
    assert_eq!(p(&format!("{long}Host: h\r\n\r\n")), Err(Error::RequestLineTooLong));
    assert_eq!(p(&format!("GET /{}", "a".repeat(40))), Err(Error::RequestLineTooLong));
    // Header count.
    assert!(p("GET / HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\n\r\n").unwrap().is_some());
    assert_eq!(p("GET / HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"), Err(Error::TooManyHeaders));
    // Header line (CRLF included), complete and incomplete.
    assert!(p(&format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", "h".repeat(16))).unwrap().is_some());
    assert_eq!(p(&format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", "h".repeat(17))), Err(Error::HeaderLineTooLong));
    assert_eq!(p(&format!("GET / HTTP/1.1\r\nHost: {}", "h".repeat(30))), Err(Error::HeaderLineTooLong));
    // Whole head.
    let s = "GET / HTTP/1.1\r\nHost: h\r\nA: 12345678901234\r\nB: 1234567\r\n\r\n";
    let n = s.len();
    let big = Limits { max_head: n - 1, ..small };
    assert_eq!(parse_with(s.as_bytes(), &big), Err(Error::HeadTooLarge));
    assert!(parse_with(s.as_bytes(), &Limits { max_head: n, ..small }).unwrap().is_some());
    assert_eq!(parse_with(&s.as_bytes()[..n - 3], &Limits { max_head: n - 10, ..small }), Err(Error::HeadTooLarge));
    // Leading empty lines count toward the head.
    assert_eq!(parse_with("\r\n".repeat(40).as_bytes(), &big), Err(Error::HeadTooLarge));
    // Header storage smaller than the limit.
    let mut hs = [EMPTY_HEADER; 1];
    assert_eq!(parse_request(CURL.as_bytes(), &mut hs, &lim()), Err(Error::TooManyHeaders));
}

#[test]
fn default_limits_match_the_plan() {
    let l = Limits::default();
    assert_eq!((l.max_request_line, l.max_head, l.max_headers, l.max_header_line), (8192, 16384, 100, 8192));
    assert_eq!(l.max_body, 10 << 20);
    let many: String = (0..101).map(|i| format!("X{i}: v\r\n")).collect();
    assert_eq!(err(&format!("GET / HTTP/1.1\r\nHost: h\r\n{many}\r\n")), Error::TooManyHeaders);
}

#[test]
fn error_statuses() {
    assert_eq!(Error::RequestLineTooLong.status(), 414);
    assert_eq!(Error::HeadTooLarge.status(), 431);
    assert_eq!(Error::TooManyHeaders.status(), 431);
    assert_eq!(Error::HeaderLineTooLong.status(), 431);
    assert_eq!(Error::VersionNotSupported.status(), 505);
    assert_eq!(Error::UnsupportedTransferCoding.status(), 501);
    assert_eq!(Error::BodyTooLarge.status(), 413);
    assert_eq!(Error::ExpectationFailed.status(), 417);
    assert_eq!(Error::TeWithContentLength.status(), 400);
    assert_eq!(Error::BareCr.to_string(), "BareCr");
}

// ---- Smuggling and desync vectors --------------------------------------------------------

#[test]
fn smuggling_cl_te_and_te_cl() {
    // CL.TE: a front end using Content-Length forwards a chunked body that hides a request.
    let cl_te = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED";
    assert_eq!(err(cl_te), Error::TeWithContentLength);
    let te_cl = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n";
    assert_eq!(err(te_cl), Error::TeWithContentLength);
    // Even when the TE value is one this parser would refuse anyway.
    assert_eq!(err(&with(&["Content-Length: 1", "Transfer-Encoding: gzip"])), Error::TeWithContentLength);
}

#[test]
fn smuggling_te_te_obfuscations() {
    // Every spelling some server accepts as chunked and another does not is refused, or is
    // simply not a Transfer-Encoding field (and then there is no body at all).
    let refused: &[&[u8]] = &[
        b"Transfer-Encoding : chunked",
        b"Transfer-Encoding\t: chunked",
        b" Transfer-Encoding: chunked",
        b"Transfer-Encoding: xchunked",
        b"Transfer-Encoding: chunked, identity",
        b"Transfer-Encoding: chunked\x0b",
        b"Transfer-Encoding: \x0cchunked",
        b"Transfer-Encoding: chunked\x00",
        b"Transfer-Encoding: \"chunked\"",
        b"Transfer-Encoding: chunk",
        b"Transfer-Encoding: chunked;",
        b"Transfer-Encoding: chunked,,",
        b"Transfer-Encoding: x\r\nTransfer-Encoding: chunked\r\nX: y",
        b"Transfer-Encoding:\n chunked",
        b"Transfer-Encoding: chunked\r\n\tx",
        b"Transfer-Encoding: chunked\r\n x",
        b"Transfer-Encoding: ch\runked",
        b"Transfer-Encoding: \xc2\xa0chunked",
        b"Transfer-Encoding\x00: chunked",
    ];
    for v in refused {
        let mut s = b"POST / HTTP/1.1\r\nHost: h\r\n".to_vec();
        s.extend_from_slice(v);
        s.extend_from_slice(b"\r\n\r\n");
        assert!(parse_with(&s, &lim()).is_err(), "{:?}", String::from_utf8_lossy(v));
    }
    // Lookalike names are just other fields: no body.
    for name in ["Transfer_Encoding", "Transfer-Encodings", "XTransfer-Encoding"] {
        assert_eq!(ok(&with(&[&format!("{name}: chunked")])).framing, Framing::None, "{name}");
    }
}

#[test]
fn smuggling_zero_cl_and_cl_zero() {
    // 0.CL: the front end ignores a malformed Content-Length; this parser refuses it.
    for v in ["Content-Length : 5", "Content-Length:\x0b5", " Content-Length: 5", "Content-Length: 5\r\n x"] {
        let s = format!("GET / HTTP/1.1\r\nHost: h\r\n{v}\r\n\r\nGET /404 HTTP/1.1\r\nX: Y");
        assert!(parse_with(s.as_bytes(), &lim()).is_err(), "{v:?}");
    }
    // CL.0: Content-Length is always honoured, whatever the method or target, so the body
    // can never be read as the next request.
    let s = "GET /static.css HTTP/1.1\r\nHost: h\r\nContent-Length: 24\r\n\r\nGET /admin HTTP/1.1\r\nX: ";
    let evs = drive(&[s.as_bytes()], &lim());
    assert_eq!(evs.len(), 2, "{evs:?}");
    assert_eq!(evs[1], Ev::Body(b"GET /admin HTTP/1.1\r\nX: ".to_vec()));
}

#[test]
fn expect_does_not_change_framing() {
    // Whether or not the server sends 100 Continue, the body is the declared length; the
    // bytes after it are the next request.
    let s = "POST / HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\nbodyGET /2 HTTP/1.1\r\nHost: h\r\n\r\n";
    let evs = drive(&[s.as_bytes()], &lim());
    assert_eq!(evs.len(), 4);
    let Ev::Head(h) = &evs[0] else { panic!() };
    assert!(h.expect);
    assert_eq!(evs[1], Ev::Body(b"body".to_vec()));
    let Ev::Head(h2) = &evs[2] else { panic!() };
    assert_eq!(h2.target, b"/2");
    // An unknown expectation is refused rather than ignored (CVE-2025-32094 style desync).
    assert_eq!(err(&with(&["Expect: y 100-continue", "Content-Length: 4"])), Error::ExpectationFailed);
    assert_eq!(err(&with(&["Expect:\x0b100-continue"])), Error::InvalidHeaderValue);
}

#[test]
fn smuggling_misc_vectors() {
    // Bare LF line endings, which some parsers accept as CRLF.
    assert!(parse_with(b"GET / HTTP/1.1\nHost: h\n\n", &lim()).is_err());
    assert!(parse_with(b"GET / HTTP/1.1\r\nHost: h\n\r\n", &lim()).is_err());
    // A bare CR inside a field value hiding a header.
    assert_eq!(err("GET / HTTP/1.1\r\nHost: h\r\nX: a\rContent-Length: 5\r\n\r\n"), Error::BareCr);
    // NUL truncation.
    assert!(parse_with(b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x00\r\nContent-Length: 5\r\n\r\n", &lim()).is_err());
    // An HTTP/0.9-style request line.
    assert!(parse_with(b"GET /\r\n\r\n", &lim()).is_err());
    // Two spaces, a tab and trailing space in the request line.
    assert!(parse_with(b"GET /  HTTP/1.1\r\nHost: h\r\n\r\n", &lim()).is_err());
    assert!(parse_with(b"GET / HTTP/1.1 \r\nHost: h\r\n\r\n", &lim()).is_err());
    // Absolute-form with a different Host is allowed (the target wins, RFC 9112 §3.2.2).
    assert_eq!(ok("GET http://a/x HTTP/1.1\r\nHost: b\r\n\r\n").form, TargetForm::Absolute);
    // Empty header name, as in HAProxy CVE-2023-25725.
    assert_eq!(err(&with(&[": x", "Content-Length: 1"])), Error::InvalidHeaderName);
    // Empty Content-Length, as in HAProxy CVE-2023-40225.
    assert_eq!(err(&with(&["Content-Length:"])), Error::InvalidContentLength);
    assert_eq!(err(&with(&["Content-Length: "])), Error::InvalidContentLength);
}

// ---- Pipelining and split invariance -------------------------------------------------------

const BROWSER: &str = "GET /index.html?q=1 HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nConnection: keep-alive\r\nCookie: session=abc123; theme=dark\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\n\r\n";

fn valid_streams() -> Vec<Vec<u8>> {
    vec![
        CURL.as_bytes().to_vec(),
        BROWSER.as_bytes().to_vec(),
        format!("{CURL}{BROWSER}{CURL}").into_bytes(),
        b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello worldGET /b HTTP/1.1\r\nHost: h\r\n\r\n".to_vec(),
        b"\r\nPOST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=\"q\\\"t\"\r\nhello\r\n1A\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nX-Trailer: t\r\nY: z\r\n\r\nPOST /d HTTP/1.0\r\nContent-Length: 2\r\n\r\nhi".to_vec(),
        b"POST /e HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /f HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\n\r\n".to_vec(),
    ]
}

#[test]
fn pipelined_requests_parse_in_order() {
    let s = valid_streams()[4].clone();
    let evs = drive(&[&s], &lim());
    let heads: Vec<_> = evs.iter().filter_map(|e| if let Ev::Head(h) = e { Some(h.target.clone()) } else { None }).collect();
    assert_eq!(heads, [b"/c".to_vec(), b"/d".to_vec()]);
    assert!(evs.contains(&Ev::Body(b"helloabcdefghijklmnopqrstuvwxyz".to_vec())));
    assert!(evs.contains(&Ev::Trailers(b"X-Trailer: t\r\nY: z\r\n\r\n".to_vec())));
    assert_eq!(evs.last(), Some(&Ev::Body(b"hi".to_vec())));
}

#[test]
fn every_single_split_parses_the_same() {
    for s in valid_streams() {
        let whole = drive(&[&s], &lim());
        assert!(!whole.iter().any(|e| matches!(e, Ev::Error(_))), "{whole:?}");
        for k in 0..=s.len() {
            assert_eq!(drive_split(&s, &[k], &lim()), whole, "split at {k}");
        }
    }
}

#[test]
fn byte_by_byte_and_random_splits_parse_the_same() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for s in valid_streams() {
        let whole = drive(&[&s], &lim());
        let bytes: Vec<&[u8]> = s.chunks(1).collect();
        assert_eq!(drive(&bytes, &lim()), whole);
        for _ in 0..300 {
            let mut cuts: Vec<usize> = (0..rng.below(8) + 1).map(|_| rng.below(s.len() + 1)).collect();
            cuts.sort_unstable();
            assert_eq!(drive_split(&s, &cuts, &lim()), whole, "{cuts:?}");
        }
    }
}

#[test]
fn trickled_head_reports_limits_promptly() {
    // A request line with no LF is refused once it passes max_request_line, not max_head.
    let lim = lim();
    let mut parser = RequestParser::new();
    let mut buf = b"GET /".to_vec();
    let mut result = None;
    for _ in 0..1000 {
        buf.extend_from_slice(&[b'a'; 64]);
        let mut hs = [EMPTY_HEADER; 8];
        match parser.parse(&buf, &mut hs, &lim) {
            Ok(Status::Partial) => continue,
            other => {
                result = Some((other.map(|_| ()), buf.len()));
                break;
            }
        }
    }
    let (r, len) = result.unwrap();
    assert_eq!(r, Err(Error::RequestLineTooLong));
    assert!(len <= lim.max_request_line + 64, "{len}");
    // A header line likewise.
    let mut parser = RequestParser::new();
    let mut buf = b"GET / HTTP/1.1\r\nHost: h\r\nX: ".to_vec();
    loop {
        buf.extend_from_slice(&[b'v'; 100]);
        let mut hs = [EMPTY_HEADER; 8];
        match parser.parse(&buf, &mut hs, &lim) {
            Ok(Status::Partial) => assert!(buf.len() < lim.max_head),
            Err(e) => {
                assert_eq!(e, Error::HeaderLineTooLong);
                assert!(buf.len() < lim.max_header_line + 200);
                break;
            }
            Ok(Status::Complete(_)) => panic!(),
        }
    }
}

#[test]
fn request_parser_resets_after_each_head() {
    let mut p = RequestParser::new();
    let mut hs = [EMPTY_HEADER; 16];
    assert_eq!(p.parse(b"GET / HT", &mut hs, &lim()), Ok(Status::Partial));
    let r = p.parse(CURL.as_bytes(), &mut hs, &lim()).unwrap();
    assert!(matches!(r, Status::Complete(_)));
    // Fresh state: a new head in a new buffer parses from scratch.
    assert!(matches!(p.parse(BROWSER.as_bytes(), &mut hs, &lim()), Ok(Status::Complete(_))));
    assert_eq!(p.parse(b"GET / HT", &mut hs, &lim()), Ok(Status::Partial));
    p.reset();
    assert!(matches!(p.parse(CURL.as_bytes(), &mut hs, &lim()), Ok(Status::Complete(_))));
    // Errors are found when the head completes, even after quick partial checks.
    let mut p = RequestParser::new();
    assert_eq!(p.parse(b"GET / HTTP/1.1\r\nHo st", &mut hs, &lim()), Err(Error::WhitespaceBeforeColon));
    assert_eq!(p.parse(b"GET / HTTP/1.1\r\nHost: h\r\nX", &mut hs, &lim()), Ok(Status::Partial));
    assert_eq!(p.parse(b"GET / HTTP/1.1\r\nHost: h\r\nX\x01: 1\r\n\r\n", &mut hs, &lim()), Err(Error::InvalidHeaderName));
}

#[test]
fn simd_and_scalar_parse_identically() {
    use simoom_sys::scan::{force, level, Level};
    // Runs in its own process-wide setting; other tests only read results, which are the
    // same at every level, so switching is safe.
    let best = level();
    let streams = valid_streams();
    let results = |l: Level| {
        assert!(force(l));
        streams.iter().map(|s| drive(&[s], &lim())).collect::<Vec<_>>()
    };
    let simd = results(best);
    let scalar = results(Level::Scalar);
    force(best);
    assert_eq!(simd, scalar);
}

#[test]
fn short_version_with_empty_line_is_an_error_not_a_wait() {
    // Found by the differential fuzzer: "HTTP/" followed by CRLF CRLF was reported as partial.
    assert_eq!(err("POST / HTTP/\r\n\r\n"), Error::InvalidVersion);
    assert_eq!(err("GET / HTTP/1\r\n\r\n"), Error::InvalidVersion);
    assert_eq!(err("GET / HTTP/1.\r\n\r\n"), Error::InvalidVersion);
    assert_eq!(err("GET / HTTP/1.1\n\r\n"), Error::BareLf);
    partial("GET / HTTP/1.1\r");
    partial("GET / HTTP/1.");
}
