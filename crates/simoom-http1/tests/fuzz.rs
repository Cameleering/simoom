//! Std-only fuzzing: a seeded xorshift mutation fuzzer over every decoder, and a differential
//! test against the plain reference parser in `reference/`.
//!
//! A quick run happens by default. For a long run:
//!
//! ```text
//! SIMOOM_FUZZ_ITERS=2000000 SIMOOM_FUZZ_SEED=7 cargo test --release -p simoom-http1 --test fuzz
//! ```
//!
//! Checked on every input: no panic; bounded work (each decoder step consumes input or waits);
//! the same outcome however the input is split; SIMD and scalar scanning agree; the fast parser
//! and the reference parser agree on accept/reject, head length and every parsed field.

mod common;
mod reference;

use common::*;
use reference::RefResult;
use simoom_http1::*;

fn iters(default: usize) -> usize {
    std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn seed(salt: u64) -> u64 {
    let s: u64 = std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed);
    (s ^ salt.wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1
}

const INTERESTING: &[&[u8]] = &[
    b"\r\n", b"\r", b"\n", b" ", b"\t", b":", b";", b",", b"=", b"\"", b"\\", b"%", b"0", b"\x00", b"\x7f", b"\xff",
    b"\r\n\r\n", b"chunked", b"Content-Length: ", b"Transfer-Encoding: ", b"Host: h\r\n", b"\r\n ", b"ffffffff",
    b"HTTP/1.1", b"100-continue", b"Connection: close\r\n", b"Upgrade: websocket\r\n",
];

/// Applies 1 to 4 random edits.
fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..rng.below(4) + 1 {
        let at = rng.below(v.len() + 1);
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 if !v.is_empty() => {
                let n = rng.below(4) + 1;
                let end = (at + n).min(v.len());
                v.drain(at.min(end)..end);
            }
            3 => {
                let s = *rng.pick(INTERESTING);
                v.splice(at..at, s.iter().copied());
            }
            4 if !v.is_empty() => {
                // Duplicate a span (repeats headers, chunks, lines).
                let a = rng.below(v.len());
                let b = (a + rng.below(40) + 1).min(v.len());
                let span = v[a..b].to_vec();
                v.splice(at..at, span);
            }
            5 => {
                let s = *rng.pick(INTERESTING);
                let end = (at + s.len()).min(v.len());
                v.splice(at..end, s.iter().copied());
            }
            _ => v.truncate(at),
        }
    }
    v
}

fn random_cuts(rng: &mut Rng, len: usize) -> Vec<usize> {
    if rng.chance(8) {
        return (1..len).collect();
    }
    let mut c: Vec<usize> = (0..rng.below(6) + 1).map(|_| rng.below(len + 1)).collect();
    c.sort_unstable();
    c
}

/// Errors compare by presence only: the kind may legitimately depend on where input stops.
fn normalize(evs: Vec<Ev>) -> Vec<Ev> {
    evs.into_iter().map(|e| if let Ev::Error(_) = e { Ev::Error(Error::BareCr) } else { e }).collect()
}

/// Split results must match the whole result, except that a split run may still be waiting
/// where the whole run already found an error in an incomplete head (errors are reported once a
/// head is complete or a limit is passed, so that trickled input is not parsed repeatedly).
fn check_split(whole: &[Ev], split: &[Ev], input: &[u8], cuts: &[usize]) {
    if whole == split {
        return;
    }
    let ok = matches!(whole.last(), Some(Ev::Error(_))) && split == &whole[..whole.len() - 1];
    assert!(ok, "split mismatch\ninput {:?}\ncuts {cuts:?}\nwhole {whole:?}\nsplit {split:?}", String::from_utf8_lossy(input));
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n".to_vec(),
        b"POST /a?b=c HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhelloGET / HTTP/1.1\r\nHost: h\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5;a=\"b\"\r\nhello\r\n0\r\nT: 1\r\n\r\nGET / HTTP/1.0\r\n\r\n".to_vec(),
        b"\r\nOPTIONS * HTTP/1.1\r\nHost: [::1]:80\r\nConnection: Upgrade, keep-alive\r\nUpgrade: websocket\r\n\r\n".to_vec(),
        b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\nGET http://x/y HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]
}

#[test]
fn fuzz_request_stream_split_invariance() {
    let mut rng = Rng(seed(1));
    let lims = [Limits::default(), Limits { max_head: 120, max_headers: 4, max_header_line: 48, max_request_line: 40, max_body: 64, max_chunk_line: 12, max_trailers: 16 }];
    let seeds = seeds();
    for i in 0..iters(4000) {
        let input = mutate(&mut rng, &seeds[i % seeds.len()]);
        let lim = &lims[i % 2];
        let whole = normalize(drive(&[&input], lim));
        let cuts = random_cuts(&mut rng, input.len());
        let split = normalize(drive_split(&input, &cuts, lim));
        check_split(&whole, &split, &input, &cuts);
    }
}

#[test]
fn fuzz_chunked_decoder() {
    let mut rng = Rng(seed(2));
    let base: &[&[u8]] = &[
        b"5\r\nhello\r\n1a;x=y\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nA: b\r\n\r\n",
        b"3;q=\"a\\\"b\"\r\nabc\r\n0\r\n\r\n",
        b"0000001\r\nx\r\nFFFF\r\n",
    ];
    let lim = Limits { max_body: 1 << 16, max_chunk_line: 32, max_trailers: 64, ..Limits::default() };
    for i in 0..iters(20000) {
        let input = mutate(&mut rng, base[i % base.len()]);
        let run = |cuts: &[usize]| -> (Result<(), Error>, Vec<u8>, Option<Vec<u8>>, usize) {
            let mut d = BodyDecoder::new(Framing::Chunked, &lim);
            let (mut data, mut buf, mut used, mut fed) = (Vec::new(), Vec::new(), 0usize, 0usize);
            let mut steps = 0;
            for &b in cuts.iter().chain(std::iter::once(&input.len())) {
                buf.extend_from_slice(&input[fed..b]);
                fed = b;
                loop {
                    steps += 1;
                    assert!(steps <= 2 * input.len() + cuts.len() + 4, "unbounded work");
                    match d.decode(&buf) {
                        Err(e) => return (Err(e), data, None, used),
                        Ok((n, ev)) => {
                            let mut wait = false;
                            match ev {
                                BodyEvent::Data(x) => data.extend_from_slice(x),
                                BodyEvent::End(t) => return (Ok(()), data, Some(t.to_vec()), used + n),
                                BodyEvent::NeedMore => wait = true,
                            }
                            used += n;
                            buf.drain(..n);
                            if wait {
                                break;
                            }
                        }
                    }
                }
            }
            (Ok(()), data, None, used)
        };
        let (r1, d1, t1, u1) = run(&[]);
        let cuts = random_cuts(&mut rng, input.len());
        let (r2, d2, t2, u2) = run(&cuts);
        assert_eq!(r1.is_ok(), r2.is_ok(), "{:?} {cuts:?}", String::from_utf8_lossy(&input));
        if r1.is_ok() {
            // Chunk-line errors are reported byte by byte, trailer errors when the section is
            // whole, so successful runs must agree exactly.
            assert_eq!((d1, t1, u1), (d2, t2, u2));
        }
    }
}

#[test]
fn fuzz_response_parser() {
    let mut rng = Rng(seed(3));
    let base: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
        b"HTTP/1.0 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
    ];
    for i in 0..iters(20000) {
        let input = mutate(&mut rng, base[i % base.len()]);
        let mut hs = [EMPTY_HEADER; 32];
        let m: &[u8] = if i % 5 == 0 { b"HEAD" } else { b"GET" };
        if let Ok(Status::Complete(r)) = parse_response(&input, &mut hs, &Limits::default(), m) {
            assert!(r.head_len <= input.len() && (100..=599).contains(&r.status));
            // Every proper prefix of a complete head is incomplete, never an error.
            let k = rng.below(r.head_len);
            let mut hs2 = [EMPTY_HEADER; 32];
            assert_eq!(parse_response(&input[..k], &mut hs2, &Limits::default(), m), Ok(Status::Partial));
        }
    }
}

#[cfg(feature = "websocket")]
#[test]
fn fuzz_websocket_decoder() {
    use simoom_http1::ws::*;
    let mut rng = Rng(seed(4));
    let mut base = Vec::new();
    write_frame(&mut base, false, Opcode::Text, "héllo ".as_bytes(), Some([1, 2, 3, 4]));
    write_frame(&mut base, true, Opcode::Ping, b"p", Some([5, 6, 7, 8]));
    write_frame(&mut base, true, Opcode::Continuation, b"world", Some([9, 10, 11, 12]));
    write_frame(&mut base, true, Opcode::Binary, &[0u8; 200], Some([0, 0, 0, 1]));
    write_close(&mut base, 1000, "bye", Some([7, 7, 7, 7]));
    let lim = WsLimits { max_frame: 4096, max_message: 8192 };
    for _ in 0..iters(20000) {
        let input = mutate(&mut rng, &base);
        let run = |cuts: &[usize]| -> (bool, Vec<u8>) {
            let mut d = FrameDecoder::new(Role::Server, lim);
            let (mut buf, mut fed, mut payload, mut steps) = (Vec::new(), 0, Vec::new(), 0);
            for &b in cuts.iter().chain(std::iter::once(&input.len())) {
                buf.extend_from_slice(&input[fed..b]);
                fed = b;
                loop {
                    steps += 1;
                    assert!(steps <= 2 * input.len() + cuts.len() + 4, "unbounded work");
                    match d.decode(&mut buf) {
                        Err(_) => return (false, payload),
                        Ok((n, ev)) => {
                            let wait = matches!(ev, WsEvent::NeedMore);
                            match ev {
                                WsEvent::Data { payload: p, .. } | WsEvent::Ping(p) | WsEvent::Pong(p) => payload.extend_from_slice(p),
                                WsEvent::Close { reason, .. } => payload.extend_from_slice(reason.as_bytes()),
                                WsEvent::NeedMore => {}
                            }
                            buf.drain(..n);
                            if wait {
                                break;
                            }
                        }
                    }
                }
            }
            (true, payload)
        };
        let a = run(&[]);
        let cuts = random_cuts(&mut rng, input.len());
        let b = run(&cuts);
        if a.0 && b.0 {
            assert_eq!(a.1, b.1);
        } else {
            // A split run can fail later than a whole one only by the bytes it has not seen yet:
            // its payload is a prefix of the whole run's.
            let (short, long) = if a.1.len() <= b.1.len() { (&a.1, &b.1) } else { (&b.1, &a.1) };
            assert_eq!(&long[..short.len()], &short[..]);
        }
    }
}

// ---- Differential: fast parser against the reference parser ------------------------------

// Each list starts with its valid entries; `pick_biased` prefers them so that a good share of
// generated requests is accepted and the rest fail in one place.
const METHODS: (&[&str], usize) = (&["GET", "POST", "PUT", "OPTIONS", "CONNECT", "M-SEARCH", "get", "G T", "GE(T", ""], 4);
const TARGETS: (&[&str], usize) = (
    &[
        "/", "/a/b?c=d&e", "/%41%2f", "http://h/x", "//", "/?", "http://u@h:1/p?q", "http://[::1]:8/", "*", "/%4",
        "/%zz", "/[x]", "h:80", "example.com:443", "/a#f", "/a b", "/\u{7f}", "/\u{e9}", "[::1]:443", "a@b:1",
        "http://h/[x]", "x",
    ],
    7,
);
const VERSIONS: (&[&str], usize) = (&["HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/1.1 ", "http/1.1", "HTTP/1.x"], 2);
const NAMES: (&[&str], usize) = (
    &[
        "X-A", "Accept", "Connection", "Content-Length", "Transfer-Encoding", "Expect", "Upgrade", "Host", "HOST",
        "transfer-encoding", "Bad Name", "", "X\u{0}", "Host ", "Content-Length\t",
    ],
    7,
);
const VALUES: (&[&str], usize) = (
    &[
        "a", " a ", "5", "0", "05", "chunked", "Chunked", "close", "keep-alive", "upgrade, keep-alive", "100-continue",
        "websocket", "h", "localhost", "*/*", "x\ty", "\u{80}\u{ff}", "", "+5", "5,5", "5, 6", "99999999999999999999",
        "gzip, chunked", "chunked, gzip", "chunked,", "Upgrade", "100-continuex", "h:80", "[::1]:8080", "a b",
        "\u{1}", "a\rb", "a\nb", "h@x",
    ],
    17,
);

fn pick_biased(rng: &mut Rng, (items, good): (&[&'static str], usize)) -> &'static str {
    if rng.below(10) < 8 {
        items[rng.below(good)]
    } else {
        items[rng.below(items.len())]
    }
}

fn generate(rng: &mut Rng) -> Vec<u8> {
    let mut s = Vec::new();
    for _ in 0..(if rng.chance(6) { rng.below(3) } else { 0 }) {
        s.extend_from_slice(b"\r\n");
    }
    let eol = |rng: &mut Rng| -> &'static [u8] {
        if rng.chance(40) {
            rng.pick(&[&b"\n"[..], b"\r", b" \r\n", b"\r\r\n"])
        } else {
            b"\r\n"
        }
    };
    s.extend_from_slice(pick_biased(rng, METHODS).as_bytes());
    s.push(b' ');
    s.extend_from_slice(pick_biased(rng, TARGETS).as_bytes());
    s.push(b' ');
    s.extend_from_slice(pick_biased(rng, VERSIONS).as_bytes());
    s.extend_from_slice(eol(rng));
    if rng.below(10) < 8 {
        s.extend_from_slice(b"Host: h\r\n");
    }
    for _ in 0..rng.below(6) {
        if rng.chance(40) {
            s.push(*rng.pick(b" \t"));
        }
        s.extend_from_slice(pick_biased(rng, NAMES).as_bytes());
        s.push(b':');
        if rng.chance(2) {
            s.push(b' ');
        }
        s.extend_from_slice(pick_biased(rng, VALUES).as_bytes());
        s.extend_from_slice(eol(rng));
    }
    s.extend_from_slice(b"\r\n");
    if rng.chance(6) {
        s = mutate(rng, &s);
    }
    s
}

fn compare(input: &[u8], lim: &Limits) {
    let fast = parse_with(input, lim);
    let slow = reference::parse(input, lim);
    let show = || String::from_utf8_lossy(input).into_owned();
    match (&fast, &slow) {
        (Ok(Some(f)), RefResult::Complete(r)) => {
            assert_eq!(
                (&f.method, &f.target, f.form, f.version, &f.headers, f.framing, f.keep_alive, f.expect, &f.upgrade, &f.host, f.head_len),
                (&r.method, &r.target, r.form, r.version, &r.headers, r.framing, r.keep_alive, r.expect, &r.upgrade, &r.host, r.head_len),
                "{:?}",
                show()
            );
        }
        (Err(_), RefResult::Rejected(_)) => {}
        (Ok(None) | Err(_), RefResult::Incomplete) => {}
        _ => panic!("fast {fast:?} vs reference {slow:?} on {:?}", show()),
    }
}

#[test]
fn differential_against_reference_parser() {
    let mut rng = Rng(seed(5));
    let lims = [
        Limits::default(),
        Limits { max_head: 90, max_headers: 3, max_header_line: 30, max_request_line: 30, max_body: 5, ..Limits::default() },
    ];
    let mut accepted = 0;
    let n = iters(30000);
    for i in 0..n {
        let input = generate(&mut rng);
        let lim = &lims[usize::from(i % 3 == 0)];
        compare(&input, lim);
        if let Ok(Some(_)) = parse_with(&input, lim) {
            accepted += 1;
        }
    }
    // The generator must exercise both sides of the decision.
    assert!(accepted > n / 50 && accepted < n - n / 50, "accepted {accepted} of {n}");
}

#[test]
fn differential_on_mutated_valid_requests() {
    let mut rng = Rng(seed(6));
    let seeds = seeds();
    for i in 0..iters(30000) {
        let input = mutate(&mut rng, &seeds[i % seeds.len()]);
        compare(&input, &Limits::default());
    }
}

#[test]
fn simd_and_scalar_agree_on_fuzz_inputs() {
    use simoom_sys::scan::{force, level, Level};
    let best = level();
    let mut rng = Rng(seed(7));
    let seeds = seeds();
    // Inputs are compared in batches so a long run (SIMOOM_FUZZ_ITERS in the millions) keeps
    // memory flat instead of holding every input at once.
    let total = iters(5000);
    let mut i = 0;
    while i < total {
        let n = (total - i).min(4096);
        let inputs: Vec<Vec<u8>> = (i..i + n)
            .map(|i| if i % 2 == 0 { generate(&mut rng) } else { mutate(&mut rng, &seeds[i % seeds.len()]) })
            .collect();
        let run = |l: Level| {
            assert!(force(l));
            inputs.iter().map(|x| (parse_with(x, &Limits::default()), drive(&[x], &Limits::default()))).collect::<Vec<_>>()
        };
        let a = run(best);
        let b = run(Level::Scalar);
        force(best);
        assert_eq!(a, b);
        i += n;
    }
}

/// Coverage-guided fuzzing (plan §7.3 F2, std-only): SanitizerCoverage edge counters from
/// `simoom_sys::sancov` decide which mutated inputs join the corpus. Every input goes through the
/// split-invariance check and the differential comparison with the reference parser.
///
/// ```text
/// RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 \
///   -C llvm-args=-sanitizer-coverage-trace-pc-guard" SIMOOM_FUZZ_SECS=600 \
///   cargo test --release -p simoom-http1 --features sancov --test fuzz coverage_guided -- --nocapture
/// ```
///
/// Linux only (the MSVC back end rejects the instrumented COMDATs). Without the RUSTFLAGS the
/// map stays empty and the test says so and returns.
#[cfg(feature = "sancov")]
#[test]
fn coverage_guided() {
    use simoom_sys::sancov;
    let secs: u64 = std::env::var("SIMOOM_FUZZ_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let lims = [Limits::default(), Limits { max_head: 120, max_headers: 4, max_header_line: 48, max_request_line: 40, max_body: 64, max_chunk_line: 12, max_trailers: 16 }];
    // AFL-style hit-count buckets, so loop counts matter a little but not every iteration.
    fn bucket(n: u8) -> u8 {
        match n {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            _ => 128,
        }
    }
    let run = |input: &[u8], rng: &mut Rng| {
        for lim in &lims {
            let whole = normalize(drive(&[input], lim));
            let cuts = random_cuts(rng, input.len());
            let split = normalize(drive_split(input, &cuts, lim));
            check_split(&whole, &split, input, &cuts);
        }
        compare(input, &Limits::default());
    };
    let mut rng = Rng(seed(99));
    let mut virgin = vec![0u8; sancov::MAP_SIZE];
    let mut snap = Vec::new();
    let mut corpus: Vec<Vec<u8>> = seeds();
    corpus.extend((0..50).map(|_| generate(&mut rng)));
    let mut novel = |input: &[u8], rng: &mut Rng, virgin: &mut Vec<u8>| -> bool {
        sancov::reset();
        run(input, rng);
        sancov::snapshot(&mut snap);
        let mut new = false;
        for (v, &s) in virgin.iter_mut().zip(snap.iter()) {
            let b = bucket(s);
            if b & !*v != 0 {
                *v |= b;
                new = true;
            }
        }
        new
    };
    for c in corpus.clone() {
        novel(&c, &mut rng, &mut virgin);
    }
    if sancov::guards() == 0 {
        eprintln!("coverage_guided: build not instrumented (set the RUSTFLAGS in the doc comment); skipped");
        return;
    }
    let start = std::time::Instant::now();
    let mut execs = 0u64;
    while start.elapsed().as_secs() < secs {
        let parent = corpus[rng.below(corpus.len())].clone();
        let mut child = mutate(&mut rng, &parent);
        if rng.chance(4) {
            // splice with another corpus entry
            let other = &corpus[rng.below(corpus.len())];
            let at = rng.below(child.len() + 1);
            let from = rng.below(other.len() + 1);
            child.truncate(at);
            child.extend_from_slice(&other[from..]);
        }
        child.truncate(4096);
        execs += 1;
        if novel(&child, &mut rng, &mut virgin) {
            corpus.push(child);
        }
    }
    let edges = virgin.iter().filter(|&&v| v != 0).count();
    eprintln!("coverage_guided: {execs} execs in {secs} s, corpus {}, edges {edges} of {} guards", corpus.len(), sancov::guards());
}
