//! Shared test helpers: owned copies of parse results, a connection-like driver over pieces of
//! input, and a seeded xorshift generator.
#![allow(dead_code)]

use simoom_http1::*;

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    pub fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Req {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub form: TargetForm,
    pub version: Version,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub framing: Framing,
    pub keep_alive: bool,
    pub expect: bool,
    pub upgrade: Option<Vec<u8>>,
    pub host: Option<Vec<u8>>,
    pub head_len: usize,
}

pub fn own(r: &Request<'_, '_>) -> Req {
    Req {
        method: r.method.to_vec(),
        target: r.target.to_vec(),
        form: r.form,
        version: r.version,
        headers: r.headers.iter().map(|h| (h.name.to_vec(), h.value.to_vec())).collect(),
        framing: r.framing,
        keep_alive: r.keep_alive,
        expect: r.expect_continue,
        upgrade: r.upgrade.map(<[u8]>::to_vec),
        host: r.host.map(<[u8]>::to_vec),
        head_len: r.head_len,
    }
}

/// Parses one request head with a fresh header array.
pub fn parse_with(s: &[u8], lim: &Limits) -> Result<Option<Req>, Error> {
    let mut hs = [EMPTY_HEADER; 128];
    match parse_request(s, &mut hs, lim)? {
        Status::Complete(r) => Ok(Some(own(&r))),
        Status::Partial => Ok(None),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    Head(Req),
    Body(Vec<u8>),
    Trailers(Vec<u8>),
    Error(Error),
}

/// Feeds `pieces` to a server-like loop (RequestParser, then BodyDecoder, repeatedly) and
/// returns what it saw. Asserts that the work is bounded: every step either consumes input or
/// waits for more.
pub fn drive(pieces: &[&[u8]], lim: &Limits) -> Vec<Ev> {
    let total: usize = pieces.iter().map(|p| p.len()).sum();
    let mut buf: Vec<u8> = Vec::new();
    let mut evs = Vec::new();
    let mut parser = RequestParser::new();
    let mut body: Option<(BodyDecoder, Vec<u8>)> = None;
    let mut steps = 0usize;
    for piece in pieces {
        buf.extend_from_slice(piece);
        loop {
            steps += 1;
            assert!(steps <= 4 * total + 4 * pieces.len() + 16, "unbounded work");
            if let Some((dec, acc)) = &mut body {
                let (n, ev) = match dec.decode(&buf) {
                    Ok(x) => x,
                    Err(e) => {
                        evs.push(Ev::Error(e));
                        return evs;
                    }
                };
                let mut wait = false;
                match ev {
                    BodyEvent::Data(d) => {
                        assert!(!d.is_empty());
                        acc.extend_from_slice(d)
                    }
                    BodyEvent::End(t) => {
                        let t = t.to_vec();
                        evs.push(Ev::Body(std::mem::take(acc)));
                        if !t.is_empty() {
                            evs.push(Ev::Trailers(t));
                        }
                        body = None;
                    }
                    BodyEvent::NeedMore => wait = true,
                }
                buf.drain(..n);
                if wait {
                    break;
                }
            } else {
                let mut hs = [EMPTY_HEADER; 128];
                match parser.parse(&buf, &mut hs, lim) {
                    Err(e) => {
                        evs.push(Ev::Error(e));
                        return evs;
                    }
                    Ok(Status::Partial) => break,
                    Ok(Status::Complete(r)) => {
                        let (n, f) = (r.head_len, r.framing);
                        evs.push(Ev::Head(own(&r)));
                        buf.drain(..n);
                        body = Some((BodyDecoder::new(f, lim), Vec::new()));
                    }
                }
            }
        }
    }
    evs
}

/// `drive` with `s` cut at the given offsets.
pub fn drive_split(s: &[u8], cuts: &[usize], lim: &Limits) -> Vec<Ev> {
    let mut pieces = Vec::new();
    let mut last = 0;
    for &c in cuts {
        pieces.push(&s[last..c]);
        last = c;
    }
    pieces.push(&s[last..]);
    drive(&pieces, lim)
}
