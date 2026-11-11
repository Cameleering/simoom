//! HTTP/2 client streams: simoom-h2's client role behind [`Proto`].

use crate::error::{Error, ErrorKind, Result};
use crate::mux::{MuxEvent, MuxIo, Proto, ReqHead};
use crate::types::{Headers, Version};
use simoom_h2::{Config, Connection, ErrorCode, Event};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Received DATA not yet read by the application (still charged to the flow-control windows).
#[derive(Default)]
struct Buf {
    data: Vec<u8>,
    pos: usize,
}

pub(crate) struct H2Proto {
    conn: Connection,
    inbuf: Vec<u8>,
    bufs: HashMap<u32, Buf>,
    epoch: Instant,
    goaway: bool,
    closed: bool,
    settings: bool,
    what: String,
}

impl H2Proto {
    /// A client connection (prior knowledge or after ALPN `h2`); the preface and SETTINGS are
    /// queued.
    pub(crate) fn new(cfg: Config, what: String) -> H2Proto {
        H2Proto { conn: Connection::client(cfg), inbuf: Vec::new(), bufs: HashMap::new(), epoch: Instant::now(), goaway: false, closed: false, settings: false, what }
    }

    /// After a `101` to an HTTP/1.1 `Upgrade: h2c` request: that request is stream 1.
    #[cfg(feature = "h2c-upgrade")]
    pub(crate) fn upgraded(cfg: Config, what: String) -> H2Proto {
        let mut p = H2Proto::new(cfg.clone(), what);
        p.conn = Connection::client_upgrade(cfg, false);
        p.bufs.insert(1, Buf::default());
        p
    }

    fn now_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_millis() as u64
    }

    fn map_err(&mut self, e: simoom_h2::Error) -> Error {
        match e {
            simoom_h2::Error::GoingAway | simoom_h2::Error::StreamIdsExhausted => {
                self.goaway = true;
                Error::new(ErrorKind::Closed, format!("HTTP/2 connection is going away: {}", self.what))
            }
            simoom_h2::Error::ConnectionClosed => {
                self.closed = true;
                Error::new(ErrorKind::Closed, format!("HTTP/2 connection closed: {}", self.what))
            }
            simoom_h2::Error::InvalidHeader => Error::new(ErrorKind::InvalidRequest, format!("header not allowed in HTTP/2: {}", self.what)),
            simoom_h2::Error::HeaderListTooLarge => Error::new(ErrorKind::InvalidRequest, format!("request header list larger than the server allows: {}", self.what)),
            simoom_h2::Error::StreamReset | simoom_h2::Error::UnknownStream | simoom_h2::Error::StreamClosed => {
                Error::new(ErrorKind::Reset(0), format!("stream closed: {}", self.what))
            }
            other => Error::protocol(format!("HTTP/2 ({other})"), &self.what),
        }
    }

    fn pump(&mut self, now: Instant, ev: &mut Vec<MuxEvent>) -> usize {
        let ms = self.now_ms(now);
        let bufs = &mut self.bufs;
        let mut goaway = false;
        let mut settings = false;
        let mut closed = None;
        let mut release: Vec<(u32, usize)> = Vec::new();
        let what = &self.what;
        let used = self.conn.recv(&self.inbuf, ms, &mut |e| match e {
            Event::Headers { stream, headers, end_stream } => {
                let id = stream as u64;
                let status = headers.status().unwrap_or(0);
                if (100..200).contains(&status) && !end_stream {
                    return;
                }
                let mut h = Headers::new();
                for (n, v) in headers.iter() {
                    h.push_raw(n, v);
                }
                ev.push(MuxEvent::Head { id, status, headers: h });
                if end_stream {
                    ev.push(MuxEvent::End(id));
                }
            }
            Event::Data { stream, data, end_stream } => {
                match bufs.get_mut(&stream) {
                    Some(b) => {
                        if !data.is_empty() {
                            b.data.extend_from_slice(data);
                            ev.push(MuxEvent::Readable(stream as u64));
                        }
                    }
                    None => release.push((stream, data.len())),
                }
                if end_stream {
                    ev.push(MuxEvent::End(stream as u64));
                }
            }
            Event::Trailers { stream, trailers } => {
                let mut h = Headers::new();
                for (n, v) in trailers.iter() {
                    h.push_raw(n, v);
                }
                ev.push(MuxEvent::Trailers { id: stream as u64, trailers: h });
                ev.push(MuxEvent::End(stream as u64));
            }
            Event::Reset { stream, code, .. } => ev.push(MuxEvent::Reset { id: stream as u64, code: code.0 as u64 }),
            Event::Pong { .. } => ev.push(MuxEvent::Pong),
            Event::GoAway { code, .. } => {
                goaway = true;
                if code != ErrorCode::NO_ERROR {
                    closed = Some(Error::new(ErrorKind::Protocol, format!("HTTP/2 GOAWAY {}: {what}", code.name())));
                }
                ev.push(MuxEvent::GoAway);
            }
            Event::Closed { code } => {
                closed = Some(Error::new(ErrorKind::Protocol, format!("HTTP/2 connection error {}: {what}", code.name())));
            }
            Event::Settings => settings = true,
        });
        if settings {
            self.settings = true;
        }
        for (s, n) in release {
            self.conn.release(s, n);
        }
        if goaway {
            self.goaway = true;
        }
        if let Some(e) = closed {
            self.closed = true;
            ev.push(MuxEvent::Closed(e));
        }
        while let Some(id) = self.conn.poll_writable() {
            ev.push(MuxEvent::Writable(id as u64));
        }
        used
    }

    fn write_out(&mut self, io: &MuxIo) -> io::Result<()> {
        let out = self.conn.output();
        if out.is_empty() {
            return Ok(());
        }
        let n = out.len();
        match io.duplex() {
            Some(d) => d.write_all(out)?,
            None => return Err(io::Error::new(io::ErrorKind::Unsupported, "HTTP/2 needs a stream transport")),
        }
        self.conn.advance_output(n);
        Ok(())
    }
}

impl Proto for H2Proto {
    fn version(&self) -> Version {
        Version::Http2
    }

    fn open(&mut self, head: &ReqHead<'_>, end: bool) -> Result<u64> {
        let fields: Vec<(&[u8], &[u8])> = head.fields.iter().map(|(n, v)| (&n[..], &v[..])).collect();
        let r = self.conn.send_request(head.method.as_bytes(), head.scheme.as_bytes(), head.authority.as_bytes(), head.path.as_bytes(), &fields, end);
        match r {
            Ok(id) => {
                self.bufs.insert(id, Buf::default());
                Ok(id as u64)
            }
            Err(e) => Err(self.map_err(e)),
        }
    }

    fn open_extended(&mut self, protocol: &str, head: &ReqHead<'_>) -> Result<u64> {
        let fields: Vec<(&[u8], &[u8])> = head.fields.iter().map(|(n, v)| (&n[..], &v[..])).collect();
        match self.conn.send_extended_connect(protocol.as_bytes(), head.scheme.as_bytes(), head.authority.as_bytes(), head.path.as_bytes(), &fields) {
            Ok(id) => {
                self.bufs.insert(id, Buf::default());
                Ok(id as u64)
            }
            Err(e) => Err(self.map_err(e)),
        }
    }

    fn extended_connect(&self) -> Option<bool> {
        if self.settings {
            Some(self.conn.peer_connect_protocol())
        } else {
            None
        }
    }

    fn send_data(&mut self, id: u64, data: &[u8], end: bool) -> Result<usize> {
        self.conn.send_data(id as u32, data, end).map_err(|e| self.map_err(e))
    }

    fn capacity(&self, id: u64) -> usize {
        self.conn.send_capacity(id as u32)
    }

    fn send_trailers(&mut self, id: u64, trailers: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let f: Vec<(&[u8], &[u8])> = trailers.iter().map(|(n, v)| (&n[..], &v[..])).collect();
        self.conn.send_trailers(id as u32, &f).map_err(|e| self.map_err(e))
    }

    fn cancel(&mut self, id: u64) {
        let s = id as u32;
        if let Some(b) = self.bufs.remove(&s) {
            self.conn.release(s, b.data.len() - b.pos);
        }
        self.conn.reset(s, ErrorCode::CANCEL);
    }

    fn forget(&mut self, id: u64) {
        let s = id as u32;
        if let Some(b) = self.bufs.remove(&s) {
            self.conn.release(s, b.data.len() - b.pos);
        }
        // A request side we never ended is closed here (RST_STREAM), so the stream stops
        // counting against the peer's concurrency limit.
        self.conn.stream_finished(s);
    }

    fn take_body(&mut self, id: u64, out: &mut Vec<u8>, max: usize, _now: Instant, _ev: &mut Vec<MuxEvent>) -> usize {
        let Some(b) = self.bufs.get_mut(&(id as u32)) else { return 0 };
        let n = (b.data.len() - b.pos).min(max);
        out.extend_from_slice(&b.data[b.pos..b.pos + n]);
        b.pos += n;
        if b.pos == b.data.len() {
            b.data.clear();
            b.pos = 0;
        }
        n
    }

    fn release(&mut self, id: u64, n: usize) {
        self.conn.release(id as u32, n);
    }

    fn input(&mut self, data: &mut [u8], _from: Option<SocketAddr>, now: Instant, io: &MuxIo, ev: &mut Vec<MuxEvent>) {
        self.inbuf.extend_from_slice(data);
        loop {
            let used = self.pump(now, ev);
            self.inbuf.drain(..used);
            if self.inbuf.is_empty() {
                break;
            }
            if used == 0 {
                // Input paused while output waits: write it, then go on.
                let before = self.conn.output().len();
                if before == 0 {
                    break;
                }
                if let Err(e) = self.write_out(io) {
                    self.closed = true;
                    ev.push(MuxEvent::Closed(Error::io(&e, &self.what)));
                    break;
                }
            }
        }
    }

    fn flush(&mut self, io: &MuxIo, _now: Instant) -> io::Result<()> {
        self.write_out(io)
    }

    fn buffered(&self, id: u64) -> Option<usize> {
        Some(self.bufs.get(&(id as u32)).map_or(0, |b| b.data.len() - b.pos))
    }

    fn take_output(&mut self, out: &mut Vec<u8>) {
        let o = self.conn.output();
        if !o.is_empty() {
            let n = o.len();
            out.extend_from_slice(o);
            self.conn.advance_output(n);
        }
    }

    fn deadline(&mut self) -> Option<Instant> {
        self.conn.poll_timeout().map(|ms| self.epoch + Duration::from_millis(ms))
    }

    fn timeout(&mut self, now: Instant, ev: &mut Vec<MuxEvent>) {
        let ms = self.now_ms(now);
        let what = self.what.clone();
        let mut closed = false;
        self.conn.handle_timeout(ms, &mut |e| {
            if let Event::Closed { code } = e {
                closed = true;
                ev.push(MuxEvent::Closed(Error::new(ErrorKind::Protocol, format!("HTTP/2 connection error {}: {what}", code.name()))));
            }
        });
        if closed {
            self.closed = true;
        }
    }

    fn ping(&mut self) -> bool {
        self.conn.ping(*b"simoomka");
        true
    }

    fn can_open(&self) -> bool {
        self.conn.can_open_stream()
    }

    fn max_streams(&self) -> usize {
        self.conn.peer_max_concurrent_streams() as usize
    }

    fn is_done(&self) -> bool {
        self.goaway || self.closed || self.conn.close_code().is_some() || self.conn.wants_close()
    }

    fn close(&mut self, now: Instant) {
        self.conn.shutdown(self.now_ms(now));
    }
}
