//! HTTP/3 client streams: simoom-quic's client endpoint and simoom-h3 behind [`Proto`].

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::mux::{Mux, MuxEvent, MuxIo, Proto, ReqHead};
use crate::types::{Headers, Version};
use simoom_h3::{H3Event, Http3, SendError};
use simoom_quic::tls::TlsProvider;
use simoom_quic::{ConnHandle, Endpoint, Event};
use simoom_tls::ClientConfig;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct H3Proto {
    ep: Endpoint,
    h: ConnHandle,
    h3: Http3,
    tx: Vec<u8>,
    resp: Vec<u8>,
    goaway: bool,
    closed: bool,
    what: String,
}

fn send_err(e: SendError, what: &str) -> Error {
    match e {
        SendError::GoingAway => Error::new(ErrorKind::Closed, format!("HTTP/3 connection is going away: {what}")),
        SendError::HeadersTooLarge => Error::new(ErrorKind::InvalidRequest, format!("request header list larger than the server allows: {what}")),
        SendError::UnknownStream => Error::new(ErrorKind::Closed, format!("HTTP/3 stream closed: {what}")),
        other => Error::protocol(format!("HTTP/3 ({other:?})"), what),
    }
}

impl H3Proto {
    fn process(&mut self, now: Instant, ev: &mut Vec<MuxEvent>) {
        while let Some(e) = self.ep.poll_event(self.h) {
            if let Event::Closed(err) = &e {
                if !self.closed {
                    self.closed = true;
                    ev.push(MuxEvent::Closed(Error::new(ErrorKind::Closed, format!("QUIC connection closed ({err:?}): {}", self.what))));
                }
            }
            if let Some(q) = self.ep.conn_mut(self.h) {
                self.h3.handle(now, q, &e);
            }
        }
        self.events(ev);
    }

    fn events(&mut self, ev: &mut Vec<MuxEvent>) {
        while let Some(e) = self.h3.poll_event() {
            match e {
                H3Event::Headers { stream, fields } => {
                    let mut status = 0u16;
                    let mut h = Headers::new();
                    for f in &fields {
                        if f.name == b":status" {
                            status = std::str::from_utf8(&f.value).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
                        } else if !f.name.starts_with(b":") {
                            h.push_raw(&f.name, &f.value);
                        }
                    }
                    if !(100..200).contains(&status) {
                        ev.push(MuxEvent::Head { id: stream, status, headers: h });
                    }
                }
                H3Event::Data { stream } => ev.push(MuxEvent::Readable(stream)),
                H3Event::Trailers { stream, fields } => {
                    let mut h = Headers::new();
                    for f in &fields {
                        h.push_raw(&f.name, &f.value);
                    }
                    ev.push(MuxEvent::Trailers { id: stream, trailers: h });
                }
                H3Event::Finished { stream } => ev.push(MuxEvent::End(stream)),
                H3Event::Reset { stream, code } => ev.push(MuxEvent::Reset { id: stream, code }),
                H3Event::Writable { stream } => ev.push(MuxEvent::Writable(stream)),
                H3Event::GoAway { .. } => {
                    self.goaway = true;
                    ev.push(MuxEvent::GoAway);
                }
                H3Event::Error(e) => {
                    self.closed = true;
                    ev.push(MuxEvent::Closed(Error::protocol(format!("HTTP/3 error {e}"), &self.what)));
                }
            }
        }
    }
}

impl Proto for H3Proto {
    fn version(&self) -> Version {
        Version::Http3
    }

    fn open(&mut self, head: &ReqHead<'_>, end: bool) -> Result<u64> {
        let mut fields: Vec<(&[u8], &[u8])> = vec![(b":method", head.method.as_bytes())];
        if head.method != "CONNECT" {
            fields.push((b":scheme", head.scheme.as_bytes()));
        }
        fields.push((b":authority", head.authority.as_bytes()));
        if head.method != "CONNECT" {
            fields.push((b":path", head.path.as_bytes()));
        }
        fields.extend(head.fields.iter().map(|(n, v)| (&n[..], &v[..])));
        let Some(q) = self.ep.conn_mut(self.h) else { return Err(Error::new(ErrorKind::Closed, format!("QUIC connection gone: {}", self.what))) };
        self.h3.send_request(q, &fields, end).map_err(|e| {
            if matches!(e, SendError::GoingAway) {
                self.goaway = true;
            }
            send_err(e, &self.what)
        })
    }

    /// Extended CONNECT (RFC 9220): `:protocol` with `:scheme`, `:authority` and `:path`; the
    /// stream stays open both ways.
    fn open_extended(&mut self, protocol: &str, head: &ReqHead<'_>) -> Result<u64> {
        let mut fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"CONNECT"),
            (b":protocol", protocol.as_bytes()),
            (b":scheme", head.scheme.as_bytes()),
            (b":authority", head.authority.as_bytes()),
            (b":path", head.path.as_bytes()),
        ];
        fields.extend(head.fields.iter().map(|(n, v)| (&n[..], &v[..])));
        let Some(q) = self.ep.conn_mut(self.h) else { return Err(Error::new(ErrorKind::Closed, format!("QUIC connection gone: {}", self.what))) };
        self.h3.send_request(q, &fields, false).map_err(|e| send_err(e, &self.what))
    }

    fn extended_connect(&self) -> Option<bool> {
        self.h3.peer_connect_protocol()
    }

    fn send_data(&mut self, id: u64, data: &[u8], end: bool) -> Result<usize> {
        let Some(q) = self.ep.conn_mut(self.h) else { return Err(Error::new(ErrorKind::Closed, format!("QUIC connection gone: {}", self.what))) };
        self.h3.send_body(q, id, data, end).map_err(|e| send_err(e, &self.what))
    }

    fn capacity(&self, id: u64) -> usize {
        self.ep.conn(self.h).and_then(|q| q.stream_writable(id)).unwrap_or(0) as usize
    }

    fn send_trailers(&mut self, id: u64, trailers: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let f: Vec<(&[u8], &[u8])> = trailers.iter().map(|(n, v)| (&n[..], &v[..])).collect();
        let Some(q) = self.ep.conn_mut(self.h) else { return Err(Error::new(ErrorKind::Closed, format!("QUIC connection gone: {}", self.what))) };
        self.h3.send_trailers(q, id, &f).map_err(|e| send_err(e, &self.what))
    }

    fn cancel(&mut self, id: u64) {
        if let Some(q) = self.ep.conn_mut(self.h) {
            self.h3.reset_stream(q, id, simoom_h3::code::REQUEST_CANCELLED);
        }
    }

    fn forget(&mut self, _id: u64) {}

    fn take_body(&mut self, id: u64, out: &mut Vec<u8>, max: usize, now: Instant, ev: &mut Vec<MuxEvent>) -> usize {
        let Some(q) = self.ep.conn_mut(self.h) else { return 0 };
        let mut chunk = [0u8; 16 * 1024];
        let mut got = 0;
        while got < max {
            let want = (max - got).min(chunk.len());
            match self.h3.recv_body(now, q, id, &mut chunk[..want]) {
                Ok((n, fin)) => {
                    out.extend_from_slice(&chunk[..n]);
                    got += n;
                    if n == 0 || fin {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        self.events(ev);
        got
    }

    fn input(&mut self, data: &mut [u8], from: Option<SocketAddr>, now: Instant, _io: &MuxIo, ev: &mut Vec<MuxEvent>) {
        if let Some(from) = from {
            let _ = self.ep.recv(now, from, data, &mut self.resp);
        }
        self.process(now, ev);
    }

    fn flush(&mut self, io: &MuxIo, now: Instant) -> io::Result<()> {
        let MuxIo::Udp(sock) = io else { return Err(io::Error::new(io::ErrorKind::Unsupported, "HTTP/3 needs UDP")) };
        while let Some((_, t)) = self.ep.poll_transmit(now, &mut self.tx, 16) {
            match t.segment_size {
                Some(seg) if seg > 0 => {
                    for chunk in self.tx[..t.size].chunks(seg) {
                        sock.send_to(chunk, t.destination)?;
                    }
                }
                _ => {
                    sock.send_to(&self.tx[..t.size], t.destination)?;
                }
            }
        }
        Ok(())
    }

    fn deadline(&mut self) -> Option<Instant> {
        self.ep.poll_timeout()
    }

    fn timeout(&mut self, now: Instant, ev: &mut Vec<MuxEvent>) {
        let mut touched = Vec::new();
        self.ep.handle_timeout(now, &mut touched);
        self.process(now, ev);
    }

    fn ping(&mut self) -> bool {
        if let Some(q) = self.ep.conn_mut(self.h) {
            q.ping();
        }
        false
    }

    fn can_open(&self) -> bool {
        !self.goaway && !self.closed
    }

    fn is_done(&self) -> bool {
        self.goaway || self.closed || self.ep.conn(self.h).is_none_or(|q| q.is_closed())
    }

    fn ready(&self) -> bool {
        self.ep.conn(self.h).is_some_and(|q| q.is_established()) && self.h3.peer_settings().is_some()
    }

    fn close(&mut self, now: Instant) {
        if let Some(q) = self.ep.conn_mut(self.h) {
            q.close(now, simoom_h3::code::NO_ERROR, b"");
        }
    }
}

/// Opens an HTTP/3 connection to `host:port` and waits for the handshake and SETTINGS.
pub(crate) fn connect(tls: Arc<ClientConfig>, host: &str, port: u16, server_name: &str, deadline: Option<Instant>, what: &str) -> Result<Mux> {
    let addr = crate::transport::resolve(host, port)?[0];
    let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().unwrap_or_else(|_| unreachable!()) } else { "[::]:0".parse().unwrap_or_else(|_| unreachable!()) };
    let sock = UdpSocket::bind(bind).map_err(|e| Error::io(&e, what))?;
    let cfg = simoom_quic::Config::new(Arc::new(TlsProvider::client(tls)));
    let mut ep = Endpoint::new(Arc::new(cfg), false);
    let h = ep.connect(Instant::now(), addr, server_name, &[]).map_err(|e| Error::new(ErrorKind::Connect, format!("QUIC connect failed ({e:?}): {what}")))?;
    let proto = H3Proto { ep, h, h3: Http3::new(false, simoom_h3::Config::default()), tx: Vec::new(), resp: Vec::new(), goaway: false, closed: false, what: what.to_string() };
    let m = Mux::new(MuxIo::Udp(sock), Box::new(proto), what.to_string());
    m.kick();
    m.wait_ready(deadline, TimeoutKind::Connect)?;
    Ok(m)
}
