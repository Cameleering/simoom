//! TCP connections, the TLS handshake, `CONNECT` tunnels, and [`Duplex`]: a byte stream (plain
//! or TLS) that one thread can read while others write.

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::proxy::ProxyAddr;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg(feature = "tls")]
use simoom_tls::ClientConnection;

/// The time left until `deadline`, or a timeout error.
pub(crate) fn remaining(deadline: Option<Instant>, kind: TimeoutKind, what: impl std::fmt::Display) -> Result<Option<Duration>> {
    match deadline {
        None => Ok(None),
        Some(d) => match d.checked_duration_since(Instant::now()) {
            Some(r) if !r.is_zero() => Ok(Some(r)),
            _ => Err(Error::timeout(kind, what)),
        },
    }
}

/// The earlier of two optional deadlines.
pub(crate) fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Resolves `host:port`. `localhost` tries IPv4 first (servers commonly bind 127.0.0.1 only, and
/// a refused `::1` costs about a second on Windows).
#[cfg_attr(feature = "dns-timeout", allow(dead_code))]
pub(crate) fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let what = format!("{host}:{port}");
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let mut addrs: Vec<SocketAddr> =
        (host, port).to_socket_addrs().map_err(|e| Error::new(ErrorKind::Connect, format!("cannot resolve {what}: {e}")))?.collect();
    if host.eq_ignore_ascii_case("localhost") {
        addrs.sort_by_key(|a| !a.is_ipv4());
    }
    if addrs.is_empty() {
        return Err(Error::new(ErrorKind::Connect, format!("unknown host: {host}")));
    }
    Ok(addrs)
}

/// Connects to `host:port`, trying each resolved address until `deadline`. Name resolution
/// uses the system resolver, which has no timeout of its own.
#[cfg_attr(not(feature = "rt"), allow(dead_code))]
pub(crate) fn tcp_connect(host: &str, port: u16, deadline: Option<Instant>) -> Result<TcpStream> {
    tcp_connect_with(host, port, deadline, Some(Duration::from_secs(10)), Duration::from_millis(250))
}

/// Like [`tcp_connect`] with a resolver timeout and Happy Eyeballs (RFC 8305): when a name has
/// several addresses, a new attempt starts every `he_delay` until one connects.
pub(crate) fn tcp_connect_with(host: &str, port: u16, deadline: Option<Instant>, dns_timeout: Option<Duration>, he_delay: Duration) -> Result<TcpStream> {
    let what = format!("{host}:{port}");
    let dns_t = match (dns_timeout, deadline) {
        (Some(t), Some(d)) => Some(t.min(d.saturating_duration_since(Instant::now()))),
        (t, None) => t,
        (None, Some(d)) => Some(d.saturating_duration_since(Instant::now())),
    };
    #[cfg(feature = "dns-timeout")]
    let addrs = crate::dns::resolve(host, port, dns_t)?;
    #[cfg(not(feature = "dns-timeout"))]
    let addrs = {
        let _ = dns_t;
        resolve(host, port)?
    };
    #[cfg(not(feature = "happy-eyeballs"))]
    let _ = he_delay;
    #[cfg(feature = "happy-eyeballs")]
    if addrs.len() > 1 {
        return match crate::dns::connect(addrs, deadline, he_delay) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                Ok(s)
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(Error::timeout(TimeoutKind::Connect, &what)),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Err(Error::new(ErrorKind::Connect, format!("connection refused: {what}"))),
            Err(e) => Err(Error::new(ErrorKind::Connect, format!("cannot connect to {what}: {e}"))),
        };
    }
    let mut last: Option<io::Error> = None;
    for a in addrs {
        let r = match remaining(deadline, TimeoutKind::Connect, &what)? {
            Some(t) => TcpStream::connect_timeout(&a, t),
            None => TcpStream::connect(a),
        };
        match r {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(match last {
        Some(e) if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock => Error::timeout(TimeoutKind::Connect, &what),
        Some(e) if e.kind() == io::ErrorKind::ConnectionRefused => Error::new(ErrorKind::Connect, format!("connection refused: {what}")),
        Some(e) => Error::new(ErrorKind::Connect, format!("cannot connect to {what}: {e}")),
        None => Error::new(ErrorKind::Connect, format!("unknown host: {host}")),
    })
}

/// Opens a `CONNECT` tunnel to `authority` through `proxy` on `tcp`. Reads only the proxy's
/// response head (a proxy must not send anything after it before the client speaks).
pub(crate) fn connect_tunnel(tcp: &TcpStream, authority: &str, proxy: &ProxyAddr, deadline: Option<Instant>) -> Result<()> {
    let what = format!("proxy {}:{}", proxy.host, proxy.port);
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(a) = proxy.authorization() {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    let _ = tcp.set_write_timeout(remaining(deadline, TimeoutKind::Connect, &what)?);
    (&*tcp).write_all(req.as_bytes()).map_err(|e| Error::io(&e, &what))?;
    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 1024];
    loop {
        let t = remaining(deadline, TimeoutKind::Connect, &what)?;
        let _ = tcp.set_read_timeout(t);
        let n = match (&*tcp).read(&mut buf) {
            Ok(0) => return Err(Error::new(ErrorKind::Proxy, format!("{what} closed the connection during CONNECT"))),
            Ok(n) => n,
            Err(e) if is_timeout(&e) => return Err(Error::timeout(TimeoutKind::Connect, &what)),
            Err(e) => return Err(Error::io(&e, &what)),
        };
        head.extend_from_slice(&buf[..n]);
        let mut hs = [simoom_http1::EMPTY_HEADER; 32];
        match simoom_http1::parse_response(&head, &mut hs, &simoom_http1::Limits::default(), b"CONNECT") {
            Ok(simoom_http1::Status::Complete(r)) => {
                if r.status / 100 == 1 {
                    let hl = r.head_len;
                    head.drain(..hl);
                    continue;
                }
                if !(200..300).contains(&r.status) {
                    let reason = String::from_utf8_lossy(r.reason).into_owned();
                    return Err(Error::new(ErrorKind::Proxy, format!("{what} refused CONNECT {authority}: {} {reason}", r.status)));
                }
                if head.len() != r.head_len {
                    return Err(Error::new(ErrorKind::Proxy, format!("{what} sent data before the client spoke")));
                }
                return Ok(());
            }
            Ok(simoom_http1::Status::Partial) => {}
            Err(e) => return Err(Error::new(ErrorKind::Proxy, format!("{what} sent an invalid CONNECT response ({e})"))),
        }
    }
}

pub(crate) fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

#[cfg(feature = "tls")]
pub(crate) fn tls_error(e: &simoom_tls::Error, what: &str) -> Error {
    Error::new(ErrorKind::Tls, format!("TLS error ({e:?}): {what}"))
}

/// Runs the TLS handshake on `tcp` until it completes or `deadline` passes.
#[cfg(feature = "tls")]
pub(crate) fn tls_handshake(tcp: &TcpStream, conn: &mut ClientConnection, deadline: Option<Instant>, what: &str) -> Result<()> {
    let mut buf = vec![0u8; 16 * 1024 + 512];
    loop {
        let out = conn.tls_output();
        if !out.is_empty() {
            let _ = tcp.set_write_timeout(remaining(deadline, TimeoutKind::Tls, what)?);
            (&*tcp).write_all(out).map_err(|e| Error::io(&e, what))?;
            let n = out.len();
            conn.consume_tls_output(n);
        }
        if let Some(e) = conn.error() {
            return Err(tls_error(e, what));
        }
        if !conn.is_handshaking() {
            return Ok(());
        }
        let _ = tcp.set_read_timeout(remaining(deadline, TimeoutKind::Tls, what)?);
        let n = match (&*tcp).read(&mut buf) {
            Ok(0) => return Err(Error::new(ErrorKind::Tls, format!("connection closed during the TLS handshake: {what}"))),
            Ok(n) => n,
            Err(e) if is_timeout(&e) => return Err(Error::timeout(TimeoutKind::Tls, what)),
            Err(e) => return Err(Error::io(&e, what)),
        };
        let mut off = 0;
        while off < n {
            let k = conn.read_tls(&buf[off..n]);
            off += k;
            if let Err(e) = conn.process_new_packets() {
                let out = conn.tls_output().to_vec();
                let _ = (&*tcp).write_all(&out);
                return Err(tls_error(&e, what));
            }
            if k == 0 && off < n {
                // Application data after the handshake: it stays buffered in `conn`'s
                // plaintext; keep feeding once it is read (cannot happen before Finished).
                return Err(Error::protocol("unexpected data during the TLS handshake", what));
            }
        }
    }
}

/// Raw input waiting for the TLS layer.
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
struct Rx {
    buf: Vec<u8>,
    pos: usize,
}

/// A connected byte stream, plain or TLS. One thread at a time reads (reads serialize on an
/// internal lock and the socket read happens outside the TLS lock), any thread may write; TLS
/// state is shared under a short lock. Read timeouts are applied per call and the socket option
/// is only touched when it changes.
pub(crate) struct Duplex {
    tcp: TcpStream,
    #[cfg(feature = "tls")]
    tls: Option<Mutex<ClientConnection>>,
    rx: Mutex<Rx>,
    /// The read timeout currently set on the socket, in ns (u64::MAX: none).
    cur_timeout: AtomicU64,
    #[cfg_attr(not(all(feature = "tls", feature = "client-h2")), allow(dead_code))]
    alpn: Option<Vec<u8>>,
}

impl std::fmt::Debug for Duplex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Duplex").field("tls", &self.is_tls()).finish()
    }
}

impl Duplex {
    /// A plain TCP stream.
    pub(crate) fn plain(tcp: TcpStream) -> Duplex {
        Duplex {
            tcp,
            #[cfg(feature = "tls")]
            tls: None,
            rx: Mutex::new(Rx { buf: Vec::new(), pos: 0 }),
            cur_timeout: AtomicU64::new(u64::MAX - 1),
            alpn: None,
        }
    }

    /// A TLS stream after a completed handshake.
    #[cfg(feature = "tls")]
    pub(crate) fn tls(tcp: TcpStream, conn: ClientConnection) -> Duplex {
        let mut d = Duplex::plain(tcp);
        d.alpn = conn.alpn_protocol().map(|a| a.to_vec());
        d.tls = Some(Mutex::new(conn));
        d
    }

    pub(crate) fn is_tls(&self) -> bool {
        #[cfg(feature = "tls")]
        {
            self.tls.is_some()
        }
        #[cfg(not(feature = "tls"))]
        {
            false
        }
    }

    /// The negotiated ALPN protocol.
    #[cfg_attr(not(all(feature = "tls", feature = "client-h2")), allow(dead_code))]
    pub(crate) fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Sets the socket read timeout, skipping the system call when the current one is close
    /// enough: at least half the wanted time (an early wake-up just reads again) and at most an
    /// eighth plus 1 ms over it (deadlines are re-checked after every read).
    fn set_timeout(&self, t: Option<Duration>) {
        let ns = t.map_or(u64::MAX, |d| d.as_nanos().min(u64::MAX as u128 - 2) as u64);
        let cur = self.cur_timeout.load(Ordering::Relaxed);
        let close = if ns == u64::MAX { cur == u64::MAX } else { cur != u64::MAX && cur >= ns / 2 && cur <= ns + ns / 8 + 1_000_000 };
        if !close {
            self.cur_timeout.store(ns, Ordering::Relaxed);
            let _ = self.tcp.set_read_timeout(t.map(|d| d.max(Duration::from_millis(1))));
        }
    }

    /// Sets the write timeout (once per connection).
    pub(crate) fn set_write_timeout(&self, t: Option<Duration>) {
        let _ = self.tcp.set_write_timeout(t.map(|d| d.max(Duration::from_millis(1))));
    }

    /// Reads plaintext, waiting at most `timeout` for the socket. `Ok(0)` is end of stream.
    pub(crate) fn read(&self, out: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        #[cfg(feature = "tls")]
        if let Some(tls) = &self.tls {
            let mut rx = self.rx.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                {
                    let mut t = tls.lock().unwrap_or_else(|p| p.into_inner());
                    let n = t.read_plaintext(out);
                    if n > 0 {
                        return Ok(n);
                    }
                    // Records may wait inside the TLS layer (it stops decrypting while its
                    // plaintext buffer is full), so process before reading the socket.
                    let mut k = 0;
                    if rx.pos < rx.buf.len() {
                        k = t.read_tls(&rx.buf[rx.pos..]);
                        rx.pos += k;
                        if rx.pos == rx.buf.len() {
                            rx.buf.clear();
                            rx.pos = 0;
                        }
                    }
                    let r = t.process_new_packets();
                    self.flush_tls(&mut t)?;
                    if let Err(e) = r {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("TLS: {e:?}")));
                    }
                    if k > 0 || !t.plaintext().is_empty() {
                        continue;
                    }
                    if t.peer_has_closed() {
                        return Ok(0);
                    }
                }
                self.set_timeout(timeout);
                let rx = &mut *rx;
                if rx.pos > 0 && rx.pos == rx.buf.len() {
                    rx.buf.clear();
                    rx.pos = 0;
                }
                let start = rx.buf.len();
                rx.buf.resize(start + 17 * 1024, 0);
                let r = (&self.tcp).read(&mut rx.buf[start..]);
                match r {
                    Ok(0) => {
                        rx.buf.truncate(start);
                        return Ok(0);
                    }
                    Ok(n) => rx.buf.truncate(start + n),
                    Err(e) => {
                        rx.buf.truncate(start);
                        return Err(e);
                    }
                }
            }
        }
        let _guard = self.rx.lock().unwrap_or_else(|p| p.into_inner());
        self.set_timeout(timeout);
        (&self.tcp).read(out)
    }

    #[cfg(feature = "tls")]
    fn flush_tls(&self, t: &mut ClientConnection) -> io::Result<()> {
        loop {
            let out = t.tls_output();
            if out.is_empty() {
                return Ok(());
            }
            let n = out.len();
            (&self.tcp).write_all(out)?;
            t.consume_tls_output(n);
        }
    }

    /// Writes all of `bufs` (one TLS record per call where it fits).
    pub(crate) fn write_all(&self, data: &[u8]) -> io::Result<()> {
        #[cfg(feature = "tls")]
        if let Some(tls) = &self.tls {
            let mut t = tls.lock().unwrap_or_else(|p| p.into_inner());
            let mut off = 0;
            while off < data.len() {
                let n = t.write_plaintext(&data[off..]).map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("TLS: {e:?}")))?;
                off += n;
                self.flush_tls(&mut t)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TLS connection closed"));
                }
            }
            return self.flush_tls(&mut t);
        }
        (&self.tcp).write_all(data)
    }

    /// Whether the peer has closed or reset an idle connection (checked without blocking).
    /// Unread bytes on an idle HTTP/1.1 connection also make it unusable.
    /// TLS records that arrived while idle (session tickets, key updates) are processed; any
    /// application data or a close makes the connection broken.
    pub(crate) fn idle_is_broken(&self) -> bool {
        if self.tcp.set_nonblocking(true).is_err() {
            return true;
        }
        let broken = self.drain_idle();
        let _ = self.tcp.set_nonblocking(false);
        broken
    }

    fn drain_idle(&self) -> bool {
        let mut b = [0u8; 4096];
        loop {
            #[cfg(feature = "tls")]
            if let Some(tls) = &self.tls {
                {
                    let t = tls.lock().unwrap_or_else(|p| p.into_inner());
                    if t.peer_has_closed() || !t.plaintext().is_empty() || t.error().is_some() {
                        return true;
                    }
                }
                match (&self.tcp).read(&mut b) {
                    Ok(0) => return true,
                    Ok(n) => {
                        let mut rx = self.rx.lock().unwrap_or_else(|p| p.into_inner());
                        let mut t = tls.lock().unwrap_or_else(|p| p.into_inner());
                        rx.buf.extend_from_slice(&b[..n]);
                        let p = rx.pos;
                        let k = t.read_tls(&rx.buf[p..]);
                        rx.pos += k;
                        if rx.pos == rx.buf.len() {
                            rx.buf.clear();
                            rx.pos = 0;
                        }
                        if t.process_new_packets().is_err() || self.flush_tls(&mut t).is_err() {
                            return true;
                        }
                        continue;
                    }
                    Err(e) => return e.kind() != io::ErrorKind::WouldBlock,
                }
            }
            return match self.tcp.peek(&mut b[..1]) {
                Ok(_) => true,
                Err(e) => e.kind() != io::ErrorKind::WouldBlock,
            };
        }
    }

    /// Sends close_notify (TLS) and shuts the socket down.
    pub(crate) fn close(&self) {
        #[cfg(feature = "tls")]
        if let Some(tls) = &self.tls {
            let mut t = tls.lock().unwrap_or_else(|p| p.into_inner());
            t.send_close_notify();
            let _ = self.flush_tls(&mut t);
        }
        let _ = self.tcp.shutdown(Shutdown::Both);
    }
}
