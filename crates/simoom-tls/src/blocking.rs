//! Blocking TLS streams (feature `blocking`): [`TlsStream`] wraps any `Read + Write` transport
//! (usually a [`TcpStream`]) in the sans-io [`Connection`] and implements `std::io::Read` and
//! `Write`, so protocol clients written against blocking sockets (SMTP, AMQP, Kafka, JDBC-style
//! drivers) can use simoom-tls unchanged. Modelled on Cameleer's `cameleer-tls/src/net.rs` and
//! `tls/stream.rs`:
//!
//! - [`connect`] / [`client`] / [`accept`] for TCP, with timeouts (the socket's read and write
//!   timeouts apply to the handshake and to later I/O; a timed-out read or write can be retried);
//! - [`lingering_close`] after a fatal alert: FIN, then reading until the peer closes (at most
//!   [`ALERT_LINGER`]), so a peer that is still sending gets the alert instead of a TCP reset
//!   (Windows discards unread data on a reset; Cameleer INTEROP bug 18);
//! - [`TlsStream::split`] into a reader and a writer for full-duplex protocols: one thread
//!   blocks in `read` while others write. The halves share one socket handle (on Windows
//!   socket timeouts belong to the handle) and one connection behind a mutex that is never
//!   held while blocking in a read.
//!
//! The adapter adds no protocol logic: everything TLS is in [`Connection`].

use crate::tls::conn::Connection;
use crate::tls::{Error, ProtocolVersion};
#[cfg(feature = "client")]
use crate::{ClientConfig, ClientConnection};
use crate::{ServerConfig, ServerConnection};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long [`lingering_close`] waits for the peer to close after a fatal alert.
pub const ALERT_LINGER: Duration = Duration::from_secs(2);

const READ_CHUNK: usize = 16 * 1024 + 512;

/// Converts a TLS error into an `io::Error` (`InvalidData`, the TLS error inside; `Closed`
/// becomes `BrokenPipe`).
pub fn tls_io_error(e: Error) -> io::Error {
    match e {
        Error::Closed => io::Error::new(io::ErrorKind::BrokenPipe, Error::Closed),
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// The TLS error inside an `io::Error` from this module, if any.
pub fn tls_error_of(e: &io::Error) -> Option<&Error> {
    e.get_ref().and_then(|i| i.downcast_ref::<Error>())
}

/// Writes all pending TLS output of `conn` to `io`. On a timeout the rest stays queued in the
/// connection and goes out with the next write or flush.
fn flush_tls<W: Write + ?Sized>(conn: &mut Connection, io: &mut W) -> io::Result<()> {
    while conn.wants_write() {
        match io.write(conn.tls_output()) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "transport closed")),
            Ok(n) => conn.consume_tls_output(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    io.flush()
}

/// Feeds received bytes; returns how many were taken (the connection may refuse more while
/// decrypted data waits to be read).
fn feed(conn: &mut Connection, data: &[u8]) -> Result<usize, Error> {
    let mut off = 0;
    while off < data.len() {
        let n = conn.read_tls(&data[off..]);
        conn.process_new_packets()?;
        if n == 0 {
            break;
        }
        off += n;
    }
    Ok(off)
}

/// An I/O failure during the handshake, kept apart from TLS errors so the caller sees the
/// original `io::Error` (timeouts stay `TimedOut`).
enum HsError {
    Io(io::Error),
    Tls(Error),
}

impl HsError {
    fn into_io(self) -> io::Error {
        match self {
            HsError::Io(e) => e,
            HsError::Tls(e) => tls_io_error(e),
        }
    }
}

/// A TLS connection over a blocking transport.
pub struct TlsStream<S: Read + Write> {
    io: S,
    conn: Connection,
    /// Received bytes the connection has not taken yet.
    pending: Vec<u8>,
    eof: bool,
}

impl<S: Read + Write> std::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream").field("conn", &self.conn).finish()
    }
}

impl<S: Read + Write> TlsStream<S> {
    fn handshake(io: S, conn: Connection) -> Result<TlsStream<S>, HsError> {
        let mut s = TlsStream { io, conn, pending: Vec::new(), eof: false };
        s.complete_handshake()?;
        Ok(s)
    }

    fn complete_handshake(&mut self) -> Result<(), HsError> {
        let mut buf = vec![0u8; READ_CHUNK];
        while self.conn.is_handshaking() {
            flush_tls(&mut self.conn, &mut self.io).map_err(HsError::Io)?;
            let n = loop {
                match self.io.read(&mut buf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(HsError::Io(e)),
                }
            };
            if n == 0 {
                return Err(HsError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during the TLS handshake")));
            }
            match feed(&mut self.conn, &buf[..n]) {
                Ok(used) => self.pending.extend_from_slice(&buf[used..n]),
                Err(e) => {
                    let _ = flush_tls(&mut self.conn, &mut self.io);
                    return Err(HsError::Tls(e));
                }
            }
        }
        // the last flight (client Finished, server tickets) and data written meanwhile
        flush_tls(&mut self.conn, &mut self.io).map_err(HsError::Io)
    }

    /// Client handshake over `io`; `server_name` is sent as SNI and verified.
    #[cfg(feature = "client")]
    pub fn connect(io: S, server_name: &str, config: Arc<ClientConfig>) -> io::Result<TlsStream<S>> {
        let conn = ClientConnection::new(config, server_name).map_err(tls_io_error)?.into_inner();
        TlsStream::handshake(io, conn).map_err(HsError::into_io)
    }

    /// Server handshake over `io`.
    pub fn accept(io: S, config: Arc<ServerConfig>) -> io::Result<TlsStream<S>> {
        TlsStream::handshake(io, ServerConnection::new(config).into_inner()).map_err(HsError::into_io)
    }

    /// The TLS connection state (version, suite, ALPN, peer certificates, exporter...).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.conn.protocol_version()
    }
    pub fn cipher_suite_name(&self) -> Option<&'static str> {
        self.conn.cipher_suite_name()
    }
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.conn.peer_certificates()
    }
    pub fn sni_hostname(&self) -> Option<&str> {
        self.conn.server_name()
    }
    pub fn session_resumed(&self) -> bool {
        self.conn.is_resumed()
    }
    /// Whether the peer sent close_notify.
    pub fn peer_closed(&self) -> bool {
        self.conn.peer_has_closed()
    }

    /// Sends close_notify (further writes fail).
    pub fn close(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        flush_tls(&mut self.conn, &mut self.io)
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }
    pub fn into_inner(self) -> S {
        self.io
    }

    fn fail(&mut self, e: Error) -> io::Error {
        let _ = flush_tls(&mut self.conn, &mut self.io);
        tls_io_error(e)
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            if !self.pending.is_empty() {
                let pending = std::mem::take(&mut self.pending);
                match feed(&mut self.conn, &pending) {
                    Ok(used) => self.pending = pending[used..].to_vec(),
                    Err(e) => return Err(self.fail(e)),
                }
            }
            let n = self.conn.read_plaintext(buf);
            if n > 0 {
                return Ok(n);
            }
            if self.conn.peer_has_closed() || self.eof {
                return Ok(0);
            }
            if let Some(e) = self.conn.error() {
                return Err(tls_io_error(e.clone()));
            }
            // KeyUpdate answers and the like
            flush_tls(&mut self.conn, &mut self.io)?;
            let n = match self.io.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                // the transport closed without close_notify: end of stream (as Java and
                // Cameleer report it); `peer_closed()` tells a clean close apart
                self.eof = true;
                return Ok(0);
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.conn.write_plaintext(buf).map_err(tls_io_error)?;
        flush_tls(&mut self.conn, &mut self.io)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        flush_tls(&mut self.conn, &mut self.io)
    }
}

/// Closes a connection on which a fatal alert was just sent without losing the alert: FIN,
/// then reading and discarding until the peer closes, [`ALERT_LINGER`] passes or 256 KiB
/// arrive. Dropping the socket at once makes the kernel answer the peer's late data (a TLS 1.3
/// client writes right after its Finished) with a reset, which discards the unread alert on
/// Windows.
pub fn lingering_close(tcp: &TcpStream) {
    let _ = tcp.shutdown(Shutdown::Write);
    let deadline = Instant::now() + ALERT_LINGER;
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    while total < 256 * 1024 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || tcp.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match (&*tcp).read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

/// Opens a TCP connection to `host:port`, trying each resolved address with `timeout`.
pub fn connect_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"));
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// One socket handle shared by a stream and its split halves (socket timeouts belong to the
/// handle on Windows, so the halves must not use `try_clone`d handles).
#[derive(Clone, Debug)]
pub struct SharedTcp(pub Arc<TcpStream>);

impl Read for SharedTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for SharedTcp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// Client handshake over a connected socket. The socket's timeouts apply.
#[cfg(feature = "client")]
pub fn client(tcp: TcpStream, server_name: &str, config: Arc<ClientConfig>) -> io::Result<TlsStream<SharedTcp>> {
    let conn = ClientConnection::new(config, server_name).map_err(tls_io_error)?.into_inner();
    finish(tcp, conn)
}

/// Server handshake over an accepted socket; after a fatal alert the socket gets a
/// [`lingering_close`] so the client receives the alert.
pub fn accept(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<TlsStream<SharedTcp>> {
    finish(tcp, ServerConnection::new(config).into_inner())
}

fn finish(tcp: TcpStream, conn: Connection) -> io::Result<TlsStream<SharedTcp>> {
    let shared = Arc::new(tcp);
    match TlsStream::handshake(SharedTcp(shared.clone()), conn) {
        Ok(s) => Ok(s),
        Err(HsError::Tls(e)) => {
            if e.alert_to_send().is_some() {
                lingering_close(&shared);
            }
            Err(tls_io_error(e))
        }
        Err(HsError::Io(e)) => Err(e),
    }
}

/// Connects to `host:port` and performs the TLS handshake, verifying `host`. `timeout` bounds
/// the TCP connect and every read and write until changed through `get_ref()`.
#[cfg(feature = "client")]
pub fn connect(host: &str, port: u16, config: Arc<ClientConfig>, timeout: Duration) -> io::Result<TlsStream<SharedTcp>> {
    let tcp = connect_tcp(host, port, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    client(tcp, host, config)
}

impl TlsStream<SharedTcp> {
    /// Splits the connection into a reader and a writer for full-duplex use.
    pub fn split(self) -> (TlsReader, TlsWriter) {
        let shared = Arc::new(Mutex::new(self.conn));
        let reader = TlsReader { conn: shared.clone(), io: self.io.clone(), pending: self.pending, eof: self.eof };
        (reader, TlsWriter { conn: shared, io: self.io })
    }

    /// Sends close_notify, then waits for the peer to close ([`lingering_close`]).
    pub fn shutdown(mut self) -> io::Result<()> {
        self.close()?;
        lingering_close(&self.io.0);
        Ok(())
    }
}

/// The reading half of a split [`TlsStream`].
pub struct TlsReader {
    conn: Arc<Mutex<Connection>>,
    io: SharedTcp,
    pending: Vec<u8>,
    eof: bool,
}

impl std::fmt::Debug for TlsReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsReader")
    }
}

/// The writing half of a split [`TlsStream`]; clones share the connection.
#[derive(Clone)]
pub struct TlsWriter {
    conn: Arc<Mutex<Connection>>,
    io: SharedTcp,
}

impl std::fmt::Debug for TlsWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsWriter")
    }
}

fn lock(m: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl TlsReader {
    /// Whether the peer sent close_notify.
    pub fn peer_closed(&self) -> bool {
        lock(&self.conn).peer_has_closed()
    }
    pub fn get_ref(&self) -> &TcpStream {
        &self.io.0
    }
}

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            {
                let mut c = lock(&self.conn);
                if !self.pending.is_empty() {
                    let pending = std::mem::take(&mut self.pending);
                    match feed(&mut c, &pending) {
                        Ok(used) => self.pending = pending[used..].to_vec(),
                        Err(e) => {
                            let _ = flush_tls(&mut c, &mut self.io);
                            return Err(tls_io_error(e));
                        }
                    }
                }
                let n = c.read_plaintext(buf);
                if n > 0 {
                    return Ok(n);
                }
                if c.peer_has_closed() || self.eof {
                    return Ok(0);
                }
                if let Some(e) = c.error() {
                    return Err(tls_io_error(e.clone()));
                }
                // replies the connection queued (KeyUpdate), in order with the writer's records
                flush_tls(&mut c, &mut self.io)?;
            }
            // block without holding the lock
            let n = match self.io.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                self.eof = true;
                return Ok(0);
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }
}

impl TlsWriter {
    /// Writes all of `buf` (one lock for the whole buffer, so concurrent writers never
    /// interleave inside one call).
    pub fn write_all_data(&self, buf: &[u8]) -> io::Result<()> {
        let mut c = lock(&self.conn);
        c.write_plaintext(buf).map_err(tls_io_error)?;
        let mut io = self.io.clone();
        flush_tls(&mut c, &mut io)
    }

    /// Sends close_notify (idempotent).
    pub fn close(&self) -> io::Result<()> {
        let mut c = lock(&self.conn);
        c.send_close_notify();
        let mut io = self.io.clone();
        flush_tls(&mut c, &mut io)
    }
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all_data(buf).map(|_| buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut c = lock(&self.conn);
        let mut io = self.io.clone();
        flush_tls(&mut c, &mut io)
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::certgen;
    use crate::tls::config::{CertifiedKey, ClientAuth};
    use crate::x509::RootStore;
    use std::net::TcpListener;

    fn configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
        let ss = certgen::self_signed("localhost");
        let s = ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap());
        let mut roots = RootStore::empty();
        roots.add_der(&ss.cert_der).unwrap();
        (Arc::new(s), Arc::new(ClientConfig::new(roots)))
    }

    #[test]
    fn echo_over_tcp_both_versions() {
        let (scfg, ccfg) = configs();
        #[allow(unused_mut)]
        let mut variants: Vec<(Arc<ServerConfig>, ProtocolVersion)> = vec![(scfg.clone(), ProtocolVersion::Tls13)];
        #[cfg(feature = "tls12")]
        {
            let mut s12 = (*scfg).clone();
            s12.max_version = ProtocolVersion::Tls12;
            variants.push((Arc::new(s12), ProtocolVersion::Tls12));
        }
        for (scfg, version) in variants {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let h = std::thread::spawn(move || {
                let (tcp, _) = l.accept().unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut s = accept(tcp, scfg).unwrap();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while got.len() < 100_000 {
                    let n = s.read(&mut buf).unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&buf[..n]);
                }
                s.write_all(&got).unwrap();
                s.close().unwrap();
                got.len()
            });
            let mut c = connect("localhost", port, ccfg.clone(), Duration::from_secs(10)).unwrap();
            assert_eq!(c.protocol_version(), Some(version));
            let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
            c.write_all(&data).unwrap();
            let mut back = Vec::new();
            c.read_to_end(&mut back).unwrap();
            assert_eq!(back, data);
            assert!(c.peer_closed());
            assert_eq!(h.join().unwrap(), 100_000);
        }
    }

    #[test]
    fn split_full_duplex() {
        let (scfg, ccfg) = configs();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            let s = accept(tcp, scfg).unwrap();
            let (mut r, mut w) = s.split();
            // echo everything as it arrives, from the reader through the writer
            let mut buf = [0u8; 8192];
            let mut total = 0;
            loop {
                let n = r.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                w.write_all(&buf[..n]).unwrap();
            }
            w.close().unwrap();
            total
        });
        let c = connect("localhost", port, ccfg, Duration::from_secs(10)).unwrap();
        let (mut r, w) = c.split();
        let writer = std::thread::spawn(move || {
            let mut w = w;
            for i in 0..200u32 {
                w.write_all(&[i as u8; 1000]).unwrap();
            }
            w.close().unwrap();
        });
        let mut got = 0;
        let mut buf = [0u8; 8192];
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        writer.join().unwrap();
        assert_eq!(got, 200_000);
        assert_eq!(h.join().unwrap(), 200_000);
    }

    #[test]
    fn host_name_is_verified() {
        let (scfg, ccfg) = configs();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            accept(tcp, scfg).is_err()
        });
        // the certificate names localhost, not wrong.example
        let tcp = connect_tcp("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let e = client(tcp, "wrong.example", ccfg).unwrap_err();
        assert!(matches!(tls_error_of(&e), Some(Error::Certificate(_))), "{e}");
        assert!(h.join().unwrap());
    }

    #[test]
    fn fatal_alert_survives_a_client_that_reads_late() {
        // the server rejects a missing client certificate; the client (TLS 1.3) has already
        // sent data after its Finished. The lingering close lets it read the alert.
        let ss = certgen::self_signed("localhost");
        let mut s = ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap());
        let mut roots = RootStore::empty();
        roots.add_der(&ss.cert_der).unwrap();
        s.client_auth = ClientAuth::Required(roots.clone());
        let scfg = Arc::new(s);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            accept(tcp, scfg).map(|_| ()).unwrap_err()
        });
        let tcp = connect_tcp("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut c = client(tcp, "localhost", Arc::new(ClientConfig::new(roots))).unwrap();
        let _ = c.write_all(&[b'x'; 64 * 1024]);
        std::thread::sleep(Duration::from_millis(200));
        let mut buf = [0u8; 16];
        let e = c.read(&mut buf).unwrap_err();
        let err = h.join().unwrap();
        assert!(err.to_string().contains("certificate"), "{err}");
        assert_eq!(tls_error_of(&e), Some(&Error::PeerAlert(crate::alert::CERTIFICATE_REQUIRED)), "{e}");
    }

    #[test]
    fn read_timeout_is_retryable() {
        let (scfg, ccfg) = configs();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            let mut s = accept(tcp, scfg).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            s.write_all(b"late").unwrap();
            s.close().unwrap();
        });
        let mut c = connect("localhost", port, ccfg, Duration::from_secs(10)).unwrap();
        c.get_ref().0.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 16];
        let e = c.read(&mut buf).unwrap_err();
        assert!(matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut), "{e:?}");
        c.get_ref().0.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"late");
        h.join().unwrap();
    }
}
