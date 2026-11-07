//! TLS 1.3 over records, sans-io: feed received bytes with [`Connection::read_tls`] and
//! [`Connection::process_new_packets`], take bytes to send with [`Connection::tls_output`] /
//! [`Connection::consume_tls_output`], and exchange plaintext with
//! [`Connection::write_plaintext`] and [`Connection::read_plaintext`].
//!
//! Records are decrypted in place in the receive buffer and plaintext is sealed in place in the
//! send buffer, so the steady state allocates nothing. Buffers are bounded: `read_tls` stops
//! accepting bytes while two records are pending, and decryption pauses while 64 KiB of
//! plaintext waits to be read.

#[cfg(feature = "client")]
use super::client::ClientHs;
#[cfg(feature = "client")]
use super::config::ClientConfig;
use super::config::ServerConfig;
use super::engine::{Engine, Event, HsReader};
use super::keyschedule::{derive_secret, expand_label_vec, next_traffic_secret, traffic_key_iv};
use super::record::{RecordCipher, MAX_CIPHERTEXT, MAX_PLAINTEXT};
use super::server::ServerHs;
use super::{alert, codec, content, hs, CipherSuite, Error, Level, NamedGroup, Result};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

const MAX_RX: usize = 2 * (5 + MAX_CIPHERTEXT);
const MAX_PLAIN_BUFFERED: usize = 64 * 1024;
const MAX_PENDING_APP: usize = 1 << 20;
/// Records sent under one key before an automatic KeyUpdate (well below the AES-GCM limit of
/// 2^24.5 full-size records, RFC 8446 section 5.5).
const KEY_UPDATE_AFTER: u64 = 1 << 23;
/// Consecutive received records that deliver nothing to the application (empty application
/// data, user_canceled warnings, KeyUpdates) before the peer is treated as hostile. Each one
/// costs a decryption, and a KeyUpdate with update_requested also a reply, so a flood of them
/// is a cheap way to burn CPU and grow output (the many-empty-records and alert-flood DoS
/// class). OpenSSL uses the same bound for empty records.
const MAX_IDLE_RECORDS: u32 = 32;

/// What [`Connection::process_new_packets`] left for the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoState {
    pub tls_bytes_to_write: usize,
    pub plaintext_bytes_to_read: usize,
    pub peer_has_closed: bool,
}

/// One direction's traffic secret and record state, for kernel TLS.
#[derive(Clone, Debug)]
pub struct DirectionalSecret {
    pub secret: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    /// The sequence number of the next record.
    pub seq: u64,
}

/// The state handed to kernel TLS (or another record layer) by
/// [`Connection::export_traffic_secrets`].
#[derive(Clone, Debug)]
pub struct ExportedSecrets {
    pub suite: CipherSuite,
    pub tx: DirectionalSecret,
    pub rx: DirectionalSecret,
    /// Received bytes not yet processed (they continue the rx record stream).
    pub unprocessed_input: Vec<u8>,
    /// Decrypted plaintext the application has not read.
    pub plaintext: Vec<u8>,
}

/// The state shared by [`ServerConnection`] and [`ClientConnection`].
pub struct Connection {
    engine: Engine,
    hs: HsReader,
    rx: Vec<u8>,
    rx_pos: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    tx: Vec<u8>,
    tx_pos: usize,
    read: Option<RecordCipher>,
    write: Option<RecordCipher>,
    read_level: Level,
    write_level: Level,
    /// (client, server) traffic secrets per level.
    secrets: [Option<(Vec<u8>, Vec<u8>)>; 3],
    pending_hs: Vec<u8>,
    pending_level: Level,
    pending_app: Vec<u8>,
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    error: Option<Error>,
    peer_closed: bool,
    sent_close: bool,
    ccs_seen: u8,
    sent_first: bool,
    /// Rejected 0-RTT bytes skipped so far (server); usize::MAX once skipping has ended.
    early_skipped: usize,
    /// Consecutive received records that delivered nothing ([`MAX_IDLE_RECORDS`]).
    idle_records: u32,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("client", &self.engine.is_client())
            .field("handshaking", &self.is_handshaking())
            .field("suite", &self.negotiated_cipher_suite())
            .finish()
    }
}

fn idx(l: Level) -> usize {
    l as usize
}

impl Connection {
    fn new(engine: Engine) -> Connection {
        let mut c = Connection {
            engine,
            hs: HsReader::new(),
            rx: Vec::new(),
            rx_pos: 0,
            plain: Vec::new(),
            plain_pos: 0,
            tx: Vec::new(),
            tx_pos: 0,
            read: None,
            write: None,
            read_level: Level::Initial,
            write_level: Level::Initial,
            secrets: [None, None, None],
            pending_hs: Vec::new(),
            pending_level: Level::Initial,
            pending_app: Vec::new(),
            read_secret: Vec::new(),
            write_secret: Vec::new(),
            error: None,
            peer_closed: false,
            sent_close: false,
            ccs_seen: 0,
            sent_first: false,
            early_skipped: 0,
            idle_records: 0,
        };
        if let Err(e) = c.drain_events() {
            c.error = Some(e);
        }
        c
    }

    fn suite(&self) -> CipherSuite {
        self.engine.shared().suite.expect("cipher suite negotiated")
    }

    fn local(&self, level: Level) -> Option<&Vec<u8>> {
        let (c, s) = self.secrets[idx(level)].as_ref()?;
        Some(if self.engine.is_client() { c } else { s })
    }

    fn remote(&self, level: Level) -> Option<&Vec<u8>> {
        let (c, s) = self.secrets[idx(level)].as_ref()?;
        Some(if self.engine.is_client() { s } else { c })
    }

    // ---------------------------------------------------------------- input

    /// Buffers received TLS bytes and returns how many were taken (fewer than offered, possibly
    /// zero, while earlier input waits to be processed or read).
    pub fn read_tls(&mut self, data: &[u8]) -> usize {
        if self.rx_pos > 0 {
            self.rx.drain(..self.rx_pos);
            self.rx_pos = 0;
        }
        let n = MAX_RX.saturating_sub(self.rx.len()).min(data.len());
        self.rx.extend_from_slice(&data[..n]);
        n
    }

    /// Processes buffered records. After an error every call returns the same error; the
    /// alert for it (if any) is already queued in the TLS output.
    pub fn process_new_packets(&mut self) -> Result<IoState> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if let Err(e) = self.process() {
            self.fail(e.clone());
            return Err(e);
        }
        Ok(self.io_state())
    }

    fn io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.tx.len() - self.tx_pos,
            plaintext_bytes_to_read: self.plain.len() - self.plain_pos,
            peer_has_closed: self.peer_closed,
        }
    }

    fn fail(&mut self, e: Error) {
        if self.error.is_none() {
            if let Some(a) = e.alert_to_send() {
                self.pending_hs.clear();
                let _ = self.send_record(content::ALERT, &[2, a]);
            }
            self.error = Some(e);
        }
    }

    fn process(&mut self) -> Result<()> {
        loop {
            if self.peer_closed || self.plain.len() - self.plain_pos >= MAX_PLAIN_BUFFERED {
                break;
            }
            let avail = self.rx.len() - self.rx_pos;
            if avail < 5 {
                break;
            }
            let p = self.rx_pos;
            let header: [u8; 5] = self.rx[p..p + 5].try_into().unwrap();
            let typ = header[0];
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if !(content::CHANGE_CIPHER_SPEC..=content::APPLICATION_DATA).contains(&typ) || header[1] != 3 {
                return Err(Error::proto(alert::UNEXPECTED_MESSAGE, "not a TLS record"));
            }
            if len > MAX_CIPHERTEXT {
                return Err(Error::proto(alert::RECORD_OVERFLOW, "record too large"));
            }
            if avail < 5 + len {
                break;
            }
            self.rx_pos += 5 + len;
            let body = p + 5..p + 5 + len;
            if typ == content::CHANGE_CIPHER_SPEC {
                // middlebox compatibility: tolerated, unprotected, only during the handshake
                if self.rx[body] != [1] || self.engine.shared().done || self.ccs_seen >= 2 {
                    return Err(Error::unexpected("ChangeCipherSpec"));
                }
                self.ccs_seen += 1;
                continue;
            }
            let (inner, range) = match self.read.as_mut() {
                Some(rc) => {
                    if typ == content::ALERT && len == 2 {
                        let d = self.rx[p + 6];
                        return Err(if d == alert::CLOSE_NOTIFY { Error::unexpected("unprotected close_notify") } else { Error::PeerAlert(d) });
                    }
                    if typ != content::APPLICATION_DATA {
                        return Err(Error::unexpected("unprotected record after the key change"));
                    }
                    match rc.open_record(&header, &mut self.rx[body.clone()]) {
                        Ok((t, n)) => {
                            self.early_skipped = usize::MAX;
                            (t, body.start..body.start + n)
                        }
                        // rejected 0-RTT data under the client's early key: skip it
                        Err(_) if self.skip_early(len) => continue,
                        Err(e) => return Err(e),
                    }
                }
                None => {
                    if len > MAX_PLAINTEXT {
                        return Err(Error::proto(alert::RECORD_OVERFLOW, "plaintext record too large"));
                    }
                    if typ == content::APPLICATION_DATA {
                        if self.skip_early(len) {
                            continue;
                        }
                        return Err(Error::unexpected("application data before the handshake keys"));
                    }
                    (typ, body)
                }
            };
            match inner {
                content::APPLICATION_DATA => {
                    if self.read_level != Level::OneRtt || !self.engine.shared().done && !self.engine.is_client() {
                        return Err(Error::unexpected("application data during the handshake"));
                    }
                    if range.is_empty() {
                        self.idle_record()?;
                        continue;
                    }
                    self.idle_records = 0;
                    if self.plain_pos == self.plain.len() {
                        self.plain.clear();
                        self.plain_pos = 0;
                    }
                    self.plain.extend_from_slice(&self.rx[range]);
                }
                content::HANDSHAKE => {
                    if range.is_empty() {
                        return Err(Error::unexpected("empty handshake record"));
                    }
                    let data = self.rx[range].to_vec();
                    self.handshake_data(&data)?;
                }
                content::ALERT => {
                    if range.len() != 2 {
                        return Err(Error::proto(alert::DECODE_ERROR, "malformed alert"));
                    }
                    let d = self.rx[range.start + 1];
                    match d {
                        alert::CLOSE_NOTIFY => self.peer_closed = true,
                        alert::USER_CANCELED => self.idle_record()?,
                        _ => return Err(Error::PeerAlert(d)),
                    }
                }
                _ => return Err(Error::unexpected("record content type")),
            }
        }
        if self.rx_pos == self.rx.len() {
            self.rx.clear();
            self.rx_pos = 0;
        }
        Ok(())
    }

    /// Counts a received record that delivered nothing; too many in a row is fatal.
    fn idle_record(&mut self) -> Result<()> {
        self.idle_records += 1;
        if self.idle_records > MAX_IDLE_RECORDS {
            return Err(Error::unexpected("too many consecutive empty records, warnings or KeyUpdates"));
        }
        Ok(())
    }

    /// Whether a record of `len` bytes is rejected early data to skip (server, 0-RTT offered,
    /// before the first record that decrypts with the client's handshake key, at most 64 KiB).
    fn skip_early(&mut self, len: usize) -> bool {
        const BUDGET: usize = 64 * 1024;
        let sh = self.engine.shared();
        if self.engine.is_client() || !sh.early_data_offered || self.read_level == Level::OneRtt || self.early_skipped > BUDGET - len.min(BUDGET) {
            return false;
        }
        self.early_skipped += len;
        true
    }

    fn handshake_data(&mut self, data: &[u8]) -> Result<()> {
        self.hs.push(self.read_level, data)?;
        let max = self.engine.shared().max_message;
        while let Some((level, msg)) = self.hs.next(max)? {
            if self.engine.shared().done && msg[0] == hs::KEY_UPDATE {
                self.idle_record()?;
                self.key_update_received(&msg)?;
                continue;
            }
            self.idle_records = 0;
            self.engine.handle(level, &msg)?;
            self.drain_events()?;
            let want = self.engine.shared().expect_level;
            if want != self.read_level {
                if !self.hs.is_empty() {
                    return Err(Error::unexpected("handshake data across a key change"));
                }
                let secret = self.remote(want).ok_or_else(|| Error::proto(alert::INTERNAL_ERROR, "missing read secret"))?.clone();
                self.read = Some(RecordCipher::new(self.suite(), &secret));
                self.read_level = want;
                if want == Level::OneRtt {
                    self.read_secret = secret;
                }
            }
        }
        Ok(())
    }

    fn key_update_received(&mut self, msg: &[u8]) -> Result<()> {
        if msg.len() != 5 || msg[4] > 1 {
            return Err(Error::proto(alert::DECODE_ERROR, "malformed KeyUpdate"));
        }
        if !self.hs.is_empty() {
            return Err(Error::unexpected("KeyUpdate not at a record boundary"));
        }
        let suite = self.suite();
        self.read_secret = next_traffic_secret(suite.hash(), &self.read_secret);
        self.read = Some(RecordCipher::new(suite, &self.read_secret));
        if msg[4] == 1 && !self.sent_close {
            self.send_key_update(false)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- output

    fn drain_events(&mut self) -> Result<()> {
        while let Some(ev) = self.engine.shared_mut().events.pop_front() {
            match ev {
                Event::Msg(level, m) => {
                    if level != self.pending_level {
                        self.flush_hs()?;
                    }
                    self.pending_level = level;
                    self.pending_hs.extend_from_slice(&m);
                }
                Event::Ccs => {
                    self.flush_hs()?;
                    self.tx.extend_from_slice(&[content::CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
                }
                Event::Secrets { level, client, server } => {
                    self.flush_hs()?;
                    self.secrets[idx(level)] = Some((client, server));
                    // After its Finished the server writes under its application traffic key
                    // (RFC 8446 sections 4.4.4 and 7.1): the client reads with that key from
                    // then on, so an alert for a rejected client certificate or Finished must
                    // use it, or the client sees bad_record_mac instead of the alert.
                    if level == Level::OneRtt && !self.engine.is_client() {
                        self.switch_write(Level::OneRtt)?;
                    }
                }
            }
        }
        self.flush_hs()?;
        if self.engine.shared().done {
            self.switch_write(Level::OneRtt)?;
            if !self.pending_app.is_empty() {
                let data = std::mem::take(&mut self.pending_app);
                self.write_plaintext(&data)?;
            }
        }
        Ok(())
    }

    fn switch_write(&mut self, level: Level) -> Result<()> {
        if level == self.write_level {
            return Ok(());
        }
        let secret = self.local(level).ok_or_else(|| Error::proto(alert::INTERNAL_ERROR, "missing write secret"))?.clone();
        self.write = Some(RecordCipher::new(self.suite(), &secret));
        self.write_level = level;
        if level == Level::OneRtt {
            self.write_secret = secret;
        }
        Ok(())
    }

    fn flush_hs(&mut self) -> Result<()> {
        if self.pending_hs.is_empty() {
            return Ok(());
        }
        if self.pending_level != Level::Initial || self.write.is_some() {
            self.switch_write(self.pending_level)?;
        }
        let data = std::mem::take(&mut self.pending_hs);
        for chunk in data.chunks(MAX_PLAINTEXT) {
            self.send_record(content::HANDSHAKE, chunk)?;
        }
        Ok(())
    }

    fn send_record(&mut self, typ: u8, payload: &[u8]) -> Result<()> {
        match self.write.as_mut() {
            Some(w) => w.seal_record(typ, payload, &mut self.tx),
            None => {
                let v = if self.sent_first { 3 } else { 1 };
                self.sent_first = true;
                self.tx.extend_from_slice(&[typ, 3, v]);
                codec::put_u16(&mut self.tx, payload.len() as u16);
                self.tx.extend_from_slice(payload);
                Ok(())
            }
        }
    }

    /// True if TLS bytes are waiting to be sent.
    pub fn wants_write(&self) -> bool {
        self.tx_pos < self.tx.len()
    }

    /// The TLS bytes waiting to be sent.
    pub fn tls_output(&self) -> &[u8] {
        &self.tx[self.tx_pos..]
    }

    /// Marks `n` bytes of [`tls_output`](Self::tls_output) as sent.
    pub fn consume_tls_output(&mut self, n: usize) {
        self.tx_pos = (self.tx_pos + n).min(self.tx.len());
        if self.tx_pos == self.tx.len() {
            self.tx.clear();
            self.tx_pos = 0;
        }
    }

    /// Moves all pending TLS output to `out`.
    pub fn write_tls_into(&mut self, out: &mut Vec<u8>) -> usize {
        let n = self.tx.len() - self.tx_pos;
        out.extend_from_slice(&self.tx[self.tx_pos..]);
        self.tx.clear();
        self.tx_pos = 0;
        n
    }

    // ---------------------------------------------------------------- plaintext

    /// Encrypts application data. Before the handshake completes the data is buffered (up to
    /// 1 MiB) and sent right after it.
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<usize> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if self.sent_close {
            return Err(Error::Closed);
        }
        if !self.engine.shared().done {
            if self.pending_app.len() + data.len() > MAX_PENDING_APP {
                return Err(Error::Config("too much data written before the handshake completed".into()));
            }
            self.pending_app.extend_from_slice(data);
            return Ok(data.len());
        }
        for chunk in data.chunks(MAX_PLAINTEXT) {
            if self.write.as_ref().is_some_and(|w| w.seq >= KEY_UPDATE_AFTER) {
                self.send_key_update(false)?;
            }
            self.send_record(content::APPLICATION_DATA, chunk)?;
        }
        Ok(data.len())
    }

    /// Copies decrypted application data into `buf`.
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.plain.len() - self.plain_pos);
        buf[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
        self.consume_plaintext(n);
        n
    }

    /// The decrypted application data not yet consumed.
    pub fn plaintext(&self) -> &[u8] {
        &self.plain[self.plain_pos..]
    }

    pub fn consume_plaintext(&mut self, n: usize) {
        self.plain_pos = (self.plain_pos + n).min(self.plain.len());
        if self.plain_pos == self.plain.len() {
            self.plain.clear();
            self.plain_pos = 0;
        }
    }

    /// Frees the capacity of empty buffers (call on idle keep-alive connections). Returns the
    /// bytes still held by buffers with pending data.
    pub fn release_buffers(&mut self) -> usize {
        for (buf, pos) in [(&mut self.rx, &mut self.rx_pos), (&mut self.plain, &mut self.plain_pos), (&mut self.tx, &mut self.tx_pos)] {
            if *pos == buf.len() {
                *buf = Vec::new();
                *pos = 0;
            }
        }
        if self.pending_app.is_empty() {
            self.pending_app = Vec::new();
        }
        self.rx.capacity() + self.plain.capacity() + self.tx.capacity() + self.pending_app.capacity()
    }

    // ---------------------------------------------------------------- control

    /// Queues close_notify. Further writes fail with [`Error::Closed`].
    pub fn send_close_notify(&mut self) {
        if self.sent_close || self.error.is_some() {
            return;
        }
        self.sent_close = true;
        let _ = self.send_record(content::ALERT, &[1, alert::CLOSE_NOTIFY]);
    }

    /// Sends a KeyUpdate and switches to the next write key; `request_peer` asks the peer to
    /// update its keys too.
    pub fn send_key_update(&mut self, request_peer: bool) -> Result<()> {
        if !self.engine.shared().done || self.write_level != Level::OneRtt {
            return Err(Error::Config("KeyUpdate requires a completed handshake".into()));
        }
        self.send_record(content::HANDSHAKE, &codec::handshake_msg(hs::KEY_UPDATE, &[request_peer as u8]))?;
        let suite = self.suite();
        self.write_secret = next_traffic_secret(suite.hash(), &self.write_secret);
        self.write = Some(RecordCipher::new(suite, &self.write_secret));
        Ok(())
    }

    // ---------------------------------------------------------------- state

    pub fn is_handshaking(&self) -> bool {
        !self.engine.shared().done
    }
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.engine.shared().alpn.as_deref()
    }
    pub fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        self.engine.shared().suite.filter(|_| !self.is_handshaking())
    }
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.engine.shared().group
    }
    /// Server: the SNI name sent by the client. Client: the name, if the server acknowledged it.
    pub fn server_name(&self) -> Option<&str> {
        self.engine.shared().sni.as_deref()
    }
    /// The peer's certificate chain, leaf first (restored from the ticket on resumption).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.engine.shared().peer_certs
    }
    pub fn is_resumed(&self) -> bool {
        self.engine.shared().resumed
    }
    pub fn peer_has_closed(&self) -> bool {
        self.peer_closed
    }
    /// The error that ended the connection, if any.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// RFC 8446 section 7.5 keying material exporter.
    pub fn export_keying_material(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>> {
        let em = self.engine.shared().exporter_master.as_ref().ok_or_else(|| Error::Config("handshake not complete".into()))?;
        let h = self.suite().hash();
        let secret = derive_secret(h, em, label, &h.hash(&[]));
        Ok(expand_label_vec(h, &secret, b"exporter", &h.hash(context), len))
    }

    /// Hands the record state to another record layer, such as kernel TLS (Linux `SOL_TLS`).
    /// Pending TLS output must have been sent first. KeyUpdates after the export are the new
    /// owner's job.
    pub fn export_traffic_secrets(self) -> Result<ExportedSecrets> {
        if self.is_handshaking() || self.error.is_some() || self.wants_write() || !self.hs.is_empty() {
            return Err(Error::Config("export needs an established connection with no pending output".into()));
        }
        let suite = self.suite();
        let dir = |secret: &Vec<u8>, c: &Option<RecordCipher>| {
            let (key, iv) = traffic_key_iv(suite, secret);
            DirectionalSecret { secret: secret.clone(), key, iv, seq: c.as_ref().map_or(0, |c| c.seq) }
        };
        Ok(ExportedSecrets {
            suite,
            tx: dir(&self.write_secret, &self.write),
            rx: dir(&self.read_secret, &self.read),
            unprocessed_input: self.rx[self.rx_pos..].to_vec(),
            plaintext: self.plain[self.plain_pos..].to_vec(),
        })
    }
}

/// A TLS 1.3 server connection.
#[derive(Debug)]
pub struct ServerConnection(Connection);

impl ServerConnection {
    pub fn new(cfg: Arc<ServerConfig>) -> ServerConnection {
        ServerConnection(Connection::new(Engine::Server(Box::new(ServerHs::new(cfg, None)))))
    }

    /// The underlying connection (for example to call [`Connection::export_traffic_secrets`]).
    pub fn into_inner(self) -> Connection {
        self.0
    }
}

impl Deref for ServerConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.0
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.0
    }
}

/// A TLS 1.3 client connection. The ClientHello is queued at construction.
#[cfg(feature = "client")]
#[derive(Debug)]
pub struct ClientConnection(Connection);

#[cfg(feature = "client")]
impl ClientConnection {
    /// `server_name` is verified against the certificate and sent as SNI (unless it is an IP
    /// address).
    pub fn new(cfg: Arc<ClientConfig>, server_name: &str) -> Result<ClientConnection> {
        Ok(ClientConnection(Connection::new(Engine::Client(Box::new(ClientHs::new(cfg, server_name, None)?)))))
    }

    /// The underlying connection (for example to call [`Connection::export_traffic_secrets`]).
    pub fn into_inner(self) -> Connection {
        self.0
    }
}

#[cfg(feature = "client")]
impl Deref for ClientConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.0
    }
}

#[cfg(feature = "client")]
impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.0
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::certgen::{self, CertParams};
    use crate::keys::{EcCurve, PrivateKey};
    use crate::tls::client::TEST_OFFER_EARLY_DATA;
    use crate::tls::config::CertifiedKey;
    use crate::x509::RootStore;

    fn move_bytes(from: &mut Connection, to: &mut Connection, inject: &[u8]) -> Result<()> {
        let mut data = from.tls_output().to_vec();
        from.consume_tls_output(data.len());
        // early data records ride right behind the client's flight
        data.extend_from_slice(inject);
        to.read_tls(&data);
        to.process_new_packets().map(|_| ())
    }

    #[test]
    fn rejected_early_data_is_skipped() {
        let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
        let scfg = Arc::new(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()));
        let mut roots = RootStore::empty();
        roots.add_der(&ss.cert_der).unwrap();
        let ccfg = Arc::new(ClientConfig::new(roots));
        let fake_early = [23u8, 3, 3, 0, 40].iter().copied().chain(std::iter::repeat_n(0x5a, 40)).collect::<Vec<u8>>();
        for offer in [true, false] {
            TEST_OFFER_EARLY_DATA.with(|f| f.set(offer));
            let mut c = ClientConnection::new(ccfg.clone(), "localhost").unwrap();
            TEST_OFFER_EARLY_DATA.with(|f| f.set(false));
            let mut s = ServerConnection::new(scfg.clone());
            let r = move_bytes(&mut c, &mut s, &fake_early);
            if !offer {
                // without 0-RTT the server already reads with the handshake key: fatal
                assert_eq!(r.unwrap_err().alert(), Some(alert::BAD_RECORD_MAC));
                continue;
            }
            r.unwrap();
            move_bytes(&mut s, &mut c, &[]).unwrap();
            // more 0-RTT records (now undecryptable under the handshake key) before Finished
            let mut early2 = fake_early.clone();
            early2.extend_from_slice(&fake_early);
            let mut flight = c.tls_output().to_vec();
            c.consume_tls_output(flight.len());
            flight.splice(0..0, early2);
            s.read_tls(&flight);
            s.process_new_packets().unwrap();
            assert!(!s.is_handshaking());
            // after the handshake key worked, garbage is fatal again
            s.read_tls(&fake_early);
            assert_eq!(s.process_new_packets().unwrap_err().alert(), Some(alert::BAD_RECORD_MAC));
        }
    }

    fn handshaken() -> (ClientConnection, ServerConnection) {
        let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
        let scfg = Arc::new(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()));
        let mut roots = RootStore::empty();
        roots.add_der(&ss.cert_der).unwrap();
        let mut c = ClientConnection::new(Arc::new(ClientConfig::new(roots)), "localhost").unwrap();
        let mut s = ServerConnection::new(scfg);
        for _ in 0..10 {
            move_bytes(&mut c, &mut s, &[]).unwrap();
            move_bytes(&mut s, &mut c, &[]).unwrap();
        }
        assert!(!c.is_handshaking() && !s.is_handshaking());
        (c, s)
    }

    /// Seals one record with the client's current write key, as a misbehaving peer would.
    fn forge(c: &mut ClientConnection, typ: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        c.0.write.as_mut().unwrap().seal_record(typ, payload, &mut out).unwrap();
        out
    }

    fn feed(s: &mut ServerConnection, data: &[u8]) -> Result<IoState> {
        let mut off = 0;
        loop {
            off += s.read_tls(&data[off..]);
            let r = s.process_new_packets();
            if r.is_err() || off == data.len() {
                return r;
            }
        }
    }

    #[test]
    fn empty_record_flood_is_bounded() {
        let (mut c, mut s) = handshaken();
        // up to the bound is tolerated, and real data resets the count
        let mut burst = Vec::new();
        for _ in 0..MAX_IDLE_RECORDS {
            burst.extend(forge(&mut c, content::APPLICATION_DATA, &[]));
        }
        burst.extend(forge(&mut c, content::APPLICATION_DATA, b"x"));
        for _ in 0..MAX_IDLE_RECORDS {
            burst.extend(forge(&mut c, content::APPLICATION_DATA, &[]));
        }
        feed(&mut s, &burst).unwrap();
        assert_eq!(s.plaintext(), b"x");
        // one more in a row is fatal
        let more = forge(&mut c, content::APPLICATION_DATA, &[]);
        assert_eq!(feed(&mut s, &more).unwrap_err().alert(), Some(alert::UNEXPECTED_MESSAGE));
    }

    #[test]
    fn warning_alert_flood_is_bounded() {
        let (mut c, mut s) = handshaken();
        let mut flood = Vec::new();
        for _ in 0..1000 {
            flood.extend(forge(&mut c, content::ALERT, &[1, alert::USER_CANCELED]));
        }
        assert_eq!(feed(&mut s, &flood).unwrap_err().alert(), Some(alert::UNEXPECTED_MESSAGE));
        // any other alert, warning level or not, is fatal in TLS 1.3 (RFC 8446 section 6)
        let (mut c, mut s) = handshaken();
        let a = forge(&mut c, content::ALERT, &[1, alert::UNSUPPORTED_CERTIFICATE]);
        assert_eq!(feed(&mut s, &a).unwrap_err(), Error::PeerAlert(alert::UNSUPPORTED_CERTIFICATE));
    }

    #[test]
    fn key_update_flood_is_bounded() {
        let (mut c, mut s) = handshaken();
        // each KeyUpdate with update_requested would make the server answer with its own
        let mut flood = Vec::new();
        for _ in 0..200 {
            flood.extend(forge(&mut c, content::HANDSHAKE, &[hs::KEY_UPDATE, 0, 0, 1, 1]));
            let next = next_traffic_secret(c.suite().hash(), &c.0.write_secret);
            c.0.write_secret = next.clone();
            c.0.write = Some(RecordCipher::new(c.suite(), &next));
        }
        assert_eq!(feed(&mut s, &flood).unwrap_err().alert(), Some(alert::UNEXPECTED_MESSAGE));
        // the replies stayed bounded by the limit
        assert!(s.tls_output().len() < (MAX_IDLE_RECORDS as usize + 2) * 64, "{} bytes queued", s.tls_output().len());
    }

    #[test]
    fn renegotiation_is_unexpected_message() {
        let (mut c, mut s) = handshaken();
        // a ClientHello (or any handshake message but KeyUpdate) after the handshake
        let ch = forge(&mut c, content::HANDSHAKE, &[hs::CLIENT_HELLO, 0, 0, 4, 3, 3, 0, 0]);
        assert_eq!(feed(&mut s, &ch).unwrap_err().alert(), Some(alert::UNEXPECTED_MESSAGE));
        // the client reads the alert under the server's application key
        move_bytes(&mut s, &mut c, &[]).unwrap_err();
        assert_eq!(c.error(), Some(&Error::PeerAlert(alert::UNEXPECTED_MESSAGE)));
    }

    #[test]
    fn oversized_records_are_record_overflow() {
        // protected: a ciphertext over 2^14 + 256 is refused from its header alone
        let (_, mut s) = handshaken();
        let len = MAX_CIPHERTEXT + 1;
        let hdr = [content::APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
        assert_eq!(feed(&mut s, &hdr).unwrap_err().alert(), Some(alert::RECORD_OVERFLOW));
        // unprotected: a plaintext handshake record over 2^14
        let scfg = {
            let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
            Arc::new(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()))
        };
        let mut s = ServerConnection::new(scfg);
        let len = MAX_PLAINTEXT + 1;
        let mut rec = vec![content::HANDSHAKE, 3, 1, (len >> 8) as u8, len as u8];
        rec.resize(5 + len, 0);
        assert_eq!(feed(&mut s, &rec).unwrap_err().alert(), Some(alert::RECORD_OVERFLOW));
    }

    #[test]
    fn rejected_early_data_beyond_the_budget_is_fatal() {
        let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
        let scfg = Arc::new(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()));
        let mut roots = RootStore::empty();
        roots.add_der(&ss.cert_der).unwrap();
        TEST_OFFER_EARLY_DATA.with(|f| f.set(true));
        let mut c = ClientConnection::new(Arc::new(ClientConfig::new(roots)), "localhost").unwrap();
        TEST_OFFER_EARLY_DATA.with(|f| f.set(false));
        let mut s = ServerConnection::new(scfg);
        let mut flight = c.tls_output().to_vec();
        c.consume_tls_output(flight.len());
        // 0-RTT the server did not accept: skipped up to 64 KiB (RFC 8446 section 4.2.10), then
        // treated as the forgery it is
        let rec: Vec<u8> = [23u8, 3, 3, 0x10, 0].iter().copied().chain(std::iter::repeat_n(0x5a, 0x1000)).collect();
        for _ in 0..17 {
            flight.extend_from_slice(&rec);
        }
        assert_eq!(feed(&mut s, &flight).unwrap_err().alert(), Some(alert::BAD_RECORD_MAC));
    }
}
