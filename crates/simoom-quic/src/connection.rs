//! The QUIC connection state machine (RFC 9000, RFC 9001, RFC 9002), sans-io.
//!
//! Feed received datagrams with [`Connection::recv`], send what [`Connection::poll_transmit`]
//! produces, call [`Connection::handle_timeout`] at [`Connection::poll_timeout`], and drain
//! [`Connection::poll_event`]. Streams are used through the `stream_*` methods.

use crate::coding::{put_varint_fixed, Reader};
use crate::config::Config;
use crate::crypto::{CryptoSession, HeaderKey, KeyChange, Keys, Level, NextSecrets, PacketKey};
use crate::error::*;
use crate::frame::{self, Frame};
use crate::packet::{self, PacketType, MIN_INITIAL_SIZE};
use crate::params::{Cid, TransportParams};
use crate::ranges::RangeSet;
use crate::recovery::{Recovery, SentFrame, SentPacket};
use crate::stream::{Control, StreamConfig, StreamEvent, Streams};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Why a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionError {
    /// We closed it because of a transport error.
    Transport(TransportError),
    /// The peer closed it with a transport error.
    PeerTransport { code: u64, frame_type: u64, reason: Vec<u8> },
    /// The peer closed it from the application.
    PeerApplication { code: u64, reason: Vec<u8> },
    /// We closed it from the application.
    LocalApplication { code: u64 },
    IdleTimeout,
    StatelessReset,
    /// The server supports none of our versions.
    VersionMismatch,
}

/// Application-visible events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake completed.
    Connected,
    /// The peer opened a stream.
    StreamOpened(u64),
    StreamReadable(u64),
    StreamWritable(u64),
    /// The peer sent STOP_SENDING (a RESET_STREAM was sent in reply).
    StreamStopped { id: u64, code: u64 },
    /// The peer reset the stream.
    StreamReset { id: u64, code: u64 },
    /// More locally initiated streams of this kind (`true` = bidirectional) may be opened.
    StreamsAvailable(bool),
    /// A path changed after successful validation.
    PathMigrated(SocketAddr),
    /// The connection closed; it drains for a while before [`Connection::is_drained`].
    Closed(ConnectionError),
}

/// Changes the endpoint must apply to its connection-ID routing table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointEvent {
    NewCid(Cid),
    RetireCid(Cid),
    /// A stateless reset token the peer may use against us.
    ResetToken([u8; 16]),
}

/// One or more datagrams in the caller's buffer, all to `destination`. When
/// `segment_size` is set, the buffer holds several datagrams of that size (the last may be
/// shorter): suitable for GSO, or to be split by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmit {
    pub destination: SocketAddr,
    pub size: usize,
    pub segment_size: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub sent_packets: u64,
    pub recv_packets: u64,
    pub lost_packets: u64,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub dropped_packets: u64,
    pub key_updates: u64,
    pub cwnd: u64,
    pub rtt: Duration,
    pub mtu: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Handshake,
    Established,
    Closing(Instant),
    Draining(Instant),
    Drained,
}

/// Average spacing of skipped 1-RTT packet numbers (optimistic-ACK detection).
const PN_SKIP_PERIOD: u64 = 256;

/// Bookkeeping charged per buffered out-of-order CRYPTO chunk (map entry and Vec header).
const CRYPTO_CHUNK_OVERHEAD: usize = 64;

/// Out-of-order CRYPTO reassembly for one level.
#[derive(Default)]
struct CryptoIn {
    read: u64,
    ooo: BTreeMap<u64, Vec<u8>>,
    ooo_bytes: usize,
}

#[derive(Default)]
struct Space {
    keys: Option<Keys>,
    crypto_out: Vec<u8>,
    crypto_sent: u64,
    crypto_retx: RangeSet,
    crypto_in: CryptoIn,
    recv: RangeSet,
    ack_floor: u64,
    largest_recv: Option<(u64, Instant)>,
    unacked_eliciting: u32,
    ack_now: bool,
    ack_deadline: Option<Instant>,
    probes: u8,
    discarded: bool,
}

impl Space {
    fn has_crypto(&self) -> bool {
        !self.crypto_retx.is_empty() || self.crypto_sent < self.crypto_out.len() as u64
    }
}

struct OneRtt {
    local: Box<dyn PacketKey>,
    remote: Box<dyn PacketKey>,
    local_hp: Box<dyn HeaderKey>,
    remote_hp: Box<dyn HeaderKey>,
    secrets: Box<dyn NextSecrets>,
    phase: bool,
    next: Option<(Box<dyn PacketKey>, Box<dyn PacketKey>)>,
    prev_remote: Option<(Box<dyn PacketKey>, Option<Instant>)>,
    phase_first_sent: u64,
    phase_first_recv: Option<u64>,
    update_allowed: bool,
    sealed: u64,
}

struct Path {
    remote: SocketAddr,
    validated: bool,
    recv_bytes: u64,
    sent_bytes: u64,
    challenge: Option<([u8; 8], Instant)>,
    challenge_pending: bool,
}

impl Path {
    fn new(remote: SocketAddr, validated: bool) -> Self {
        Path { remote, validated, recv_bytes: 0, sent_bytes: 0, challenge: None, challenge_pending: false }
    }
    /// Bytes we may still send before address validation (RFC 9000 §8.1).
    fn budget(&self) -> usize {
        if self.validated {
            usize::MAX
        } else {
            (self.recv_bytes * 3).saturating_sub(self.sent_bytes) as usize
        }
    }
}

struct LocalCid {
    seq: u64,
    cid: Cid,
    retired: bool,
}

struct RemoteCid {
    seq: u64,
    cid: Cid,
    token: Option<[u8; 16]>,
}

/// A packet written into the datagram buffer but not yet sealed.
struct Building {
    space: usize,
    start: usize,
    len_at: Option<usize>,
    pn_at: usize,
    pn: u64,
    pn_len: usize,
    eliciting: bool,
    frames: Vec<SentFrame>,
    mtu_probe: bool,
}

pub struct Connection {
    cfg: Arc<Config>,
    is_server: bool,
    version: u32,
    state: State,
    session: Box<dyn CryptoSession>,
    write_level: Level,
    spaces: [Space; 3],
    one_rtt: Option<OneRtt>,
    handshake_complete: bool,
    handshake_confirmed: bool,
    peer_params: Option<TransportParams>,
    streams: Streams,
    recovery: Recovery,
    path: Path,
    prev_path: Option<Path>,
    path_responses: VecDeque<([u8; 8], SocketAddr)>,
    local_cids: Vec<LocalCid>,
    next_local_seq: u64,
    remote_cids: Vec<RemoteCid>,
    remote_cid_seq: u64,
    retire_prior_to: u64,
    pending_retire: VecDeque<u64>,
    pending_new_cids: VecDeque<u64>,
    /// The client's first destination CID (server: from the first Initial).
    orig_dcid: Cid,
    /// Client: the DCID chosen by the server is adopted once.
    dcid_switched: bool,
    retry_scid: Option<Cid>,
    peer_initial_scid: Option<Cid>,
    token: Vec<u8>,
    new_token: Option<Vec<u8>>,
    new_token_pending: bool,
    received_new_token: Option<Vec<u8>>,
    handshake_done_pending: bool,
    ping_pending: bool,
    /// Test hook: raw frame bytes written verbatim into the next 1-RTT packet.
    raw_frames: Vec<u8>,
    close: Option<(u64, Option<u64>, Vec<u8>)>,
    close_sent_count: u32,
    close_recv_count: u32,
    error: Option<ConnectionError>,
    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEvent>,
    idle_timeout: Duration,
    last_activity: Instant,
    eliciting_since_recv: bool,
    mds: usize,
    mtu_probe: Option<(usize, u8)>,
    mtu_probe_inflight: bool,
    probe_allowed: bool,
    pacing_until: Option<Instant>,
    failed_decrypts: u64,
    any_packet_processed: bool,
    stats: Stats,
    /// The connection ID the Initial keys are derived from (RFC 9001 §5.2).
    initial_dcid: Cid,
    /// Server with more than one version: the TLS session starts once the whole ClientHello
    /// is in, so its version (RFC 9368) is known. Holds (odcid, retry_scid) until then.
    deferred: Option<(Cid, Option<Cid>)>,
    /// The ClientHello bytes buffered while `deferred` is set.
    hello: Vec<u8>,
}

fn space_of(ty: PacketType) -> usize {
    match ty {
        PacketType::Initial => 0,
        PacketType::Handshake => 1,
        _ => 2,
    }
}

impl Connection {
    fn new(
        cfg: Arc<Config>,
        is_server: bool,
        version: u32,
        now: Instant,
        remote: SocketAddr,
        session: Box<dyn CryptoSession>,
        local_cid: Cid,
        remote_cid: Cid,
        orig_dcid: Cid,
    ) -> Self {
        let t = &cfg.transport;
        let streams = Streams::new(
            is_server,
            StreamConfig {
                max_streams_bidi: t.max_streams_bidi,
                max_streams_uni: t.max_streams_uni,
                stream_window_bidi_local: t.stream_window_bidi_local,
                stream_window_bidi_remote: t.stream_window_bidi_remote,
                stream_window_uni: t.stream_window_uni,
                conn_window: t.max_data,
                send_buffer: t.send_buffer,
            },
        );
        let mut spaces: [Space; 3] = Default::default();
        spaces[0].keys = Some(cfg.provider.initial_keys(version, &orig_dcid, is_server));
        let idle = t.max_idle_timeout;
        Connection {
            is_server,
            version,
            state: State::Handshake,
            session,
            write_level: Level::Initial,
            spaces,
            one_rtt: None,
            handshake_complete: false,
            handshake_confirmed: false,
            peer_params: None,
            streams,
            recovery: Recovery::new(MIN_INITIAL_SIZE as u64),
            path: Path::new(remote, !is_server),
            prev_path: None,
            path_responses: VecDeque::new(),
            local_cids: vec![LocalCid { seq: 0, cid: local_cid, retired: false }],
            next_local_seq: 1,
            remote_cids: vec![RemoteCid { seq: 0, cid: remote_cid, token: None }],
            remote_cid_seq: 0,
            retire_prior_to: 0,
            pending_retire: VecDeque::new(),
            pending_new_cids: VecDeque::new(),
            orig_dcid,
            dcid_switched: is_server,
            retry_scid: None,
            peer_initial_scid: None,
            token: Vec::new(),
            new_token: None,
            new_token_pending: false,
            received_new_token: None,
            handshake_done_pending: false,
            ping_pending: false,
            raw_frames: Vec::new(),
            close: None,
            close_sent_count: 0,
            close_recv_count: 0,
            error: None,
            events: VecDeque::new(),
            endpoint_events: VecDeque::new(),
            idle_timeout: idle,
            last_activity: now,
            eliciting_since_recv: false,
            mds: MIN_INITIAL_SIZE,
            mtu_probe: None,
            mtu_probe_inflight: false,
            probe_allowed: false,
            pacing_until: None,
            failed_decrypts: 0,
            any_packet_processed: false,
            stats: Stats::default(),
            initial_dcid: orig_dcid,
            deferred: None,
            hello: Vec::new(),
            cfg,
        }
    }

    fn local_params(&self, odcid: Option<Cid>, retry_scid: Option<Cid>) -> Vec<u8> {
        let t = &self.cfg.transport;
        let local = self.local_cids[0].cid;
        let p = TransportParams {
            original_destination_connection_id: odcid,
            max_idle_timeout: t.max_idle_timeout.as_millis() as u64,
            stateless_reset_token: if self.is_server { Some(self.cfg.reset_token(&local)) } else { None },
            max_udp_payload_size: t.max_udp_payload_size,
            initial_max_data: t.max_data,
            initial_max_stream_data_bidi_local: t.stream_window_bidi_local,
            initial_max_stream_data_bidi_remote: t.stream_window_bidi_remote,
            initial_max_stream_data_uni: t.stream_window_uni,
            initial_max_streams_bidi: t.max_streams_bidi,
            initial_max_streams_uni: t.max_streams_uni,
            ack_delay_exponent: t.ack_delay_exponent,
            max_ack_delay: t.max_ack_delay.as_millis() as u64,
            disable_active_migration: t.disable_active_migration,
            preferred_address: None,
            active_connection_id_limit: t.active_connection_id_limit,
            initial_source_connection_id: Some(local),
            retry_source_connection_id: retry_scid,
            // Compatible version negotiation (RFC 9368): only when more than one version is
            // configured, so a v1-only endpoint sends exactly what it did before.
            version_information: (self.cfg.versions.len() > 1).then(|| (self.version, self.cfg.versions.clone())),
        };
        let mut b = Vec::with_capacity(128);
        p.encode(&mut b);
        b
    }

    /// Starts a client connection to `remote`. `token` is a NEW_TOKEN value from an
    /// earlier connection, or empty.
    pub fn connect(
        cfg: Arc<Config>,
        now: Instant,
        remote: SocketAddr,
        server_name: &str,
        token: &[u8],
    ) -> Result<Self, TransportError> {
        let mut scid = [0u8; 20];
        let mut dcid = [0u8; 8];
        cfg.provider.fill_random(&mut scid[..cfg.cid_len]);
        cfg.provider.fill_random(&mut dcid);
        let local = Cid::new(&scid[..cfg.cid_len]);
        let dcid = Cid::new(&dcid);
        let version = cfg.versions[0];
        let placeholder: Box<dyn CryptoSession> = Box::new(Placeholder);
        let mut c = Connection::new(cfg.clone(), false, version, now, remote, placeholder, local, dcid, dcid);
        let tp = c.local_params(None, None);
        c.session = cfg.provider.client_session(version, server_name, tp)?;
        c.token = token.to_vec();
        c.endpoint_events.push_back(EndpointEvent::NewCid(local));
        c.drive_crypto()?;
        Ok(c)
    }

    /// Creates a server connection for a client Initial (called by the endpoint).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accept(
        cfg: Arc<Config>,
        now: Instant,
        remote: SocketAddr,
        version: u32,
        local_cid: Cid,
        client_dcid: Cid,
        client_scid: Cid,
        odcid: Cid,
        retry_scid: Option<Cid>,
        validated: bool,
    ) -> Result<Self, TransportError> {
        let placeholder: Box<dyn CryptoSession> = Box::new(Placeholder);
        let mut c = Connection::new(cfg.clone(), true, version, now, remote, placeholder, local_cid, client_scid, client_dcid);
        if cfg.versions.len() > 1 {
            // The version may still change (RFC 9368): start TLS after the ClientHello.
            c.deferred = Some((odcid, retry_scid));
        } else {
            let tp = c.local_params(Some(odcid), retry_scid);
            c.session = cfg.provider.server_session(version, tp)?;
        }
        c.orig_dcid = odcid;
        c.retry_scid = retry_scid;
        c.peer_initial_scid = Some(client_scid);
        c.path.validated = validated;
        Ok(c)
    }

    // ---------------------------------------------------------------- accessors

    pub fn is_server(&self) -> bool {
        self.is_server
    }
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }
    pub fn is_handshaking(&self) -> bool {
        self.state == State::Handshake
    }
    /// Closing or draining (no new streams or data).
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closing(_) | State::Draining(_) | State::Drained)
    }
    /// The connection can be dropped.
    pub fn is_drained(&self) -> bool {
        self.state == State::Drained
    }
    pub fn error(&self) -> Option<&ConnectionError> {
        self.error.as_ref()
    }
    pub fn alpn(&self) -> Option<&[u8]> {
        self.session.alpn_protocol()
    }
    pub fn remote_address(&self) -> SocketAddr {
        self.path.remote
    }
    pub fn path_validated(&self) -> bool {
        self.path.validated
    }
    pub fn peer_params(&self) -> Option<&TransportParams> {
        self.peer_params.as_ref()
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn stats(&self) -> Stats {
        let mut s = self.stats;
        s.cwnd = self.recovery.cc.cwnd;
        s.rtt = self.recovery.rtt.smoothed;
        s.mtu = self.mds;
        s
    }
    /// Our connection IDs currently active.
    pub fn local_cids(&self) -> impl Iterator<Item = Cid> + '_ {
        self.local_cids.iter().filter(|c| !c.retired).map(|c| c.cid)
    }
    /// The destination connection ID in use.
    pub fn remote_cid(&self) -> Cid {
        self.remote_cids[0].cid
    }
    /// The original destination connection ID (client's first DCID).
    pub fn original_dcid(&self) -> Cid {
        self.orig_dcid
    }
    /// Client: a token received in NEW_TOKEN, for a later connection.
    pub fn new_token(&self) -> Option<&[u8]> {
        self.received_new_token.as_deref()
    }
    pub fn poll_event(&mut self) -> Option<Event> {
        self.pull_stream_events();
        self.events.pop_front()
    }
    pub fn poll_endpoint_event(&mut self) -> Option<EndpointEvent> {
        self.endpoint_events.pop_front()
    }
    /// Streams currently tracked.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    fn pull_stream_events(&mut self) {
        while let Some(e) = self.streams.events.pop_front() {
            self.events.push_back(match e {
                StreamEvent::Opened(id) => Event::StreamOpened(id),
                StreamEvent::Readable(id) => Event::StreamReadable(id),
                StreamEvent::Writable(id) => Event::StreamWritable(id),
                StreamEvent::Stopped(id, code) => Event::StreamStopped { id, code },
                StreamEvent::Reset(id, code) => Event::StreamReset { id, code },
                StreamEvent::Available(b) => Event::StreamsAvailable(b),
            });
        }
    }

    // ---------------------------------------------------------------- streams

    fn usable(&self) -> Result<(), StreamError> {
        if self.is_closed() {
            Err(StreamError::ConnectionClosed)
        } else {
            Ok(())
        }
    }

    /// Opens a bidirectional stream.
    pub fn open_bi(&mut self) -> Result<u64, StreamError> {
        self.usable()?;
        self.streams.open(true)
    }
    /// Opens a unidirectional stream.
    pub fn open_uni(&mut self) -> Result<u64, StreamError> {
        self.usable()?;
        self.streams.open(false)
    }
    /// Queues data; returns the number of bytes accepted (backpressure: fewer than given).
    pub fn stream_send(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize, StreamError> {
        self.usable()?;
        self.streams.write(id, data, fin)
    }
    /// Ends the send side.
    pub fn stream_finish(&mut self, id: u64) -> Result<(), StreamError> {
        self.usable()?;
        self.streams.write(id, &[], true).map(|_| ())
    }
    /// Reads data; returns (bytes, fin).
    pub fn stream_recv(&mut self, id: u64, out: &mut [u8]) -> Result<(usize, bool), StreamError> {
        self.usable()?;
        self.streams.read(id, out)
    }
    pub fn stream_reset(&mut self, id: u64, code: u64) -> Result<(), StreamError> {
        self.usable()?;
        self.streams.reset(id, code)
    }
    pub fn stream_stop(&mut self, id: u64, code: u64) -> Result<(), StreamError> {
        self.usable()?;
        self.streams.stop(id, code)
    }
    /// Bytes `stream_send` would accept now.
    pub fn stream_writable(&self, id: u64) -> Option<u64> {
        self.streams.writable(id)
    }
    /// Bytes written to the stream but not yet acknowledged.
    pub fn stream_unacked(&self, id: u64) -> Option<u64> {
        self.streams.unacked(id)
    }
    pub fn stream_exists(&self, id: u64) -> bool {
        self.streams.contains(id)
    }
    /// Sends a PING (keep-alive).
    pub fn ping(&mut self) {
        self.ping_pending = true;
    }

    /// Test hook for adversarial tests: the largest 1-RTT packet number sent so far. Not part
    /// of the stable API.
    #[doc(hidden)]
    pub fn largest_sent_packet_number(&self) -> Option<u64> {
        let sp = &self.recovery.spaces[2];
        let last = sp.next_pn.checked_sub(1)?;
        if sp.skipped.back() == Some(&last) {
            last.checked_sub(1)
        } else {
            Some(last)
        }
    }

    /// Test hook for adversarial tests: `frames` (already encoded) are written verbatim into
    /// the next 1-RTT packet, so a misbehaving peer can be played through the real packet
    /// protection. Not part of the stable API.
    #[doc(hidden)]
    pub fn send_raw_frames(&mut self, frames: &[u8]) {
        self.raw_frames.extend_from_slice(frames);
        self.ping_pending = true;
    }

    // ---------------------------------------------------------------- closing

    /// Closes the connection with an application error code.
    pub fn close(&mut self, now: Instant, code: u64, reason: &[u8]) {
        if self.is_closed() {
            return;
        }
        self.close = Some((code, None, reason.to_vec()));
        self.error = Some(ConnectionError::LocalApplication { code });
        self.enter_closing(now);
    }

    fn close_transport(&mut self, now: Instant, e: TransportError) {
        if self.is_closed() {
            return;
        }
        self.close = Some((e.code, Some(e.frame_type), e.reason.as_bytes().to_vec()));
        self.error = Some(ConnectionError::Transport(e.clone()));
        self.events.push_back(Event::Closed(ConnectionError::Transport(e)));
        self.enter_closing(now);
    }

    fn enter_closing(&mut self, now: Instant) {
        let until = now + self.recovery.pto(2) * 3;
        self.state = State::Closing(until);
        self.close_sent_count = 0;
        self.close_recv_count = 0;
        self.ping_pending = false;
    }

    fn enter_draining(&mut self, now: Instant, err: ConnectionError) {
        if matches!(self.state, State::Draining(_) | State::Drained) {
            return;
        }
        let already_closing = matches!(self.state, State::Closing(_));
        self.state = State::Draining(now + self.recovery.pto(2) * 3);
        if !already_closing {
            self.error = Some(err.clone());
            self.events.push_back(Event::Closed(err));
        }
    }

    fn drain_now(&mut self, err: ConnectionError) {
        if self.state == State::Drained {
            return;
        }
        if !self.is_closed() {
            self.error = Some(err.clone());
            self.events.push_back(Event::Closed(err));
        }
        self.state = State::Drained;
        for c in &self.local_cids {
            if !c.retired {
                self.endpoint_events.push_back(EndpointEvent::RetireCid(c.cid));
            }
        }
    }

    // ---------------------------------------------------------------- receiving

    /// Processes one received datagram (may hold coalesced packets). `data` is decrypted in
    /// place.
    pub fn recv(&mut self, now: Instant, remote: SocketAddr, data: &mut [u8]) {
        if self.state == State::Drained {
            return;
        }
        let len = data.len();
        self.stats.recv_bytes += len as u64;
        if remote == self.path.remote {
            self.path.recv_bytes += len as u64;
        } else if let Some(p) = self.prev_path.as_mut().filter(|p| p.remote == remote) {
            p.recv_bytes += len as u64;
        }
        let mut start = 0;
        let mut processed_any = false;
        let mut first_dcid: Option<Cid> = None;
        while start < len {
            let cid_len = self.local_cids[0].cid.len();
            let Some(h) = packet::parse_header(data, start, cid_len) else { break };
            if let Some(f) = first_dcid {
                // Coalesced packets must share the connection ID (RFC 9000 §12.2).
                if data[h.dcid.clone()] != f[..] {
                    break;
                }
            } else {
                first_dcid = Some(Cid::new(&data[h.dcid.clone()]));
            }
            let end = h.end;
            match h.ty {
                PacketType::VersionNegotiation => {
                    self.on_version_negotiation(now, &data[h.token.clone()]);
                    return;
                }
                PacketType::Retry => {
                    self.on_retry(now, data, &h);
                    return;
                }
                PacketType::ZeroRtt => {
                    // 0-RTT is not supported: discard.
                    self.stats.dropped_packets += 1;
                    start = end;
                    continue;
                }
                _ => {}
            }
            if h.ty != PacketType::OneRtt && h.version != self.version && !self.follow_version(&h) {
                break;
            }
            match self.recv_packet(now, remote, data, start, &h) {
                Ok(true) => processed_any = true,
                Ok(false) => self.stats.dropped_packets += 1,
                Err(e) => {
                    self.close_transport(now, e);
                    return;
                }
            }
            if self.state == State::Drained {
                return;
            }
            start = end;
        }
        if !processed_any {
            self.check_stateless_reset(now, data);
        }
    }

    fn check_stateless_reset(&mut self, _now: Instant, data: &[u8]) {
        if data.len() < packet::MIN_RESET_SIZE || data[0] & 0x80 != 0 {
            return;
        }
        let tail = &data[data.len() - 16..];
        let hit = self.remote_cids.iter().any(|c| c.token.is_some_and(|t| crate::crypto::ct_eq(&t, tail)));
        if hit {
            self.drain_now(ConnectionError::StatelessReset);
        }
    }

    /// Client: the server answered our first Initial in another configured, compatible
    /// version (compatible version negotiation, RFC 9368 §2.3); continue in it.
    fn follow_version(&mut self, h: &packet::Header) -> bool {
        let ok = !self.is_server
            && !self.any_packet_processed
            && h.ty == PacketType::Initial
            && self.cfg.versions.contains(&h.version)
            && crate::vn::compatible(self.version, h.version);
        if ok {
            self.version = h.version;
            self.spaces[0].keys = Some(self.cfg.provider.initial_keys(h.version, &self.initial_dcid, false));
            self.session.set_version(h.version);
        }
        ok
    }

    fn on_version_negotiation(&mut self, now: Instant, list: &[u8]) {
        if self.is_server || self.any_packet_processed {
            return;
        }
        let mut r = Reader::new(list);
        while let Some(v) = r.u32() {
            if v == self.version {
                return; // Must be ignored (RFC 9000 §6.2).
            }
        }
        let _ = now;
        self.drain_now(ConnectionError::VersionMismatch);
    }

    fn on_retry(&mut self, _now: Instant, data: &[u8], h: &packet::Header) {
        if self.is_server || self.any_packet_processed || self.retry_scid.is_some() {
            return;
        }
        let scid = Cid::new(&data[h.scid.clone()]);
        let token = &data[h.token.clone()];
        if token.is_empty() || scid[..] == self.remote_cids[0].cid[..] {
            return;
        }
        let tag_at = data.len() - 16;
        let expect = packet::retry_tag(&*self.cfg.provider, self.version, &self.orig_dcid, &data[..tag_at]);
        if !crate::crypto::ct_eq(&expect, &data[tag_at..]) {
            return;
        }
        self.retry_scid = Some(scid);
        self.remote_cids[0].cid = scid;
        self.token = token.to_vec();
        self.spaces[0].keys = Some(self.cfg.provider.initial_keys(self.version, &scid, false));
        self.initial_dcid = scid;
        // Everything sent in Initial packets is resent with the token.
        let s = &mut self.spaces[0];
        s.crypto_retx.clear();
        s.crypto_sent = 0;
        self.recovery.discard(0);
    }

    /// Returns Ok(false) if the packet was dropped.
    fn recv_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        data: &mut [u8],
        start: usize,
        h: &packet::Header,
    ) -> Result<bool, TransportError> {
        let space = space_of(h.ty);
        if self.spaces[space].discarded {
            return Ok(false);
        }
        if space < 2 && self.spaces[space].keys.is_none() {
            return Ok(false);
        }
        if space == 2 && self.one_rtt.is_none() {
            return Ok(false);
        }
        // Header protection.
        let hp: &dyn HeaderKey = if space == 2 {
            &*self.one_rtt.as_ref().unwrap().remote_hp
        } else {
            &*self.spaces[space].keys.as_ref().unwrap().remote.header
        };
        let first_before = data[start];
        let Some((tpn, pn_len)) = packet::unprotect(data, start, h.pn_offset, h.end, hp) else {
            return Ok(false);
        };
        let largest = self.spaces[space].largest_recv.map(|x| x.0);
        let pn = packet::decode_pn(largest, tpn, pn_len);
        let hdr_end = h.pn_offset + pn_len;
        let first = data[start];
        let (head, rest) = data[start..h.end].split_at_mut(hdr_end - start);
        let decrypted = if space == 2 {
            let phase = first & 0x04 != 0;
            self.open_one_rtt(now, pn, phase, head, rest)
        } else {
            self.spaces[space].keys.as_ref().unwrap().remote.packet.open(pn, head, rest).ok()
        };
        let Some(plen) = decrypted else {
            data[start] = first_before;
            self.failed_decrypts += 1;
            let limit = self.one_rtt.as_ref().map(|k| k.remote.integrity_limit()).unwrap_or(u64::MAX);
            if self.failed_decrypts >= limit {
                return Err(TransportError::new(AEAD_LIMIT_REACHED, "integrity limit reached"));
            }
            return Ok(false);
        };
        // Reserved bits must be zero once protection is removed (RFC 9000 §17.2, §17.3.1).
        let reserved = if first & 0x80 != 0 { first & 0x0c } else { first & 0x18 };
        if reserved != 0 {
            return Err(TransportError::proto("reserved header bits set"));
        }
        // Duplicate detection.
        let sp = &self.spaces[space];
        if pn < sp.ack_floor || sp.recv.contains(pn) {
            return Ok(false);
        }
        self.any_packet_processed = true;
        self.stats.recv_packets += 1;

        // Client: adopt the server's chosen connection ID from its first Initial/Handshake.
        if !self.is_server && !self.dcid_switched && space < 2 {
            self.dcid_switched = true;
            let scid = Cid::new(&data[h.scid.clone()]);
            self.remote_cids[0].cid = scid;
            self.peer_initial_scid = Some(scid);
        }
        let dcid = Cid::new(&data[h.dcid.clone()]);
        let payload_start = hdr_end;
        let payload_end = hdr_end + plen;
        let payload: &[u8] = &data[payload_start..payload_end];
        let ptype = h.ty;
        let (eliciting, non_probing) = self.process_frames(now, remote, ptype, space, payload, &dcid)?;

        // Record for acknowledgement.
        let sp = &mut self.spaces[space];
        let out_of_order = sp.largest_recv.is_some_and(|(l, _)| pn != l + 1);
        sp.recv.insert(pn, pn + 1);
        sp.recv.truncate_low(self.cfg.transport.max_ack_ranges);
        if sp.largest_recv.is_none_or(|(l, _)| pn > l) {
            sp.largest_recv = Some((pn, now));
        }
        if eliciting {
            sp.unacked_eliciting += 1;
            if space < 2 || out_of_order || sp.unacked_eliciting >= self.cfg.transport.ack_eliciting_threshold {
                sp.ack_now = true;
            } else if sp.ack_deadline.is_none() {
                sp.ack_deadline = Some(now + self.cfg.transport.max_ack_delay);
            }
        }
        // Server: a Handshake packet proves the client's address; Initial keys go.
        if self.is_server && space == 1 {
            self.path.validated = true;
            self.discard_space(0);
        }
        // Migration (RFC 9000 §9): a non-probing packet with the highest number from a new
        // address moves the connection there.
        if space == 2 && remote != self.path.remote && non_probing {
            let highest = self.spaces[2].largest_recv.is_some_and(|(l, _)| l == pn);
            if highest && self.is_server && self.handshake_confirmed {
                self.migrate(now, remote);
            }
        }
        if self.is_closed() {
            if let State::Closing(_) = self.state {
                // Answer packets in the closing state with CONNECTION_CLOSE, at a falling rate.
                self.close_recv_count += 1;
            }
            return Ok(true);
        }
        self.last_activity = now;
        self.eliciting_since_recv = false;
        Ok(true)
    }

    fn open_one_rtt(&mut self, now: Instant, pn: u64, phase: bool, head: &[u8], rest: &mut [u8]) -> Option<usize> {
        let k = self.one_rtt.as_mut().unwrap();
        if phase == k.phase {
            let n = k.remote.open(pn, head, rest).ok()?;
            if k.phase_first_recv.is_none_or(|f| pn < f) {
                if k.phase_first_recv.is_none() {
                    // The peer moved to the phase we started: the old key can go soon.
                    let pto3 = self.recovery.pto(2) * 3;
                    if let Some(p) = k.prev_remote.as_mut() {
                        p.1.get_or_insert(now + pto3);
                    }
                }
                k.phase_first_recv = Some(pn);
            }
            return Some(n);
        }
        // Old phase: a reordered packet from before the last update, or the peer has not
        // yet seen the update we started.
        if let Some((prev, _)) = &k.prev_remote {
            if k.phase_first_recv.is_none_or(|f| pn < f) {
                return prev.open(pn, head, rest).ok();
            }
        }
        // New phase: the peer updated keys (RFC 9001 §6.2).
        if k.next.is_none() {
            k.next = Some(k.secrets.next_packet_keys());
        }
        let n = k.next.as_ref().unwrap().1.open(pn, head, rest).ok()?;
        if k.phase_first_recv.is_some_and(|f| pn < f) {
            return None;
        }
        let pto3 = self.recovery.pto(2) * 3;
        let k = self.one_rtt.as_mut().unwrap();
        let (nl, nr) = k.next.take().unwrap();
        let old_remote = std::mem::replace(&mut k.remote, nr);
        k.local = nl;
        k.prev_remote = Some((old_remote, Some(now + pto3)));
        k.phase = !k.phase;
        k.phase_first_recv = Some(pn);
        k.phase_first_sent = self.recovery.spaces[2].next_pn;
        k.update_allowed = false;
        k.sealed = 0;
        self.stats.key_updates += 1;
        Some(n)
    }

    /// Starts a key update (RFC 9001 §6.1). Returns false when one is not allowed yet.
    pub fn initiate_key_update(&mut self) -> bool {
        if !self.handshake_confirmed {
            return false;
        }
        let next_pn = self.recovery.spaces[2].next_pn;
        let Some(k) = self.one_rtt.as_mut() else { return false };
        if !k.update_allowed {
            return false;
        }
        if k.next.is_none() {
            k.next = Some(k.secrets.next_packet_keys());
        }
        let (nl, nr) = k.next.take().unwrap();
        let old_remote = std::mem::replace(&mut k.remote, nr);
        k.local = nl;
        // The old remote key stays until the peer has moved to the new phase.
        k.prev_remote = Some((old_remote, None));
        k.phase = !k.phase;
        k.phase_first_recv = None;
        k.phase_first_sent = next_pn;
        k.update_allowed = false;
        k.sealed = 0;
        self.stats.key_updates += 1;
        true
    }

    fn process_frames(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ptype: PacketType,
        space: usize,
        payload: &[u8],
        dcid: &Cid,
    ) -> Result<(bool, bool), TransportError> {
        if payload.is_empty() {
            return Err(TransportError::proto("packet without frames"));
        }
        let mut r = Reader::new(payload);
        let mut eliciting = false;
        let mut non_probing = false;
        while !r.is_empty() {
            let (ty, f) = frame::parse(&mut r)?;
            let allowed = match ptype {
                PacketType::Initial | PacketType::Handshake => matches!(
                    f,
                    Frame::Padding | Frame::Ping | Frame::Ack { .. } | Frame::Crypto { .. }
                ) || matches!(f, Frame::ConnectionClose { frame_type: Some(_), .. }),
                _ => true,
            };
            if !allowed {
                return Err(TransportError::frame(PROTOCOL_VIOLATION, ty, "frame not allowed in this packet type"));
            }
            eliciting |= f.is_ack_eliciting();
            non_probing |= !f.is_probing();
            if self.is_closed() {
                // In the closing or draining state only CONNECTION_CLOSE matters.
                if let Frame::ConnectionClose { code, frame_type, reason } = f {
                    self.on_peer_close(now, code, frame_type, reason);
                }
                continue;
            }
            self.process_frame(now, remote, space, ty, f, dcid)?;
            if self.state == State::Drained {
                break;
            }
        }
        Ok((eliciting, non_probing))
    }

    fn on_peer_close(&mut self, now: Instant, code: u64, frame_type: Option<u64>, reason: &[u8]) {
        let reason = reason[..reason.len().min(256)].to_vec();
        let err = match frame_type {
            Some(frame_type) => ConnectionError::PeerTransport { code, frame_type, reason },
            None => ConnectionError::PeerApplication { code, reason },
        };
        self.enter_draining(now, err);
    }

    fn process_frame(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        space: usize,
        ty: u64,
        f: Frame<'_>,
        dcid: &Cid,
    ) -> Result<(), TransportError> {
        let server_only = |is_server: bool| {
            if is_server {
                Err(TransportError::frame(PROTOCOL_VIOLATION, ty, "frame only a server may send"))
            } else {
                Ok(())
            }
        };
        match f {
            Frame::Padding | Frame::Ping => {}
            Frame::Ack { ranges, delay, .. } => {
                let exp = self.peer_params.as_ref().map_or(3, |p| p.ack_delay_exponent);
                let delay = Duration::from_micros(delay.checked_shl(exp as u32).unwrap_or(u64::MAX).min(1 << 40));
                let res = self.recovery.on_ack(space, &ranges, delay, now, self.handshake_confirmed)?;
                for p in res.acked {
                    self.on_packet_acked(space, p);
                }
                self.on_packets_lost(space, res.lost);
            }
            Frame::Crypto { offset, data } => self.on_crypto(space, offset, data)?,
            Frame::Stream { id, offset, data, fin } => self.streams.on_stream(id, offset, data, fin)?,
            Frame::ResetStream { id, code, final_size } => self.streams.on_reset(id, code, final_size)?,
            Frame::StopSending { id, code } => self.streams.on_stop_sending(id, code)?,
            Frame::MaxData(m) => self.streams.on_max_data(m),
            Frame::MaxStreamData { id, max } => self.streams.on_max_stream_data(id, max)?,
            Frame::MaxStreams { bidi, max } => self.streams.on_max_streams(bidi, max),
            Frame::DataBlocked(_) => {}
            Frame::StreamDataBlocked { id, .. } => self.streams.on_stream_data_blocked(id)?,
            Frame::StreamsBlocked { bidi, limit } => self.streams.on_streams_blocked(bidi, limit),
            Frame::NewToken { token } => {
                server_only(self.is_server)?;
                self.received_new_token = Some(token.to_vec());
            }
            Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token } => {
                self.on_new_cid(seq, retire_prior_to, cid, reset_token)?
            }
            Frame::RetireConnectionId { seq } => self.on_retire_cid(seq, dcid)?,
            Frame::PathChallenge(d) => {
                if self.path_responses.len() < 8 {
                    self.path_responses.push_back((d, remote));
                }
            }
            Frame::PathResponse(d) => self.on_path_response(now, d),
            Frame::ConnectionClose { code, frame_type, reason } => self.on_peer_close(now, code, frame_type, reason),
            Frame::HandshakeDone => {
                server_only(self.is_server)?;
                if !self.handshake_confirmed {
                    self.handshake_confirmed = true;
                    self.discard_space(1);
                    self.start_mtu_probe();
                }
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- crypto

    fn on_crypto(&mut self, space: usize, offset: u64, data: &[u8]) -> Result<(), TransportError> {
        let cap = self.cfg.transport.crypto_buffer;
        let level = Level::ALL[space];
        let ci = &mut self.spaces[space].crypto_in;
        let end = offset + data.len() as u64;
        if end <= ci.read {
            // A server that sees the client's ClientHello again during the handshake knows
            // the client's PTO fired, so its own flight was most likely lost: resend it now
            // rather than wait for its own (backed-off) PTO. Still subject to the
            // anti-amplification limit and congestion control.
            if self.is_server && space == 0 && !data.is_empty() && !self.handshake_complete {
                self.resend_handshake_flight();
            }
            return Ok(());
        }
        if offset > ci.read {
            // Each buffered chunk is charged its bookkeeping too, so a flood of tiny
            // out-of-order frames cannot hold far more memory than the buffer size.
            let charge = data.len() + CRYPTO_CHUNK_OVERHEAD;
            if end - ci.read > cap as u64 || ci.ooo_bytes + charge > cap {
                return Err(TransportError::frame(CRYPTO_BUFFER_EXCEEDED, frame::CRYPTO, "CRYPTO buffer exceeded"));
            }
            if !ci.ooo.contains_key(&offset) {
                ci.ooo_bytes += charge;
                ci.ooo.insert(offset, data.to_vec());
            }
            return Ok(());
        }
        let skip = (ci.read - offset) as usize;
        ci.read = end;
        self.feed_handshake(level, &data[skip..])?;
        // Deliver buffered chunks that became contiguous.
        loop {
            let ci = &mut self.spaces[space].crypto_in;
            let Some((&o, _)) = ci.ooo.first_key_value() else { break };
            if o > ci.read {
                break;
            }
            let chunk = ci.ooo.pop_first().unwrap().1;
            ci.ooo_bytes -= chunk.len() + CRYPTO_CHUNK_OVERHEAD;
            let e = o + chunk.len() as u64;
            if e <= ci.read {
                continue;
            }
            let skip = (ci.read - o) as usize;
            ci.read = e;
            self.feed_handshake(level, &chunk[skip..])?;
        }
        self.drive_crypto()
    }

    /// Hands in-order handshake bytes to TLS. A server with more than one version first
    /// collects the whole ClientHello, picks the version from the client's
    /// `version_information` (RFC 9368), and only then starts its TLS session in that version.
    fn feed_handshake(&mut self, level: Level, data: &[u8]) -> Result<(), TransportError> {
        let Some((odcid, retry_scid)) = self.deferred else {
            return Ok(self.session.read_handshake(level, data)?);
        };
        if level != Level::Initial {
            return Err(TransportError::new(PROTOCOL_VIOLATION, "handshake data before the ClientHello"));
        }
        self.hello.extend_from_slice(data);
        if self.hello.is_empty() {
            return Ok(());
        }
        // Not a TLS ClientHello (a test crypto provider's handshake): no negotiation.
        let tls = self.hello[0] == 1;
        let need = if tls { crate::vn::hello_len(&self.hello) } else { Some(0) };
        let Some(need) = need else { return Ok(()) };
        if need > self.cfg.transport.crypto_buffer {
            return Err(TransportError::new(CRYPTO_BUFFER_EXCEEDED, "ClientHello too large"));
        }
        if self.hello.len() < need {
            return Ok(());
        }
        let client = if tls { crate::vn::client_versions(&self.hello[..need]) } else { None };
        let chosen = crate::vn::choose(self.version, &self.cfg.versions, client.as_ref());
        if chosen != self.version {
            // Continue in the negotiated version: our Initial packets (and the client's from
            // now on) use its keys, derived from the same connection ID.
            self.version = chosen;
            self.spaces[0].keys = Some(self.cfg.provider.initial_keys(chosen, &self.initial_dcid, true));
        }
        self.deferred = None;
        let tp = self.local_params(Some(odcid), retry_scid);
        self.session = self.cfg.provider.server_session(self.version, tp)?;
        let hello = std::mem::take(&mut self.hello);
        Ok(self.session.read_handshake(level, &hello)?)
    }

    /// Pulls handshake output and key changes from the TLS session.
    fn drive_crypto(&mut self) -> Result<(), TransportError> {
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let change = self.session.write_handshake(&mut buf);
            let lvl = self.write_level as usize;
            self.spaces[lvl].crypto_out.extend_from_slice(&buf);
            match change {
                None => break,
                Some(KeyChange::Handshake { keys }) => {
                    self.spaces[1].keys = Some(keys);
                    self.write_level = Level::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    let Keys { local, remote } = keys;
                    self.one_rtt = Some(OneRtt {
                        local: local.packet,
                        remote: remote.packet,
                        local_hp: local.header,
                        remote_hp: remote.header,
                        secrets: next,
                        phase: false,
                        next: None,
                        prev_remote: None,
                        phase_first_sent: 0,
                        phase_first_recv: None,
                        update_allowed: false,
                        sealed: 0,
                    });
                    self.write_level = Level::OneRtt;
                }
            }
        }
        if self.peer_params.is_none() {
            if let Some(tp) = self.session.peer_transport_params() {
                let p = TransportParams::decode(tp, !self.is_server)?;
                self.apply_peer_params(p)?;
            }
        }
        if !self.handshake_complete && !self.session.is_handshaking() {
            if self.peer_params.is_none() {
                return Err(TransportError::new(TRANSPORT_PARAMETER_ERROR, "missing transport parameters"));
            }
            self.handshake_complete = true;
            self.state = State::Established;
            self.events.push_back(Event::Connected);
            if self.is_server {
                self.handshake_confirmed = true;
                self.handshake_done_pending = true;
                self.discard_space(1);
                if self.cfg.new_token_lifetime.is_some() {
                    self.new_token_pending = true;
                }
                self.start_mtu_probe();
            }
            self.issue_cids();
        }
        Ok(())
    }

    fn apply_peer_params(&mut self, p: TransportParams) -> Result<(), TransportError> {
        let err = |r| TransportError::new(TRANSPORT_PARAMETER_ERROR, r);
        if p.initial_source_connection_id != self.peer_initial_scid {
            return Err(err("initial_source_connection_id mismatch"));
        }
        if !self.is_server {
            if p.original_destination_connection_id != Some(self.orig_dcid) {
                return Err(err("original_destination_connection_id mismatch"));
            }
            if p.retry_source_connection_id != self.retry_scid {
                return Err(err("retry_source_connection_id mismatch"));
            }
            self.remote_cids[0].token = p.stateless_reset_token;
            if let Some(t) = p.stateless_reset_token {
                self.endpoint_events.push_back(EndpointEvent::ResetToken(t));
            }
        }
        self.streams.set_peer_params(&p);
        let peer_idle = Duration::from_millis(p.max_idle_timeout);
        let local_idle = self.cfg.transport.max_idle_timeout;
        self.idle_timeout = match (local_idle.is_zero(), peer_idle.is_zero()) {
            (true, true) => Duration::ZERO,
            (true, false) => peer_idle,
            (false, true) => local_idle,
            (false, false) => local_idle.min(peer_idle),
        };
        self.recovery.max_ack_delay = Duration::from_millis(p.max_ack_delay);
        self.peer_params = Some(p);
        Ok(())
    }

    fn discard_space(&mut self, space: usize) {
        let s = &mut self.spaces[space];
        if s.discarded {
            return;
        }
        s.discarded = true;
        s.keys = None;
        s.crypto_out = Vec::new();
        s.crypto_retx.clear();
        s.ack_now = false;
        s.ack_deadline = None;
        s.probes = 0;
        self.recovery.discard(space);
    }

    // ---------------------------------------------------------------- connection IDs

    fn issue_cids(&mut self) {
        let peer_limit = self.peer_params.as_ref().map_or(2, |p| p.active_connection_id_limit);
        let want = peer_limit.min(self.cfg.transport.max_local_cids);
        while (self.local_cids.iter().filter(|c| !c.retired).count() as u64) < want {
            let mut b = [0u8; 20];
            self.cfg.provider.fill_random(&mut b[..self.cfg.cid_len]);
            let cid = Cid::new(&b[..self.cfg.cid_len]);
            let seq = self.next_local_seq;
            self.next_local_seq += 1;
            self.local_cids.push(LocalCid { seq, cid, retired: false });
            self.pending_new_cids.push_back(seq);
            self.endpoint_events.push_back(EndpointEvent::NewCid(cid));
        }
    }

    fn on_retire_cid(&mut self, seq: u64, dcid: &Cid) -> Result<(), TransportError> {
        if seq >= self.next_local_seq {
            return Err(TransportError::frame(PROTOCOL_VIOLATION, frame::RETIRE_CONNECTION_ID, "retired an unissued CID"));
        }
        let Some(c) = self.local_cids.iter_mut().find(|c| c.seq == seq) else { return Ok(()) };
        if c.retired {
            return Ok(());
        }
        if c.cid == *dcid {
            return Err(TransportError::frame(
                PROTOCOL_VIOLATION,
                frame::RETIRE_CONNECTION_ID,
                "retired the CID the packet was sent to",
            ));
        }
        c.retired = true;
        let cid = c.cid;
        self.endpoint_events.push_back(EndpointEvent::RetireCid(cid));
        self.local_cids.retain(|c| !c.retired);
        self.issue_cids();
        Ok(())
    }

    fn on_new_cid(&mut self, seq: u64, rpt: u64, cid: &[u8], token: [u8; 16]) -> Result<(), TransportError> {
        let ty = frame::NEW_CONNECTION_ID;
        if self.remote_cids[0].cid.is_empty() {
            return Err(TransportError::frame(PROTOCOL_VIOLATION, ty, "NEW_CONNECTION_ID with a zero-length CID"));
        }
        let cid = Cid::new(cid);
        if let Some(c) = self.remote_cids.iter().find(|c| c.seq == seq) {
            if c.cid != cid || (c.token.is_some() && c.token != Some(token)) {
                return Err(TransportError::frame(PROTOCOL_VIOLATION, ty, "NEW_CONNECTION_ID changed"));
            }
            return Ok(());
        }
        if seq < self.retire_prior_to {
            // Already retired by an earlier retire_prior_to.
            self.queue_retire(seq)?;
            return Ok(());
        }
        self.remote_cids.push(RemoteCid { seq, cid, token: Some(token) });
        self.endpoint_events.push_back(EndpointEvent::ResetToken(token));
        if rpt > self.retire_prior_to {
            self.retire_prior_to = rpt;
            let mut i = 0;
            while i < self.remote_cids.len() {
                if self.remote_cids[i].seq < rpt {
                    let c = self.remote_cids.remove(i);
                    self.queue_retire(c.seq)?;
                } else {
                    i += 1;
                }
            }
            if self.remote_cids.is_empty() {
                return Err(TransportError::frame(PROTOCOL_VIOLATION, ty, "no connection ID left"));
            }
            // Element 0 is the one in use; keep the lowest sequence number active.
            self.remote_cids.sort_by_key(|c| c.seq);
            self.remote_cid_seq = self.remote_cids[0].seq;
        }
        if self.remote_cids.len() as u64 > self.cfg.transport.active_connection_id_limit {
            return Err(TransportError::frame(CONNECTION_ID_LIMIT_ERROR, ty, "too many connection IDs"));
        }
        Ok(())
    }

    /// Queues a RETIRE_CONNECTION_ID. Duplicates are dropped, and a peer that makes us queue
    /// more retirements than a few times its CID limit is closed with
    /// CONNECTION_ID_LIMIT_ERROR (RFC 9000 §5.1.2), so NEW_CONNECTION_ID frames that raise
    /// retire_prior_to (or replay old sequence numbers) cannot grow the queue without bound.
    fn queue_retire(&mut self, seq: u64) -> Result<(), TransportError> {
        if self.pending_retire.contains(&seq) {
            return Ok(());
        }
        let cap = (self.cfg.transport.active_connection_id_limit.max(2) * 8) as usize;
        if self.pending_retire.len() >= cap {
            return Err(TransportError::frame(
                CONNECTION_ID_LIMIT_ERROR,
                frame::NEW_CONNECTION_ID,
                "too many connection IDs waiting to be retired",
            ));
        }
        self.pending_retire.push_back(seq);
        Ok(())
    }

    /// Switches to an unused destination connection ID and retires the current one.
    /// Returns false if none is available.
    pub fn rotate_remote_cid(&mut self) -> bool {
        if self.remote_cids.len() < 2 {
            return false;
        }
        let old = self.remote_cids.remove(0);
        self.pending_retire.push_back(old.seq);
        self.remote_cid_seq = self.remote_cids[0].seq;
        true
    }

    // ---------------------------------------------------------------- paths

    fn migrate(&mut self, now: Instant, remote: SocketAddr) {
        // disable_active_migration does not stop us following a NAT rebinding (RFC 9000 §9).
        let mut new = Path::new(remote, false);
        // Count the datagram that triggered the migration.
        new.recv_bytes = self.stats.recv_bytes.min(MIN_INITIAL_SIZE as u64 * 3);
        let old = std::mem::replace(&mut self.path, new);
        self.prev_path = Some(old);
        self.recovery.cc.reset();
        self.rotate_remote_cid();
        self.start_challenge(now);
    }

    fn start_challenge(&mut self, now: Instant) {
        let mut d = [0u8; 8];
        self.cfg.provider.fill_random(&mut d);
        let pto = self.recovery.pto(2);
        self.path.challenge = Some((d, now + (pto * 3).max(Duration::from_millis(100))));
        self.path.challenge_pending = true;
    }

    fn on_path_response(&mut self, now: Instant, d: [u8; 8]) {
        if let Some((c, _)) = self.path.challenge {
            if c == d {
                self.path.challenge = None;
                self.path.challenge_pending = false;
                if !self.path.validated {
                    self.path.validated = true;
                    self.prev_path = None;
                    self.events.push_back(Event::PathMigrated(self.path.remote));
                }
            }
        }
        let _ = now;
    }

    // ---------------------------------------------------------------- acks and loss

    fn on_packet_acked(&mut self, space: usize, p: SentPacket) {
        if p.mtu_probe_size() > 0 {
            self.mds = p.mtu_probe_size();
            self.recovery.cc.mds = self.mds as u64;
            self.mtu_probe_inflight = false;
            self.next_mtu_probe(true);
        }
        if space == 2 {
            if let Some(k) = self.one_rtt.as_mut() {
                if p.pn >= k.phase_first_sent {
                    k.update_allowed = true;
                }
            }
        }
        for f in p.frames {
            match f {
                SentFrame::Stream { id, off, len, fin } => self.streams.on_stream_acked(id, off, len as u64, fin),
                SentFrame::Crypto { off, len } => {
                    self.spaces[space].crypto_retx.remove(off, off + len as u64);
                }
                SentFrame::Control(Control::ResetStream(id)) => self.streams.on_reset_acked(id),
                SentFrame::Ack(largest) => {
                    // The peer has our ACK up to `largest`: stop reporting older packets.
                    let s = &mut self.spaces[space];
                    if largest >= s.ack_floor && s.recv.max().is_some_and(|m| m > largest) {
                        s.recv.remove_below(largest + 1);
                        s.ack_floor = largest + 1;
                    }
                }
                _ => {}
            }
        }
    }

    fn on_packets_lost(&mut self, space: usize, lost: Vec<SentPacket>) {
        for p in lost {
            self.stats.lost_packets += 1;
            if p.mtu_probe_size() > 0 {
                self.mtu_probe_inflight = false;
                self.next_mtu_probe(false);
            }
            self.requeue(space, &p.frames);
        }
    }

    fn requeue(&mut self, space: usize, frames: &[SentFrame]) {
        for &f in frames {
            match f {
                SentFrame::Stream { id, off, len, fin } => self.streams.on_stream_lost(id, off, len as u64, fin),
                SentFrame::Crypto { off, len } => {
                    if !self.spaces[space].discarded {
                        self.spaces[space].crypto_retx.insert(off, off + len as u64);
                    }
                }
                SentFrame::Control(c) => {
                    if !self.streams.control.contains(&c) {
                        self.streams.control.push_back(c);
                    }
                }
                SentFrame::NewConnectionId(seq) => {
                    if self.local_cids.iter().any(|c| c.seq == seq) && !self.pending_new_cids.contains(&seq) {
                        self.pending_new_cids.push_back(seq);
                    }
                }
                SentFrame::RetireConnectionId(seq) => {
                    if !self.pending_retire.contains(&seq) {
                        self.pending_retire.push_back(seq);
                    }
                }
                SentFrame::HandshakeDone => self.handshake_done_pending = true,
                SentFrame::NewToken => self.new_token_pending = true,
                SentFrame::Ack(_) | SentFrame::Ping | SentFrame::MtuProbe(_) => {}
            }
        }
    }

    fn start_mtu_probe(&mut self) {
        if self.cfg.transport.mtu_probing && self.cfg.transport.max_datagram_size > self.mds {
            self.next_mtu_probe(true);
        }
    }

    /// Simple PMTU search: try the configured maximum, then the midpoint, each up to 3 times.
    fn next_mtu_probe(&mut self, success: bool) {
        let peer = self.peer_params.as_ref().map_or(1200, |p| p.max_udp_payload_size) as usize;
        let target = self.cfg.transport.max_datagram_size.min(peer);
        if target <= self.mds {
            self.mtu_probe = None;
            return;
        }
        self.mtu_probe = match self.mtu_probe {
            Some((size, tries)) if !success && tries < 2 => Some((size, tries + 1)),
            Some((size, _)) if !success => {
                let mid = (self.mds + size) / 2;
                if mid > self.mds + 20 {
                    Some((mid, 0))
                } else {
                    None
                }
            }
            _ => Some((target, 0)),
        };
    }

    // ---------------------------------------------------------------- timers

    /// The next time [`Connection::handle_timeout`] must be called.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut t: Option<Instant> = None;
        let mut put = |x: Option<Instant>| {
            if let Some(x) = x {
                t = Some(t.map_or(x, |y| y.min(x)));
            }
        };
        match self.state {
            State::Drained => return None,
            State::Closing(u) | State::Draining(u) => return Some(u),
            _ => {}
        }
        if !self.idle_timeout.is_zero() {
            let idle = self.idle_timeout.max(self.recovery.pto(2) * 3);
            put(Some(self.last_activity + idle));
        }
        for s in &self.spaces {
            put(s.ack_deadline);
        }
        put(self.loss_timer());
        put(self.path.challenge.map(|c| c.1));
        if let Some(k) = &self.one_rtt {
            put(k.prev_remote.as_ref().and_then(|p| p.1));
        }
        put(self.pacing_until);
        t
    }

    fn active_spaces(&self) -> [bool; 3] {
        [
            self.spaces[0].keys.is_some(),
            self.spaces[1].keys.is_some(),
            self.one_rtt.is_some(),
        ]
    }

    fn loss_timer(&self) -> Option<Instant> {
        if let Some((t, _)) = self.recovery.earliest_loss_time() {
            return Some(t);
        }
        if self.is_server && self.path.budget() < MIN_INITIAL_SIZE / 2 {
            return None; // Blocked by the anti-amplification limit (RFC 9002 §6.2.2.1).
        }
        let anti_deadlock = !self.is_server && !self.handshake_complete;
        self.recovery
            .pto_deadline(self.last_activity, self.active_spaces(), self.handshake_confirmed, anti_deadlock)
            .map(|x| x.0)
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        match self.state {
            State::Drained => return,
            State::Closing(u) | State::Draining(u) => {
                if now >= u {
                    let err = self.error.clone().unwrap_or(ConnectionError::IdleTimeout);
                    self.drain_now(err);
                }
                return;
            }
            _ => {}
        }
        if self.pacing_until.is_some_and(|t| now >= t) {
            self.pacing_until = None;
        }
        if !self.idle_timeout.is_zero() {
            let idle = self.idle_timeout.max(self.recovery.pto(2) * 3);
            if now >= self.last_activity + idle {
                self.drain_now(ConnectionError::IdleTimeout);
                return;
            }
        }
        for s in &mut self.spaces {
            if s.ack_deadline.is_some_and(|d| now >= d) {
                s.ack_deadline = None;
                s.ack_now = true;
            }
        }
        if let Some((_, deadline)) = self.path.challenge {
            if now >= deadline {
                // Validation failed: go back to the previous path if there is one.
                self.path.challenge = None;
                self.path.challenge_pending = false;
                if let Some(prev) = self.prev_path.take() {
                    self.path = prev;
                }
            }
        }
        if let Some(k) = self.one_rtt.as_mut() {
            if k.prev_remote.as_ref().and_then(|p| p.1).is_some_and(|d| now >= d) {
                k.prev_remote = None;
            }
        }
        // Loss detection timer (RFC 9002 §6.2, Appendix A.9).
        if let Some((t, space)) = self.recovery.earliest_loss_time() {
            if now >= t {
                let lost = self.recovery.detect_lost(space, now);
                self.on_packets_lost(space, lost);
            }
            return;
        }
        if let Some(t) = self.loss_timer() {
            if now >= t {
                self.on_pto(now);
            }
        }
    }

    /// Server: queues the unacknowledged Initial and Handshake data again (see `on_crypto`).
    fn resend_handshake_flight(&mut self) {
        for space in 0..2 {
            if self.spaces[space].keys.is_none() || self.spaces[space].discarded {
                continue;
            }
            let frames: Vec<SentFrame> = self.recovery.spaces[space].sent.values().flat_map(|p| p.frames.iter().copied()).collect();
            self.requeue(space, &frames);
        }
    }

    fn on_pto(&mut self, _now: Instant) {
        let active = self.active_spaces();
        let anti_deadlock = !self.is_server && !self.handshake_complete;
        let space = match self.recovery.pto_deadline(self.last_activity, active, self.handshake_confirmed, anti_deadlock) {
            Some((_, s)) => s,
            None => return,
        };
        self.recovery.pto_count += 1;
        // Probe: resend unacknowledged data from the oldest packets (RFC 9002 §6.2.4).
        let frames: Vec<SentFrame> = if space < 2 {
            self.recovery.spaces[space].sent.values().flat_map(|p| p.frames.iter().copied()).collect()
        } else {
            self.recovery.spaces[space].sent.values().filter(|p| p.ack_eliciting).take(2).flat_map(|p| p.frames.iter().copied()).collect()
        };
        self.requeue(space, &frames);
        self.spaces[space].probes = 2;
        // During the handshake, a client also probes Initial if Handshake has nothing.
        if space == 1 && !self.is_server && self.spaces[0].keys.is_some() {
            self.spaces[0].probes = 1;
        }
    }

    // ---------------------------------------------------------------- sending

    /// Writes up to `max_datagrams` datagrams into `buf` (cleared first).
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut Vec<u8>, max_datagrams: usize) -> Option<Transmit> {
        buf.clear();
        if matches!(self.state, State::Draining(_) | State::Drained) {
            return None;
        }
        self.maybe_auto_key_update();
        // PATH_RESPONSEs for other addresses go alone.
        if let Some(&(_, addr)) = self.path_responses.front() {
            if addr != self.path.remote {
                let (d, addr) = self.path_responses.pop_front().unwrap();
                if self.build_path_response(now, buf, d, addr) {
                    return Some(Transmit { destination: addr, size: buf.len(), segment_size: None });
                }
                buf.clear();
            }
        }
        let seg = self.mds;
        let mut count = 0;
        while count < max_datagrams.max(1) {
            let before = buf.len();
            // A PMTU probe is larger than the segment size, so it only starts a batch.
            self.probe_allowed = count == 0;
            let built = self.build_datagram(now, buf);
            self.probe_allowed = false;
            if !built {
                break;
            }
            let n = buf.len() - before;
            count += 1;
            if n != seg {
                break;
            }
            if let State::Closing(_) = self.state {
                break;
            }
        }
        if count == 0 {
            return None;
        }
        let dest = self.path.remote;
        Some(Transmit { destination: dest, size: buf.len(), segment_size: if count > 1 { Some(seg) } else { None } })
    }

    fn maybe_auto_key_update(&mut self) {
        let Some(k) = &self.one_rtt else { return };
        let limit = match self.cfg.transport.key_update_interval {
            Some(n) => n,
            None => k.local.confidentiality_limit().saturating_sub(1000),
        };
        if k.sealed >= limit && k.update_allowed {
            self.initiate_key_update();
        }
    }

    fn build_path_response(&mut self, now: Instant, buf: &mut Vec<u8>, d: [u8; 8], addr: SocketAddr) -> bool {
        if self.one_rtt.is_none() {
            return false;
        }
        let Some(mut b) = self.begin_packet(buf, 2) else { return false };
        frame::put_path(buf, true, &d);
        b.eliciting = true;
        // Pad to 1200 when the amplification budget for that address allows (RFC 9000 §8.2.1).
        let budget = 3 * MIN_INITIAL_SIZE;
        let target = MIN_INITIAL_SIZE.min(budget) - self.one_rtt.as_ref().unwrap().local.tag_len();
        if buf.len() < target {
            buf.resize(target, 0);
        }
        self.finish_packet(now, buf, b);
        let _ = addr;
        true
    }

    /// Room left in the datagram that starts at `dstart` given amplification and size.
    fn datagram_limit(&self) -> usize {
        let mut limit = self.mds;
        if !self.handshake_confirmed {
            limit = MIN_INITIAL_SIZE;
        }
        limit.min(self.path.budget())
    }

    fn wants_ack(&self, space: usize) -> bool {
        let s = &self.spaces[space];
        s.ack_now && !s.recv.is_empty()
    }

    fn space_has_data(&self, space: usize) -> bool {
        let s = &self.spaces[space];
        if s.has_crypto() || s.probes > 0 {
            return true;
        }
        if space == 2 {
            return self.handshake_done_pending
                || self.ping_pending
                || self.path.challenge_pending
                || self.path_responses.front().is_some_and(|x| x.1 == self.path.remote)
                || !self.pending_new_cids.is_empty()
                || !self.pending_retire.is_empty()
                || self.new_token_pending
                || !self.streams.control.is_empty()
                || self.streams.has_pending_data()
                || (self.probe_allowed && self.mtu_probe.is_some() && !self.mtu_probe_inflight && self.recovery.rtt.has_sample);
        }
        false
    }

    /// Builds one datagram; returns false if there was nothing to send.
    fn build_datagram(&mut self, now: Instant, buf: &mut Vec<u8>) -> bool {
        let dstart = buf.len();
        let closing = matches!(self.state, State::Closing(_));
        if closing {
            // Send CONNECTION_CLOSE once, then again only for every few packets received.
            let due = self.close_sent_count == 0 || self.close_recv_count >= (1 << self.close_sent_count.min(10));
            if !due {
                return false;
            }
            self.close_recv_count = 0;
        }
        let limit_total = self.datagram_limit();
        if limit_total < 64 {
            return false;
        }
        let cwnd_room = self.recovery.cc.available() as usize;
        let probing = self.spaces.iter().any(|s| s.probes > 0);
        // Pacing.
        if self.cfg.transport.pacing && !closing && !probing && self.recovery.rtt.has_sample {
            if let Some(t) = self.recovery.pacer.delay(
                now,
                self.mds as u64,
                self.recovery.rtt.smoothed,
                self.recovery.cc.cwnd,
                self.mds as u64,
            ) {
                if self.spaces.iter().all(|s| !s.ack_now) {
                    self.pacing_until = Some(t);
                    return false;
                }
            }
        }
        let mut pending: Option<Building> = None;
        let mut needs_padding = false;
        let mut sent_initial = false;
        for space in 0..3 {
            let has_keys = if space == 2 { self.one_rtt.is_some() } else { self.spaces[space].keys.is_some() };
            if !has_keys {
                continue;
            }
            // Before the handshake completes, a server does not send 1-RTT data other than
            // what TLS allows (0.5-RTT); we keep it simple and wait for completion, except
            // for closing.
            if space == 2 && !self.handshake_complete && !closing {
                continue;
            }
            let ack = self.wants_ack(space);
            let data = self.space_has_data(space);
            if !(ack || data || (closing && self.close_space_ok(space))) {
                continue;
            }
            // Room for this packet.
            let used = buf.len() - dstart;
            let tag = self.tag_len(space);
            if used + 40 + tag >= limit_total {
                break;
            }
            // Congestion control: ack-only and close packets are not limited, nor is the
            // PATH_CHALLENGE that validates a new path (after a migration the bytes still in
            // flight on the old path can fill the reset window, and the first packet on the
            // new path must carry the challenge, RFC 9000 §9.3).
            let cc_limited = !closing && !probing && cwnd_room < self.mds;
            let challenge = space == 2 && self.path.challenge_pending;
            if cc_limited && !ack && !challenge {
                continue;
            }
            if let Some(p) = pending.take() {
                self.finish_packet(now, buf, p);
            }
            let Some(mut b) = self.begin_packet(buf, space) else { continue };
            let limit = dstart + limit_total - tag;
            // An ACK-only packet goes out only when an ACK is due; otherwise "data" that
            // writes nothing would send ACK-only packets in a loop at one instant.
            let ack_due = ack || self.spaces[space].unacked_eliciting > 0;
            self.write_frames(now, buf, &mut b, limit, closing, cc_limited);
            let ack_only = b.frames.iter().all(|f| matches!(f, SentFrame::Ack(_)));
            if !closing && ((b.frames.is_empty() && buf.len() == b.pn_at + b.pn_len) || (ack_only && !ack_due)) {
                // Nothing (useful) fit: roll back.
                buf.truncate(b.start);
                continue;
            }
            if space == 0 {
                sent_initial = true;
                if !self.is_server || b.eliciting {
                    needs_padding = true;
                }
            }
            if b.mtu_probe {
                needs_padding = false;
            }
            pending = Some(b);
            if space == 2 {
                break;
            }
        }
        let Some(mut last) = pending else {
            return false;
        };
        let tag = self.tag_len(last.space);
        if needs_padding {
            let target = dstart + MIN_INITIAL_SIZE.min(limit_total) - tag;
            if buf.len() < target {
                buf.resize(target, 0);
            }
        }
        if last.mtu_probe {
            let size = self.mtu_probe.map_or(self.mds, |m| m.0);
            let target = dstart + size - tag;
            if buf.len() < target {
                buf.resize(target, 0);
            }
            last.eliciting = true;
        }
        self.finish_packet(now, buf, last);
        if closing {
            self.close_sent_count += 1;
        }
        let n = buf.len() - dstart;
        self.path.sent_bytes += n as u64;
        self.stats.sent_bytes += n as u64;
        // A client discards Initial keys when it first sends a Handshake packet.
        if !self.is_server && self.spaces[1].keys.is_some() && !sent_initial && self.spaces[0].keys.is_some() {
            let sent_handshake = self.recovery.spaces[1].next_pn > 0;
            if sent_handshake {
                self.discard_space(0);
            }
        }
        true
    }

    fn close_space_ok(&self, space: usize) -> bool {
        // Send the close in every space we have keys for until the handshake is confirmed.
        space == 2 || !self.handshake_confirmed
    }

    fn tag_len(&self, space: usize) -> usize {
        if space == 2 {
            self.one_rtt.as_ref().map_or(16, |k| k.local.tag_len())
        } else {
            self.spaces[space].keys.as_ref().map_or(16, |k| k.local.packet.tag_len())
        }
    }

    fn begin_packet(&mut self, buf: &mut Vec<u8>, space: usize) -> Option<Building> {
        let start = buf.len();
        let pn = self.recovery.spaces[space].next_pn;
        let pn_len = packet::pn_len(pn, self.recovery.spaces[space].largest_acked);
        let dcid = self.remote_cids[0].cid;
        let (len_at, pn_at) = if space == 2 {
            let phase = self.one_rtt.as_ref()?.phase;
            (None, packet::put_short_header(buf, false, phase, &dcid, pn, pn_len))
        } else {
            let ty = if space == 0 { PacketType::Initial } else { PacketType::Handshake };
            let token = if space == 0 { Some(&self.token[..]).filter(|_| !self.is_server).or(Some(&[][..])) } else { None };
            let scid = self.local_cids[0].cid;
            let (l, p) = packet::put_long_header(buf, self.version, ty, &dcid, &scid, token, pn, pn_len);
            (Some(l), p)
        };
        Some(Building { space, start, len_at, pn_at, pn, pn_len, eliciting: false, frames: Vec::new(), mtu_probe: false })
    }

    fn write_frames(&mut self, now: Instant, buf: &mut Vec<u8>, b: &mut Building, limit: usize, closing: bool, cc_limited: bool) {
        let space = b.space;
        // ACK first.
        if !self.spaces[space].recv.is_empty() && (self.spaces[space].ack_now || self.spaces[space].unacked_eliciting > 0 || closing || !cc_limited) {
            let s = &mut self.spaces[space];
            let delay = s.largest_recv.map_or(0, |(_, t)| now.saturating_duration_since(t).as_micros() as u64)
                >> self.cfg.transport.ack_delay_exponent;
            let before = buf.len();
            let delay = if space == 2 { delay } else { 0 };
            frame::put_ack(buf, &s.recv, delay, self.cfg.transport.max_ack_ranges);
            if buf.len() > limit {
                buf.truncate(before);
            } else {
                b.frames.push(SentFrame::Ack(s.recv.max().unwrap()));
                s.ack_now = false;
                s.ack_deadline = None;
                s.unacked_eliciting = 0;
            }
        }
        if closing {
            let (code, ft, reason) = self.close.clone().unwrap_or((0, Some(0), Vec::new()));
            let reason = &reason[..reason.len().min(limit.saturating_sub(buf.len() + 24))];
            if space == 2 {
                frame::put_close(buf, code, ft, reason);
            } else {
                // Application closes are sent as APPLICATION_ERROR before 1-RTT (RFC 9000 §10.2.3).
                match ft {
                    Some(t) => frame::put_close(buf, code, Some(t), reason),
                    None => frame::put_close(buf, APPLICATION_ERROR, Some(0), b""),
                }
            }
            b.frames.push(SentFrame::Ping);
            return;
        }
        // The PATH_CHALLENGE for a new path goes first and is not held back by congestion
        // control (see `build_datagram`).
        if space == 2 && self.path.challenge_pending && buf.len() + 9 <= limit {
            if let Some((d, _)) = self.path.challenge {
                frame::put_path(buf, false, &d);
                self.path.challenge_pending = false;
                b.eliciting = true;
                b.frames.push(SentFrame::Ping);
            }
        }
        if cc_limited {
            return;
        }
        if space == 2 {
            if self.handshake_done_pending && buf.len() + 1 <= limit {
                frame::put_simple(buf, frame::HANDSHAKE_DONE, &[]);
                self.handshake_done_pending = false;
                b.frames.push(SentFrame::HandshakeDone);
                b.eliciting = true;
            }
            while let Some(&(d, addr)) = self.path_responses.front() {
                if addr != self.path.remote || buf.len() + 9 > limit {
                    break;
                }
                frame::put_path(buf, true, &d);
                self.path_responses.pop_front();
                b.eliciting = true;
            }
            while let Some(&seq) = self.pending_new_cids.front() {
                if buf.len() + 1 + 8 + 8 + 21 + 16 > limit {
                    break;
                }
                self.pending_new_cids.pop_front();
                if let Some(c) = self.local_cids.iter().find(|c| c.seq == seq && !c.retired) {
                    let token = self.cfg.reset_token(&c.cid);
                    frame::put_new_connection_id(buf, seq, 0, &c.cid, &token);
                    b.frames.push(SentFrame::NewConnectionId(seq));
                    b.eliciting = true;
                }
            }
            while let Some(&seq) = self.pending_retire.front() {
                if buf.len() + 9 > limit {
                    break;
                }
                self.pending_retire.pop_front();
                frame::put_simple(buf, frame::RETIRE_CONNECTION_ID, &[seq]);
                b.frames.push(SentFrame::RetireConnectionId(seq));
                b.eliciting = true;
            }
            if self.new_token_pending && buf.len() + 80 <= limit {
                self.new_token_pending = false;
                let token = self.new_token.get_or_insert_with(|| {
                    crate::token::new_token(&self.cfg, self.path.remote, now)
                });
                frame::put_new_token(buf, token);
                b.frames.push(SentFrame::NewToken);
                b.eliciting = true;
            }
            let mut n = self.streams.control.len();
            while n > 0 {
                n -= 1;
                let Some(c) = self.streams.control.pop_front() else { break };
                match self.streams.write_control(c, buf, limit) {
                    None => {}
                    Some(true) => {
                        b.frames.push(SentFrame::Control(c));
                        b.eliciting = true;
                    }
                    Some(false) => {
                        self.streams.control.push_front(c);
                        break;
                    }
                }
            }
        }
        // CRYPTO data: retransmissions first.
        while buf.len() + 16 < limit {
            let s = &mut self.spaces[space];
            let room = (limit - buf.len()) as u64;
            let (off, len) = if let Some((a, e)) = s.crypto_retx.first() {
                let ov = frame::crypto_overhead(a, (e - a) as usize) as u64;
                if room <= ov {
                    break;
                }
                let len = (e - a).min(room - ov);
                s.crypto_retx.remove(a, a + len);
                (a, len)
            } else if s.crypto_sent < s.crypto_out.len() as u64 {
                let a = s.crypto_sent;
                let avail = s.crypto_out.len() as u64 - a;
                let ov = frame::crypto_overhead(a, avail as usize) as u64;
                if room <= ov {
                    break;
                }
                let len = avail.min(room - ov);
                s.crypto_sent += len;
                (a, len)
            } else {
                break;
            };
            frame::put_crypto(buf, off, &s.crypto_out[off as usize..(off + len) as usize]);
            b.frames.push(SentFrame::Crypto { off, len: len as u32 });
            b.eliciting = true;
        }
        if space == 2 {
            if self.probe_allowed && self.mtu_probe.is_some() && !self.mtu_probe_inflight && self.recovery.rtt.has_sample {
                let size = self.mtu_probe.unwrap().0;
                // A probe carries only PING and PADDING, so loss does not lose data.
                if b.frames.iter().all(|f| matches!(f, SentFrame::Ack(_))) {
                    frame::put_simple(buf, frame::PING, &[]);
                    b.frames.push(SentFrame::MtuProbe(size as u16));
                    b.mtu_probe = true;
                    b.eliciting = true;
                    self.mtu_probe_inflight = true;
                    return;
                }
            }
            let before = b.frames.len();
            self.streams.write_frames(buf, limit, &mut b.frames);
            if b.frames.len() > before {
                b.eliciting = true;
            } else if !self.streams.has_pending_data() && self.recovery.cc.available() > 0 {
                self.recovery.app_limited = true;
            }
            if self.streams.has_pending_data() {
                self.recovery.app_limited = false;
            }
            if !self.raw_frames.is_empty() && buf.len() + self.raw_frames.len() <= limit {
                buf.extend_from_slice(&self.raw_frames);
                self.raw_frames.clear();
                b.frames.push(SentFrame::Ping);
                b.eliciting = true;
            }
            if self.ping_pending && buf.len() < limit {
                frame::put_simple(buf, frame::PING, &[]);
                self.ping_pending = false;
                b.frames.push(SentFrame::Ping);
                b.eliciting = true;
            }
        }
        let s = &mut self.spaces[space];
        if s.probes > 0 {
            s.probes -= 1;
            if !b.eliciting && buf.len() < limit {
                frame::put_simple(buf, frame::PING, &[]);
                b.frames.push(SentFrame::Ping);
                b.eliciting = true;
            }
        }
    }

    /// Pads, seals and header-protects the packet, then records it.
    fn finish_packet(&mut self, now: Instant, buf: &mut Vec<u8>, b: Building) {
        let payload_start = b.pn_at + b.pn_len;
        // The header protection sample needs 4 bytes after the packet number start.
        if buf.len() < b.pn_at + 4 {
            buf.resize(b.pn_at + 4, 0);
        }
        let tag_len = self.tag_len(b.space);
        if let Some(len_at) = b.len_at {
            let len = buf.len() - b.pn_at + tag_len;
            put_varint_fixed(&mut buf[len_at..], len as u64, 2);
        }
        let end = buf.len();
        buf.resize(end + tag_len, 0);
        {
            let (head, rest) = buf[b.start..].split_at_mut(payload_start - b.start);
            let (payload, tag) = rest.split_at_mut(end - payload_start);
            if b.space == 2 {
                let k = self.one_rtt.as_mut().unwrap();
                k.local.seal(b.pn, head, payload, tag);
                k.sealed += 1;
            } else {
                self.spaces[b.space].keys.as_ref().unwrap().local.packet.seal(b.pn, head, payload, tag);
            }
        }
        let hp: &dyn HeaderKey = if b.space == 2 {
            &*self.one_rtt.as_ref().unwrap().local_hp
        } else {
            &*self.spaces[b.space].keys.as_ref().unwrap().local.header
        };
        packet::protect(buf, b.start, b.pn_at, b.pn_len, hp);
        let size = buf.len() - b.start;
        let sp = &mut self.recovery.spaces[b.space];
        sp.next_pn = b.pn + 1;
        if b.space == 2 {
            // Skip a 1-RTT packet number now and then, at random, to catch optimistic ACKs
            // (RFC 9000 §21.4); on average one in PN_SKIP_PERIOD packets.
            if sp.next_pn >= sp.skip_at {
                if sp.skip_at != 0 {
                    sp.skipped.push_back(sp.next_pn);
                    if sp.skipped.len() > 4 {
                        sp.skipped.pop_front();
                    }
                    sp.next_pn += 1;
                }
                let mut r = [0u8; 2];
                self.cfg.provider.fill_random(&mut r);
                let jitter = u64::from(u16::from_le_bytes(r)) % PN_SKIP_PERIOD;
                sp.skip_at = sp.next_pn + PN_SKIP_PERIOD / 2 + jitter;
            }
        }
        if b.eliciting && !self.eliciting_since_recv {
            // The idle timer restarts on the first ack-eliciting packet after receiving.
            self.eliciting_since_recv = true;
            self.last_activity = now;
        }
        self.stats.sent_packets += 1;
        self.recovery.on_sent(
            b.space,
            SentPacket {
                pn: b.pn,
                time: now,
                size: size as u16,
                ack_eliciting: b.eliciting,
                in_flight: b.eliciting,
                frames: b.frames,
            },
        );
    }
}

/// Stands in for the TLS session while the connection builds its transport parameters.
struct Placeholder;

impl CryptoSession for Placeholder {
    fn read_handshake(&mut self, _: Level, _: &[u8]) -> Result<(), crate::crypto::CryptoError> {
        Ok(())
    }
    fn write_handshake(&mut self, _: &mut Vec<u8>) -> Option<KeyChange> {
        None
    }
    fn peer_transport_params(&self) -> Option<&[u8]> {
        None
    }
    fn alpn_protocol(&self) -> Option<&[u8]> {
        None
    }
    fn is_handshaking(&self) -> bool {
        true
    }
}

impl SentPacket {
    fn mtu_probe_size(&self) -> usize {
        self.frames
            .iter()
            .find_map(|f| if let SentFrame::MtuProbe(s) = f { Some(*s as usize) } else { None })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::crypto::null::NullProvider;
    use crate::sim::{Link, Pair};
    use std::sync::Arc;
    use std::time::Duration;

    /// Regression (fuzz seed 7000098): a server whose handshake completed without an RTT
    /// sample (a client that never ACKs) had a PMTU probe "pending" that could not be built,
    /// so every `poll_transmit` at the same instant produced another ACK-only packet: an
    /// unbounded loop of datagrams and a busy event loop.
    #[test]
    fn unbuildable_mtu_probe_does_not_spin_ack_only_packets() {
        let cfg = |seed| Arc::new(Config::new(Arc::new(NullProvider::new(seed))));
        let mut p = Pair::new(cfg(1), cfg(2), Link::default(), 1);
        let c = p.connect();
        let ok = p.run_until(Duration::from_secs(30), |p| {
            p.client.conn(c).is_some_and(|x| x.is_established()) && p.server_conn().and_then(|s| p.server.conn(s)).is_some_and(|x| x.is_established())
        });
        assert!(ok);
        p.run_for(Duration::from_millis(200));
        let s = p.server_conn().unwrap();
        let now = p.now;
        let conn = p.server.conn_mut(s).unwrap();
        conn.recovery.rtt.has_sample = false;
        conn.mtu_probe = Some((1400, 0));
        conn.mtu_probe_inflight = false;
        // Something to acknowledge, so the first packet may be an ACK.
        conn.spaces[2].unacked_eliciting = 1;
        let mut buf = Vec::new();
        let mut sent = 0;
        while conn.poll_transmit(now, &mut buf, 1).is_some() {
            sent += 1;
            assert!(sent < 20, "poll_transmit keeps producing packets at one instant");
        }
    }

    /// Handshake under loss (interop `handshakeloss`): when the client's ClientHello arrives
    /// again, the client's PTO fired, so the server's flight was probably lost; the server
    /// queues it again at once instead of waiting for its own backed-off PTO.
    #[test]
    fn duplicate_client_hello_resends_the_server_flight() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let cfg = |seed| Arc::new(Config::new(Arc::new(NullProvider::new(seed))));
        let mut p = Pair::new(cfg(5), cfg(6), Link::default(), 5);
        // (client datagrams, server datagrams of at least 1200 bytes): everything the server
        // sends is dropped, so the client's PTO fires and it resends its ClientHello.
        let count: Rc<RefCell<(usize, usize)>> = Rc::default();
        let c2 = count.clone();
        p.tamper = Some(Box::new(move |to_server, d| {
            let mut c = c2.borrow_mut();
            if to_server {
                c.0 += 1;
            } else if d.len() >= 1200 {
                c.1 += 1;
            }
            to_server
        }));
        p.connect();
        p.run_until(Duration::from_millis(50), |p| p.server_conn().is_some());
        p.run_for(Duration::from_millis(20));
        let s = p.server_conn().expect("server connection");
        assert!(count.borrow().1 > 0, "the server sent its flight");
        // Push the server's own PTO far away, so only the repeated ClientHello can trigger a
        // resend; then let the client's PTO resend its Initial (with a new packet number).
        p.server.conn_mut(s).unwrap().recovery.pto_count = 12;
        let (clients, flights) = *count.borrow();
        let c3 = count.clone();
        assert!(p.run_until(Duration::from_secs(5), |_| c3.borrow().0 > clients), "the client resent its Initial");
        p.run_for(Duration::from_millis(30));
        assert!(count.borrow().1 > flights, "a repeated ClientHello makes the server resend its flight at once");
    }

    /// The QUIC Interop Runner's rebind cases: after a NAT rebinding the first packet the
    /// server sends on the new path must carry PATH_CHALLENGE, even when the bytes still in
    /// flight on the old path fill the (reset) congestion window. Before the fix that packet
    /// was ACK-only and the challenge waited for the window.
    #[test]
    fn first_packet_on_a_new_path_carries_the_challenge_when_cwnd_is_full() {
        let cfg = |seed| Arc::new(Config::new(Arc::new(NullProvider::new(seed))));
        let mut p = Pair::new(cfg(3), cfg(4), Link::default(), 3);
        let c = p.connect();
        let ok = p.run_until(Duration::from_secs(30), |p| {
            p.client.conn(c).is_some_and(|x| x.is_established()) && p.server_conn().and_then(|s| p.server.conn(s)).is_some_and(|x| x.is_established())
        });
        assert!(ok);
        p.run_for(Duration::from_millis(200));
        let s = p.server_conn().unwrap();
        let now = p.now;
        let new: std::net::SocketAddr = "10.0.0.9:6000".parse().unwrap();
        let conn = p.server.conn_mut(s).unwrap();
        assert!(conn.handshake_confirmed);
        conn.migrate(now, new);
        // The old path's bytes in flight fill the window; an ACK is due.
        conn.recovery.cc.in_flight = conn.recovery.cc.cwnd;
        conn.spaces[2].ack_now = true;
        let mut buf = Vec::new();
        let t = conn.poll_transmit(now, &mut buf, 1).expect("a packet on the new path");
        assert_eq!(t.destination, new);
        assert!(!conn.path.challenge_pending, "the first packet on the new path carries PATH_CHALLENGE");
        let last = conn.recovery.spaces[2].sent.values().last().unwrap();
        assert!(last.ack_eliciting, "the packet is not ACK-only");
    }
}
