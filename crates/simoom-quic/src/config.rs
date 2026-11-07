//! Endpoint and transport configuration.

use crate::crypto::CryptoProvider;
use crate::packet::VERSION_1;
use std::sync::Arc;
use std::time::Duration;

/// Per-connection transport settings (sent as transport parameters where applicable).
#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub max_idle_timeout: Duration,
    /// Largest UDP payload we accept (transport parameter `max_udp_payload_size`).
    pub max_udp_payload_size: u64,
    /// Largest datagram we try to send; reached by PMTU probing from 1200 bytes.
    pub max_datagram_size: usize,
    /// Probe for a larger path MTU after the handshake (RFC 9000 §14.3).
    pub mtu_probing: bool,
    pub max_data: u64,
    pub stream_window_bidi_local: u64,
    pub stream_window_bidi_remote: u64,
    pub stream_window_uni: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    /// Unacknowledged bytes buffered per send stream.
    pub send_buffer: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: Duration,
    /// Connection IDs we accept from the peer.
    pub active_connection_id_limit: u64,
    /// Connection IDs we issue at most (capped by the peer's limit).
    pub max_local_cids: u64,
    pub disable_active_migration: bool,
    /// Out-of-order CRYPTO bytes buffered per level (RFC 9000 §7.5).
    pub crypto_buffer: usize,
    /// ACK ranges tracked and sent.
    pub max_ack_ranges: usize,
    pub pacing: bool,
    /// Packets per key phase before a key update; `None` uses the AEAD limit.
    pub key_update_interval: Option<u64>,
    /// Ack-eliciting packets received before an ACK is sent immediately.
    pub ack_eliciting_threshold: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            max_idle_timeout: Duration::from_secs(30),
            max_udp_payload_size: 1472,
            max_datagram_size: 1452,
            mtu_probing: true,
            max_data: 4 << 20,
            stream_window_bidi_local: 1 << 20,
            stream_window_bidi_remote: 1 << 20,
            stream_window_uni: 256 << 10,
            max_streams_bidi: 100,
            max_streams_uni: 16,
            send_buffer: 1 << 20,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            active_connection_id_limit: 4,
            max_local_cids: 4,
            disable_active_migration: false,
            crypto_buffer: 64 << 10,
            max_ack_ranges: 32,
            pacing: true,
            key_update_interval: None,
            ack_eliciting_threshold: 2,
        }
    }
}

/// Endpoint-wide configuration shared by its connections.
pub struct Config {
    pub provider: Arc<dyn CryptoProvider>,
    pub transport: TransportConfig,
    /// Key for stateless reset tokens (HMAC of the connection ID).
    pub reset_key: [u8; 32],
    /// Key for Retry and NEW_TOKEN address-validation tokens.
    pub token_key: [u8; 32],
    /// Versions accepted by a server, preferred first. A client uses the first.
    pub versions: Vec<u32>,
    /// Server: always validate addresses with Retry.
    pub retry: bool,
    /// Server: send Retry once this many connections are in the handshake.
    pub retry_threshold: usize,
    /// Lifetime of Retry tokens.
    pub retry_token_lifetime: Duration,
    /// Server: issue NEW_TOKEN after the handshake; lifetime of those tokens.
    pub new_token_lifetime: Option<Duration>,
    /// Length of the connection IDs this endpoint issues (4..=20).
    pub cid_len: usize,
    /// Server: most connections kept at once.
    pub max_connections: usize,
    /// Time base for token ages, set by the first time value the endpoint sees.
    pub epoch: std::sync::OnceLock<std::time::Instant>,
}

impl Config {
    /// A configuration with random keys from the provider and default settings.
    pub fn new(provider: Arc<dyn CryptoProvider>) -> Self {
        let mut reset_key = [0u8; 32];
        let mut token_key = [0u8; 32];
        provider.fill_random(&mut reset_key);
        provider.fill_random(&mut token_key);
        Config {
            provider,
            transport: TransportConfig::default(),
            reset_key,
            token_key,
            versions: vec![VERSION_1],
            retry: false,
            retry_threshold: 1000,
            retry_token_lifetime: Duration::from_secs(10),
            new_token_lifetime: None,
            cid_len: 8,
            max_connections: 100_000,
            epoch: std::sync::OnceLock::new(),
        }
    }

    /// The stateless reset token for a connection ID (RFC 9000 §10.3.2).
    pub fn reset_token(&self, cid: &[u8]) -> [u8; 16] {
        let h = self.provider.hmac(&self.reset_key, &[b"reset", cid]);
        h[..16].try_into().unwrap()
    }
}
