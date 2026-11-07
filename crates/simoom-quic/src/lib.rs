//! Sans-io QUIC v1 transport (RFC 9000, RFC 9001, RFC 9002) for simoom, with QUIC v2
//! (RFC 9369) when enabled in [`Config::versions`].
//!
//! The crate never touches sockets or clocks: an [`Endpoint`] takes datagrams, the time and
//! the peer address, and returns datagrams to send, a deadline and per-connection events.
//! Packet protection and the TLS handshake go through the [`crypto`] traits.

#![forbid(unsafe_code)]

pub mod coding;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod endpoint;
pub mod error;
pub mod frame;
pub mod packet;
pub mod params;
pub mod ranges;
pub mod recovery;
pub mod sim;
pub mod stream;
pub mod tls;
pub mod token;

pub use config::{Config, TransportConfig};
pub use connection::{Connection, ConnectionError, EndpointEvent, Event, Stats, Transmit};
pub use crypto::{CryptoProvider, CryptoSession, Level};
pub use endpoint::{ConnHandle, DatagramEvent, Endpoint};
pub use error::{StreamError, TransportError};
pub use packet::{VERSION_1, VERSION_2};
pub use params::{Cid, TransportParams};
