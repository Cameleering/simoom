//! Sans-io TLS 1.3 server and client for simoom, with the QUIC interface (RFC 9001).
//!
//! Everything is std-only and written from scratch; the only `unsafe` code (hardware AES,
//! carry-less multiply, SHA-256, SIMD ChaCha20 and the OS random source) lives in
//! `simoom_sys::arch` behind safe wrappers. This crate forbids `unsafe`.
//!
//! # TLS over a byte stream
//!
//! A [`ServerConnection`] or [`ClientConnection`] never touches a socket or a clock. Feed it
//! received bytes, process them, send what it produces, and exchange plaintext:
//!
//! ```
//! # #[cfg(feature = "client")]
//! # fn main() -> Result<(), simoom_tls::Error> {
//! use simoom_tls::{certgen, x509::RootStore, CertifiedKey, ClientConfig, ClientConnection, ServerConfig, ServerConnection};
//! use std::sync::Arc;
//!
//! let cert = certgen::self_signed("localhost");
//! let server_cfg = Arc::new(ServerConfig::new(CertifiedKey::new(vec![cert.cert_der.clone()], cert.key.clone())?).with_alpn(&[b"h2"]));
//! let mut roots = RootStore::empty();
//! roots.add_der(&cert.cert_der).unwrap();
//! let client_cfg = Arc::new(ClientConfig::new(roots).with_alpn(&[b"h2"]));
//!
//! let mut server = ServerConnection::new(server_cfg);
//! let mut client = ClientConnection::new(client_cfg, "localhost")?;
//! client.write_plaintext(b"hello")?; // sent as soon as the handshake completes
//! while client.wants_write() || server.wants_write() {
//!     let n = server.read_tls(client.tls_output());
//!     client.consume_tls_output(n);
//!     server.process_new_packets()?;
//!     let n = client.read_tls(server.tls_output());
//!     server.consume_tls_output(n);
//!     client.process_new_packets()?;
//! }
//! let mut buf = [0u8; 16];
//! let n = server.read_plaintext(&mut buf);
//! assert_eq!(&buf[..n], b"hello");
//! assert_eq!(server.alpn_protocol(), Some(&b"h2"[..]));
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "client"))]
//! # fn main() {}
//! ```
//!
//! # What is supported
//!
//! - TLS 1.3 only (RFC 8446): `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
//!   `TLS_CHACHA20_POLY1305_SHA256`; X25519 and secp256r1 key exchange; HelloRetryRequest.
//! - Certificates: ECDSA P-256 and P-384, Ed25519, RSA (PSS signatures in the handshake,
//!   PKCS#1 v1.5 and PSS in certificates); chains from PEM or DER; keys in PKCS#8, SEC1 or
//!   PKCS#1; SNI-based certificate selection; X.509 path validation with hostname checks.
//! - ALPN, SNI, client certificates ([`ClientAuth`]), session tickets with rotating keys
//!   ([`Ticketer`]) and PSK-DHE resumption, KeyUpdate, alerts, close_notify, the keying
//!   material exporter, and [`Connection::export_traffic_secrets`] for kernel TLS.
//! - 0-RTT is never offered or accepted; rejected early data is skipped as RFC 8446 requires.
//! - [`quic::QuicConnection`]: handshake messages per encryption level, packet and header
//!   protection keys, key updates, Retry integrity tags, QUIC v1 and v2.
//! - [`certgen`]: self-signed and CA-issued certificates for tests.
//!
//! TLS 1.2 is not implemented (the plan's optional `tls12` feature).
//!
//! The `client` feature (default) provides the client side; servers can turn it off.

#![forbid(unsafe_code)]

pub mod asn1;
pub mod certgen;
pub mod crypto;
pub mod keys;
pub mod pem;
pub mod quic;
pub mod tls;
pub mod util;
pub mod x509;

pub use tls::config::{CertifiedKey, ClientAuth, ServerConfig, SystemClock, Ticketer, TimeSource};
#[cfg(feature = "client")]
pub use tls::config::{ClientConfig, SessionCache};
#[cfg(feature = "client")]
pub use tls::conn::ClientConnection;
pub use tls::conn::{Connection, DirectionalSecret, ExportedSecrets, IoState, ServerConnection};
pub use tls::{alert, CipherSuite, Error, Level, NamedGroup};
