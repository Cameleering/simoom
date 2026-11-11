//! TLS 1.3 (RFC 8446): the sans-io handshake engine shared by the record-layer connections and
//! the QUIC interface, plus the record layer itself.

#[cfg(feature = "client")]
pub(crate) mod client;
pub(crate) mod codec;
pub mod config;
pub mod conn;
pub(crate) mod engine;
pub(crate) mod keyschedule;
pub(crate) mod record;
pub(crate) mod server;
#[cfg(feature = "tls12")]
pub mod tls12;
#[cfg(all(feature = "tls12", feature = "client"))]
pub(crate) mod client12;
#[cfg(feature = "tls12")]
pub(crate) mod server12;

use crate::crypto::sha2::HashAlg;
use crate::crypto::{p256, rng, x25519};
use crate::keys::{EcCurve, PrivateKey, PublicKey};
use crate::x509::CertError;
use std::fmt;

pub(crate) mod content {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

pub(crate) mod hs {
    #[cfg(feature = "tls12")]
    pub const HELLO_REQUEST: u8 = 0;
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const NEW_SESSION_TICKET: u8 = 4;
    pub const END_OF_EARLY_DATA: u8 = 5;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_REQUEST: u8 = 13;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
    pub const KEY_UPDATE: u8 = 24;
    #[cfg(feature = "tls12")]
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    #[cfg(feature = "tls12")]
    pub const SERVER_HELLO_DONE: u8 = 14;
    #[cfg(feature = "tls12")]
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    #[cfg(all(feature = "tls12", any(feature = "client", feature = "revocation")))]
    pub const CERTIFICATE_STATUS: u8 = 22;
    pub const MESSAGE_HASH: u8 = 254;
}

pub(crate) mod ext {
    pub const SERVER_NAME: u16 = 0;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const ALPN: u16 = 16;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const EARLY_DATA: u16 = 42;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    #[cfg(feature = "client")]
    pub const COOKIE: u16 = 44;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const CERTIFICATE_AUTHORITIES: u16 = 47;
    pub const KEY_SHARE: u16 = 51;
    pub const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;
    #[cfg(any(all(feature = "tls12", feature = "client"), feature = "revocation"))]
    pub const STATUS_REQUEST: u16 = 5;
    #[cfg(feature = "tls12")]
    pub const EC_POINT_FORMATS: u16 = 11;
    #[cfg(feature = "tls12")]
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    #[cfg(feature = "tls12")]
    pub const SESSION_TICKET: u16 = 35;
    #[cfg(feature = "tls12")]
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// TLS alert descriptions (RFC 8446 section 6).
pub mod alert {
    pub const CLOSE_NOTIFY: u8 = 0;
    pub const UNEXPECTED_MESSAGE: u8 = 10;
    pub const BAD_RECORD_MAC: u8 = 20;
    pub const RECORD_OVERFLOW: u8 = 22;
    pub const HANDSHAKE_FAILURE: u8 = 40;
    pub const BAD_CERTIFICATE: u8 = 42;
    pub const UNSUPPORTED_CERTIFICATE: u8 = 43;
    pub const CERTIFICATE_REVOKED: u8 = 44;
    pub const CERTIFICATE_EXPIRED: u8 = 45;
    pub const CERTIFICATE_UNKNOWN: u8 = 46;
    pub const ILLEGAL_PARAMETER: u8 = 47;
    pub const UNKNOWN_CA: u8 = 48;
    pub const DECODE_ERROR: u8 = 50;
    pub const DECRYPT_ERROR: u8 = 51;
    pub const PROTOCOL_VERSION: u8 = 70;
    pub const INAPPROPRIATE_FALLBACK: u8 = 86;
    pub const INTERNAL_ERROR: u8 = 80;
    pub const USER_CANCELED: u8 = 90;
    pub const NO_RENEGOTIATION: u8 = 100;
    pub const MISSING_EXTENSION: u8 = 109;
    pub const UNSUPPORTED_EXTENSION: u8 = 110;
    pub const UNRECOGNIZED_NAME: u8 = 112;
    pub const BAD_CERTIFICATE_STATUS_RESPONSE: u8 = 113;
    pub const CERTIFICATE_REQUIRED: u8 = 116;
    pub const NO_APPLICATION_PROTOCOL: u8 = 120;

    /// The RFC name of an alert.
    pub fn name(code: u8) -> &'static str {
        match code {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            22 => "record_overflow",
            40 => "handshake_failure",
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            47 => "illegal_parameter",
            48 => "unknown_ca",
            49 => "access_denied",
            50 => "decode_error",
            51 => "decrypt_error",
            70 => "protocol_version",
            71 => "insufficient_security",
            80 => "internal_error",
            86 => "inappropriate_fallback",
            90 => "user_canceled",
            100 => "no_renegotiation",
            109 => "missing_extension",
            110 => "unsupported_extension",
            112 => "unrecognized_name",
            113 => "bad_certificate_status_response",
            116 => "certificate_required",
            120 => "no_application_protocol",
            _ => "unknown_alert",
        }
    }
}

/// A TLS error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A protocol violation detected locally; `alert` is sent to the peer.
    Protocol { alert: u8, reason: std::borrow::Cow<'static, str> },
    /// The peer sent a fatal alert.
    PeerAlert(u8),
    /// The peer's certificate failed validation.
    Certificate(CertError),
    /// Invalid configuration or API misuse.
    Config(String),
    /// The connection is closed.
    Closed,
}

impl Error {
    pub(crate) fn proto(alert: u8, reason: impl Into<std::borrow::Cow<'static, str>>) -> Error {
        Error::Protocol { alert, reason: reason.into() }
    }
    #[cold]
    #[inline(never)]
    pub(crate) fn decode(what: &str) -> Error {
        Error::proto(alert::DECODE_ERROR, format!("malformed {what}"))
    }
    #[cold]
    #[inline(never)]
    pub(crate) fn unexpected(what: &str) -> Error {
        Error::proto(alert::UNEXPECTED_MESSAGE, format!("unexpected {what}"))
    }
    /// The alert this error sends to the peer (or the one the peer sent).
    pub fn alert(&self) -> Option<u8> {
        match self {
            Error::Protocol { alert, .. } => Some(*alert),
            Error::PeerAlert(a) => Some(*a),
            Error::Certificate(c) => Some(match c {
                CertError::Expired { .. } | CertError::NotYetValid { .. } => alert::CERTIFICATE_EXPIRED,
                CertError::UnknownIssuer { .. } => alert::UNKNOWN_CA,
                CertError::Parse(_) | CertError::BadSignature { .. } => alert::BAD_CERTIFICATE,
                CertError::NoCertificates => alert::CERTIFICATE_REQUIRED,
                CertError::Revoked { .. } => alert::CERTIFICATE_REVOKED,
                CertError::RevocationUnknown { .. } => alert::BAD_CERTIFICATE_STATUS_RESPONSE,
                _ => alert::CERTIFICATE_UNKNOWN,
            }),
            Error::Config(_) => Some(alert::INTERNAL_ERROR),
            Error::Closed => None,
        }
    }
    /// The alert to send for a locally detected error (None for peer alerts).
    pub(crate) fn alert_to_send(&self) -> Option<u8> {
        match self {
            Error::PeerAlert(_) | Error::Closed => None,
            e => e.alert(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol { alert: a, reason } => write!(f, "TLS protocol error: {reason} (alert {})", alert::name(*a)),
            Error::PeerAlert(a) => write!(f, "TLS alert from peer: {} ({a})", alert::name(*a)),
            Error::Certificate(c) => write!(f, "TLS certificate error: {c}"),
            Error::Config(m) => write!(f, "TLS configuration error: {m}"),
            Error::Closed => f.write_str("TLS connection closed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<CertError> for Error {
    fn from(e: CertError) -> Error {
        Error::Certificate(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// A negotiated protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolVersion {
    /// TLS 1.2 (RFC 5246), only with the `tls12` feature.
    Tls12,
    /// TLS 1.3 (RFC 8446).
    Tls13,
}

impl ProtocolVersion {
    /// The name Java and Camel use (`TLSv1.2`, `TLSv1.3`).
    pub fn name(self) -> &'static str {
        match self {
            ProtocolVersion::Tls12 => "TLSv1.2",
            ProtocolVersion::Tls13 => "TLSv1.3",
        }
    }
    /// Parses `TLSv1.2`, `TLSv1.3`, `1.2`, `TLS1.3` and similar spellings.
    pub fn parse(s: &str) -> Option<ProtocolVersion> {
        let v = s.trim().to_ascii_lowercase();
        let v = v.trim_start_matches("tlsv").trim_start_matches("tls");
        match v.trim_start_matches(['v', '_', '-']) {
            "1.2" | "12" | "1_2" => Some(ProtocolVersion::Tls12),
            "1.3" | "13" | "1_3" => Some(ProtocolVersion::Tls13),
            _ => None,
        }
    }
}

/// Encryption level of handshake data (RFC 9001 terms; the record layer uses the same three).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Plaintext (QUIC Initial packets).
    Initial,
    /// Handshake traffic keys.
    Handshake,
    /// Application traffic keys.
    OneRtt,
}

/// TLS 1.3 cipher suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    #[cfg(feature = "chacha20")]
    Chacha20Poly1305Sha256,
}

/// The AEAD of a cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    #[cfg(feature = "chacha20")]
    Chacha20Poly1305,
}

impl AeadAlg {
    pub fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            _ => 32,
        }
    }
}

impl CipherSuite {
    /// Every suite, in the default server preference when the CPU has AES instructions.
    #[cfg(feature = "chacha20")]
    pub const ALL: [CipherSuite; 3] = [CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384, CipherSuite::Chacha20Poly1305Sha256];
    /// Every suite, in the default server preference.
    #[cfg(not(feature = "chacha20"))]
    pub const ALL: [CipherSuite; 2] = [CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];

    /// The default preference: AES-GCM first with hardware AES, ChaCha20-Poly1305 first without.
    pub fn default_order() -> Vec<CipherSuite> {
        #[cfg(feature = "chacha20")]
        if !(simoom_sys::arch::has_aes() && simoom_sys::arch::has_clmul()) {
            return vec![CipherSuite::Chacha20Poly1305Sha256, CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384];
        }
        CipherSuite::ALL.to_vec()
    }
    pub fn id(self) -> u16 {
        match self {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::Aes256GcmSha384 => 0x1302,
            #[cfg(feature = "chacha20")]
            CipherSuite::Chacha20Poly1305Sha256 => 0x1303,
        }
    }
    pub fn from_id(id: u16) -> Option<CipherSuite> {
        CipherSuite::ALL.into_iter().find(|s| s.id() == id)
    }
    /// The IANA name, such as `TLS_AES_128_GCM_SHA256`.
    pub fn name(self) -> &'static str {
        match self {
            CipherSuite::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            #[cfg(feature = "chacha20")]
            CipherSuite::Chacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }
    pub fn hash(self) -> HashAlg {
        match self {
            CipherSuite::Aes256GcmSha384 => HashAlg::Sha384,
            _ => HashAlg::Sha256,
        }
    }
    pub fn aead(self) -> AeadAlg {
        match self {
            CipherSuite::Aes128GcmSha256 => AeadAlg::Aes128Gcm,
            CipherSuite::Aes256GcmSha384 => AeadAlg::Aes256Gcm,
            #[cfg(feature = "chacha20")]
            CipherSuite::Chacha20Poly1305Sha256 => AeadAlg::Chacha20Poly1305,
        }
    }
}

/// Key-exchange groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamedGroup {
    X25519,
    Secp256r1,
    /// secp384r1 (feature `p384`): not in the default lists; add it to `groups` to offer or
    /// accept it.
    #[cfg(feature = "p384")]
    Secp384r1,
}

impl NamedGroup {
    /// The default groups, in preference order.
    pub const ALL: [NamedGroup; 2] = [NamedGroup::X25519, NamedGroup::Secp256r1];
    pub fn id(self) -> u16 {
        match self {
            NamedGroup::X25519 => 0x001d,
            NamedGroup::Secp256r1 => 0x0017,
            #[cfg(feature = "p384")]
            NamedGroup::Secp384r1 => 0x0018,
        }
    }
    pub fn from_id(id: u16) -> Option<NamedGroup> {
        match id {
            0x001d => Some(NamedGroup::X25519),
            0x0017 => Some(NamedGroup::Secp256r1),
            #[cfg(feature = "p384")]
            0x0018 => Some(NamedGroup::Secp384r1),
            _ => None,
        }
    }
    /// The IANA name (`x25519`, `secp256r1`, `secp384r1`).
    pub fn name(self) -> &'static str {
        match self {
            NamedGroup::X25519 => "x25519",
            NamedGroup::Secp256r1 => "secp256r1",
            #[cfg(feature = "p384")]
            NamedGroup::Secp384r1 => "secp384r1",
        }
    }
}

/// An ephemeral key pair.
pub(crate) struct KeyShare {
    pub group: NamedGroup,
    private: [u8; 48],
    pub public: Vec<u8>,
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.private);
    }
}

impl KeyShare {
    pub fn generate(group: NamedGroup) -> KeyShare {
        match group {
            NamedGroup::X25519 => {
                let mut sk = rng::array::<32>();
                let public = x25519::x25519_base(&sk).to_vec();
                let private = Self::pad(&sk);
                crate::util::zeroize(&mut sk);
                KeyShare { group, public, private }
            }
            NamedGroup::Secp256r1 => {
                let mut sk = p256::generate_private();
                let public = p256::public_key(&sk).expect("valid scalar").to_vec();
                let private = Self::pad(&sk);
                crate::util::zeroize(&mut sk);
                KeyShare { group, public, private }
            }
            #[cfg(feature = "p384")]
            NamedGroup::Secp384r1 => {
                let mut sk = crate::crypto::ec::p384::generate_private();
                let public = crate::crypto::ec::p384::public_key(&sk).expect("valid scalar");
                let mut private = [0u8; 48];
                private.copy_from_slice(&sk);
                crate::util::zeroize(&mut sk);
                KeyShare { group, public, private }
            }
        }
    }

    fn pad(sk: &[u8]) -> [u8; 48] {
        let mut p = [0u8; 48];
        p[..sk.len()].copy_from_slice(sk);
        p
    }

    /// The shared secret; fails for invalid peer keys.
    pub fn agree(&self, peer: &[u8]) -> Result<Vec<u8>> {
        let bad = || Error::proto(alert::ILLEGAL_PARAMETER, "invalid key share");
        match self.group {
            NamedGroup::X25519 => {
                let p: [u8; 32] = peer.try_into().map_err(|_| bad())?;
                let sk: &[u8; 32] = self.private[..32].try_into().expect("32 bytes");
                x25519::agree(sk, &p).map(|s| s.to_vec()).ok_or_else(bad)
            }
            NamedGroup::Secp256r1 => {
                let sk: &[u8; 32] = self.private[..32].try_into().expect("32 bytes");
                p256::ecdh(sk, peer).map(|s| s.to_vec()).ok_or_else(bad)
            }
            #[cfg(feature = "p384")]
            NamedGroup::Secp384r1 => crate::crypto::ec::p384::ecdh(&self.private, peer).ok_or_else(bad),
        }
    }
}

/// Signature schemes (RFC 8446 section 4.2.3).
#[allow(dead_code)] // some are unused without the rsa or ed25519 features
pub(crate) mod sigscheme {
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const ED25519: u16 = 0x0807;

    /// What we offer and accept in signature_algorithms. PKCS#1 v1.5 is listed because it
    /// also covers certificate signatures; it is never accepted in CertificateVerify.
    pub const SUPPORTED: &[u16] = &[
        #[cfg(feature = "ed25519")]
        ED25519,
        ECDSA_SECP256R1_SHA256,
        #[cfg(feature = "p384")]
        ECDSA_SECP384R1_SHA384,
        #[cfg(feature = "rsa")]
        RSA_PSS_RSAE_SHA256,
        #[cfg(feature = "rsa")]
        RSA_PSS_RSAE_SHA384,
        #[cfg(feature = "rsa")]
        RSA_PSS_RSAE_SHA512,
        #[cfg(feature = "rsa")]
        RSA_PKCS1_SHA256,
        #[cfg(feature = "rsa")]
        RSA_PKCS1_SHA384,
        #[cfg(feature = "rsa")]
        RSA_PKCS1_SHA512,
    ];
}

fn scheme_hash(scheme: u16) -> Option<HashAlg> {
    use sigscheme::*;
    match scheme {
        ECDSA_SECP256R1_SHA256 | RSA_PSS_RSAE_SHA256 => Some(HashAlg::Sha256),
        ECDSA_SECP384R1_SHA384 | RSA_PSS_RSAE_SHA384 => Some(HashAlg::Sha384),
        RSA_PSS_RSAE_SHA512 => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// The signature scheme for `key` among the peer's offered schemes.
pub(crate) fn choose_scheme(key: &PrivateKey, offered: &[u16]) -> Option<u16> {
    use sigscheme::*;
    let candidates: &[u16] = match key {
        PrivateKey::Ec { curve: EcCurve::P256, .. } => &[ECDSA_SECP256R1_SHA256],
        #[cfg(feature = "p384")]
        PrivateKey::Ec { curve: EcCurve::P384, .. } => &[ECDSA_SECP384R1_SHA384],
        #[cfg(feature = "ed25519")]
        PrivateKey::Ed25519 { .. } => &[ED25519],
        #[cfg(feature = "rsa")]
        PrivateKey::Rsa(_) => &[RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512],
    };
    candidates.iter().copied().find(|c| offered.contains(c))
}

/// Signs a CertificateVerify message.
pub(crate) fn sign_message(key: &PrivateKey, scheme: u16, message: &[u8]) -> Result<Vec<u8>> {
    let fail = || Error::proto(alert::INTERNAL_ERROR, "signing failed");
    #[cfg(feature = "ed25519")]
    if let PrivateKey::Ed25519 { seed, public } = key {
        return Ok(crate::crypto::ed25519::sign_with_public(seed, public, message).to_vec());
    }
    let h = scheme_hash(scheme).ok_or_else(fail)?;
    let digest = h.hash(message);
    match key {
        PrivateKey::Ec { curve, d, .. } => {
            curve.sign(d, &digest, h).map(|(r, s)| crate::keys::ecdsa_sig_to_der(&r, &s)).ok_or_else(fail)
        }
        #[cfg(feature = "rsa")]
        PrivateKey::Rsa(k) => k.sign_pss(h, &digest).ok_or_else(fail),
        #[cfg(feature = "ed25519")]
        PrivateKey::Ed25519 { .. } => Err(fail()),
    }
}

/// Verifies a CertificateVerify signature. ECDSA schemes are bound to their curve and PKCS#1
/// v1.5 is refused, as TLS 1.3 requires.
pub(crate) fn verify_message(key: &PublicKey, scheme: u16, message: &[u8], sig: &[u8]) -> Result<()> {
    use sigscheme::*;
    let fail = || Error::proto(alert::DECRYPT_ERROR, "handshake signature verification failed");
    let mismatch = || Error::proto(alert::ILLEGAL_PARAMETER, "signature scheme does not match the key");
    let ok = match (key, scheme) {
        #[cfg(feature = "ed25519")]
        (PublicKey::Ed25519(k), ED25519) => crate::crypto::ed25519::verify(k, message, sig),
        (PublicKey::Ec { curve, point }, ECDSA_SECP256R1_SHA256 | ECDSA_SECP384R1_SHA384) => {
            if (scheme == ECDSA_SECP256R1_SHA256) != (*curve == EcCurve::P256) {
                return Err(mismatch());
            }
            let h = scheme_hash(scheme).unwrap();
            match crate::keys::ecdsa_sig_from_der(sig) {
                Some((r, s)) => curve.verify(point, &h.hash(message), &r, &s),
                None => false,
            }
        }
        #[cfg(feature = "rsa")]
        (PublicKey::Rsa(k), RSA_PSS_RSAE_SHA256 | RSA_PSS_RSAE_SHA384 | RSA_PSS_RSAE_SHA512) => {
            let h = scheme_hash(scheme).unwrap();
            k.verify_pss(h, &h.hash(message), sig, Some(h.output_len()))
        }
        _ => return Err(mismatch()),
    };
    if ok {
        Ok(())
    } else {
        Err(fail())
    }
}

/// The content signed in CertificateVerify (RFC 8446 section 4.4.3).
pub(crate) fn cv_content(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let mut m = vec![0x20u8; 64];
    m.extend_from_slice(if server { b"TLS 1.3, server CertificateVerify" } else { b"TLS 1.3, client CertificateVerify" });
    m.push(0);
    m.extend_from_slice(transcript_hash);
    m
}

/// The fixed ServerHello.random of a HelloRetryRequest.
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a,
    0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// How a peer's certificate chain is checked (shared by both versions and both sides).
pub(crate) struct PeerCheck<'a> {
    pub roots: &'a crate::x509::RootStore,
    /// Unix seconds.
    pub now: i64,
    pub eku: &'a str,
    #[cfg(feature = "revocation")]
    pub revocation: Option<&'a crate::revocation::RevocationPolicy>,
    #[cfg(feature = "revocation")]
    pub staple: Option<&'a [u8]>,
}

impl PeerCheck<'_> {
    /// Validates the chain (and its revocation status, when a policy is set) and returns the
    /// leaf's public key. `host` is an argument rather than a field, so that a server-only build
    /// (every caller passes `None`) leaves the hostname checks out.
    pub fn verify(&self, certs: &[Vec<u8>], host: Option<&str>) -> Result<PublicKey> {
        #[cfg(feature = "revocation")]
        if let Some(policy) = self.revocation {
            let path = crate::x509::verify_chain_path(certs, host, self.roots, self.now, self.eku)?;
            crate::revocation::check_path(&path, policy, self.now, self.staple)?;
            return path
                .into_iter()
                .next()
                .and_then(|leaf| leaf.public_key)
                .ok_or_else(|| Error::proto(alert::UNSUPPORTED_CERTIFICATE, "unsupported certificate key"));
        }
        crate::x509::verify_chain(certs, host, self.roots, self.now, self.eku)?
            .public_key
            .ok_or_else(|| Error::proto(alert::UNSUPPORTED_CERTIFICATE, "unsupported certificate key"))
    }
}
