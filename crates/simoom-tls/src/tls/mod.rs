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
    pub const CERTIFICATE_EXPIRED: u8 = 45;
    pub const CERTIFICATE_UNKNOWN: u8 = 46;
    pub const ILLEGAL_PARAMETER: u8 = 47;
    pub const UNKNOWN_CA: u8 = 48;
    pub const DECODE_ERROR: u8 = 50;
    pub const DECRYPT_ERROR: u8 = 51;
    pub const PROTOCOL_VERSION: u8 = 70;
    pub const INTERNAL_ERROR: u8 = 80;
    pub const USER_CANCELED: u8 = 90;
    pub const MISSING_EXTENSION: u8 = 109;
    pub const UNSUPPORTED_EXTENSION: u8 = 110;
    pub const UNRECOGNIZED_NAME: u8 = 112;
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
            109 => "missing_extension",
            110 => "unsupported_extension",
            112 => "unrecognized_name",
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
    pub(crate) fn decode(what: &str) -> Error {
        Error::proto(alert::DECODE_ERROR, format!("malformed {what}"))
    }
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
}

impl NamedGroup {
    pub const ALL: [NamedGroup; 2] = [NamedGroup::X25519, NamedGroup::Secp256r1];
    pub fn id(self) -> u16 {
        match self {
            NamedGroup::X25519 => 0x001d,
            NamedGroup::Secp256r1 => 0x0017,
        }
    }
    pub fn from_id(id: u16) -> Option<NamedGroup> {
        NamedGroup::ALL.into_iter().find(|g| g.id() == id)
    }
}

/// An ephemeral key pair.
pub(crate) struct KeyShare {
    pub group: NamedGroup,
    private: [u8; 32],
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
                let sk = rng::array::<32>();
                KeyShare { group, public: x25519::x25519_base(&sk).to_vec(), private: sk }
            }
            NamedGroup::Secp256r1 => {
                let sk = p256::generate_private();
                KeyShare { group, public: p256::public_key(&sk).expect("valid scalar").to_vec(), private: sk }
            }
        }
    }

    /// The shared secret; fails for invalid peer keys.
    pub fn agree(&self, peer: &[u8]) -> Result<Vec<u8>> {
        let bad = || Error::proto(alert::ILLEGAL_PARAMETER, "invalid key share");
        match self.group {
            NamedGroup::X25519 => {
                let p: [u8; 32] = peer.try_into().map_err(|_| bad())?;
                x25519::agree(&self.private, &p).map(|s| s.to_vec()).ok_or_else(bad)
            }
            NamedGroup::Secp256r1 => p256::ecdh(&self.private, peer).map(|s| s.to_vec()).ok_or_else(bad),
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
