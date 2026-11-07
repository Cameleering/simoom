//! Server and client configuration: certificates and SNI, client authentication, ALPN, session
//! tickets with rotating keys, and the time source.

use super::{CipherSuite, Error, NamedGroup, Result};
use crate::crypto::gcm::AesGcm;
use crate::crypto::rng;
use crate::keys::PrivateKey;
use crate::x509::{Certificate, RootStore};
#[cfg(feature = "client")]
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Wall-clock time in Unix milliseconds. The protocol code never reads a clock itself: ticket
/// ages and certificate validity use this. Tests inject fixed times.
pub trait TimeSource: Send + Sync {
    fn unix_millis(&self) -> u64;
}

/// The operating system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl TimeSource for SystemClock {
    fn unix_millis(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
}

/// A certificate chain (leaf first, DER) with its private key.
#[derive(Clone, Debug)]
pub struct CertifiedKey {
    pub chain: Vec<Vec<u8>>,
    pub key: PrivateKey,
}

impl CertifiedKey {
    /// Checks that the key matches the leaf certificate.
    pub fn new(chain: Vec<Vec<u8>>, key: PrivateKey) -> Result<CertifiedKey> {
        let leaf = chain.first().ok_or_else(|| Error::Config("empty certificate chain".into()))?;
        let cert = Certificate::from_der(leaf).map_err(|e| Error::Config(format!("bad certificate: {e}")))?;
        match &cert.public_key {
            Some(pk) if pk.same_as(&key.public_key()) => Ok(CertifiedKey { chain, key }),
            Some(_) => Err(Error::Config("the private key does not match the certificate".into())),
            None => Err(Error::Config("unsupported certificate key type".into())),
        }
    }

    /// From PEM text: every CERTIFICATE block (leaf first) and the first private key.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey> {
        let chain: Vec<Vec<u8>> = crate::pem::parse_pem(cert_pem)
            .map_err(Error::Config)?
            .into_iter()
            .filter(|b| b.label == "CERTIFICATE")
            .map(|b| b.der)
            .collect();
        let key = PrivateKey::from_pem(key_pem).map_err(Error::Config)?;
        CertifiedKey::new(chain, key)
    }

    /// From DER: the chain and a key in PKCS#8, SEC1 or PKCS#1.
    pub fn from_der(chain: Vec<Vec<u8>>, key_der: &[u8]) -> Result<CertifiedKey> {
        let key = PrivateKey::from_der(key_der).map_err(Error::Config)?;
        CertifiedKey::new(chain, key)
    }

    fn names(&self) -> Vec<String> {
        match Certificate::from_der(&self.chain[0]) {
            Ok(c) if c.has_san => c.dns_names,
            Ok(c) => c.subject.common_name().map(|s| vec![s.to_ascii_lowercase()]).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }
}

/// Client certificate authentication on a server.
#[derive(Clone, Debug, Default)]
pub enum ClientAuth {
    /// No CertificateRequest.
    #[default]
    None,
    /// Request a certificate; accept clients without one, validate the ones that send one.
    Optional(RootStore),
    /// Require a valid client certificate.
    Required(RootStore),
}

/// Encrypts and decrypts session tickets with AES-256-GCM under keys that rotate every
/// `rotate_secs`; the previous key stays valid for one more period.
pub struct Ticketer {
    keys: Mutex<TicketKeys>,
    rotate_ms: u64,
}

struct TicketKey {
    id: [u8; 8],
    aead: AesGcm,
    created_ms: u64,
}

struct TicketKeys {
    current: Option<TicketKey>,
    previous: Option<TicketKey>,
}

impl std::fmt::Debug for Ticketer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ticketer(rotate every {} s)", self.rotate_ms / 1000)
    }
}

impl Ticketer {
    pub fn new(rotate_secs: u32) -> Ticketer {
        Ticketer { keys: Mutex::new(TicketKeys { current: None, previous: None }), rotate_ms: rotate_secs.max(1) as u64 * 1000 }
    }

    fn fresh(now: u64) -> TicketKey {
        let mut k = rng::array::<32>();
        let key = TicketKey { id: rng::array(), aead: AesGcm::new(&k), created_ms: now };
        crate::util::zeroize(&mut k);
        key
    }

    fn rotate(&self, keys: &mut TicketKeys, now: u64) {
        let stale = match &keys.current {
            None => true,
            Some(k) => now.saturating_sub(k.created_ms) >= self.rotate_ms,
        };
        if stale {
            keys.previous = keys.current.take();
            keys.current = Some(Self::fresh(now));
            if let Some(p) = &keys.previous {
                if now.saturating_sub(p.created_ms) >= 2 * self.rotate_ms {
                    keys.previous = None;
                }
            }
        }
    }

    /// key id (8) || nonce (12) || ciphertext || tag (16).
    pub(crate) fn seal(&self, now: u64, plain: &[u8]) -> Vec<u8> {
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        self.rotate(&mut keys, now);
        let k = keys.current.as_ref().expect("current key");
        let nonce = rng::array::<12>();
        let mut out = Vec::with_capacity(36 + plain.len());
        out.extend_from_slice(&k.id);
        out.extend_from_slice(&nonce);
        let start = out.len();
        out.extend_from_slice(plain);
        let tag = k.aead.seal(&nonce, &k.id, &mut out[start..]);
        out.extend_from_slice(&tag);
        out
    }

    pub(crate) fn open(&self, now: u64, ticket: &[u8]) -> Option<Vec<u8>> {
        if ticket.len() < 36 {
            return None;
        }
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        self.rotate(&mut keys, now);
        let (id, rest) = ticket.split_at(8);
        let (nonce, rest) = rest.split_at(12);
        let (ct, tag) = rest.split_at(rest.len() - 16);
        for k in [&keys.current, &keys.previous].into_iter().flatten() {
            if k.id == id {
                let mut pt = ct.to_vec();
                return k.aead.open(nonce.try_into().unwrap(), &k.id, &mut pt, tag).then_some(pt);
            }
        }
        None
    }

    /// Forces a new key now (for tests and operators).
    pub fn rotate_now(&self, now_ms: u64) {
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        keys.previous = keys.current.take();
        keys.current = Some(Self::fresh(now_ms));
    }
}

/// Server configuration.
pub struct ServerConfig {
    pub(crate) default_cert: Option<Arc<CertifiedKey>>,
    pub(crate) sni_certs: Vec<(String, Arc<CertifiedKey>)>,
    /// ALPN protocols in preference order (empty: ALPN is ignored).
    pub alpn: Vec<Vec<u8>>,
    pub client_auth: ClientAuth,
    pub suites: Vec<CipherSuite>,
    pub groups: Vec<NamedGroup>,
    /// Session tickets (None disables resumption).
    pub ticketer: Option<Arc<Ticketer>>,
    /// Ticket lifetime advertised to clients and enforced on resumption.
    pub ticket_lifetime_secs: u32,
    /// NewSessionTickets sent after each full handshake.
    pub ticket_count: u8,
    /// Reject clients whose SNI matches no configured name (unrecognized_name) instead of
    /// using the default certificate.
    pub strict_sni: bool,
    /// Largest handshake message accepted.
    pub max_handshake_message: usize,
    pub time: Arc<dyn TimeSource>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig").field("alpn", &self.alpn).field("suites", &self.suites).field("groups", &self.groups).finish()
    }
}

impl ServerConfig {
    /// A configuration serving one certificate chain; tickets on, no client authentication.
    pub fn new(cert: CertifiedKey) -> ServerConfig {
        ServerConfig {
            default_cert: Some(Arc::new(cert)),
            sni_certs: Vec::new(),
            alpn: Vec::new(),
            client_auth: ClientAuth::None,
            suites: CipherSuite::default_order(),
            groups: NamedGroup::ALL.to_vec(),
            ticketer: Some(Arc::new(Ticketer::new(6 * 3600))),
            ticket_lifetime_secs: 6 * 3600,
            ticket_count: 1,
            strict_sni: false,
            max_handshake_message: 64 * 1024,
            time: Arc::new(SystemClock),
        }
    }

    /// From PEM certificate chain and key.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig> {
        Ok(ServerConfig::new(CertifiedKey::from_pem(cert_pem, key_pem)?))
    }

    /// Adds a certificate selected by SNI for every DNS name in its leaf (wildcards included).
    pub fn add_sni_cert(&mut self, cert: CertifiedKey) {
        let cert = Arc::new(cert);
        for n in cert.names() {
            self.sni_certs.push((n, cert.clone()));
        }
    }

    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> ServerConfig {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    pub(crate) fn resolve(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = sni {
            if let Some((_, c)) = self.sni_certs.iter().find(|(p, _)| crate::x509::dns_name_matches(p, name)) {
                return Some(c.clone());
            }
            if self.strict_sni && !self.sni_certs.is_empty() {
                return None;
            }
        }
        self.default_cert.clone()
    }
}

/// A resumable session remembered by a client.
#[cfg(feature = "client")]
#[derive(Clone, Debug)]
pub(crate) struct StoredSession {
    pub suite: CipherSuite,
    pub psk: Vec<u8>,
    pub ticket: Vec<u8>,
    pub age_add: u32,
    pub received_ms: u64,
    pub lifetime_secs: u32,
    pub alpn: Option<Vec<u8>>,
}

/// The client's session store: up to `per_server` tickets per server name, each used once.
#[cfg(feature = "client")]
pub struct SessionCache {
    map: Mutex<HashMap<String, VecDeque<StoredSession>>>,
    max_servers: usize,
    per_server: usize,
}

#[cfg(feature = "client")]
impl std::fmt::Debug for SessionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionCache({} servers)", self.map.lock().map(|m| m.len()).unwrap_or(0))
    }
}

#[cfg(feature = "client")]
impl SessionCache {
    pub fn new(max_servers: usize) -> SessionCache {
        SessionCache { map: Mutex::new(HashMap::new()), max_servers: max_servers.max(1), per_server: 4 }
    }

    pub(crate) fn put(&self, server: &str, s: StoredSession) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if !m.contains_key(server) && m.len() >= self.max_servers {
            if let Some(k) = m.keys().next().cloned() {
                m.remove(&k);
            }
        }
        let q = m.entry(server.to_string()).or_default();
        if q.len() >= self.per_server {
            q.pop_front();
        }
        q.push_back(s);
    }

    pub(crate) fn take(&self, server: &str, now: u64) -> Option<StoredSession> {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let q = m.get_mut(server)?;
        while let Some(s) = q.pop_back() {
            if now < s.received_ms + s.lifetime_secs as u64 * 1000 {
                return Some(s);
            }
        }
        None
    }

    /// Number of stored tickets for `server`.
    pub fn len_for(&self, server: &str) -> usize {
        self.map.lock().map(|m| m.get(server).map_or(0, |q| q.len())).unwrap_or(0)
    }
}

/// Client configuration.
#[cfg(feature = "client")]
pub struct ClientConfig {
    /// Trust anchors for server certificates. Verification cannot be turned off; to trust a
    /// self-signed server, add its certificate here.
    pub roots: RootStore,
    pub alpn: Vec<Vec<u8>>,
    pub suites: Vec<CipherSuite>,
    /// Groups in preference order; the first gets a key share in the ClientHello.
    pub groups: Vec<NamedGroup>,
    /// A certificate for servers that request one.
    pub client_cert: Option<CertifiedKey>,
    /// Session resumption (None disables it).
    pub sessions: Option<Arc<SessionCache>>,
    /// Send the server_name extension.
    pub enable_sni: bool,
    pub max_handshake_message: usize,
    pub time: Arc<dyn TimeSource>,
}

#[cfg(feature = "client")]
impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig").field("roots", &self.roots).field("alpn", &self.alpn).finish()
    }
}

#[cfg(feature = "client")]
impl ClientConfig {
    pub fn new(roots: RootStore) -> ClientConfig {
        ClientConfig {
            roots,
            alpn: Vec::new(),
            suites: CipherSuite::ALL.to_vec(),
            groups: NamedGroup::ALL.to_vec(),
            client_cert: None,
            sessions: Some(Arc::new(SessionCache::new(256))),
            enable_sni: true,
            max_handshake_message: 64 * 1024,
            time: Arc::new(SystemClock),
        }
    }

    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> ClientConfig {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }
}
