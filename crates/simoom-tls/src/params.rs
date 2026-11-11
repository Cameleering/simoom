//! [`SslContextParameters`]: the equivalent of Camel's `SSLContextParameters` (feature
//! `keystore`), ported from Cameleer's `cameleer-tls/src/params.rs` with the same field names,
//! builder methods, property keys and semantics, so Cameleer can switch with few changes. One
//! description of trust material, key material and protocol options builds a [`ServerConfig`]
//! or a [`ClientConfig`].
//!
//! Key and trust stores may be PEM files, PKCS#12 (`.p12`/`.pfx`, feature `pkcs12`), Java JKS
//! or JCEKS (feature `jks`), detected from the content or set with `keyStoreType` /
//! `trustStoreType`. A key store holds the certificate chain (leaf first) and the private key,
//! or a PEM chain is paired with a separate (optionally encrypted) PEM or DER key file. A trust
//! store holds CA certificates.
//!
//! Differences from Cameleer, all on the side of safety:
//! - `insecure_skip_verify = true` and `hostname_verification = Some(false)` are refused with a
//!   configuration error: simoom never turns certificate or host name verification off. Trust
//!   a self-signed peer by adding its certificate to the trust store.
//! - CRL files need the `revocation` feature (they become a revocation policy that checks every
//!   certificate whose issuer has a configured CRL, as Cameleer's `verify_chain_with_crls` does).
//! - `cipher_suites` (Camel's `cipherSuites`) is supported here; Cameleer ignored it.
//!
//! ```
//! # #[cfg(feature = "client")]
//! # {
//! use simoom_tls::params::SslContextParameters;
//! let id = simoom_tls::certgen::self_signed("localhost");
//! let server = SslContextParameters::new().key_pair_pem(&id.cert_pem, &id.key_pem);
//! let client = SslContextParameters::new().trust_pem(&id.cert_pem);
//! let _scfg = server.server_config().unwrap();
//! let _ccfg = client.client_config().unwrap();
//! # }
//! ```

use crate::keystore::{KeyStore, KeyStoreFormat};
use crate::pem;
use crate::tls::config::{CertifiedKey, ClientAuth, ServerConfig};
use crate::tls::{CipherSuite, Error, ProtocolVersion};
use crate::x509::RootStore;
use std::path::PathBuf;

#[cfg(feature = "client")]
use crate::tls::config::{ClientConfig, SessionCache};

/// Source of key or trust material: a file path (any supported format) or inline PEM text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PemSource {
    File(PathBuf),
    Inline(String),
}

impl PemSource {
    pub fn load(&self) -> Result<Vec<u8>, Error> {
        match self {
            PemSource::File(p) => std::fs::read(p).map_err(|e| Error::Config(format!("{}: {e}", p.display()))),
            PemSource::Inline(s) => Ok(s.as_bytes().to_vec()),
        }
    }

    /// `file:` prefixes are accepted; text containing `-----BEGIN` is inline PEM.
    pub fn parse(s: &str) -> PemSource {
        let s = s.trim();
        if s.contains("-----BEGIN") {
            PemSource::Inline(s.to_string())
        } else {
            PemSource::File(PathBuf::from(s.strip_prefix("file:").unwrap_or(s)))
        }
    }
}

/// Client certificate authentication on a server (Camel `clientAuthentication`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientAuthMode {
    #[default]
    None,
    /// Request a certificate; connections without one are accepted.
    Want,
    /// Require a certificate.
    Need,
}

impl ClientAuthMode {
    /// Parses `NONE` / `WANT` / `REQUIRE` (also `NEED`, `true`/`false`, `optional`).
    pub fn parse(s: &str) -> Option<ClientAuthMode> {
        match s.trim().to_ascii_uppercase().as_str() {
            "NONE" | "FALSE" | "NO" | "OFF" | "" => Some(ClientAuthMode::None),
            "WANT" | "OPTIONAL" | "REQUEST" | "REQUESTED" => Some(ClientAuthMode::Want),
            "REQUIRE" | "REQUIRED" | "NEED" | "TRUE" | "YES" | "ON" => Some(ClientAuthMode::Need),
            _ => None,
        }
    }
}

/// Default session lifetime in seconds, like Java's `SSLSessionContext` (capped at 7 days, the
/// TLS 1.3 ticket limit).
pub const DEFAULT_SESSION_LIFETIME: u32 = 86_400;

/// Trust, key and protocol settings shared by TLS clients and servers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SslContextParameters {
    /// CA certificates to trust.
    pub trust_store: Vec<PemSource>,
    /// Whether to also trust the system CA bundle. `None`: only when no `trust_store` is set
    /// (Camel semantics: configured trust managers replace the default).
    pub use_system_trust_store: Option<bool>,
    /// Certificate chain (leaf first); may also contain the private key, or be a key store.
    pub cert_chain: Option<PemSource>,
    /// Private key (PKCS#8, SEC1 or PKCS#1 PEM, encrypted PKCS#8, or DER). If absent it is read
    /// from `cert_chain`.
    pub private_key: Option<PemSource>,
    /// Kept for Cameleer compatibility; `true` is refused (verification cannot be disabled).
    pub insecure_skip_verify: bool,
    /// Kept for Cameleer compatibility; `Some(false)` is refused.
    pub hostname_verification: Option<bool>,
    /// ALPN protocols to offer (client) or accept (server).
    pub alpn: Vec<String>,
    pub min_version: Option<ProtocolVersion>,
    pub max_version: Option<ProtocolVersion>,
    /// Cipher suites to enable (IANA or OpenSSL names, both versions); empty: the defaults.
    pub cipher_suites: Vec<String>,
    /// Overrides the SNI / host name used for verification on client connections.
    pub server_name: Option<String>,
    /// Key store password (`keystorePassword`).
    pub key_store_password: Option<String>,
    /// Private key password (`keyPassword`, default: the key store password).
    pub key_password: Option<String>,
    /// `PKCS12`, `JKS`, `JCEKS` or `PEM` (default: detected).
    pub key_store_type: Option<String>,
    /// Alias of the key entry to use (`certAlias`, default: the first key entry).
    pub cert_alias: Option<String>,
    pub trust_store_password: Option<String>,
    pub trust_store_type: Option<String>,
    /// Server side: client certificate authentication (`clientAuthentication`).
    pub client_authentication: Option<ClientAuthMode>,
    /// CRL files (PEM `X509 CRL` or DER) checked during chain validation (feature `revocation`).
    pub crl_files: Vec<PemSource>,
    /// Session resumption (default true).
    pub session_resumption: Option<bool>,
    /// Session lifetime in seconds (`sessionTimeout`, default 86400).
    pub session_timeout: Option<u32>,
}

/// Parses `TLSv1.2` / `TLSv1.3` / `1.2` style protocol names.
pub fn parse_tls_version(s: &str) -> Option<ProtocolVersion> {
    ProtocolVersion::parse(s)
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1")
}

#[cfg(feature = "tls12")]
type Suite12 = crate::tls::tls12::Tls12Suite;
#[cfg(not(feature = "tls12"))]
type Suite12 = ();

impl SslContextParameters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a CA PEM file to the trust store.
    pub fn trust_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.trust_store.push(PemSource::File(path.into()));
        self
    }

    /// Adds inline CA PEM text to the trust store.
    pub fn trust_pem(mut self, pem: &str) -> Self {
        self.trust_store.push(PemSource::Inline(pem.to_string()));
        self
    }

    /// Whether to trust the system CA bundle in addition to `trust_store`.
    pub fn system_trust_store(mut self, yes: bool) -> Self {
        self.use_system_trust_store = Some(yes);
        self
    }

    /// Certificate chain + private key from PEM files.
    pub fn key_pair_files(mut self, cert_chain: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.cert_chain = Some(PemSource::File(cert_chain.into()));
        self.private_key = Some(PemSource::File(key.into()));
        self
    }

    /// Certificate chain + private key from inline PEM text.
    pub fn key_pair_pem(mut self, cert_chain: &str, key: &str) -> Self {
        self.cert_chain = Some(PemSource::Inline(cert_chain.to_string()));
        self.private_key = Some(PemSource::Inline(key.to_string()));
        self
    }

    /// A single PEM "key store" file with both certificates and the private key.
    pub fn key_store_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.cert_chain = Some(PemSource::File(path.into()));
        self.private_key = None;
        self
    }

    /// A key store file (PKCS#12, JKS, JCEKS or PEM) with its password.
    pub fn key_store(mut self, path: impl Into<PathBuf>, password: &str) -> Self {
        self.cert_chain = Some(PemSource::File(path.into()));
        self.private_key = None;
        self.key_store_password = Some(password.to_string());
        self
    }

    /// A trust store file (PKCS#12, JKS, JCEKS, PEM or DER) with its password.
    pub fn trust_store(mut self, path: impl Into<PathBuf>, password: Option<&str>) -> Self {
        self.trust_store.push(PemSource::File(path.into()));
        self.trust_store_password = password.map(str::to_string);
        self
    }

    pub fn key_password(mut self, password: &str) -> Self {
        self.key_password = Some(password.to_string());
        self
    }

    pub fn cert_alias(mut self, alias: &str) -> Self {
        self.cert_alias = Some(alias.to_string());
        self
    }

    /// Server side: client certificate authentication mode.
    pub fn client_authentication(mut self, mode: ClientAuthMode) -> Self {
        self.client_authentication = Some(mode);
        self
    }

    /// Adds a CRL file.
    pub fn crl_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.crl_files.push(PemSource::File(path.into()));
        self
    }

    /// Enables (default) or disables session resumption.
    pub fn session_resumption(mut self, yes: bool) -> Self {
        self.session_resumption = Some(yes);
        self
    }

    pub fn alpn_protocols(mut self, protos: &[&str]) -> Self {
        self.alpn = protos.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn versions(mut self, min: ProtocolVersion, max: ProtocolVersion) -> Self {
        self.min_version = Some(min);
        self.max_version = Some(max);
        self
    }

    pub fn cipher_suites(mut self, names: &[&str]) -> Self {
        self.cipher_suites = names.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_server_name(mut self, name: &str) -> Self {
        self.server_name = Some(name.to_string());
        self
    }

    /// The name to send as SNI and verify against when connecting to `host`.
    pub fn sni_name<'a>(&'a self, host: &'a str) -> &'a str {
        self.server_name.as_deref().unwrap_or(host)
    }

    /// Whether key material is configured (needed for servers).
    pub fn has_key_material(&self) -> bool {
        self.cert_chain.is_some()
    }

    fn version_range(&self) -> Result<(ProtocolVersion, ProtocolVersion), Error> {
        let min = self.min_version.unwrap_or(ProtocolVersion::Tls12);
        let max = self.max_version.unwrap_or(ProtocolVersion::Tls13).max(min);
        #[cfg(not(feature = "tls12"))]
        if max < ProtocolVersion::Tls13 {
            return Err(Error::Config("TLS 1.2 needs the tls12 feature".into()));
        }
        Ok((min, max))
    }

    fn store_format(name: &Option<String>, data: &[u8]) -> Result<KeyStoreFormat, Error> {
        match name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(n) => KeyStoreFormat::from_name(n).ok_or_else(|| Error::Config(format!("unsupported key store type {n}"))),
            None => Ok(KeyStoreFormat::detect(data)),
        }
    }

    /// The configured certificate chain and private key (None without key material).
    pub fn key_material(&self) -> Result<Option<CertifiedKey>, Error> {
        let Some(src) = &self.cert_chain else { return Ok(None) };
        let data = src.load()?;
        let what = |e: String| Error::Config(format!("key store: {e}"));
        let key_pw = self.key_password.as_deref().or(self.key_store_password.as_deref());
        if let Some(k) = &self.private_key {
            // certificate chain + separate key file
            let chain: Vec<Vec<u8>> = match Self::store_format(&self.key_store_type, &data)? {
                KeyStoreFormat::Pem => pem::parse_pem(&data).map_err(what)?.into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.der).collect(),
                KeyStoreFormat::Der => vec![data.clone()],
                _ => return Err(Error::Config("a separate private key needs a PEM or DER certificate chain".into())),
            };
            let kdata = k.load()?;
            let key = crate::keystore::private_key_from_pem(&kdata, key_pw)
                .or_else(|e| crate::keys::PrivateKey::from_der(&kdata).map_err(|_| e))
                .or_else(|e| match key_pw {
                    // DER EncryptedPrivateKeyInfo (pgjdbc's .pk8 key files)
                    Some(pw) => crate::keystore::pbe::decrypt_encrypted_private_key_info(&kdata, pw)
                        .and_then(|der| crate::keys::PrivateKey::from_pkcs8(&der).map_err(|x| x.to_string()))
                        .map_err(|_| e),
                    None => Err(e),
                })
                .map_err(|e| Error::Config(format!("private key: {e}")))?;
            return CertifiedKey::new(chain, key).map(Some);
        }
        let fmt = Self::store_format(&self.key_store_type, &data)?;
        let ks = KeyStore::load_as(&data, fmt, self.key_store_password.as_deref(), key_pw).map_err(what)?;
        let (key, chain) = ks.key_entry(self.cert_alias.as_deref()).ok_or_else(|| {
            Error::Config(match &self.cert_alias {
                Some(a) => format!("key store has no private key entry '{a}' (aliases: {})", ks.aliases().join(", ")),
                None => "key store contains no private key".into(),
            })
        })?;
        CertifiedKey::new(chain.to_vec(), key.clone()).map(Some)
    }

    /// The configured trust anchors (empty when no trust store is set).
    pub fn trust_roots(&self) -> Result<RootStore, Error> {
        let mut roots = RootStore::empty();
        for t in &self.trust_store {
            let data = t.load()?;
            match Self::store_format(&self.trust_store_type, &data)? {
                KeyStoreFormat::Pem => {
                    roots.add_pem(&data).map_err(|e| Error::Config(format!("trust store: {e}")))?;
                }
                fmt => {
                    let ks = KeyStore::load_as(&data, fmt, self.trust_store_password.as_deref(), None).map_err(|e| Error::Config(format!("trust store: {e}")))?;
                    let certs = ks.trusted_certs();
                    if certs.is_empty() {
                        return Err(Error::Config("trust store contains no trusted certificate entries".into()));
                    }
                    for c in certs {
                        roots.add_der(&c).map_err(|e| Error::Config(format!("trust store: {e}")))?;
                    }
                }
            }
        }
        Ok(roots)
    }

    /// The configured CRLs as a revocation policy (None without CRL files).
    #[cfg(feature = "revocation")]
    pub fn revocation_policy(&self) -> Result<Option<crate::revocation::RevocationPolicy>, Error> {
        if self.crl_files.is_empty() {
            return Ok(None);
        }
        let mut p = crate::revocation::RevocationPolicy::new().with_crl_mode(crate::revocation::CrlMode::IfAvailable);
        for c in &self.crl_files {
            p.add_crls(&c.load()?).map_err(|e| Error::Config(format!("CRL: {e}")))?;
        }
        Ok(Some(p))
    }

    fn check_safety(&self) -> Result<(), Error> {
        if self.insecure_skip_verify {
            return Err(Error::Config("insecureSkipVerify is not supported: add the peer's certificate (or its CA) to the trust store".into()));
        }
        if self.hostname_verification == Some(false) {
            return Err(Error::Config("hostnameVerification=false is not supported; use serverName to verify another name".into()));
        }
        #[cfg(not(feature = "revocation"))]
        if !self.crl_files.is_empty() {
            return Err(Error::Config("crlFile needs the revocation feature".into()));
        }
        Ok(())
    }

    /// The enabled suites from `cipher_suites`: (TLS 1.3, TLS 1.2).
    fn suites(&self) -> Result<Option<(Vec<CipherSuite>, Vec<Suite12>)>, Error> {
        if self.cipher_suites.is_empty() {
            return Ok(None);
        }
        let mut s13 = Vec::new();
        #[allow(unused_mut)]
        let mut s12: Vec<Suite12> = Vec::new();
        for n in &self.cipher_suites {
            let n = n.trim();
            if let Some(s) = CipherSuite::ALL.iter().copied().find(|s| s.name().eq_ignore_ascii_case(n)) {
                s13.push(s);
            }
            #[cfg(feature = "tls12")]
            if let Some(s) = crate::tls::tls12::Tls12Suite::from_name(n) {
                s12.push(s);
            }
        }
        if s13.is_empty() && s12.is_empty() {
            return Err(Error::Config(format!("none of the cipher suites is supported: {}", self.cipher_suites.join(", "))));
        }
        Ok(Some((s13, s12)))
    }

    /// Builds a client configuration (presenting the key material, if any, as the client
    /// certificate when the server requests one).
    #[cfg(feature = "client")]
    pub fn client_config(&self) -> Result<ClientConfig, Error> {
        self.check_safety()?;
        let system = self.use_system_trust_store.unwrap_or(self.trust_store.is_empty());
        let mut roots = if system { RootStore::system() } else { RootStore::empty() };
        roots.extend(&self.trust_roots()?);
        let mut c = ClientConfig::new(roots);
        c.client_cert = self.key_material()?;
        c.alpn = self.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        c.sessions = if self.session_resumption.unwrap_or(true) { Some(std::sync::Arc::new(SessionCache::new(256))) } else { None };
        let (_min, _max) = self.version_range()?;
        #[cfg(feature = "tls12")]
        {
            c.min_version = _min;
            c.max_version = _max;
        }
        if let Some((s13, _s12)) = self.suites()? {
            c.suites = s13;
            #[cfg(feature = "tls12")]
            {
                c.suites12 = _s12;
                if c.suites.is_empty() {
                    c.max_version = ProtocolVersion::Tls12;
                }
                if c.suites12.is_empty() {
                    c.min_version = ProtocolVersion::Tls13;
                }
            }
            #[cfg(not(feature = "tls12"))]
            if c.suites.is_empty() {
                return Err(Error::Config("no TLS 1.3 cipher suite enabled (TLS 1.2 needs the tls12 feature)".into()));
            }
        }
        #[cfg(feature = "revocation")]
        {
            c.revocation = self.revocation_policy()?;
        }
        Ok(c)
    }

    /// Builds a server configuration (requires key material). With client authentication the
    /// trust store validates client certificates.
    pub fn server_config(&self) -> Result<ServerConfig, Error> {
        self.check_safety()?;
        let ck = self.key_material()?.ok_or_else(|| Error::Config("no server certificate configured (keyStore / certificate chain)".into()))?;
        let mut s = ServerConfig::new(ck);
        s.alpn = self.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        let (_min, _max) = self.version_range()?;
        #[cfg(feature = "tls12")]
        {
            s.min_version = _min;
            s.max_version = _max;
        }
        if let Some((s13, _s12)) = self.suites()? {
            s.suites = s13;
            #[cfg(feature = "tls12")]
            {
                s.suites12 = _s12;
                if s.suites.is_empty() {
                    s.max_version = ProtocolVersion::Tls12;
                }
                if s.suites12.is_empty() {
                    s.min_version = ProtocolVersion::Tls13;
                }
            }
            #[cfg(not(feature = "tls12"))]
            if s.suites.is_empty() {
                return Err(Error::Config("no TLS 1.3 cipher suite enabled (TLS 1.2 needs the tls12 feature)".into()));
            }
        }
        if !self.session_resumption.unwrap_or(true) {
            s.ticketer = None;
            #[cfg(feature = "tls12")]
            {
                s.session_ids = None;
            }
        }
        s.ticket_lifetime_secs = self.session_timeout.unwrap_or(DEFAULT_SESSION_LIFETIME).clamp(1, 604_800);
        let mode = self.client_authentication.unwrap_or_default();
        if mode != ClientAuthMode::None {
            let roots = self.trust_roots()?;
            if roots.is_empty() {
                return Err(Error::Config(format!("clientAuthentication={mode:?} requires a trust store for client certificates")));
            }
            s.client_auth = if mode == ClientAuthMode::Need { ClientAuth::Required(roots) } else { ClientAuth::Optional(roots) };
            #[cfg(feature = "revocation")]
            {
                s.client_revocation = self.revocation_policy()?;
            }
        }
        Ok(s)
    }

    /// Reads parameters from properties below `prefix` (for example `camel.ssl.`), with relaxed
    /// key matching (case, `-` and `_` insensitive). The keys are Cameleer's: `keyStore`
    /// (combined PEM or a key store) or `certFile`/`certChain` + `keyFile`/`privateKey`,
    /// `trustStore` (comma-separated files or inline PEM), `useSystemTrustStore`,
    /// `trustAllCertificates`/`insecureSkipVerify` (refused when true by the builders),
    /// `hostnameVerification`, `secureSocketProtocol` (one version), `secureSocketProtocols`
    /// (a list: min..max), `minVersion`, `maxVersion`, `cipherSuites`, `alpn`, `serverName`,
    /// `keystorePassword`, `keyPassword`, `keyStoreType`, `certAlias`, `trustStorePassword`,
    /// `trustStoreType`, `clientAuthentication` (also `serverParameters.clientAuthentication`,
    /// `clientAuth`, `needClientAuth=true`, `wantClientAuth=true`), `crlFile`, `sessionTimeout`,
    /// `sessionResumption`. Returns `None` when none is set.
    pub fn from_properties(prefix: &str, get: &dyn Fn(&str) -> Option<String>, keys: &[String]) -> Result<Option<Self>, Error> {
        let norm = |k: &str| k.to_ascii_lowercase().replace(['-', '_'], "");
        let lookup = |names: &[&str]| -> Option<String> {
            for k in keys {
                if let Some(rest) = k.strip_prefix(prefix) {
                    let n = norm(rest);
                    if names.iter().any(|x| norm(x) == n) {
                        if let Some(v) = get(k) {
                            if !v.trim().is_empty() {
                                return Some(v);
                            }
                        }
                    }
                }
            }
            None
        };
        let mut p = SslContextParameters::new();
        let mut any = false;
        if let Some(v) = lookup(&["keyStore", "keyStoreFile", "keyStore.resource"]) {
            p.cert_chain = Some(PemSource::parse(&v));
            any = true;
        }
        if let Some(v) = lookup(&["certFile", "certChain", "certificate", "certChainFile"]) {
            p.cert_chain = Some(PemSource::parse(&v));
            any = true;
        }
        if let Some(v) = lookup(&["keyFile", "privateKey", "privateKeyFile"]) {
            p.private_key = Some(PemSource::parse(&v));
            any = true;
        }
        if let Some(v) = lookup(&["trustStore", "trustStoreFile", "trustStore.resource", "caFile", "trustedCertificates"]) {
            if v.contains("-----BEGIN") {
                p.trust_store.push(PemSource::Inline(v));
            } else {
                p.trust_store.extend(v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(PemSource::parse));
            }
            any = true;
        }
        if let Some(v) = lookup(&["useSystemTrustStore", "systemTrustStore"]) {
            p.use_system_trust_store = Some(truthy(&v));
            any = true;
        }
        if let Some(v) = lookup(&["trustAllCertificates", "insecureSkipVerify", "insecure"]) {
            p.insecure_skip_verify = truthy(&v);
            any = true;
        }
        if let Some(v) = lookup(&["hostnameVerification", "verifyHostname"]) {
            p.hostname_verification = Some(truthy(&v));
            any = true;
        }
        if let Some(v) = lookup(&["secureSocketProtocol", "protocol"]) {
            if let Some(ver) = parse_tls_version(&v) {
                p.min_version = Some(ver);
                p.max_version = Some(ver);
            }
            any = true;
        }
        if let Some(v) = lookup(&["secureSocketProtocols", "protocols", "enabledProtocols"]) {
            let vs: Vec<ProtocolVersion> = v.split(',').filter_map(parse_tls_version).collect();
            if !vs.is_empty() {
                p.min_version = vs.iter().min().copied();
                p.max_version = vs.iter().max().copied();
            }
            any = true;
        }
        if let Some(v) = lookup(&["minVersion"]).and_then(|v| parse_tls_version(&v)) {
            p.min_version = Some(v);
            any = true;
        }
        if let Some(v) = lookup(&["maxVersion"]).and_then(|v| parse_tls_version(&v)) {
            p.max_version = Some(v);
            any = true;
        }
        if let Some(v) = lookup(&["cipherSuites", "ciphers", "enabledCipherSuites", "cipherSuitesFilter.include"]) {
            p.cipher_suites = v.split([',', ':']).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            any = true;
        }
        if let Some(v) = lookup(&["alpn", "applicationProtocols", "alpnProtocols"]) {
            p.alpn = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            any = true;
        }
        if let Some(v) = lookup(&["serverName", "sniHostName"]) {
            p.server_name = Some(v.trim().to_string());
            any = true;
        }
        if let Some(v) = lookup(&["keystorePassword", "keyStore.password", "keyStorePass"]) {
            p.key_store_password = Some(v);
            any = true;
        }
        if let Some(v) = lookup(&["keyPassword", "keyManagers.keyPassword", "privateKeyPassword"]) {
            p.key_password = Some(v);
            any = true;
        }
        if let Some(v) = lookup(&["keyStoreType", "keyStore.type"]) {
            p.key_store_type = Some(v.trim().to_string());
            any = true;
        }
        if let Some(v) = lookup(&["certAlias", "keyAlias", "alias"]) {
            p.cert_alias = Some(v.trim().to_string());
            any = true;
        }
        if let Some(v) = lookup(&["trustStorePassword", "trustStore.password"]) {
            p.trust_store_password = Some(v);
            any = true;
        }
        if let Some(v) = lookup(&["trustStoreType", "trustStore.type"]) {
            p.trust_store_type = Some(v.trim().to_string());
            any = true;
        }
        if let Some(v) = lookup(&["clientAuthentication", "serverParameters.clientAuthentication", "clientAuth"]) {
            p.client_authentication =
                Some(ClientAuthMode::parse(&v).ok_or_else(|| Error::Config(format!("invalid clientAuthentication '{v}' (NONE, WANT or REQUIRE)")))?);
            any = true;
        }
        if let Some(v) = lookup(&["needClientAuth"]) {
            if truthy(&v) {
                p.client_authentication = Some(ClientAuthMode::Need);
            }
            any = true;
        }
        if let Some(v) = lookup(&["wantClientAuth"]) {
            if truthy(&v) && p.client_authentication != Some(ClientAuthMode::Need) {
                p.client_authentication = Some(ClientAuthMode::Want);
            }
            any = true;
        }
        if let Some(v) = lookup(&["crlFile", "crlFiles", "crl"]) {
            p.crl_files.extend(v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(PemSource::parse));
            any = true;
        }
        if let Some(v) = lookup(&["sessionTimeout"]) {
            p.session_timeout = Some(v.trim().parse().map_err(|_| Error::Config(format!("invalid sessionTimeout '{v}'")))?);
            any = true;
        }
        if let Some(v) = lookup(&["sessionResumption", "sessionCaching", "sessionCacheEnabled"]) {
            p.session_resumption = Some(truthy(&v));
            any = true;
        }
        Ok(if any { Some(p) } else { None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn versions_parse() {
        assert_eq!(parse_tls_version("TLSv1.2"), Some(ProtocolVersion::Tls12));
        assert_eq!(parse_tls_version("TLSv1.3"), Some(ProtocolVersion::Tls13));
        assert_eq!(parse_tls_version("1.3"), Some(ProtocolVersion::Tls13));
        assert_eq!(parse_tls_version("SSLv3"), None);
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("simoom-tls-params-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn properties_and_configs() {
        let id = crate::certgen::self_signed("localhost");
        let d = dir("pem");
        let ks = d.join("ks.pem");
        std::fs::write(&ks, format!("{}{}", id.cert_pem, id.key_pem)).unwrap();
        let ca = d.join("ca.pem");
        std::fs::write(&ca, &id.cert_pem).unwrap();
        let mut m = BTreeMap::new();
        m.insert("camel.ssl.keystore".to_string(), ks.display().to_string());
        m.insert("camel.ssl.trust-store".to_string(), ca.display().to_string());
        m.insert("camel.ssl.secureSocketProtocol".to_string(), "TLSv1.3".to_string());
        m.insert("camel.ssl.alpn".to_string(), "h2,http/1.1".to_string());
        m.insert("other.x".to_string(), "y".to_string());
        let keys: Vec<String> = m.keys().cloned().collect();
        let p = SslContextParameters::from_properties("camel.ssl.", &|k| m.get(k).cloned(), &keys).unwrap().unwrap();
        assert_eq!(p.min_version, Some(ProtocolVersion::Tls13));
        assert_eq!(p.trust_store.len(), 1);
        let s = p.server_config().unwrap();
        assert_eq!(s.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        #[cfg(feature = "client")]
        {
            let c = p.client_config().unwrap();
            assert_eq!(c.roots.len(), 1, "system roots are not added when a trust store is set");
        }
        let none = SslContextParameters::from_properties("camel.nossl.", &|k| m.get(k).cloned(), &keys).unwrap();
        assert!(none.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn verification_cannot_be_disabled() {
        let id = crate::certgen::self_signed("localhost");
        let base = SslContextParameters::new().key_pair_pem(&id.cert_pem, &id.key_pem).trust_pem(&id.cert_pem);
        let insecure = SslContextParameters { insecure_skip_verify: true, ..base.clone() };
        assert!(insecure.server_config().unwrap_err().to_string().contains("insecureSkipVerify"));
        let no_host = SslContextParameters { hostname_verification: Some(false), ..base.clone() };
        assert!(no_host.server_config().is_err());
        #[cfg(feature = "client")]
        {
            assert!(insecure.client_config().is_err());
            assert!(no_host.client_config().is_err());
            assert!(base.client_config().is_ok());
        }
    }

    #[test]
    fn cipher_suites_and_resumption() {
        let id = crate::certgen::self_signed("localhost");
        let base = SslContextParameters::new().key_pair_pem(&id.cert_pem, &id.key_pem);
        let p = base.clone().cipher_suites(&["TLS_AES_256_GCM_SHA384", "bogus"]);
        let s = p.server_config().unwrap();
        assert_eq!(s.suites, vec![CipherSuite::Aes256GcmSha384]);
        assert!(base.clone().cipher_suites(&["bogus"]).server_config().is_err());
        let s = SslContextParameters { session_resumption: Some(false), session_timeout: Some(30), ..base.clone() }.server_config().unwrap();
        assert!(s.ticketer.is_none());
        assert_eq!(s.ticket_lifetime_secs, 30);
        #[cfg(feature = "tls12")]
        {
            let s = base.clone().cipher_suites(&["ECDHE-ECDSA-AES128-GCM-SHA256"]).server_config().unwrap();
            assert!(s.suites.is_empty());
            assert_eq!(s.max_version, ProtocolVersion::Tls12);
            let s = base.clone().versions(ProtocolVersion::Tls12, ProtocolVersion::Tls12).server_config().unwrap();
            assert_eq!((s.min_version, s.max_version), (ProtocolVersion::Tls12, ProtocolVersion::Tls12));
        }
    }

    #[test]
    fn missing_key_material_is_reported() {
        let e = SslContextParameters::new().server_config().unwrap_err();
        assert!(e.to_string().contains("no server certificate"));
    }

    #[cfg(all(feature = "pkcs12", feature = "jks"))]
    #[test]
    fn keystore_and_client_auth_properties() {
        let d = dir("ks");
        let ca = crate::certgen::issue(&crate::certgen::CertParams::ca("Params CA"), crate::keys::PrivateKey::generate_ec(crate::keys::EcCurve::P256), None);
        let srv = crate::certgen::issue(&crate::certgen::CertParams::server(&["localhost"]), crate::keys::PrivateKey::generate_ec(crate::keys::EcCurve::P256), Some(&ca));
        let ks = d.join("server.jks");
        let store = KeyStore::from_key_entry("srv", srv.key.clone(), vec![srv.cert_der.clone(), ca.cert_der.clone()]);
        std::fs::write(&ks, store.to_jks("storepw", "keypw")).unwrap();
        let ts = d.join("trust.p12");
        std::fs::write(&ts, KeyStore::new().add_cert("ca", ca.cert_der.clone()).to_pkcs12("trustpw")).unwrap();
        let mut m = BTreeMap::new();
        m.insert("camel.ssl.keyStore".to_string(), ks.display().to_string());
        m.insert("camel.ssl.keystorePassword".to_string(), "storepw".to_string());
        m.insert("camel.ssl.keyPassword".to_string(), "keypw".to_string());
        m.insert("camel.ssl.keyStoreType".to_string(), "JKS".to_string());
        m.insert("camel.ssl.certAlias".to_string(), "srv".to_string());
        m.insert("camel.ssl.trustStore".to_string(), ts.display().to_string());
        m.insert("camel.ssl.trustStorePassword".to_string(), "trustpw".to_string());
        m.insert("camel.ssl.serverParameters.clientAuthentication".to_string(), "REQUIRE".to_string());
        m.insert("camel.ssl.sessionTimeout".to_string(), "600".to_string());
        let keys: Vec<String> = m.keys().cloned().collect();
        let p = SslContextParameters::from_properties("camel.ssl.", &|k| m.get(k).cloned(), &keys).unwrap().unwrap();
        assert_eq!(p.client_authentication, Some(ClientAuthMode::Need));
        assert_eq!(p.session_timeout, Some(600));
        let scfg = p.server_config().unwrap();
        assert!(matches!(scfg.client_auth, ClientAuth::Required(_)));
        assert_eq!(scfg.ticket_lifetime_secs, 600);
        #[cfg(feature = "client")]
        assert!(p.client_config().unwrap().client_cert.is_some());
        let mut bad = m.clone();
        bad.insert("camel.ssl.clientAuthentication".to_string(), "SOMETIMES".to_string());
        let bad_keys: Vec<String> = bad.keys().cloned().collect();
        assert!(SslContextParameters::from_properties("camel.ssl.", &|k| bad.get(k).cloned(), &bad_keys).is_err());
        let no_trust = SslContextParameters { trust_store: Vec::new(), ..p.clone() };
        assert!(no_trust.server_config().is_err());
        let wrong_alias = SslContextParameters { cert_alias: Some("nope".into()), ..p };
        assert!(wrong_alias.server_config().unwrap_err().to_string().contains("aliases: srv"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
