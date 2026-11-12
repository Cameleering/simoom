//! Key and trust stores: PEM, PKCS#12 (`.p12` / `.pfx`, feature `pkcs12`), Java JKS and
//! JCEKS (feature `jks`), and single DER certificates.
//!
//! [`KeyStore::load`] detects the format from the content (JKS magic `FEEDFEED`, JCEKS magic
//! `CECECECE`, PEM text, otherwise PKCS#12 or a single DER certificate). A store holds
//! private-key entries (key + certificate chain, leaf first) and trusted-certificate entries,
//! like `java.security.KeyStore`.
//!
//! Integrity is checked first and in constant time (the PKCS#12 MAC, the JKS digest); a wrong
//! password is an error, never garbage keys. Everything read from a file is bounded: KDF
//! iteration counts (`pbe::MAX_ITERATIONS`), entry counts ([`MAX_ENTRIES`]), nesting and
//! chain lengths.
//!
//! ```
//! # #[cfg(feature = "pkcs12")]
//! # {
//! use simoom_tls::keystore::KeyStore;
//! let id = simoom_tls::certgen::self_signed("localhost");
//! let p12 = KeyStore::from_key_entry("server", id.key.clone(), vec![id.cert_der.clone()]).to_pkcs12("changeit");
//! let ks = KeyStore::load(&p12, Some("changeit"), None).unwrap();
//! assert_eq!(ks.key_entry(Some("server")).unwrap().1.len(), 1);
//! # }
//! ```
//!
//! (**Moves to ksar-pki**; from Cameleer `cameleer-tls/src/keystore/mod.rs`.)
//!

#[cfg(feature = "jks")]
pub mod jks;
pub mod pbe;
mod pem_key;
#[cfg(feature = "pkcs12")]
pub mod pkcs12;

pub use pem_key::decrypt_private_key_pem;

use crate::keys::PrivateKey;
use crate::pem;
use crate::x509::Certificate;

/// JKS file magic.
pub const JKS_MAGIC: u32 = 0xFEED_FEED;
/// JCEKS file magic.
pub const JCEKS_MAGIC: u32 = 0xCECE_CECE;
/// Most entries (keys plus certificates) accepted from one store.
pub const MAX_ENTRIES: usize = 10_000;

/// Like `PrivateKey::from_pem`, also accepting an `ENCRYPTED PRIVATE KEY` (PKCS#8
/// `EncryptedPrivateKeyInfo`: PBES2 or a PKCS#12 PBE scheme) with `password`. This is
/// Cameleer's `PrivateKey::from_pem_with_password`.
pub fn private_key_from_pem(data: &[u8], password: Option<&str>) -> Result<PrivateKey, String> {
    decrypt_private_key_pem(data, password)
}

/// One key store entry.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)] // a handful per store; boxing would only add an indirection
pub enum KeyStoreEntry {
    /// A private key with its certificate chain (DER, leaf first).
    Key { alias: String, key: PrivateKey, chain: Vec<Vec<u8>> },
    /// A trusted certificate (DER).
    Cert { alias: String, der: Vec<u8> },
}

impl KeyStoreEntry {
    pub fn alias(&self) -> &str {
        match self {
            KeyStoreEntry::Key { alias, .. } | KeyStoreEntry::Cert { alias, .. } => alias,
        }
    }
}

/// Key store format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStoreFormat {
    Pem,
    Pkcs12,
    Jks,
    Jceks,
    Der,
}

impl KeyStoreFormat {
    /// Detects the format of key store bytes.
    pub fn detect(data: &[u8]) -> KeyStoreFormat {
        if data.starts_with(&JKS_MAGIC.to_be_bytes()) {
            KeyStoreFormat::Jks
        } else if data.starts_with(&JCEKS_MAGIC.to_be_bytes()) {
            KeyStoreFormat::Jceks
        } else if data.windows(10).any(|w| w == b"-----BEGIN") {
            KeyStoreFormat::Pem
        } else if Certificate::from_der(data).is_ok() {
            KeyStoreFormat::Der
        } else {
            KeyStoreFormat::Pkcs12
        }
    }

    /// Parses a `keyStoreType` / `trustStoreType` name (`PKCS12`, `JKS`, `JCEKS`, `PEM`, `DER`).
    pub fn from_name(name: &str) -> Option<KeyStoreFormat> {
        match name.trim().to_ascii_uppercase().as_str() {
            "PKCS12" | "P12" | "PFX" => Some(KeyStoreFormat::Pkcs12),
            "JKS" => Some(KeyStoreFormat::Jks),
            "JCEKS" => Some(KeyStoreFormat::Jceks),
            "PEM" => Some(KeyStoreFormat::Pem),
            "DER" | "CER" | "CRT" => Some(KeyStoreFormat::Der),
            _ => None,
        }
    }
}

/// An in-memory key store.
#[derive(Clone, Debug, Default)]
pub struct KeyStore {
    pub entries: Vec<KeyStoreEntry>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore::default()
    }

    /// A store with one key entry.
    pub fn from_key_entry(alias: &str, key: PrivateKey, chain: Vec<Vec<u8>>) -> KeyStore {
        KeyStore { entries: vec![KeyStoreEntry::Key { alias: alias.to_string(), key, chain }] }
    }

    pub fn add_key(mut self, alias: &str, key: PrivateKey, chain: Vec<Vec<u8>>) -> KeyStore {
        self.entries.push(KeyStoreEntry::Key { alias: alias.to_string(), key, chain });
        self
    }

    pub fn add_cert(mut self, alias: &str, der: Vec<u8>) -> KeyStore {
        self.entries.push(KeyStoreEntry::Cert { alias: alias.to_string(), der });
        self
    }

    /// Loads a store of any supported format. `store_password` protects the store (integrity /
    /// PKCS#12 encryption); `key_password` the private keys (defaults to the store password).
    pub fn load(data: &[u8], store_password: Option<&str>, key_password: Option<&str>) -> Result<KeyStore, String> {
        KeyStore::load_as(data, KeyStoreFormat::detect(data), store_password, key_password)
    }

    /// Loads a store of the given format.
    pub fn load_as(data: &[u8], format: KeyStoreFormat, store_password: Option<&str>, key_password: Option<&str>) -> Result<KeyStore, String> {
        let key_password = key_password.or(store_password);
        match format {
            KeyStoreFormat::Pem => KeyStore::from_pem(data, key_password),
            KeyStoreFormat::Der => {
                Certificate::from_der(data).map_err(|e| e.to_string())?;
                Ok(KeyStore::new().add_cert("cert", data.to_vec()))
            }
            #[cfg(feature = "pkcs12")]
            KeyStoreFormat::Pkcs12 => pkcs12::parse(data, store_password.unwrap_or(""), key_password),
            #[cfg(not(feature = "pkcs12"))]
            KeyStoreFormat::Pkcs12 => Err("PKCS#12 key stores need the `pkcs12` feature".into()),
            #[cfg(feature = "jks")]
            KeyStoreFormat::Jks | KeyStoreFormat::Jceks => jks::parse(data, store_password, key_password),
            #[cfg(not(feature = "jks"))]
            KeyStoreFormat::Jks | KeyStoreFormat::Jceks => Err("JKS and JCEKS key stores need the `jks` feature".into()),
        }
    }

    /// Loads a store from a file.
    pub fn load_file(path: impl AsRef<std::path::Path>, store_password: Option<&str>, key_password: Option<&str>) -> Result<KeyStore, String> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        KeyStore::load(&data, store_password, key_password).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// PEM: every CERTIFICATE becomes a trusted entry; a private key (plain or
    /// `ENCRYPTED PRIVATE KEY`) becomes a key entry with all certificates as its chain.
    pub fn from_pem(data: &[u8], key_password: Option<&str>) -> Result<KeyStore, String> {
        let blocks = pem::parse_pem(data)?;
        let certs: Vec<Vec<u8>> = blocks.iter().filter(|b| b.label == "CERTIFICATE" || b.label == "TRUSTED CERTIFICATE").map(|b| b.der.clone()).collect();
        if certs.len() > MAX_ENTRIES {
            return Err(format!("PEM: more than {MAX_ENTRIES} certificates"));
        }
        let mut ks = KeyStore::new();
        if blocks.iter().any(|b| b.label.ends_with("PRIVATE KEY")) {
            let key = decrypt_private_key_pem(data, key_password)?;
            let chain = order_chain(&key, &certs);
            ks = ks.add_key("key", key, chain);
        }
        for (i, c) in certs.into_iter().enumerate() {
            ks = ks.add_cert(&format!("cert{i}"), c);
        }
        Ok(ks)
    }

    /// The key entry `alias` (case-insensitive), or the first key entry.
    pub fn key_entry(&self, alias: Option<&str>) -> Option<(&PrivateKey, &[Vec<u8>])> {
        self.entries.iter().find_map(|e| match e {
            KeyStoreEntry::Key { alias: a, key, chain } if alias.is_none_or(|x| x.eq_ignore_ascii_case(a)) => Some((key, chain.as_slice())),
            _ => None,
        })
    }

    /// Trusted-certificate entries (DER).
    pub fn trusted_certs(&self) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                KeyStoreEntry::Cert { der, .. } => Some(der.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn aliases(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.alias()).collect()
    }

    /// Serialises as PKCS#12 (PBES2/AES-256-CBC, HMAC-SHA256 MAC: the OpenSSL 3 default).
    #[cfg(feature = "pkcs12")]
    pub fn to_pkcs12(&self, password: &str) -> Vec<u8> {
        pkcs12::write(self, password, pkcs12::Pkcs12Profile::Modern)
    }

    /// Serialises as a Java JKS key store.
    #[cfg(feature = "jks")]
    pub fn to_jks(&self, store_password: &str, key_password: &str) -> Vec<u8> {
        jks::write(self, store_password, key_password)
    }

    /// Serialises as a Java JCEKS key store.
    #[cfg(feature = "jks")]
    pub fn to_jceks(&self, store_password: &str, key_password: &str) -> Vec<u8> {
        jks::write_jceks(self, store_password, key_password)
    }
}

/// Orders `certs` into a chain starting with the certificate matching `key` (followed by its
/// issuers, as far as present). Falls back to the given order.
pub fn order_chain(key: &PrivateKey, certs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let parsed: Vec<Option<Certificate>> = certs.iter().map(|d| Certificate::from_der(d).ok()).collect();
    let pk = key.public_key();
    let leaf = parsed.iter().position(|c| c.as_ref().and_then(|c| c.public_key.as_ref()).is_some_and(|k| k.same_as(&pk)));
    let Some(mut idx) = leaf else { return certs.to_vec() };
    let mut out = vec![certs[idx].clone()];
    let mut used = vec![false; certs.len()];
    used[idx] = true;
    while let Some(cur) = &parsed[idx] {
        if cur.is_self_issued() {
            break;
        }
        match parsed.iter().enumerate().position(|(j, c)| !used[j] && c.as_ref().is_some_and(|c| c.subject_raw == cur.issuer_raw)) {
            Some(j) => {
                used[j] = true;
                out.push(certs[j].clone());
                idx = j;
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_detection_and_names() {
        assert_eq!(KeyStoreFormat::detect(&JKS_MAGIC.to_be_bytes()), KeyStoreFormat::Jks);
        assert_eq!(KeyStoreFormat::detect(&JCEKS_MAGIC.to_be_bytes()), KeyStoreFormat::Jceks);
        assert_eq!(KeyStoreFormat::detect(b"junk\n-----BEGIN CERTIFICATE-----"), KeyStoreFormat::Pem);
        let id = crate::certgen::self_signed("localhost");
        assert_eq!(KeyStoreFormat::detect(&id.cert_der), KeyStoreFormat::Der);
        assert_eq!(KeyStoreFormat::detect(&[0x30, 0x03, 0x02, 0x01, 0x03]), KeyStoreFormat::Pkcs12);
        assert_eq!(KeyStoreFormat::from_name(" pkcs12 "), Some(KeyStoreFormat::Pkcs12));
        assert_eq!(KeyStoreFormat::from_name("pfx"), Some(KeyStoreFormat::Pkcs12));
        assert_eq!(KeyStoreFormat::from_name("jceks"), Some(KeyStoreFormat::Jceks));
        assert_eq!(KeyStoreFormat::from_name("CRT"), Some(KeyStoreFormat::Der));
        assert_eq!(KeyStoreFormat::from_name("BKS"), None);
    }

    #[test]
    fn pem_and_der_stores() {
        let id = crate::certgen::self_signed("localhost");
        let text = format!("{}{}", id.cert_pem, id.key_pem);
        let ks = KeyStore::load(text.as_bytes(), None, None).unwrap();
        let (k, chain) = ks.key_entry(None).unwrap();
        assert!(k.public_key().same_as(&id.key.public_key()));
        assert_eq!(chain, &[id.cert_der.clone()][..]);
        assert_eq!(ks.trusted_certs(), vec![id.cert_der.clone()]);
        assert_eq!(ks.aliases(), vec!["key", "cert0"]);
        let ks = KeyStore::load(&id.cert_der, None, None).unwrap();
        assert_eq!(ks.trusted_certs().len(), 1);
        assert!(ks.key_entry(None).is_none());
        assert!(KeyStore::load_as(b"nope", KeyStoreFormat::Der, None, None).is_err());
        assert!(KeyStore::load_file("does/not/exist.p12", None, None).unwrap_err().contains("exist.p12"));
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn encrypted_pem_key_round_trip() {
        let id = crate::certgen::self_signed("localhost");
        let enc = pbe::encrypt_private_key_info(&id.key.to_pkcs8(), "pw");
        let text = pem::encode_pem("ENCRYPTED PRIVATE KEY", &enc);
        let k = private_key_from_pem(text.as_bytes(), Some("pw")).unwrap();
        assert!(k.public_key().same_as(&id.key.public_key()));
        assert!(private_key_from_pem(text.as_bytes(), None).unwrap_err().contains("password"));
        assert!(private_key_from_pem(text.as_bytes(), Some("wrong")).is_err());
        // a PEM store with an encrypted key takes the key password
        let store = format!("{}{}", id.cert_pem, text);
        assert!(KeyStore::load(store.as_bytes(), None, Some("pw")).unwrap().key_entry(None).is_some());
        assert!(KeyStore::load(store.as_bytes(), None, None).is_err());
    }

    #[cfg(feature = "pkcs12")]
    #[test]
    fn pkcs12_round_trip_and_tampering() {
        let id = crate::certgen::self_signed("localhost");
        let ks = KeyStore::from_key_entry("server", id.key.clone(), vec![id.cert_der.clone()]).add_cert("ca", id.cert_der.clone());
        for profile in [pkcs12::Pkcs12Profile::Modern, pkcs12::Pkcs12Profile::Legacy] {
            let p12 = pkcs12::write(&ks, "pw", profile);
            let back = KeyStore::load(&p12, Some("pw"), None).unwrap();
            assert!(back.key_entry(Some("SERVER")).unwrap().0.public_key().same_as(&id.key.public_key()));
            assert_eq!(back.trusted_certs(), vec![id.cert_der.clone()]);
            assert!(KeyStore::load(&p12, Some("pW"), None).unwrap_err().contains("password"));
            // flipped bytes are caught (MAC, structure or decryption), never a panic
            for i in (0..p12.len()).step_by(61) {
                let mut bad = p12.clone();
                bad[i] ^= 0x01;
                assert!(KeyStore::load_as(&bad, KeyStoreFormat::Pkcs12, Some("pw"), None).is_err(), "byte {i}");
            }
            for n in [0, 1, 10, p12.len() / 2, p12.len() - 1] {
                assert!(KeyStore::load_as(&p12[..n], KeyStoreFormat::Pkcs12, Some("pw"), None).is_err());
            }
        }
    }

    #[cfg(feature = "jks")]
    #[test]
    fn jks_and_jceks_round_trip_and_tampering() {
        let id = crate::certgen::self_signed("localhost");
        let ks = KeyStore::from_key_entry("server", id.key.clone(), vec![id.cert_der.clone()]).add_cert("ca", id.cert_der.clone());
        for (jks, fmt) in [(ks.to_jks("pw", "kp"), KeyStoreFormat::Jks), (ks.to_jceks("pw", "kp"), KeyStoreFormat::Jceks)] {
            assert_eq!(KeyStoreFormat::detect(&jks), fmt);
            let back = KeyStore::load(&jks, Some("pw"), Some("kp")).unwrap();
            assert!(back.key_entry(Some("server")).unwrap().0.public_key().same_as(&id.key.public_key()));
            assert_eq!(back.trusted_certs(), vec![id.cert_der.clone()]);
            assert!(KeyStore::load(&jks, Some("px"), Some("kp")).unwrap_err().contains("password"));
            assert!(KeyStore::load(&jks, Some("pw"), Some("kx")).unwrap_err().contains("wrong key password"));
            let mut bad = jks.clone();
            bad[20] ^= 1;
            assert!(KeyStore::load(&bad, Some("pw"), Some("kp")).unwrap_err().contains("tampered"));
            for n in [0, 4, 31, jks.len() / 2, jks.len() - 1] {
                assert!(KeyStore::load_as(&jks[..n], fmt, Some("pw"), Some("kp")).is_err());
            }
        }
    }
}
