//! PKI formats and checks (**moves to ksar-pki**): key stores (PKCS#12, JKS/JCEKS, PEM
//! bundles and encrypted PKCS#8 keys, `keystore`) and revocation (CRLs, OCSP and the path
//! check, `revocation`). Nothing here depends on the TLS state machine: only on the crypto
//! modules, `asn1`, `x509`, `keys` and `pem`. The crate root re-exports both as
//! `simoom_tls::keystore` and `simoom_tls::revocation`.

#[cfg(feature = "keystore")]
pub mod keystore;
#[cfg(feature = "revocation")]
pub mod revocation;
