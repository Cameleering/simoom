//! Private keys from PEM, including `ENCRYPTED PRIVATE KEY` (PKCS#8 `EncryptedPrivateKeyInfo`
//! with PBES2 or a PKCS#12 PBE scheme).
//!
//! (**Moves to ksar-pki**; from Cameleer `cameleer-tls/src/keys.rs` `from_pem_with_password`.)

use crate::keys::PrivateKey;
use crate::pem;

/// The first private key in PEM text: `PRIVATE KEY` (PKCS#8), `EC PRIVATE KEY` (SEC1),
/// `RSA PRIVATE KEY` (PKCS#1, feature `rsa`) or `ENCRYPTED PRIVATE KEY`, which needs
/// `password`. A wrong password is an error, never a garbage key. Legacy OpenSSL
/// `Proc-Type: 4,ENCRYPTED` PEM headers are not supported.
pub fn decrypt_private_key_pem(data: &[u8], password: Option<&str>) -> Result<PrivateKey, String> {
    let blocks = pem::parse_pem(data)?;
    for b in blocks {
        let r = match b.label.as_str() {
            "PRIVATE KEY" => PrivateKey::from_pkcs8(&b.der).map_err(|e| e.to_string()),
            "EC PRIVATE KEY" => PrivateKey::from_sec1(&b.der, None).map_err(|e| e.to_string()),
            #[cfg(feature = "rsa")]
            "RSA PRIVATE KEY" => PrivateKey::from_pkcs1(&b.der).map_err(|e| e.to_string()),
            #[cfg(feature = "sha1")]
            "ENCRYPTED PRIVATE KEY" => {
                let pw = password.ok_or("the private key is encrypted: a key password is required (keyPassword)")?;
                let mut der = super::pbe::decrypt_encrypted_private_key_info(&b.der, pw)?;
                let k = PrivateKey::from_pkcs8(&der).map_err(|e| format!("encrypted private key (wrong password?): {e}"));
                crate::util::zeroize(&mut der);
                k
            }
            #[cfg(not(feature = "sha1"))]
            "ENCRYPTED PRIVATE KEY" => {
                let _ = password;
                Err("encrypted private keys need the `sha1` feature (implied by `pkcs12` and `jks`)".to_string())
            }
            _ => continue,
        };
        return r;
    }
    Err("no private key found in PEM input".into())
}
