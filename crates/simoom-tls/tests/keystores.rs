//! Key store parsing (PKCS#12, JKS, JCEKS, encrypted PKCS#8) against fixtures made by
//! `openssl pkcs12` / `openssl pkcs8` and Java `keytool` (testdata/keystores, see its README),
//! round trips through our writers, hostile inputs, and using the stores for a TLS handshake.

use simoom_tls::asn1;
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::crypto::md::{bmp_password, Md, PKCS12_MAC};
use simoom_tls::keys::PrivateKey;
use simoom_tls::keystore::{self, pbe, pkcs12, KeyStore, KeyStoreFormat};
use simoom_tls::x509::{Certificate, RootStore};
use simoom_tls::{CertifiedKey, ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn leaf_key() -> PrivateKey {
    PrivateKey::from_pem(&read("leaf.key")).unwrap()
}

fn rsa_key() -> PrivateKey {
    PrivateKey::from_pem(&read("rsa2048.pkcs8.pem")).unwrap()
}

fn subject_cn(der: &[u8]) -> String {
    Certificate::from_der(der).unwrap().subject.common_name().unwrap_or("").to_string()
}

fn same_key(a: &PrivateKey, b: &PrivateKey) -> bool {
    a.public_key().same_as(&b.public_key())
}

fn check_leaf_store(f: &str, ks: &KeyStore, full_chain: bool) {
    let (key, chain) = ks.key_entry(Some("server")).unwrap_or_else(|| panic!("{f}: no 'server' entry: {:?}", ks.aliases()));
    assert!(same_key(key, &leaf_key()), "{f}");
    assert_eq!(subject_cn(&chain[0]), "leaf.camel.test", "{f}");
    if full_chain {
        assert_eq!(chain.len(), 3, "{f}: chain leaf, intermediate, root");
        assert_eq!(subject_cn(&chain[1]), "Camel Test Intermediate", "{f}");
        assert_eq!(subject_cn(&chain[2]), "Camel Test Root CA", "{f}");
        // the chain certificates belong to the key entry, not the trusted entries
        assert!(ks.trusted_certs().is_empty(), "{f}");
    }
}

#[test]
fn openssl_pkcs12_fixtures() {
    // made by OpenSSL 3 (default, -legacy, AES-128 with a SHA-1 MAC), copied from Cameleer
    for f in ["keystores/openssl_modern.p12", "keystores/openssl_legacy.p12", "keystores/openssl_aes128_sha1mac.p12"] {
        let data = read(f);
        assert_eq!(KeyStoreFormat::detect(&data), KeyStoreFormat::Pkcs12, "{f}");
        let ks = KeyStore::load(&data, Some("changeit"), None).unwrap_or_else(|e| panic!("{f}: {e}"));
        check_leaf_store(f, &ks, !f.contains("aes128"));
        let e = KeyStore::load(&data, Some("wrong"), None).unwrap_err();
        assert!(e.contains("password"), "{f}: {e}");
    }
    let ts = KeyStore::load(&read("keystores/openssl_trust.p12"), Some("changeit"), None).unwrap();
    assert_eq!(ts.trusted_certs().len(), 1);
    assert!(ts.key_entry(None).is_none());
}

#[test]
fn fresh_openssl3_pkcs12_fixtures() {
    // made here with OpenSSL 3.5 (see testdata/keystores/README.md)
    for f in ["keystores/openssl3_default.p12", "keystores/openssl3_legacy.p12", "keystores/openssl3_aes192_sha512mac.p12"] {
        let data = read(f);
        let ks = KeyStore::load(&data, Some("changeit"), None).unwrap_or_else(|e| panic!("{f}: {e}"));
        check_leaf_store(f, &ks, true);
        assert!(KeyStore::load(&data, Some("changeiT"), None).unwrap_err().contains("password"), "{f}");
        assert!(KeyStore::load(&data, None, None).is_err(), "{f}");
    }
    // unencrypted key bag and certificate, no MAC: readable without a password
    let ks = KeyStore::load(&read("keystores/openssl3_plain_nomac.p12"), None, None).unwrap();
    check_leaf_store("plain_nomac", &ks, false);
    // RSA key in a shrouded key bag
    let ks = KeyStore::load(&read("keystores/openssl3_rsa.p12"), Some("changeit"), None).unwrap();
    let (k, chain) = ks.key_entry(Some("rsa")).unwrap();
    assert!(matches!(k, PrivateKey::Rsa(_)));
    assert!(same_key(k, &rsa_key()));
    assert_eq!(chain.len(), 1);
}

#[test]
fn keytool_stores() {
    // JDK keytool is not installed here: these fixtures were made with keytool for Cameleer.
    // JKS / JCEKS with a separate key password, imported from the OpenSSL PKCS#12.
    for f in ["keystores/keytool.jks", "keystores/keytool.jceks"] {
        let data = read(f);
        let ks = KeyStore::load(&data, Some("changeit"), Some("keypass")).unwrap_or_else(|e| panic!("{f}: {e}"));
        check_leaf_store(f, &ks, true);
        assert!(KeyStore::load(&data, Some("changeit"), Some("nope")).is_err());
        let e = KeyStore::load(&data, Some("wrong"), Some("keypass")).unwrap_err();
        assert!(e.contains("password"), "{e}");
        // a store loaded without its password skips the integrity check but still needs the key password
        assert!(KeyStore::load(&data, None, Some("keypass")).is_ok());
        assert!(KeyStore::load(&data, None, None).unwrap_err().contains("key password"));
    }
    let ts = KeyStore::load(&read("keystores/keytool_trust.jks"), None, None).unwrap();
    assert_eq!(subject_cn(&ts.trusted_certs()[0]), "Camel Test Root CA");
    let ts = KeyStore::load(&read("keystores/keytool_trust.jks"), Some("changeit"), None).unwrap();
    assert_eq!(ts.trusted_certs().len(), 1);
    let ts = KeyStore::load(&read("keystores/keytool_trust.p12"), Some("changeit"), None).unwrap();
    assert_eq!(subject_cn(&ts.trusted_certs()[0]), "Camel Test Root CA");
    // keys generated by keytool (Java PKCS#12 = PBES2/AES-256/HmacSHA256)
    let ec = KeyStore::load(&read("keystores/keytool_ec.p12"), Some("changeit"), None).unwrap();
    assert!(matches!(ec.key_entry(Some("server")).unwrap().0, PrivateKey::Ec { .. }));
    let rsa = KeyStore::load(&read("keystores/keytool_rsa.jks"), Some("changeit"), None).unwrap();
    assert!(matches!(rsa.key_entry(Some("rsaserver")).unwrap().0, PrivateKey::Rsa(_)));
    let ed = KeyStore::load(&read("keystores/keytool_ed25519.p12"), Some("changeit"), None).unwrap();
    assert!(matches!(ed.key_entry(Some("ed")).unwrap().0, PrivateKey::Ed25519 { .. }));
}

#[test]
fn encrypted_pkcs8_pem() {
    let leaf = [
        "leaf_pbes2_aes256.key",
        "leaf_pbes2_sha1_aes128.key",
        "leaf_pbes2_des3.key",
        "leaf_pbe_sha1_3des.key",
        "leaf_openssl3_aes256.key",
        "leaf_openssl3_aes192_sha512.key",
        "leaf_openssl3_pbe_sha1_2des.key",
        "leaf_openssl3_pbe_sha1_rc2_40.key",
        "leaf_openssl3_pbe_sha1_rc2_128.key",
    ];
    for f in leaf.iter().map(|f| (f, leaf_key())).chain([(&"rsa_openssl3_aes128_sha384.key", rsa_key())]) {
        let (name, expected) = f;
        let data = read(&format!("keystores/{name}"));
        assert!(PrivateKey::from_pem(&data).is_err(), "{name}: the plain parser refuses encrypted keys");
        assert!(keystore::private_key_from_pem(&data, None).unwrap_err().contains("password"), "{name}");
        let k = keystore::private_key_from_pem(&data, Some("secret")).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(same_key(&k, &expected), "{name}");
        assert!(keystore::decrypt_private_key_pem(&data, Some("wrong")).is_err(), "{name}");
        // the PEM store loader takes the key password
        let ks = KeyStore::load(&data, None, Some("secret")).unwrap();
        assert!(same_key(ks.key_entry(None).unwrap().0, &expected));
    }
    // plain keys go through the same function
    assert!(same_key(&keystore::private_key_from_pem(&read("leaf.key"), None).unwrap(), &leaf_key()));
    assert!(keystore::private_key_from_pem(&read("ec256.sec1.pem"), None).is_ok());
    assert!(keystore::private_key_from_pem(&read("rsa2048.pkcs1.pem"), None).is_ok());
    assert!(keystore::private_key_from_pem(&read("leaf.pem"), None).unwrap_err().contains("no private key"));
}

fn mixed_store() -> (KeyStore, PrivateKey, PrivateKey, PrivateKey, Vec<u8>) {
    let id = certgen::self_signed("localhost");
    let rsa = rsa_key();
    let rsa_cert = simoom_tls::pem::parse_pem(&read("rsa_selfsigned.pem")).unwrap().remove(0).der;
    let ed = certgen::issue(&CertParams::server(&["ed.test"]), PrivateKey::generate_ed25519(), None);
    let p384 = certgen::issue(&CertParams::server(&["p384.test"]), PrivateKey::generate_ec(simoom_tls::keys::EcCurve::P384), None);
    let ks = KeyStore::from_key_entry("ec", id.key.clone(), vec![id.cert_der.clone()])
        .add_key("rsa", rsa.clone(), vec![rsa_cert.clone()])
        .add_key("ed", ed.key.clone(), vec![ed.cert_der.clone()])
        .add_key("p384", p384.key.clone(), vec![p384.cert_der.clone()])
        .add_cert("trusted", rsa_cert.clone());
    (ks, id.key, rsa, ed.key, rsa_cert)
}

#[test]
fn writer_round_trips() {
    let (ks, ec, rsa, ed, rsa_cert) = mixed_store();
    for (name, bytes, kp) in [
        ("pkcs12", ks.to_pkcs12("s3cret"), "s3cret"),
        ("legacy pkcs12", pkcs12::write(&ks, "s3cret", pkcs12::Pkcs12Profile::Legacy), "s3cret"),
        ("jks", ks.to_jks("s3cret", "kp"), "kp"),
        ("jceks", ks.to_jceks("s3cret", "kp"), "kp"),
    ] {
        let back = KeyStore::load(&bytes, Some("s3cret"), Some(kp)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(back.aliases(), vec!["ec", "rsa", "ed", "p384", "trusted"], "{name}");
        assert!(same_key(back.key_entry(Some("ec")).unwrap().0, &ec), "{name}");
        assert!(same_key(back.key_entry(Some("rsa")).unwrap().0, &rsa), "{name}");
        assert!(same_key(back.key_entry(Some("ed")).unwrap().0, &ed), "{name}");
        assert!(matches!(back.key_entry(Some("p384")).unwrap().0, PrivateKey::Ec { .. }), "{name}");
        assert_eq!(back.trusted_certs(), vec![rsa_cert.clone()], "{name}");
        assert!(KeyStore::load(&bytes, Some("S3cret"), Some(kp)).is_err(), "{name}: wrong store password");
    }
    // the modern profile is PBES2 / AES-256 with an HMAC-SHA256 MAC
    let p12 = ks.to_pkcs12("pw");
    let has = |needle: &str| p12.windows(asn1::oid(needle).len()).any(|w| w == asn1::oid(needle).as_slice());
    assert!(has(pbe::OID_PBES2) && has(pbe::OID_AES256_CBC) && has(pbe::OID_HMAC_SHA256) && has("2.16.840.1.101.3.4.2.1"));
    assert!(!has(pbe::OID_PBE_SHA_3DES) && !has(pbe::OID_PBE_SHA_RC2_40));
    // an empty store and an empty password
    let empty = KeyStore::new();
    assert!(KeyStore::load(&empty.to_pkcs12(""), Some(""), None).unwrap().entries.is_empty());
    assert!(KeyStore::load(&empty.to_jks("", ""), Some(""), None).unwrap().entries.is_empty());
    // encrypted PKCS#8 round trip
    let enc = pbe::encrypt_private_key_info(&ec.to_pkcs8(), "pw");
    let pem = simoom_tls::pem::encode_pem("ENCRYPTED PRIVATE KEY", &enc);
    assert!(same_key(&keystore::private_key_from_pem(pem.as_bytes(), Some("pw")).unwrap(), &ec));
    // separate key password in PKCS#12 shrouded bags is the store password for our writer
    assert!(KeyStore::load(&ks.to_pkcs12("pw"), Some("pw"), Some("other")).is_err());
}

#[test]
fn tampered_and_truncated_fixtures_fail_cleanly() {
    for (f, sp, kp) in [
        ("keystores/openssl_modern.p12", "changeit", "changeit"),
        ("keystores/openssl3_legacy.p12", "changeit", "changeit"),
        ("keystores/keytool.jks", "changeit", "keypass"),
        ("keystores/keytool.jceks", "changeit", "keypass"),
    ] {
        let data = read(f);
        for i in (0..data.len()).step_by(97) {
            let mut bad = data.clone();
            bad[i] ^= 0x40;
            assert!(KeyStore::load(&bad, Some(sp), Some(kp)).is_err(), "{f}: flipped byte {i} accepted");
        }
        for n in [0, 3, 16, 33, data.len() / 3, data.len() - 21, data.len() - 1] {
            assert!(KeyStore::load(&data[..n], Some(sp), Some(kp)).is_err(), "{f}: truncated to {n} accepted");
        }
        let mut longer = data.clone();
        longer.push(0);
        assert!(KeyStore::load(&longer, Some(sp), Some(kp)).is_err(), "{f}: trailing byte accepted");
    }
}

/// A PFX around `auth_safe` with a valid MAC (so the inner structure is what gets tested).
fn pfx_with_mac(auth_safe: &[u8], password: &str, iterations: u64, mac_iterations_field: u64) -> Vec<u8> {
    let salt = [7u8; 8];
    let key = Md::Sha256.pkcs12_kdf(&bmp_password(password), &salt, PKCS12_MAC, iterations as u32, 32);
    let mac = Md::Sha256.hmac(&key, &[auth_safe]);
    let data_ci = asn1::seq(&[asn1::oid("1.2.840.113549.1.7.1"), asn1::explicit(0, &asn1::octet_string(auth_safe))]);
    let mac_data = asn1::seq(&[
        asn1::seq(&[asn1::seq(&[asn1::oid(Md::Sha256.oid()), asn1::tlv(asn1::TAG_NULL, &[])]), asn1::octet_string(&mac)]),
        asn1::octet_string(&salt),
        asn1::uint(&mac_iterations_field.to_be_bytes()),
    ]);
    asn1::seq(&[asn1::uint(&[3]), data_ci, mac_data])
}

#[test]
fn hostile_iteration_counts_and_sizes_are_bounded() {
    let t = Instant::now();
    // MAC iteration count above the cap
    let auth_safe = asn1::seq(&[]);
    let e = pkcs12::parse(&pfx_with_mac(&auth_safe, "pw", 1, pbe::MAX_ITERATIONS + 1), "pw", None).unwrap_err();
    assert!(e.contains("iteration"), "{e}");
    let e = pkcs12::parse(&pfx_with_mac(&auth_safe, "pw", 1, u64::MAX >> 1), "pw", None).unwrap_err();
    assert!(e.contains("iteration"), "{e}");
    // a valid MAC around encrypted contents asking for 4 billion PBKDF2 iterations
    let alg = asn1::seq(&[
        asn1::oid(pbe::OID_PBES2),
        asn1::seq(&[
            asn1::seq(&[asn1::oid(pbe::OID_PBKDF2), asn1::seq(&[asn1::octet_string(&[1; 8]), asn1::uint(&u32::MAX.to_be_bytes())])]),
            asn1::seq(&[asn1::oid(pbe::OID_AES256_CBC), asn1::octet_string(&[0; 16])]),
        ]),
    ]);
    let eci = asn1::seq(&[asn1::oid("1.2.840.113549.1.7.1"), alg.clone(), asn1::tlv(0x80, &[0; 32])]);
    let auth_safe = asn1::seq(&[asn1::seq(&[asn1::oid("1.2.840.113549.1.7.6"), asn1::explicit(0, &asn1::seq(&[asn1::uint(&[0]), eci]))])]);
    let e = pkcs12::parse(&pfx_with_mac(&auth_safe, "pw", 1, 1), "pw", None).unwrap_err();
    assert!(e.contains("iteration"), "{e}");
    // the same in an encrypted PEM key
    let epki = asn1::seq(&[alg, asn1::octet_string(&[0; 32])]);
    let pem = simoom_tls::pem::encode_pem("ENCRYPTED PRIVATE KEY", &epki);
    assert!(keystore::private_key_from_pem(pem.as_bytes(), Some("pw")).unwrap_err().contains("iteration"));
    // more entries than MAX_ENTRIES (unencrypted cert bags behind a valid MAC)
    let id = certgen::self_signed("localhost");
    let bag = asn1::seq(&[
        asn1::oid("1.2.840.113549.1.12.10.1.3"),
        asn1::explicit(0, &asn1::seq(&[asn1::oid("1.2.840.113549.1.9.22.1"), asn1::explicit(0, &asn1::octet_string(&id.cert_der))])),
    ]);
    let bags = asn1::seq(&vec![bag; keystore::MAX_ENTRIES + 1]);
    let auth_safe = asn1::seq(&[asn1::seq(&[asn1::oid("1.2.840.113549.1.7.1"), asn1::explicit(0, &asn1::octet_string(&bags))])]);
    let e = pkcs12::parse(&pfx_with_mac(&auth_safe, "pw", 1, 1), "pw", None).unwrap_err();
    assert!(e.contains("entries"), "{e}");
    // nested safe-contents bags beyond the depth limit
    let mut inner = asn1::seq(&[]);
    for _ in 0..10 {
        inner = asn1::seq(&[asn1::seq(&[asn1::oid("1.2.840.113549.1.12.10.1.6"), asn1::explicit(0, &inner)])]);
    }
    let auth_safe = asn1::seq(&[asn1::seq(&[asn1::oid("1.2.840.113549.1.7.1"), asn1::explicit(0, &asn1::octet_string(&inner))])]);
    let e = pkcs12::parse(&pfx_with_mac(&auth_safe, "pw", 1, 1), "pw", None).unwrap_err();
    assert!(e.contains("nested"), "{e}");
    assert!(t.elapsed() < Duration::from_secs(20), "bounded inputs took {:?}", t.elapsed());
}

fn handshake(server_key: CertifiedKey, root_der: &[u8], host: &str) {
    let server_cfg = Arc::new(ServerConfig::new(server_key));
    let mut roots = RootStore::empty();
    roots.add_der(root_der).unwrap();
    let client_cfg = Arc::new(ClientConfig::new(roots));
    let mut server = ServerConnection::new(server_cfg);
    let mut client = ClientConnection::new(client_cfg, host).unwrap();
    client.write_plaintext(b"ping").unwrap();
    for _ in 0..20 {
        if !(client.wants_write() || server.wants_write()) {
            break;
        }
        let n = server.read_tls(client.tls_output());
        client.consume_tls_output(n);
        server.process_new_packets().unwrap();
        let n = client.read_tls(server.tls_output());
        server.consume_tls_output(n);
        client.process_new_packets().unwrap();
    }
    let mut buf = [0u8; 8];
    let n = server.read_plaintext(&mut buf);
    assert_eq!(&buf[..n], b"ping");
}

#[test]
fn key_stores_drive_tls_handshakes() {
    // the leaf.camel.test chain (leaf <- intermediate <- root), trusted through a JKS trust store
    let trust = KeyStore::load(&read("keystores/keytool_trust.jks"), Some("changeit"), None).unwrap();
    let root = trust.trusted_certs().remove(0);
    for (f, kp) in [("keystores/openssl_modern.p12", None), ("keystores/openssl3_legacy.p12", None), ("keystores/keytool.jceks", Some("keypass"))] {
        let ks = KeyStore::load(&read(f), Some("changeit"), kp).unwrap();
        let (key, chain) = ks.key_entry(Some("server")).unwrap();
        handshake(CertifiedKey::new(chain.to_vec(), key.clone()).unwrap(), &root, "leaf.camel.test");
    }
    // keytool-generated Ed25519 key
    let ks = KeyStore::load(&read("keystores/keytool_ed25519.p12"), Some("changeit"), None).unwrap();
    let (key, chain) = ks.key_entry(None).unwrap();
    let host = Certificate::from_der(&chain[0]).unwrap().dns_names.first().cloned().unwrap_or_else(|| "localhost".into());
    handshake(CertifiedKey::new(chain.to_vec(), key.clone()).unwrap(), &chain[0], &host);
    // our own writer, RSA
    let (mixed, ..) = mixed_store();
    let back = KeyStore::load(&mixed.to_pkcs12("pw"), Some("pw"), None).unwrap();
    let (key, chain) = back.key_entry(Some("ec")).unwrap();
    handshake(CertifiedKey::new(chain.to_vec(), key.clone()).unwrap(), &chain[0], "localhost");
}

/// OpenSSL reads our PKCS#12 output (skipped when no `openssl` binary is on the PATH).
#[test]
fn openssl_reads_our_pkcs12() {
    let Ok(v) = std::process::Command::new("openssl").arg("version").output() else {
        eprintln!("openssl not found: skipping");
        return;
    };
    if !v.status.success() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("simoom-tls-ks-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let id = certgen::self_signed("localhost");
    let ks = KeyStore::from_key_entry("mykey", id.key.clone(), vec![id.cert_der.clone()]);
    let p = dir.join("ours.p12");
    std::fs::write(&p, ks.to_pkcs12("changeit")).unwrap();
    let out = std::process::Command::new("openssl")
        .args(["pkcs12", "-in", p.to_str().unwrap(), "-passin", "pass:changeit", "-nodes"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("BEGIN PRIVATE KEY") && text.contains("BEGIN CERTIFICATE"), "{text} {}", String::from_utf8_lossy(&out.stderr));
    assert!(same_key(&PrivateKey::from_pem(text.as_bytes()).unwrap(), &id.key));
    // and our encrypted PKCS#8
    let k = dir.join("ours.key");
    std::fs::write(&k, simoom_tls::pem::encode_pem("ENCRYPTED PRIVATE KEY", &pbe::encrypt_private_key_info(&id.key.to_pkcs8(), "pw"))).unwrap();
    let out = std::process::Command::new("openssl").args(["pkey", "-in", k.to_str().unwrap(), "-passin", "pass:pw"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(same_key(&PrivateKey::from_pem(&out.stdout).unwrap(), &id.key));
    let _ = std::fs::remove_dir_all(&dir);
}
