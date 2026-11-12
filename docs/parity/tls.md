# TLS parity: Cameleer `cameleer-tls` to `simoom-tls`

BUGS.md items C1 (TLS 1.2), C2 (key stores, `SSLContextParameters`), C3 (revocation), C4 (the
crypto they need), C11 (blocking stream adapter) and the TLS rows of C10. Each row names the
Cameleer feature, its simoom-tls equivalent and the test that proves it. All new code is behind
cargo features that are off in simoom's server builds (`scripts/size.sh` reports their cost).

Features: `tls12`, `sha1`, `legacy` (MD5, DES/3DES, RC2, CBC AES; implied by `keystore`),
`keystore` (PEM bundles, encrypted PKCS#8, `KeyStore`, `SslContextParameters`), `pkcs12`, `jks`,
`revocation`, `blocking`.

## Where the code came from, and where it goes

The owner plans a shared crypto family, **ksar** (`ksar` for primitives, `ksar-pki`
for PKI). The modules below are self-contained (no dependency on the TLS state machine) so they
can move mechanically; their module docs say the same.

| simoom-tls module | ported from (Cameleer `crates/cameleer-tls/src/`) | destination |
|---|---|---|
| `crypto/sha1.rs` | `crypto/hash.rs` (`Sha1`) | moves to ksar |
| `crypto/md.rs` (HMAC, PBKDF2, PKCS#12 KDF over SHA-1/SHA-2) | `crypto/hash.rs`, `crypto/kdf.rs` | moves to ksar |
| `crypto/legacy/` (bitsliced AES both directions + CBC, DES/3DES, RC2, MD5, HMAC-MD5) | `crypto/aes.rs` (inverse cipher, CBC), `crypto/des.rs`, `crypto/rc2.rs`, `crypto/md5.rs` | moves to ksar |
| `crypto/legacy/md4.rs` (MD4, RFC 1320; HMAC-MD4) for NTLM client auth | new: Cameleer has no MD4 | moves to ksar |
| `pki/keystore/mod.rs` (`KeyStore`, formats, PEM bundles) | `keystore/mod.rs` | moves to ksar-pki |
| `pki/keystore/pem_key.rs` (encrypted PKCS#8 PEM) | `keys.rs` `from_pem_with_password` | moves to ksar-pki |
| `pki/keystore/pbe.rs` (PBES2, PKCS#12 PBE) | `pbe.rs` | moves to ksar-pki |
| `pki/keystore/pkcs12.rs` | `keystore/pkcs12.rs` | moves to ksar-pki |
| `pki/keystore/jks.rs` (JKS, JCEKS, the JKS keyed digest) | `keystore/jks.rs` | moves to ksar-pki |
| `pki/revocation/crl.rs` | `x509.rs` (`Crl`), `certgen.rs` (`issue_crl`) | moves to ksar-pki |
| `pki/revocation/ocsp.rs` | `ocsp.rs` | moves to ksar-pki |
| `pki/revocation/mod.rs` (policy, `check_path`, CRL cache, `StapleSource`) | `x509.rs` `verify_chain_with_crls`, `tls/config.rs` `OcspMode`, `tls/client.rs` `check_ocsp` | moves to ksar-pki |
| `keys.rs` `SignatureAlgorithm::{RsaPkcs1Sha1, EcdsaSha1}`, `crypto/rsa.rs` `verify_pkcs1_sha1` | `keys.rs`, `crypto/rsa.rs` | with keys/rsa to ksar |
| `tls/tls12.rs`, `tls/server12.rs`, `tls/client12.rs` | `tls/server.rs` `server12`, `tls/client.rs` `client12`, `tls/keyschedule.rs` (PRF, EMS, key block), `tls/record.rs` (1.2 records), `tls/session.rs` | stays (TLS engine) |
| `params.rs` (`SslContextParameters`) | `params.rs` | stays |
| `blocking.rs` | `net.rs`, `tls/stream.rs` | stays |

The keystore and revocation work kept Cameleer's tests and vectors (adapted) and its keytool
fixtures (`testdata/keystores/`, copied from Cameleer; JDK keytool is not installed here).

## C1: TLS 1.2

| Cameleer | simoom-tls | test |
|---|---|---|
| TLS 1.2 client and server next to 1.3 (`min_version`/`max_version`) | `ServerConfig`/`ClientConfig` `min_version`, `max_version` (`ProtocolVersion`), default 1.2..1.3; sans-io, same `Connection` API | `tests/tls12.rs` `tls13_is_chosen_when_both_sides_support_it` |
| Suites `ECDHE_{ECDSA,RSA}_WITH_AES_128/256_GCM`, `..._CHACHA20_POLY1305` (Cameleer offers exactly these six; no CBC, RC4, static RSA or export suites, so none were added) | `tls12::Tls12Suite` (IANA and OpenSSL names), `suites12` | `tls12.rs` `every_suite_and_key_type`; `interop12.rs` all suites both directions |
| Groups X25519, P-256, P-384 | `NamedGroup::Secp384r1` (feature `p384`, opt-in in `groups`; also usable in TLS 1.3) | `every_suite_and_key_type` (each group); dudect `timing_legacy.rs` `p384_ecdh_is_constant_time_in_the_scalar` |
| RSA, ECDSA (P-256, P-384) and Ed25519 certificates; PKCS#1 v1.5 and PSS signatures in 1.2 | `tls12::{choose_scheme12, sign12, verify12}`; RFC 8422 cert-curve check | `every_suite_and_key_type`; interop with RSA and ECDSA certs |
| Extended master secret (Cameleer: optional) | **required** both sides (RFC 7627); a peer without it gets handshake_failure | `extended_master_secret_is_required`; `interop12.rs` `-no_ems` refused |
| Session tickets (RFC 5077) and session IDs | server: `ticketer` (shared with 1.3, version-tagged state) and `session_ids: SessionIdCache`; client: `SessionCache` (1.2 entries reusable) | `ticket_and_session_id_resumption`; `interop12.rs` resumption with `-sess_out/-sess_in`, `-no_ticket`, and against `s_server` |
| `renegotiation_info` checked; renegotiation refused | `renegotiation_info`/SCSV answered; HelloRequest or a second ClientHello gets a `no_renegotiation` warning, bounded by the idle-record limit | `tls::conn` `tls12_renegotiation_is_refused_with_a_warning` |
| Downgrade sentinel (RFC 8446 4.1.3) | server marks its random when it supports 1.3; a 1.3-offering client refuses it; `TLS_FALLBACK_SCSV` gets inappropriate_fallback | `downgrade_sentinel_is_detected`, `fallback_scsv_is_refused_when_tls13_is_supported`, `hardening.rs` `client_rejects_the_downgrade_sentinels` |
| Client certificates in 1.2 (CertificateRequest, CertificateVerify over the transcript) | `server12`/`client12` | `client_certificates`; `interop12.rs` mTLS both directions |
| TLS 1.2 PRF, key block, Finished | `tls12::{prf, master_secret, ciphers, finished}` | `tls12::tests` PRF vectors (SHA-256 from the IETF list, SHA-384 cross-checked with Python) |
| AEAD records (explicit nonce GCM, RFC 7905 ChaCha) | `RecordCipher::tls12`, `open_record12`/`seal_record12` | every handshake test; `bytewise_and_tampered_flights` |
| Exporter (RFC 5705) | `Connection::export_keying_material` (1.2: RFC 5705) | `exporter_matches_on_both_sides` |
| QUIC stays TLS 1.3 only | QUIC engines never offer or accept 1.2 | `quic_stays_tls13_only`; simoom-quic suite |
| Negotiated version and suite name | `Connection::protocol_version`, `cipher_suite_name`, `negotiated_tls12_suite` | all of the above |
| 0-RTT early data (Cameleer opt-in) | not supported: simoom never offers or accepts 0-RTT (plan decision) | `conn` `rejected_early_data_is_skipped` |

Interop (Windows 11 and WSL2 Ubuntu 24.04, all local): `openssl s_client -tls1_2` (OpenSSL
3.5.9 Windows, 3.0.13 WSL) against the simoom server for all six suites, X25519/P-256/P-384,
ALPN, tickets and session-ID resumption, mTLS, `-no_ems` refusal (OpenSSL 3.5 only; 3.0 has no `-no_ems`); the simoom client against
`openssl s_server -tls1_2` for all six suites, a 1.3+1.2 client against a 1.2-only server (no
false downgrade alarm), tickets and session IDs, mTLS; curl `--tls-max 1.2` (curl 8.23
Schannel and the Windows system curl 8.21 Schannel on Windows; OpenSSL curl on WSL) with ECDSA
and RSA certificates; Python `ssl` (3.12 / OpenSSL 3.0.16 Windows, WSL's python3) as a TLS 1.2
client and server. Test file: `tests/interop12.rs`.

## C2: key stores and `SSLContextParameters`

| Cameleer | simoom-tls | test |
|---|---|---|
| `keystore::KeyStore` (load, load_as, load_file, from_pem, key_entry, trusted_certs, aliases, to_pkcs12, to_jks, order_chain) | `simoom_tls::keystore::KeyStore`, same names and signatures (errors as `String`); plus `to_jceks` | `pki::keystore` unit tests; `tests/keystores.rs` |
| PKCS#12 read: PBES2 (PBKDF2 + AES-128/192/256-CBC), legacy PBE-SHA1-3DES / 2DES / RC2-40 / RC2-128, MAC check (SHA-1/256/384/512) | `keystore::pkcs12::parse` (MAC verified in constant time first) | `keystores.rs` `openssl_pkcs12_fixtures`, `fresh_openssl3_pkcs12_fixtures`, `keytool_stores` |
| PKCS#12 write (modern; legacy profile) | `pkcs12::write(ks, pw, Pkcs12Profile::{Modern, Legacy})`; OpenSSL reads ours | `writer_round_trips`, `openssl_reads_our_pkcs12` |
| JKS and JCEKS read and write (JKS keyed SHA-1 digest, JKS key protector, JCEKS PBEWithMD5AndTripleDES) | `keystore::jks::{parse, write, write_jceks}` | `keytool_stores`, `writer_round_trips` |
| PEM bundles, encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) | `KeyStore::from_pem`, `keystore::private_key_from_pem` | `encrypted_pkcs8_pem` (OpenSSL PBES2 AES/SHA-2 PRFs, PBE-SHA1-2DES, RC2) |
| DER `EncryptedPrivateKeyInfo` key files (pgjdbc `.pk8`) | `keystore::pbe::decrypt_encrypted_private_key_info`, used by `SslContextParameters` | `pki::keystore::pbe` tests |
| Hostile files bounded | iterations 1..10,000,000, at most 10,000 entries, nesting depth 4, chain 64, trailing data refused | `hostile_iteration_counts_and_sizes_are_bounded`; fuzz `tests/fuzzing_keystore.rs` |
| `SslContextParameters` (fields, builders, `key_material`, `trust_roots`, `client_config`, `server_config`, `from_properties` with every Cameleer key) | `simoom_tls::params::SslContextParameters`, same field and method names; `ClientAuthMode` for Cameleer's `ClientAuth` (simoom's `ClientAuth` carries the trust store) | `params::tests` (properties, JKS key store + PKCS#12 trust store + REQUIRE, wrong alias, missing trust) |
| `cipherSuites` | supported (IANA or OpenSSL names, both versions; Cameleer ignored it) | `cipher_suites_and_resumption` |
| `insecureSkipVerify`, `hostnameVerification=false` | **refused** with a configuration error (simoom never disables verification) | `verification_cannot_be_disabled` |
| `crlFile` | a `RevocationPolicy` with `CrlMode::IfAvailable` on client and server (feature `revocation`) | `tests/tls_revocation.rs` |
| `sessionTimeout`, `sessionResumption` | `ticket_lifetime_secs` (capped at 7 days), tickets / session IDs / client cache off | `cipher_suites_and_resumption` |
| `camel_support.rs` (registry lookup, `camel.ssl.*`, exception kinds, `EndpointTls`, `client_cert_headers`) | stays in Cameleer: it depends on `cameleer-core`; it maps onto `SslContextParameters` and `blocking` unchanged | n/a |

## C3: revocation

| Cameleer | simoom-tls | test |
|---|---|---|
| CRL parse, signature, revoked serial lookup | `revocation::crl::Crl` (`from_der`, `parse_all`, `verify_signature`, `is_revoked`, `covers`, `is_fresh`), limits | `pki::revocation` unit tests; `tests/revocation.rs` (OpenSSL `ca -gencrl` fixtures incl. SHA-1 signed) |
| `verify_chain_with_crls` | `x509::verify_chain_path` + `revocation::check_path` with `CrlMode::{Off, IfAvailable, Require}`, CRL DP fetch through a caller-supplied `RevocationFetcher` (sans-io), CRL cache | `revocation.rs`, `tls_revocation.rs` `crls_for_server_and_client_certificates` |
| OCSP request/response build and parse, signature (issuer or delegated responder with OCSPSigning), freshness, nonce | `revocation::ocsp` (`build_request` byte-identical to OpenSSL's, `OcspResponse::parse/validate`, `build_response`) | `revocation.rs` (OpenSSL `ocsp` fixtures), unit tests |
| Client `OcspMode::{Off, Request, Require}` (stapling) | `ClientConfig::revocation: Option<RevocationPolicy>` with `ocsp`; sends `status_request`; validates the TLS 1.3 leaf-entry staple and the TLS 1.2 CertificateStatus; `Connection::ocsp_response()` | `tls_revocation.rs` `stapled_ocsp_good_revoked_missing` (1.3 and 1.2) |
| Server stapling (`ocsp_response`, `set_ocsp_response`) | `ServerConfig::ocsp_staple: Option<StapleSource>`; the caller fetches/refreshes (`set`, `set_checked`); read per handshake | `stapled_ocsp_good_revoked_missing`; interop: `openssl s_client -status` (1.3, 1.2) and `openssl s_server -status_file` (1.3, 1.2) |
| CRLs on client certificates (server) | `ServerConfig::client_revocation` | `crls_for_server_and_client_certificates` |
| Online OCSP (not in Cameleer) | `RevocationPolicy::ocsp_online` through the fetcher, nonce always sent | `revocation.rs` |
| Alerts | `certificate_revoked` (44), `bad_certificate_status_response` (113) | `tls_revocation.rs` |

## C4: crypto

| Cameleer | simoom-tls | test |
|---|---|---|
| SHA-1 | `crypto::sha1` (feature `sha1`), `crypto::md::Md` (HMAC, PBKDF2, PKCS#12 KDF) | FIPS 180 vectors, RFC 2202, RFC 6070, PKCS#12 KDF vectors |
| sha1WithRSA / ecdsa-with-SHA1 certificate, CRL and OCSP signatures | `SignatureAlgorithm::{RsaPkcs1Sha1, EcdsaSha1}` (feature `sha1`; never in a handshake) | `revocation.rs` SHA-1 CRLs |
| MD4 and HMAC-MD5 (NTLMv2 client auth; not in Cameleer's TLS crate) | `crypto::legacy::{Md4, hmac_md5, hmac_md4}` | RFC 1320 (all 7), RFC 2202 HMAC-MD5, MS-NLMP NTOWFv1/NTOWFv2 vectors |
| MD5, DES/3DES, RC2, AES-CBC (key stores) | `crypto::legacy` (feature `legacy`); AES bitsliced and constant time, DES/RC2/MD5 table-driven and only for key-store data | RFC 1321, RFC 2268, SP 800-67, FIPS-197, SP 800-38A vectors; dudect `timing_legacy.rs` |
| RSA-OAEP | **not ported**: no key store or TLS path needs it; only Cameleer's XML Encryption uses it (`cameleer-xml`), outside this scope | n/a |

## C11: blocking adapter

| Cameleer (`net.rs`, `tls/stream.rs`) | simoom-tls (`blocking`) | test |
|---|---|---|
| `TlsStream<S: Read + Write>` connect/accept, `Read`/`Write`, `close`, accessors (version, suite, ALPN, peer certs, SNI, resumed) | `blocking::TlsStream` | `blocking::tests::echo_over_tcp_both_versions` (TLS 1.3 and 1.2) |
| `connect_tcp`, `NetStream::client/server`, `connect` with timeout | `connect_tcp`, `client`, `accept`, `connect`; socket timeouts apply; a timed-out read can be retried | `read_timeout_is_retryable`, `host_name_is_verified` |
| `lingering_close`, `accept_tls` (alert not lost to a reset, INTEROP bug 18) | `lingering_close`, used by `accept` after a fatal alert | `fatal_alert_survives_a_client_that_reads_late` |
| `split` into read/write halves sharing one handle | `TlsStream::split` -> `TlsReader`, `TlsWriter` (clonable) over `SharedTcp` | `split_full_duplex` |
| STARTTLS (`start_tls_client/server` on a plain stream) | `client`/`accept` on the already-connected `TcpStream` (or `TlsStream::connect` on any stream) | covered by the same paths |
| `shutdown_socket` (`CancelIoEx` to wake a blocked read on Windows) | not ported: needs `unsafe` in simoom-sys; `split` halves close with close_notify instead | n/a |

## Size (x86-64 Linux, `dist`, `scripts/size.sh`, 2026-11-09)

Inside simoom (budgeted rows): `http1,http2,tls` 564,704 bytes added (budget 614,400);
`http1,http2,tls,tls12` (new row) 605,680, so TLS 1.2 costs about 41 KB inside simoom. With the
new features off, this work adds 3.3 KB to the TLS rows (561,392 before, measured with the
previous simoom-tls on the same tree): the locator parsing, the stapling encoder and path
building with certificate copies are compiled only with `revocation`. `http1,http2,tls,io-uring`
is 597,096 of 614,400 (593,816 before this work): under budget but, as before it, without the 5%
headroom.

What each feature adds to a TLS server that uses it (`examples/size_features.rs`, base 583,464):

| feature | added |
|---|---:|
| `tls12` | 49,624 |
| `keystore` (PEM, encrypted PKCS#8, `SslContextParameters`) | 66,176 |
| `pkcs12` | 94,080 |
| `jks` | 89,312 |
| `revocation` | 85,616 |
| `blocking` | 21,416 |
| all of them | 271,232 |

## Not covered here

- Cameleer's `sasl.rs`, `stream_body.rs` and `testing*.rs` are not TLS and stay in Cameleer.
- `cameleer-tls`'s `ClientSessionCache` keyed by an arbitrary session key (`connect_with_session_key`):
  simoom keys its client cache by server name.
