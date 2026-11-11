# Revocation fixtures

Made with OpenSSL 3.5.9 (Git for Windows, `/ucrt64/bin/openssl`) by `gen.sh` on 2026-11-09:

```sh
cd crates/simoom-tls/testdata/revocation && ./gen.sh /ucrt64/bin/openssl
```

Everything is valid for 100 years from that date, so the tests can use the real fixture times.

| file | what |
|---|---|
| `ca.pem`, `ca.key` | EC P-256 CA "Revocation Fixture CA" (keyCertSign, cRLSign) |
| `leaf-good.pem` | serial 0x1001, valid; CRL DP `http://crl.revocation.test/ca.crl`, AIA OCSP `http://ocsp.revocation.test/`, caIssuers `http://ca.revocation.test/ca.der` |
| `leaf-revoked.pem` | serial 0x1002, revoked 2026-01-01 (keyCompromise) |
| `leaf-unknown.pem` | serial 0x1003, not in the CA database (OCSP "unknown") |
| `responder.pem` | delegated OCSP responder issued by the CA, EKU OCSPSigning |
| `responder-noeku.pem` | issued by the CA, EKU serverAuth only (must not be accepted as a responder) |
| `crl-sha256.pem`, `crl-sha256.der` | `openssl ca -gencrl`, ecdsa-with-SHA256, AKI and CRL number, revokes 0x1002 |
| `crl-ecdsa-sha1.der` | the same CRL signed with ecdsa-with-SHA1 (`-md sha1`) |
| `rsa-ca.pem`, `crl-rsa-sha1.der` | an RSA-2048 CA and its sha1WithRSAEncryption CRL revoking 0x1002 |
| `req-{good,revoked,unknown}.der` | `openssl ocsp -issuer ca.pem -cert leaf-X.pem -reqout` (with OpenSSL's default nonce) |
| `req-good-nononce.der` | the same with `-no_nonce` |
| `resp-{good,revoked,unknown}-issuer.der` | `openssl ocsp -index ... -rsigner ca.pem -respout -ndays 36500`, signed by the CA, nonce echoed, responder ID by name |
| `resp-{good,revoked}-delegated.der` | signed by `responder.pem` (included in the response) |
| `resp-good-noeku.der` | signed by `responder-noeku.pem` (OpenSSL itself refuses it too) |
| `resp-good-nononce.der` | the CA's answer to `req-good-nononce.der` (no nonce) |
