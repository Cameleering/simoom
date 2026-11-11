# Key store fixtures

Used by `tests/keystores.rs` and `tests/fuzzing_keystore.rs`. The key and chain are
`../leaf.key` with `../leaf.pem` <- `../int.pem` <- `../ca.pem` (CN `leaf.camel.test`,
`Camel Test Intermediate`, `Camel Test Root CA`); RSA files use `../rsa2048.pkcs8.pem` and
`../rsa_selfsigned.pem`. Store passwords are `changeit` (JKS/JCEKS key password `keypass`),
encrypted PEM keys use `secret`.

## Copied from Cameleer (`crates/cameleer-tls/testdata/keystores`)

- `keytool*.jks`, `keytool*.jceks`, `keytool*.p12`: made with JDK `keytool` (`-importkeystore`
  from `openssl_modern.p12` with key password `keypass`; `-genkeypair` for the EC, RSA and
  Ed25519 stores; `-importcert` for the trust stores). keytool is not installed on this machine,
  so no new keytool fixtures were made here.
- `openssl_modern.p12`, `openssl_legacy.p12`, `openssl_aes128_sha1mac.p12`, `openssl_trust.p12`,
  `leaf_pbes2_*.key`, `leaf_pbe_sha1_3des.key`: made with `openssl pkcs12` / `openssl pkcs8`.

## Made here with OpenSSL 3.5.9 (Git for Windows `/ucrt64/bin/openssl`)

`chain.pem` is `int.pem` followed by `ca.pem`.

```sh
openssl pkcs12 -export -inkey leaf.key -in leaf.pem -certfile chain.pem -name server -passout pass:changeit -out keystores/openssl3_default.p12
openssl pkcs12 -export -legacy -inkey leaf.key -in leaf.pem -certfile chain.pem -name server -passout pass:changeit -out keystores/openssl3_legacy.p12
openssl pkcs12 -export -inkey leaf.key -in leaf.pem -certfile chain.pem -name server -keypbe AES-192-CBC -certpbe AES-192-CBC -macalg sha512 -iter 3000 -passout pass:changeit -out keystores/openssl3_aes192_sha512mac.p12
openssl pkcs12 -export -inkey leaf.key -in leaf.pem -name server -keypbe NONE -certpbe NONE -nomac -passout pass: -out keystores/openssl3_plain_nomac.p12
openssl pkcs12 -export -inkey rsa2048.pkcs8.pem -in rsa_selfsigned.pem -name rsa -passout pass:changeit -out keystores/openssl3_rsa.p12
openssl pkcs8 -topk8 -v2 aes-256-cbc -in leaf.key -passout pass:secret -out keystores/leaf_openssl3_aes256.key
openssl pkcs8 -topk8 -v2 aes-192-cbc -v2prf hmacWithSHA512 -iter 5000 -in leaf.key -passout pass:secret -out keystores/leaf_openssl3_aes192_sha512.key
openssl pkcs8 -topk8 -v2 aes-128-cbc -v2prf hmacWithSHA384 -in rsa2048.pkcs8.pem -passout pass:secret -out keystores/rsa_openssl3_aes128_sha384.key
openssl pkcs8 -topk8 -v1 PBE-SHA1-2DES -in leaf.key -passout pass:secret -out keystores/leaf_openssl3_pbe_sha1_2des.key
openssl pkcs8 -topk8 -provider legacy -provider default -v1 PBE-SHA1-RC2-40 -in leaf.key -passout pass:secret -out keystores/leaf_openssl3_pbe_sha1_rc2_40.key
openssl pkcs8 -topk8 -provider legacy -provider default -v1 PBE-SHA1-RC2-128 -in leaf.key -passout pass:secret -out keystores/leaf_openssl3_pbe_sha1_rc2_128.key
```
