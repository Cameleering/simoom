#!/usr/bin/env bash
# Regenerates the OpenSSL revocation fixtures (see README.md). Needs OpenSSL 3.
# Usage: cd crates/simoom-tls/testdata/revocation && ./gen.sh [path/to/openssl]
set -euo pipefail
OPENSSL=${1:-openssl}
export MSYS2_ARG_CONV_EXCL='*'
W=.gen-tmp
rm -rf "$W"; mkdir "$W"
trap 'rm -rf "$W"' EXIT

cat > "$W/ext.cnf" <<'CNF'
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:leaf.revocation.test
crlDistributionPoints = URI:http://crl.revocation.test/ca.crl
authorityInfoAccess = OCSP;URI:http://ocsp.revocation.test/,caIssuers;URI:http://ca.revocation.test/ca.der
[responder]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
[noeku]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
CNF

issue() { # name serial section signer-cert signer-key
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/$1.key" 2>/dev/null
  "$OPENSSL" req -new -key "$W/$1.key" -subj "/O=simoom/CN=$1" -out "$W/$1.csr"
  "$OPENSSL" x509 -req -in "$W/$1.csr" -CA "$4" -CAkey "$5" -set_serial "$2" -days 36500 -sha256 \
    -extfile "$W/ext.cnf" -extensions "$3" -out "$1.pem" 2>/dev/null
}

# the EC CA and its certificates
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key 2>/dev/null
"$OPENSSL" req -new -x509 -key ca.key -subj "/O=simoom/CN=Revocation Fixture CA" -days 36500 -sha256 \
  -config "$W/ext.cnf" -extensions ca -set_serial 1 -out ca.pem
issue leaf-good 0x1001 leaf ca.pem ca.key
issue leaf-revoked 0x1002 leaf ca.pem ca.key
issue leaf-unknown 0x1003 leaf ca.pem ca.key
issue responder 0x2001 responder ca.pem ca.key
issue responder-noeku 0x2002 noeku ca.pem ca.key
cp "$W/responder.key" responder.key
cp "$W/responder-noeku.key" responder-noeku.key

# openssl ca database: 0x1001 valid, 0x1002 revoked (keyCompromise); 0x1003 not listed
subj() { "$OPENSSL" x509 -in "$1" -noout -subject -nameopt compat | sed 's/^subject=//'; }
printf 'V\t21250101000000Z\t\t1001\tunknown\t%s\n' "$(subj leaf-good.pem)" > "$W/index.txt"
printf 'R\t21250101000000Z\t260101000000Z,keyCompromise\t1002\tunknown\t%s\n' "$(subj leaf-revoked.pem)" >> "$W/index.txt"
echo 01 > "$W/crlnumber"
cat > "$W/ca.cnf" <<CNF
[ca]
default_ca = d
[d]
database = $W/index.txt
crlnumber = $W/crlnumber
certificate = ca.pem
private_key = ca.key
default_md = sha256
default_crl_days = 36500
crl_extensions = crlext
[crlext]
authorityKeyIdentifier = keyid
CNF
"$OPENSSL" ca -batch -gencrl -config "$W/ca.cnf" -out crl-sha256.pem 2>/dev/null
"$OPENSSL" crl -in crl-sha256.pem -outform DER -out crl-sha256.der
"$OPENSSL" ca -batch -gencrl -config "$W/ca.cnf" -md sha1 -out "$W/crl-sha1.pem" 2>/dev/null
"$OPENSSL" crl -in "$W/crl-sha1.pem" -outform DER -out crl-ecdsa-sha1.der

# an RSA CA with a sha1WithRSAEncryption CRL revoking 0x1002
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$W/rsa-ca.key" 2>/dev/null
"$OPENSSL" req -new -x509 -key "$W/rsa-ca.key" -subj "/O=simoom/CN=Revocation Fixture RSA CA" -days 36500 -sha256 \
  -config "$W/ext.cnf" -extensions ca -set_serial 2 -out rsa-ca.pem
sed -e "s#certificate = ca.pem#certificate = rsa-ca.pem#" -e "s#private_key = ca.key#private_key = $W/rsa-ca.key#" "$W/ca.cnf" > "$W/rsa.cnf"
"$OPENSSL" ca -batch -gencrl -config "$W/rsa.cnf" -md sha1 -out "$W/rsa.pem" 2>/dev/null
"$OPENSSL" crl -in "$W/rsa.pem" -outform DER -out crl-rsa-sha1.der

# OCSP requests (with the default nonce, and one without) and responses
for s in good revoked unknown; do
  "$OPENSSL" ocsp -issuer ca.pem -cert leaf-$s.pem -reqout req-$s.der >/dev/null
  "$OPENSSL" ocsp -index "$W/index.txt" -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin req-$s.der \
    -respout resp-$s-issuer.der -ndays 36500 >/dev/null 2>&1
done
"$OPENSSL" ocsp -issuer ca.pem -cert leaf-good.pem -no_nonce -reqout req-good-nononce.der >/dev/null
"$OPENSSL" ocsp -index "$W/index.txt" -CA ca.pem -rsigner responder.pem -rkey responder.key -reqin req-good.der \
  -respout resp-good-delegated.der -ndays 36500 >/dev/null 2>&1
"$OPENSSL" ocsp -index "$W/index.txt" -CA ca.pem -rsigner responder.pem -rkey responder.key -reqin req-revoked.der \
  -respout resp-revoked-delegated.der -ndays 36500 >/dev/null 2>&1
"$OPENSSL" ocsp -index "$W/index.txt" -CA ca.pem -rsigner responder-noeku.pem -rkey responder-noeku.key -reqin req-good.der \
  -respout resp-good-noeku.der -ndays 36500 >/dev/null 2>&1
"$OPENSSL" ocsp -index "$W/index.txt" -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin req-good-nononce.der \
  -respout resp-good-nononce.der -ndays 36500 >/dev/null 2>&1
rm -f responder.key responder-noeku.key
ls -l
