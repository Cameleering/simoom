#!/usr/bin/env bash
# HAProxy from Ubuntu 24.04's package (2.8 LTS; version recorded at run time).
. "$(dirname "$0")/../lib.sh"
apt_install haproxy
systemctl disable --now haproxy 2>/dev/null || true
ensure_cert
cat "$OPT/cert/cert.pem" "$OPT/cert/key.pem" > "$OPT/cert/haproxy.pem"
