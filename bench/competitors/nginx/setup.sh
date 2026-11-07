#!/usr/bin/env bash
# nginx from Ubuntu 24.04's package (version recorded at run time); the stock service is disabled.
. "$(dirname "$0")/../lib.sh"
apt_install nginx-light || apt_install nginx
systemctl disable --now nginx 2>/dev/null || true
ensure_cert
