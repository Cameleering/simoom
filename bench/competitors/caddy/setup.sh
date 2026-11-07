#!/usr/bin/env bash
# Caddy's official release binary, pinned and checksum-verified.
. "$(dirname "$0")/../lib.sh"
fetch "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION/caddy_${CADDY_VERSION}_linux_amd64.tar.gz" "$OPT/dl/caddy.tgz" sha256 "$CADDY_SHA256"
mkdir -p "$OPT/caddy" && tar -xzf "$OPT/dl/caddy.tgz" -C "$OPT/caddy" caddy
ensure_cert
