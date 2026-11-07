#!/usr/bin/env bash
# Envoy's official static binary, pinned and checksum-verified.
. "$(dirname "$0")/../lib.sh"
fetch "https://github.com/envoyproxy/envoy/releases/download/v$ENVOY_VERSION/envoy-$ENVOY_VERSION-linux-x86_64" "$OPT/dl/envoy-$ENVOY_VERSION" sha256 "$ENVOY_SHA256"
install -m 0755 "$OPT/dl/envoy-$ENVOY_VERSION" "$OPT/envoy"
ensure_cert
