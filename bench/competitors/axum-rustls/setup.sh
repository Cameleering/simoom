#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
ensure_cert
apt_install cmake clang
rust_build "$COMP/axum-rustls" bench-axum-rustls
