#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-axum-rustls"
VERSION="echo \"\$(lock_version $COMP/axum-rustls/Cargo.lock axum) \$(lock_version $COMP/axum-rustls/Cargo.lock rustls) \$(lock_version $COMP/axum-rustls/Cargo.lock aws-lc-rs)\""
CMD=("$BIN")
dispatch "$@"
