#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-axum"
VERSION="lock_version $COMP/axum/Cargo.lock axum"
CMD=("$BIN")
dispatch "$@"
