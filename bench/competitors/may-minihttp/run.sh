#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-may-minihttp"
VERSION="lock_version $COMP/may-minihttp/Cargo.lock may_minihttp"
CMD=("$BIN")
dispatch "$@"
