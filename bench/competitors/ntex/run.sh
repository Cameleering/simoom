#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-ntex"
VERSION="lock_version $COMP/ntex/Cargo.lock ntex"
CMD=("$BIN")
dispatch "$@"
