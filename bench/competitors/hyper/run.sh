#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-hyper"
VERSION="lock_version $COMP/hyper/Cargo.lock hyper"
CMD=("$BIN")
dispatch "$@"
