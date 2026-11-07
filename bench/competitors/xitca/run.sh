#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-xitca"
VERSION="lock_version $COMP/xitca/Cargo.lock xitca-web"
CMD=("$BIN")
dispatch "$@"
