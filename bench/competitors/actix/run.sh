#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-actix"
VERSION="lock_version $COMP/actix/Cargo.lock actix-web"
CMD=("$BIN")
dispatch "$@"
