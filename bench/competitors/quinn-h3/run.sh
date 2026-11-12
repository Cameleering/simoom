#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$CARGO_TARGET_DIR/release/bench-quinn-h3"
VERSION="echo \"\$(lock_version $COMP/quinn-h3/Cargo.lock h3) \$(lock_version $COMP/quinn-h3/Cargo.lock quinn) \$(lock_version $COMP/quinn-h3/Cargo.lock rustls)\""
CMD=("$BIN")
dispatch "$@"
