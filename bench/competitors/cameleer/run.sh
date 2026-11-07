#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN=/root/cameleer/target/release/cameleer
VERSION="$BIN --version"
CMD=("$BIN" run "$COMP/cameleer/fixed.camel.yaml")
dispatch "$@"
