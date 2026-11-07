#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/bench-fasthttp"
VERSION="$OPT/go/bin/go version $OPT/bench-fasthttp | cut -d' ' -f2; grep -h fasthttp $COMP/fasthttp/go.mod | head -1"
CMD=("$BIN")
dispatch "$@"
