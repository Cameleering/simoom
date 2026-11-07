#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/bench-go-nethttp"
VERSION="$OPT/go/bin/go version $OPT/bench-go-nethttp | cut -d' ' -f2; grep -h fasthttp $COMP/go-nethttp/go.mod | head -1"
CMD=("$BIN")
dispatch "$@"
