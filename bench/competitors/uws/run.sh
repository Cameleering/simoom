#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/node/bin/node"
VERSION="echo uWebSockets.js $UWS_TAG; $OPT/node/bin/node --version"
CMD=("$OPT/node/bin/node" "$COMP/uws/server.mjs")
dispatch "$@"
