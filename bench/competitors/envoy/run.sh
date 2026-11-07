#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/envoy"
VERSION="$OPT/envoy --version | tail -1"
CMD=("$OPT/envoy" -c "$COMP/envoy/envoy.yaml" --concurrency "$NPROC" --log-level warn --disable-hot-restart)
dispatch "$@"
