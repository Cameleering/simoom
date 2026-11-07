#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/kestrel/bench-kestrel"
VERSION="echo .NET SDK $DOTNET_SDK_VERSION"
CMD=("$OPT/kestrel/bench-kestrel")
dispatch "$@"
