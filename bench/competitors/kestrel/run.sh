#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
export DOTNET_ROOT="$OPT/dotnet" DOTNET_gcServer=1
BIN="$OPT/kestrel/bench-kestrel"
VERSION="echo .NET SDK $DOTNET_SDK_VERSION"
# env carries DOTNET_ROOT into the printed command (run.sh --print, used by the start-up step)
CMD=(env "DOTNET_ROOT=$OPT/dotnet" DOTNET_gcServer=1 "$OPT/kestrel/bench-kestrel")
dispatch "$@"
