#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
ensure_dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
(cd "$COMP/kestrel" && "$OPT/dotnet/dotnet" publish -c Release -o "$OPT/kestrel" >/dev/null)
