#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/caddy/caddy"
VERSION="$OPT/caddy/caddy version"
CMD=("$OPT/caddy/caddy" run --config "$COMP/caddy/Caddyfile" --adapter caddyfile)
dispatch "$@"
