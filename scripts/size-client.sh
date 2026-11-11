#!/usr/bin/env bash
# Size cost of simoom-client's cargo features: the stripped `dist` binary of
# crates/simoom-client/examples/size_get.rs per feature set, minus an empty `fn main` built the
# same way. Report only (the client has no budget of its own; scripts/size.sh holds the server
# budgets). Run on x86-64 Linux for the numbers in docs/parity/client.md.
#
#   scripts/size-client.sh
#   SIZE_MD=1 scripts/size-client.sh    # Markdown table
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET_DIR=${CARGO_TARGET_DIR:-target-size-client}
EXT=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXT=".exe" ;; esac
OUT="$TARGET_DIR/dist/examples"
size_of() { wc -c <"$1" | tr -d ' '; }
build() { CARGO_TARGET_DIR="$TARGET_DIR" cargo build -q -p simoom-client --profile dist "$@"; }

ROWS=$(cat <<LIST
client-h1 (plain HTTP/1.1)|--no-default-features --features client-h1
client-h1,tls|--no-default-features --features client-h1,tls
client-h1,tls,compress|--no-default-features --features client-h1,tls,compress
client-h1,client-h2,tls|--no-default-features --features client-h1,client-h2,tls
client-h1,client-ws,tls|--no-default-features --features client-h1,client-ws,tls
default (h1,h2,ws,tls,compress)|--features default
client-h3 (h1,h3,tls)|--no-default-features --features client-h1,client-h3
rt (h1 on event loops, tls)|--no-default-features --features client-h1,tls,rt
default,cookies|--features cookies
default,auth-digest|--features auth-digest
default,auth-ntlm|--features auth-ntlm
default,multipart|--features multipart
full|--features full
LIST
)

build --example client_empty --no-default-features
base=$(size_of "$OUT/client_empty$EXT")
if [ -n "${SIZE_MD:-}" ]; then
    printf '| features | binary | added |\n|---|---:|---:|\n| (empty fn main) | %s | - |\n' "$base"
else
    printf '%-34s %10s %10s\n' features binary added
    printf '%-34s %10s %10s\n' "(empty fn main)" "$base" -
fi
while IFS='|' read -r label args; do
    [ -z "$label" ] && continue
    # shellcheck disable=SC2086
    build --example size_get $args
    size=$(size_of "$OUT/size_get$EXT")
    if [ -n "${SIZE_MD:-}" ]; then
        printf '| %s | %s | %s |\n' "$label" "$size" "$((size - base))"
    else
        printf '%-34s %10s %10s\n' "$label" "$size" "$((size - base))"
    fi
done <<<"$ROWS"

# Marginal cost in a binary that already has the server (simoom with http1, http2, tls, http3,
# websocket, as in the dev-dependency).
build --example client_size_server
srv=$(size_of "$OUT/client_size_server$EXT")
build --example size_both
both=$(size_of "$OUT/size_both$EXT")
if [ -n "${SIZE_MD:-}" ]; then
    printf '| server alone (h1, h2, tls, h3, ws) | %s | %s |
| server + client (default features) | %s | %s (client: +%s) |
' "$srv" "$((srv - base))" "$both" "$((both - base))" "$((both - srv))"
else
    printf '%-34s %10s %10s
' "server alone" "$srv" "$((srv - base))"
    printf '%-34s %10s %10s  client adds %s
' "server + client (default)" "$both" "$((both - base))" "$((both - srv))"
fi
