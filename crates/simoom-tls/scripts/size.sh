#!/usr/bin/env bash
# Size that simoom-tls adds to a stripped `dist` binary (plan §0), per feature combination:
# examples/size_server.rs (a TLS 1.3 server) against examples/size_empty.rs (the same file and
# stdin/stdout handling without TLS),
# both built with the workspace `dist` profile (fat LTO, panic=abort, strip). Run it on Linux
# (WSL) for the numbers plan §0 budgets; it also works in Git Bash.
#
#   crates/simoom-tls/scripts/size.sh [feature-set ...]
#   CARGO_TARGET_DIR=... crates/simoom-tls/scripts/size.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."
TARGET_DIR=${CARGO_TARGET_DIR:-target-tls-size}
EXT=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXT=".exe" ;; esac
OUT="$TARGET_DIR/dist/examples"
size_of() { wc -c <"$1" | tr -d ' '; }
build() { CARGO_TARGET_DIR="$TARGET_DIR" cargo build -q -p simoom-tls --profile dist "$@"; }

build --no-default-features --example size_empty
base=$(size_of "$OUT/size_empty$EXT")
if [ $# -gt 0 ]; then sets=("$@"); else
    # every combination of the four algorithm features (server only), then the default with the client
    sets=(
        "rsa,p384,ed25519,chacha20"
        "rsa,p384,ed25519"
        "rsa,p384,chacha20"
        "rsa,ed25519,chacha20"
        "p384,ed25519,chacha20"
        "rsa,p384"
        "rsa,ed25519"
        "rsa,chacha20"
        "p384,ed25519"
        "p384,chacha20"
        "ed25519,chacha20"
        "rsa"
        "p384"
        "ed25519"
        "chacha20"
        ""
        "rsa,p384,ed25519,chacha20,client"
    )
fi
printf '%-40s %10s %10s\n' "features (server only unless client)" "binary" "added"
printf '%-40s %10s %10s\n' "(size_empty: same I/O, no TLS)" "$base" "-"
for f in "${sets[@]}"; do
    build --no-default-features --features "$f" --example size_server
    s=$(size_of "$OUT/size_server$EXT")
    printf '%-40s %10s %10s\n' "${f:-(none: X25519, P-256, AES-GCM)}" "$s" "$((s - base))"
done
