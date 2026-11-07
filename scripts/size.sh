#!/usr/bin/env bash
# Stripped binary sizes of crates/simoom/examples/hello.rs per feature set, in the `dist`
# profile (fat LTO, panic=abort, strip), against an empty `fn main` built the same way.
# Checks plan.md §0's budgets for the code simoom adds. Works on Linux and in Git Bash.
#
#   scripts/size.sh            # exit 1 if a budget is exceeded
#   CARGO_TARGET_DIR=... scripts/size.sh
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET_DIR=${CARGO_TARGET_DIR:-target-size}
EXT=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXT=".exe" ;; esac
OUT="$TARGET_DIR/dist/examples"

size_of() { wc -c <"$1" | tr -d ' '; }

build() { # name, cargo feature arguments...
    local name=$1
    shift
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build -q -p simoom --profile dist "$@"
}

build empty --example empty --no-default-features
base=$(size_of "$OUT/empty$EXT")

fail=0
printf '%-36s %10s %10s %10s  %s\n' "features" "binary" "added" "budget" "status"
printf '%-36s %10s %10s %10s  %s\n' "(empty fn main)" "$base" "-" "-" ""
while IFS='|' read -r label args budget; do
    # shellcheck disable=SC2086
    build hello --example hello $args
    size=$(size_of "$OUT/hello$EXT")
    added=$((size - base))
    if [ "$budget" = "-" ]; then
        status=""
    elif [ "$added" -le "$budget" ]; then
        status="ok"
    else
        status="OVER"
        fail=1
    fi
    printf '%-36s %10s %10s %10s  %s\n' "$label" "$size" "$added" "$budget" "$status"
done <<'LIST'
http1|--no-default-features --features http1|256000
http1,http2|--no-default-features --features http1,http2|-
http1,http2,tls|--no-default-features --features http1,http2,tls|614400
default (http1,http2,websocket)||-
full|--features full|1048576
LIST
exit $fail
