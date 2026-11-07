#!/usr/bin/env bash
# The size gate (plan.md §0): stripped binary size of crates/simoom/examples/hello.rs per
# feature set, in the `dist` profile (fat LTO, panic=abort, strip), minus an empty `fn main`
# built the same way. Fails when a budgeted build is over its budget. CI runs it on x86-64
# Linux, where the budgets apply; on Windows (Git Bash) it reports the PE sizes.
#
#   scripts/size.sh              # every row below; exit 1 if a budget is exceeded
#   scripts/size.sh http1 full   # only the rows whose label is given
#   CARGO_TARGET_DIR=... scripts/size.sh
#   SIZE_MD=1 scripts/size.sh    # print a Markdown table
#
# Budgets (bytes added over an empty `fn main`):
#   HTTP/1.1 only                  256000  (250 KB)
#   HTTP/1.1 + HTTP/2 + TLS 1.3    614400  (600 KB)
#   everything, HTTP/3 included   1048576  (1 MB)
# A build without a budget of its own is held to the budget of the smallest budgeted build
# that contains its features.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET_DIR=${CARGO_TARGET_DIR:-target-size}
EXT=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXT=".exe" ;; esac
OUT="$TARGET_DIR/dist/examples"
H1=256000
H12TLS=614400
FULL=1048576

size_of() { wc -c <"$1" | tr -d ' '; }

build() { # cargo feature arguments...
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build -q -p simoom --profile dist "$@"
}

# label | cargo arguments | budget
ROWS=$(cat <<LIST
http1|--no-default-features --features http1|$H1
http1,io-uring|--no-default-features --features http1,io-uring|$H1
http1,websocket|--no-default-features --features http1,websocket|$H12TLS
http2|--no-default-features --features http2|$H12TLS
http1,http2|--no-default-features --features http1,http2|$H12TLS
tls,http2|--no-default-features --features tls,http2|$H12TLS
http1,http2,tls|--no-default-features --features http1,http2,tls|$H12TLS
http1,http2,tls,io-uring|--no-default-features --features http1,http2,tls,io-uring|$H12TLS
http1,http2,tls,websocket|--no-default-features --features http1,http2,tls,websocket|$FULL
http3|--no-default-features --features http3|$FULL
default|--features default|$FULL
full-server (no TLS client)|--no-default-features --features http1,http2,http3,tls,websocket,io-uring|$FULL
full|--features full|$FULL
LIST
)

build --example empty --no-default-features
base=$(size_of "$OUT/empty$EXT")

fail=0
if [ -n "${SIZE_MD:-}" ]; then
    printf '| features | binary | added | budget | status |\n|---|---:|---:|---:|---|\n'
    printf '| (empty fn main) | %s | - | - | |\n' "$base"
else
    printf '%-30s %10s %10s %10s  %s\n' "features" "binary" "added" "budget" "status"
    printf '%-30s %10s %10s %10s  %s\n' "(empty fn main)" "$base" "-" "-" ""
fi
while IFS='|' read -r label args budget; do
    [ -z "$label" ] && continue
    if [ $# -gt 0 ]; then
        want=0
        for l in "$@"; do [ "$l" = "$label" ] && want=1; done
        [ $want = 1 ] || continue
    fi
    # shellcheck disable=SC2086
    build --example hello $args
    size=$(size_of "$OUT/hello$EXT")
    added=$((size - base))
    if [ "$added" -le "$budget" ]; then
        status="ok"
    else
        status="OVER by $((added - budget))"
        fail=1
    fi
    if [ -n "${SIZE_MD:-}" ]; then
        printf '| %s | %s | %s | %s | %s |\n' "$label" "$size" "$added" "$budget" "$status"
    else
        printf '%-30s %10s %10s %10s  %s\n' "$label" "$size" "$added" "$budget" "$status"
    fi
done <<<"$ROWS"
exit $fail
