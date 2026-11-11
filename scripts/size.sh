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
#   + compression                    +65536  (64 KB on top of the build it joins)
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
# Owner decision 2026-11-09: the 1 MB budget applies to the full *server* build (HTTP/1.1, HTTP/2,
# HTTP/3, TLS, WebSocket, io_uring). Builds that add the HTTP client and every optional codec or
# keystore are reported without a budget, since each of those parts is an opt-in feature.
FULL=1048576
# The `compression` feature (gzip/deflate responses) is held to its own allowance on top of
# the build it joins: 64 KB.
H1C=$((H1 + 65536))
FULLC=$((FULL + 65536))
# Brotli also carries its static dictionary (59 KB DEFLATE-compressed): 160 KB allowance.
FULLBR=$((FULL + 163840))
# Each server helper (multipart, cookies, conditional, cors) on HTTP/1.1: 32 KB.
H1X=$((H1 + 32768))
# Authentication (Digest needs MD5, SHA-256 and SHA-512 plus HMAC) on HTTP/1.1: 64 KB.
H1A=$((H1 + 65536))

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
full (server, client and every option; report only)|--features full|-
http1,compression|--no-default-features --features http1,compression|$H1C
default,compression|--features default,compression|$FULLC
default,websocket-h2|--features default,websocket-h2|$FULL
default,h2-keepalive|--features default,h2-keepalive|$FULL
full,compression (report only)|--features full,compression|-
default,brotli|--features default,brotli|$FULLBR
default,zstd|--features default,zstd|$FULLC
default,ws-deflate|--features default,ws-deflate|$FULLC
http1,http3,websocket|--no-default-features --features http1,http3,websocket|$FULL
http3,websocket-h3|--no-default-features --features http3,websocket-h3|$FULL
http1,multipart|--no-default-features --features http1,multipart|$H1X
http1,cookies|--no-default-features --features http1,cookies|$H1X
http1,conditional|--no-default-features --features http1,conditional|$H1X
http1,cors|--no-default-features --features http1,cors|$H1X
http1,auth|--no-default-features --features http1,auth|$H1A
http1,http2,tls,tls12|--no-default-features --features http1,http2,tls,simoom-tls/tls12|$H12TLS
full,tls12 (report only)|--features full,simoom-tls/tls12|-
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
    if [ "$budget" = "-" ]; then
        status="report only"
    elif [ "$added" -le "$budget" ]; then
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

# simoom-tls optional features (report only, no budget): what each adds to a TLS server that
# uses it (crates/simoom-tls/examples/size_features.rs), over the same server without it. They
# are all off in simoom's server builds; the rows above with `tls12` show that feature inside
# simoom. Skipped with SIZE_TLS_FEATURES=0.
if [ "${SIZE_TLS_FEATURES:-1}" != 0 ] && [ $# -eq 0 ]; then
    tls_build() { CARGO_TARGET_DIR="$TARGET_DIR" cargo build -q -p simoom-tls --profile dist --no-default-features --example size_features "$@"; }
    tls_build --features rsa
    tbase=$(size_of "$OUT/size_features$EXT")
    if [ -n "${SIZE_MD:-}" ]; then
        printf '\n| simoom-tls feature (rsa server base: %s) | binary | added |\n|---|---:|---:|\n' "$tbase"
    else
        printf '\n%-30s %10s %10s\n' "simoom-tls feature" "binary" "added"
        printf '%-30s %10s %10s\n' "(TLS 1.3 server, rsa)" "$tbase" "-"
    fi
    for f in tls12 keystore pkcs12 jks revocation blocking tls12,pkcs12,jks,revocation,blocking; do
        tls_build --features "rsa,$f"
        sz=$(size_of "$OUT/size_features$EXT")
        if [ -n "${SIZE_MD:-}" ]; then
            printf '| %s | %s | %s |\n' "$f" "$sz" "$((sz - tbase))"
        else
            printf '%-30s %10s %10s\n' "+$f" "$sz" "$((sz - tbase))"
        fi
    done
fi
exit $fail
