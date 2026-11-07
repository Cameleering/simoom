#!/usr/bin/env bash
# Throughput of the facade (crates/simoom/examples/bench_server.rs) against simoom-rt's raw
# responder (crates/simoom-rt/examples/raw_http.rs), both measured with simoom-rt's closed-loop
# load generator, alternating, several rounds. Linux or Git Bash.
#
#   scripts/bench-facade.sh [backend] [rounds] [secs]      backend: auto|epoll|io_uring|iocp
#   env: SERVER_THREADS (4) LOAD_THREADS (4) CONNS (256) PIPELINE (1) MODES ("raw fixed builder")
set -euo pipefail
cd "$(dirname "$0")/.."
BACKEND=${1:-auto}
ROUNDS=${2:-3}
SECS=${3:-10}
ST=${SERVER_THREADS:-4}
LT=${LOAD_THREADS:-4}
CONNS=${CONNS:-256}
PIPE=${PIPELINE:-1}
MODES=${MODES:-"raw fixed builder"}
TD=${CARGO_TARGET_DIR:-target}
EXT=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXT=".exe" ;; esac
cargo build -q --release -p simoom --example bench_server
cargo build -q --release -p simoom-rt --example raw_http --example loadgen
BIN="$TD/release/examples"
PORT=18900
for r in $(seq 1 "$ROUNDS"); do
    for m in $MODES; do
        PORT=$((PORT + 1))
        if [ "$m" = raw ]; then
            "$BIN/raw_http$EXT" --port "$PORT" --threads "$ST" --secs $((SECS + 4)) --backend "$BACKEND" >/dev/null 2>&1 &
        else
            "$BIN/bench_server$EXT" --port "$PORT" --threads "$ST" --secs $((SECS + 4)) --backend "$BACKEND" --mode "$m" >/dev/null 2>&1 &
        fi
        srv=$!
        sleep 1
        out=$("$BIN/loadgen$EXT" --addr "127.0.0.1:$PORT" --conns "$CONNS" --threads "$LT" --secs "$SECS" --pipeline "$PIPE" 2>&1 | tail -1)
        echo "round $r $m: $out"
        wait $srv 2>/dev/null || true
    done
done
