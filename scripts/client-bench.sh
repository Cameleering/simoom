#!/usr/bin/env bash
# Client benchmark (docs/parity/client.md): simoom-client against Cameleer's client, both
# closed-loop against simoom's bench_server on loopback, plus curl as a sanity check.
# Linux (WSL2) only: CPU time per request comes from /proc/self/stat.
#
#   scripts/client-bench.sh                 # default: 10 s per run, threads 1 4 16
#   SECS=5 THREADS="1 8" scripts/client-bench.sh
#
# The server runs on CPUs SERVER_CPUS (default 0-3) with 4 loops, the clients on CLIENT_CPUS
# (default 4-7), so client CPU is measured apart from the server's.
set -euo pipefail
cd "$(dirname "$0")/.."
SECS=${SECS:-10}
THREADS=${THREADS:-"1 4 16"}
PROTOS=${PROTOS:-"h1 h2c"}
ROUNDS=${ROUNDS:-2}
SERVER_CPUS=${SERVER_CPUS:-0-3}
CLIENT_CPUS=${CLIENT_CPUS:-4-7}
PORT=${PORT:-18080}
T=${CARGO_TARGET_DIR:-$HOME/simoom-target-client}
CT=${CAMELEER_TARGET_DIR:-$HOME/cameleer-client-min-target}

CARGO_TARGET_DIR="$T" cargo build -q --release -p simoom --example bench_server
CARGO_TARGET_DIR="$T" cargo build -q --release -p simoom-client --example client_bench
(cd bench/competitors/cameleer-client-min && CARGO_TARGET_DIR="$CT" cargo build -q --release)

taskset -c "$SERVER_CPUS" "$T/release/examples/bench_server" --addr 127.0.0.1 --port "$PORT" --threads 4 >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done
URL="http://127.0.0.1:$PORT/"

echo "# $(date -u +%FT%TZ) $(uname -r) $(nproc) CPUs; server CPUs $SERVER_CPUS, client CPUs $CLIENT_CPUS, $SECS s per run"
for proto in $PROTOS; do
    flag=""
    [ "$proto" = h2c ] && flag="--h2"
    for t in $THREADS; do
        for round in $(seq "$ROUNDS"); do
            taskset -c "$CLIENT_CPUS" "$T/release/examples/client_bench" --url "$URL" --threads "$t" --secs "$SECS" $flag | sed "s/^/$proto round=$round /"
            taskset -c "$CLIENT_CPUS" "$CT/release/cameleer-client-min" --url "$URL" --threads "$t" --secs "$SECS" $flag | sed "s/^/$proto round=$round /"
        done
    done
done

# curl: one process, keep-alive, sequential (a sanity check of the single-thread numbers)
N=20000
urls=$(for _ in $(seq $N); do printf '%s ' "$URL"; done)
start=$(date +%s.%N)
# shellcheck disable=SC2086
taskset -c "$CLIENT_CPUS" curl -s -o /dev/null $urls
end=$(date +%s.%N)
echo "h1 curl threads=1 requests=$N rps=$(echo "$N / ($end - $start)" | bc)"
