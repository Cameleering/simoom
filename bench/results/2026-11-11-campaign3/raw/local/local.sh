#!/usr/bin/env bash
# Local (WSL2) same-machine checks for campaign 3: cold start and idle PSS of min_server against
# cameleer-http-min, then scripts/client-bench.sh. Builds in the shared slots only.
set -uo pipefail
cd /mnt/e/Work/DataHQ/Code/simoom
T=$HOME/simoom-target-2; CT=$HOME/simoom-target-3
OUT=${OUT:-/tmp/c3-local}; mkdir -p $OUT
echo "build $(date -u +%T)"
CARGO_TARGET_DIR=$T cargo build -q --release -p simoom-bench || exit 1
CARGO_TARGET_DIR=$T cargo build -q --release -p simoom --example min_server --example bench_server || exit 1
CARGO_TARGET_DIR=$T cargo build -q --release -p simoom-client --example client_bench || exit 1
(cd bench/competitors/cameleer-http-min && CARGO_TARGET_DIR=$CT cargo build -q --release --locked) || exit 1
(cd bench/competitors/cameleer-client-min && CARGO_TARGET_DIR=$CT cargo build -q --release) || exit 1
echo "built $(date -u +%T)"
SB=$T/release/simoom-bench
pss() { awk '/^Pss:/ {print $2}' /proc/$1/smaps_rollup; }
for round in 1 2 3; do
  for v in "min_server|$T/release/examples/min_server --addr 127.0.0.1:18099" "cameleer-http-min|$CT/release/cameleer-http-min --addr 127.0.0.1:18099"; do
    n=${v%%|*}; c=${v#*|}
    $SB coldstart --addr 127.0.0.1:18099 --repeat 40 -- $c 2>&1 | grep -E '^COLDSTART' | sed "s/^/LOCAL round=$round variant=$n /"
    $c >/dev/null 2>&1 & p=$!
    for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:18099/ && break; sleep 0.05; done
    sleep 1; echo "LOCAL round=$round variant=$n idle_pss_kb=$(pss $p)"
    kill $p; wait $p 2>/dev/null
  done
done | tee $OUT/cold.txt
echo "client $(date -u +%T)"
CARGO_TARGET_DIR=$T CAMELEER_TARGET_DIR=$CT SECS=10 THREADS="1 4 16" ROUNDS=3 SERVER_CPUS=0-3 CLIENT_CPUS=4-7 bash scripts/client-bench.sh 2>&1 | tee $OUT/client.txt
echo "LOCAL DONE $(date -u +%T)"
