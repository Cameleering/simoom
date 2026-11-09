#!/usr/bin/env bash
# Control-flow check of campaign.sh without any machine: every remote command and load run is
# logged instead of executed (DRY=1). Prints the server/scenario cells that ran per round and
# checks that every server ran in every pass.
#
#   bench/cloud/dry-run.sh                         the default passes, every server
#   PASSES="2:S1,S5 3:S1,S5" DEADLINE=... bench/cloud/dry-run.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
SERVERS="${SERVERS:-simoom simoom-uring simoom-builder simoom-builder-uring simoom-default simoom-deferred simoom-deferred-stream simoom-blocking cameleer-http-min nginx h2o haproxy envoy caddy hyper axum actix may-minihttp xitca ntex go-nethttp fasthttp netty vertx uws kestrel cameleer}"
cat > "$D/env" <<ENV
SRV_A=10.0.0.1
SRV_B=10.0.0.2
LOADS="10.0.0.11 10.0.0.12 10.0.0.13"
SERVERS="$SERVERS"
ROUNDS="${ROUNDS:-1 2 3}"
SCENARIOS="${SCENARIOS:-}"
ENV
[ -n "${PASSES:-}" ] && echo "PASSES=\"$PASSES\"" >> "$D/env"
[ -n "${DEADLINE:-}" ] && echo "DEADLINE=$DEADLINE" >> "$D/env"
DRY=1 CAMPAIGN_DIR="$D" SB=/bin/false bash "$HERE/campaign.sh" > "$D/stdout" 2>&1 || { tail -20 "$D/stdout"; exit 1; }
R="$D/out/results.txt"
echo "passes:"; grep '^ROUNDSET' "$R" | sed 's/^/  /' | cut -c1-160
echo "cells done per round:"; grep '^DONE' "$R" | awk '{print $2}' | sort | uniq -c | sed 's/^/  /'
echo "servers per round:"; grep '^DONE' "$R" | awk '{print $2, $3}' | sort -u | awk '{print $1}' | uniq -c | sed 's/^/  /'
echo "skipped: $(grep -c '^SKIPPED' "$R" || true)"
echo "VERSION lines: $(grep -c '^VERSION' "$R" || true) (one per round and server); BASE lines: $(grep -c 'idle-base; echo' "$D/out/dry.log" || true)"
echo "remote commands: $(grep -c '^DRY on' "$D/out/dry.log"), load runs: $(grep -c '^DRY sb' "$D/out/dry.log")"
echo "S1 sweeps: $(grep -c 'DRY sb sweep.*scenario=S1 ' "$D/out/dry.log"), NIC monitors: $(grep -c 'mon-begin' "$D/out/dry.log")"
echo "coldstart variants: $(grep -o 'coldstart --addr 127.0.0.1:8080 --repeat 20 -- [^ ]*' "$D/out/dry.log" | sort -u | wc -l)"
grep -h 'profile.sh' "$D/out/dry.log" || true
[ -n "${KEEP:-}" ] && cp -r "$D/out" "$KEEP"
tail -3 "$D/out/campaign.log"
