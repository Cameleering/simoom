#!/usr/bin/env bash
# Local (WSL2) like-for-like start-up and idle memory, plain and TLS, 10 alternating rounds:
# simoom min_server (default features; --features tls) against cameleer-http-min.
set -uo pipefail
cd /mnt/e/Work/DataHQ/Code/simoom
T=$HOME/simoom-target-2; TT=$HOME/simoom-target-4; CT=$HOME/simoom-target-3
CARGO_TARGET_DIR=$TT cargo build -q --release -p simoom --features tls --example min_server || exit 1
D=/tmp/c3cert; mkdir -p $D
[ -f $D/cert.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=bench.local" -addext "subjectAltName=DNS:bench.local" -keyout $D/key.pem -out $D/cert.pem 2>/dev/null
SB=$T/release/simoom-bench
pss() { awk '/^Pss:/ {print $2}' /proc/$1/smaps_rollup; }
TLS="--tls-addr 127.0.0.1:18443 --cert $D/cert.pem --key $D/key.pem"
for round in $(seq 10); do
  for v in "plain|min_server|$T/release/examples/min_server --addr 127.0.0.1:18099" \
           "plain|cameleer-http-min|$CT/release/cameleer-http-min --addr 127.0.0.1:18099" \
           "tls|min_server-tls|$TT/release/examples/min_server --addr 127.0.0.1:18099 $TLS" \
           "tls|cameleer-http-min-tls|$CT/release/cameleer-http-min --addr 127.0.0.1:18099 $TLS"; do
    k=${v%%|*}; r=${v#*|}; n=${r%%|*}; c=${r#*|}
    cs=$($SB coldstart --addr 127.0.0.1:18099 --repeat 20 -- $c 2>&1 | grep -o 'median_ms=[0-9.]*')
    $c >/dev/null 2>&1 & p=$!
    for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:18099/ && break; sleep 0.05; done
    [ $k = tls ] && curl -s --cacert $D/cert.pem -o /dev/null --resolve bench.local:18443:127.0.0.1 https://bench.local:18443/
    sleep 1; echo "LOCAL2 round=$round kind=$k variant=$n $cs idle_pss_kb=$(pss $p) rss_kb=$(awk '/^VmRSS/ {print $2}' /proc/$p/status)"
    kill $p; wait $p 2>/dev/null
  done
done
echo LOCAL2 DONE
