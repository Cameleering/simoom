#!/usr/bin/env bash
# Validates every simoom-bench mode on one Linux machine (WSL is fine) against simoom-server and
# nginx: HTTP/1.1, TLS 1.3 (h1 and h2), h2c, HTTP/3, a connection per request (plain, TLS full
# and resumed), large bodies, overload accounting and the slow attackers. Each mode prints its
# RESULT line; the script checks that requests succeeded (errors=0, samples > 0).
#
#   scripts/bench-modes.sh [OUT_DIR]
#
# Environment: SB, SRV (binaries; default target-bench/release/...), NGINX (default nginx on PATH,
# skipped when absent), DUR (5), PORT base (18080: +0 h1/h2c, +363 TLS and QUIC; nginx +1000).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/bench/results/$(date -u +%Y-%m-%d)-modes}"
SB="${SB:-$ROOT/target-bench/release/simoom-bench}"
SRV="${SRV:-$ROOT/target-bench/release/simoom-server}"
NGINX="${NGINX:-$(command -v nginx || true)}"
DUR="${DUR:-5}"
P="${PORT:-18080}"; PT=$((P + 363)); NP=$((P + 1000)); NPT=$((NP + 363)); NP2=$((NP + 1))
mkdir -p "$OUT"
W="$OUT/work"; mkdir -p "$W"
fail=0

# a P-256 certificate for bench.local and 127.0.0.1
if [ ! -f "$W/cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=bench.local" \
    -addext "subjectAltName=DNS:bench.local,IP:127.0.0.1" -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null
fi
CA=(--cacert "$W/cert.pem" --sni bench.local)

"$SRV" --addr 127.0.0.1:$P --tls-addr 127.0.0.1:$PT --quic-addr 127.0.0.1:$PT --cert "$W/cert.pem" --key "$W/key.pem" --threads 2 >"$W/simoom.log" 2>&1 &
SPID=$!
NPID=""
if [ -n "$NGINX" ]; then
  head -c 65536 /dev/zero | tr '\0' x > "$W/64k"; head -c 1048576 /dev/zero | tr '\0' x > "$W/1m"
  mkdir -p "$W/nginx"
  cat > "$W/nginx.conf" <<EOF
worker_processes 2;
pid $W/nginx/nginx.pid;
error_log $W/nginx/error.log warn;
daemon off;
events { worker_connections 20000; }
http {
  access_log off;
  keepalive_requests 100000000;
  keepalive_timeout 120s;
  client_body_temp_path $W/nginx/body; proxy_temp_path $W/nginx/proxy; fastcgi_temp_path $W/nginx/fcgi;
  uwsgi_temp_path $W/nginx/uwsgi; scgi_temp_path $W/nginx/scgi;
  server {
    listen 127.0.0.1:$NP;
    listen 127.0.0.1:$NP2 http2;
    listen 127.0.0.1:$NPT ssl http2;
    ssl_certificate $W/cert.pem; ssl_certificate_key $W/key.pem; ssl_protocols TLSv1.3;
    location = /64k { alias $W/64k; }
    location = /1m { alias $W/1m; }
    location / { default_type text/plain; return 200 "Hello, World!"; }
  }
}
EOF
  "$NGINX" -p "$W/nginx" -c "$W/nginx.conf" >"$W/nginx.log" 2>&1 &
  NPID=$!
fi
trap 'kill $SPID $NPID 2>/dev/null' EXIT
sleep 1

run() { # run NAME ARGS...
  local name=$1; shift
  local line
  line=$("$SB" load --threads 2 --warmup 1 --duration "$DUR" "$@" --label "mode=$name" 2>"$W/$name.err" | grep '^RESULT')
  echo "$line" >> "$OUT/results.txt"
  local err samples
  err=$(grep -o ' errors=[0-9]*' <<<"$line" | cut -d= -f2); samples=$(grep -o ' samples=[0-9]*' <<<"$line" | cut -d= -f2)
  if [ -z "$line" ] || [ "${err:-1}" != 0 ] || [ "${samples:-0}" = 0 ]; then
    echo "FAIL $name: ${line:-no result}"; tail -3 "$W/$name.err"; fail=1
  else
    echo "ok   $name: $(grep -oE '(achieved|p99_us|goodput|ok_p99_us|connects|mbit_in)=[^ ]*' <<<"$line" | tr '\n' ' ')"
  fi
}

: > "$OUT/results.txt"
for side in simoom nginx; do
  if [ $side = simoom ]; then h=127.0.0.1:$P; t=127.0.0.1:$PT; c=127.0.0.1:$P; else [ -n "$NPID" ] || continue; h=127.0.0.1:$NP; t=127.0.0.1:$NPT; c=127.0.0.1:$NP2; fi
  run $side-h1-closed --url http://$h/ --conns 32
  run $side-h1-open --url http://$h/ --conns 32 --rate 20000
  run $side-h1-tls --url https://$t/ --conns 32 --rate 20000 "${CA[@]}"
  run $side-h2-tls --url https://$t/ --proto h2 --depth 10 --conns 8 --rate 20000 "${CA[@]}"
  run $side-h2c --url http://$c/ --proto h2c --depth 10 --conns 8 --rate 20000
  run $side-s4-64k --url http://$h/64k --conns 16 --rate 2000
  run $side-s4-1m --url http://$h/1m --conns 8 --rate 200
  run $side-s4-1m-tls --url https://$t/1m --conns 8 --rate 200 "${CA[@]}"
  run $side-s5-plain --url http://$h/ --new-conn --conns 16 --rate 2000
  run $side-s5-closed --url http://$h/ --new-conn --conns 16
  run $side-s7-full --url https://$t/ --new-conn --conns 16 "${CA[@]}"
  run $side-s7-resumed --url https://$t/ --new-conn --conns 16 --tls-resume "${CA[@]}"
  run $side-s9-overload --url http://$h/ --conns 256 --rate 400000
done
run simoom-h3-open --url https://127.0.0.1:$PT/ --proto h3 --conns 8 --depth 4 --rate 5000 "${CA[@]}"
run simoom-h3-closed --url https://127.0.0.1:$PT/ --proto h3 --conns 8 --depth 4 "${CA[@]}"
run simoom-h3-1m --url https://127.0.0.1:$PT/1m --proto h3 --conns 2 --rate 20 "${CA[@]}"

echo "== S10: 2000 slowloris + 200 slow readers against simoom while measuring"
"$SB" attack --addr 127.0.0.1:$P --slowloris 2000 --slowread 200 --path /64k --interval-s 5 --duration $((DUR + 6)) --label side=simoom > "$W/attack.txt" 2>"$W/attack.err" &
APID=$!
sleep 3
run simoom-s10-legit --url http://127.0.0.1:$P/ --conns 32 --rate 10000
wait $APID; cat "$W/attack.txt" | tee -a "$OUT/results.txt"
[ $fail = 0 ] && echo "ALL MODES OK" || echo "SOME MODES FAILED"
exit $fail
