#!/usr/bin/env bash
# Cross-checks simoom-bench against wrk (closed loop, pipelined) and wrk2 (open loop) on one
# Linux machine, against the same server. The bar is agreement within 5% (plan §6.1).
#
#   scripts/bench-validate.sh [OUT_DIR]
#
# Environment:
#   SB        simoom-bench binary   (default target-bench/release/simoom-bench)
#   SERVER    server command line   (default: the simoom-rt raw_http example on SERVER_CPUS)
#   WRK, WRK2 paths of wrk and wrk2 (default: wrk on PATH, ~/wrk2/wrk)
#   SERVER_CPUS, GEN_CPUS   taskset lists (default 0-3 and 4-7)
#   PORT (18080), CONNS (64), THREADS (4), DUR (20), RATES ("50000 100000 200000")
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/bench/results/$(date -u +%Y-%m-%d)-validate}"
SB="${SB:-$ROOT/target-bench/release/simoom-bench}"
RAW="${RAW:-$ROOT/target-bench/release/examples/raw_http}"
WRK="${WRK:-$(command -v wrk || true)}"
WRK2="${WRK2:-$HOME/wrk2/wrk}"
SERVER_CPUS="${SERVER_CPUS:-0-3}"; GEN_CPUS="${GEN_CPUS:-4-7}"
PORT="${PORT:-18080}"; CONNS="${CONNS:-64}"; THREADS="${THREADS:-4}"; DUR="${DUR:-20}"
RATES="${RATES:-50000 100000 200000}"
# open loop: enough connections that each stays far below 1000 req/s, so wrk2's millisecond
# timers can keep every connection on schedule (its README's advice)
OPEN_CONNS="${OPEN_CONNS:-1024}"
mkdir -p "$OUT"
cpulist() { # 4-7 -> 4,5,6,7
  local a b; IFS=- read -r a b <<<"$1"; [ -n "${b:-}" ] && seq -s, "$a" "$b" || echo "$1"; }
GEN_LIST="$(cpulist "$GEN_CPUS")"
SERVER="${SERVER:-$RAW --port $PORT --threads $THREADS --secs 100000}"
URL="http://127.0.0.1:$PORT/"

taskset -c "$SERVER_CPUS" $SERVER >"$OUT/server.log" 2>&1 &
SPID=$!
trap 'kill $SPID 2>/dev/null || true' EXIT
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done

{
  echo "date: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "kernel: $(uname -r)"; echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
  echo "server: $SERVER (cpus $SERVER_CPUS); generators on cpus $GEN_CPUS; $CONNS connections, $THREADS threads, $DUR s"
  echo "wrk: $("$WRK" --version 2>&1 | head -1)"
  echo "wrk2: $(git -C "$(dirname "$WRK2")" log -1 --format='%h %cs' 2>/dev/null || echo "$WRK2")"
  echo "simoom-bench: $("$SB" version)"
} > "$OUT/machine.txt"

wrk_rps() { awk '/^Requests\/sec/ {print $2}' "$1"; }
# wrk prints latencies with units; normalize to microseconds
to_us() { awk -v v="$1" 'BEGIN{ n=v; u=v; sub(/[a-z]+$/,"",n); sub(/^[0-9.]+/,"",u); m=(u=="s")?1e6:(u=="ms")?1e3:(u=="us")?1:1e6; printf "%.1f", n*m }'; }
wrk_pct() { local v; v=$(awk -v p="$2" '$1==p {print $2; exit}' "$1"); [ -n "$v" ] && to_us "$v" || echo "-"; }
sb_field() { grep -o "$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

echo "| test | tool | req/s | p50 us | p99 us | p99.9 us | note |" > "$OUT/table.md"
echo "|---|---|---:|---:|---:|---:|---|" >> "$OUT/table.md"
row() { echo "| $1 | $2 | $3 | $4 | $5 | $6 | $7 |" >> "$OUT/table.md"; }

echo "== closed loop, keep-alive"
taskset -c "$GEN_CPUS" "$WRK" -t"$THREADS" -c"$CONNS" -d"${DUR}s" --latency "$URL" > "$OUT/wrk-closed.txt"
"$SB" load --url "$URL" --conns "$CONNS" --threads "$THREADS" --cpus "$GEN_LIST" --warmup 2 --duration "$DUR" > "$OUT/sb-closed.txt"
row closed-64 wrk "$(wrk_rps "$OUT/wrk-closed.txt")" "$(wrk_pct "$OUT/wrk-closed.txt" 50%)" "$(wrk_pct "$OUT/wrk-closed.txt" 99%)" - "wrk 4.1"
row closed-64 simoom-bench "$(sb_field "$OUT/sb-closed.txt" achieved)" "$(sb_field "$OUT/sb-closed.txt" p50_us)" "$(sb_field "$OUT/sb-closed.txt" p99_us)" "$(sb_field "$OUT/sb-closed.txt" p999_us)" "gen cpu $(sb_field "$OUT/sb-closed.txt" gen_cpu_pct)%"

echo "== pipelined, depth 16"
cat > "$OUT/pipeline.lua" <<'EOF'
init = function(args)
  local r = {}
  for i = 1, 16 do r[i] = wrk.format() end
  req = table.concat(r)
end
request = function() return req end
EOF
taskset -c "$GEN_CPUS" "$WRK" -t"$THREADS" -c"$CONNS" -d"${DUR}s" -s "$OUT/pipeline.lua" "$URL" > "$OUT/wrk-pipe16.txt"
"$SB" load --url "$URL" --conns "$CONNS" --threads "$THREADS" --cpus "$GEN_LIST" --depth 16 --batch --warmup 2 --duration "$DUR" > "$OUT/sb-pipe16.txt"
row pipelined-16 wrk "$(wrk_rps "$OUT/wrk-pipe16.txt")" - - - "lua pipeline script (wrk counts responses)"
row pipelined-16 "simoom-bench --batch" "$(sb_field "$OUT/sb-pipe16.txt" achieved)" "$(sb_field "$OUT/sb-pipe16.txt" p50_us)" "$(sb_field "$OUT/sb-pipe16.txt" p99_us)" "$(sb_field "$OUT/sb-pipe16.txt" p999_us)" "gen cpu $(sb_field "$OUT/sb-pipe16.txt" gen_cpu_pct)%"

for R in $RATES; do
  echo "== open loop at $R req/s"
  # wrk2 spends its first 10 s calibrating; give it the same measured time after that
  taskset -c "$GEN_CPUS" "$WRK2" -t"$THREADS" -c"$OPEN_CONNS" -d"$((DUR + 10))s" -R"$R" --latency "$URL" > "$OUT/wrk2-$R.txt"
  for be in epoll io_uring; do
    "$SB" load --url "$URL" --conns "$OPEN_CONNS" --threads "$THREADS" --cpus "$GEN_LIST" --rate "$R" --backend $be --warmup 2 --duration "$DUR" --out "$OUT/sb-$R-$be" > "$OUT/sb-$R-$be.txt"
  done
  # wrk2's --latency prints "50.000%  1.23ms" lines (HdrHistogram) after "Latency Distribution"
  w2() { awk -v p="$2" '/Latency Distribution \(HdrHistogram - Recorded Latency\)/ {f=1} f && $1==p {print $2; exit}' "$1"; }
  v50=$(w2 "$OUT/wrk2-$R.txt" 50.000%); v99=$(w2 "$OUT/wrk2-$R.txt" 99.000%); v999=$(w2 "$OUT/wrk2-$R.txt" 99.900%)
  row "open-$R-c$OPEN_CONNS" wrk2 "$(wrk_rps "$OUT/wrk2-$R.txt")" "$( [ -n "$v50" ] && to_us "$v50" || echo -)" "$( [ -n "$v99" ] && to_us "$v99" || echo -)" "$( [ -n "$v999" ] && to_us "$v999" || echo -)" "ms timers (epoll)"
  for be in epoll io_uring; do
    f="$OUT/sb-$R-$be.txt"
    row "open-$R-c$OPEN_CONNS" "simoom-bench ($be)" "$(sb_field "$f" achieved)" "$(sb_field "$f" p50_us)" "$(sb_field "$f" p99_us)" "$(sb_field "$f" p999_us)" "timer lag p99 $(sb_field "$f" lag_p99_us) us, gen cpu $(sb_field "$f" gen_cpu_pct)%"
  done
done
cat "$OUT/table.md"
