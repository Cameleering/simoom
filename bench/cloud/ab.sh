#!/usr/bin/env bash
# Same-droplet A/B of server variants (the K12/K13 fix round): one server droplet, two or more load
# nodes, every variant measured on the same droplet, rounds interleaving the variants. Runs ON
# load1 (like campaign.sh), from /root/ab/env:
#   SRV      private IP of the server droplet          SRVNAME  its name (srvA)
#   LOADS    private IPs of the load nodes (agents on :7070)
#   SPEC     the variant file (default /root/ab/spec), one line per variant:
#              LABEL SERVER SCENARIOS [VAR=VALUE ...]
#            SERVER is a bench/competitors directory; SCENARIOS a comma list of
#              S1    SLO search at 64, 256 and 1024 connections (campaign 3's lane settings)
#              S1R   SLO search at 256 connections only
#              S9    1024 connections at S9_RATE req/s (195000), 30 s
#              MP    256 connections at MP_RATE req/s for 15 s with per-CPU mpstat on the server
#              S3 S5 S7 S8 CPU   as in campaign.sh (S7: full and resumed handshakes, S1 over TLS;
#                    CPU: CPU time per request at 50k req/s, a RESULT line with metric=1)
#            VAR=VALUE pairs go to the server's environment (server.sh passes SIMOOM_* on), for
#            example SIMOOM_EXTRA="--no-balance --stats-s 5" (quote values with spaces).
#   ROUNDS   rounds (default "1 2"); each round runs every line of SPEC in order
# Output: /root/ab/out/results.txt (RESULT, SLO, STATS and MPSTAT lines tagged round= srv=
# variant= server=), progress.txt, run.log. A DONE line per (round, variant) makes a restart resume.
set -uo pipefail
ulimit -n 1048576 2>/dev/null || ulimit -n 65536
A=${AB_DIR:-/root/ab}
. $A/env
OUT=$A/out; mkdir -p $OUT/hdr
RES=$OUT/results.txt; touch $RES
SPEC=${SPEC:-$A/spec}
ROUNDS=${ROUNDS:-1 2}
S9_RATE=${S9_RATE:-195000}
MP_RATE=${MP_RATE:-130000}
SB=/root/simoom/target/release/simoom-bench
SRVSH=/root/simoom/bench/competitors/server.sh
HINTS=/root/simoom/bench/cloud/hints.txt
CA=(--cacert /root/bench-ca.pem --sni bench.local)
AGENTS="$(for l in $LOADS; do printf '%s:7070,' "$l"; done)"; AGENTS="${AGENTS%,}"
SSH=(ssh -i $A/key -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$A/known_hosts -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30)
on() { local h=$1; shift; "${SSH[@]}" "root@$h" "$@"; }
log() { printf '==> %s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a $OUT/ab.log >&2; }
sb() { $SB "$@" 2>>$OUT/run.log; }
rec() { sed -u "s/^\(RESULT\|SLO\|STATS\|MPSTAT\|FAILED\|VERSION\) /\1 $1 /" | grep -E '^(RESULT|SLO|STATS|MPSTAT|FAILED|VERSION) ' | tee -a $RES; }
# campaign 3's lane settings: SWEEP_ONE at 64 and 1024 connections, SWEEP_LONG at 256
SWEEP_LONG="--probe 3 --step-warmup 2 --step 5 --steps 5 --precision 0.04 --point-warmup 3 --point 20 --points 0.5,0.8,0.95,1,1"
SWEEP_ONE="--probe 3 --step-warmup 2 --step 5 --steps 5 --precision 0.04 --point-warmup 3 --point 15 --points 0.9,1"
hint() { # hint SERVER CONNS: this run's earlier SLO for the variant's server, else hints.txt
  local m=$1; case $m in simoom*) m=simoom ;; esac
  local v; v=$(awk -v s="$m" -v c="$2" '$1==s && $2=="S1" && $3==c {print $4}' $HINTS | tail -1)
  [ -n "$v" ] && echo "--hint $v"
}
url="http://$SRV:8080/"
for r in $ROUNDS; do
  while read -r label server scen envs <&3; do
    case "$label" in ''|'#'*) continue ;; esac
    grep -q "^DONE round=$r variant=$label\$" $RES && continue
    tag="round=$r srv=$SRVNAME variant=$label server=$server"
    log "round $r: $label ($server: $scen) $envs"
    t0=$(on "$SRV" 'date +%s')
    if ! on "$SRV" "$SRVSH stop >/dev/null 2>&1; $envs $SRVSH start $server" >>$OUT/run.log 2>&1; then
      echo "FAILED step=start" | rec "$tag"; echo "DONE round=$r variant=$label" >> $RES; continue
    fi
    echo "VERSION $(on "$SRV" "$envs $SRVSH version $server" | tr '\n' ' ') env=$(echo $envs | tr ' ' ',')" | rec "$tag"
    sb load --url "$url" --conns 256 --agents "$AGENTS" --warmup 0 --duration 15 >/dev/null  # warm
    for s in $(echo "$scen" | tr ',' ' '); do
      case $s in
        S1|S1R)
          cl="64 256 1024"; [ $s = S1R ] && cl=256
          for c in $cl; do
            plan="$SWEEP_ONE"; [ $c = 256 ] && plan="$SWEEP_LONG"
            sb sweep --url "$url" --conns $c --agents "$AGENTS" $plan $(hint "$server" $c) --label "$tag scenario=S1 conns=$c" --out $OUT/hdr/r$r-$label-S1-c$c | rec ""
          done ;;
        S3)
          sb sweep --url "http://$SRV:8080/echo" --body-size 1024 --conns 256 --agents "$AGENTS" $SWEEP_ONE --hint 150000 --label "$tag scenario=S3 conns=256" | rec "" ;;
        S5)
          sb sweep --url "$url" --new-conn --conns 192 --agents "$AGENTS" $SWEEP_ONE --hint 22000 --slo-us 5000 --label "$tag scenario=S5 conns=192" | rec "" ;;
        S7)
          sb load --url "https://$SRV:8443/" "${CA[@]}" --new-conn --conns 192 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S7 kind=full conns=192 phase=closed" | rec ""
          sb load --url "https://$SRV:8443/" "${CA[@]}" --new-conn --tls-resume --conns 192 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S7 kind=resumed conns=192 phase=closed" | rec ""
          sb sweep --url "https://$SRV:8443/" "${CA[@]}" --conns 256 --agents "$AGENTS" $SWEEP_ONE --hint 150000 --label "$tag scenario=S7 kind=S1-tls conns=256" | rec "" ;;
        S8)
          sb sweep --url "$url" --proto h2c --depth 100 --conns 64 --agents "$AGENTS" $SWEEP_ONE --hint 150000 --slo-us 5000 --label "$tag scenario=S8 conns=64 streams=100" | rec "" ;;
        CPU)
          on "$SRV" "bash /root/simoom/bench/cloud/node.sh cost-begin 15 6"
          sb load --url "$url" --conns 256 --rate 50000 --agents "$AGENTS" --warmup 4 --duration 15 --label "$tag scenario=cpufix conns=256" > $A/cpu.txt
          rec "" < $A/cpu.txt >/dev/null
          recv=$(grep -o 'received=[0-9]*' $A/cpu.txt | cut -d= -f2); sleep 3
          on "$SRV" "bash /root/simoom/bench/cloud/node.sh cost-end $server 256 ${recv:-0} 15 19" | sed 's/^METRIC /RESULT scenario=cpufix metric=1 /' | rec "$tag" ;;
        S9)
          sb load --url "$url" --conns 1024 --rate $S9_RATE --agents "$AGENTS" --warmup 5 --duration 30 --label "$tag scenario=S9 conns=1024 offered=abs" | rec "" ;;
        MP)
          on "$SRV" "nohup bash -c 'sleep 5; mpstat -P ALL 10 1' > /root/mpstat.txt 2>&1 < /dev/null &"
          sb load --url "$url" --conns 256 --rate $MP_RATE --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=MP conns=256" | rec ""
          sleep 1
          on "$SRV" "awk '/^Average:/ && \$2 != \"CPU\" {printf \"MPSTAT cpu=%s usr=%s sys=%s soft=%s steal=%s idle=%s\\n\", \$2, \$3, \$5, \$8, \$9, \$12}' /root/mpstat.txt" | rec "$tag" ;;
      esac
    done
    on "$SRV" "journalctl -u bench-server --since @$t0 -o cat 2>/dev/null | grep '^STATS' | tail -n 40" | rec "$tag"
    on "$SRV" "$SRVSH stop" >/dev/null 2>&1
    echo "DONE round=$r variant=$label" >> $RES
    echo "$(date -u +%FT%TZ) round=$r variant=$label" >> $OUT/progress.txt
  done 3< "$SPEC"
done
log "ab done"
echo "AB DONE $(date -u +%FT%TZ)" >> $OUT/ab.log
