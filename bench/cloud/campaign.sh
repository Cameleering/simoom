#!/usr/bin/env bash
# The full benchmark campaign (plan §6.2), run ON load1 so it survives the operator's session.
# Two server droplets alternate between rounds; load1..3 run simoom-bench agents and load1 also
# coordinates. Every record line goes to $OUT/results.txt with round= and srv= fields; a DONE line
# per (round, server, scenario) makes a restarted campaign skip what is finished.
#
#   campaign.sh                      run everything not yet DONE
#   ROUNDS="1" SERVERS="simoom nginx" SCENARIOS="S1 S5" campaign.sh
#
# Environment (written by campaign-ctl.sh into /root/campaign/env):
#   SRV_A, SRV_B       private IPs of the two server droplets (round 1, 3 on A; 2 on B)
#   LOADS              private IPs of load1 load2 load3
#   SERVERS            competitors, in order
#   ROUNDS             (1 2 3)
#   SCENARIOS_R1       scenarios of round 1 (all), SCENARIOS_RN those of rounds 2 and 3
set -uo pipefail
ulimit -n 1048576 2>/dev/null || ulimit -n 65536
C=/root/campaign
. $C/env
OUT=$C/out
mkdir -p $OUT/hdr $OUT/prof
RES=$OUT/results.txt
touch $RES
SB=/root/simoom/target/release/simoom-bench
SRVSH=/root/simoom/bench/competitors/server.sh
NODE="bash /root/simoom/bench/cloud/node.sh"
CA=(--cacert /root/bench-ca.pem --sni bench.local)
AGENTS="$(for l in $LOADS; do printf '%s:7070,' "$l"; done)"; AGENTS="${AGENTS%,}"
read -r -a LOADA <<<"$LOADS"
SSH=(ssh -i $C/key -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$C/known_hosts -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30)
on() { local h=$1; shift; "${SSH[@]}" "root@$h" "$@"; }
log() { printf '==> %s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a $OUT/campaign.log >&2; }
# search: short steps; points: 5 x 30 s (50, 80, 95, 100, 100% of the SLO throughput)
SWEEP_LONG="--probe 4 --step-warmup 2 --step 6 --steps 7 --point-warmup 5 --point 20 --points 0.5,0.8,0.95,1,1"
SWEEP_SHORT="--probe 3 --step-warmup 2 --step 5 --steps 6 --point-warmup 3 --point 10 --points 0.5,0.95"
ROUNDS="${ROUNDS:-1 2 3}"
SCENARIOS_R1="${SCENARIOS_R1:-S1 S3 S4 S5 S6 S7 S8 S9 S10 H3 COLD}"
SCENARIOS_RN="${SCENARIOS_RN:-S1 S5}"
# rounds 2 and 3 repeat the headline scenarios on the simoom variants and the TOPN best other
# servers of round 1 (by S1 SLO throughput at 256 connections) plus nginx
TOPN="${TOPN:-8}"

# capabilities: echo s4 tls h2c-port h3 (from the competitor configs)
caps() {
  case "$1" in
    simoom*) echo "echo s4 tls h2c:8080 h3" ;;
    nginx) echo "s4 tls h2c:8081 h3?" ;;
    h2o) echo "s4 tls h2c:8080 h3" ;;
    haproxy) echo "tls h2c:8081" ;;
    envoy) echo "h2c:8080" ;;
    caddy) echo "s4 tls h2c:8080 h3" ;;
    go-nethttp) echo "echo s4 tls h2c:8080" ;;
    hyper|axum|actix) echo "echo s4 h2c:8080" ;;
    xitca) echo "" ;;
    vertx) echo "echo h2c:8080" ;;
    may-minihttp|fasthttp) echo "echo" ;;
    kestrel) echo "echo h2c:8081" ;;
    ntex|netty|uws|cameleer) echo "echo" ;;
    *) echo "" ;;
  esac
}
has() { case " $(caps "$1") " in *" $2 "*) return 0 ;; esac; return 1; }
h2cport() { caps "$1" | tr ' ' '\n' | awk -F: '$1=="h2c" {print $2}'; }

done_mark() { grep -q "^DONE round=$1 server=$2 scenario=$3\$" $RES; }
mark() { echo "DONE round=$1 server=$2 scenario=$3" >> $RES; }
rec() { # rec PREFIX: tag record lines from stdin and append them
  if [ -z "$1" ]; then grep -E '^(RESULT|SLO|METRIC|NIC|PEAK|BASE|IDLE|COLDSTART|SIZE|VERSION|ATTACK|SKIPPED|FAILED|PROFILE) ' | tee -a $RES; return; fi
  sed -u "s/^\(RESULT\|SLO\|METRIC\|NIC\|PEAK\|BASE\|IDLE\|COLDSTART\|SIZE\|VERSION\|ATTACK\|SKIPPED\|FAILED\|PROFILE\) /\1 $1 /" | grep -E '^(RESULT|SLO|METRIC|NIC|PEAK|BASE|IDLE|COLDSTART|SIZE|VERSION|ATTACK|SKIPPED|FAILED|PROFILE) ' | tee -a $RES
}
sb() { $SB "$@" 2>>$OUT/run.log; }
slo_of() { # slo_of ROUND SERVER SCENARIO CONNS -> last SLO rate of that cell (any round as fallback)
  local v
  v=$(grep "^SLO round=$1 srv=[^ ]* server=$2 scenario=$3 conns=$4 " $RES | grep -o 'slo_rps=[0-9]*' | tail -1 | cut -d= -f2)
  [ -z "$v" ] && v=$(grep " server=$2 scenario=$3 conns=$4 " $RES | grep '^SLO' | grep -o 'slo_rps=[0-9]*' | tail -1 | cut -d= -f2)
  echo "${v:-0}"
}

machine() { # machine NAME HOST
  on "$2" 'bash -s' <<'EOF' | sed "s/^/$1 /"
echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "vcpus: $(nproc)"
echo "ram: $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
echo "os: $(. /etc/os-release && echo "$PRETTY_NAME") kernel $(uname -r)"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
for k in net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.core.busy_poll net.core.busy_read net.ipv4.ip_local_port_range net.core.netdev_max_backlog net.ipv4.tcp_tw_reuse; do echo "sysctl $k = $(sysctl -n $k | tr '\t' ' ')"; done
echo "nic: $(ip -o -4 addr show | awk '{print $2, $4}' | tr '\n' ' ') driver $(ethtool -i eth1 2>/dev/null | awk '/^driver/ {print $2}')"
echo "io_uring_disabled: $(sysctl -n kernel.io_uring_disabled 2>/dev/null || echo n/a)"
echo "perf: $(perf stat -e cycles -x, true 2>&1 | head -1)"
echo "nginx: $(nginx -V 2>&1 | grep -o 'http_v3_module' || echo no-http3)"
EOF
}

server_start() { # server_start HOST NAME
  on "$1" "$SRVSH stop >/dev/null 2>&1; $SRVSH start $2"
}

warm() { # 15 s of closed-loop load before a server's first measurement
  sb load --url "http://$1:8080/" --conns 256 --agents "$AGENTS" --warmup 0 --duration 15 >/dev/null
}

run_server() { # run_server ROUND HOST SRVNAME NAME SCENARIOS
  local r=$1 S=$2 sv=$3 n=$4 scen=$5 tag="round=$1 srv=$3 server=$4"
  local all=1
  for s in $scen; do done_mark "$r" "$n" "$s" || all=0; done
  [ $all = 1 ] && return 0
  log "round $r on $sv: $n ($scen)"
  if ! on "$S" "b=\$($SRVSH binary $n 2>/dev/null); [ -n \"\$b\" ] && [ -x \"\$b\" ]"; then
    echo "SKIPPED reason=setup-failed" | rec "$tag"; for s in $scen; do mark "$r" "$n" "$s"; done; return 0
  fi
  echo "VERSION $(on "$S" "$SRVSH version $n" | tr '\n' ' ')" | rec "$tag"
  if ! server_start "$S" "$n" >>$OUT/run.log 2>&1; then
    echo "FAILED step=start" | rec "$tag"; for s in $scen; do mark "$r" "$n" "$s"; done; return 0
  fi
  on "$S" "$NODE idle-base; echo \"BASE pss_kb=\$(cat /root/node/pss0) mem_kb=\$($SRVSH mem | cut -d' ' -f1)\"" | rec "$tag"
  on "$S" "$NODE pss-begin"
  warm "$S"
  local url="http://$S:8080/"
  for s in $scen; do
    done_mark "$r" "$n" "$s" && continue
    log "  $n $s"
    case $s in
      S1)
        for c in 64 256 1024; do
          local plan="$SWEEP_SHORT"; [ $c = 256 ] && plan="$SWEEP_LONG"
          sb sweep --url "$url" --conns $c --agents "$AGENTS" $plan --label "$tag scenario=S1 conns=$c" --out $OUT/hdr/r$r-$n-S1-c$c | rec ""
        done
        # cost per request at 80% of the SLO throughput, 256 connections; NIC packets/s alongside
        local slo; slo=$(slo_of "$r" "$n" S1 256)
        if [ "$slo" -gt 0 ]; then
          local rate=$((slo * 8 / 10)) secs=15 warm=4
          on "$S" "$NODE sar-begin r$r-$n $((secs + warm + 8)); $NODE cost-begin $secs $((warm + 2))"
          $NODE sar-begin r$r-$n $((secs + warm + 8))
          sb load --url "$url" --conns 256 --rate $rate --agents "$AGENTS" --warmup $warm --duration $secs --label "$tag scenario=cost conns=256" > $C/cost.txt
          rec "" < $C/cost.txt >/dev/null
          local recv; recv=$(grep -o 'received=[0-9]*' $C/cost.txt | cut -d= -f2)
          sleep 3
          on "$S" "$NODE cost-end $n 256 ${recv:-0} $secs $((secs + warm))" | rec "$tag"
          sleep 5
          on "$S" "$NODE nic r$r-$n 'node=srv'" | rec "$tag"
          $NODE nic r$r-$n 'node=load1' | rec "$tag"
        fi ;;
      S3)
        if has "$n" echo; then
          sb sweep --url "http://$S:8080/echo" --body-size 1024 --conns 256 --agents "$AGENTS" $SWEEP_SHORT --label "$tag scenario=S3 conns=256" --out $OUT/hdr/r$r-$n-S3 | rec ""
        fi ;;
      S4)
        if has "$n" s4; then
          sb sweep --url "http://$S:8080/64k" --conns 64 --agents "$AGENTS" $SWEEP_SHORT --slo-us 5000 --label "$tag scenario=S4 size=64k conns=64" --out $OUT/hdr/r$r-$n-S4-64k | rec ""
          sb load --url "http://$S:8080/1m" --conns 64 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S4 size=1m conns=64 phase=closed" | rec ""
          if has "$n" tls; then
            sb load --url "https://$S:8443/1m" "${CA[@]}" --conns 64 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S4 size=1m-tls conns=64 phase=closed" | rec ""
          fi
        fi ;;
      S5)
        sb sweep --url "$url" --new-conn --conns 192 --agents "$AGENTS" $SWEEP_SHORT --slo-us 5000 --label "$tag scenario=S5 conns=192" --out $OUT/hdr/r$r-$n-S5 | rec "" ;;
      S7)
        if has "$n" tls; then
          sb load --url "https://$S:8443/" "${CA[@]}" --new-conn --conns 192 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S7 kind=full conns=192 phase=closed" | rec ""
          sb load --url "https://$S:8443/" "${CA[@]}" --new-conn --tls-resume --conns 192 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S7 kind=resumed conns=192 phase=closed" | rec ""
          sb sweep --url "https://$S:8443/" "${CA[@]}" --conns 256 --agents "$AGENTS" $SWEEP_SHORT --label "$tag scenario=S7 kind=S1-tls conns=256" --out $OUT/hdr/r$r-$n-S7 | rec ""
        fi ;;
      S8)
        local hp; hp=$(h2cport "$n")
        if [ -n "$hp" ]; then
          sb sweep --url "http://$S:$hp/" --proto h2c --depth 100 --conns 64 --agents "$AGENTS" $SWEEP_SHORT --slo-us 5000 --label "$tag scenario=S8 conns=64 streams=100" --out $OUT/hdr/r$r-$n-S8 | rec ""
        fi ;;
      S9)
        local slo; slo=$(slo_of "$r" "$n" S1 1024)
        if [ "$slo" -gt 0 ]; then
          sb load --url "$url" --conns 1024 --rate $((slo * 2)) --agents "$AGENTS" --warmup 5 --duration 30 --label "$tag scenario=S9 conns=1024 slo_rps=$slo" | rec ""
        fi ;;
      S10)
        local slo; slo=$(slo_of "$r" "$n" S1 256)
        if [ "$slo" -gt 0 ]; then
          local L3=${LOADA[2]}
          on "$L3" "ulimit -n 200000; $SB attack --addr $S:8080 --slowloris 10000 --slowread 1000 --path /64k --interval-s 10 --duration 75" > $C/attack.txt 2>>$OUT/run.log &
          local ap=$!
          sleep 20   # the attackers are open and pressing
          sb load --url "$url" --conns 256 --rate $((slo / 2)) --agents "$AGENTS" --warmup 5 --duration 30 --label "$tag scenario=S10 conns=256 attack=slowloris10k+slowread1k" | rec ""
          wait $ap
          rec "$tag" < $C/attack.txt
          # baseline without the attack, same rate
          sb load --url "$url" --conns 256 --rate $((slo / 2)) --agents "$AGENTS" --warmup 5 --duration 30 --label "$tag scenario=S10 conns=256 attack=none" | rec ""
          server_start "$S" "$n" >>$OUT/run.log 2>&1 || true
        fi ;;
      H3)
        local h3=0
        has "$n" h3 && h3=1
        if [ "$n" = nginx ] && on "$S" "nginx -V 2>&1 | grep -q http_v3_module"; then h3=1; fi
        if [ $h3 = 1 ]; then
          sb sweep --url "https://$S:8443/" --proto h3 "${CA[@]}" --conns 64 --depth 1 --agents "$AGENTS" $SWEEP_SHORT --label "$tag scenario=H3 conns=64" --out $OUT/hdr/r$r-$n-H3 | rec ""
          sb load --url "https://$S:8443/64k" --proto h3 "${CA[@]}" --conns 24 --depth 4 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=H3bulk size=64k conns=24 phase=closed" | rec ""
          sb load --url "https://$S:8443/1m" --proto h3 "${CA[@]}" --conns 12 --depth 1 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=H3bulk size=1m conns=12 phase=closed" | rec ""
        fi ;;
      S6)
        on "$S" "$NODE pss-end $n" | rec "$tag"
        for ic in 10000 100000; do
          server_start "$S" "$n" >>$OUT/run.log 2>&1 || { echo "FAILED step=start-idle" | rec "$tag"; continue; }
          on "$S" "$NODE idle-base"
          sb load --url "$url" --idle --conns $ic --agents "$AGENTS" --warmup 0 --duration 40 --connect-threads 64 --label "$tag scenario=S6 conns=$ic" > $C/idle.txt &
          local lp=$! got="" est=0
          for _ in $(seq 60); do
            sleep 2
            est=$(on "$S" "$NODE established")
            if [ "$est" -ge $((ic * 99 / 100)) ]; then sleep 5; got=$(on "$S" "$NODE idle $n $ic"); break; fi
            kill -0 $lp 2>/dev/null || break
          done
          wait $lp; rec "" < $C/idle.txt >/dev/null
          # still open at the end of the hold? (idle timeouts shorter than the test show here)
          echo "${got:-IDLE conns=$ic failed=1 established=$est}" | sed "s/^IDLE server=[^ ]* /IDLE /" | rec "$tag"
        done
        server_start "$S" "$n" >>$OUT/run.log 2>&1 || true ;;
      COLD)
        on "$S" "$SRVSH stop" >/dev/null 2>&1
        on "$S" "b=\$($SRVSH binary $n); cp \"\$b\" /tmp/size.bin && strip -s /tmp/size.bin 2>/dev/null; echo \"SIZE bytes=\$(stat -c %s /tmp/size.bin) unstripped=\$(stat -c %s \"\$b\") path=\$b\"" | rec "$tag"
        case $n in simoom) on "$S" "b=/root/simoom/target/release/examples/bench_server; cp \$b /tmp/size.bin && strip -s /tmp/size.bin; echo \"SIZE variant=bench_server bytes=\$(stat -c %s /tmp/size.bin) unstripped=\$(stat -c %s \$b) path=\$b\"" | rec "$tag" ;; esac
        on "$S" "$SB coldstart --addr 127.0.0.1:8080 --repeat 10 -- \$($SRVSH cmd $n)" 2>&1 | grep -E '^COLDSTART|simoom-bench:' | sed 's/^simoom-bench: /FAILED step=coldstart /' | rec "$tag"
        server_start "$S" "$n" >>$OUT/run.log 2>&1 || true ;;
    esac
    mark "$r" "$n" "$s"
  done
  case " $scen " in *" S6 "*) ;; *) on "$S" "$NODE pss-end $n" | rec "$tag" ;; esac
  on "$S" "$SRVSH stop" >/dev/null 2>&1
}

log "campaign start: rounds [$ROUNDS], servers [$SERVERS]"
for r in $ROUNDS; do
  if [ $((r % 2)) = 1 ]; then S=$SRV_A; sv=srvA; else S=$SRV_B; sv=srvB; fi
  if ! grep -q "^MACHINE round=$r " $OUT/machine.txt 2>/dev/null; then
    { echo "MACHINE round=$r srv=$sv"; machine "srv-$sv" "$S"; i=1; for l in $LOADS; do machine "load$i" "$l"; i=$((i + 1)); done; } >> $OUT/machine.txt
  fi
  scen="$SCENARIOS_RN"; [ $r = 1 ] && scen="$SCENARIOS_R1"
  [ -n "${SCENARIOS:-}" ] && scen="$SCENARIOS"
  list="$SERVERS"
  if [ $r != 1 ] && [ -z "${SCENARIOS:-}" ]; then
    top=$(grep "^SLO round=1 srv=[^ ]* server=[^ ]* scenario=S1 conns=256 " $RES | sed 's/.* server=\([^ ]*\) .*slo_rps=\([0-9]*\).*/\2 \1/' | grep -v " simoom" | sort -rn | head -n $TOPN | awk '{print $2}' | tr '\n' ' ')
    list=$(for n in $SERVERS; do case " $top nginx " in *" $n "*) echo $n ;; esac; case $n in simoom*) echo $n ;; esac; done | awk '!seen[$0]++' | tr '\n' ' ')
    grep -q "^ROUNDSET round=$r " $RES || echo "ROUNDSET round=$r servers=$(echo $list | tr ' ' ',')" >> $RES
  fi
  for n in $list; do run_server "$r" "$S" "$sv" "$n" "$scen"; done
done
# profiles: simoom (frame pointers) next to the best other server of S1, S5, S7 and S8 and nginx
if ! grep -q "^PROFILE " $RES; then
  best() { grep "^SLO round=1 srv=[^ ]* server=[^ ]* scenario=$1 conns=$2 " $RES | sed 's/.* server=\([^ ]*\) .*slo_rps=\([0-9]*\).*/\2 \1/' | grep -v " simoom" | sort -rn | head -n 1 | awk '{print $2}'; }
  ps=$(printf '%s\n' simoom-prof nginx "$(best S1 256)" "$(best S5 192)" "$(best "S7 kind=S1-tls" 256)" | grep . | awk '!seen[$0]++' | tr '\n' ' ')
  log "profiles: $ps"
  PROF_SRV=A PROF_SERVERS="$ps" PROF_CASES="s1 s5 s7 s8" bash /root/simoom/bench/cloud/profile.sh >> $OUT/run.log 2>&1
fi
log "campaign done"
echo "CAMPAIGN DONE $(date -u +%FT%TZ)" >> $OUT/campaign.log
