#!/usr/bin/env bash
# The full benchmark campaign (plan §6.2), run ON load1 so it survives the operator's session.
# Two server droplets alternate between rounds; load1..3 run simoom-bench agents and load1 also
# coordinates. Every record line goes to $OUT/results.txt with round= and srv= fields; a DONE line
# per (round, server, scenario) makes a restarted campaign skip what is finished.
#
#   campaign.sh                      run everything not yet DONE
#   ROUNDS="1" SERVERS="simoom nginx" SCENARIOS="S1 S5" campaign.sh
#   PASSES="2:S1,S5 3:S1,S5 2:S3,S7,S8" campaign.sh
#
# Every server runs in every round (campaign 2; campaign 1 repeated rounds 2 and 3 only for the
# TOPN best servers of round 1, which TOPN=N still selects). A pass is ROUND:SCENARIOS; passes run
# in order, so the headline scenarios of every round can come before the extras. With DEADLINE
# (epoch seconds) a server is started only if its estimated time fits before the deadline;
# otherwise a SKIPPED reason=deadline line is written and the cells stay open for a later run.
# After every scenario a line goes to $OUT/progress.txt; campaign-ctl.sh follow copies out/ back to
# the operator's machine incrementally.
#
# DRY=1 replaces every remote command and load run with a log line (bench/cloud/dry-run.sh).
#
# Environment (written by campaign-ctl.sh into /root/campaign/env):
#   SRV_A, SRV_B       private IPs of the two server droplets (round 1, 3 on A; 2 on B)
#   LOADS              private IPs of load1 load2 load3
#   SERVERS            competitors, in order
#   ROUNDS             (1 2 3)
#   SCENARIOS_R1       scenarios of round 1 (all), SCENARIOS_RN those of rounds 2 and 3
#   PASSES             explicit passes (overrides ROUNDS and the SCENARIOS_* lists)
#   DEADLINE           epoch seconds; nothing is started that would end after it
set -uo pipefail
ulimit -n 1048576 2>/dev/null || ulimit -n 65536
C=${CAMPAIGN_DIR:-/root/campaign}
. $C/env
OUT=${OUT_DIR:-$C/out}
mkdir -p $OUT/hdr $OUT/prof
RES=$OUT/results.txt
touch $RES
SB=${SB:-/root/simoom/target/release/simoom-bench}
SRVSH=/root/simoom/bench/competitors/server.sh
NODE="bash /root/simoom/bench/cloud/node.sh"
PSSLOG=/root/node/pss.log
CA=(--cacert /root/bench-ca.pem --sni bench.local)
AGENTS="$(for l in $LOADS; do printf '%s:7070,' "$l"; done)"; AGENTS="${AGENTS%,}"
read -r -a LOADA <<<"$LOADS"
SSH=(ssh -i $C/key -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$C/known_hosts -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30)
on() { local h=$1; shift; "${SSH[@]}" "root@$h" "$@"; }
log() { printf '==> %s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a $OUT/campaign.log >&2; }
# search: short steps; points: 5 x 30 s (50, 80, 95, 100, 100% of the SLO throughput)
SWEEP_LONG="--probe 4 --step-warmup 2 --step 6 --steps 7 --point-warmup 5 --point 20 --points 0.5,0.8,0.95,1,1"
SWEEP_SHORT="--probe 3 --step-warmup 2 --step 5 --steps 6 --point-warmup 3 --point 10 --points 0.5,0.95"
SWEEP_ONE="$SWEEP_SHORT"
SWEEP_R="$SWEEP_LONG"
if [ -n "${LANE:-}" ]; then
  # lane mode (three servers measured at once): a search started from a hint (campaign 1's result
  # or this campaign's earlier round, then +-30%, then bisection to 4%), and 20 s measured points
  SWEEP_LONG="--probe 3 --step-warmup 2 --step 5 --steps 5 --precision 0.04 --point-warmup 3 --point 20 --points 0.5,0.8,0.95,1,1"
  SWEEP_ONE="--probe 3 --step-warmup 2 --step 5 --steps 5 --precision 0.04 --point-warmup 3 --point 15 --points 0.9,1"
  SWEEP_R="--probe 3 --step-warmup 2 --step 5 --steps 5 --precision 0.04 --point-warmup 3 --point 20 --points 0.95,1"
fi
HINTS=${HINTS_FILE:-/root/simoom/bench/cloud/hints.txt}
hint_arg() { # hint_arg SERVER KEY CONNS -> "--hint R": this lane's earlier SLO, else hints.txt
  local sc=${2%%:*} v="" m=$1
  v=$(grep "^SLO round=[0-9]* srv=[^ ]* server=$1 scenario=$sc " $RES 2>/dev/null | grep " conns=$3 " | { case $2 in *:*) grep "=${2#*:} " ;; *) cat ;; esac; } | grep -o 'slo_rps=[0-9]*' | tail -1 | cut -d= -f2)
  if [ -z "$v" ] || [ "$v" = 0 ]; then
    case $1 in simoom*) m=simoom ;; cameleer-http-min) m=cameleer ;; esac
    v=$(awk -v s="$m" -v k="$2" -v c="$3" '$1==s && $2==k && $3==c {print $4}' $HINTS 2>/dev/null | tail -1)
  fi
  [ -n "$v" ] && [ "$v" != 0 ] && echo "--hint $v"
}
# lane mode: which scenarios a server runs in a round. Three rounds for the simoom variants,
# cameleer-http-min and campaign 1's top competitors (THREE); one round for the rest. Round 1: the
# common set plus each server's extras; rounds 2 and 3: S1 at 256 connections (S1R).
THREE="${THREE:-simoom simoom-uring simoom-builder simoom-builder-uring simoom-default simoom-deferred simoom-deferred-stream simoom-blocking cameleer-http-min hyper may-minihttp xitca ntex axum h2o nginx haproxy}"
scen_for() { # scen_for SERVER ROUND
  # campaign 4 (C4=1): the whole field against the current simoom, simoom in every lane. Round 1:
  # every scenario a server supports; rounds 2 and 3, on the other two droplets: the headline
  # scenarios again, so each competitor/simoom ratio has three same-droplet samples.
  if [ -n "${C4:-}" ]; then
    case $1 in
      axum-rustls) [ "$2" = 1 ] && echo "S7 COLD" || echo "S7" ;;
      quinn-h3) [ "$2" = 1 ] && echo "H3 COLD" || echo "H3" ;;
      *) [ "$2" = 1 ] && echo "S1 S3 S4 S5 S7 S8 S9 S10 H3 CPU S6 COLD" || echo "S1R S3 S5 S7 H3 CPU" ;;
    esac
    return
  fi
  if [ "$2" != 1 ]; then case " $THREE " in *" $1 "*) echo S1R ;; esac; return; fi
  local x=""
  case $1 in
    nginx) x="S4 S6 S9 S10" ;; hyper) x="S6 S9" ;; xitca) x="S6 S9" ;; ntex|may-minihttp) x="S9" ;; haproxy) x="S9 S10" ;;
    cameleer-http-min) x="S6 SLEEP" ;; simoom-deferred*|simoom-blocking) x="SLEEP" ;;
    # campaign 3: the scenarios of campaign 2's losses (K4-K8) on simoom itself, in the lanes
    simoom) x="S4 S6 S9 S10" ;; simoom-uring) x="S6 S9 S10" ;; simoom-default) x="S6" ;;
  esac
  echo "S1 S3 S5 S7 S8 H3 CPU $x COLD"
}
ROUNDS="${ROUNDS:-1 2 3}"
SCENARIOS_R1="${SCENARIOS_R1:-S1 S3 S4 S5 S6 S7 S8 S9 S10 H3 CPU SLEEP COLD}"
SCENARIOS_RN="${SCENARIOS_RN:-S1 S5 CPU}"
# CPU: cost per request at one fixed rate for every server (50k req/s, 256 connections)
CPU_RATE="${CPU_RATE:-50000}"
# SLEEP: GET /sleep (the handler blocks 100 ms on a worker thread), 500 clients, closed loop
# TOPN=0 (default): every server in every round. TOPN=N: rounds 2 and 3 only for the simoom
# variants, nginx and the N best other servers of round 1 by S1 SLO throughput at 256 connections.
TOPN="${TOPN:-0}"
DEADLINE="${DEADLINE:-0}"
# estimated seconds per scenario (from campaign 1's log), for the deadline check
est_of() {
  local t=60 s
  for s in $1; do
    case $s in S1) t=$((t + 420)) ;; S3|S5|S8) t=$((t + 90)) ;; S4) t=$((t + 120)) ;; S6) t=$((t + 150)) ;;
      S7) t=$((t + 140)) ;; S9) t=$((t + 45)) ;; S10) t=$((t + 120)) ;; H3) t=$((t + 140)) ;; COLD) t=$((t + 90)) ;; S1R) t=$((t + 140)) ;;
      CPU) t=$((t + 40)) ;; SLEEP) t=$((t + 35)) ;; *) t=$((t + 90)) ;; esac
  done
  echo $t
}
fits() { [ "$DEADLINE" = 0 ] || [ $(( $(date +%s) + $1 )) -le "$DEADLINE" ]; }

# capabilities: echo s4 tls h2c-port h3 (from the competitor configs)
caps() {
  case "$1" in
    simoom-default) echo "echo s4 h2c:8080" ;;
    simoom-deferred*|simoom-blocking) echo "echo" ;;
    simoom*) echo "echo s4 tls h2c:8080 h3" ;;
    cameleer-http-min) echo "tls" ;;
    axum-rustls) echo "tls" ;;
    quinn-h3) echo "h3" ;;
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

# applies SERVER SCENARIO: the blocking-path variants (deferred replies on the server's own thread
# pool, simoom's offload pool) run only the scenarios that measure that path; only they and
# cameleer-http-min (a thread per connection) serve GET /sleep
applies() {
  case "$1:$2" in
    simoom-deferred*:S1|simoom-deferred*:S1R|simoom-deferred*:S3|simoom-deferred*:CPU|simoom-deferred*:SLEEP) return 0 ;;
    simoom-blocking:S1|simoom-blocking:S1R|simoom-blocking:S3|simoom-blocking:CPU|simoom-blocking:SLEEP) return 0 ;;
    simoom-deferred*:*|simoom-blocking:*) return 1 ;;
    cameleer-http-min:SLEEP) return 0 ;;
    *:SLEEP) return 1 ;;
  esac
  return 0
}

done_mark() { grep -q "^DONE round=$1 server=$2 scenario=$3\$" $RES; }
mark() { echo "DONE round=$1 server=$2 scenario=$3" >> $RES; echo "$(date -u +%FT%TZ) round=$1 server=$2 scenario=$3" >> $OUT/progress.txt; }
rec() { # rec PREFIX: tag record lines from stdin and append them
  if [ -z "$1" ]; then grep -E '^(RESULT|SLO|METRIC|NIC|NICPEAK|PEAK|SPEAK|BASE|IDLE|COLDSTART|SIZE|VERSION|ATTACK|SKIPPED|FAILED|PROFILE) ' | tee -a $RES; return; fi
  sed -u "s/^\(RESULT\|SLO\|METRIC\|NIC\|NICPEAK\|PEAK\|SPEAK\|BASE\|IDLE\|COLDSTART\|SIZE\|VERSION\|ATTACK\|SKIPPED\|FAILED\|PROFILE\) /\1 $1 /" | grep -E '^(RESULT|SLO|METRIC|NIC|NICPEAK|PEAK|SPEAK|BASE|IDLE|COLDSTART|SIZE|VERSION|ATTACK|SKIPPED|FAILED|PROFILE) ' | tee -a $RES
}
sb() { $SB "$@" 2>>$OUT/run.log; }
if [ "${DRY:-0}" = 1 ]; then # control-flow check: every remote command and load run is logged
  on() { echo "DRY on $*" >> $OUT/dry.log; case "$*" in *" established"*) echo 999999 ;; *"binary "*) echo /bin/true ;; esac; return 0; }
  sb() { echo "DRY sb $*" >> $OUT/dry.log; local l="" p="" a; for a in "$@"; do [ "$p" = --label ] && l=$a; p=$a; done; [ "$1" = sweep ] && echo "SLO $l slo_rps=100000 capped=0"; return 0; }
  NODE="echo DRY node.sh"
  sleep() { :; }
fi
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
  local r=$1 S=$2 sv=$3 n=$4 scen="" tag="round=$1 srv=$3 server=$4" s0
  for s0 in $5; do
    applies "$n" "$s0" || continue
    case $s0 in S3) has "$n" echo || continue ;; S4) has "$n" s4 || continue ;; S7) has "$n" tls || continue ;;
      S8) [ -n "$(h2cport "$n")" ] || continue ;; H3) has "$n" h3 || [ "$n" = nginx ] || continue ;; esac
    scen="$scen $s0"
  done
  scen="${scen# }"
  [ -n "$scen" ] || return 0
  local all=1
  for s in $scen; do done_mark "$r" "$n" "$s" || all=0; done
  [ $all = 1 ] && return 0
  local need; need=$(est_of "$scen")
  if ! fits "$need"; then
    log "round $r on $sv: $n ($scen) skipped: needs ~${need}s, deadline $(date -u -d @$DEADLINE +%H:%M:%S)"
    echo "SKIPPED reason=deadline scenarios=$(echo $scen | tr ' ' ',')" | rec "$tag"; return 0
  fi
  log "round $r on $sv: $n ($scen)"
  local first=1
  grep -q "^VERSION $tag " $RES && first=0
  if ! on "$S" "b=\$($SRVSH binary $n 2>/dev/null); [ -n \"\$b\" ] && [ -x \"\$b\" ]"; then
    echo "SKIPPED reason=setup-failed" | rec "$tag"; for s in $scen; do mark "$r" "$n" "$s"; done; return 0
  fi
  [ $first = 1 ] && echo "VERSION $(on "$S" "$SRVSH version $n" | tr '\n' ' ')" | rec "$tag"
  if ! server_start "$S" "$n" >>$OUT/run.log 2>&1; then
    echo "FAILED step=start" | rec "$tag"; for s in $scen; do mark "$r" "$n" "$s"; done; return 0
  fi
  [ $first = 1 ] && on "$S" "$NODE idle-base; echo \"BASE pss_kb=\$(cat /root/node/pss0) mem_kb=\$($SRVSH mem | cut -d' ' -f1)\"" | rec "$tag"
  on "$S" "$NODE pss-begin"
  warm "$S"
  local url="http://$S:8080/"
  for s in $scen; do
    done_mark "$r" "$n" "$s" && continue
    log "  $n $s"
    local pss_n0; pss_n0=$(on "$S" "wc -l < $PSSLOG 2>/dev/null || echo 0")
    case $s in
      S1|S1R)
        local cl="64 256 1024"
        if [ -n "${LANE:-}" ]; then
          cl="256 1024"; case $n in simoom*|may-minihttp|hyper) cl="64 256 1024" ;; esac
          [ -n "${C4:-}" ] && cl="64 256 1024"
          [ $s = S1R ] && cl=256
        fi
        for c in $cl; do
          local plan="$SWEEP_ONE"; [ $c = 256 ] && plan="$SWEEP_LONG"; [ $s = S1R ] && plan="$SWEEP_R"
          if [ $c = 256 ]; then # NIC packets/s and CPU (busy, steal) per second on the server and load1
            on "$S" "$NODE mon-begin r$r-$n-s1 260"; $NODE mon-begin r$r-$n-s1 260
          fi
          sb sweep --url "$url" --conns $c --agents "$AGENTS" $plan $(hint_arg "$n" S1 $c) --label "$tag scenario=S1 conns=$c" --out $OUT/hdr/r$r-$n-S1-c$c | rec ""
          if [ $c = 256 ]; then
            on "$S" "$NODE mon-end r$r-$n-s1 'node=srv scenario=S1 conns=256'" | rec "$tag"
            $NODE mon-end r$r-$n-s1 'node=load1 scenario=S1 conns=256' | rec "$tag"
          fi
        done
        # cost per request at 80% of the SLO throughput, 256 connections; NIC packets/s alongside
        local slo; slo=$(slo_of "$r" "$n" S1 256)
        [ -n "${LANE:-}" ] && slo=0  # lane mode: the CPU scenario (one fixed rate) replaces this
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
          sb sweep --url "http://$S:8080/echo" --body-size 1024 --conns 256 --agents "$AGENTS" $SWEEP_ONE $(hint_arg "$n" S3 256) --label "$tag scenario=S3 conns=256" --out $OUT/hdr/r$r-$n-S3 | rec ""
        fi ;;
      S4)
        if has "$n" s4; then
          sb sweep --url "http://$S:8080/64k" --conns 64 --agents "$AGENTS" $SWEEP_ONE $(hint_arg "$n" S4:64k 64) --slo-us 5000 --label "$tag scenario=S4 size=64k conns=64" --out $OUT/hdr/r$r-$n-S4-64k | rec ""
          sb load --url "http://$S:8080/1m" --conns 64 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S4 size=1m conns=64 phase=closed" | rec ""
          if has "$n" tls; then
            sb load --url "https://$S:8443/1m" "${CA[@]}" --conns 64 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S4 size=1m-tls conns=64 phase=closed" | rec ""
          fi
        fi ;;
      S5)
        sb sweep --url "$url" --new-conn --conns 192 --agents "$AGENTS" $SWEEP_ONE $(hint_arg "$n" S5 192) --slo-us 5000 --label "$tag scenario=S5 conns=192" --out $OUT/hdr/r$r-$n-S5 | rec "" ;;
      S7)
        if has "$n" tls; then
          sb load --url "https://$S:8443/" "${CA[@]}" --new-conn --conns 192 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S7 kind=full conns=192 phase=closed" | rec ""
          sb load --url "https://$S:8443/" "${CA[@]}" --new-conn --tls-resume --conns 192 --agents "$AGENTS" --warmup 3 --duration 15 --label "$tag scenario=S7 kind=resumed conns=192 phase=closed" | rec ""
          sb sweep --url "https://$S:8443/" "${CA[@]}" --conns 256 --agents "$AGENTS" $SWEEP_ONE $(hint_arg "$n" S7:S1-tls 256) --label "$tag scenario=S7 kind=S1-tls conns=256" --out $OUT/hdr/r$r-$n-S7 | rec ""
        fi ;;
      S8)
        local hp; hp=$(h2cport "$n")
        if [ -n "$hp" ]; then
          sb sweep --url "http://$S:$hp/" --proto h2c --depth 100 --conns 64 --agents "$AGENTS" $SWEEP_ONE $(hint_arg "$n" S8 64) --slo-us 5000 --label "$tag scenario=S8 conns=64 streams=100" --out $OUT/hdr/r$r-$n-S8 | rec ""
        fi ;;
      S9)
        # S9_RATE (campaign 3): one absolute offered rate for every server (about 1.15 x the c-4 NIC
        # ceiling), so the rows compare; without it, 2 x the server's own S1 SLO at 1024 connections
        local slo; slo=$(slo_of "$r" "$n" S1 1024)
        if [ -n "${S9_RATE:-}" ]; then
          sb load --url "$url" --conns 1024 --rate $S9_RATE --agents "$AGENTS" --warmup 5 --duration 30 --label "$tag scenario=S9 conns=1024 slo_rps=$slo offered=abs" | rec ""
        elif [ "$slo" -gt 0 ]; then
          sb load --url "$url" --conns 1024 --rate $((slo * 2)) --agents "$AGENTS" --warmup 5 --duration 30 --label "$tag scenario=S9 conns=1024 slo_rps=$slo" | rec ""
        fi ;;
      S10)
        local slo; slo=$(slo_of "$r" "$n" S1 256)
        if [ "$slo" -gt 0 ]; then
          local L3=${LOADA[$((${#LOADA[@]} - 1))]}
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
          sb sweep --url "https://$S:8443/" --proto h3 "${CA[@]}" --conns 64 --depth 1 --agents "$AGENTS" $SWEEP_ONE $(hint_arg "$n" H3 64) --label "$tag scenario=H3 conns=64" --out $OUT/hdr/r$r-$n-H3 | rec ""
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
      CPU)
        local secs=15 warm=4
        on "$S" "$NODE cost-begin $secs $((warm + 2))"
        sb load --url "$url" --conns 256 --rate $CPU_RATE --agents "$AGENTS" --warmup $warm --duration $secs --label "$tag scenario=cpufix conns=256" > $C/cpu.txt
        rec "" < $C/cpu.txt >/dev/null
        local recv; recv=$(grep -o 'received=[0-9]*' $C/cpu.txt | cut -d= -f2)
        sleep 3
        on "$S" "$NODE cost-end $n 256 ${recv:-0} $secs $((secs + warm))" | sed 's/^METRIC /METRIC scenario=cpufix /' | rec "$tag" ;;
      SLEEP)
        sb load --url "http://$S:8080/sleep" --conns 500 --agents "$AGENTS" --warmup 5 --duration 20 --label "$tag scenario=SLEEP conns=500 phase=closed" | rec "" ;;
      COLD)
        on "$S" "$SRVSH stop" >/dev/null 2>&1
        on "$S" "b=\$($SRVSH binary $n); cp \"\$b\" /tmp/size.bin && strip -s /tmp/size.bin 2>/dev/null; echo \"SIZE bytes=\$(stat -c %s /tmp/size.bin) unstripped=\$(stat -c %s \"\$b\") path=\$b\"" | rec "$tag"
        if [ $n = simoom ]; then
          for v in bench_server:/root/simoom/target/release/examples/bench_server min_server:/root/simoom/target-minplain/release/examples/min_server min_server-tls:/root/simoom/target-mintls/release/examples/min_server min_server-h1:/root/simoom/target-minh1/release/examples/min_server; do
            on "$S" "b=${v#*:}; cp \$b /tmp/size.bin && strip -s /tmp/size.bin; echo \"SIZE variant=${v%%:*} bytes=\$(stat -c %s /tmp/size.bin) unstripped=\$(stat -c %s \$b) path=\$b\"" | rec "$tag"
          done
        fi
        on "$S" "$SB coldstart --addr 127.0.0.1:8080 --repeat 20 -- \$($SRVSH cmd $n)" 2>&1 | grep -E '^COLDSTART|simoom-bench:' | sed 's/^simoom-bench: /FAILED step=coldstart /' | rec "$tag"
        # like-for-like with Cameleer's cameleer-http (docs/STATUS.md): the smallest servers,
        # plain and with TLS, the same reply and arguments
        local cert="--cert /opt/bench/cert/cert.pem --key /opt/bench/cert/key.pem" cv=""
        case $n in
          simoom) cv="bench_server|/root/simoom/target/release/examples/bench_server --addr 0.0.0.0:8080
min_server|/root/simoom/target-minplain/release/examples/min_server --addr 0.0.0.0:8080
min_server-tls|/root/simoom/target-mintls/release/examples/min_server --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 $cert
min_server-h1|/root/simoom/target-minh1/release/examples/min_server --addr 0.0.0.0:8080
server-no-tls|/root/simoom/target/release/simoom-server --addr 0.0.0.0:8080 --no-tls" ;;
          cameleer-http-min) cv="plain|/root/cameleer/target-min/release/cameleer-http-min --addr 0.0.0.0:8080" ;;
        esac
        while IFS='|' read -r vn vc; do
          [ -n "$vn" ] || continue
          on "$S" "$SB coldstart --addr 127.0.0.1:8080 --repeat 20 -- $vc" 2>&1 < /dev/null | grep -E '^COLDSTART|simoom-bench:' | sed "s/^COLDSTART /COLDSTART variant=$vn /; s/^simoom-bench: /FAILED step=coldstart-$vn /" | rec "$tag"
        done <<<"$cv"
        server_start "$S" "$n" >>$OUT/run.log 2>&1 || true ;;
    esac
    # peak PSS during this scenario alone (campaign 4; S6 and COLD restart the server, skip them)
    case $s in S6|COLD) ;; *)
      local sp; sp=$(on "$S" "tail -n +$(( ${pss_n0:-0} + 1 )) $PSSLOG 2>/dev/null | sort -n | tail -1")
      [ -n "$sp" ] && echo "SPEAK scenario=$s pss_kb=$sp" | rec "$tag" ;;
    esac
    mark "$r" "$n" "$s"
  done
  case " $scen " in *" S6 "*) ;; *) on "$S" "$NODE pss-end $n" | rec "$tag" ;; esac
  on "$S" "$SRVSH stop" >/dev/null 2>&1
}

if [ -n "${LANE:-}" ]; then
  # lane LANE of three: its own load nodes (LOADS) and servers (SERVERS); round r runs on server
  # droplet (LANE - 1 + r - 1) mod 3 of LANE_SRVS, so every server meets a different droplet each round
  read -r -a LS <<<"$LANE_SRVS"; read -r -a LN <<<"${LANE_NAMES:-srvA srvB srvC}"
  log "lane $LANE start: rounds [$ROUNDS], servers [$SERVERS], loads [$LOADS], deadline $([ "$DEADLINE" = 0 ] && echo none || date -u -d @$DEADLINE +%FT%TZ)"
  BAR=${BARRIER_DIR:-/root/campaign/barrier}; mkdir -p "$BAR"
  for r in $ROUNDS; do
    # barrier: the lanes rotate over the same three server droplets, so no lane may start round r
    # before every lane has finished round r-1 (two lanes on one droplet would stop each other's server)
    if [ "$r" != "${ROUNDS%% *}" ]; then
      touch "$BAR/done-r$((r - 1))-lane$LANE"
      log "lane $LANE waiting for the other lanes to finish round $((r - 1))"
      while [ "$(ls "$BAR" | grep -c "^done-r$((r - 1))-lane")" -lt "${LANES:-3}" ]; do [ "${DRY:-0}" = 1 ] && break; command sleep 10; done
    fi
    k=$(( (LANE - 1 + r - 1) % 3 )); S=${LS[$k]}; sv=${LN[$k]}
    if ! grep -q "^MACHINE round=$r lane=$LANE " $OUT/machine.txt 2>/dev/null; then
      { echo "MACHINE round=$r lane=$LANE srv=$sv"; machine "srv-$sv" "$S"; i=1; for l in $LOADS; do machine "load$i" "$l"; i=$((i + 1)); done; } >> $OUT/machine.txt
    fi
    for n in $SERVERS; do
      scen=$(scen_for "$n" "$r")
      [ -n "$scen" ] && run_server "$r" "$S" "$sv" "$n" "$scen"
    done
  done
  if [ -n "${PROF_SERVERS:-}" ] && fits 600; then
    log "profiles: $PROF_SERVERS"
    if [ "${DRY:-0}" = 1 ]; then echo "DRY profile.sh $PROF_SERVERS" >> $OUT/dry.log
    else PROF_HOST=$S PROF_NAME=$sv PROF_CASES="${PROF_CASES:-s1 s3 s8}" bash /root/simoom/bench/cloud/profile.sh >> $OUT/run.log 2>&1; fi
  fi
  log "campaign done"
  echo "CAMPAIGN DONE $(date -u +%FT%TZ)" >> $OUT/campaign.log
  exit 0
fi
if [ -z "${PASSES:-}" ]; then
  PASSES=""
  for r in $ROUNDS; do
    scen="$SCENARIOS_RN"; [ $r = 1 ] && scen="$SCENARIOS_R1"
    [ -n "${SCENARIOS:-}" ] && scen="$SCENARIOS"
    PASSES="$PASSES $r:$(echo $scen | tr ' ' ',')"
  done
fi
log "campaign start: passes [$PASSES], servers [$SERVERS], deadline $([ "$DEADLINE" = 0 ] && echo none || date -u -d @$DEADLINE +%FT%TZ)"
for pass in $PASSES; do
  r=${pass%%:*}; scen=$(echo "${pass#*:}" | tr ',' ' ')
  if [ $((r % 2)) = 1 ]; then S=$SRV_A; sv=srvA; else S=$SRV_B; sv=srvB; fi
  if ! grep -q "^MACHINE round=$r " $OUT/machine.txt 2>/dev/null; then
    { echo "MACHINE round=$r srv=$sv"; machine "srv-$sv" "$S"; i=1; for l in $LOADS; do machine "load$i" "$l"; i=$((i + 1)); done; } >> $OUT/machine.txt
  fi
  list="$SERVERS"
  if [ $r != 1 ] && [ "$TOPN" != 0 ]; then
    top=$(grep "^SLO round=1 srv=[^ ]* server=[^ ]* scenario=S1 conns=256 " $RES | sed 's/.* server=\([^ ]*\) .*slo_rps=\([0-9]*\).*/\2 \1/' | grep -v " simoom" | sort -rn | head -n $TOPN | awk '{print $2}' | tr '\n' ' ')
    list=$(for n in $SERVERS; do case " $top nginx " in *" $n "*) echo $n ;; esac; case $n in simoom*) echo $n ;; esac; done | awk '!seen[$0]++' | tr '\n' ' ')
  fi
  sc=$(echo $scen | tr ' ' ',')
  grep -q "^ROUNDSET round=$r scenarios=$sc " $RES || echo "ROUNDSET round=$r scenarios=$sc servers=$(echo $list | tr ' ' ',')" >> $RES
  for n in $list; do run_server "$r" "$S" "$sv" "$n" "$scen"; done
done
# profiles: simoom (frame pointers) next to the best other server of S1, S5, S7 and S8 and nginx
if [ "${PROFILES:-1}" = 1 ] && ! grep -q "^PROFILE " $RES && fits 2700; then
  best() { grep "^SLO round=1 srv=[^ ]* server=[^ ]* scenario=$1 conns=$2 " $RES | sed 's/.* server=\([^ ]*\) .*slo_rps=\([0-9]*\).*/\2 \1/' | grep -v " simoom" | sort -rn | head -n 1 | awk '{print $2}'; }
  ps=$(printf '%s\n' simoom-prof simoom-prof-uring nginx "$(best S1 256)" "$(best S3 256)" "$(best S5 192)" "$(best "S7 kind=S1-tls" 256)" "$(best S8 64)" | grep . | awk '!seen[$0]++' | tr '\n' ' ')
  log "profiles: $ps"
  if [ "${DRY:-0}" = 1 ]; then echo "DRY profile.sh $ps" >> $OUT/dry.log
  else PROF_SRV=A PROF_SERVERS="$ps" PROF_CASES="${PROF_CASES:-s1 s3 s5 s7 s8}" bash /root/simoom/bench/cloud/profile.sh >> $OUT/run.log 2>&1; fi
fi
log "campaign done"
echo "CAMPAIGN DONE $(date -u +%FT%TZ)" >> $OUT/campaign.log
