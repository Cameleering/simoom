#!/usr/bin/env bash
# Profiles servers on one server droplet while load1..3 drive a fixed load (run ON load1, with the
# campaign's env and key). For every server in PROF_SERVERS and every case in PROF_CASES:
#   - the load runs at the given rate for 35 s; after 10 s, node.sh profile records 15 s of perf
#     call graphs (folded stacks), a flat symbol report and a bpftrace syscall histogram;
#   - perf stat (cycles, instructions, context switches) and the cgroup CPU over the same window.
# Output: /root/campaign/out/prof/<case>/<server>.* and PROFILE/RESULT/METRIC lines in results.txt.
#
#   PROF_SRV=A PROF_SERVERS="simoom-prof nginx" PROF_CASES="s1 s5 s7" profile.sh
set -uo pipefail
ulimit -n 1048576 2>/dev/null || true
C=${CAMPAIGN_DIR:-/root/campaign}
. $C/env
OUT=$C/out; RES=$OUT/results.txt
SB=/root/simoom/target/release/simoom-bench
SRVSH=/root/simoom/bench/competitors/server.sh
NODE="bash /root/simoom/bench/cloud/node.sh"
AGENTS="$(for l in $LOADS; do printf '%s:7070,' "$l"; done)"; AGENTS="${AGENTS%,}"
SSH=(ssh -i $C/key -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$C/known_hosts -o BatchMode=yes -o ConnectTimeout=10)
on() { local h=$1; shift; "${SSH[@]}" "root@$h" "$@"; }
S=$SRV_A; sv=srvA; [ "${PROF_SRV:-A}" = B ] && { S=$SRV_B; sv=srvB; }
[ -n "${PROF_HOST:-}" ] && { S=$PROF_HOST; sv=${PROF_NAME:-srv}; }
CA=(--cacert /root/bench-ca.pem --sni bench.local)
RATE_S1="${RATE_S1:-60000}"; RATE_S5="${RATE_S5:-8000}"; RATE_S7="${RATE_S7:-2000}"; RATE_S8="${RATE_S8:-60000}"
for n in ${PROF_SERVERS:-simoom-prof nginx}; do
  on "$S" "$SRVSH stop >/dev/null 2>&1; $SRVSH start $n" || { echo "FAILED prof server=$n step=start" | tee -a $RES; continue; }
  $SB load --url "http://$S:8080/" --conns 256 --agents "$AGENTS" --warmup 0 --duration 10 >/dev/null 2>&1
  for c in ${PROF_CASES:-s1 s5}; do
    case $c in
      s1) args=(--url "http://$S:8080/" --conns 256 --rate $RATE_S1) ;;
      s3) args=(--url "http://$S:8080/echo" --body-size 1024 --conns 256 --rate $RATE_S1) ;;
      s5) args=(--url "http://$S:8080/" --new-conn --conns 192 --rate $RATE_S5) ;;
      s7) args=(--url "https://$S:8443/" "${CA[@]}" --new-conn --conns 192 --rate $RATE_S7) ;;
      s8) args=(--url "http://$S:8080/" --proto h2c --depth 100 --conns 64 --rate $RATE_S8) ;;
      s7ka) args=(--url "https://$S:8443/" "${CA[@]}" --conns 256 --rate $RATE_S1) ;;
      *) continue ;;
    esac
    on "$S" "$NODE cost-begin 15 12; (sleep 12; $NODE profile $n 15 /root/prof/$c) > /root/prof-$c.log 2>&1 &"
    $SB load "${args[@]}" --agents "$AGENTS" --warmup 10 --duration 20 --label "prof=1 srv=$sv server=$n case=$c" 2>/dev/null > $C/prof.txt
    grep '^RESULT' $C/prof.txt | tee -a $RES
    recv=$(grep -o 'received=[0-9]*' $C/prof.txt | cut -d= -f2)
    sleep 15
    # the counters cover 15 s of the 20 s window: scale the received count to 15 s
    on "$S" "$NODE cost-end $n 0 $(( ${recv:-0} * 15 / 20 )) 15 30" | sed "s/^METRIC /METRIC prof=1 srv=$sv case=$c /" | tee -a $RES
    on "$S" "cat /root/prof-$c.log" | grep '^PROFILE' | sed "s/^PROFILE /PROFILE srv=$sv case=$c /" | tee -a $RES
  done
  on "$S" "$SRVSH stop" >/dev/null 2>&1
done
mkdir -p $OUT/prof
on "$S" 'cd /root/prof && tar -czf - .' | tar -xzf - -C $OUT/prof
echo "profile done"
