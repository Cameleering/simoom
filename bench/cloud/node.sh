#!/usr/bin/env bash
# Measurements taken on a node during a run, called by run.sh over SSH. Prints record lines.
#
#   node.sh cost-begin SECS DELAY          CPU counters now; perf, bpftrace and sar from DELAY s on
#   node.sh cost-end NAME CONNS RECEIVED SECS WALL
#                                          METRIC line: CPU us, cycles, instructions, context
#                                          switches and syscalls per request
#   node.sh sar-begin TAG SECS             sar -n DEV in the background
#   node.sh nic TAG LABEL                  NIC line: average packets/s on the private interface
#   node.sh pss-begin / pss-end NAME       PEAK line: highest summed PSS while sampling, cgroup peak
#   node.sh idle-base                      remember the server's PSS before the idle test
#   node.sh established                    established connections on port 8080
#   node.sh idle NAME CONNS                IDLE line: PSS and cgroup memory with the connections open
set -euo pipefail
SRV=/root/simoom/bench/competitors/server.sh
CG=/sys/fs/cgroup/system.slice/bench-server.service
W=/root/node
mkdir -p $W

case "$1" in
  cost-begin)
    secs=$2; delay=$3
    $SRV cpu_us > $W/cpu0 2>/dev/null || echo 0 > $W/cpu0
    rm -f $W/perf.txt $W/sys.txt
    nohup bash -c "sleep $delay; perf stat -a -x, -e cycles,instructions,context-switches -G system.slice/bench-server.service,system.slice/bench-server.service,system.slice/bench-server.service -- sleep $secs" > /dev/null 2> $W/perf.txt < /dev/null &
    nohup bash -c "sleep $delay; timeout $((secs + 10)) bpftrace -q -e 'tracepoint:raw_syscalls:sys_enter /cgroup == cgroupid(\"$CG\")/ { @n = count(); } interval:s:$secs { exit(); }'" > $W/sys.txt 2>&1 < /dev/null &
    ;;
  cost-end)
    n=$2; c=$3; r=$4; secs=$5; wall=$6
    sleep 1
    c1=$($SRV cpu_us 2>/dev/null || echo 0); d=$(( ${c1:-0} - $(cat $W/cpu0) ))
    field() { awk -F, -v k="$1" '$3 ~ k && $1 ~ /^[0-9]+$/ {print $1; exit}' $W/perf.txt 2>/dev/null; }
    cyc=$(field cycles); ins=$(field instructions); cs=$(field context-switches)
    sc=$(grep -o '@n: [0-9]*' $W/sys.txt 2>/dev/null | grep -o '[0-9]*' | tail -1 || true)
    awk -v n="$n" -v c="$c" -v r="$r" -v d="$d" -v cyc="${cyc:-}" -v ins="${ins:-}" -v cs="${cs:-}" -v sc="${sc:-}" -v secs="$secs" -v wall="$wall" 'BEGIN {
      rate = r / secs; tot = rate * wall
      printf "METRIC server=%s conns=%d rate=%.0f cpu_us_per_req=%.2f", n, c, rate, (tot > 0 ? d / tot : 0)
      printf " cycles_per_req=%s", (cyc != "" && r > 0) ? sprintf("%.0f", cyc / r) : "-"
      printf " instr_per_req=%s", (ins != "" && r > 0) ? sprintf("%.0f", ins / r) : "-"
      printf " ctxsw_per_req=%s", (cs != "" && r > 0) ? sprintf("%.3f", cs / r) : "-"
      printf " syscalls_per_req=%s\n", (sc != "" && r > 0) ? sprintf("%.2f", sc / r) : "-"
    }'
    ;;
  sar-begin) nohup sar -n DEV 1 "$3" > "$W/sar-$2.log" 2>&1 < /dev/null & ;;
  nic)
    awk -v l="$3" '/^Average:/ && ($2 ~ /^eth1$|^ens4$/) {print "NIC " l " iface=" $2 " rxpck_s=" $3 " txpck_s=" $4 " rxkB_s=" $5 " txkB_s=" $6}' "$W/sar-$2.log"
    ;;
  pss-begin)
    nohup bash -c "while true; do $SRV pss; sleep 1; done" > $W/pss.log 2>/dev/null < /dev/null &
    echo $! > $W/pss.pid
    ;;
  pss-end)
    kill "$(cat $W/pss.pid)" 2>/dev/null || true
    echo "PEAK server=$2 pss_kb=$(sort -n $W/pss.log | tail -1) mem_peak_kb=$($SRV mem | cut -d' ' -f2)"
    ;;
  idle-base) curl -s -o /dev/null http://127.0.0.1:8080/; sleep 1; $SRV pss > $W/pss0 ;;
  established) ss -Htn state established '( sport = :8080 )' | wc -l ;;
  idle)
    p0=$(cat $W/pss0); p=$($SRV pss); m=$($SRV mem | cut -d' ' -f1)
    e=$(ss -Htn state established '( sport = :8080 )' | wc -l)
    echo "IDLE server=$2 conns=$3 established=$e pss0_kb=$p0 pss_kb=$p mem_kb=$m per_conn_b=$(( (p - p0) * 1024 / (e > 0 ? e : 1) ))"
    ;;
  profile)
    # profile NAME SECS OUTDIR: perf call graphs of the server's processes, folded stacks for flame
    # graphs, and a syscall histogram by name (bpftrace), while a load runs
    n=$2; secs=$3; o=$4; mkdir -p "$o"
    pids=$(cat $CG/cgroup.procs | paste -sd, -)
    timeout $((secs + 20)) bpftrace -q -e "tracepoint:syscalls:sys_enter_* /cgroup == cgroupid(\"$CG\")/ { @[probe] = count(); } interval:s:$secs { exit(); }" > "$o/$n.syscalls.txt" 2>&1 &
    perf record -q -F 1999 -g -p "$pids" -o "$o/$n.perf.data" -- sleep "$secs" 2>/dev/null
    wait
    perf report -i "$o/$n.perf.data" --stdio --no-children --percent-limit 0.4 --sort dso,symbol -g none 2>/dev/null | grep -v '^$' | head -250 > "$o/$n.report.txt"
    perf report -i "$o/$n.perf.data" --stdio --children --percent-limit 2 --sort symbol -g none 2>/dev/null | grep -v '^$' | head -120 > "$o/$n.children.txt"
    perf script -i "$o/$n.perf.data" 2>/dev/null | python3 /root/simoom/bench/cloud/fold.py > "$o/$n.folded.txt"
    rm -f "$o/$n.perf.data"
    echo "PROFILE server=$n secs=$secs dir=$o"
    ;;
  *) echo "usage: see the header of $0" >&2; exit 1 ;;
esac
