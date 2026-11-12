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
#   node.sh net-begin TAG SECS / net-end TAG
#                                          NET line: retransmits, drops, softirqs per CPU and
#                                          where the server's threads ran (bench/cloud/ab.sh FR)
#   node.sh idle NAME CONNS                IDLE line: PSS and cgroup memory with the connections open
set -euo pipefail
SRV=/root/simoom/bench/competitors/server.sh
CG=/sys/fs/cgroup/system.slice/bench-server.service
W=/root/node
mkdir -p $W
# one line of numbers each, for net-begin and net-end: softnet drops and squeezes summed over CPUs
# (hex in the file), NET_RX softirqs per CPU, the private NIC's receive drops and misses, and
# ksoftirqd's CPU ticks per CPU
softnet() { local d=0 s=0 a b c; while read -r a b c _; do d=$((d + 16#$b)); s=$((s + 16#$c)); done < /proc/net/softnet_stat; echo "$d $s"; }
netrx() { awk '/NET_RX:/ {for (i = 2; i <= NF; i++) printf "%s ", $i; print ""}' /proc/softirqs; }
nicdrop() { local l; l=$(ip -s -s link show dev eth1 2>/dev/null | awk 'f == 1 {print $4, $5; exit} /RX:/ {f = 1}'); echo "${l:-0 0}"; }
ksoft() { local c; for c in $(seq 0 $(( $(nproc) - 1 ))); do p=$(pgrep -x "ksoftirqd/$c" | head -1); [ -n "$p" ] && awk '{printf "%d ", $14 + $15}' /proc/$p/stat || printf '0 '; done; echo; }
# tcpstat FIELD...: the named counters of the Tcp: line in /proc/net/snmp (retransmits, K4)
tcpstat() { awk -v f="$*" '/^Tcp:/ { if (!h) { for (i = 2; i <= NF; i++) c[$i] = i; h = 1 } else { n = split(f, k, " "); o = ""; for (j = 1; j <= n; j++) o = o (j > 1 ? " " : "") $(c[k[j]]); print o } }' /proc/net/snmp; }

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
  mon-begin) # mon-begin TAG SECS: per-second NIC packets and CPU (busy, steal) in the background
    pkill -f "# mon-$2\$" 2>/dev/null || true
    LC_ALL=C nohup bash -c "sar -n DEV 1 $3 # mon-$2" > "$W/mon-$2.net" 2>&1 < /dev/null &
    LC_ALL=C nohup bash -c "sar -u 1 $3 # mon-$2" > "$W/mon-$2.cpu" 2>&1 < /dev/null &
    tcpstat RetransSegs OutSegs > "$W/mon-$2.tcp"
    ;;
  mon-end) # mon-end TAG LABEL: NICPEAK line, the highest per-second values seen
    pkill -f "# mon-$2\$" 2>/dev/null || true
    sleep 0.2
    sec='$1 ~ /^[0-9]+:[0-9]+:[0-9]+$/ && ($2 ~ /^eth1$|^ens4$/)'
    rx=$(awk "$sec"' {if ($3 > m) m = $3} END {printf "%.0f", m}' "$W/mon-$2.net")
    tx=$(awk "$sec"' {if ($4 > m) m = $4} END {printf "%.0f", m}' "$W/mon-$2.net")
    pk=$(awk "$sec"' {if ($3 + $4 > m) m = $3 + $4} END {printf "%.0f", m}' "$W/mon-$2.net")
    mb=$(awk "$sec"' {v = ($5 + $6) * 8 / 1000; if (v > m) m = v} END {printf "%.0f", m}' "$W/mon-$2.net")
    cpu=$(awk '$1 ~ /^[0-9]+:[0-9]+:[0-9]+$/ && $2 == "all" {b = 100 - $8; if (b > m) m = b; if (b > 20) {s += $7; n++}; if ($7 > sm) sm = $7} END {printf "cpu_busy_max=%.1f steal_max=%.1f steal_avg_busy=%.1f busy_secs=%d", m, sm, (n ? s / n : 0), n}' "$W/mon-$2.cpu")
    read -r rt0 os0 < "$W/mon-$2.tcp" 2>/dev/null || { rt0=0; os0=0; }
    read -r rt1 os1 < <(tcpstat RetransSegs OutSegs)
    echo "NICPEAK $3 rxpck_max=$rx txpck_max=$tx pck_max=$pk mbit_max=$mb $cpu retrans_segs=$((rt1 - rt0)) out_segs=$((os1 - os0))"
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
  net-begin) # net-begin TAG SECS: counters for net-end, and per-CPU placement samples of the server's
    # running threads (every 0.2 s for SECS) in the background
    nstat -n >/dev/null 2>&1 || true
    softnet > "$W/net-$2.softnet"
    netrx > "$W/net-$2.rx"
    nicdrop > "$W/net-$2.link"
    ksoft > "$W/net-$2.ksoft"
    pids=$(cat $CG/cgroup.procs 2>/dev/null | paste -sd, - || true); : > "$W/net-$2.place"
    pkill -f "# place-$2\$" 2>/dev/null || true
    nohup bash -c "for i in \$(seq \$(( $3 * 5 ))); do ps -L -o psr=,stat= -p '$pids' 2>/dev/null | awk '\$2 ~ /^R/ {print \$1}'; sleep 0.2; done # place-$2" > "$W/net-$2.place" 2>/dev/null < /dev/null &
    ;;
  net-end) # net-end TAG: NET line: TCP retransmits and losses, softnet drops and squeezes, NIC drops,
    # NET_RX softirqs and ksoftirqd CPU ticks per CPU, and where the server's running threads were
    # sampled (CPU:samples)
    pkill -f "# place-$2\$" 2>/dev/null || true
    n=$(nstat -z 2>/dev/null | awk '$1 ~ /^(TcpRetransSegs|TcpExtTCPLossProbes|TcpExtTCPTimeouts|TcpExtTCPRcvQDrop|TcpExtTCPBacklogDrop|TcpExtTCPLostRetransmit|TcpExtTCPDSACKRecv|TcpExtTCPSpuriousRTOs|TcpExtTCPOFOQueue|TcpInSegs|TcpOutSegs|TcpExtListenDrops|TcpExtTCPDelivered)$/ {sub(/^TcpExt/, ""); sub(/^Tcp/, ""); printf "%s=%s ", $1, $2}')
    diffcols() { paste -d' ' "$1" <(cat) | awk '{n = NF / 2; o = ""; for (i = 1; i <= n; i++) o = o (i > 1 ? "," : "") ($(n + i) - $i); print o}'; }
    sn=$(softnet | diffcols "$W/net-$2.softnet")
    nd=$(nicdrop | diffcols "$W/net-$2.link")
    rx=$(netrx | diffcols "$W/net-$2.rx")
    ks=$(ksoft | diffcols "$W/net-$2.ksoft")
    pl=$(sort -n "$W/net-$2.place" 2>/dev/null | uniq -c | awk '{printf "%s%s:%s", (NR > 1 ? "," : ""), $2, $1}')
    echo "NET ${n}softnet_drop,squeeze=$sn nic_drop,missed=$nd netrx_cpu=$rx ksoftirqd_ticks=$ks running_cpu=$pl"
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
