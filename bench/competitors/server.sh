#!/usr/bin/env bash
# Install, start, stop and measure one competitor on a server node (Ubuntu 24.04, root).
#
#   server.sh list                    the competitors
#   server.sh setup NAME...           install or build them (NAME/setup.sh)
#   server.sh start NAME              start as the transient systemd unit bench-server; wait for 200
#   server.sh stop                    stop it and wait for port 8080 to close
#   server.sh cmd NAME                the foreground command line (for cold-start timing)
#   server.sh binary NAME             path of the main executable (for size)
#   server.sh version NAME            its version string
#   server.sh pss                     summed PSS of the unit's processes, KB
#   server.sh mem                     the unit's cgroup memory.current and memory.peak, KB
#   server.sh cpu_us                  the unit's cgroup CPU time, microseconds
#
# Every competitor serves GET / with the 13-byte body "Hello, World!" (text/plain) on port 8080
# (HTTP/1.1, and h2c where the server takes both on one port), POST /echo with the request body
# where that is cheap, h2c on 8081 where it needs its own port, and TLS on 8443 where configured.
set -euo pipefail
COMP="$(cd "$(dirname "$0")" && pwd)"
UNIT=bench-server
CG=/sys/fs/cgroup/system.slice/$UNIT.service

port_open() { ss -Htln '( sport = :8080 )' | grep -q .; }

names() { for d in "$COMP"/*/; do [ -f "$d/run.sh" ] && basename "$d"; done; }

wait_ready() {
  for _ in $(seq 600); do
    if curl -s -o /dev/null -w '%{http_code}' --max-time 1 http://127.0.0.1:8080/ 2>/dev/null | grep -q '^2'; then return 0; fi
    systemctl is-active -q $UNIT || { journalctl -u $UNIT --no-pager | tail -30 >&2; return 1; }
    sleep 0.1
  done
  echo "server did not answer on 8080" >&2; return 1
}

case "${1:-list}" in
  list) names ;;
  setup) shift; for n in "$@"; do echo "==> setup $n" >&2; bash "$COMP/$n/setup.sh"; done ;;
  start)
    n=${2:?name}
    "$0" stop >/dev/null 2>&1 || true
    if port_open; then echo "port 8080 is still in use: $(ss -Htlnp '( sport = :8080 )' | head -2)" >&2; exit 1; fi
    systemd-run -q --unit=$UNIT --collect -p LimitNOFILE=1048576 -p TasksMax=infinity -p MemoryAccounting=yes \
      -p CPUAccounting=yes -E HOME=/root -E PATH="$PATH" bash "$COMP/$n/run.sh"
    wait_ready ;;
  stop)
    systemctl stop $UNIT 2>/dev/null || true
    # anything left in the unit's cgroup (forked helpers) or still on the port is killed
    for p in $(cat $CG/cgroup.procs 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
    for i in $(seq 100); do
      port_open || exit 0
      [ "$i" = 30 ] && fuser -k -9 8080/tcp >/dev/null 2>&1 || true
      sleep 0.1
    done
    echo "port 8080 still open" >&2; exit 1 ;;
  cmd) bash "$COMP/${2:?name}/run.sh" --print ;;
  binary) bash "$COMP/${2:?name}/run.sh" --binary ;;
  version) bash "$COMP/${2:?name}/run.sh" --version ;;
  pss)
    t=0
    for p in $(cat $CG/cgroup.procs 2>/dev/null); do
      v=$(awk '/^Pss:/ {print $2}' /proc/$p/smaps_rollup 2>/dev/null || echo 0); t=$((t + ${v:-0}))
    done
    echo $t ;;
  mem) echo "$(( $(cat $CG/memory.current) / 1024 )) $(( $(cat $CG/memory.peak 2>/dev/null || echo 0) / 1024 ))" ;;
  cpu_us) awk '/^usage_usec/ {print $2}' $CG/cpu.stat ;;
  *) echo "usage: see the header of $0" >&2; exit 1 ;;
esac
