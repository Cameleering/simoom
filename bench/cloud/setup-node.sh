#!/usr/bin/env bash
# Prepare one Ubuntu 24.04 droplet of the simoom benchmark. Runs as root on the droplet, from the
# unpacked simoom tree (/root/simoom).
#
#   setup-node.sh server "nginx h2o ..."     OS settings, tools, and the competitors to run
#   setup-node.sh load <private-ip>          OS settings, simoom-bench, and the agent on <ip>:7070
#
# Every node gets the same kernel settings. Downloads are pinned and checksum-verified
# (bench/competitors/versions.env).
set -euo pipefail
ROLE="${1:?server|load}"
SRC=/root/simoom
. "$SRC/bench/competitors/lib.sh"

base() {
  log "waiting for cloud-init and apt"
  cloud-init status --wait >/dev/null 2>&1 || true
  systemctl stop unattended-upgrades apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  export DEBIAN_FRONTEND=noninteractive
  for _ in $(seq 30); do apt-get update -qq && break; sleep 5; done
  apt_install build-essential pkg-config curl ca-certificates sysstat time unzip openssl
  apt_install "linux-tools-$(uname -r)" linux-tools-common || true
  apt_install bpftrace || true
  log "kernel settings (the same on every node; busy_poll left at its default)"
  cat > /etc/sysctl.d/90-bench.conf <<'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.core.netdev_max_backlog = 65536
fs.file-max = 4194304
fs.nr_open = 4194304
net.ipv4.tcp_fin_timeout = 15
EOF
  sysctl -q --system
  ensure_rust
  rustc -V >&2
}

case "$ROLE" in
  server)
    base
    log "building simoom-bench (cold-start timer)"
    (cd "$SRC" && cargo build -q --release -p simoom-bench --target-dir "$SRC/target")
    for n in ${2:-}; do
      log "competitor $n"
      bash "$COMP/server.sh" setup "$n" >"/root/setup-$n.log" 2>&1 || { tail -30 "/root/setup-$n.log" >&2; echo "SETUP FAILED $n" >&2; }
    done
    ;;
  load)
    ip="${2:?private ip}"
    base
    log "building simoom-bench"
    (cd "$SRC" && cargo build -q --release -p simoom-bench --target-dir "$SRC/target")
    systemctl stop bench-agent 2>/dev/null || true
    systemctl reset-failed bench-agent 2>/dev/null || true
    systemd-run -q --unit=bench-agent --collect -p LimitNOFILE=1048576 -p TasksMax=infinity \
      "$SRC/target/release/simoom-bench" agent --listen "$ip:7070"
    sleep 0.5
    systemctl is-active bench-agent >&2
    ;;
  *) echo "usage: $0 server|load" >&2; exit 1 ;;
esac
log "done"
