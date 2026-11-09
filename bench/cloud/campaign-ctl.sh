#!/usr/bin/env bash
# Operator side of the campaign (bench/cloud/campaign.sh runs on load1). From the simoom checkout:
#
#   campaign-ctl.sh up        create srvA, srvB, load1..3 (c-4, blr1, tagged simoom-bench)
#   campaign-ctl.sh setup     ship the trees, shared certificate and keys, prepare every node
#   campaign-ctl.sh start     start (or resume) the campaign on load1 in the background
#   campaign-ctl.sh status    tail of the campaign log and record counts
#   campaign-ctl.sh fetch     copy the results to bench/results/<date>-campaign/
#   campaign-ctl.sh sh NODE   a shell command on a node (srvA, srvB, load1..3): campaign-ctl.sh sh load1 'uptime'
#   campaign-ctl.sh down      delete the droplets (droplets.sh down) and confirm none is left
#
# Environment: DO_TOKEN_FILE, SERVERS, ROUNDS, CAMELEER_SRC (default ../Rust-camel), LABEL (campaign).
set -euo pipefail
export MSYS_NO_PATHCONV=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_DIR="${BENCH_STATE:-$ROOT/target-bench/cloud}"
export BENCH_STATE="$STATE_DIR"
STATE="$STATE_DIR/droplets.txt"
KEY="${DO_SSH_KEY:-$HOME/.ssh/id_ed25519}"
export DO_NAMES="${DO_NAMES:-simoom-bench-srvA simoom-bench-srvB simoom-bench-load1 simoom-bench-load2 simoom-bench-load3}"
SERVERS="${SERVERS:-simoom simoom-uring simoom-builder simoom-builder-uring nginx h2o haproxy envoy caddy hyper axum actix may-minihttp xitca ntex go-nethttp fasthttp netty vertx uws kestrel cameleer}"
CAMELEER_SRC="${CAMELEER_SRC:-$(cd "$ROOT/.." && pwd)/Rust-camel}"
LABEL="${LABEL:-campaign}"
OUT="${BENCH_OUT:-$ROOT/bench/results/$(date -u +%Y-%m-%d)-$LABEL}"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE_DIR/known_hosts" -o ServerAliveInterval=30 -o BatchMode=yes -o ConnectTimeout=15)
log() { printf '==> %s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
field() { awk -v n="simoom-bench-$1" -v c="$2" '$1==n {print $c}' "$STATE"; }
pub() { field "$1" 2; }
priv() { field "$1" 3; }
on() { local h; h=$(pub "$1"); shift; ssh "${SSH_OPTS[@]}" "root@$h" "$@"; }
NODES="srvA srvB load1 load2 load3"
# native git on Windows does not take MSYS paths with path conversion off
gr() { (cd "$ROOT" && git "$@"); }
gc() { (cd "$CAMELEER_SRC" && git "$@"); }

ship() {
  mkdir -p "$STATE_DIR"
  local head diff; head=$(gr rev-parse --short HEAD)
  diff=$(gr diff --stat | tail -1)
  log "packing simoom at $head + working tree ($diff)"
  { echo "simoom head: $head"; echo "simoom diff --stat:"; gr diff --stat; echo "untracked:"; gr ls-files --others --exclude-standard; } > "$STATE_DIR/tree.txt"
  tar -C "$ROOT" --exclude='./target*' --exclude='./.git' --exclude='./bench/results' --exclude='*/target' --exclude='./.claude' -czf "$STATE_DIR/simoom.tgz" .
  local chead; chead=$(gc rev-parse --short HEAD)
  echo "cameleer head: $chead ($(gc rev-parse --abbrev-ref HEAD), committed tree)" >> "$STATE_DIR/tree.txt"
  gc archive --format=tar.gz HEAD > "$STATE_DIR/cameleer.tgz"
  for n in $NODES; do
    { scp -q "${SSH_OPTS[@]}" "$STATE_DIR/simoom.tgz" "$STATE_DIR/tree.txt" "root@$(pub $n):/root/" &&
      on $n "rm -rf /root/simoom && mkdir -p /root/simoom && tar -xzf /root/simoom.tgz -C /root/simoom 2>/dev/null && echo $head+worktree > /root/simoom/REVISION && chmod +x /root/simoom/bench/*/*.sh /root/simoom/bench/competitors/*/*.sh"; } &
  done
  wait
  for n in srvA srvB; do
    { scp -q "${SSH_OPTS[@]}" "$STATE_DIR/cameleer.tgz" "root@$(pub $n):/root/cameleer.tgz" && on $n 'rm -rf /root/cameleer && mkdir -p /root/cameleer && tar -xzf /root/cameleer.tgz -C /root/cameleer'; } &
  done
  wait
}

keys() {
  log "certificate and campaign key from load1"
  on load1 'mkdir -p /root/campaign && cd /root/campaign && [ -f key ] || ssh-keygen -q -t ed25519 -N "" -f key; [ -f /root/bench-key.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=bench.local" -addext "subjectAltName=DNS:bench.local" -keyout /root/bench-key.pem -out /root/bench-ca.pem 2>/dev/null'
  local kp cert key; kp=$(on load1 'cat /root/campaign/key.pub'); cert=$(on load1 'cat /root/bench-ca.pem'); key=$(on load1 'cat /root/bench-key.pem')
  for n in $NODES; do
    on $n "grep -qF '$kp' /root/.ssh/authorized_keys || echo '$kp' >> /root/.ssh/authorized_keys"
  done
  for n in srvA srvB; do
    on $n "mkdir -p /opt/bench/cert && cat > /opt/bench/cert/cert.pem && chmod 600 /opt/bench/cert/cert.pem" <<<"$cert"
    on $n "cat > /opt/bench/cert/key.pem && chmod 600 /opt/bench/cert/key.pem && cat /opt/bench/cert/cert.pem /opt/bench/cert/key.pem > /opt/bench/cert/haproxy.pem" <<<"$key"
  done
}

setup() {
  ship
  keys
  log "preparing the nodes in parallel (logs in $STATE_DIR/setup-*.log)"
  for n in srvA srvB; do on $n "bash /root/simoom/bench/cloud/setup-node.sh server '$SERVERS simoom-prof'" > "$STATE_DIR/setup-$n.log" 2>&1 & done
  for n in load1 load2 load3; do on $n "bash /root/simoom/bench/cloud/setup-node.sh load $(priv $n)" > "$STATE_DIR/setup-$n.log" 2>&1 & done
  wait || true
  for f in "$STATE_DIR"/setup-*.log; do echo "--- $f"; tail -n 3 "$f"; done
  grep -h "SETUP FAILED" "$STATE_DIR"/setup-srv*.log || true
}

envfile() {
  on load1 "cat > /root/campaign/env" <<EOF
SRV_A=$(priv srvA)
SRV_B=$(priv srvB)
LOADS="$(priv load1) $(priv load2) $(priv load3)"
SERVERS="$SERVERS"
ROUNDS="${ROUNDS:-1 2 3}"
SCENARIOS="${SCENARIOS:-}"
EOF
}

start() {
  envfile
  on load1 "cp /root/tree.txt /root/campaign/ 2>/dev/null; mkdir -p /root/campaign/out; cp /root/tree.txt /root/campaign/out/tree.txt; nohup setsid bash /root/simoom/bench/cloud/campaign.sh > /root/campaign/out/nohup.log 2>&1 < /dev/null & echo started"
}

status() {
  on load1 'tail -n 15 /root/campaign/out/campaign.log; echo; echo "records: $(wc -l < /root/campaign/out/results.txt), done cells: $(grep -c ^DONE /root/campaign/out/results.txt)"; pgrep -f campaign.sh >/dev/null && echo running || echo "not running"'
}

fetch() {
  mkdir -p "$OUT"
  on load1 'cd /root/campaign/out && tar -czf /root/campaign-out.tgz .'
  scp -q "${SSH_OPTS[@]}" "root@$(pub load1):/root/campaign-out.tgz" "$STATE_DIR/campaign-out.tgz"
  tar -xzf "$STATE_DIR/campaign-out.tgz" -C "$OUT"
  log "results in $OUT"
}

syncbench() { # ship bench/ again (scripts and configs only, no rebuild)
  tar -C "$ROOT" --exclude='./bench/results' -czf "$STATE_DIR/bench.tgz" ./bench
  for n in $NODES; do
    { scp -q "${SSH_OPTS[@]}" "$STATE_DIR/bench.tgz" "root@$(pub $n):/root/bench.tgz" && on $n 'cd /root/simoom && tar -xzf /root/bench.tgz && chmod +x bench/*/*.sh bench/competitors/*/*.sh'; } &
  done
  wait
}

waitssh() {
  for n in $NODES; do
    for _ in $(seq 60); do on $n true 2>/dev/null && break; sleep 5; done
  done
}

case "${1:-status}" in
  all) bash "$ROOT/bench/cloud/droplets.sh" up && waitssh && setup && start ;;
  syncbench) syncbench ;;
  up) bash "$ROOT/bench/cloud/droplets.sh" up ;;
  down) bash "$ROOT/bench/cloud/droplets.sh" down ;;
  ship) ship ;;
  keys) keys ;;
  setup) setup ;;
  start) start ;;
  status) status ;;
  fetch) fetch ;;
  sh) n=$2; shift 2; on "$n" "$@" ;;
  *) echo "usage: see the header of $0" >&2; exit 1 ;;
esac
