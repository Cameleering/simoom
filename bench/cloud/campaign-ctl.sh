#!/usr/bin/env bash
# Operator side of the campaign (bench/cloud/campaign.sh runs on load1). From the simoom checkout:
#
#   campaign-ctl.sh up        create srvA, srvB, load1..3 (c-4, blr1, tagged simoom-bench)
#   campaign-ctl.sh setup     ship the trees, shared certificate and keys, prepare every node
#   campaign-ctl.sh start     start (or resume) the campaign on load1 in the background
#   campaign-ctl.sh status    tail of the campaign log and record counts
#   campaign-ctl.sh fetch     copy the results to bench/results/<date>-<label>/raw/<session>/
#   campaign-ctl.sh pull      copy only what changed since the last pull (incremental fetch)
#   campaign-ctl.sh follow    pull every FOLLOW_S seconds (120) until the campaign has finished;
#                             run it in the background so nothing is lost if the operator stops
#   campaign-ctl.sh merge     combine raw/*/ (sessions) into results.txt, machine.txt, hdr/, prof/
#   campaign-ctl.sh lanes     three lanes at once (1 server + 2 load nodes each, srvA-C rotating per
#                             round): LANE1/LANE2/LANE3 are the lanes' server lists; DONE cells of
#                             /root/campaign/out carry over. Pull a lane with REMOTE_OUT=/root/campaign/laneN/out
#                             SESSION=laneN campaign-ctl.sh pull|follow
#   campaign-ctl.sh sh NODE   a shell command on a node (srvA, srvB, load1..3): campaign-ctl.sh sh load1 'uptime'
#   campaign-ctl.sh down      delete the droplets (droplets.sh down) and confirm none is left
#
# Environment: DO_TOKEN_FILE, SERVERS, ROUNDS or PASSES, DEADLINE (epoch s), CAMELEER_SRC (default
# ../Rust-camel), LABEL (campaign), SESSION (s1: one droplet set; a campaign may span several).
set -euo pipefail
export MSYS_NO_PATHCONV=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_DIR="${BENCH_STATE:-$ROOT/target-bench/cloud}"
export BENCH_STATE="$STATE_DIR"
STATE="$STATE_DIR/droplets.txt"
KEY="${DO_SSH_KEY:-$HOME/.ssh/id_ed25519}"
export DO_NAMES="${DO_NAMES:-simoom-bench-srvA simoom-bench-srvB simoom-bench-load1 simoom-bench-load2 simoom-bench-load3}"
# simoom first, then campaign 1's leaders, so a deadline cuts the least informative servers
SERVERS="${SERVERS:-simoom simoom-uring simoom-builder simoom-builder-uring simoom-default simoom-deferred simoom-deferred-stream simoom-blocking hyper may-minihttp xitca ntex axum h2o nginx haproxy fasthttp netty actix go-nethttp envoy caddy vertx uws kestrel cameleer-http-min cameleer}"
SESSION="${SESSION:-s1}"
RO="${REMOTE_OUT:-/root/campaign/out}"
CAMELEER_SRC="${CAMELEER_SRC:-$(cd "$ROOT/.." && pwd)/Rust-camel}"
LABEL="${LABEL:-campaign}"
OUT="${BENCH_OUT:-$ROOT/bench/results/$(date -u +%Y-%m-%d)-$LABEL}"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE_DIR/known_hosts" -o ServerAliveInterval=30 -o BatchMode=yes -o ConnectTimeout=15)
log() { printf '==> %s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
field() { awk -v n="simoom-bench-$1" -v c="$2" '$1==n {print $c}' "$STATE"; }
pub() { field "$1" 2; }
priv() { field "$1" 3; }
on() { local h; h=$(pub "$1"); shift; ssh "${SSH_OPTS[@]}" "root@$h" "$@"; }
NODES="${NODES:-srvA srvB srvC load1 load2 load3 load4 load5 load6}"
SRVN=$(for n in $NODES; do case $n in srv*) echo $n ;; esac; done | tr "
" " ")
LOADN=$(for n in $NODES; do case $n in load*) echo $n ;; esac; done | tr "
" " ")
# native git on Windows does not take MSYS paths with path conversion off
gr() { (cd "$ROOT" && git "$@"); }
gc() { (cd "$CAMELEER_SRC" && git "$@"); }

ship() {
  mkdir -p "$STATE_DIR"
  # the simoom crates pinned to SIMOOM_REV (other agents edit the working tree), the benchmark's
  # own paths from the working tree (bench/cloud/pin-tree.sh)
  local rev="${SIMOOM_REV:?set SIMOOM_REV to the measured commit}"
  log "packing simoom at $rev + the benchmark paths of the working tree"
  SIMOOM_REV="$rev" bash "$ROOT/bench/cloud/pin-tree.sh" --tgz "$STATE_DIR/simoom.tgz"
  tar -xzOf "$STATE_DIR/simoom.tgz" ./PIN.txt > "$STATE_DIR/tree.txt"
  local chead; chead=$(gc rev-parse --short HEAD)
  echo "cameleer head: $chead ($(gc rev-parse --abbrev-ref HEAD), committed tree)" >> "$STATE_DIR/tree.txt"
  gc archive --format=tar.gz HEAD > "$STATE_DIR/cameleer.tgz"
  for n in $NODES; do
    { scp -q "${SSH_OPTS[@]}" "$STATE_DIR/simoom.tgz" "$STATE_DIR/tree.txt" "root@$(pub $n):/root/" &&
      on $n "rm -rf /root/simoom && mkdir -p /root/simoom && tar -xzf /root/simoom.tgz -C /root/simoom 2>/dev/null && chmod +x /root/simoom/bench/*/*.sh /root/simoom/bench/competitors/*/*.sh"; } &
  done
  wait
  for n in $SRVN; do
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
  for n in $SRVN; do
    on $n "mkdir -p /opt/bench/cert && cat > /opt/bench/cert/cert.pem && chmod 600 /opt/bench/cert/cert.pem" <<<"$cert"
    on $n "cat > /opt/bench/cert/key.pem && chmod 600 /opt/bench/cert/key.pem && cat /opt/bench/cert/cert.pem /opt/bench/cert/key.pem > /opt/bench/cert/haproxy.pem" <<<"$key"
  done
}

setup() {
  ship
  keys
  log "preparing the nodes in parallel (logs in $STATE_DIR/setup-*.log)"
  for n in $SRVN; do on $n "bash /root/simoom/bench/cloud/setup-node.sh server '$SERVERS simoom-prof simoom-prof-uring'" > "$STATE_DIR/setup-$n.log" 2>&1 & done
  for n in $LOADN; do on $n "bash /root/simoom/bench/cloud/setup-node.sh load $(priv $n)" > "$STATE_DIR/setup-$n.log" 2>&1 & done
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
PASSES="${PASSES:-}"
DEADLINE="${DEADLINE:-0}"
EOF
}

start() {
  envfile
  on load1 "cp /root/tree.txt /root/campaign/ 2>/dev/null; mkdir -p /root/campaign/out; cp /root/tree.txt /root/campaign/out/tree.txt; nohup setsid bash /root/simoom/bench/cloud/campaign.sh > /root/campaign/out/nohup.log 2>&1 < /dev/null & echo started"
}

status() {
  on load1 'date -u; tail -n 15 /root/campaign/out/campaign.log; echo; echo "records: $(wc -l < /root/campaign/out/results.txt), done cells: $(grep -c ^DONE /root/campaign/out/results.txt)"; pgrep -f campaign.sh >/dev/null && echo running || echo "not running"'
}

fetch() {
  local dst="$OUT/raw/$SESSION"; mkdir -p "$dst"
  on load1 "cd $RO && tar -czf /root/campaign-out-$SESSION.tgz ."
  scp -q "${SSH_OPTS[@]}" "root@$(pub load1):/root/campaign-out-$SESSION.tgz" "$STATE_DIR/campaign-out.tgz"
  tar -xzf "$STATE_DIR/campaign-out.tgz" -C "$dst"
  log "results in $dst"
}

pull() { # only files changed since the last successful pull (by the remote clock, 10 s margin)
  local dst="$OUT/raw/$SESSION" since=0 stamp; mkdir -p "$dst"
  [ -f "$STATE_DIR/pull-stamp-$SESSION" ] && since=$(cat "$STATE_DIR/pull-stamp-$SESSION")
  stamp=$(on load1 "s=\$(date +%s); cd $RO && tar -czf /root/pull-$SESSION.tgz --newer-mtime=@$since . 2>/dev/null; echo \$s") || return 1
  scp -q "${SSH_OPTS[@]}" "root@$(pub load1):/root/pull-$SESSION.tgz" "$STATE_DIR/pull-$SESSION.tgz" || return 1
  tar -xzf "$STATE_DIR/pull-$SESSION.tgz" -C "$dst" || return 1
  echo $((stamp - 10)) > "$STATE_DIR/pull-stamp-$SESSION"
  log "pulled into $dst: $(wc -l < "$dst/results.txt" 2>/dev/null || echo 0) record lines, $(tail -n 1 "$dst/progress.txt" 2>/dev/null)"
}

follow() {
  while true; do
    pull || log "pull failed, retrying"
    if on load1 "grep -q '^CAMPAIGN DONE' $RO/campaign.log 2>/dev/null"; then pull; fetch; log "campaign finished"; return 0; fi
    sleep "${FOLLOW_S:-120}"
  done
}

resync() { # overlay the current pinned tree on every node (keeps the built targets), rebuild simoom-bench
  SIMOOM_REV="${SIMOOM_REV:-1e50579}" bash "$ROOT/bench/cloud/pin-tree.sh" --tgz "$STATE_DIR/simoom.tgz"
  tar -xzOf "$STATE_DIR/simoom.tgz" ./PIN.txt > "$STATE_DIR/tree.txt"
  for n in $NODES; do
    { scp -q "${SSH_OPTS[@]}" "$STATE_DIR/simoom.tgz" "$STATE_DIR/tree.txt" "root@$(pub $n):/root/" &&
      on $n "tar -xzf /root/simoom.tgz -C /root/simoom 2>/dev/null; chmod +x /root/simoom/bench/*/*.sh /root/simoom/bench/competitors/*/*.sh"; } &
  done
  wait
  for n in $SRVN; do on $n "cd /root/simoom && /root/.cargo/bin/cargo build -q --release -p simoom-bench --target-dir /root/simoom/target" > "$STATE_DIR/resync-$n.log" 2>&1 & done
  for n in $LOADN; do on $n "bash /root/simoom/bench/cloud/setup-node.sh load $(priv $n)" > "$STATE_DIR/resync-$n.log" 2>&1 & done
  wait
  for f in "$STATE_DIR"/resync-*.log; do echo "--- $f: $(tail -n 1 "$f")"; done
}

lanes() {
  local i
  on load1 'pkill -f bench/cloud/[c]ampaign.sh; pkill -f "simoom-bench (sweep|load|attack)"; sleep 1; pgrep -f bench/cloud/[c]ampaign.sh || echo "old campaign stopped"'
  for i in $SRVN; do on $i 'bash /root/simoom/bench/competitors/server.sh stop' >/dev/null 2>&1 || true; done
  for i in 1 2 3; do
    local srv loads l
    case $i in 1) loads="$(priv load1) $(priv load2)"; srv="${LANE1:?}" ;; 2) loads="$(priv load3) $(priv load4)"; srv="${LANE2:?}" ;; 3) loads="$(priv load5) $(priv load6)"; srv="${LANE3:?}" ;; esac
    on load1 "mkdir -p /root/campaign/lane$i/out/hdr && cd /root/campaign/lane$i && ln -sf ../key key && ln -sf ../key.pub key.pub && cp -n ../known_hosts known_hosts 2>/dev/null; touch out/results.txt; grep -h '^DONE ' /root/campaign/out/results.txt >> out/results.txt 2>/dev/null; cp /root/tree.txt out/tree.txt 2>/dev/null; true"
    on load1 "cat > /root/campaign/lane$i/env" <<EOF
SRV_A=$(priv srvA)
SRV_B=$(priv srvB)
LANE=$i
LANE_SRVS="$(priv srvA) $(priv srvB) $(priv srvC)"
LANE_NAMES="srvA srvB srvC"
LOADS="$loads"
SERVERS="$srv"
ROUNDS="1 2 3"
DEADLINE="${DEADLINE:-0}"
S9_RATE="${S9_RATE:-}"
PROF_SERVERS="$(eval echo \${PROF$i:-})"
PROF_CASES="${PROF_CASES:-s1 s3 s5 s8}"
EOF
    on load1 "CAMPAIGN_DIR=/root/campaign/lane$i nohup setsid bash /root/simoom/bench/cloud/campaign.sh > /root/campaign/lane$i/out/nohup.log 2>&1 < /dev/null & echo lane $i started"
  done
}

merge() { # one results.txt etc. from every session under raw/
  local s
  : > "$OUT/results.txt"; : > "$OUT/machine.txt"; : > "$OUT/campaign.log"; : > "$OUT/tree.txt"
  mkdir -p "$OUT/hdr" "$OUT/prof"
  for s in "$OUT"/raw/*/; do
    local n; n=$(basename "$s")
    [ -f "$s/results.txt" ] && grep -v '^DONE ' "$s/results.txt" | sed "s/^\([A-Z]*\) /\1 session=$n /" >> "$OUT/results.txt"
    [ -f "$s/machine.txt" ] && sed "s/^MACHINE /MACHINE session=$n /" "$s/machine.txt" >> "$OUT/machine.txt"
    [ -f "$s/campaign.log" ] && { echo "--- session $n"; cat "$s/campaign.log"; } >> "$OUT/campaign.log"
    [ -f "$s/tree.txt" ] && { echo "--- session $n"; cat "$s/tree.txt"; } >> "$OUT/tree.txt"
    [ -d "$s/hdr" ] && cp -r "$s/hdr/." "$OUT/hdr/"
    [ -d "$s/prof" ] && { mkdir -p "$OUT/prof/$n"; cp -r "$s/prof/." "$OUT/prof/$n/"; }
  done
  log "merged $(ls -d "$OUT"/raw/*/ | wc -l) sessions into $OUT"
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

# an armed safety net whose deadline passed while the operator was away (machine restarted, task
# missed) fires before anything else; the token stays on this machine
case "${1:-status}" in down|merge|sh) ;; *)
  if [ -f "$STATE_DIR/safety-net.deadline" ]; then BENCH_STATE="$STATE_DIR" bash "$ROOT/bench/cloud/safety-net.sh" due || true; fi ;;
esac
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
  pull) pull ;;
  follow) follow ;;
  merge) merge ;;
  lanes) lanes ;;
  resync) resync ;;
  sh) n=$2; shift 2; on "$n" "$@" ;;
  *) echo "usage: see the header of $0" >&2; exit 1 ;;
esac
