#!/usr/bin/env bash
# Local safety net for the benchmark droplets (Windows, Git Bash): whatever happens to the operator
# (stopped, rate-limited, machine asleep), every droplet tagged simoom-bench and the SSH key
# simoom-bench-key are deleted at a hard deadline. Campaign 1 lost about 147 droplet-hours to an
# operator that was stopped; this is the fix.
#
#   safety-net.sh arm HOURS    fire at now + HOURS (at most 10): a Windows scheduled task
#                              (wakes the machine, runs late if it was off) and a detached watcher
#                              process, independent of the shell that armed them
#   safety-net.sh fire         final incremental pull of the results (campaign-ctl.sh pull, at most
#                              10 min), then delete; logs to $BENCH_STATE/safety-net.log
#   safety-net.sh due          fire if the armed deadline has passed, else print the time left
#                              (the scheduled task runs this at the deadline and at every logon,
#                              and campaign-ctl.sh runs it before every command)
#   safety-net.sh delete       delete now, without the pull
#   safety-net.sh disarm       remove the task and stop the watcher
#   safety-net.sh status       the task, the watcher, the deadline and what is still alive
#   safety-net.sh test         arm a task 2 minutes ahead with DRY=1 (lists, deletes nothing)
#
# Campaign 3 (2026-11-11) lost about 77 droplet-hours although the net was armed: the machine
# restarted, the watcher process died with the session, and the task (registered for the logged-on
# user only) never ran. Hence `due`: the task also triggers at logon, and the operator's next
# campaign-ctl.sh command fires an overdue net before doing anything else.
#
# Deletes only droplets that carry the simoom-bench tag AND whose name starts with simoom-bench-,
# re-read by id just before the delete; never ubuntu-s-4vcpu-8gb-blr1, never an untagged droplet.
# Deletes only the SSH key named exactly simoom-bench-key. The token is read from DO_TOKEN_FILE
# here and never leaves this machine.
set -uo pipefail
export MSYS_NO_PATHCONV=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export BENCH_STATE="${BENCH_STATE:-$ROOT/target-bench2/cloud}"
mkdir -p "$BENCH_STATE"
LOG="$BENCH_STATE/safety-net.log"
TASK=simoom-bench-safety-net
TAG=simoom-bench
KEY_NAME=simoom-bench-key
NEVER=ubuntu-s-4vcpu-8gb-blr1
API=https://api.digitalocean.com/v2
DO_TOKEN_FILE="${DO_TOKEN_FILE:-C:\\Users\\SudheeshPM\\Documents\\do.config.txt}"
BASH_EXE='C:\Program Files\Git\bin\bash.exe'
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG" >&2; }

token() { grep -o 'dop_v1_[0-9a-f]\{64\}' "$DO_TOKEN_FILE" | head -1; }
api() { # api METHOD PATH: the token goes to curl through a config on stdin, never on a command line
  printf 'header = "Authorization: Bearer %s"\n' "$(token)" | curl -sS -m 60 -X "$1" -H "Content-Type: application/json" -K - "$API$2"
}
PY=python3; "$PY" -c 'import sys' 2>/dev/null || PY=python

tagged() { # id name, one tagged droplet per line
  api GET "/droplets?tag_name=$TAG&per_page=200" | "$PY" -c "
import json,sys
for d in json.load(sys.stdin).get('droplets', []):
    if '$TAG' in d.get('tags', []): print(d['id'], d['name'])"
}

delete_all() {
  local n=0 id name ok
  while read -r id name; do
    [ -n "$id" ] || continue
    ok=$(api GET "/droplets/$id" | "$PY" -c "
import json,sys
d=json.load(sys.stdin).get('droplet',{})
n=d.get('name','')
print('yes' if '$TAG' in d.get('tags',[]) and n.startswith('simoom-bench-') and n != '$NEVER' else 'no')")
    if [ "$ok" != yes ]; then log "refusing droplet $id ($name): tag or name check failed"; continue; fi
    if [ "${DRY:-0}" = 1 ]; then log "DRY: would delete droplet $id ($name)"; continue; fi
    api DELETE "/droplets/$id" >/dev/null && log "deleting droplet $id ($name)"; n=$((n + 1))
  done < <(tagged)
  if [ "${DRY:-0}" != 1 ]; then
    for _ in $(seq 60); do [ -z "$(tagged)" ] && break; sleep 5; done
  fi
  local kid
  kid=$(api GET "/account/keys?per_page=200" | "$PY" -c "
import json,sys
for k in json.load(sys.stdin).get('ssh_keys', []):
    if k['name'] == '$KEY_NAME': print(k['id'])")
  for k in $kid; do
    if [ "${DRY:-0}" = 1 ]; then log "DRY: would delete SSH key $k ($KEY_NAME)"; continue; fi
    api DELETE "/account/keys/$k" >/dev/null && log "deleted SSH key $k ($KEY_NAME)"
  done
  rm -f "$BENCH_STATE/uploaded-key-id"
  log "remaining tagged droplets: $(tagged | wc -l); key $KEY_NAME present: $([ -n "$(api GET "/account/keys?per_page=200" | grep -o "\"name\":\"$KEY_NAME\"")" ] && echo yes || echo no)"
}

case "${1:-status}" in
  arm)
    h="${2:?hours}"
    awk -v h="$h" 'BEGIN { exit !(h > 0 && h <= 10) }' || { echo "HOURS must be in (0, 10]" >&2; exit 1; }
    secs=$(awk -v h="$h" 'BEGIN { printf "%d", h * 3600 }')
    at=$(( $(date +%s) + secs ))
    echo "$at" > "$BENCH_STATE/safety-net.deadline"
    out="${BENCH_OUT:-$ROOT/bench/results/$(date -u +%F)-${LABEL:-campaign2}}"
    cmd="cd '$ROOT' && BENCH_STATE='$BENCH_STATE' BENCH_OUT='$out' DO_TOKEN_FILE='$DO_TOKEN_FILE' SESSION='${SESSION:-s1}' DRY='${DRY:-0}' bash bench/cloud/safety-net.sh due"
    printf '%s\n' "$cmd" > "$BENCH_STATE/safety-net.cmd"
    # the scheduled task: wakes the machine, starts as soon as possible if the time was missed
    powershell.exe -NoProfile -Command "
      \$a = New-ScheduledTaskAction -Execute '$BASH_EXE' -Argument '-lc \"bash ''$BENCH_STATE/safety-net.cmd''\"'
      \$t = @((New-ScheduledTaskTrigger -Once -At ([DateTimeOffset]::FromUnixTimeSeconds($at).LocalDateTime)), (New-ScheduledTaskTrigger -AtLogOn -User \$env:USERNAME))
      \$s = New-ScheduledTaskSettingsSet -WakeToRun -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
      Register-ScheduledTask -TaskName '$TASK' -Action \$a -Trigger \$t -Settings \$s -Force | Out-Null
      (Get-ScheduledTask -TaskName '$TASK').State" || { echo "scheduled task failed" >&2; exit 1; }
    # the watcher: a separate hidden process, not a child of this shell
    wpid=$(powershell.exe -NoProfile -Command "(Start-Process -WindowStyle Hidden -PassThru -FilePath '$BASH_EXE' -ArgumentList '-lc \"sleep $secs; bash ''$BENCH_STATE/safety-net.cmd''\"').Id" | tr -d '\r')
    echo "$wpid" > "$BENCH_STATE/safety-net.watcher"
    log "armed: fires at $(date -u -d @$at +%FT%TZ) (task $TASK, watcher pid $wpid)"
    ;;
  fire)
    log "firing (deadline reached)"
    if [ -f "$BENCH_STATE/droplets.txt" ] && [ "${DRY:-0}" != 1 ]; then
      timeout 600 bash "$ROOT/bench/cloud/campaign-ctl.sh" pull >> "$LOG" 2>&1 && log "final pull done" || log "final pull failed or timed out"
    fi
    delete_all
    ;;
  due)
    [ -f "$BENCH_STATE/safety-net.deadline" ] || { echo "safety net: not armed" >&2; exit 0; }
    d=$(cat "$BENCH_STATE/safety-net.deadline")
    if [ "$(date +%s)" -ge "$d" ]; then
      log "deadline $(date -u -d @"$d" +%FT%TZ) has passed: firing now"
      "$0" fire
      rm -f "$BENCH_STATE/safety-net.deadline"
    else
      echo "safety net: $(( (d - $(date +%s)) / 60 )) min left" >&2
    fi
    ;;
  delete) delete_all ;;
  disarm)
    powershell.exe -NoProfile -Command "Unregister-ScheduledTask -TaskName '$TASK' -Confirm:\$false -ErrorAction SilentlyContinue; if (Get-ScheduledTask -TaskName '$TASK' -ErrorAction SilentlyContinue) { 'task still present' } else { 'task removed' }"
    if [ -f "$BENCH_STATE/safety-net.watcher" ]; then
      w=$(cat "$BENCH_STATE/safety-net.watcher")
      # the watcher is bash.exe running sleep; stop it and its children
      taskkill.exe /PID "$w" /T /F >/dev/null 2>&1 && log "watcher $w stopped" || log "watcher $w not running"
      rm -f "$BENCH_STATE/safety-net.watcher"
    fi
    rm -f "$BENCH_STATE/safety-net.deadline"
    log "disarmed"
    ;;
  status)
    powershell.exe -NoProfile -Command "\$t = Get-ScheduledTask -TaskName '$TASK' -ErrorAction SilentlyContinue; if (\$t) { 'task: ' + \$t.State + ', next run ' + (Get-ScheduledTaskInfo -TaskName '$TASK').NextRunTime } else { 'task: none' }"
    if [ -f "$BENCH_STATE/safety-net.watcher" ]; then
      w=$(cat "$BENCH_STATE/safety-net.watcher")
      echo "watcher pid $w: $(tasklist.exe /FI "PID eq $w" /NH 2>/dev/null | grep -q "$w" && echo running || echo gone)"
    fi
    [ -f "$BENCH_STATE/safety-net.deadline" ] && echo "deadline: $(date -u -d @"$(cat "$BENCH_STATE/safety-net.deadline")" +%FT%TZ) ($(( ($(cat "$BENCH_STATE/safety-net.deadline") - $(date +%s)) / 60 )) min left)"
    echo "tagged droplets:"; tagged | sed 's/^/  /'
    ;;
  test)
    DRY=1 SESSION=test bash "$0" arm 0.034
    ;;
  *) echo "usage: see the header of $0" >&2; exit 1 ;;
esac
