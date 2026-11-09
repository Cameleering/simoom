#!/usr/bin/env bash
# Create and delete the DigitalOcean droplets of the simoom benchmark: one server and three load
# nodes (c-4, blr1), all tagged simoom-bench, in the region's default VPC.
#
#   bench/cloud/droplets.sh up       create the droplets (prints name and IPs) and upload the SSH key
#   bench/cloud/droplets.sh status   list droplets tagged simoom-bench and the SSH key
#   bench/cloud/droplets.sh down     delete ONLY droplets tagged simoom-bench, and the SSH key if
#                                    this script uploaded it; then confirm none is left
#
# Safety: every delete is by droplet id, after re-reading that droplet and checking it carries the
# simoom-bench tag. A droplet without the tag (such as ubuntu-s-4vcpu-8gb-blr1) is never touched.
#
# Environment:
#   DO_TOKEN_FILE   file holding a DigitalOcean API token (read here only, never printed)
#   DO_REGION (blr1), DO_SIZE (c-4), DO_SSH_PUB (~/.ssh/id_ed25519.pub)
#   DO_NAMES        droplet names (default: simoom-bench-srv simoom-bench-load1..3)
#   BENCH_STATE     state directory (default target-bench/cloud)
set -euo pipefail

TAG=simoom-bench
KEY_NAME=simoom-bench-key
REGION="${DO_REGION:-blr1}"
SIZE="${DO_SIZE:-c-4}"
IMAGE=ubuntu-24-04-x64
read -r -a NAMES <<< "${DO_NAMES:-simoom-bench-srv simoom-bench-load1 simoom-bench-load2 simoom-bench-load3}"
SSH_PUB="${DO_SSH_PUB:-$HOME/.ssh/id_ed25519.pub}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_DIR="${BENCH_STATE:-$ROOT/target-bench/cloud}"
STATE="$STATE_DIR/droplets.txt"
API=https://api.digitalocean.com/v2
mkdir -p "$STATE_DIR"

[ -n "${DO_TOKEN_FILE:-}" ] && [ -f "$DO_TOKEN_FILE" ] || { echo "set DO_TOKEN_FILE to the token file" >&2; exit 1; }
TOKEN="$(grep -o 'dop_v1_[0-9a-f]\{64\}' "$DO_TOKEN_FILE" | head -1)"
[ -n "$TOKEN" ] || { echo "no DigitalOcean token in $DO_TOKEN_FILE" >&2; exit 1; }

api() { # api METHOD PATH [JSON]; the token goes in a header read from stdin-free config
  local args=(-sS -X "$1" -H "Content-Type: application/json" -K -)
  [ $# -ge 3 ] && args+=(-d "$3")
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl "${args[@]}" "$API$2"
}

PY=python3
"$PY" -c 'import sys' 2>/dev/null || PY=python
py() { "$PY" -c "$@"; }

key_id() { # the id of our key, by name
  api GET "/account/keys?per_page=200" | py "
import json,sys
for k in json.load(sys.stdin)['ssh_keys']:
    if k['name']=='$KEY_NAME': print(k['id'])"
}

list() { # name public_ip private_ip status size region id, one tagged droplet per line
  api GET "/droplets?tag_name=$TAG&per_page=200" | py "
import json,sys
for d in json.load(sys.stdin)['droplets']:
    if '$TAG' not in d.get('tags', []): continue
    ip=lambda t: next((n['ip_address'] for n in d['networks']['v4'] if n['type']==t), '-')
    print(d['name'], ip('public'), ip('private'), d['status'], d['size_slug'], d['region']['slug'], d['id'])"
}

vpc_id() {
  api GET "/vpcs?per_page=200" | py "
import json,sys
for v in json.load(sys.stdin)['vpcs']:
    if v['region']=='$REGION' and v.get('default'): print(v['id'])"
}

up() {
  # DO_ADD=1: add droplets (DO_NAMES) next to the tagged ones that already exist
  if [ -n "$(list)" ] && [ "${DO_ADD:-0}" != 1 ]; then echo "droplets tagged $TAG already exist:" >&2; list >&2; exit 1; fi
  local kid; kid="$(key_id)"
  if [ -z "$kid" ]; then
    local pub; pub="$(cat "$SSH_PUB")"
    kid="$(api POST /account/keys "{\"name\":\"$KEY_NAME\",\"public_key\":\"$pub\"}" | py "import json,sys; r=json.load(sys.stdin); print(r['ssh_key']['id']) if 'ssh_key' in r else sys.exit('key upload failed: '+r.get('message',''))")"
    echo "$kid" > "$STATE_DIR/uploaded-key-id"
  fi
  local vpc; vpc="$(vpc_id)"
  local names; names="$(printf '"%s",' "${NAMES[@]}")"
  local vpcj=""; [ -n "$vpc" ] && vpcj=",\"vpc_uuid\":\"$vpc\""
  api POST /droplets "{\"names\":[${names%,}],\"region\":\"$REGION\",\"size\":\"$SIZE\",\"image\":\"$IMAGE\",\"ssh_keys\":[$kid],\"tags\":[\"$TAG\"],\"monitoring\":false,\"ipv6\":false$vpcj}" \
    | py "import json,sys; r=json.load(sys.stdin); print('created:', [d['name'] for d in r['droplets']]) if 'droplets' in r else sys.exit('create failed: '+r.get('message',''))"
  echo "waiting for the droplets to become active" >&2
  local want=${#NAMES[@]}; [ "${DO_ADD:-0}" = 1 ] && want=$(( $(list | wc -l) ))
  for _ in $(seq 90); do
    if [ "$(list | awk '$4=="active" && $3!="-"' | wc -l)" -ge "$want" ]; then break; fi
    sleep 5
  done
  list | tee "$STATE"
  [ -f "$STATE_DIR/created-at" ] || date -u +%s > "$STATE_DIR/created-at"
}

down() {
  local ids; ids="$(list | awk '{print $7}')"
  for id in $ids; do
    # re-read the droplet and check the tag once more before deleting it
    local ok; ok="$(api GET "/droplets/$id" | py "
import json,sys
d=json.load(sys.stdin).get('droplet',{})
print('yes' if '$TAG' in d.get('tags',[]) and d.get('name','').startswith('simoom-bench') else 'no')")"
    if [ "$ok" = yes ]; then
      api DELETE "/droplets/$id" >/dev/null && echo "deleting droplet $id" >&2
    else
      echo "refusing to delete droplet $id: tag or name check failed" >&2
    fi
  done
  for _ in $(seq 60); do [ -z "$(list)" ] && break; sleep 5; done
  if [ -f "$STATE_DIR/uploaded-key-id" ]; then
    local kid; kid="$(cat "$STATE_DIR/uploaded-key-id")"
    if [ "$(key_id)" = "$kid" ]; then api DELETE "/account/keys/$kid" >/dev/null && echo "deleted SSH key $KEY_NAME" >&2; fi
    rm -f "$STATE_DIR/uploaded-key-id"
  fi
  [ -f "$STATE_DIR/created-at" ] && echo "droplets lived $(( ($(date -u +%s) - $(cat "$STATE_DIR/created-at")) / 60 )) min" >&2
  rm -f "$STATE_DIR/created-at"
  status
}

status() {
  echo "droplets tagged $TAG:"; list | sed 's/^/  /'
  echo "remaining tagged droplets: $(list | wc -l)"
  echo "SSH key $KEY_NAME: $(key_id || true)"
}

case "${1:-status}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|status|down" >&2; exit 1 ;;
esac
