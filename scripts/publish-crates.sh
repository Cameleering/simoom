#!/usr/bin/env bash
# Publish every simoom crate to crates.io in dependency order.
#
#   scripts/publish-crates.sh            # needs `cargo login` first
#   DRY_RUN=1 scripts/publish-crates.sh  # package and verify only
#
# Versions already on crates.io are skipped, so the script can be re-run after an
# interruption. crates.io rate-limits new crate names (a short burst, then one about every
# 10 minutes) and new versions; on HTTP 429 the script waits and retries.
set -euo pipefail
cd "$(dirname "$0")/.."

UA="simoom-publish-script"
PY=python3; command -v python3 >/dev/null 2>&1 && python3 -c "" 2>/dev/null || PY=python
VERSION=$(cargo metadata --format-version 1 --no-deps | "$PY" -c 'import json,sys; m=json.load(sys.stdin); print(next(p["version"] for p in m["packages"] if p["name"]=="simoom"))')

# topological order of the publishable workspace crates (internal normal dependencies only)
ORDER=$(cargo metadata --format-version 1 --no-deps | "$PY" -c '
import json, sys
m = json.load(sys.stdin)
pkgs = {p["name"]: p for p in m["packages"] if p.get("publish") != []}
deps = {n: {d["name"] for d in p["dependencies"] if d["name"] in pkgs and d.get("kind") is None} for n, p in pkgs.items()}
done, out = set(), []
while len(out) < len(pkgs):
    ready = sorted(n for n in pkgs if n not in done and deps[n] <= done)
    if not ready:
        sys.exit("dependency cycle among " + ", ".join(sorted(set(pkgs) - done)))
    for n in ready:
        done.add(n); out.append(n)
print(" ".join(out))
')

echo "simoom $VERSION, publishing in order: $ORDER"
for crate in $ORDER; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA" "https://crates.io/api/v1/crates/$crate/$VERSION")
  if [ "$code" = "200" ]; then
    echo "== $crate $VERSION is already on crates.io, skipping"
    continue
  fi
  if [ -n "${DRY_RUN:-}" ]; then
    cargo publish -p "$crate" --dry-run --no-verify
    continue
  fi
  for attempt in $(seq 1 12); do
    echo "== publishing $crate $VERSION (attempt $attempt)"
    if out=$(cargo publish -p "$crate" 2>&1); then
      echo "$out" | tail -3
      break
    fi
    echo "$out" | tail -5
    if echo "$out" | grep -q -E "429|Too Many Requests|rate limit"; then
      echo "   rate-limited by crates.io; waiting 10 minutes"
      sleep 600
    else
      echo "   failed for another reason; stopping" >&2
      exit 1
    fi
  done
done
echo "done: https://crates.io/crates/simoom"
