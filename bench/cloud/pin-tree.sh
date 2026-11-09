#!/usr/bin/env bash
# The simoom tree a campaign measures: the simoom crates exactly as committed at SIMOOM_REV
# (default 1e50579; other agents edit the live working tree in parallel), with the benchmark's own
# paths overlaid from the working tree (crates/simoom-bench, bench/, scripts/bench*).
#
#   bench/cloud/pin-tree.sh DEST          write the tree into DEST (emptied first)
#   bench/cloud/pin-tree.sh --tgz FILE    the same as a .tgz
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REV="${SIMOOM_REV:-1e50579}"
OVERLAY="crates/simoom-bench bench scripts/bench-facade.sh scripts/bench-modes.sh scripts/bench-validate.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
(cd "$ROOT" && git archive --format=tar "$REV") | tar -xf - -C "$T"
for p in $OVERLAY; do
  [ -e "$ROOT/$p" ] || continue
  rm -rf "${T:?}/$p"; mkdir -p "$T/$(dirname "$p")"
  tar -C "$ROOT" --exclude='./bench/results' --exclude='bench/results' --exclude='*/target' -cf - "$p" | tar -xf - -C "$T"
done
rm -rf "$T/bench/results"
{ echo "simoom commit (measured): $(cd "$ROOT" && git rev-parse "$REV")"
  echo "overlaid from the working tree: $OVERLAY"
  echo "benchmark diff against $REV:"; (cd "$ROOT" && git diff --stat "$REV" -- $OVERLAY; git ls-files --others --exclude-standard -- $OVERLAY | sed 's/^/  new: /')
  echo "crates outside the overlay differ from the working tree in: $(cd "$ROOT" && git diff --name-only "$REV" -- crates | grep -v '^crates/simoom-bench/' | tr '\n' ' ')"
} > "$T/PIN.txt"
echo "$(cd "$ROOT" && git rev-parse --short "$REV")+bench" > "$T/REVISION"
if [ "$1" = --tgz ]; then tar -C "$T" -czf "$2" .; else rm -rf "${1:?}"; mkdir -p "$1"; cp -r "$T/." "$1/"; fi
