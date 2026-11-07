#!/usr/bin/env bash
# The `cameleer` CLI built from the Cameleer source shipped by bench/cloud/run.sh to
# /root/cameleer (a `git archive` of E:\Work\DataHQ\Code\Rust-camel main).
. "$(dirname "$0")/../lib.sh"
ensure_rust
[ -d /root/cameleer ] || { echo "no /root/cameleer: run.sh ships it when cameleer is in SERVERS" >&2; exit 1; }
(cd /root/cameleer && CARGO_TARGET_DIR=/root/cameleer/target cargo build -q --release -p cameleer-main --bin cameleer)
