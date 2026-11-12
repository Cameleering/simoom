#!/usr/bin/env bash
# simoom at campaign 2's pinned commit (1e50579), for the K12 same-droplet A/B: the operator ships
# that tree to /root/simoom-c2 (bench/cloud/pin-tree.sh with SIMOOM_REV=1e50579, see ab.sh).
. "$(dirname "$0")/../lib.sh"
ensure_rust
ensure_cert
cd /root/simoom-c2
cargo build -q --release -p simoom-bench --target-dir /root/simoom-c2/target
