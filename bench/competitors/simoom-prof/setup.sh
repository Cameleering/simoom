#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
ensure_rust
cd /root/simoom && RUSTFLAGS="-C force-frame-pointers=yes" cargo build -q --release -p simoom-bench --bin simoom-server --target-dir /root/simoom/target-fp
