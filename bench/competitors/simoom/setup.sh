#!/usr/bin/env bash
# simoom: simoom-bench's campaign server and the facade's bench_server example (its size is
# recorded too), built from the simoom source shipped by bench/cloud/run.sh to /root/simoom.
. "$(dirname "$0")/../lib.sh"
ensure_rust
ensure_cert
cd /root/simoom
cargo build -q --release -p simoom-bench --target-dir /root/simoom/target
cargo build -q --release -p simoom --example bench_server --target-dir /root/simoom/target
