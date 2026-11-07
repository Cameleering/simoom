#!/usr/bin/env bash
# simoom: the facade's bench_server example when it exists, else the simoom-rt raw responder
# (`simoom-bench raw`). Built from the simoom source shipped by bench/cloud/run.sh to /root/simoom.
. "$(dirname "$0")/../lib.sh"
ensure_rust
cd /root/simoom
cargo build -q --release -p simoom-bench --target-dir /root/simoom/target
if [ -f crates/simoom/examples/bench_server.rs ]; then
  cargo build -q --release -p simoom --example bench_server --target-dir /root/simoom/target || echo "bench_server did not build; using the raw responder" >&2
fi
