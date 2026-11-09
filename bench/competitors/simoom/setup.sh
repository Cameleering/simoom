#!/usr/bin/env bash
# simoom: simoom-bench's campaign server and the facade's bench_server example (its size is
# recorded too), built from the simoom source shipped by bench/cloud/run.sh to /root/simoom.
. "$(dirname "$0")/../lib.sh"
ensure_rust
ensure_cert
cd /root/simoom
cargo build -q --release -p simoom-bench --target-dir /root/simoom/target
cargo build -q --release -p simoom --example bench_server --target-dir /root/simoom/target
# The smallest server, plain (default features) and with TLS, for the like-for-like cold start
# against cameleer-http-min (docs/STATUS.md); own target directories so features don't unify.
cargo build -q --release -p simoom --example min_server --target-dir /root/simoom/target-minplain
cargo build -q --release -p simoom --features tls --example min_server --target-dir /root/simoom/target-mintls
