#!/usr/bin/env bash
# Builds and prints the path of the Cameleer client baseline (Linux or Git Bash). Compare with
# simoom-client's `client_bench` example (scripts/client-bench.sh runs both).
set -e
cd "$(dirname "$0")"
cargo build -q --release
echo "$(pwd)/target/release/cameleer-client-min"
