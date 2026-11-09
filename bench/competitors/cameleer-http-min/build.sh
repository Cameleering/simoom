#!/usr/bin/env bash
# Builds and prints the path of the baseline binary (Linux or Git Bash).
set -e
cd "$(dirname "$0")"
cargo build -q --release
echo "$(pwd)/target/release/cameleer-http-min"
