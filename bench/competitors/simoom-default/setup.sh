#!/usr/bin/env bash
# simoom-default: the campaign server built against simoom with its default features (no TLS,
# no HTTP/3), from the simoom source shipped to /root/simoom. Standalone project, own target dir.
. "$(dirname "$0")/../lib.sh"
ensure_rust
cd "$COMP/simoom-default"
[ -f Cargo.lock ] || cargo generate-lockfile --offline
cargo build -q --release --locked --target-dir /root/simoom/target-default
ls -la /root/simoom/target-default/release/simoom-default >&2
