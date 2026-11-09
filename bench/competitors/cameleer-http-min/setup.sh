#!/usr/bin/env bash
# cameleer-http-min: Cameleer's thread-pool HTTP/1.1 server (cameleer-http, plain and with
# cameleer-tls) with a fixed 13-byte reply, the like-for-like baseline of docs/STATUS.md. Its path
# dependencies point at ../../../../Rust-camel, i.e. /root/Rust-camel on a server node: a link to
# the Cameleer source shipped to /root/cameleer by campaign-ctl.sh.
. "$(dirname "$0")/../lib.sh"
ensure_rust
[ -d /root/cameleer/crates/cameleer-http ] || { echo "no /root/cameleer: campaign-ctl.sh ships it to the server nodes" >&2; exit 1; }
ln -sfn /root/cameleer /root/Rust-camel
cd "$COMP/cameleer-http-min"
cargo build -q --release --locked --target-dir /root/cameleer/target-min
ls -la /root/cameleer/target-min/release/cameleer-http-min >&2
