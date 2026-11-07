#!/usr/bin/env bash
# simoom side. The facade's bench_server example is used once it can bind a non-loopback address
# (an `--addr` option) and run without a time limit; until then the simoom-rt raw responder
# (`simoom-bench raw`) is the simoom side. SIMOOM_SIDE=raw|bench_server forces one.
. "$(dirname "$0")/../lib.sh"
T=/root/simoom/target/release
EX=/root/simoom/crates/simoom/examples/bench_server.rs
side="${SIMOOM_SIDE:-auto}"
if [ "$side" = auto ]; then
  side=raw
  [ -x "$T/examples/bench_server" ] && grep -q '"--addr"' "$EX" 2>/dev/null && side=bench_server
fi
if [ "$side" = bench_server ]; then
  BIN="$T/examples/bench_server"; CMD=("$BIN" --addr 0.0.0.0:8080 --secs 1000000000 --backend "${SIMOOM_BACKEND:-epoll}")
else
  BIN="$T/simoom-bench"; CMD=("$BIN" raw --addr 0.0.0.0:8080 --backend "${SIMOOM_BACKEND:-epoll}")
fi
VERSION="echo simoom $(cat /root/simoom/REVISION 2>/dev/null) side=$side"
dispatch "$@"
