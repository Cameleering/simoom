#!/usr/bin/env bash
# simoom with SIMOOM_MODE=blocking (see ../simoom/run.sh and crates/simoom-bench/src/bin/simoom-server.rs).
export SIMOOM_BACKEND=epoll SIMOOM_MODE=blocking SIMOOM_EXTRA=""
exec bash "$(dirname "$0")/../simoom/run.sh" "$@"
