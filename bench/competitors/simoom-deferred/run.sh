#!/usr/bin/env bash
# simoom with SIMOOM_MODE=deferred (see ../simoom/run.sh and crates/simoom-bench/src/bin/simoom-server.rs).
export SIMOOM_BACKEND=epoll SIMOOM_MODE=deferred SIMOOM_EXTRA="--body-buffer 512"
exec bash "$(dirname "$0")/../simoom/run.sh" "$@"
