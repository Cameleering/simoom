#!/usr/bin/env bash
# simoom with SIMOOM_BACKEND=epoll SIMOOM_MODE=builder (see ../simoom/run.sh).
export SIMOOM_BACKEND=epoll SIMOOM_MODE=builder
exec bash "$(dirname "$0")/../simoom/run.sh" "$@"
