#!/usr/bin/env bash
# simoom with SIMOOM_BACKEND=io_uring SIMOOM_MODE=builder (see ../simoom/run.sh).
export SIMOOM_BACKEND=io_uring SIMOOM_MODE=builder
exec bash "$(dirname "$0")/../simoom/run.sh" "$@"
