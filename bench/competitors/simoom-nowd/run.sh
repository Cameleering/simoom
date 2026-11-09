#!/usr/bin/env bash
# simoom (epoll, fixed) with the stall watchdog off (Limits::inline_budget = None).
export SIMOOM_BACKEND=epoll SIMOOM_MODE=fixed SIMOOM_EXTRA=--no-watchdog
exec bash "$(dirname "$0")/../simoom/run.sh" "$@"
