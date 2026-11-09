#!/usr/bin/env bash
# simoom-prof with --mode deferred (profiling only).
export SIMOOM_MODE=deferred
exec bash "$(dirname "$0")/../simoom-prof/run.sh" "$@"
