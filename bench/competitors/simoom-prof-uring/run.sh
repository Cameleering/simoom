#!/usr/bin/env bash
# simoom-prof with the io_uring back end (profiling only).
export SIMOOM_BACKEND=io_uring
exec bash "$(dirname "$0")/../simoom-prof/run.sh" "$@"
