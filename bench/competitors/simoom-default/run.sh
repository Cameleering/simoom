#!/usr/bin/env bash
# simoom-default (see setup.sh): HTTP/1.1 and h2c on 8080, epoll, fixed replies, keep-alive 120 s.
. "$(dirname "$0")/../lib.sh"
BIN=/root/simoom/target-default/release/simoom-default
CMD=("$BIN" --addr 0.0.0.0:8080 --backend "${SIMOOM_BACKEND:-epoll}" --mode "${SIMOOM_MODE:-fixed}" --keepalive-s 120)
VERSION="echo simoom-default $(cat /root/simoom/REVISION 2>/dev/null) default-features backend=${SIMOOM_BACKEND:-epoll} mode=${SIMOOM_MODE:-fixed}"
dispatch "$@"
