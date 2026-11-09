#!/usr/bin/env bash
# simoom (epoll, fixed) built with frame pointers for perf call graphs (profiling only; the
# campaign's numbers come from ../simoom). Built by setup.sh into /root/simoom/target-fp.
. "$(dirname "$0")/../lib.sh"
ensure_cert
BIN=/root/simoom/target-fp/release/simoom-server
CMD=("$BIN" --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 --quic-addr 0.0.0.0:8443 --cert "$OPT/cert/cert.pem" --key "$OPT/cert/key.pem"
     --backend "${SIMOOM_BACKEND:-epoll}" --mode "${SIMOOM_MODE:-fixed}" --keepalive-s 120)
VERSION="echo simoom-prof $(cat /root/simoom/REVISION 2>/dev/null) frame-pointers"
dispatch "$@"
