#!/usr/bin/env bash
# simoom side: simoom-bench's campaign server (crates/simoom-bench/src/bin/simoom-server.rs), the
# facade with every route of the campaign: GET / (13 bytes), POST /echo, GET /64k and /1m;
# HTTP/1.1 and h2c on 8080, TLS 1.3 (h2, http/1.1) on 8443 and HTTP/3 on 8443/udp.
# Variants (the simoom-* directories): SIMOOM_BACKEND=epoll|io_uring, SIMOOM_MODE=fixed|builder.
. "$(dirname "$0")/../lib.sh"
ensure_cert
T=/root/simoom/target/release
# SIMOOM_BIN: another build of the campaign server (bench/cloud/ab.sh A/B of two builds)
BIN="${SIMOOM_BIN:-$T/simoom-server}"
CMD=("$BIN" --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 --quic-addr 0.0.0.0:8443 --cert "$OPT/cert/cert.pem" --key "$OPT/cert/key.pem"
     --backend "${SIMOOM_BACKEND:-epoll}" --mode "${SIMOOM_MODE:-fixed}" --keepalive-s 120 ${SIMOOM_EXTRA:-})
VERSION="echo simoom $(cat /root/simoom/REVISION 2>/dev/null) backend=${SIMOOM_BACKEND:-epoll} mode=${SIMOOM_MODE:-fixed} ${SIMOOM_EXTRA:-} ${SIMOOM_BIN:+bin=$SIMOOM_BIN}"
dispatch "$@"
