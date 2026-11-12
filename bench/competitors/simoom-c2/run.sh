#!/usr/bin/env bash
# simoom-server built from campaign 2's commit (see setup.sh); SIMOOM_BACKEND as in ../simoom.
. "$(dirname "$0")/../lib.sh"
ensure_cert
BIN=/root/simoom-c2/target/release/simoom-server
CMD=("$BIN" --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 --quic-addr 0.0.0.0:8443 --cert "$OPT/cert/cert.pem" --key "$OPT/cert/key.pem"
     --backend "${SIMOOM_BACKEND:-epoll}" --mode fixed --keepalive-s 120)
VERSION="echo simoom $(cat /root/simoom-c2/PIN.txt 2>/dev/null | head -1) backend=${SIMOOM_BACKEND:-epoll} (campaign 2 commit)"
dispatch "$@"
