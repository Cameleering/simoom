#!/usr/bin/env bash
# cameleer-http-min (see setup.sh): plain HTTP/1.1 on 8080, TLS on 8443 with the shared P-256
# certificate; --pool 1024 (workers start on demand) is above the 500 clients of the SLEEP
# scenario, so the baseline is a thread per connection there. build.sh builds it on a workstation and prints the binary's path.
. "$(dirname "$0")/../lib.sh"
ensure_cert
BIN=/root/cameleer/target-min/release/cameleer-http-min
CMD=("$BIN" --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 --cert "$OPT/cert/cert.pem" --key "$OPT/cert/key.pem" --pool 1024)
V=$(awk -F'"' '/^version/ {print $2; exit}' /root/cameleer/Cargo.toml 2>/dev/null)
VERSION="echo cameleer-http-min cameleer-http $V thread-pool + cameleer-tls"
dispatch "$@"
