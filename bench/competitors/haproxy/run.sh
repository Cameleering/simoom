#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN=/usr/sbin/haproxy
VERSION="haproxy -v | head -1"
CMD=(/usr/sbin/haproxy -W -db -f "$COMP/haproxy/haproxy.cfg")
dispatch "$@"
