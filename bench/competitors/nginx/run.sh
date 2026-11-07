#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
mkdir -p /run/bench-nginx
BIN=/usr/sbin/nginx
VERSION="nginx -v; dpkg-query -W -f='\${Package} \${Version}' 'nginx*' 2>/dev/null | head -1"
CMD=(/usr/sbin/nginx -p /run/bench-nginx -c "$COMP/nginx/nginx.conf")
dispatch "$@"
