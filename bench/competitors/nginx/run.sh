#!/usr/bin/env bash
# nginx from Ubuntu's package. The config is generated into /run/bench-nginx: nginx.conf, plus an
# HTTP/3 listener on 8443/udp when this nginx was built with the http_v3 module.
. "$(dirname "$0")/../lib.sh"
ensure_files
mkdir -p /run/bench-nginx
conf=/run/bench-nginx/nginx.conf
if nginx -V 2>&1 | grep -q http_v3_module; then
  sed 's|# QUIC-LISTEN|listen 8443 quic reuseport; add_header Alt-Svc '"'"'h3=":8443"; ma=86400'"'"';|' "$COMP/nginx/nginx.conf" > "$conf"
else
  cp "$COMP/nginx/nginx.conf" "$conf"
fi
BIN=/usr/sbin/nginx
VERSION="nginx -v; dpkg-query -W -f='\${Package} \${Version}' 'nginx*' 2>/dev/null | head -1; nginx -V 2>&1 | grep -q http_v3_module && echo http3=yes || echo http3=no"
CMD=(/usr/sbin/nginx -p /run/bench-nginx -c "$conf")
dispatch "$@"
