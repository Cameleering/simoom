#!/usr/bin/env bash
# Smoke-checks every competitor on a server node (run there, as root): start it, then GET / over
# HTTP/1.1, h2c prior knowledge (8080 or 8081), TLS 1.3 (8443), POST /echo, GET /64k, and the
# HTTP/3 listener (UDP 8443 bound). Prints one CHECK line per server.
#   check-servers.sh "simoom nginx ..."
SRV=/root/simoom/bench/competitors/server.sh
for n in $1; do
  if ! $SRV start "$n" >/tmp/check-$n.log 2>&1; then echo "CHECK server=$n start=FAIL $(tail -n 2 /tmp/check-$n.log | tr '\n' ' ')"; continue; fi
  get=$(curl -s -m 2 http://127.0.0.1:8080/)
  h2c8080=$(curl -s -m 2 -o /dev/null -w '%{http_version}' --http2-prior-knowledge http://127.0.0.1:8080/)
  h2c8081=$(curl -s -m 2 -o /dev/null -w '%{http_version}' --http2-prior-knowledge http://127.0.0.1:8081/)
  tls=$(curl -s -m 2 -o /dev/null -w '%{http_version}' --cacert /opt/bench/cert/cert.pem --resolve bench.local:8443:127.0.0.1 https://bench.local:8443/)
  echo_=$(curl -s -m 2 -X POST -H 'content-type: application/json' --data '{"a":1}' http://127.0.0.1:8080/echo)
  k64=$(curl -s -m 2 http://127.0.0.1:8080/64k | wc -c)
  udp=$(ss -Hlnu '( sport = :8443 )' | wc -l)
  echo "CHECK server=$n get=$([ "$get" = 'Hello, World!' ] && echo ok || echo "bad:${get:0:20}") h2c8080=${h2c8080:-0} h2c8081=${h2c8081:-0} tls=${tls:-0} echo=$([ "$echo_" = '{"a":1}' ] && echo ok || echo no) 64k=$k64 udp8443=$udp"
  $SRV stop >/dev/null 2>&1
done
