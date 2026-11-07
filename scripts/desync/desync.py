#!/usr/bin/env python3
"""Differential HTTP/1.1 desync testing (T-Reqs style, written for simoom; stdlib only).

Sends generated request streams to:
  * simoom directly                         (conformance_server, port BASE)
  * nginx as a reverse proxy in front of it (port BASE+1)
  * haproxy as a reverse proxy in front     (port BASE+2)
  * nginx as an origin server               (port BASE+3)
  * haproxy as an origin server             (port BASE+4)

and compares how many requests each hop saw and where the request boundaries fell.

Desync (dangerous): through a proxy, simoom saw a request the proxy did not forward as such
(a different count, or a target the proxy never logged, such as /smuggled).
Divergence (reviewed): simoom accepts a stream that nginx and haproxy, as origins, both reject,
or frames it differently.

Usage (WSL, after building the conformance server in release):
  python3 scripts/desync/desync.py --server ~/simoom-target-sec/release/examples/conformance_server \
      --nginx /usr/sbin/nginx --haproxy ~/aptx/root/usr/sbin/haproxy [--out ~/desync]

Exit status 1 if any desync is found.
"""
import argparse, os, re, socket, subprocess, sys, time, json

SMUGGLE = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"


def cases():
    """(name, bytes). Every stream ends with a well-formed GET /smuggled, so a parser that
    swallows or splits a body differently shows up as a different request count or target."""
    c = []
    H = b"Host: x\r\n"

    def post(headers, body):
        return b"POST /a HTTP/1.1\r\n" + H + headers + b"\r\n" + body + SMUGGLE

    # --- baseline
    c.append(("baseline GET", b"GET /a HTTP/1.1\r\n" + H + b"\r\n" + SMUGGLE))
    c.append(("baseline POST CL", post(b"Content-Length: 5\r\n", b"hello")))
    c.append(("baseline POST chunked", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n")))
    # --- CL.TE / TE.CL
    body_te = b"0\r\n\r\n"
    c.append(("CL+TE (CL covers smuggle)", post(b"Content-Length: 40\r\nTransfer-Encoding: chunked\r\n", body_te)))
    c.append(("TE+CL (CL short)", post(b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n", b"5\r\nhello\r\n0\r\n\r\n")))
    for te in [b"xchunked", b" chunked", b"chunked ", b"\tchunked", b"Chunked", b"CHUNKED", b"chunked, identity", b"identity, chunked",
               b"chunked,chunked", b"chunked, gzip", b"gzip, chunked", b"identity", b"chunked\x00", b"chunk", b"\"chunked\"", b"chunked;q=1",
               b"x, chunked", b"", b",chunked", b"chunked,"]:
        c.append(("TE value %r + CL" % te, post(b"Transfer-Encoding: " + te + b"\r\nContent-Length: 5\r\n", b"0\r\n\r\n")))
        c.append(("TE value %r alone" % te, post(b"Transfer-Encoding: " + te + b"\r\n", b"5\r\nhello\r\n0\r\n\r\n")))
    for name in [b"Transfer-Encoding :", b"Transfer-Encoding\t:", b" Transfer-Encoding:", b"Transfer_Encoding:", b"Transfer-Encoding\x00:",
                 b"transfer-encoding:", b"TRANSFER-ENCODING:", b"Transfer-Encodin:", b"\x0bTransfer-Encoding:"]:
        c.append(("TE name %r + CL" % name, post(name + b" chunked\r\nContent-Length: 5\r\n", b"0\r\n\r\n")))
    c.append(("two TE headers chunked/identity", post(b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n", b"5\r\nhello\r\n0\r\n\r\n")))
    c.append(("two TE headers identity/chunked", post(b"Transfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n")))
    c.append(("TE obs-fold", post(b"Transfer-Encoding:\r\n chunked\r\nContent-Length: 5\r\n", b"0\r\n\r\n")))
    c.append(("TE in HTTP/1.0", b"POST /a HTTP/1.0\r\n" + H + b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n" + SMUGGLE))
    # --- Content-Length variants
    for cl in [b"+5", b"05", b" 5", b"5 ", b"5,5", b"5, 5", b"5,6", b"0x5", b"5\x00", b"\t5", b"-5", b"", b"5.0", b"1e1", b"99999999999999999999",
               b"5\r\nContent-Length: 5", b"5\r\nContent-Length: 6", b"5\r\n Content-Length: 6"]:
        c.append(("CL %r" % cl, post(b"Content-Length: " + cl + b"\r\n", b"hello")))
    for name in [b"Content-Length :", b"Content-Length\t:", b" Content-Length:", b"Content_Length:", b"content-length:", b"Content-Length\x00:"]:
        c.append(("CL name %r" % name, post(name + b" 5\r\n", b"hello")))
    # --- chunk oddities
    for size_line in [b"5;ext", b"5 ;ext", b"5\t;ext", b"5;ext=\"q;x\"", b"5;ext=\"a\r\nb\"", b"5;", b"5 ", b" 5", b"0x5", b"05", b"00000005",
                      b"5\x00", b"-5", b"+5", b"5\n", b"5\rx", b"fffffffffffffffff5", b"5;\x00", b"5;ext\x01", b"5;a=b;c=d", b"5;a=\"\\\"\""]:
        line_end = b"" if size_line.endswith(b"\n") else b"\r\n"
        c.append(("chunk size %r" % size_line, post(b"Transfer-Encoding: chunked\r\n", size_line + line_end + b"hello\r\n0\r\n\r\n")))
    c.append(("chunk data without CRLF", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello0\r\n\r\n")))
    c.append(("chunk data with LF only", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello\n0\r\n\r\n")))
    c.append(("chunk data too long", post(b"Transfer-Encoding: chunked\r\n", b"3\r\nhello\r\n0\r\n\r\n")))
    c.append(("last chunk LF only", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\n\n")))
    c.append(("trailer fields", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n")))
    c.append(("trailer Content-Length", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\nContent-Length: 40\r\n\r\n")))
    c.append(("trailer obs-fold", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\nX-T: 1\r\n 2\r\n\r\n")))
    c.append(("trailer bare LF", post(b"Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\nX-T: 1\n\r\n")))
    # --- whitespace, casing, line endings, NUL
    c.append(("bare LF line endings", b"GET /a HTTP/1.1\nHost: x\n\n" + SMUGGLE))
    c.append(("bare CR in header value", b"GET /a HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\n\r\n" + SMUGGLE))
    c.append(("bare CR line ending", b"GET /a HTTP/1.1\rHost: x\r\n\r\n" + SMUGGLE))
    c.append(("NUL in header value", b"GET /a HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n" + SMUGGLE))
    c.append(("NUL in target", b"GET /a\x00b HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("obs-fold in a header", b"GET /a HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n\r\n" + SMUGGLE))
    c.append(("whitespace before first header", b"GET /a HTTP/1.1\r\n Host: x\r\n\r\n" + SMUGGLE))
    c.append(("space before colon", b"GET /a HTTP/1.1\r\nHost : x\r\n\r\n" + SMUGGLE))
    c.append(("empty header name", b"GET /a HTTP/1.1\r\nHost: x\r\n: v\r\n\r\n" + SMUGGLE))
    c.append(("header without colon", b"GET /a HTTP/1.1\r\nHost: x\r\nNoColon\r\n\r\n" + SMUGGLE))
    c.append(("double space in request line", b"GET  /a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("tab in request line", b"GET\t/a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("trailing space in request line", b"GET /a HTTP/1.1 \r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("lowercase version", b"GET /a http/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("version 1.10", b"GET /a HTTP/1.10\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("version 2.0 in h1", b"GET /a HTTP/2.0\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("HTTP/0.9 style", b"GET /a\r\n\r\n" + SMUGGLE))
    c.append(("lowercase method", b"get /a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("leading CRLF", b"\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("leading spaces", b"  GET /a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("missing Host", b"GET /a HTTP/1.1\r\n\r\n" + SMUGGLE))
    c.append(("duplicate Host", b"GET /a HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n" + SMUGGLE))
    c.append(("Host with space", b"GET /a HTTP/1.1\r\nHost: x y\r\n\r\n" + SMUGGLE))
    c.append(("non-token header name", b"GET /a HTTP/1.1\r\nHost: x\r\nX(A): 1\r\n\r\n" + SMUGGLE))
    c.append(("high byte in header value", b"GET /a HTTP/1.1\r\nHost: x\r\nX-A: \xff\r\n\r\n" + SMUGGLE))
    c.append(("high byte in target", b"GET /a\xff HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("GET with body CL", b"GET /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" + SMUGGLE))
    c.append(("GET with chunked body", b"GET /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" + SMUGGLE))
    c.append(("HEAD with CL body", b"HEAD /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" + SMUGGLE))
    # --- Expect
    c.append(("Expect 100-continue with body", post(b"Content-Length: 5\r\nExpect: 100-continue\r\n", b"hello")))
    c.append(("Expect 100-continue, GET CL 0", b"GET /a HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n" + SMUGGLE))
    c.append(("Expect unknown value", post(b"Content-Length: 5\r\nExpect: 100-continuex\r\n", b"hello")))
    c.append(("Expect obs-fold", post(b"Content-Length: 5\r\nExpect:\r\n 100-continue\r\n", b"hello")))
    c.append(("Expect 100-continue, body is a request (0.CL)", b"POST /a HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: " +
              str(len(SMUGGLE)).encode() + b"\r\n\r\n" + SMUGGLE))
    c.append(("Expect 100-continue HTTP/1.0", b"POST /a HTTP/1.0\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello" + SMUGGLE))
    # --- Upgrade
    c.append(("Upgrade h2c with body", post(b"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nContent-Length: 5\r\n", b"hello")))
    c.append(("Upgrade h2c without HTTP2-Settings", b"GET /a HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n" + SMUGGLE))
    c.append(("Upgrade websocket POST", post(b"Connection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 5\r\n", b"hello")))
    c.append(("Upgrade unknown", b"GET /a HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: foo/1\r\n\r\n" + SMUGGLE))
    c.append(("Upgrade without Connection", b"GET /a HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n" + SMUGGLE))
    c.append(("h2 preface inside h1", b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nPRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
    # --- request-target forms
    c.append(("absolute-form", b"GET http://x/a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("absolute-form other host", b"GET http://y/a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("absolute-form https", b"GET https://x/a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("absolute-form with userinfo", b"GET http://u:p@x/a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("absolute-form no path", b"GET http://x HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("authority-form CONNECT", b"CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\n" + SMUGGLE))
    c.append(("asterisk OPTIONS", b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("asterisk GET", b"GET * HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("target without slash", b"GET a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("target with fragment", b"GET /a#f HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("target with space-escaped %20", b"GET /a%20b HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("target with raw space", b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    c.append(("target ../", b"GET /../a HTTP/1.1\r\nHost: x\r\n\r\n" + SMUGGLE))
    return c


# --------------------------------------------------------------------------- plumbing

def send(port, data, timeout=1.0):
    """Sends `data` and returns everything read until close or `timeout` of silence. The write
    side stays open: proxies treat a half-close as an abort (nginx logs 499) and would not
    forward pipelined requests."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(data)
        out = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not b:
                break
            out += b
            end = time.time() + timeout
        return out
    finally:
        s.close()


STATUS = re.compile(rb"HTTP/1\.[01] (\d{3})")


def statuses(resp):
    """Final status codes of the responses in a byte stream (1xx skipped)."""
    return [int(m.group(1)) for m in STATUS.finditer(resp) if not m.group(1).startswith(b"1")]


class LogTail:
    def __init__(self, path):
        self.path = path
        self.pos = os.path.getsize(path) if os.path.exists(path) else 0

    def new_lines(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, "rb") as f:
            f.seek(self.pos)
            data = f.read()
        self.pos += len(data)
        return [l for l in data.decode("latin-1").splitlines() if l.strip()]


def settle(tails, quiet=0.15, limit=2.0):
    """Collects new lines until every log has been quiet for `quiet` seconds."""
    got = [[] for _ in tails]
    end = time.time() + limit
    last = time.time()
    while time.time() < end:
        any_new = False
        for i, t in enumerate(tails):
            n = t.new_lines()
            if n:
                got[i] += n
                any_new = True
        if any_new:
            last = time.time()
        elif time.time() - last > quiet:
            break
        time.sleep(0.03)
    return got


def simoom_reqs(lines):
    out = []
    for l in lines:
        p = l.split()
        if len(p) >= 4 and p[0] == "REQ":
            out.append((p[2], p[3], p[4] if len(p) > 4 else ""))
    return out


NGINX_CONF = """
worker_processes 1;
error_log {d}/nginx-error.log warn;
pid {d}/nginx.pid;
events {{ worker_connections 256; }}
http {{
  access_log off;
  client_body_temp_path {d}/tmp; proxy_temp_path {d}/tmp; fastcgi_temp_path {d}/tmp; uwsgi_temp_path {d}/tmp; scgi_temp_path {d}/tmp;
  log_format up '$request_method $request_uri up=$upstream_status st=$status len=$request_length';
  upstream simoom {{ server 127.0.0.1:{p0}; keepalive 4; }}
  server {{
    listen 127.0.0.1:{p1};
    access_log {d}/nginx-proxy.log up;
    location / {{ proxy_pass http://simoom; proxy_http_version 1.1; proxy_set_header Connection ""; proxy_request_buffering off; }}
  }}
  server {{
    listen 127.0.0.1:{p3};
    access_log {d}/nginx-origin.log up;
    location / {{ client_max_body_size 1m; proxy_pass http://127.0.0.1:{p3b}; }}
  }}
  server {{
    listen 127.0.0.1:{p3b};
    access_log off;
    location / {{ return 200 "ok\\n"; }}
  }}
}}
"""

HAPROXY_CONF = """
global
  log stdout format raw local0
  maxconn 256
defaults
  mode http
  log global
  option httplog
  log-format "%HM %HU up=%ST st=%ST bytes=%U"
  timeout connect 2s
  timeout client 3s
  timeout server 3s
  http-reuse always
frontend proxy
  bind 127.0.0.1:{p2}
  default_backend simoom
backend simoom
  server s1 127.0.0.1:{p0}
frontend origin
  bind 127.0.0.1:{p4}
  http-request return status 200 content-type text/plain string "ok"
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server")
    ap.add_argument("--nginx", default="/usr/sbin/nginx")
    ap.add_argument("--haproxy")
    ap.add_argument("--out", default=os.path.expanduser("~/desync"))
    ap.add_argument("--base", type=int, default=19080)
    ap.add_argument("--analyze", help="re-run the analysis on a results.json and exit")
    a = ap.parse_args()
    if a.analyze:
        sys.exit(report(json.load(open(a.analyze))))
    d = a.out
    os.makedirs(d + "/tmp", exist_ok=True)
    for f in os.listdir(d):
        if f.endswith(".log"):
            os.remove(os.path.join(d, f))
    p0, p1, p2, p3, p4, p3b = a.base, a.base + 1, a.base + 2, a.base + 3, a.base + 4, a.base + 5
    open(d + "/nginx.conf", "w").write(NGINX_CONF.format(d=d, p0=p0, p1=p1, p3=p3, p3b=p3b))
    open(d + "/haproxy.cfg", "w").write(HAPROXY_CONF.format(p0=p0, p2=p2, p4=p4))
    procs = []
    procs.append(subprocess.Popen([a.server, "--addr", "127.0.0.1:%d" % p0], stdout=open(d + "/simoom.log", "wb"), stderr=subprocess.DEVNULL))
    procs.append(subprocess.Popen([a.nginx, "-p", d, "-e", d + "/nginx-e.log", "-c", d + "/nginx.conf", "-g", "daemon off;"], stderr=open(d + "/nginx-stderr.log", "wb")))
    procs.append(subprocess.Popen([a.haproxy, "-db", "-f", d + "/haproxy.cfg"], stdout=open(d + "/haproxy.log", "wb"), stderr=subprocess.STDOUT))
    time.sleep(1.0)
    results = []
    try:
        sim = LogTail(d + "/simoom.log")
        ngx = LogTail(d + "/nginx-proxy.log")
        hap = LogTail(d + "/haproxy.log")
        ngo = LogTail(d + "/nginx-origin.log")
        for name, data in cases():
            r = {"case": name}
            # direct
            settle([sim])
            resp = send(p0, data)
            (sl,) = settle([sim])
            r["simoom"] = {"reqs": [x[1] for x in simoom_reqs(sl)], "status": statuses(resp)}
            # nginx proxy
            settle([sim, ngx])
            resp = send(p1, data)
            sl, nl = settle([sim, ngx], quiet=0.25)
            fwd = [l.split()[1] for l in nl if "up=-" not in l and len(l.split()) > 1]
            r["nginx_proxy"] = {"proxy_fwd": fwd, "proxy_log": nl, "simoom_reqs": [x[1] for x in simoom_reqs(sl)], "status": statuses(resp)}
            # haproxy proxy
            settle([sim, hap])
            resp = send(p2, data)
            sl, hl = settle([sim, hap], quiet=0.25)
            hfwd = []
            for l in hl:
                p = l.split()
                if len(p) >= 3 and p[2].startswith("up=") and p[2] not in ("up=-1",) and not p[0].startswith("<BADREQ>"):
                    if p[0] != "<BADREQ>":
                        hfwd.append(p[1])
            r["haproxy_proxy"] = {"proxy_fwd": hfwd, "proxy_log": hl, "simoom_reqs": [x[1] for x in simoom_reqs(sl)], "status": statuses(resp)}
            # origins
            settle([ngo])
            r["nginx_origin"] = {"status": statuses(send(p3, data))}
            settle([ngo])
            r["haproxy_origin"] = {"status": statuses(send(p4, data))}
            settle([hap])
            results.append(r)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(3)
            except Exception:
                p.kill()

    json.dump(results, open(d + "/results.json", "w"), indent=1)
    sys.exit(report(results))


def norm(t):
    """Request target as the origin's service sees it: absolute-form reduced to path and query
    (RFC 9112 §3.2.2, as simoom does), nginx's backslash-x hex log escapes undone."""
    t = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), t)
    m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?]*(.*)$", t)
    if m:
        return m.group(1) or "/"
    return t


def subsequence(small, big):
    it = iter(big)
    return all(any(x == y for y in it) for x in small)


def report(results):
    """Desync: simoom ran a request the proxy did not forward as a request of its own (a
    target the proxy never sent, or requests out of order). A request simoom refused is fine:
    the proxy then sends the next request on a new upstream connection."""
    desync = []
    diverge = []
    for r in results:
        for hop in ("nginx_proxy", "haproxy_proxy"):
            h = r[hop]
            fwd = [norm(x) for x in h["proxy_fwd"]]
            if not subsequence([norm(x) for x in h["simoom_reqs"]], fwd):
                desync.append((r["case"], hop, h["proxy_fwd"], h["simoom_reqs"]))
        s_ok = len(r["simoom"]["status"]) > 0 and r["simoom"]["status"][0] < 400
        n_ok = len(r["nginx_origin"]["status"]) > 0 and r["nginx_origin"]["status"][0] < 400
        h_ok = len(r["haproxy_origin"]["status"]) > 0 and r["haproxy_origin"]["status"][0] < 400
        if s_ok and not n_ok and not h_ok:
            diverge.append((r["case"], "simoom accepts, nginx and haproxy reject", r))
        elif s_ok:
            counts = [len(r[o]["status"]) for o in ("nginx_origin", "haproxy_origin") if r[o]["status"] and r[o]["status"][0] < 400]
            if len(r["simoom"]["status"]) not in counts:
                diverge.append((r["case"], "different number of responses", r))
    print("cases: %d" % len(results))
    print("desyncs: %d" % len(desync))
    for x in desync:
        print("  DESYNC %s via %s: proxy forwarded %s, simoom saw %s" % x)
    print("origin divergences: %d" % len(diverge))
    for c, why, r in diverge:
        print("  DIVERGE %s: %s | simoom %s | nginx %s | haproxy %s" % (c, why, r["simoom"]["status"], r["nginx_origin"]["status"], r["haproxy_origin"]["status"]))
    acc = sum(1 for r in results if r["simoom"]["status"] and r["simoom"]["status"][0] < 400)
    rej_all = sum(1 for r in results if not (r["simoom"]["status"] and r["simoom"]["status"][0] < 400)
                  and not (r["nginx_origin"]["status"] and r["nginx_origin"]["status"][0] < 400)
                  and not (r["haproxy_origin"]["status"] and r["haproxy_origin"]["status"][0] < 400))
    stricter = sum(1 for r in results if not (r["simoom"]["status"] and r["simoom"]["status"][0] < 400)
                   and ((r["nginx_origin"]["status"] and r["nginx_origin"]["status"][0] < 400)
                        or (r["haproxy_origin"]["status"] and r["haproxy_origin"]["status"][0] < 400)))
    print("simoom accepted the first request in %d of %d cases; all three refused %d; simoom refused where nginx or haproxy accepted %d"
          % (acc, len(results), rej_all, stricter))
    return 1 if desync else 0


if __name__ == "__main__":
    main()
