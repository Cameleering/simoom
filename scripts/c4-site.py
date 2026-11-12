#!/usr/bin/env python3
"""Render campaign 4's report (bench/cloud/c4-report.py --json) into the microsite.

    python bench/cloud/c4-report.py bench/results/<date>-campaign4/results.txt --json > c4.json
    python scripts/c4-site.py c4.json

Writes the block between <!-- c4:begin --> and <!-- c4:end --> in site/simoom/benchmarks/index.html
and site/simoom/benchmarks/c4.json (the data behind every figure). Nothing on the page is typed by
hand: every bar, value and ratio comes from the report. Std-only.

Bars are an index against simoom measured on the same droplet in the same round (simoom = 100), so
no bar compares two machines; each row also shows its own absolute value.
"""
import html
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "site", "simoom", "benchmarks", "index.html")

NAMES = {
    "simoom": "simoom", "simoom-default": "simoom, smallest build", "hyper": "hyper", "axum": "axum",
    "axum-rustls": "axum + rustls", "actix": "actix-web", "ntex": "ntex", "xitca": "xitca-web",
    "may-minihttp": "may-minihttp", "quinn-h3": "quinn + h3", "nginx": "nginx", "h2o": "H2O",
    "haproxy": "HAProxy", "envoy": "Envoy", "caddy": "Caddy", "go-nethttp": "Go net/http",
    "fasthttp": "fasthttp (Go)", "netty": "Netty (Java)", "vertx": "Vert.x (Java)", "kestrel": "Kestrel (.NET)",
    "uws": "uWebSockets.js", "cameleer-http-min": "Cameleer's old server",
}

USE_CASES = [
    ("status", "Health checks and status endpoints",
     "A small GET answered from memory: load-balancer probes, status pages, the busiest route of most APIs."),
    ("api", "JSON APIs", "A 1 KB JSON body in, a 1 KB JSON body out, the shape of most service calls."),
    ("https", "HTTPS APIs and new TLS clients",
     "The same API over TLS 1.3, and how many new and returning clients the handshake can take per second."),
    ("newconn", "Clients that connect for every request",
     "Serverless callers, scripts and devices that open a connection, send one request and close it."),
    ("h2", "Service-to-service HTTP/2", "64 connections with 100 streams each, as gRPC and service meshes use HTTP/2."),
    ("h3", "Mobile clients over HTTP/3", "QUIC instead of TCP, for clients on lossy or changing networks."),
    ("download", "Downloads", "64 KB responses; 1 MB responses fill the network card for every server."),
    ("idle", "Many idle connections", "Devices and push clients that stay connected and mostly say nothing."),
    ("spike", "Traffic spikes", "195,000 requests per second offered, more than the network card can carry."),
    ("attack", "Slow attackers", "Real requests while 10,000 slowloris and 1,000 slow-read connections press."),
    ("footprint", "Start-up, size and memory", "What a server costs before and while it answers."),
]


def esc(s):
    return html.escape(str(s), quote=True)


def fmt(v, unit):
    if v is None:
        return "–"
    if unit == "ms":
        return f"{v:,.2f} ms"
    if unit == "µs":
        return f"{v:,.1f} µs" if v < 100 else f"{v:,.0f} µs"
    if unit == "KB" and v >= 10240:
        return f"{v / 1024:,.1f} MB"
    return f"{v:,.0f} {unit}".replace(" /s", "/s")


def ratio_text(a):
    if a is None:
        return ""
    if a >= 99:
        return "only simoom met the target"
    if a == 0:
        return "only this server met the target"
    if 0.97 <= a <= 1.03:
        return "level"
    if a > 1:
        return f"simoom {a:.1f}x" if a >= 1.95 else f"simoom +{(a - 1) * 100:.0f}%"
    b = 1 / a
    return f"{b:.1f}x simoom" if b >= 1.95 else f"+{(b - 1) * 100:.0f}% over simoom"


def metric_block(mid, m):
    rows = m["rows"]
    if "simoom" not in rows:
        return ""
    hib = m["higher_is_better"]
    items = []
    for srv, r in rows.items():
        if srv == "simoom":
            idx = 100.0
        elif r["simoom_advantage"] is not None:
            a = r["simoom_advantage"]
            idx = 0.0 if a >= 99 else (200.0 if a == 0 else 100.0 / a)  # >100: better than simoom on the same droplet
        else:
            continue
        items.append((srv, idx, r))
    items.sort(key=lambda t: -t[1])
    top = max(i[1] for i in items) if items else 100
    out = [f'<div class="bar-group" id="m-{esc(mid)}">', f"<h4>{esc(m['title'])}</h4>",
           f'<p class="axis">Bar: simoom = 100 on the same droplet, longer is better. '
           f'Value: median of rounds, {"higher" if hib else "lower"} is better.</p>']
    for srv, idx, r in items:
        cls = "bar us" if srv == "simoom" else "bar"
        loss = srv != "simoom" and idx > 103
        label = esc(NAMES.get(srv, srv))
        rt = "" if srv == "simoom" else ratio_text(r["simoom_advantage"])
        out.append(f'<div class="{cls}{" ahead" if loss else ""}"><span>{label}</span>'
                   f'<span class="track"><span class="fill" style="width:{max(idx / top * 100, 1):.1f}%"></span></span>'
                   f'<span class="val">{esc(fmt(r["value"], m["unit"]))}{" · " + esc(rt) if rt else ""}</span></div>')
    out.append("</div>")
    return "\n".join(out)


def summary_cards(res):
    cards = []
    for uid, title, desc in USE_CASES:
        mids = [k for k, m in res.items() if m["use"] == uid and "simoom" in m["rows"]]
        if not mids:
            continue
        m = res[mids[0]]
        others = [(s, r) for s, r in m["rows"].items() if s != "simoom" and r["simoom_advantage"]]
        if not others:
            continue
        better = sum(1 for _, r in others if r["simoom_advantage"] > 1.03)
        worse = [(s, r) for s, r in others if r["simoom_advantage"] < 0.97]
        best_other = min(others, key=lambda t: t[1]["simoom_advantage"])
        verdict = (f"ahead of {better} of {len(others)}" if not worse else
                   f"ahead of {better} of {len(others)}; behind {', '.join(NAMES.get(s, s) for s, _ in worse)}")
        cards.append(
            f'<a class="card" href="#u-{uid}"><h3>{esc(title)}</h3><p>{esc(desc)}</p>'
            f'<span class="res">{esc(ratio_text(best_other[1]["simoom_advantage"]) or "level")} '
            f'<small>against the best other, {esc(NAMES.get(best_other[0], best_other[0]))}; {esc(verdict)}</small></span></a>')
    return '<div class="cards">' + "\n".join(cards) + "</div>"


def matrix(res):
    cols = [k for k, m in res.items() if "simoom" in m["rows"]]
    servers = sorted({s for k in cols for s in res[k]["rows"] if s != "simoom"}, key=lambda s: NAMES.get(s, s).lower())
    head = "".join(f'<th class="num" title="{esc(res[k]["title"])}"><a href="#m-{esc(k)}">{esc(k)}</a></th>' for k in cols)
    body = []
    for s in servers:
        cells = []
        for k in cols:
            r = res[k]["rows"].get(s)
            a = r and r["simoom_advantage"]
            if not a:
                cells.append('<td class="num">–</td>')
            else:
                cls = "win" if a > 1.03 else ("loss" if a < 0.97 else "")
                cells.append(f'<td class="num"><span class="{cls}">{a:.2f}</span></td>')
        body.append(f"<tr><td>{esc(NAMES.get(s, s))}</td>{''.join(cells)}</tr>")
    return ('<div class="c-table-wrap"><table class="c-table matrix"><thead><tr><th>server</th>' + head +
            "</tr></thead><tbody>" + "\n".join(body) + "</tbody></table></div>")


def render(res):
    parts = ['<section class="c-sec" id="field">', '<div class="wrap">',
             "<h2>simoom against the field, use case by use case</h2>",
             '<p class="intro">Campaign 4: 22 servers, each measured on the same DigitalOcean droplet as simoom, with the same '
             "load machines, in the same round; three rounds on three droplets. Every bar is relative to simoom on that droplet, "
             "so no comparison mixes machines. Losses are in the same charts as wins.</p>",
             summary_cards(res)]
    for uid, title, desc in USE_CASES:
        blocks = [metric_block(k, m) for k, m in res.items() if m["use"] == uid]
        blocks = [b for b in blocks if b]
        if not blocks:
            continue
        parts += [f'<h3 id="u-{uid}">{esc(title)}</h3>', f'<p class="intro">{esc(desc)}</p>', '<div class="bars">', *blocks, "</div>"]
    parts += ["<h3 id=\"matrix\">Every server, every measure</h3>",
              '<p class="intro">simoom\'s advantage on the same droplet, median of rounds: above 1.00 simoom is better, '
              "below 1.00 the other server is. Column names link to the charts above.</p>", matrix(res),
              '<p class="note">The data behind this section: <a href="c4.json">c4.json</a>, generated from the raw records in '
              '<a href="https://github.com/Cameleering/simoom/tree/main/bench/results">bench/results</a> by '
              "<code>bench/cloud/c4-report.py</code> and <code>scripts/c4-site.py</code>.</p>",
              "</div>", "</section>"]
    return "\n".join(parts)


def main():
    res = json.load(open(sys.argv[1], encoding="utf-8"))
    block = render(res)
    page = open(PAGE, encoding="utf-8").read()
    b, e = "<!-- c4:begin -->", "<!-- c4:end -->"
    if b not in page:
        page = page.replace('<section class="c-sec" id="method">', f"{b}\n{e}\n\n" + '<section class="c-sec" id="method">', 1)
    pre, rest = page.split(b, 1)
    _, post = rest.split(e, 1)
    open(PAGE, "w", encoding="utf-8", newline="").write(pre + b + "\n" + block + "\n" + e + post)
    json.dump(res, open(os.path.join(os.path.dirname(PAGE), "c4.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"wrote {PAGE}")


if __name__ == "__main__":
    main()
