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
import statistics
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


def word(m):
    """What 'better' means for this measure."""
    if m["higher_is_better"]:
        return "more"
    if m["unit"] in ("ms", "µs"):
        return "faster" if m["use"] == "footprint" else "lower"
    return "smaller" if m.get("title", "").startswith("Program size") else "less"


def ratio_text(a, m, subject=None):
    """a = simoom's advantage (good/bad, > 1: simoom better). subject: the other server, for losses."""
    if a is None:
        return ""
    if a >= 1e5:
        return "only simoom met the target"
    if a == 0:
        return "only this server met the target"
    if 0.97 <= a <= 1.03:
        return "level"
    w = word(m)
    r = a if a > 1 else 1 / a
    if r >= 1.95:
        q = f"{r:.1f}x {w}" if r < 10 else f"{r:.0f}x {w}"
    elif m["higher_is_better"] or w == "faster":
        q = f"{(r - 1) * 100:.0f}% {w}"
    else:
        q = f"{(1 - 1 / r) * 100:.0f}% {w}"
    return f"simoom {q}" if a > 1 else f"{q} than simoom"


def metric_block(mid, m):
    rows = m["rows"]
    if "simoom" not in rows:
        return ""
    hib = m["higher_is_better"]
    items = []
    for srv, r in rows.items():
        if srv == "simoom-default" and m["use"] != "footprint":
            continue  # simoom itself, built with fewer features; it belongs in the footprint charts only
        if srv == "simoom":
            idx = 100.0
        elif r["simoom_advantage"] is not None:
            a = r["simoom_advantage"]
            idx = 0.0 if a >= 1e5 else (200.0 if a == 0 else 100.0 / a)  # >100: better than simoom on the same droplet
        else:
            continue
        items.append((srv, idx, r))
    items.sort(key=lambda t: -t[1])
    top = max(i[1] for i in items) if items else 100
    runs = max((r["samples"] for s_, _, r in items if s_ != "simoom"), default=0)
    rn = "one round" if runs <= 1 else f"median of {runs} rounds"
    out = [f'<div class="bar-group" id="m-{esc(mid)}">', f"<h4>{esc(m['title'])}</h4>",
           f'<p class="axis">Bar: simoom = 100 on the same droplet, longer is better. '
           f'Value: {rn}, {"higher" if hib else "lower"} is better; in brackets, simoom in the same runs.</p>']
    for srv, idx, r in items:
        cls = "bar us" if srv == "simoom" else "bar"
        loss = srv != "simoom" and idx > 103
        label = esc(NAMES.get(srv, srv))
        rt = "" if srv == "simoom" else ratio_text(r["simoom_advantage"], m)
        out.append(f'<div class="{cls}{" ahead" if loss else ""}"><span>{label}</span>'
                   f'<span class="track"><span class="fill" style="width:{max(idx / top * 100, 1):.1f}%"></span></span>'
                   f'<span class="val">{esc(fmt(r["value"], m["unit"]))}'
                   f'{"" if srv == "simoom" else " (simoom " + esc(fmt(r["simoom_same_droplet"], m["unit"])) + ")"}'
                   f'{" · " + esc(rt) if rt else ""}</span></div>')
    out.append("</div>")
    return "\n".join(out)


PRIMARY = {"status": "s1-256", "api": "s3", "https": "s7-tls", "newconn": "s5", "h2": "s8", "h3": "h3",
           "download": "s4-64k", "idle": "idle-10k", "spike": "s9", "attack": "s10", "footprint": "cold-plain"}


def summary_cards(res):
    cards = []
    for uid, title, desc in USE_CASES:
        mid = PRIMARY.get(uid)
        m = res.get(mid)
        if not m or "simoom" not in m["rows"]:
            continue
        others = [(s_, r) for s_, r in m["rows"].items() if s_ not in RIVALS_EXCLUDED and r["simoom_advantage"]]
        if not others:
            continue
        better = sum(1 for _, r in others if r["simoom_advantage"] > 1.03)
        level = sum(1 for _, r in others if 0.97 <= r["simoom_advantage"] <= 1.03)
        worse = [NAMES.get(s_, s_) for s_, r in sorted(others, key=lambda t: t[1]["simoom_advantage"]) if r["simoom_advantage"] < 0.97]
        best_s, best_r = min(others, key=lambda t: t[1]["simoom_advantage"])
        a = best_r["simoom_advantage"]
        name = NAMES.get(best_s, best_s)
        if a > 1.03:
            head = f"First of {len(others) + 1}: {ratio_text(a, m)} than the next best, {name}"
            head = head.replace(" than the next best", " than the next best") if " than simoom" not in head else head
        elif a >= 0.97:
            head = f"Level with the best, {name}"
        else:
            head = f"Behind {name}: {ratio_text(a, m)}"
        tally = f"ahead of {better} of {len(others)}" + (f", level with {level}" if level else "") + (f"; behind {', '.join(worse)}" if worse else "")
        cards.append(
            f'<a class="card" href="#u-{uid}"><h3>{esc(title)}</h3><p>{esc(desc)}</p>'
            f'<span class="res">{esc(head)} <small>{esc(m["title"])}; {esc(tally)}</small></span></a>')
    return '<div class="cards">' + "\n".join(cards) + "</div>"


def matrix(res):
    cols = [k for k, m in res.items() if "simoom" in m["rows"]]
    servers = sorted({s for k in cols for s in res[k]["rows"] if s not in ("simoom", "simoom-default")}, key=lambda s: NAMES.get(s, s).lower())
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


RIVALS_EXCLUDED = ("simoom", "simoom-default")
HEADLINES = [("s1-256", "Status endpoint, 256 clients"), ("cpu-50k", "CPU per request at 50,000 req/s"),
             ("idle-10k", "Memory per idle connection, 10,000 open"), ("cold-plain", "Start-up to first answer")]


def rivals(m):
    return [(s_, r["simoom_advantage"]) for s_, r in m["rows"].items() if s_ not in RIVALS_EXCLUDED and r["simoom_advantage"]]


def times(a):
    return f"{a:.1f}x" if a < 10 else f"{a:.0f}x"


def stats(res):
    out = ['<div class="stats">']
    for mid, label in HEADLINES:
        rs = sorted(a for _, a in rivals(res[mid]))
        if not rs:
            continue
        real = [a for a in rs if 0 < a < 1e5]
        med = statistics.median(real)
        ahead = sum(1 for a in rs if a > 1.03)
        behind = [NAMES.get(s_, s_) for s_, a in rivals(res[mid]) if a < 0.97]
        tail = f"; behind {', '.join(behind)}" if behind else ""
        out.append(f'<div class="stat"><b>{times(med)}</b><span>{esc(label)}: simoom against the median of {len(rs)} servers, '
                   f'range {real[0]:.2f}–{times(real[-1])}; ahead of {ahead}{esc(tail)}</span></div>')
    out.append("</div>")
    return "\n".join(out)


def losses(res):
    items = []
    for mid, m in res.items():
        worse = sorted(((a, s_) for s_, a in rivals(m) if a < 0.97), key=lambda t: t[0])
        if not worse or "simoom" not in m["rows"]:
            continue
        who = ", ".join(f"{NAMES.get(s_, s_)} ({ratio_text(a, m)})" for a, s_ in worse)
        items.append(f'<li><b>{esc(m["title"])}.</b> {esc(who)}. <a href="#m-{esc(mid)}">Chart</a></li>')
    return ('<section class="c-sec" id="losses"><div class="wrap"><h2>Where simoom is behind</h2>'
            '<p class="intro">Every measure where another server beat simoom by more than 3% on the same droplet, generated from '
            'the same data as the charts.</p><ul class="losses">' + "\n".join(items) +
            "<li><b>Coverage.</b> Every figure comes from 4-vCPU droplets with a single-queue network card. Larger machines "
            "and multi-queue network cards have not been measured.</li></ul></div></section>")


def render(res):
    parts = ['<section class="c-sec" id="field">', '<div class="wrap">',
             "<h2>simoom against the field, use case by use case</h2>",
             '<p class="intro">Campaign 4: simoom and 20 other servers, each measured on the same DigitalOcean droplet as simoom, with the same '
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
              "</div>", "</section>", losses(res)]
    return "\n".join(parts)


# ---------- home page (site/simoom/index.html): hero facts, scoreboard, speed charts, losses ----------
HOME = os.path.join(ROOT, "site", "simoom", "index.html")
NL = chr(10)


def place(m):
    rs = rivals(m)
    behind = sum(1 for _, a in rs if a < 0.97)
    n = len(rs) + 1
    return behind + 1, n


def ordinal(k):
    return {1: "1st", 2: "2nd", 3: "3rd"}.get(k, f"{k}th")


def median_adv(m):
    real = [a for _, a in rivals(m) if 0 < a < 1e5]
    return statistics.median(real) if real else None


def home_facts(res):
    out = ['<dl class="facts">']
    for mid, label in (("cold-plain", "start-up"), ("idle-10k", "memory per idle connection"), ("cpu-50k", "CPU per request")):
        m = res[mid]
        med = median_adv(m)
        k, n = place(m)
        hy = m["rows"].get("hyper", {}).get("simoom_advantage")
        w = word(m)
        extra = f"; {ratio_text(hy, m).replace('simoom ', '')} than hyper" if hy and hy > 1.03 else ""
        out.append(f'<div><dt>{times(med)}</dt><dd>{esc(w)} {esc(label)} than the median of {n - 1} servers; {ordinal(k)} of {n}</dd></div>')
    out.append("</dl>")
    return NL.join(out)


def home_board(res):
    rows = []
    for uid, title, desc in USE_CASES:
        mid = PRIMARY.get(uid)
        m = res.get(mid)
        if not m or "simoom" not in m["rows"] or not rivals(m):
            continue
        k, n = place(m)
        best_s, a = min(rivals(m), key=lambda t: t[1])
        med = median_adv(m)
        tied = k == 1 and min(a_ for _, a_ in rivals(m)) <= 1.03
        cls = "win" if k == 1 and not tied else ("loss" if k > 3 else "")
        rows.append(f'<tr><td><a href="benchmarks/#u-{uid}">{esc(title)}</a><small>{esc(m["title"])}</small></td>'
                    f'<td class="num"><span class="{cls}">{"joint " if tied else ""}{ordinal(k)} of {n}</span></td>'
                    f'<td>{esc(NAMES.get(best_s, best_s))}: {esc(ratio_text(a, m))}</td>'
                    f'<td>{esc(ratio_text(med, m)) if med else "–"}</td></tr>')
    return ('<div class="c-table-wrap"><table class="c-table board"><thead><tr><th>use case and measure</th><th class="num">simoom\'s place</th>'
            '<th>against the best other</th><th>against the median server</th></tr></thead><tbody>' + NL.join(rows) + "</tbody></table></div>")


def home_numbers(res):
    blocks = [metric_block(k, res[k]) for k in ("s1-256", "s7-tls", "cpu-50k", "s3")]
    worse = []
    for uid, title, _ in USE_CASES:
        mid = PRIMARY.get(uid)
        m = res.get(mid)
        if not m or "simoom" not in m["rows"]:
            continue
        w = sorted(((a, s_) for s_, a in rivals(m) if a < 0.97))
        if w:
            worse.append(f'<li><b>{esc(title)}:</b> {esc(", ".join(f"{NAMES.get(s_, s_)} ({ratio_text(a, m)})" for a, s_ in w[:4]))}'
                         f'{" and " + str(len(w) - 4) + " more" if len(w) > 4 else ""}.</li>')
    return ('<div id="field"><div class="bars">' + NL.join(blocks) + "</div></div>" +
            '<h3>Where simoom is behind</h3><ul class="losses">' + NL.join(worse) + "</ul>")


def splice(page, name, body):
    b, e = f"<!-- {name}:begin -->", f"<!-- {name}:end -->"
    if b not in page:
        return page
    pre, rest = page.split(b, 1)
    _, post = rest.split(e, 1)
    return pre + b + NL + body + NL + e + post


def write_home(res):
    page = open(HOME, encoding="utf-8").read()
    page = splice(page, "c4-facts", home_facts(res))
    page = splice(page, "c4-board", home_board(res))
    page = splice(page, "c4-numbers", home_numbers(res))
    open(HOME, "w", encoding="utf-8", newline="").write(page)
    print(f"wrote {HOME}")


# ---------- compare pages: hero tally and a head-to-head table, generated ----------
COMPARE = {
    "compare/simoom-vs-hyper-axum": (["hyper", "axum", "axum-rustls", "actix"], ["s1-256", "cpu-50k", "idle-10k"]),
    "compare/simoom-vs-may-minihttp": (["may-minihttp"], ["s1-256", "cpu-50k", "idle-10k"]),
    "compare/simoom-vs-nginx-h2o": (["nginx", "h2o"], ["s7-tls", "h3", "idle-10k"]),
}


def tally(res, srv):
    w = l = t = 0
    for mid, m in res.items():
        r = m["rows"].get(srv)
        if not r or r["simoom_advantage"] is None or "simoom" not in m["rows"]:
            continue
        a = r["simoom_advantage"]
        if a > 1.03:
            w += 1
        elif a < 0.97:
            l += 1
        else:
            t += 1
    return w, t, l


def cmp_stats(res, servers, mids):
    out = ['<div class="stats">']
    main = servers[0]
    w, t, l = tally(res, main)
    out.append(f'<div class="stat"><b>{w} of {w + t + l}</b><span>campaign 4 measures where simoom is ahead of {esc(NAMES.get(main, main))}</span>'
               f'<small>level on {t}, behind on {l}</small></div>')
    for mid in mids:
        m = res[mid]
        cells = [(s_, m["rows"][s_]) for s_ in servers if s_ in m["rows"] and m["rows"][s_]["simoom_advantage"] is not None]
        if not cells:
            continue
        s_, r = cells[0]
        others = "; ".join(f"{NAMES.get(x, x)}: {ratio_text(rr['simoom_advantage'], m)}" for x, rr in cells[1:])
        out.append(f'<div class="stat"><b>{esc(ratio_text(r["simoom_advantage"], m))}</b><span>{esc(m["title"])}, against {esc(NAMES.get(s_, s_))}</span>'
                   f'<small>simoom {esc(fmt(r["simoom_same_droplet"], m["unit"]))}, {esc(NAMES.get(s_, s_))} {esc(fmt(r["value"], m["unit"]))}{"; " + esc(others) if others else ""}</small></div>')
    out.append("</div>")
    return NL.join(out)


def cmp_table(res, servers):
    head = "".join(f"<th>{esc(NAMES.get(s_, s_))}</th>" for s_ in servers)
    body = []
    for uid, title, _ in USE_CASES:
        for mid, m in res.items():
            if m["use"] != uid or "simoom" not in m["rows"]:
                continue
            cells = []
            any_ = False
            for s_ in servers:
                r = m["rows"].get(s_)
                if not r or r["simoom_advantage"] is None:
                    cells.append("<td>–</td>")
                    continue
                any_ = True
                a = r["simoom_advantage"]
                cls = "win" if a > 1.03 else ("loss" if a < 0.97 else "")
                cells.append(f'<td><span class="{cls}">{esc(ratio_text(a, m))}</span>'
                             f'<small>{esc(fmt(r["value"], m["unit"]))} vs simoom {esc(fmt(r["simoom_same_droplet"], m["unit"]))}</small></td>')
            if any_:
                body.append(f'<tr><td><a href="../../benchmarks/#m-{esc(mid)}">{esc(m["title"])}</a></td>{"".join(cells)}</tr>')
    return ('<div class="c-table-wrap"><table class="c-table board"><thead><tr><th>measure (campaign 4)</th>' + head +
            "</tr></thead><tbody>" + NL.join(body) + "</tbody></table></div>"
            '<p class="note">Each cell: simoom against that server on the same droplet in the same round, median of rounds, then the '
            'server\'s value against simoom\'s in the same runs. Every measure and every other server: <a href="../../benchmarks/#field">the benchmarks</a>.</p>')


def write_compare(res):
    base = os.path.join(ROOT, "site", "simoom")
    for rel, (servers, mids) in COMPARE.items():
        f = os.path.join(base, rel, "index.html")
        page = open(f, encoding="utf-8").read()
        page = splice(page, "c4-cmp-stats", cmp_stats(res, servers, mids))
        page = splice(page, "c4-cmp", cmp_table(res, servers))
        open(f, "w", encoding="utf-8", newline="").write(page)
    f = os.path.join(base, "compare", "index.html")
    page = open(f, encoding="utf-8").read()
    page = splice(page, "c4-stats", stats(res))
    open(f, "w", encoding="utf-8", newline="").write(page)
    print("wrote the compare pages")


def main():
    res = json.load(open(sys.argv[1], encoding="utf-8"))
    block = render(res)
    page = open(PAGE, encoding="utf-8").read()
    b, e = "<!-- c4:begin -->", "<!-- c4:end -->"
    if b not in page:
        page = page.replace('<section class="c-sec" id="method">', f"{b}\n{e}\n\n" + '<section class="c-sec" id="method">', 1)
    pre, rest = page.split(b, 1)
    _, post = rest.split(e, 1)
    page = pre + b + "\n" + block + "\n" + e + post
    sb, se = "<!-- c4-stats:begin -->", "<!-- c4-stats:end -->"
    if sb in page:
        pre, rest = page.split(sb, 1)
        _, post = rest.split(se, 1)
        page = pre + sb + "\n" + stats(res) + "\n" + se + post
    open(PAGE, "w", encoding="utf-8", newline="").write(page)
    json.dump(res, open(os.path.join(os.path.dirname(PAGE), "c4.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"wrote {PAGE}")
    write_home(res)
    write_compare(res)


if __name__ == "__main__":
    main()
