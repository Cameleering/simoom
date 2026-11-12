#!/usr/bin/env python3
"""Summarize a simoom benchmark campaign (bench/cloud/campaign.sh) into Markdown tables.

    python3 bench/cloud/summarize-campaign.py bench/results/<date>-campaign > summary.md

Reads results.txt (record lines tagged round= srv= server=), machine.txt and tree.txt. Every cell
is the median over the rounds that measured it, with the range [min-max] when there is more than
one round. Stdlib only. Latencies in RESULT lines are microseconds.
"""
import os
import re
import statistics
import sys
from collections import defaultdict

ORDER = ["simoom", "simoom-uring", "simoom-builder", "simoom-builder-uring", "simoom-default", "simoom-deferred",
         "simoom-deferred-stream", "simoom-blocking", "nginx", "h2o", "haproxy", "envoy", "caddy",
         "hyper", "axum", "actix", "may-minihttp", "xitca", "ntex", "go-nethttp", "fasthttp", "netty", "vertx", "uws",
         "kestrel", "cameleer-http-min", "cameleer"]


def parse(path):
    recs = defaultdict(list)
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if " " not in line:
            continue
        kind, rest = line.split(" ", 1)
        kv = {}
        for k, v in re.findall(r"(\w+)=(\S+)", rest):
            kv.setdefault(k, v)  # the first occurrence wins (the tag comes first)
        kv["_raw"] = rest
        recs[kind].append(kv)
    return recs


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def med(vals, digits=0, unit=""):
    vals = [v for v in vals if v is not None]
    if not vals:
        return "-"
    m = statistics.median(vals)
    f = (lambda x: f"{x:,.{digits}f}{unit}")
    if len(vals) == 1:
        return f(m)
    return f"{f(m)} [{f(min(vals))}–{f(max(vals))}]"


def medv(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def fmt0(v):
    n = num(v)
    return "-" if n is None else f"{n:,.0f}"


MIB_GBIT = 1048576 * 8 / 1e9  # Gbit per 1 MiB response (body only)


def verified_of(R, server, scen, keyname, key, limit_us, extra=None):
    """Per round: the highest measured point (the 20-30 s runs after the search) whose p99 met the
    limit with no errors; the search's own short steps are not used."""
    out = []
    rows = [x for x in R if x.get("server") == server and x.get("scenario") == scen and x.get(keyname) == str(key)
            and x.get("phase") == "point" and (extra is None or all(x.get(k) == v for k, v in extra.items()))]
    for rnd in sorted({x.get("round") for x in rows}):
        pts = [x for x in rows if x.get("round") == rnd]
        ok = [num(x.get("achieved")) for x in pts if (num(x.get("p99_us")) or 1e18) <= limit_us and num(x.get("errors")) == 0]
        out.append(max(ok) if ok else 0.0)
    return out


def axes(recs):
    """Every axis of the campaign: (name, unit, higher_is_better, {server: [value per round]})."""
    R = [x for x in recs["RESULT"] if x.get("prof") != "1"]
    MET = [x for x in recs["METRIC"] if x.get("prof") != "1" and x.get("scenario") != "cpufix"]
    FIX = [x for x in recs["METRIC"] if x.get("scenario") == "cpufix"]
    S = servers_in(recs)
    out = []

    def ver(name, scen, key, lim, keyname="conns", extra=None):
        out.append((name, "req/s", True, {s: v for s in S if (v := verified_of(R, s, scen, keyname, key, lim, extra))}))

    def closed(name, scen, unit, field, hib, scale=1.0, **kw):
        vals = {}
        for s in S:
            rr = [x for x in R if x.get("server") == s and x.get("scenario") == scen and x.get("phase") == "closed"
                  and all(x.get(k) == v for k, v in kw.items()) and (num(x.get("errors")) or 0) == 0 and num(x.get(field))]
            rr = [x for x in rr if (num(x.get("non2xx")) or 0) == 0]
            if rr:
                vals[s] = [num(x.get(field)) * scale for x in rr]
        out.append((name, unit, hib, vals))

    ver("S1 @64 verified SLO", "S1", 64, 1000)
    ver("S1 @256 verified SLO", "S1", 256, 1000)
    ver("S1 @1024 verified SLO", "S1", 1024, 1000)
    ver("S3 1 KB echo verified SLO", "S3", 256, 1000)
    ver("S4 64 KB verified SLO (p99 5 ms)", "S4", 64, 5000)
    closed("S4 1 MB plain", "S4", "Gbit/s", "achieved", True, MIB_GBIT, size="1m")
    closed("S4 1 MB TLS", "S4", "Gbit/s", "achieved", True, MIB_GBIT, size="1m-tls")
    ver("S5 connection per request verified SLO (p99 5 ms)", "S5", 192, 5000)
    closed("S7 full TLS handshakes", "S7", "per s", "achieved", True, kind="full")
    closed("S7 resumed TLS handshakes", "S7", "per s", "achieved", True, kind="resumed")
    ver("S7 S1 over TLS verified SLO", "S7", 256, 1000)
    ver("S8 h2c 100 streams verified SLO (p99 5 ms)", "S8", 64, 5000)
    s9 = {}
    for s in S:
        rr = [x for x in R if x.get("server") == s and x.get("scenario") == "S9"]
        if rr:
            s9[s] = [num(x.get("goodput_slo")) for x in rr]
    out.append(("S9 goodput within 1 ms at 2x load", "req/s", True, s9))
    s10 = {}
    for s in S:
        rr = [x for x in R if x.get("server") == s and x.get("scenario") == "S10" and x.get("attack") not in (None, "none")]
        if rr:
            s10[s] = [num(x.get("p99_us")) for x in rr]
    out.append(("S10 legitimate p99 under attack", "µs", False, s10))
    ver("HTTP/3 S1 verified SLO", "H3", 64, 1000)
    closed("HTTP/3 64 KB download", "H3bulk", "Gbit/s", "achieved", True, MIB_GBIT / 16, size="64k")
    closed("HTTP/3 1 MB download", "H3bulk", "Gbit/s", "achieved", True, MIB_GBIT, size="1m")
    cpu = {}
    for s in S:
        m = [num(x.get("cpu_us_per_req")) for x in MET if x.get("server") == s and num(x.get("cpu_us_per_req"))]
        if m:
            cpu[s] = m
    if not any(x.get("session") for x in MET):  # campaign 1 only: campaign 2 measures CPU at one fixed rate
        out.append(("CPU per request at 80% of own S1 SLO", "µs", False, cpu))
    fix = {}
    for s in S:
        ok = {x.get("round") for x in R if x.get("server") == s and x.get("scenario") == "cpufix" and (num(x.get("errors")) or 0) == 0
              and (num(x.get("achieved")) or 0) >= 0.97 * (num(x.get("rate")) or 1e18)}
        m = [num(x.get("cpu_us_per_req")) for x in FIX if x.get("server") == s and x.get("round") in ok and num(x.get("cpu_us_per_req"))]
        if m:
            fix[s] = m
    out.append(("CPU per request at 50k req/s (S1, every server, same rate)", "µs", False, fix))
    sl = {}
    for s in S:
        rr = [x for x in R if x.get("server") == s and x.get("scenario") == "SLEEP" and (num(x.get("errors")) or 0) == 0]
        if rr:
            sl[s] = [num(x.get("achieved")) for x in rr]
    out.append(("100 ms blocking handler, 500 clients (no errors)", "req/s", True, sl))
    PM = [x for x in recs["METRIC"] if x.get("prof") == "1"]
    PR = [x for x in recs["RESULT"] if x.get("prof") == "1"]
    for case in ("s1", "s3", "s5", "s7", "s8"):
        v = {}
        for m in PM:
            rr = [x for x in PR if x.get("server") == m.get("server") and x.get("case") == case and x.get("srv") == m.get("srv")]
            if not rr or not num(rr[-1].get("achieved")) or (num(rr[-1].get("errors")) or 0) > 0:
                continue
            if m.get("case") == case and num(m.get("cpu_us_per_req")):
                v.setdefault(m.get("server").replace("simoom-prof-uring", "simoom-uring").replace("simoom-prof", "simoom"), []).append(num(m.get("cpu_us_per_req")))
        if v:
            out.append((f"CPU per request at a fixed rate (profile case {case})", "µs", False, v))
    cold = {}
    for s in S:
        cs = [num(x.get("median_ms")) for x in recs["COLDSTART"] if x.get("server") == s and not x.get("variant") and num(x.get("median_ms"))]
        if cs:
            cold[s] = cs
    for x in recs["COLDSTART"]:
        if x.get("variant") and num(x.get("median_ms")):
            cold.setdefault(f"{x.get('server')}:{x.get('variant')}", []).append(num(x.get("median_ms")))
    out.append(("cold start to first response", "ms", False, cold))
    size = {}
    for x in recs["SIZE"]:
        # native executables only: the JVM and .NET entries are launchers of a runtime
        if num(x.get("bytes")) and x.get("server") not in ("netty", "vertx", "kestrel"):
            k = x.get("server") + (f":{x['variant']}" if x.get("variant") else "")
            size.setdefault(k, []).append(num(x.get("bytes")) / 1024)
    out.append(("stripped binary size (native executables)", "KB", False, size))
    # PEAK: only runs whose scenario set was S1 alone (campaign 2 rounds 2 and 3), so every server
    # did the same work; round 1 ran different scenario sets per server
    s1only = {(x.get("round"), x.get("server")) for x in R if x.get("scenario") == "S1"} -         {(x.get("round"), x.get("server")) for x in R if x.get("scenario") not in ("S1", None)}
    for kind, name in (("BASE", "idle memory (PSS) after one request"), ("PEAK", "peak memory (PSS) during S1 at 256 connections (rounds 2-3)")):
        v = {}
        for x in recs[kind]:
            if kind == "PEAK" and (x.get("round"), x.get("server")) not in s1only:
                continue
            if num(x.get("pss_kb")) and num(x.get("pss_kb")) < 1e8:
                v.setdefault(x.get("server"), []).append(num(x.get("pss_kb")) / 1024)
        out.append((name, "MB", False, v))
    for ic in ("10000", "100000"):
        v = {}
        for x in recs["IDLE"]:
            if x.get("conns") == ic and not x.get("failed") and num(x.get("per_conn_b")) and num(x.get("established")) and num(x.get("established")) >= int(ic) * 0.99:
                v.setdefault(x.get("server"), []).append(num(x.get("per_conn_b")))
        out.append((f"memory per idle connection, {int(ic) // 1000}k open", "B", False, v))
    return out


def leaderboard(recs):
    """Per axis: the best server, the best simoom variant, simoom's rank and the margin."""
    rows = []
    for name, unit, hib, vals in axes(recs):
        meds = {s: medv(v) for s, v in vals.items() if medv(v) is not None and (medv(v) > 0 or not hib)}
        if not meds:
            continue
        order = sorted(meds, key=lambda s: -meds[s] if hib else meds[s])
        sim = [s for s in order if s.startswith("simoom")]
        best = order[0]
        bs = sim[0] if sim else None
        others = [s for s in order if not s.startswith("simoom")]
        bo = others[0] if others else None
        margin = None
        if bs and bo and meds[bo]:
            margin = (meds[bs] / meds[bo] - 1) * 100 if hib else (meds[bo] / meds[bs] - 1) * 100
        rows.append(dict(axis=name, unit=unit, hib=hib, best=best, best_v=meds[best], simoom=bs, simoom_v=meds.get(bs),
                         rank=(order.index(bs) + 1 if bs else None), n=len(order), other=bo, other_v=meds.get(bo), margin=margin,
                         rounds=len(vals.get(bs, [])) if bs else 0, other_rounds=len(vals.get(bo, [])) if bo else 0))
    return rows


def fmtv(v, unit):
    if v is None:
        return "-"
    if unit in ("Gbit/s", "ms", "MB"):
        return f"{v:,.2f}"
    if unit == "µs" and v < 100:
        return f"{v:,.1f}"
    return f"{v:,.0f}"


def servers_in(recs):
    seen = set()
    for kind in ("VERSION", "RESULT", "SKIPPED"):
        for r in recs[kind]:
            if r.get("server"):
                seen.add(r["server"])
    return sorted(seen, key=lambda s: (ORDER.index(s) if s in ORDER else 99, s))


def sel(rows, **kw):
    out = []
    for r in rows:
        if all(r.get(k) == str(v) for k, v in kw.items()):
            out.append(r)
    return out


def main():
    d = sys.argv[1]
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    recs = parse(os.path.join(d, "results.txt"))
    S = servers_in(recs)
    PR = [x for x in recs["RESULT"] if x.get("prof") == "1"]
    PM = [x for x in recs["METRIC"] if x.get("prof") == "1"]
    R = [x for x in recs["RESULT"] if x.get("prof") != "1"]
    MET = [x for x in recs["METRIC"] if x.get("prof") != "1" and x.get("scenario") != "cpufix"]
    FIX = [x for x in recs["METRIC"] if x.get("scenario") == "cpufix"]
    SLO = recs["SLO"]

    def verified(server, scen, keyname, key, limit_us):
        return verified_of(R, server, scen, keyname, key, limit_us)
    out = []
    w = out.append
    w("# simoom benchmark campaign\n")
    w("_Generated by `bench/cloud/summarize-campaign.py` from `results.txt` (raw record lines) and the HdrHistogram files in `hdr/`. "
      "Each cell is the median over the rounds that measured it, with [min–max] across rounds; rounds alternate between two server droplets._\n")
    w("## Leaderboard\n")
    w("Per axis: the best server (median over rounds), the best simoom variant, its rank among every server measured on that axis, and the margin against the best non-simoom server "
      "(positive: simoom ahead). Throughput axes use the verified SLO (the longer measured points), not the search. `n` = rounds behind each median.\n")
    w("| axis | unit | best | best simoom (n) | rank | best other (n) | simoom vs best other |")
    w("|---|---|---|---|---:|---|---:|")
    for x in leaderboard(recs):
        mg = "-" if x["margin"] is None else f"{x['margin']:+.1f}%"
        w(f"| {x['axis']} | {x['unit']} {'↑' if x['hib'] else '↓'} | {x['best']} {fmtv(x['best_v'], x['unit'])} | {x['simoom'] or '-'} {fmtv(x['simoom_v'], x['unit'])} ({x['rounds']}) | "
          f"{x['rank'] or '-'}/{x['n']} | {x['other'] or '-'} {fmtv(x['other_v'], x['unit'])} ({x['other_rounds']}) | {mg} |")
    w("")
    cov = defaultdict(set)
    for x in R:
        if x.get("scenario") == "S1" and x.get("phase") == "point":
            cov[x.get("server")].add(x.get("round"))
    if cov:
        w("Rounds with S1 data: " + ", ".join(f"{s} {len(cov[s])}" for s in S if s in cov) + ".\n")
    dl = [r for r in recs["SKIPPED"] if r.get("reason") == "deadline"]
    if dl:
        w("Not run before the session deadline: " + ", ".join(sorted({f"{r.get('server')} round {r.get('round')} ({r.get('scenarios')})" for r in dl})) + ".\n")

    for f in ("tree.txt", "machine.txt"):
        p = os.path.join(d, f)
        if os.path.exists(p):
            w(f"## {f}\n\n```")
            for line in open(p, encoding="utf-8", errors="replace"):
                w(line.rstrip())
            w("```\n")

    w("## Versions and binary size\n")
    w("| server | version | stripped main binary |")
    w("|---|---|---:|")
    for s in S:
        v = next((r["_raw"].split("server=" + s, 1)[-1].strip() for r in recs["VERSION"] if r.get("server") == s), "")
        sizes = [r for r in recs["SIZE"] if r.get("server") == s]
        sz = "; ".join(f"{num(r.get('bytes')) / 1024:,.0f} KB" + (f" ({r['variant']})" if r.get("variant") else "") for r in sizes if num(r.get("bytes")))
        w(f"| {s} | {v[:90]} | {sz or '-'} |")
    skipped = [(r.get("server"), r.get("reason") or r.get("step")) for r in recs["SKIPPED"] + recs["FAILED"]]
    if skipped:
        w("\nSkipped or failed steps: " + ", ".join(sorted({f"{a} ({b})" for a, b in skipped})) + "\n")

    def slo_table(title, scen, keyname, keyvals, extra=None, note=""):
        rows = [x for x in SLO if x.get("scenario") == scen and (extra is None or all(x.get(k) == v for k, v in extra.items()))]
        if not rows:
            return
        w(f"## {title}\n")
        if note:
            w(note + "\n")
        w("| server | " + " | ".join(f"{keyname} {k}" for k in keyvals) + " |")
        w("|---|" + "---:|" * len(keyvals))
        for s in S:
            cells = []
            any_ = False
            for k in keyvals:
                rr = [x for x in rows if x.get("server") == s and x.get(keyname) == str(k)]
                if rr:
                    any_ = True
                vals = [num(x.get("slo_rps")) for x in rr]
                cap = any(x.get("capped") == "1" for x in rr)
                probe = [num(x.get("probe_rps")) for x in rr]
                lim = 1000.0 if scen not in ("S4", "S5", "S8") else 5000.0
                ver = verified(s, scen, keyname, k, lim) if rr else []
                cells.append(med(vals) + (" ≥" if cap else "") + (f" / {med(ver)}" if ver else "") + (f" ({med(probe)})" if rr else ""))
            if any_:
                w(f"| {s} | " + " | ".join(cells) + " |")
        w("")

    slo_table("S1: GET, 13-byte reply, SLO throughput (req/s, p99 ≤ 1 ms)", "S1", "conns", [64, 256, 1024],
              note="Each cell: **search SLO / verified SLO (closed-loop probe)**. Search SLO: highest open-loop rate whose short search step (5-6 s) met p99 ≤ 1 ms with no errors and the rate achieved; `≥`: the search's top (1.05 × the probe) passed. "
                   "Verified SLO: the highest of the longer measured points (50/80/95/100/100% of the search SLO at 256 connections, 20 s each; 50/95% at 10 s otherwise) that still met p99 ≤ 1 ms; 0 means none did. "
                   "The verified figure is the one to quote: a search step can pass by luck. Medians over rounds, [min–max] across rounds.")

    pts = [x for x in R if x.get("scenario") == "S1" and x.get("conns") == "256" and x.get("phase") == "point"]
    if pts:
        w("### S1 latency at 256 connections (µs, p50 / p99 / p99.9, open loop from the intended send time)\n")
        w("| server | 50% | 80% | 95% | 100% (two runs) |")
        w("|---|---|---|---|---|")
        for s in S:
            cells = []
            for pct in ("50", "80", "95", "100"):
                rr = [x for x in pts if x.get("server") == s and x.get("pct") == pct]
                if not rr:
                    cells.append("-")
                    continue
                cells.append(" / ".join(f"{medv([num(x.get(k)) for x in rr]) or 0:,.0f}" for k in ("p50_us", "p99_us", "p999_us")))
            if any(c != "-" for c in cells):
                w(f"| {s} | " + " | ".join(cells) + " |")
        w("")

    if MET:
        w("## Cost per request (S1 at 80% of the SLO throughput, 256 connections)\n")
        w("CPU time from the server's cgroup; cycles, instructions and context switches from `perf stat` on the cgroup; syscalls from bpftrace on the cgroup (`-` where unavailable).\n")
        w("| server | rate | CPU µs/req | cycles/req | instr/req | ctx sw/req | syscalls/req | server NIC rx/tx pkt/s |")
        w("|---|---:|---:|---:|---:|---:|---:|---|")
        nic = recs["NIC"]
        for s in S:
            m = [x for x in MET if x.get("server") == s]
            if not m:
                continue
            n = [x for x in nic if x.get("server") == s and x.get("node") == "srv"]
            w(f"| {s} | {med([num(x.get('rate')) for x in m])} | {med([num(x.get('cpu_us_per_req')) for x in m], 2)} | "
              f"{med([num(x.get('cycles_per_req')) for x in m])} | {med([num(x.get('instr_per_req')) for x in m])} | "
              f"{med([num(x.get('ctxsw_per_req')) for x in m], 3)} | {med([num(x.get('syscalls_per_req')) for x in m], 2)} | "
              f"{med([num(x.get('rxpck_s')) for x in n])} / {med([num(x.get('txpck_s')) for x in n])} |")
        w("")

    npk = recs["NICPEAK"]
    if npk:
        w("## Machine load during the S1 search at 256 connections (highest per-second values)\n")
        w("Private-interface packets per second and CPU from `sar` on the server and on load1 while the S1 sweep at 256 connections ran (search and points). steal: hypervisor steal time.\n")
        w("| server | server rx+tx pkt/s | server Mbit/s | server CPU busy % | server steal % (busy s) | load1 pkt/s | load1 CPU busy % |")
        w("|---|---:|---:|---:|---:|---:|---:|")
        for s in S:
            a = [x for x in npk if x.get("server") == s and x.get("node") == "srv"]
            b = [x for x in npk if x.get("server") == s and x.get("node") == "load1"]
            if a or b:
                w(f"| {s} | {med([num(x.get('pck_max')) for x in a])} | {med([num(x.get('mbit_max')) for x in a])} | {med([num(x.get('cpu_busy_max')) for x in a], 1)} | "
                  f"{med([num(x.get('steal_avg_busy')) for x in a], 1)} | {med([num(x.get('pck_max')) for x in b])} | {med([num(x.get('cpu_busy_max')) for x in b], 1)} |")
        w("")

    if FIX:
        w("## CPU per request at one fixed rate (S1, 256 connections, every server)\n")
        w("The same offered rate for every server, so the CPU costs compare directly. The simoom rows include the blocking paths: "
          "`simoom` answers inline on the loop thread (pre-serialized reply), `simoom-builder` inline with a built reply, `simoom-deferred` defers to a plain std thread pool owned by the server "
          "(`Reply::defer`, `Responder::send` from the worker; Cameleer's path), `simoom-deferred-stream` the same with `Responder::stream`, `simoom-blocking` simoom's offload pool (`simoom::blocking`). "
          "`*` marks rounds where the server did not reach 97% of the rate or had errors (its figure is shown but not ranked).\n")
        w("| server | achieved | p99 µs | CPU µs/req | cycles/req | instr/req | ctx sw/req | syscalls/req |")
        w("|---|---:|---:|---:|---:|---:|---:|---:|")
        for s in S:
            m = [x for x in FIX if x.get("server") == s]
            if not m:
                continue
            rr = [x for x in R if x.get("server") == s and x.get("scenario") == "cpufix"]
            bad = any((num(x.get("errors")) or 0) > 0 or (num(x.get("achieved")) or 0) < 0.97 * (num(x.get("rate")) or 1e18) for x in rr)
            w(f"| {s}{' *' if bad else ''} | {med([num(x.get('achieved')) for x in rr])} | {med([num(x.get('p99_us')) for x in rr])} | {med([num(x.get('cpu_us_per_req')) for x in m], 2)} | "
              f"{med([num(x.get('cycles_per_req')) for x in m])} | {med([num(x.get('instr_per_req')) for x in m])} | "
              f"{med([num(x.get('ctxsw_per_req')) for x in m], 3)} | {med([num(x.get('syscalls_per_req')) for x in m], 2)} |")
        w("")
    slp = [x for x in R if x.get("scenario") == "SLEEP"]
    if slp:
        w("## A handler that blocks 100 ms (GET /sleep, 500 clients, closed loop)\n")
        w("The ideal is 500 / 0.1 s = 5,000 req/s at a p50 just over 100 ms. simoom-deferred: `Reply::defer` and a 512-thread std pool owned by the server; simoom-blocking: simoom's offload pool at its defaults; "
          "cameleer-http-min: Cameleer's thread-pool server (a thread per connection, worker limit 1024).\n")
        w("| server | req/s | p50 ms | p99 ms | p99.9 ms | max ms | errors | non-2xx |")
        w("|---|---:|---:|---:|---:|---:|---:|---:|")
        for s in S:
            rr = [x for x in slp if x.get("server") == s]
            if rr:
                w(f"| {s} | {med([num(x.get('achieved')) for x in rr])} | {med([(num(x.get('p50_us')) or 0) / 1000 for x in rr], 1)} | {med([(num(x.get('p99_us')) or 0) / 1000 for x in rr], 1)} | "
                  f"{med([(num(x.get('p999_us')) or 0) / 1000 for x in rr], 1)} | {med([(num(x.get('max_us')) or 0) / 1000 for x in rr], 1)} | {med([num(x.get('errors')) for x in rr])} | {med([num(x.get('non2xx')) for x in rr])} |")
        w("")

    slo_table("S3: POST 1 KB JSON, echoed (SLO throughput, req/s, p99 ≤ 1 ms)", "S3", "conns", [256])
    slo_table("S4: 64 KB replies (SLO throughput, req/s, p99 ≤ 5 ms)", "S4", "conns", [64], extra={"size": "64k"})
    big = [x for x in R if x.get("scenario") == "S4" and x.get("phase") == "closed"]
    if big:
        w("### S4: 1 MB replies, closed loop, 64 connections\n")
        w("| server | plain: req/s | plain: Gbit/s | TLS: req/s | TLS: Gbit/s |")
        w("|---|---:|---:|---:|---:|")
        for s in S:
            a = [x for x in big if x.get("server") == s and x.get("size") == "1m"]
            b = [x for x in big if x.get("server") == s and x.get("size") == "1m-tls"]
            if a or b:
                w(f"| {s} | {med([num(x.get('achieved')) for x in a])} | {med([num(x.get('mbit_in')) / 1000 for x in a if num(x.get('mbit_in'))], 2)} | "
                  f"{med([num(x.get('achieved')) for x in b])} | {med([num(x.get('mbit_in')) / 1000 for x in b if num(x.get('mbit_in'))], 2)} |")
        w("")
    slo_table("S5: a new connection per request (SLO throughput, connections/s, p99 ≤ 5 ms incl. connect)", "S5", "conns", [192])

    s7 = [x for x in R if x.get("scenario") == "S7" and x.get("phase") == "closed"]
    if s7:
        w("## S7: TLS 1.3 handshakes per second (closed loop, 192 workers per run, a request per connection)\n")
        w("| server | full handshakes/s | p99 µs | resumed handshakes/s | p99 µs | errors |")
        w("|---|---:|---:|---:|---:|---:|")
        for s in S:
            f = [x for x in s7 if x.get("server") == s and x.get("kind") == "full"]
            rs = [x for x in s7 if x.get("server") == s and x.get("kind") == "resumed"]
            if f or rs:
                w(f"| {s} | {med([num(x.get('achieved')) for x in f])} | {med([num(x.get('p99_us')) for x in f])} | "
                  f"{med([num(x.get('achieved')) for x in rs])} | {med([num(x.get('p99_us')) for x in rs])} | "
                  f"{med([num(x.get('errors')) for x in f + rs])} |")
        w("")
    slo_table("S7: S1 over TLS 1.3 (SLO throughput, req/s, p99 ≤ 1 ms)", "S7", "conns", [256])
    slo_table("S8: HTTP/2 (h2c), 100 streams per connection (SLO throughput, req/s, p99 ≤ 5 ms)", "S8", "conns", [64])

    s9 = [x for x in R if x.get("scenario") == "S9"]
    if s9:
        w("## S9: overload, 1024 connections (offered: one absolute rate from campaign 3 on, 2 × the server's S1 SLO before)\n")
        w("Goodput: 2xx responses per second in the window; within SLO: answered ≤ 1 ms after the intended time; admitted p99: latency of the answered requests from when they were actually sent.\n")
        w("| server | offered | achieved | goodput | goodput within SLO | admitted p50 / p99 / p99.9 µs | errors |")
        w("|---|---:|---:|---:|---:|---|---:|")
        for s in S:
            x = [y for y in s9 if y.get("server") == s]
            if x:
                w(f"| {s} | {med([num(y.get('rate')) for y in x])} | {med([num(y.get('achieved')) for y in x])} | {med([num(y.get('goodput')) for y in x])} | "
                  f"{med([num(y.get('goodput_slo')) for y in x])} | {medv([num(y.get('ok_p50_us')) for y in x]) or 0:,.0f} / {medv([num(y.get('ok_p99_us')) for y in x]) or 0:,.0f} / {medv([num(y.get('ok_p999_us')) for y in x]) or 0:,.0f} | "
                  f"{med([num(y.get('errors')) for y in x])} |")
        w("")

    s10 = [x for x in R if x.get("scenario") == "S10"]
    if s10:
        att = recs["ATTACK"]
        w("## S10: legitimate p99 under 10k slowloris + 1k slow-read attackers (S1 at 50% of its SLO rate, 256 connections)\n")
        w("| server | no attack: p50 / p99 / p99.9 µs | under attack: p50 / p99 / p99.9 µs | errors under attack | slowloris closed by the server | slowloris still open at the end | slow readers open at the end |")
        w("|---|---|---|---:|---:|---:|---:|")
        for s in S:
            a = [y for y in s10 if y.get("server") == s and y.get("attack") == "none"]
            b = [y for y in s10 if y.get("server") == s and y.get("attack") != "none"]
            t = [y for y in att if y.get("server") == s]
            if a or b:
                f3 = lambda xs: " / ".join(f"{medv([num(y.get(k)) for y in xs]) or 0:,.0f}" for k in ("p50_us", "p99_us", "p999_us")) if xs else "-"
                w(f"| {s} | {f3(a)} | {f3(b)} | {med([num(y.get('errors')) for y in b])} | {med([num(y.get('slowloris_closed_by_server')) for y in t])} | "
                  f"{med([num(y.get('slowloris_open_end')) for y in t])} | {med([num(y.get('slowread_open_end')) for y in t])} |")
        w("")

    slo_table("HTTP/3: S1 over QUIC (SLO throughput, req/s, p99 ≤ 1 ms)", "H3", "conns", [64])
    hb = [x for x in R if x.get("scenario") == "H3bulk"]
    if hb:
        w("### HTTP/3 bulk download, closed loop\n")
        w("| server | 64 KB: req/s | 64 KB: Gbit/s | 1 MB: req/s | 1 MB: Gbit/s | 1 MB errors / incomplete |")
        w("|---|---:|---:|---:|---:|---|")
        for s in S:
            a = [y for y in hb if y.get("server") == s and y.get("size") == "64k"]
            b = [y for y in hb if y.get("server") == s and y.get("size") == "1m"]
            if a or b:
                w(f"| {s} | {med([num(y.get('achieved')) for y in a])} | {med([(num(y.get('mbit_in')) or 0) / 1000 for y in a], 2)} | "
                  f"{med([num(y.get('achieved')) for y in b])} | {med([(num(y.get('mbit_in')) or 0) / 1000 for y in b], 2)} | "
                  f"{med([num(y.get('errors')) for y in b])} / {med([num(y.get('incomplete')) for y in b])} |")
        w("")

    w("## Footprint\n")
    w("PSS summed over the server's processes. Per idle connection: (PSS with the connections − PSS before) / established. Cold start: spawn to the first 2xx, median of 10 (min–max), on the server node.\n")
    w("| server | base PSS | peak PSS under load | 10k idle: PSS, B/conn | 100k idle: PSS, B/conn | cold start ms |")
    w("|---|---:|---:|---|---|---|")
    for s in S:
        base = [num(x.get("pss_kb")) for x in recs["BASE"] if x.get("server") == s]
        # a PSS sampler left running by an interrupted run can concatenate lines: drop absurd values
        peak = [p for p in (num(x.get("pss_kb")) for x in recs["PEAK"] if x.get("server") == s) if p and p < 1e8]
        cells = []
        for ic in ("10000", "100000"):
            rr = [x for x in recs["IDLE"] if x.get("server") == s and x.get("conns") == ic]
            if not rr:
                cells.append("-")
            elif any(x.get("failed") for x in rr):
                cells.append("failed (" + ", ".join(x.get("established", "?") for x in rr) + " open)")
            else:
                est = medv([num(x.get("established")) for x in rr]) or 0
                c = f"{(medv([num(x.get('pss_kb')) for x in rr]) or 0) / 1024:,.1f} MB, {medv([num(x.get('per_conn_b')) for x in rr]) or 0:,.0f}"
                if est < int(ic) * 0.99:
                    c += f" ({est:,.0f} open)"
                cells.append(c)
        cs = [x for x in recs["COLDSTART"] if x.get("server") == s and not x.get("variant")]
        cold = f"{med([num(x.get('median_ms')) for x in cs], 2)} ({med([num(x.get('min_ms')) for x in cs], 2)}–{med([num(x.get('max_ms')) for x in cs], 2)})" if cs else "-"
        w(f"| {s} | {med([b / 1024 for b in base if b], 1, ' MB')} | {med([p / 1024 for p in peak if p], 1, ' MB')} | {cells[0]} | {cells[1]} | {cold} |")
    w("")

    cv = [x for x in recs["COLDSTART"] if x.get("variant")]
    if cv:
        w("### Cold start and size of the smallest builds (like-for-like with Cameleer's cameleer-http)\n")
        w("`min_server`: simoom's smallest server (default features; `-tls`: with the `tls` feature and TLS on 8443); `bench_server`: the facade's throughput probe; "
          "`server-no-tls`: the campaign server with TLS and QUIC off; cameleer-http-min `plain`: Cameleer's thread-pool server without TLS (its main row has TLS on 8443). "
          "Spawn to the first 2xx, median of 20 per round.\n")
        w("| server | variant | cold start ms (median of rounds) | stripped size |")
        w("|---|---|---:|---:|")
        keys = sorted({(x.get("server"), x.get("variant")) for x in cv})
        for sv, vn in keys:
            rr = [x for x in cv if x.get("server") == sv and x.get("variant") == vn]
            sz = [num(x.get("bytes")) for x in recs["SIZE"] if x.get("server") == sv and x.get("variant") == vn and num(x.get("bytes"))]
            w(f"| {sv} | {vn} | {med([num(x.get('median_ms')) for x in rr], 2)} | {med([z / 1024 for z in sz], 0, ' KB') if sz else '-'} |")
        w("")

    if PM:
        w("## Profiles at a fixed load (the same rate for every server)\n")
        w("simoom is the frame-pointer build (`simoom-prof`, epoll, fixed). perf stat and bpftrace on the server cgroup over 15 s; flat profiles, folded stacks and syscall histograms by name are in `prof/<case>/`. Cases: s1 = S1 at 60k req/s, 256 conns; s3 = 1 KB echo at 60k req/s; s5 = new connection per request at 8k/s; s7 = TLS full handshake per request at 2k/s; s8 = h2c 100 streams at 60k req/s.\n")
        w("| case | server | achieved | p99 µs | CPU µs/req | cycles/req | instr/req | ctx sw/req | syscalls/req |")
        w("|---|---|---:|---:|---:|---:|---:|---:|---:|")
        for m in sorted(PM, key=lambda x: (x.get("case", ""), x.get("server", ""))):
            rr = [x for x in PR if x.get("server") == m.get("server") and x.get("case") == m.get("case")]
            a = rr[-1] if rr else {}
            if not num(a.get("achieved")) or (num(a.get("errors")) or 0) > 0:
                continue
            w(f"| {m.get('case')} | {m.get('server')} | {fmt0(a.get('achieved'))} | {fmt0(a.get('p99_us'))} | {m.get('cpu_us_per_req')} | {m.get('cycles_per_req')} | {m.get('instr_per_req')} | {m.get('ctxsw_per_req')} | {m.get('syscalls_per_req')} |")
        w("")

    w("## Load generator health\n")
    flagged = [x for x in R if x.get("load_node_over_60pct") == "1"]
    node = [num(x.get("node_cpu_pct")) for x in R if num(x.get("node_cpu_pct")) is not None]
    lag = [num(x.get("lag_p99_us")) for x in R if num(x.get("lag_p99_us")) is not None]
    w(f"- runs: {len(R)}; flagged (a load node over 60% CPU): {len(flagged)}; highest load-node CPU: {max(node) if node else 0:.1f}%")
    if flagged:
        w("- flagged runs: " + ", ".join(sorted({f"{x.get('server')} {x.get('scenario')} {x.get('phase', '')}" for x in flagged})))
    w(f"- worst open-loop timer lag p99: {max(lag) if lag else 0:,.0f} µs")
    print("\n".join(out))


if __name__ == "__main__":
    main()
