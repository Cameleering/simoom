#!/usr/bin/env python3
"""Campaign 4 report: every competitor against simoom on the same droplet.

    python bench/cloud/c4-report.py bench/results/<date>-campaign4/results.txt > report.md
    python bench/cloud/c4-report.py results.txt --json > c4.json

simoom runs in every lane and every round. For each metric and each competitor, the ratio is taken
per (lane, round) against the simoom run of that same lane and round, so both ran on the same
droplet with the same load nodes; the published ratio is the median over rounds. Absolute values are
medians over rounds too. Std-only.
"""
import json
import re
import statistics
import sys
from collections import defaultdict

REF = "simoom"


def parse(path):
    recs = defaultdict(list)
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if " " not in line:
            continue
        kind, rest = line.split(" ", 1)
        kv = {}
        for k, v in re.findall(r"(\w+)=(\S+)", rest):
            kv.setdefault(k, v)
        recs[kind].append(kv)
    return recs


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def cell(x):
    return (x.get("session", "s1"), x.get("round", "1"))


# metric: (id, use case, title, unit, higher_is_better, extractor(recs) -> {server: {(lane, round): value}})
def verified(scen, keyname, key, limit_us, extra=None):
    def f(R):
        out = defaultdict(dict)
        rows = [x for x in R["RESULT"] if x.get("scenario") == scen and x.get(keyname) == str(key) and x.get("phase") == "point"
                and (extra is None or all(x.get(k) == v for k, v in extra.items()))]
        groups = defaultdict(list)
        for x in rows:
            groups[(x["server"], cell(x))].append(x)
        for (srv, c), pts in groups.items():
            ok = [num(p.get("achieved")) for p in pts if (num(p.get("p99_us")) or 1e18) <= limit_us and num(p.get("errors")) == 0]
            out[srv][c] = max(ok) if ok else 0.0
        return out
    return f


def closed(scen, field, extra):
    def f(R):
        out = defaultdict(dict)
        for x in R["RESULT"]:
            if x.get("scenario") == scen and all(x.get(k) == v for k, v in extra.items()) and x.get("phase") in ("closed", "measure", None):
                v = num(x.get(field))
                if v is not None:
                    out[x["server"]][cell(x)] = v
        return out
    return f


def rec(kind, field, extra=None, absent=()):
    def f(R):
        out = defaultdict(dict)
        for x in R[kind]:
            if extra and not all(x.get(k) == v for k, v in extra.items()):
                continue
            if any(k in x for k in absent):
                continue
            v = num(x.get(field))
            if v is not None:
                out[x["server"]][cell(x)] = v
        return out
    return f


def fixed_rate(field):
    # the CPU scenario: every server at the same 50,000 req/s on 256 connections
    def f(R):
        out = defaultdict(dict)
        for x in R["RESULT"]:
            if x.get("scenario") == "cpufix":
                v = num(x.get(field))
                if v is not None:
                    out[x["server"]][cell(x)] = v
        return out
    return f


def speak_metric(scen):
    def f(R):
        d = SPEAK_TS.get(scen, {})
        return d
    return f


SPEAK_TS = {}


METRICS = [
    ("s1-64", "status", "Status endpoint, 64 clients: requests/s with 99% within 1 ms", "req/s", True, verified("S1", "conns", 64, 1000)),
    ("s1-256", "status", "Status endpoint, 256 clients: requests/s with 99% within 1 ms", "req/s", True, verified("S1", "conns", 256, 1000)),
    ("s1-1024", "status", "Status endpoint, 1,024 clients: requests/s with 99% within 1 ms", "req/s", True, verified("S1", "conns", 1024, 1000)),
    ("p99-50k", "status", "Latency at a fixed 50,000 requests/s (256 clients): p99", "µs", False, fixed_rate("p99_us")),
    ("cpu-50k", "status", "CPU per request at a fixed 50,000 requests/s", "µs", False, rec("METRIC", "cpu_us_per_req", {"scenario": "cpufix"})),
    ("s3", "api", "JSON API, 1 KB in and out, 256 clients: requests/s with 99% within 1 ms", "req/s", True, verified("S3", "conns", 256, 1000)),
    ("s4-64k", "download", "64 KB downloads, 64 clients: requests/s with 99% within 5 ms", "req/s", True, verified("S4", "conns", 64, 5000, {"size": "64k"})),
    ("s5", "newconn", "A new connection per request, 192 clients: requests/s with 99% within 5 ms", "req/s", True, verified("S5", "conns", 192, 5000)),
    ("s7-tls", "https", "HTTPS API, 256 clients: requests/s with 99% within 1 ms", "req/s", True, verified("S7", "conns", 256, 1000, {"kind": "S1-tls"})),
    ("s7-full", "https", "New TLS 1.3 clients: full handshakes per second", "/s", True, closed("S7", "achieved", {"kind": "full"})),
    ("s7-resumed", "https", "Returning TLS 1.3 clients: resumed handshakes per second", "/s", True, closed("S7", "achieved", {"kind": "resumed"})),
    ("s8", "h2", "Service-to-service HTTP/2, 64 connections x 100 streams: requests/s with 99% within 5 ms", "req/s", True, verified("S8", "conns", 64, 5000)),
    ("h3", "h3", "HTTP/3, 64 clients: requests/s with 99% within 1 ms", "req/s", True, verified("H3", "conns", 64, 1000)),
    ("s9", "spike", "Traffic spike at 195,000 requests/s offered: answers within 1 ms per second", "req/s", True, closed("S9", "goodput_slo", {})),
    ("s9-total", "spike", "Traffic spike: all answers per second", "req/s", True, closed("S9", "goodput", {})),
    ("s10", "attack", "Under 11,000 slow attackers: p99 of real requests", "µs", False, closed("S10", "p99_us", {"attack": "slowloris10k+slowread1k"})),
    ("idle-10k", "idle", "10,000 idle connections: memory per connection", "B", False, rec("IDLE", "per_conn_b", {"conns": "10000"})),
    ("idle-100k", "idle", "100,000 idle connections: memory per connection", "B", False, rec("IDLE", "per_conn_b", {"conns": "100000"})),
    ("cold", "footprint", "Start-up: process start to first answer", "ms", False, rec("COLDSTART", "median_ms", absent=("variant",))),
    ("size", "footprint", "Program size, stripped", "KB", False, lambda R: {k: {c: v / 1024 for c, v in d.items()} for k, d in rec("SIZE", "bytes", absent=("variant",))(R).items()}),
    ("base", "footprint", "Memory at rest (PSS)", "KB", False, rec("BASE", "pss_kb")),
    ("peak", "footprint", "Peak memory over the whole run (PSS)", "KB", False, rec("PEAK", "pss_kb")),
    ("peak-s1", "footprint", "Peak memory while serving the status endpoint (PSS)", "KB", False, speak_metric("S1")),
    ("peak-s3", "footprint", "Peak memory while serving the JSON API (PSS)", "KB", False, speak_metric("S3")),
    ("peak-s7", "footprint", "Peak memory while serving HTTPS (PSS)", "KB", False, speak_metric("S7")),
    ("peak-h3", "footprint", "Peak memory while serving HTTP/3 (PSS)", "KB", False, speak_metric("H3")),
]


def speak_from_samples(raw_dir):
    """Peak PSS per (server, scenario, lane, round) from the timestamped samplers on the server
    droplets (raw/lane1/pss-ts-srvX.log: "epoch pss_kb" every second) and each lane's progress.txt
    (the time each scenario finished; it started when the previous entry of that lane finished)."""
    import datetime
    import glob
    import os
    samples = {}
    for f in glob.glob(os.path.join(raw_dir, "lane*", "pss-ts-*.log")):
        srv = os.path.basename(f)[len("pss-ts-"):-len(".log")]
        pts = []
        for line in open(f, encoding="utf-8", errors="replace"):
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                pts.append((int(parts[0]), int(parts[1])))
        samples[srv] = sorted(pts)
    out = defaultdict(lambda: defaultdict(dict))
    if not samples:
        return out
    for lane_dir in sorted(glob.glob(os.path.join(raw_dir, "lane*"))):
        lane = os.path.basename(lane_dir)
        droplet = {}
        mf = os.path.join(lane_dir, "machine.txt")
        if os.path.exists(mf):
            for line in open(mf, encoding="utf-8"):
                m = re.match(r"MACHINE round=(\d+) lane=\d+ srv=(\S+)", line)
                if m:
                    droplet[m.group(1)] = m.group(2)
        pf = os.path.join(lane_dir, "progress.txt")
        if not os.path.exists(pf):
            continue
        prev = None
        for line in open(pf, encoding="utf-8"):
            m = re.match(r"(\S+Z) round=(\d+) server=(\S+) scenario=(\S+)", line)
            if not m:
                continue
            t = int(datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp())
            rnd, srvname, scen = m.group(2), m.group(3), m.group(4)
            if prev is not None and scen not in ("S6", "COLD"):
                pts = samples.get(droplet.get(rnd, ""), [])
                vals = [v for (ts, v) in pts if prev < ts <= t]
                if vals:
                    out[(srvname, scen)][(lane, rnd)] = max(vals)
            prev = t
    return out


def med(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def compute(R):
    out = {}
    for mid, use, title, unit, hib, fn in METRICS:
        data = fn(R)
        ref = data.get(REF, {})
        rows = {}
        for srv, cells in data.items():
            ratios = []
            for c, v in cells.items():
                r = ref.get(c)
                if r is None or v is None:
                    continue
                if hib:
                    ratios.append(r / v if v > 0 else None)   # >1: simoom ahead
                else:
                    ratios.append(v / r if r > 0 else None)   # >1: simoom ahead (less is better)
            ratios = [x for x in ratios if x is not None]
            rows[srv] = {
                "value": med(cells.values()),
                "rounds": len(cells),
                "lanes": sorted({c[0] for c in cells}),
                "simoom_same_droplet": med([ref[c] for c in cells if c in ref]),
                "simoom_advantage": med(ratios) if ratios else None,
                "samples": len(ratios),
            }
        out[mid] = {"use": use, "title": title, "unit": unit, "higher_is_better": hib, "rows": rows}
    return out


def fmt(v, unit):
    if v is None:
        return "-"
    if unit in ("ms",):
        return f"{v:,.2f} {unit}"
    if unit in ("µs",) and v < 100:
        return f"{v:,.1f} {unit}"
    return f"{v:,.0f} {unit}"


def adv(a):
    if a is None:
        return "-"
    if 0.97 <= a <= 1.03:
        return "level (within 3%)"
    if a >= 1:
        return f"simoom {a:.2f}x"
    return f"**{1 / a:.2f}x ahead of simoom**"


def markdown(res):
    lines = ["# Campaign 4: every competitor against simoom on the same droplet", "",
             "Each ratio compares a server with the simoom run on the same droplet, with the same load nodes, in the same round;",
             "the figure is the median over rounds. `simoom 1.30x` means simoom is 1.30 times better on that metric",
             "(more throughput, or less latency, memory or time). Losses are marked in bold.", ""]
    for mid, m in res.items():
        rows = m["rows"]
        if not rows:
            continue
        lines += [f"## {m['title']}", "", f"`{mid}` · use case `{m['use']}` · {'higher' if m['higher_is_better'] else 'lower'} is better", "",
                  "| server | value | simoom on the same droplet | comparison | runs |", "|---|---:|---:|---|---:|"]
        order = sorted(rows.items(), key=lambda kv: (-(kv[1]["value"] or 0) if m["higher_is_better"] else (kv[1]["value"] if kv[1]["value"] is not None else 1e18)))
        for srv, r in order:
            name = f"**{srv}**" if srv == REF else srv
            comp = "reference" if srv == REF else adv(r["simoom_advantage"])
            lines.append(f"| {name} | {fmt(r['value'], m['unit'])} | {fmt(r['simoom_same_droplet'], m['unit']) if srv != REF else '-'} | {comp} | {r['rounds']} |")
        lines.append("")
    return "\n".join(lines)


def main():
    R = parse(sys.argv[1])
    import os
    raw = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "raw")
    for (srv, scen), cells in speak_from_samples(raw).items():
        scen = "S1" if scen == "S1R" else scen
        SPEAK_TS.setdefault(scen, defaultdict(dict))[srv].update(cells)
    res = compute(R)
    if "--json" in sys.argv:
        json.dump(res, sys.stdout, indent=1, ensure_ascii=False)
    else:
        print(markdown(res))


if __name__ == "__main__":
    main()
