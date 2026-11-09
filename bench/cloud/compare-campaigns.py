#!/usr/bin/env python3
"""Compare two simoom campaigns axis by axis (the leaderboard of summarize-campaign.py).

    python3 bench/cloud/compare-campaigns.py bench/results/2026-11-07-campaign bench/results/<date>-campaign2

For every axis: the best simoom variant in each campaign, the change, the best other server in
each, and simoom's margin against it. Stdlib only.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("summ", os.path.join(HERE, "summarize-campaign.py"))
summ = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summ)


def board(d):
    return {x["axis"]: x for x in summ.leaderboard(summ.parse(os.path.join(d, "results.txt")))}


def main():
    a, b = sys.argv[1], sys.argv[2]
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    A, B = board(a), board(b)
    print(f"| axis | unit | campaign 1: best simoom | campaign 2: best simoom | change | campaign 1: best other | campaign 2: best other | margin 1 | margin 2 |")
    print("|---|---|---|---|---:|---|---|---:|---:|")
    for axis in list(B) + [x for x in A if x not in B]:
        x, y = A.get(axis), B.get(axis)
        ref = y or x
        unit, hib = ref["unit"], ref["hib"]
        f = lambda r, k, n: f"{r[n] or '-'} {summ.fmtv(r[k], unit)}" if r and r.get(n) else "-"
        ch = "-"
        if x and y and x.get("simoom_v") and y.get("simoom_v"):
            c = (y["simoom_v"] / x["simoom_v"] - 1) * 100
            ch = f"{c if hib else -c:+.1f}%"
        m = lambda r: "-" if not r or r.get("margin") is None else f"{r['margin']:+.1f}%"
        print(f"| {axis} | {unit} {'↑' if hib else '↓'} | {f(x, 'simoom_v', 'simoom')} | {f(y, 'simoom_v', 'simoom')} | {ch} | "
              f"{f(x, 'other_v', 'other')} | {f(y, 'other_v', 'other')} | {m(x)} | {m(y)} |")
    print("\nchange: improvement of simoom's best variant (positive is better on every axis); margin: simoom's best against the best other server (positive: simoom ahead).")


if __name__ == "__main__":
    main()
