#!/usr/bin/env python3
"""Tables from bench/cloud/ab.sh results: S1 SLO throughput per variant and connection count, S9
overload goodput, per-CPU load (MP) and per-loop connection counts (STATS lines).

    python3 bench/cloud/ab-summary.py results.txt [more results.txt ...]
"""
import re
import sys
from collections import defaultdict


def fields(line):
    return dict(re.findall(r'(\w+)=(\S+)', line))


def main(paths):
    slo = defaultdict(list)       # (variant, conns) -> [slo_rps per round]
    s9 = defaultdict(list)        # variant -> [record]
    mp = defaultdict(list)        # variant -> [(cpu, usr, sys, soft, steal, idle)]
    mpres = {}                    # variant -> RESULT of the MP run
    stats = defaultdict(list)     # variant -> [STATS line fields]
    order = []
    for p in paths:
        for line in open(p, encoding='utf-8'):
            kind = line.split(' ', 1)[0]
            f = fields(line)
            v = f.get('variant')
            if not v:
                continue
            if v not in order:
                order.append(v)
            if kind == 'SLO':
                slo[(v, int(f['conns']))].append(int(f['slo_rps']))
            elif kind == 'RESULT' and f.get('scenario') == 'S9':
                s9[v].append(f)
            elif kind == 'RESULT' and f.get('scenario') == 'MP':
                mpres[v] = f
            elif kind == 'MPSTAT':
                mp[v].append(f)
            elif kind == 'STATS':
                stats[v].append(line)
    print('## S1: SLO throughput (req/s, p99 <= 1 ms), per round\n')
    print('| variant | 64 | 256 | 1024 |')
    print('|---|---:|---:|---:|')
    for v in order:
        cells = []
        for c in (64, 256, 1024):
            r = slo.get((v, c))
            cells.append(' / '.join(f'{x:,}' for x in r) if r else '')
        if any(cells):
            print(f'| {v} | ' + ' | '.join(cells) + ' |')
    if s9:
        print('\n## S9: 1024 connections at 195,000 req/s offered\n')
        print('| variant | goodput | within 1 ms | admitted p50 us | admitted p99 us | incomplete |')
        print('|---|---:|---:|---:|---:|---:|')
        for v in order:
            for f in s9.get(v, []):
                print(f"| {v} | {float(f['goodput']):,.0f} | {float(f['goodput_slo']):,.0f} | {f['ok_p50_us']} | {f['ok_p99_us']} | {f['incomplete']} |")
    if mp:
        print('\n## MP: 256 connections at a fixed rate, server CPUs (mpstat, %)\n')
        print('| variant | achieved | p99 us | cpu: usr/sys/soft/steal/idle ... |')
        print('|---|---:|---:|---|')
        for v in order:
            if v not in mp:
                continue
            r = mpres.get(v, {})
            cpus = ' ; '.join(f"{c['cpu']}: {c['usr']}/{c['sys']}/{c['soft']}/{c['steal']}/{c['idle']}" for c in mp[v])
            print(f"| {v} | {r.get('achieved', '')} | {r.get('p99_us', '')} | {cpus} |")
    if stats:
        print('\n## Connections per loop (the STATS line with the most connections open)\n')
        for v in order:
            if not stats.get(v):
                continue
            best = max(stats[v], key=lambda l: sum(int(x) for x in re.findall(r'loop\d+=active:(\d+)', l)))
            act = re.findall(r'loop\d+=active:(\d+)', best)
            starved = re.findall(r'starved:(\d+)', best)
            print(f'- {v}: {", ".join(act)} (receives without a buffer in that interval: {", ".join(starved)})')


if __name__ == '__main__':
    main(sys.argv[1:])
