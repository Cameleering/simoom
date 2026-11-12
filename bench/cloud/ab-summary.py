#!/usr/bin/env python3
"""Tables from bench/cloud/ab.sh results: S1 SLO throughput per variant and connection count, fixed
rates (FR) with the network counters of their NET lines, S9 overload goodput, S7 handshakes, per-CPU
load (MP) and per-loop connection counts (STATS lines).

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
    fr = defaultdict(list)        # (variant, conns, offered) -> [RESULT fields per round]
    net = defaultdict(list)       # (variant, conns, offered, node kind) -> [NET fields per round]
    hs = defaultdict(list)        # (variant, kind) -> [achieved]
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
            if kind == 'SLO' and f.get('scenario') == 'S1':
                slo[(v, int(f['conns']))].append(int(f['slo_rps']))
            elif kind == 'RESULT' and f.get('scenario') == 'S9':
                s9[v].append(f)
            elif kind == 'RESULT' and f.get('scenario') == 'MP':
                mpres[v] = f
            elif kind == 'MPSTAT':
                mp[v].append(f)
            elif kind == 'STATS':
                stats[v].append(line)
            elif kind == 'RESULT' and f.get('scenario') == 'FR':
                fr[(v, int(f['conns']), int(f['offered']))].append(f)
            elif kind == 'NET' and f.get('scenario') == 'FR':
                node = 'srv' if f.get('node') == 'srv' else 'load'
                net[(v, int(f['conns']), int(f['offered']), node)].append(f)
            elif kind == 'RESULT' and f.get('scenario') == 'S7' and f.get('kind') in ('full', 'resumed'):
                hs[(v, f['kind'])].append(float(f['achieved']))
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
    if fr:
        print('\n## FR: fixed rates, p99 us per round (* = over 1 ms), p99.9 and max of the worst round\n')
        print('| variant | conns | offered | p99 per round | worst p99.9 | worst max | retrans srv/load | softnet drop | NIC drop | where the server ran (CPU:samples) |')
        print('|---|---:|---:|---|---:|---:|---|---:|---:|---|')
        for (v, c, o) in sorted(fr, key=lambda k: (k[1], k[2], order.index(k[0]))):
            rs = fr[(v, c, o)]
            p99 = ' / '.join(f"{float(r['p99_us']):,.0f}{'*' if float(r['p99_us']) > 1000 else ''}" for r in rs)
            worst = max(rs, key=lambda r: float(r['p99_us']))
            ns = net.get((v, c, o, 'srv'), [])
            nl = net.get((v, c, o, 'load'), [])
            rt_s = sum(int(n.get('RetransSegs', 0)) for n in ns)
            rt_l = sum(int(n.get('RetransSegs', 0)) for n in nl)
            sd = sum(int(n.get('softnet_drop,squeeze', '0,0').split(',')[0]) for n in ns + nl)
            nd = sum(int(n.get('nic_drop,missed', '0,0').split(',')[0]) for n in ns + nl)
            place = defaultdict(int)
            for n in ns:
                for kv in n.get('running_cpu', '').split(','):
                    if ':' in kv:
                        a, b = kv.split(':')
                        place[a] += int(b)
            pl = ','.join(f'{k}:{place[k]}' for k in sorted(place, key=int))
            print(f"| {v} | {c} | {o:,} | {p99} | {float(worst['p999_us']):,.0f} | {float(worst['max_us']):,.0f} | {rt_s}/{rt_l} | {sd} | {nd} | {pl} |")
    if hs:
        print('\n## S7: TLS handshakes per second (closed loop, 192 connections), per run\n')
        print('| variant | full | resumed |')
        print('|---|---|---|')
        for v in order:
            if (v, 'full') in hs or (v, 'resumed') in hs:
                def cell(k):
                    return ' / '.join(f'{x:,.0f}' for x in hs.get((v, k), []))
                print(f'| {v} | {cell("full")} | {cell("resumed")} |')
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
            print(f'- {v}: {", ".join(act)}')


if __name__ == '__main__':
    main(sys.argv[1:])
