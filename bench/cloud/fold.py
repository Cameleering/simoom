#!/usr/bin/env python3
"""Folds `perf script` output into flame-graph lines: `comm;outer;...;inner count` (stdlib only,
the format of Brendan Gregg's stackcollapse-perf.pl). Reads stdin, writes stdout sorted by count."""
import re
import sys
from collections import Counter

counts = Counter()
comm, stack = None, []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line.strip():
        if comm is not None:
            counts[";".join([comm] + stack[::-1])] += 1
        comm, stack = None, []
        continue
    if not line.startswith((" ", "\t")):
        comm = line.split()[0] if line.split() else "?"
        continue
    parts = line.strip().split(None, 1)
    if len(parts) == 2:
        sym = re.sub(r"\+0x[0-9a-f]+$", "", parts[1].split(" (")[0])
        stack.append(sym.replace(";", ":"))
if comm is not None:
    counts[";".join([comm] + stack[::-1])] += 1
for k, v in counts.most_common():
    print(f"{k} {v}")
