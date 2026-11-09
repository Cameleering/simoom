"""zlib (through Python's zlib module) on the files written by
`bench_compress --write-corpus DIR`, measured like bench_compress: gzip format, levels 1, 6 and
9, compress input MB/s, decompress output MB/s, best of five timed runs."""

import sys
import time
import zlib
from pathlib import Path


def best(f):
    b = float("inf")
    for _ in range(5):
        t = time.perf_counter()
        n = 0
        while time.perf_counter() - t < 0.15:
            f()
            n += 1
        b = min(b, (time.perf_counter() - t) / n)
    return b


def main():
    d = Path(sys.argv[1])
    print(f"zlib {zlib.ZLIB_RUNTIME_VERSION}")
    print("| input | size | impl | level | ratio | compress MB/s | decompress MB/s |")
    print("|---|---:|---|---:|---:|---:|---:|")
    for name in ["json", "log", "source", "binary", "random"]:
        data = (d / name).read_bytes()
        for level in (1, 6, 9):
            def comp():
                c = zlib.compressobj(level, zlib.DEFLATED, 31)
                return c.compress(data) + c.flush()
            out = comp()
            assert zlib.decompress(out, 47) == data
            c = best(comp)
            dd = best(lambda: zlib.decompress(out, 47))
            print(f"| {name} | {len(data)} | zlib | {level} | {len(out) / len(data):.3f} | {len(data) / c / 1e6:.1f} | {len(data) / dd / 1e6:.1f} |")


if __name__ == "__main__":
    main()
