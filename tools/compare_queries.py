# SPDX-License-Identifier: AGPL-3.0-only
"""Compare two query recordings (tests/conftest.py, OCC_RECORD): per test, the multiset of queries must match.

    OCC_RECORD=/tmp/before.jsonl pytest -q -p no:randomly
    OCC_RECORD=/tmp/after.jsonl  pytest -q -p no:randomly
    python tools/compare_queries.py /tmp/before.jsonl /tmp/after.jsonl
"""
import json
import sys
from collections import Counter, defaultdict


def load(p):
    d = defaultdict(Counter)
    for ln in open(p, encoding="utf-8"):
        r = json.loads(ln)
        d[r["t"]][(r["k"], r["i"], r["b"])] += 1
    return d


def main(a, b):
    x, y = load(a), load(b)
    bad = 0
    for t in sorted(set(x) | set(y)):
        if x[t] != y[t]:
            bad += 1
            print("DIFF", t)
            for q in (x[t] - y[t]):
                print("  -", q[0], q[1], q[2][:300])
            for q in (y[t] - x[t]):
                print("  +", q[0], q[1], q[2][:300])
    print(f"{len(set(x) | set(y))} tests, {sum(sum(c.values()) for c in x.values())} queries before, "
          f"{sum(sum(c.values()) for c in y.values())} after, {bad} differ")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
