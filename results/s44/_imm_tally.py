#!/usr/bin/env python3
"""Tally the validated immediate check (addendum A4): per corpus, modules and functions, with rule RS applied to
the output and raw counts alongside. usage: _imm_tally.py imm-*.jsonl"""
import collections, json, math, sys

RS = {"init_module", "cleanup_module", "__pfx_init_module", "__pfx_cleanup_module"}


def wilson_upper(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    return (p + z * z / (2 * n) + z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d


tab = collections.defaultdict(lambda: collections.Counter())
rest = []
for path in sys.argv[1:]:
    for line in open(path):
        r = json.loads(line)
        t = tab[r["corpus"]]
        t["rows"] += 1
        v = r["verdict"]
        t["raw_" + v] += 1
        if v == "DIVERGENT":
            keep = [f for f in r["divergent"] if f not in RS]
            v = "DIVERGENT" if keep else "CONSISTENT"
            if keep:
                rest.append((r["corpus"], r["pkg"], r["patch"], r["ko"], keep, r.get("mod_cc"), r.get("ref_cc")))
        t[v] += 1
        if r.get("functions"):
            t["functions"] += r["functions"]
        if r.get("mod_cc") and r.get("ref_cc") and not set(r["mod_cc"]) & set(r["ref_cc"]):
            t["toolchain_differs"] += 1
        if r.get("undecoded"):
            t["with_undecoded"] += 1

for c, t in tab.items():
    n = t["CONSISTENT"] + t["DIVERGENT"]
    print(c, dict(t), "wilson_upper_div=%.4f" % (wilson_upper(t["DIVERGENT"], n) or 0))
print("remaining DIVERGENT after RS:")
for x in rest:
    print(" ", x)
