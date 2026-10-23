#!/usr/bin/env python3
"""S43 summary of one arm (outcomes 1-4 of internal/S43-PREREG-2026-10-21.md). Wilson 95% intervals; package-level
bootstrap (2,000 resamples, seed 43) for the module false-alarm rate and per-operator detection.
usage: s43_summary.py <results.jsonl>"""
import json, math, random, sys
from collections import Counter, defaultdict


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - a) / d, 4), round((c + a) / d, 4)]


recs = [json.loads(l) for l in open(sys.argv[1])]
support = Counter()
mods = []                       # (pkg, verdict, funcs, divergent funcs)
det = defaultdict(list)         # op -> [(pkg, detected)]
det_bad_parent = Counter()
excluded = Counter()
sites = defaultdict(lambda: [0, 0])   # op -> [modules with eligible sites, modules]
for r in recs:
    if r.get("status"):
        support[r["status"]] += 1
        continue
    support["package scored"] += 1
    for m in r["modules"]:
        if m.get("status"):
            support[m["status"].split(" ")[0]] += 1
            continue
        v = m["v20"]
        mods.append((r["pkg"], v["overall"], v["funcs"], len(v["div"]), m["v18"]["overall"]))
        for op, o in m.get("ops", {}).items():
            if "error" in o:
                continue
            sites[op][1] += 1
            sites[op][0] += o["eligible"] > 0
            for mu in o["mutants"]:
                if "excluded" in mu:
                    excluded[(op, mu["excluded"].split(":")[0].split(" of ")[0])] += 1
                    continue
                hit = mu["v20"]["overall"] in ("DIVERGENT", "LOAD_FAIL")
                if v["overall"] == "CONSISTENT":
                    det[op].append((r["pkg"], hit, mu["v18"]["overall"] in ("DIVERGENT", "LOAD_FAIL")))
                else:
                    det_bad_parent[op] += 1

pk = sorted({p for p, *_ in mods})
fa = [(p, v != "CONSISTENT") for p, v, *_ in mods]
funcs = sum(m[2] for m in mods)
divf = sum(m[3] for m in mods)


def boot(rows, seed=43, n=2000):
    by = defaultdict(list)
    for p, x, *_ in rows:
        by[p].append(x)
    keys = sorted(by)
    if not keys:
        return None
    rng = random.Random(seed)
    vals = []
    for _ in range(n):
        s = [rng.choice(keys) for _ in keys]
        tot = sum(len(by[k]) for k in s)
        vals.append(sum(sum(by[k]) for k in s) / tot if tot else 0)
    vals.sort()
    return [round(vals[int(0.025 * n)], 4), round(vals[int(0.975 * n) - 1], 4)]


print("support:", dict(support))
print(f"modules scored {len(mods)} in {len(pk)} packages; v2.0 verdicts {dict(Counter(m[1] for m in mods))}; "
      f"v1.8 verdicts {dict(Counter(m[4] for m in mods))}")
k = sum(x for _, x in fa)
print(f"false alarms (module): {k}/{len(fa)} wilson {wilson(k, len(fa))} bootstrap {boot(fa)}")
print(f"patched functions compared {funcs}, divergent {divf}, wilson {wilson(divf, funcs)}")
for op in sorted(set(det) | set(sites)):
    rows = det.get(op, [])
    k = sum(h for _, h, _ in rows)
    k18 = sum(h for _, _, h in rows)
    print(f"{op:12s} detected {k}/{len(rows)} wilson {wilson(k, len(rows))} bootstrap {boot([(p, h) for p, h, _ in rows])} "
          f"| v1.8 {k18}/{len(rows)} | modules with sites {sites[op][0]}/{sites[op][1]} | non-consistent parent {det_bad_parent[op]}")
print("excluded before scoring:", dict(excluded))
for p, v, f, d, v18 in mods:
    if v != "CONSISTENT":
        print("  alarm:", p, v, "funcs", f, "divergent", d, "v1.8", v18)
