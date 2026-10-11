#!/usr/bin/env python3
"""Loader and livepatch core on the S2 operator mutants (real-fix and fixture modules) and their parents,
paired with the binding oracle v1.1 verdicts of the same mutants (lab/s2/s2-s12-fixtures-2026-10-09.json).

A mutant is detected by the loader when it fails loudly: rejected at load, kernel crash, never `enabled`,
or transition not completed within 60 s. LOADED_ENABLED is silent acceptance. LOADED_NOT_LIVEPATCH (an
in-tree fixture module that is not a livepatch) is reported apart and excluded from the rates, as in the
fixture analysis. Wilson 95% intervals; exact McNemar test of loader against oracle on the same mutants.

Usage: python analyse_loader_s2.py s2-loader/loader-baseline.json ../s2/s2-s12-fixtures-2026-10-09.json OUT.json
"""

import json
import math
import sys
from collections import Counter, defaultdict

LOUD = {"CRASH", "LOAD_FAIL", "NOT_ENABLED", "TIMEOUT"}


def wilson(k, n, z=1.959964):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 4), round(min(1, c + h), 4)]


def mcnemar(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


loader = json.load(open(sys.argv[1], encoding="utf-8"))["rows"]
s2 = json.load(open(sys.argv[2], encoding="utf-8"))["rows"]
oracle = {}
for row in s2:
    for m in row["mutants"]:
        if not m.get("built") or m.get("noop") or m.get("duplicate_of"):
            continue
        tail = "/".join(m["path"].split("/")[-3:])          # s12/6.1__CVE-2025-38100/swap-39.ko
        oracle[tail] = m["v1.1"]["overall"] == "DIVERGENT"

out = {"parents": Counter(), "sets": {}, "excluded_parent_not_accepted": Counter()}
groups = defaultdict(list)
# A mutant counts only if its unmodified parent was accepted (as in the fixture analysis): the parents of
# CVE-2026-64435 never complete their transition (Section 7.1), so their mutants would time out regardless.
bad_parents = {"/".join(r["id"].split("/")[1:3]) for r in loader
               if r["id"].startswith("s2parent/") and r["outcome"] != "LOADED_ENABLED"}
for r in loader:
    parts = r["id"].split("/")
    if parts[0] == "s2parent":
        out["parents"][r["outcome"]] += 1
        continue
    _, st = parts[0], parts[1]
    op = parts[-1].rsplit("-", 1)[0]
    if st == "s12" and f"{parts[2]}/{parts[3]}" in bad_parents:
        out["excluded_parent_not_accepted"][op] += 1
        continue
    if st == "s12":
        tail = f"s12/{parts[2]}__{parts[3]}/{parts[4]}.ko"
    else:
        tail = f"fixtures/{'__'.join(parts[2:-1])}/{parts[-1]}.ko"
    groups[(st, op)].append((r["outcome"], oracle.get(tail)))

for (st, op), rows in sorted(groups.items()):
    lp = [(o, v) for o, v in rows if o != "LOADED_NOT_LIVEPATCH"]
    n = len(lp)
    loud = sum(o in LOUD for o, _ in lp)
    paired = [(o in LOUD, v) for o, v in lp if v is not None]
    b = sum(v and not l for l, v in paired)     # oracle detects, loader silent
    c = sum(l and not v for l, v in paired)     # loader detects, oracle misses
    out["sets"].setdefault(st, {})[op] = {
        "mutants": len(rows), "not_livepatch": len(rows) - n, "livepatch": n,
        "outcomes": dict(Counter(o for o, _ in lp)),
        "loader_detected": loud, "loader_detected_rate": round(loud / n, 4) if n else None,
        "loader_detected_ci95": wilson(loud, n), "accepted_silently": n - loud,
        "paired_with_oracle": len(paired), "oracle_only": b, "loader_only": c,
        "both": sum(l and v for l, v in paired), "neither": sum((not l) and (v is False) for l, v in paired),
        "mcnemar_exact_p": mcnemar(b, c)}

for st, ops in out["sets"].items():
    n = sum(v["livepatch"] for v in ops.values())
    k = sum(v["loader_detected"] for v in ops.values())
    ops["_all"] = {"livepatch": n, "loader_detected": k, "loader_detected_rate": round(k / n, 4),
                   "loader_detected_ci95": wilson(k, n),
                   "oracle_only": sum(v["oracle_only"] for v in ops.values()),
                   "loader_only": sum(v["loader_only"] for v in ops.values())}
out["parents"] = dict(out["parents"])
out["excluded_parent_not_accepted"] = dict(out["excluded_parent_not_accepted"])
out["bad_parents"] = sorted(bad_parents)
json.dump(out, open(sys.argv[3], "w", encoding="utf-8"), indent=1)
print(json.dumps(out["parents"]), out["bad_parents"], out["excluded_parent_not_accepted"])
for st, ops in out["sets"].items():
    for op, v in ops.items():
        print(st, op, v.get("livepatch"), v.get("loader_detected"), v.get("loader_detected_rate"), v.get("loader_detected_ci95"),
              "oracle_only", v.get("oracle_only"), "loader_only", v.get("loader_only"), "p", v.get("mcnemar_exact_p"))
