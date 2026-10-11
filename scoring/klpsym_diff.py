#!/usr/bin/env python3
"""Compare the livepatch symbol bindings (.klp.sym.* names, with positions) of two sets of modules built
from the same fixes. Raw data only, no oracle: a difference says the two releases bind different
symbols or positions for the same fix, not which one is right.

Usage (build host): python3 klpsym_diff.py RESULTS_A RESULTS_B   e.g. results/v0.9.10-gcc-14/6.12 results/v0.9.11-gcc-14/6.12
"""
import glob
import json
import os
import re
import subprocess
import sys


def klp_syms(ko: str) -> set[str]:
    out = subprocess.run(["readelf", "-sW", ko], capture_output=True, text=True).stdout
    return set(re.findall(r"\.klp\.sym\.[^\s]+", out))


def built(d: str) -> dict[str, str]:
    res = {}
    for st in glob.glob(os.path.join(d, "*", "status.json")):
        fix = os.path.basename(os.path.dirname(st))
        if json.load(open(st)).get("ok"):
            kos = glob.glob(os.path.join(os.path.dirname(st), "build", "*.ko"))
            if kos:
                res[fix] = kos[0]
    return res


a, b = built(sys.argv[1]), built(sys.argv[2])
common = sorted(set(a) & set(b))
diffs = []
for fix in common:
    sa, sb = klp_syms(a[fix]), klp_syms(b[fix])
    if sa != sb:
        diffs.append({"fix": fix, "only_a": sorted(sa - sb), "only_b": sorted(sb - sa)})
print(json.dumps({"a": sys.argv[1], "b": sys.argv[2], "built_a": len(a), "built_b": len(b),
                  "common": len(common), "differ": len(diffs), "diffs": diffs}, indent=1))
