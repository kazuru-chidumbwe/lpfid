#!/usr/bin/env python3
"""Summarise sibling-mutant detection, v1.7 vs v1.8, per reference. A mutant counts as detected when its
mutated function is reported divergent; only mutants whose parent module is CONSISTENT under that version are
in the denominator. usage: sum_sibling.py (in ~/s41)"""
import collections, glob, json

meta = {}
for l in open("jobs-sibling.jsonl"):
    j = json.loads(l)
    meta[(j["set"], j["id"])] = j["meta"]
par = {}
for f in glob.glob("out-*.jsonl"):
    for l in open(f):
        r = json.loads(l)
        if r["set"] in ("s12-kp", "s21-v0.9.11-gcc-13-rind") and "v18" in r:
            par[(r["set"], r["id"])] = r
res = collections.defaultdict(collections.Counter)
rows = []
for f in glob.glob("sib-*.jsonl"):
    for l in open(f):
        r = json.loads(l)
        m = meta[(r["set"], r["id"])]
        if "error" in r:
            res[r["set"]]["error"] += 1
            continue
        pset = "s12-kp" if r["set"] == "sibling-kp" else "s21-v0.9.11-gcc-13-rind"
        p = par.get((pset, r["id"].split(" ")[0]))
        cls = "indistinguishable" if m["indistinguishable"] else "distinguishable"
        if p is None:
            res[r["set"]][cls + " parent-pending"] += 1
            continue
        for v in ("v17", "v18"):
            if p[v]["overall"] != "CONSISTENT":
                res[r["set"]][f"{cls} {v} parent-alarm"] += 1
                continue
            det = r[v]["overall"] in ("DIVERGENT", "LOAD_FAIL") and m["function"] in r[v]["div"]
            res[r["set"]][f"{cls} {v} {'detected' if det else 'missed'}"] += 1
        rows.append({"set": r["set"], "id": r["id"], **m, "v17": r["v17"]["overall"], "v18": r["v18"]["overall"]})
for k in sorted(res):
    print(k)
    for kk, vv in sorted(res[k].items()):
        print("   ", kk, vv)
json.dump(rows, open("sibling-rows.json", "w"), indent=1)
print("bases:", collections.Counter(r["from"].rsplit(".", 1)[0] for r in rows if r["set"] == "sibling-kp"))
