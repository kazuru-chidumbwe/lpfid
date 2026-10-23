"""Restrict the baseline rows to the scored real-fix set: built, not a no-op, not a duplicate."""
import json
import os
from collections import Counter

manifest = "/opt/atlas/s12-eval/s2/s2-s12-fixtures.json"
if not os.path.isfile(manifest):
    manifest = "/home/developer/s2-s12-fixtures-2026-10-09.json"
s2 = json.load(open(manifest))
keep = set()
dropped = Counter()
for subj in s2["rows"]:
    if subj.get("set") != "s12":
        continue
    for m in subj["mutants"]:
        tail = m["path"].split("/mut/", 1)[-1]
        if not m.get("built") or m.get("noop") or m.get("duplicate_of"):
            dropped[m["op"]] += 1
            continue
        keep.add(tail)
print("keep", len(keep), "dropped", dict(dropped))

faith = {}
for line in open("/opt/atlas/s42-naive/faithful.jsonl"):
    r = json.loads(line)
    faith[(r["kdir"], r["cve"])] = r["indep"]["verdict"]

seen = set()
on = Counter()
missing = 0
for line in open("/opt/atlas/s42-naive/mutants.jsonl"):
    r = json.loads(line)
    tail = r["ko"].split("/mut/", 1)[-1]
    if tail not in keep:
        continue
    seen.add(tail)
    base = faith[(r["kdir"], r["cve"])]
    on[(base, r["op"], r["indep"]["verdict"])] += 1
print("matched", len(seen), "unmatched_keep", len(keep - seen))
for k, v in sorted(on.items()):
    print(k, v)
