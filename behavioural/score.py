#!/usr/bin/env python3
"""S5 scoring (internal/S5-PREREG-2026-10-11.md). Reads the runner output rows-mut.tsv, the contracts and the binding
oracle's verdicts on the same mutants; writes s5-score.json and prints the per-operator table.
Verdict per mutant: LOUD (did not load, enable or complete the transition, or the VM crashed), CONTRACT_FAILURE (phase 1
not the vulnerable line on every repeat), DETECTED (phase 2 not the fixed line on every repeat, or phase 3 not the
vulnerable line on every repeat), PASSED otherwise. FLAKY marks repeats that disagree within a phase.
"""
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
C = {json.load(open(f))["fix"]: json.load(open(f)) for f in HERE.glob("contracts/*.json")}
DET = {"DIVERGENT", "LOAD_FAIL"}


def wilson(k, n):
    if not n:
        return None
    z, p = 1.959964, k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h) * 100, 1), round(min(1, c + h) * 100, 1)]


oracle = {r["id"]: r["v1.3_rind"] for r in json.load(open(HERE / "kpatch-mut-oracle.json"))}
for m in json.load(open(HERE / "mut-31774.json"))["mutants"]:
    if m.get("built") and not m["noop"] and not m["duplicate_of"]:
        oracle[f"mut:6.19/CVE-2026-31774:{m['op']}-{m['site_index']}"] = (m.get("v1.4") or {}).get("overall", "?")

rows = list(csv.DictReader(open(HERE / "rows-mut.tsv", encoding="utf-8"), delimiter="\t"))
out, tally = [], defaultdict(Counter)
for r in rows:
    fix = r["id"].split(":")[1].split("/")[1]
    op = r["id"].split(":")[2].rsplit("-", 1)[0]
    c = C[fix]
    p = {ph: [x for x in (r[ph] or "").split("|") if x] for ph in ("P1", "P2", "P3")}
    loaded = r["insmod_rc"] == "0" and r["enable_state"] == "S5_ENABLED=1 TRANSITION=0" and r["crash_lines"] == "0" and r["done"] == "1"
    flaky = any(len(set(v)) > 1 for v in p.values())
    if not loaded:
        v = "LOUD"
    elif p["P1"] != [c["vulnerable"]] * 3:
        v = "CONTRACT_FAILURE"
    elif p["P2"] != [c["fixed"]] * 3 or p["P3"] != [c["vulnerable"]] * 3:
        v = "DETECTED"
    else:
        v = "PASSED"
    o = oracle.get(r["id"], "?")
    tally[op][v] += 1
    tally[op]["oracle_detected"] += o in DET
    tally[op]["only_behavioural"] += v == "DETECTED" and o not in DET
    tally[op]["only_oracle"] += v == "PASSED" and o in DET
    out.append({"id": r["id"], "fix": fix, "op": op, "verdict": v, "flaky": flaky, "oracle": o, "phases": p})
summary = {}
for op, t in sorted(tally.items()):
    n = sum(t[k] for k in ("LOUD", "CONTRACT_FAILURE", "DETECTED", "PASSED"))
    judged = t["DETECTED"] + t["PASSED"]
    summary[op] = {"mutants": n, "loud": t["LOUD"], "contract_failure": t["CONTRACT_FAILURE"], "judged": judged,
                   "behavioural_detected": t["DETECTED"], "behavioural_wilson": wilson(t["DETECTED"], judged),
                   "oracle_detected": t["oracle_detected"], "only_behavioural": t["only_behavioural"],
                   "only_oracle": t["only_oracle"]}
json.dump({"summary": summary, "rows": out, "flaky": sum(r["flaky"] for r in out)}, open(HERE / "s5-score.json", "w"), indent=1)
for op, s in summary.items():
    print(op, s)
print("flaky:", sum(r["flaky"] for r in out))
