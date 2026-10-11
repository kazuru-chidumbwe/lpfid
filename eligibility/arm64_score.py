#!/usr/bin/env python3
"""S6b B4 (arm64) scoring, under the rule registered before any B4 scan (S6B-PREREG amendment):
v2 is scored only through its architecture-neutral evidence. A REPLACE label whose only source is a store in code
(a module parameter) is excluded from v2's accuracy and reported as not testable with v2's x86-64 code rules.
Run on the arm64 instance in ~/b4 after the scans. Writes b4-score.json.
"""
import json
from pathlib import Path

HZ = {"SHADOW": "uses_shadow", "CALLBACKS": "has_state_callbacks", "REPLACE": "is_replace", "STATES": "uses_klp_states"}
L = {Path(r["source"]).stem: r for r in json.load(open("b4-labels.json"))["rows"]}
rows, tally = [], {v: {k: {"TP": 0, "FN": 0, "FP": 0, "TN": 0} for k in HZ} for v in ("v1", "v2")}
excluded = []
for n, r in sorted(L.items()):
    v1 = json.load(open(f"scan/{n}.v1.json"))
    v2 = json.loads(open(f"scan/{n}.v2.json").read().strip().splitlines()[-1])
    ev = v2.get("evidence", {})
    neutral_replace = any("initialised non-zero" in e for e in ev.get("REPLACE", []))
    for k, s in HZ.items():
        lab = bool(r[k])
        code_only = k == "REPLACE" and lab and r.get("conditional")
        for ver, out in (("v1", v1), ("v2", v2)):
            got = bool(out.get(s))
            if ver == "v2" and k == "REPLACE":
                got = neutral_replace
                if code_only:
                    excluded.append(f"{n}: REPLACE via module parameter (code store); v2 code-rule evidence: {ev.get('REPLACE', [])}")
                    continue
            cell = ("TP" if got else "FN") if lab else ("FP" if got else "TN")
            tally[ver][k][cell] += 1
    rows.append({"module": n, "label": {k: r[k] for k in HZ}, "conditional": r.get("conditional", ""),
                 "v1": {k: bool(v1.get(s)) for k, s in HZ.items()}, "v1_class": v1.get("pre_class"),
                 "v2": {k: bool(v2.get(s)) for k, s in HZ.items()}, "v2_class": v2.get("pre_class"),
                 "v2_evidence": ev, "v2_layout": v2.get("layout_source")})
json.dump({"tally": tally, "excluded_from_v2": excluded, "rows": rows}, open("b4-score.json", "w"), indent=1)
for ver in ("v1", "v2"):
    print(ver, {k: t for k, t in tally[ver].items()})
print("excluded from v2 (code-store REPLACE):")
for e in excluded:
    print("  ", e)
for r in rows:
    print(r["module"], "label", [k for k in HZ if r["label"][k]], "| v1", [k for k in HZ if r["v1"][k]], "| v2", [k for k in HZ if r["v2"][k]], r["v2_layout"])
