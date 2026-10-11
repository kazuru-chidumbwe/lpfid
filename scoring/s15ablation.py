#!/usr/bin/env python3
"""S15: ablation of each normalisation rule of the frozen oracle v1.1 (manuscript 7.4).

Inputs (all already scored with every rule on): the 78 fixture goods, the 123 unmodified S12 modules (R-kp), the
1,266 S1 redirect mutants of the fixtures, and every scored S2 addend mutant (real-fix and fixture). For each rule
R in N0, N1, N2, N3, A1, N4, N5, the oracle runs with LPFID_DISABLE=R; nothing else changes. Reported per rule:
false alarms on the unmodified modules (goods, S12) and detections on the mutants, against the all-rules run.
Usage: nice -n 19 python3 s15ablation.py [--workers 2]   (writes /opt/atlas/s15/ablation.json)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

A = Path("/opt/atlas")
C = A / "livepatch-corpus"
PY = A / "venvs/lpfid-oracle-v11/bin/python"
V11 = A / "lpfid/blind-reloc-oracle-v1.1.py"
FROZEN = "5139e049aa6fc4a1ca1c6641595a9fdd802e7e11d6de058d702cbc7d898d0add"
FIX = A / "lpfid-fixtures"
OUT = A / "s15/ablation.json"
RULES = ["", "N0", "N1", "N2", "N3", "A1", "N4", "N5"]   # "" = every rule on (baseline of this run)
FIX_TREES = {"5.16.10": C / "linux-dirtypipe", "6.1.119": C / "linux-second-pin", "6.6.47": C / "pilot-work/linux"}
S12_TREES = {"6.1": C / "linux-second-pin", "6.6": C / "pilot-work/linux", "6.12": C / "linux-6.12.51"}
DET = ("DIVERGENT", "LOAD_FAIL")


def run(ko: str, refs: list[str], tree: Path, disable: str) -> str:
    env = dict(os.environ, LPFID_DISABLE=disable)
    r = subprocess.run([str(PY), str(V11), ko, *refs, "--vmlinux", str(tree / "vmlinux"), "--modules-dir", str(tree)],
                       capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)["overall_verdict"]
    except (json.JSONDecodeError, KeyError):
        return "ERROR"


def jobs() -> list[dict]:
    out = []
    goods = json.loads((FIX / "goods-recheck.json").read_text())["rows"]
    refs = {f"{g['pin']}/{g['kind']}/{g['name']}": g["refs"] for g in goods}
    for g in goods:
        out.append({"set": "fixture_goods", "id": f"{g['pin']}/{g['kind']}/{g['name']}", "ko": g["module"],
                    "refs": g["refs"], "tree": FIX_TREES[g["pin"]]})
    for r in json.loads((A / "s12/oracle/rkp.json").read_text())["rows"]:
        out.append({"set": "s12_goods", "id": f"{r['branch']}/{r['cve']}", "ko": r["module"], "refs": r["refs"],
                    "tree": S12_TREES[r["branch"]]})
    for m in json.loads((FIX / "s1-mutants.json").read_text())["rows"]:
        if not m.get("built") or m.get("noop"):
            continue
        key = f"{m['pin']}/{m['kind']}/{m['name']}"
        ko = FIX / "s1mut" / m["pin"] / m["kind"] / m["name"] / f"{m['src']}__to__{m['dst']}.ko"
        out.append({"set": "s1_redirect", "id": f"{key} {m['src']}->{m['dst']}", "ko": str(ko), "refs": refs[key],
                    "tree": FIX_TREES[m["pin"]]})
    s2 = json.loads((A / "s2/s2-s12-fixtures.json").read_text())["rows"]
    s12refs = {f"{r['branch']}/{r['cve']}": r["refs"] for r in json.loads((A / "s12/oracle/rkp.json").read_text())["rows"]}
    for subj in s2:
        if subj["set"] == "s12":
            tree, rf = S12_TREES[subj["id"].split("/")[0]], s12refs[subj["id"]]
        else:
            tree, rf = FIX_TREES[subj["id"].split("/")[0]], refs[subj["id"]]
        for m in subj["mutants"]:
            if m["op"] == "addend" and m.get("built") and not m.get("noop") and not m.get("duplicate_of"):
                out.append({"set": f"s2_addend_{subj['set']}", "id": f"{subj['id']} {m['op']}-{m['site_index']}",
                            "ko": m["path"], "refs": rf, "tree": tree})
    return out


def one(job: dict) -> dict:
    return {"set": job["set"], "id": job["id"], "verdicts": {r or "all": run(job["ko"], job["refs"], job["tree"], r) for r in RULES}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=2)
    a = ap.parse_args()
    if hashlib.sha256(V11.read_bytes()).hexdigest() != FROZEN:
        raise SystemExit("oracle v1.1 hash is not the frozen value")
    js = jobs()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = list(ex.map(one, js))
    summary = {"inputs": dict(Counter(r["set"] for r in rows)), "oracle_v11_sha256": FROZEN, "per_rule": {}}
    for rule in ["all"] + RULES[1:]:
        per = {}
        for s in sorted({r["set"] for r in rows}):
            rs = [r for r in rows if r["set"] == s]
            alarms = sum(r["verdicts"][rule] in DET for r in rs)
            per[s] = {"n": len(rs), "alarms_or_detected": alarms, "errors": sum(r["verdicts"][rule] == "ERROR" for r in rs),
                      "changed_vs_all": sum(r["verdicts"][rule] != r["verdicts"]["all"] for r in rs)}
        summary["per_rule"][rule] = per
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
