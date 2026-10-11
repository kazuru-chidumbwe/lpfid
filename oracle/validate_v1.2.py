#!/usr/bin/env python3
"""Validation of oracle v1.2 (S16 Deviation 2) before it scores any module it has not seen.

Inputs, all already scored by the frozen v1.1: the 78 fixture goods, the 123 unmodified S12 modules (R-kp), the
1,266 S1 redirect mutants of the fixtures, and every scored S2 operator mutant (real-fix and fixture).
For each input, v1.2 runs with every rule on and with LPFID_DISABLE=N3M,ALT. Pass when:
  (1) with N3M,ALT off, the overall verdict equals the recorded v1.1 verdict on every input;
  (2) with them on, every unmodified module (fixtures, S12) stays CONSISTENT;
  (3) every mutant v1.1 detected is still detected.
Mutants detected only by v1.2 are listed.
Usage: nice -n 19 python3 oracle_v12_validate.py [--workers 3]   (writes /opt/atlas/lpfid/oracle-v12-validation.json)
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
V12 = A / "lpfid/blind-reloc-oracle-v1.2.py"
FIX = A / "lpfid-fixtures"
OUT = A / "lpfid/oracle-v12-validation.json"
FIX_TREES = {"5.16.10": C / "linux-dirtypipe", "6.1.119": C / "linux-second-pin", "6.6.47": C / "pilot-work/linux"}
S12_TREES = {"6.1": C / "linux-second-pin", "6.6": C / "pilot-work/linux", "6.12": C / "linux-6.12.51"}
DET = ("DIVERGENT", "LOAD_FAIL")


def run(ko: str, refs: list[str], tree: Path, disable: str = "") -> str:
    env = dict(os.environ, LPFID_DISABLE=disable)
    r = subprocess.run([str(PY), str(V12), ko, *refs, "--vmlinux", str(tree / "vmlinux"), "--modules-dir", str(tree)],
                       capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)["overall_verdict"]
    except (json.JSONDecodeError, KeyError):
        return "ERROR"


def jobs() -> list[dict]:
    v11 = {(r["set"], r["id"]): r["v11"] for r in json.loads((A / "lpfid/oracle-v11-validation.json").read_text())["rows"]}
    out = []
    goods = json.loads((FIX / "goods-recheck.json").read_text())["rows"]
    refs = {f"{g['pin']}/{g['kind']}/{g['name']}": g["refs"] for g in goods}
    for g in goods:
        i = f"{g['pin']}/{g['kind']}/{g['name']}"
        out.append({"set": "fixture_goods", "id": i, "ko": g["module"], "refs": g["refs"], "tree": FIX_TREES[g["pin"]],
                    "v11": v11[("fixtures", i)], "good": True})
    s12rows = json.loads((A / "s12/oracle/rkp.json").read_text())["rows"]
    s12refs = {f"{r['branch']}/{r['cve']}": r["refs"] for r in s12rows}
    for r in s12rows:
        i = f"{r['branch']}/{r['cve']}"
        out.append({"set": "s12_goods", "id": i, "ko": r["module"], "refs": r["refs"], "tree": S12_TREES[r["branch"]],
                    "v11": v11[("s12", i)], "good": True})
    for m in json.loads((FIX / "s1-mutants.json").read_text())["rows"]:
        if not m.get("built") or m.get("noop"):
            continue
        key = f"{m['pin']}/{m['kind']}/{m['name']}"
        i = f"{key} {m['src']}->{m['dst']}"
        ko = FIX / "s1mut" / m["pin"] / m["kind"] / m["name"] / f"{m['src']}__to__{m['dst']}.ko"
        out.append({"set": "s1_redirect", "id": i, "ko": str(ko), "refs": refs[key], "tree": FIX_TREES[m["pin"]],
                    "v11": v11[("mutants", i)], "good": False})
    for subj in json.loads((A / "s2/s2-s12-fixtures.json").read_text())["rows"]:
        if subj["set"] == "s12":
            tree, rf = S12_TREES[subj["id"].split("/")[0]], s12refs[subj["id"]]
        else:
            tree, rf = FIX_TREES[subj["id"].split("/")[0]], refs[subj["id"]]
        for m in subj["mutants"]:
            if m.get("built") and not m.get("noop") and not m.get("duplicate_of") and "v1.1" in m:
                out.append({"set": f"s2_{subj['set']}_{m['op']}", "id": f"{subj['id']} {m['op']}-{m['site_index']}",
                            "ko": m["path"], "refs": rf, "tree": tree, "v11": m["v1.1"].get("overall", "ERROR"), "good": False})
    return out


def one(j: dict) -> dict:
    on = run(j["ko"], j["refs"], j["tree"])
    off = run(j["ko"], j["refs"], j["tree"], "N3M,ALT")
    return {"set": j["set"], "id": j["id"], "good": j["good"], "v11": j["v11"], "v12": on, "v12_off": off}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    js = jobs()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = list(ex.map(one, js))
    off_mismatch = [f"{r['set']} {r['id']}: v1.1 {r['v11']} v1.2-off {r['v12_off']}" for r in rows if r["v12_off"] != r["v11"]]
    goods_alarm = [f"{r['set']} {r['id']}: {r['v12']}" for r in rows if r["good"] and r["v12"] != "CONSISTENT"]
    lost = [f"{r['set']} {r['id']}" for r in rows if not r["good"] and r["v11"] in DET and r["v12"] not in DET]
    gained = [f"{r['set']} {r['id']}" for r in rows if not r["good"] and r["v11"] not in DET and r["v12"] in DET]
    summary = {"oracle_v12_sha256": hashlib.sha256(V12.read_bytes()).hexdigest(), "inputs": dict(Counter(r["set"] for r in rows)),
               "off_equals_v11": len(rows) - len(off_mismatch), "off_mismatch": off_mismatch[:200],
               "goods_not_consistent": goods_alarm, "v11_detected_v12_missed": lost, "detected_by_v12_only": gained,
               "pass": not off_mismatch and not goods_alarm and not lost}
    OUT.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
