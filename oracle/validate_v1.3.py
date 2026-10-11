#!/usr/bin/env python3
"""Validation of oracle v1.3 (S16 Deviation 3) before it is used.

Inputs: (a) the 9,680 inputs of the v1.2 validation (oracle-v12-validation.json, verdicts v12 recorded there), and
(b) every module v1.2 has scored since in an S21/S3 set (/opt/atlas/s12/oracle/s21-*.json; verdict row["v1.2"]).
For each input, v1.3 runs with every rule on and with LPFID_DISABLE=DUP. Pass when:
  (1) with DUP off, the overall verdict equals the recorded v1.2 verdict on every input;
  (2) with DUP on, every unmodified module of (a) stays CONSISTENT;
  (3) every mutant of (a) that v1.2 detected is still detected.
Verdict changes on (b) are listed (expected: the xt_nat false alarm on 5.15 clears).
Usage: nice -n 19 python3 oracle_v13_validate.py [--workers 6]   (writes /opt/atlas/lpfid/oracle-v13-validation.json)
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "/opt/atlas/lpfid")
import oracle_v12_validate as v12  # noqa: E402  (same inputs, trees and paths)

A = Path("/opt/atlas")
PY = v12.PY
V13 = A / "lpfid/blind-reloc-oracle-v1.3.py"
OUT = A / "lpfid/oracle-v13-validation.json"
DET = v12.DET
C = A / "livepatch-corpus"
PINS = {"6.1": C / "linux-second-pin", "6.6": C / "pilot-work/linux", "6.12": C / "linux-6.12.51",
        "5.15": C / "linux-5.15.173", "6.19": C / "linux-6.19"}


def run(ko: str, refs: list[str], tree: Path, disable: str = "", t1: str | None = None) -> str:
    env = dict(os.environ, LPFID_DISABLE=disable)
    if t1:
        env["LPFID_T1"] = t1
    r = subprocess.run([str(PY), str(V13), ko, *refs, "--vmlinux", str(tree / "vmlinux"), "--modules-dir", str(tree)],
                       capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)["overall_verdict"]
    except (json.JSONDecodeError, KeyError):
        return "ERROR"


def jobs() -> list[dict]:
    rec = {(r["set"], r["id"]): r["v12"] for r in json.loads((A / "lpfid/oracle-v12-validation.json").read_text())["rows"]}
    out = []
    for j in v12.jobs():
        j["v12"] = rec[(j["set"], j["id"])]
        j["part"] = "a"
        out.append(j)
    for f in sorted(glob.glob(str(A / "s12/oracle/s21-*.json"))):
        name = Path(f).stem
        gcc = "gcc-14" if "gcc-14" in name else "gcc-13"
        t1 = "version" if "t1version" in name else None
        for r in json.loads(Path(f).read_text())["rows"]:
            v = r.get("v1.2") or {}
            if not v.get("scored"):
                continue
            tree = PINS[r["branch"]]
            if gcc == "gcc-14":
                tree = tree.with_name(tree.name + "-gcc14")
            out.append({"set": name, "id": f"{r['branch']}/{r['cve']}", "ko": r["module"], "refs": r["refs"], "tree": tree,
                        "v12": v["overall"], "good": None, "part": "b", "t1": t1})
    return out


def one(j: dict) -> dict:
    on = run(j["ko"], j["refs"], j["tree"], t1=j.get("t1"))
    off = run(j["ko"], j["refs"], j["tree"], "DUP", t1=j.get("t1"))
    return {"set": j["set"], "id": j["id"], "part": j["part"], "good": j["good"], "v12": j["v12"], "v13": on, "v13_off": off}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    js = jobs()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = list(ex.map(one, js))
    off_mismatch = [f"{r['set']} {r['id']}: v1.2 {r['v12']} v1.3-off {r['v13_off']}" for r in rows if r["v13_off"] != r["v12"]]
    goods_alarm = [f"{r['set']} {r['id']}: {r['v13']}" for r in rows if r["part"] == "a" and r["good"] and r["v13"] != "CONSISTENT"]
    lost = [f"{r['set']} {r['id']}" for r in rows if r["part"] == "a" and r["good"] is False and r["v12"] in DET and r["v13"] not in DET]
    gained = [f"{r['set']} {r['id']}" for r in rows if r["part"] == "a" and r["good"] is False and r["v12"] not in DET and r["v13"] in DET]
    changed_b = [f"{r['set']} {r['id']}: v1.2 {r['v12']} -> v1.3 {r['v13']}" for r in rows if r["part"] == "b" and r["v13"] != r["v12"]]
    summary = {"oracle_v13_sha256": hashlib.sha256(V13.read_bytes()).hexdigest(),
               "inputs": dict(Counter(r["set"] for r in rows)), "n": len(rows),
               "off_equals_v12": len(rows) - len(off_mismatch), "off_mismatch": off_mismatch[:200],
               "goods_not_consistent": goods_alarm, "v12_detected_v13_missed": lost, "detected_by_v13_only": gained,
               "heldout_changed": changed_b,
               "pass": not off_mismatch and not goods_alarm and not lost}
    OUT.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
