#!/usr/bin/env python3
"""Validation of oracle v1.4 (S16 Deviation 4) before any held-out use.

Inputs: (a) every input of the v1.3 validation (oracle-v13-validation.json, verdict v13 recorded there, same jobs
as oracle_v13_validate.jobs()); (b) any S21 set scored since, from /opt/atlas/s12/oracle/s21-*.json (v1.3 is run
here when no v1.3 verdict was recorded); (c) the S11 klp-build modules: 34 against R-ind, 34 against R-kp (klp-build's
patched vmlinux.o), and the 7 fixed-objtool rebuilds against R-ind.
For each input, v1.4 runs with every rule on and with LPFID_DISABLE=R0,RB,RC. Pass when:
  (1) with the rules off, the overall verdict equals the v1.3 verdict on every input;
  (2) with the rules on, every unmodified module of (a) stays CONSISTENT;
  (3) every mutant of (a) that v1.3 detected is still detected;
  (4) the 7 S11 modules with the objtool string fault stay DIVERGENT against R-ind.
Verdict changes elsewhere are listed; the S11 sets are a fit (the rules were written after seeing them).
Usage: nice -n 19 python3 oracle_v14_validate.py [--workers 4]   (writes /opt/atlas/lpfid/oracle-v14-validation.json)
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
import oracle_v13_validate as v13  # noqa: E402  (same inputs, trees and paths)

A = Path("/opt/atlas")
PY = v13.PY
V13 = A / "lpfid/blind-reloc-oracle-v1.3.py"
V14 = A / "lpfid/blind-reloc-oracle-v1.4.py"
OUT = A / "lpfid/oracle-v14-validation.json"
DET = v13.DET
T619 = A / "livepatch-corpus/linux-6.19"
RES = A / "s12/results/klp-gcc-13/6.19"
FIXRES = A / "s12/s11-fixobjtool"
IND = A / "s12/refs-independent/6.19"
FAULTY = {"CVE-2026-23467", "CVE-2026-31447", "CVE-2026-31449", "CVE-2026-31521", "CVE-2026-31571",
          "CVE-2026-43152", "CVE-2026-43163"}


def run(oracle: Path, ko: str, refs: list[str], tree: Path, disable: str = "", t1: str | None = None) -> str:
    env = dict(os.environ, LPFID_DISABLE=disable)
    if t1:
        env["LPFID_T1"] = t1
    r = subprocess.run([str(PY), str(oracle), ko, *refs, "--vmlinux", str(tree / "vmlinux"), "--modules-dir", str(tree)],
                       capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)["overall_verdict"]
    except (json.JSONDecodeError, KeyError):
        return "ERROR"


def s11_jobs() -> list[dict]:
    out = []
    for kind, base in (("s11-klp", RES), ("s11-fixobjtool", FIXRES)):
        for st in sorted(base.glob("*/status.json")):
            s = json.loads(st.read_text())
            kos = sorted(st.parent.glob("build/*.ko"))
            if not s.get("ok") or not kos:
                continue
            cve = st.parent.name
            rind = sorted(str(p) for p in (IND / cve).rglob("*.o"))
            if rind:
                out.append({"set": f"{kind}-rind", "id": cve, "ko": str(kos[0]), "refs": rind, "tree": T619,
                            "v13": None, "good": None, "part": "c"})
            if kind == "s11-klp":
                rkp = sorted(str(p) for p in (st.parent / "patched").rglob("*.o"))
                if rkp:
                    out.append({"set": "s11-klp-rkp", "id": cve, "ko": str(kos[0]), "refs": rkp, "tree": T619,
                                "v13": None, "good": None, "part": "c"})
    return out


def jobs() -> list[dict]:
    rec = {(r["set"], r["id"]): r["v13"] for r in json.loads((A / "lpfid/oracle-v13-validation.json").read_text())["rows"]}
    out = []
    for j in v13.jobs():
        j["v13"] = rec.get((j["set"], j["id"]))
        if j["part"] == "b" and j["set"].startswith("s21-klp-"):
            continue  # the S11 klp-build modules are covered by s11_jobs()
        out.append(j)
    return out + s11_jobs()


def one(j: dict) -> dict:
    t1 = j.get("t1")
    base = j["v13"] if j["v13"] is not None else run(V13, j["ko"], j["refs"], j["tree"], t1=t1)
    on = run(V14, j["ko"], j["refs"], j["tree"], t1=t1)
    off = run(V14, j["ko"], j["refs"], j["tree"], "R0,RB,RC", t1=t1)
    return {"set": j["set"], "id": j["id"], "part": j["part"], "good": j["good"], "v13": base,
            "v13_recorded": j["v13"] is not None, "v14": on, "v14_off": off}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    js = jobs()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = list(ex.map(one, js))
    off_mismatch = [f"{r['set']} {r['id']}: v1.3 {r['v13']} v1.4-off {r['v14_off']}" for r in rows if r["v14_off"] != r["v13"]]
    goods_alarm = [f"{r['set']} {r['id']}: {r['v14']}" for r in rows if r["part"] == "a" and r["good"] and r["v14"] != "CONSISTENT"]
    lost = [f"{r['set']} {r['id']}" for r in rows if r["part"] == "a" and r["good"] is False and r["v13"] in DET and r["v14"] not in DET]
    gained = [f"{r['set']} {r['id']}" for r in rows if r["part"] == "a" and r["good"] is False and r["v13"] not in DET and r["v14"] in DET]
    faulty_cleared = [f"{r['set']} {r['id']}: {r['v14']}" for r in rows
                      if r["set"] == "s11-klp-rind" and r["id"] in FAULTY and r["v14"] != "DIVERGENT"]
    changed = [f"{r['set']} {r['id']}: v1.3 {r['v13']} -> v1.4 {r['v14']}" for r in rows if r["part"] != "a" and r["v14"] != r["v13"]]
    s11 = {s: dict(Counter(r["v14"] for r in rows if r["set"] == s)) for s in ("s11-klp-rind", "s11-klp-rkp", "s11-fixobjtool-rind")}
    summary = {"oracle_v14_sha256": hashlib.sha256(V14.read_bytes()).hexdigest(),
               "inputs": dict(Counter(r["set"] for r in rows)), "n": len(rows),
               "off_equals_v13": len(rows) - len(off_mismatch), "off_mismatch": off_mismatch[:200],
               "goods_not_consistent": goods_alarm, "v13_detected_v14_missed": lost, "detected_by_v14_only": gained,
               "s11_faulty_not_divergent": faulty_cleared, "changed_outside_a": changed, "s11_fit_v14": s11,
               "pass": not off_mismatch and not goods_alarm and not lost and not faulty_cleared}
    OUT.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
