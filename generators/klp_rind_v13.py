#!/usr/bin/env python3
"""S11: score the klp-build modules on the 6.19 pin with oracle v1.3 against R-ind only, keeping the
relocation-level differences, to check whether every R-ind divergence is made of R_X86_64_NONE (type 0) rows.
Read-only check: no oracle change. Writes /opt/atlas/s12/oracle/s11-klp-rind-v13-detail.json.
Usage (build host): nice -n 19 python3 klp_rind_v13.py [--workers 4]
"""
import argparse
import glob
import json
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

A = Path("/opt/atlas")
PY = A / "venvs/lpfid-oracle-v11/bin/python"
V13 = A / "lpfid/blind-reloc-oracle-v1.3.py"
TREE = A / "livepatch-corpus/linux-6.19"
RES = A / "s12/results/klp-gcc-13/6.19"
IND = A / "s12/refs-independent/6.19"


def none_only(f):
    rows = f.get("only_in_module", []) + f.get("only_in_reference", [])
    return bool(rows) and all(r.startswith("0:") for r in rows)


def one(cve):
    kos = sorted(glob.glob(str(RES / cve / "build/*.ko")))
    if not kos:
        return None
    refs = sorted(glob.glob(str(IND / cve / "**/*.o"), recursive=True))
    if not refs:
        return {"cve": cve, "verdict": "NO_REFERENCE"}
    r = subprocess.run([str(PY), str(V13), kos[0], *refs, "--vmlinux", str(TREE / "vmlinux"), "--modules-dir", str(TREE)],
                       capture_output=True, text=True)
    try:
        d = json.loads(r.stdout)
    except Exception:
        return {"cve": cve, "verdict": "ERROR", "stderr": r.stderr[-400:]}
    div = d.get("divergent_functions", [])
    cls = "NONE" if div == [] else ("NONE_ONLY" if all(none_only(f) for f in div) else "OTHER")
    return {"cve": cve, "module": kos[0], "verdict": d["overall_verdict"], "sympos": d.get("sympos_verdict"),
            "compared": d.get("functions_compared"), "not_in_ref": d.get("functions_in_module_not_in_reference"),
            "divergence_kind": cls, "divergent": div}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    cves = sorted(p.name for p in RES.iterdir()
                  if (p / "status.json").exists() and json.loads((p / "status.json").read_text()).get("ok"))
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = [r for r in ex.map(one, cves) if r]
    summ = {"modules": len(rows), "verdicts": dict(Counter(r["verdict"] for r in rows)),
            "divergence_kind": dict(Counter(r.get("divergence_kind") for r in rows)),
            "other": [r["cve"] for r in rows if r.get("divergence_kind") == "OTHER" or r["verdict"] == "ERROR"]}
    (A / "s12/oracle/s11-klp-rind-v13-detail.json").write_text(json.dumps({"summary": summ, "rows": rows}, indent=1))
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
