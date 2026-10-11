#!/usr/bin/env python3
"""Restore canary for the 5.15 arm (S12-PREREG Deviation 7): fix A, fix B, fix A again on one worker.

Pass when A's two modules have identical symbol tables and identical non-debug relocation sections
(module name tag replaced), and kpatch's patched objects are byte-identical, as in canary_check.py.
Also records each build's own status. Writes one JSON line to canary515.log.
"""
import hashlib, json, os, subprocess, sys
from pathlib import Path

BR = sys.argv[1] if len(sys.argv) > 1 else "5.15"   # S11 calls it with 6.19
os.environ["S12_RESULTS"] = "/opt/atlas/s12/canary" + BR.replace(".", "")
sys.argv = [sys.argv[0]]
import importlib.util
spec = importlib.util.spec_from_file_location("b", "/opt/atlas/s12/s12build.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
sel = json.loads(Path(f"/opt/atlas/s12/out/{BR}/selection.json").read_text())
A, B = sel["main"][0], sel["main"][1]
D = Path(os.environ["S12_RESULTS"]) / "v0.9.11-gcc-13" / BR


def run(job, tag):
    j = {**job, "branch": BR, "set": "canary", "cve": job["cve"] + tag}
    b.build(j, 7, "v0.9.11", "gcc-13")
    st = json.loads((D / j["cve"] / "status.json").read_text())
    return st


def view(cve, tag):
    d = D / f"{cve}{tag}"
    ko = next((d / "build").glob("*.ko"))
    name = "lp" + (cve + tag).replace("CVE-", "").replace("-", "_")
    syms = subprocess.run(["readelf", "-sW", str(ko)], capture_output=True, text=True, check=True).stdout
    rels = subprocess.run(["readelf", "-rW", str(ko)], capture_output=True, text=True, check=True).stdout
    keep, out = True, []
    for line in rels.splitlines():
        if line.startswith("Relocation section"):
            keep = ".rela.debug" not in line
        if keep:
            out.append(line)
    objs = {str(p.relative_to(d / "patched")): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((d / "patched").rglob("*.o"))}
    return syms.replace(name, "LPMOD"), "\n".join(out).replace(name, "LPMOD"), objs


s1, s2, s3 = run(A, "-a1"), run(B, "-b"), run(A, "-a2")
res = {"A": A["cve"], "B": B["cve"], "A1": [s1["ok"], s1["rc"]], "B_built": [s2["ok"], s2["rc"]],
       "A2": [s3["ok"], s3["rc"]]}
if s1["ok"] and s3["ok"]:
    y1, r1, o1 = view(A["cve"], "-a1")
    y2, r2, o2 = view(A["cve"], "-a2")
    res.update(A_symbols_identical=y1 == y2, A_nondebug_relocs_identical=r1 == r2,
               A_patched_objects_identical=bool(o1) and o1 == o2)
res["pass"] = bool(s1["ok"] and s3["ok"] and res.get("A_symbols_identical") and res.get("A_nondebug_relocs_identical")
                   and res.get("A_patched_objects_identical"))
with open(f"/opt/atlas/s12/canary{BR.replace('.', '')}.log", "a") as f:
    f.write(json.dumps(res) + "\n")
print(json.dumps(res))
