#!/usr/bin/env python3
"""S26 design draw, binding verdict on the shipped modules. The S26 keep step copied the locally built module over the
shipped one (same file name), so every later score read from keep/*.ko saw a local build. This scores every S26 module
as extracted again from the binary rpm (~/s44/s26re/keep/<pkg>/ko) against the rebuilt references
(~/s44/s26re/keep/<pkg>/ref/<patch>), with oracle v1.6 (LPFID_T1=version, the S26 v1.6 rescore setting) and the census
checker v2.1. Same pairing as s26_body.py. usage: s26re_bind.py > bind-s26re-2026-10-26.jsonl"""
import glob, json, os, subprocess
from multiprocessing import Pool

H = os.path.expanduser("~")
PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"
ORA = {"v1.6": "/opt/atlas/lpfid/blind-reloc-oracle-v1.6.py", "v2.1": f"{H}/s44/blind-reloc-oracle-v2.1.py"}
ENV = dict(os.environ, LPFID_T1="version")


def score(job):
    pkg, patch, name = job
    k = os.path.join(H, "s44/s26re/keep", pkg)
    ko = os.path.join(k, "ko", name)
    refs = sorted(glob.glob(os.path.join(k, "ref", patch, "*.o")))
    row = {"pkg": pkg, "patch": patch, "ko": name, "ref_n": len(refs)}
    if not os.path.exists(ko) or not refs:
        row["verdict"] = "NO_MODULE" if not os.path.exists(ko) else "NO_REFERENCE"
        return row
    for v, op in ORA.items():
        r = subprocess.run([PY, op, ko, *refs], capture_output=True, text=True, timeout=1800, env=ENV)
        try:
            d = json.loads(r.stdout)
            row[v] = {"overall": d.get("overall_verdict"),
                      "divergent": [x.get("function") for x in (d.get("divergent_functions") or [])],
                      "scaffolding": [x.get("function") for x in (d.get("scaffolding_divergences") or [])],
                      "functions": d.get("functions_compared")}
        except Exception:
            row[v] = {"error": (r.stderr or r.stdout)[-300:]}
    return row


jobs = []
for rf in sorted(glob.glob(f"{H}/s26/results/*/result.json")):
    r = json.load(open(rf))
    for m in r.get("modules", []):
        jobs.append((r["pkg"], m["patch"], m["ko"]))
with Pool(6) as p:
    for row in p.imap(score, jobs):
        print(json.dumps(row), flush=True)
