#!/usr/bin/env python3
"""S44 addendum A3, S26 part: immediate check on every S26 module, against the rebuilt references in ~/s44/s26re/keep.
Module and patch pairing come from the S26 result files. One JSON line per module on stdout.
usage: s26_body.py > body-s26-2026-10-25.jsonl"""
import glob, json, os, subprocess

PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"
BODY = "/opt/atlas/lpfid/body_check_v16.py"
H = os.path.expanduser("~")

for rf in sorted(glob.glob(f"{H}/s26/results/*/result.json")):
    r = json.load(open(rf))
    pkg = r["pkg"]
    for m in r.get("modules", []):
        ko = os.path.join(H, "s44/s26re/keep", pkg, "ko", m["ko"])
        refs = sorted(glob.glob(os.path.join(H, "s44/s26re/keep", pkg, "ref", m["patch"], "*.o")))
        row = {"corpus": "S26", "pkg": pkg, "patch": m["patch"], "ko": m["ko"], "ref_n": len(refs)}
        if not os.path.exists(ko) or not refs:
            row["verdict"] = "NO_MODULE" if not os.path.exists(ko) else "NO_REFERENCE"
        else:
            p = subprocess.run([PY, BODY, ko, *refs], capture_output=True, text=True, timeout=600)
            try:
                d = json.loads(p.stdout)
                row.update(verdict=d["verdict"], functions=d.get("functions_compared"),
                           divergent=d.get("divergent_functions", []))
            except Exception:
                row.update(verdict="ERROR", tail=(p.stdout or p.stderr)[-400:])
        print(json.dumps(row), flush=True)
