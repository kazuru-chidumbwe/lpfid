#!/usr/bin/env python3
"""S44 addendum A3: immediate-differential check (body_check_v16.py) on every unmodified x86-64 Amazon module of S26,
S43 and S44, against the reference objects the binding verdict used. One JSON line per module on stdout.

S43 and S44 pair module and reference from the scored results (`ko`, `patch`); S26 from `keep/<patch>/`.
usage: s44_body.py > body-x86-2026-10-25.jsonl"""
import glob, json, os, subprocess

PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"
BODY = "/opt/atlas/lpfid/body_check_v16.py"
H = os.path.expanduser("~")


def run(corpus, pkg, patch, ko, refs):
    row = {"corpus": corpus, "pkg": pkg, "patch": patch, "ko": os.path.basename(ko), "ref_n": len(refs)}
    if not refs or not os.path.exists(ko):
        row["verdict"] = "NO_REFERENCE" if os.path.exists(ko) else "NO_MODULE"
    else:
        p = subprocess.run([PY, BODY, ko, *refs], capture_output=True, text=True, timeout=600)
        try:
            d = json.loads(p.stdout)
            row.update(verdict=d["verdict"], functions=d.get("functions_compared"),
                       divergent=d.get("divergent_functions", []), scaffolding=d.get("scaffolding_divergences", []))
        except Exception:
            row.update(verdict="ERROR", rc=p.returncode, tail=(p.stdout or p.stderr)[-400:])
    print(json.dumps(row), flush=True)


for corpus, res, root in (("S43", f"{H}/s43/results-x86_64.jsonl", f"{H}/s43/x86"),
                          ("S44", f"{H}/s44/results-x86_64.jsonl", f"{H}/s44/x86")):
    for line in open(res):
        r = json.loads(line)
        for m in r.get("modules", []):
            d = os.path.join(root, r["pkg"])
            refs = sorted(glob.glob(os.path.join(d, "ref", m["patch"], "**", "*.o"), recursive=True)) if m.get("patch") else []
            run(corpus, r["pkg"], m.get("patch"), os.path.join(d, "ko", m["ko"] + ".ko"), refs)

for k in sorted(glob.glob(f"{H}/s26/results/*/keep/*/")):
    kos = sorted(glob.glob(os.path.join(k, "*.ko")))
    refs = sorted(glob.glob(os.path.join(k, "ref", "**", "*.o"), recursive=True))
    pkg = k.split("/results/")[1].split("/")[0]
    for ko in kos:
        run("S26", pkg, os.path.basename(k.rstrip("/")), ko, refs)
