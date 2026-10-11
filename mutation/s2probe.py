#!/usr/bin/env python3
"""S2 probe: per-operator detection on the 6.6.47 kpatch modules (up to 5 sites per operator)."""
import json, os, random, subprocess, sys
from pathlib import Path
B = Path("/opt/atlas/s2test"); R = Path("/opt/atlas/s1full/refs/6.6.47/kpatch")
def oracle(ko, refs):
    r = subprocess.run(["python3", str(B/"blind-reloc-oracle.py"), ko, *refs], capture_output=True, text=True, env={**os.environ, "LPFID_T1": "strict"})
    try:
        d = json.loads(r.stdout); return f'{d.get("multiset_verdict")}/{d.get("sequence_verdict")}'
    except Exception: return "ERR " + (r.stderr or r.stdout)[-120:].replace("\n", " ")
rows = []
for m in sorted(R.iterdir()):
    kos = list((m/"build").glob("*.ko"))
    if not kos: continue
    ko = str(kos[0]); refs = [str(p) for p in (m/"patched").rglob("*.o")] + ([str(m/"patch-hook.o")] if (m/"patch-hook.o").exists() else [])
    rows.append({"module": m.name, "op": "good", "verdict": oracle(ko, refs)})
    for op in ["redirect", "swap", "addend", "sympos", "dropcall", "constant"]:
        sites = json.loads(subprocess.run(["python3", str(B/"lpfid-mutate.py"), "list", op, ko], capture_output=True, text=True).stdout or "[]")
        for i in sorted(random.Random(7).sample(range(len(sites)), min(5, len(sites)))):
            out = B/"mut"/m.name/f"{op}-{i}.ko"; out.parent.mkdir(parents=True, exist_ok=True)
            a = subprocess.run(["python3", str(B/"lpfid-mutate.py"), "apply", op, str(i), ko, str(out)], capture_output=True, text=True)
            if a.returncode: rows.append({"module": m.name, "op": op, "site": i, "verdict": "APPLY_ERR " + a.stderr[-120:]}); continue
            noop = json.loads(a.stdout).get("noop")
            rows.append({"module": m.name, "op": op, "site": i, "noop": noop, "verdict": oracle(str(out), refs)})
json.dump(rows, open(B/"s2probe.json", "w"), indent=1)
from collections import Counter
c = Counter((r["op"], r["verdict"]) for r in rows)
for k, v in sorted(c.items()): print(k[0], k[1], v)
