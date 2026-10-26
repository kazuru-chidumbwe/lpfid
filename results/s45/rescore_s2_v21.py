#!/usr/bin/env python3
"""S45: re-score the six-operator campaign (S2: 123 real-fix modules and 78 fixtures, every scored mutant) under
binding oracle v2.1, with the S2 pairing (kpatch's own patched objects plus patch-hook.o, pin vmlinux and tree).
One JSON line per file: the recorded v1.1 verdict and the v2.1 verdict.
usage: rescore_s2_v21.py <oracle-v2.1.py> <out.jsonl> [workers]"""
import importlib.util, json, subprocess, sys
from multiprocessing import Pool
from pathlib import Path

ORC, OUT = sys.argv[1], sys.argv[2]
NW = int(sys.argv[3]) if len(sys.argv) > 3 else 6
PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"

spec = importlib.util.spec_from_file_location("s2run", "/opt/atlas/s2/s2run.py")
s2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s2)


def v21(ko, refs, tree):
    r = subprocess.run([PY, ORC, ko, *refs, "--vmlinux", str(Path(tree) / "vmlinux"), "--modules-dir", tree],
                       capture_output=True, text=True, timeout=1800)
    try:
        d = json.loads(r.stdout)
        return {"overall": d["overall_verdict"], "multiset": d["multiset_verdict"],
                "sequence": d["sequence_verdict"], "sympos": d["sympos_verdict"]}
    except Exception:
        return {"error": (r.stderr or r.stdout)[-300:]}


def job(t):
    kind, sid, op, ko, rec, refs, tree = t
    return {"kind": kind, "id": sid, "op": op, "ko": ko, "v1.1": rec, "v2.1": v21(ko, refs, tree)}


def main():
    rows = json.load(open("/opt/atlas/s2/s2-s12-fixtures.json"))["rows"]
    subj = {(x["set"], x["id"]): x for x in s2.subjects(["s12", "fixtures"])}
    jobs = []
    for r in rows:
        x = subj[(r["set"], r["id"])]
        jobs.append(("parent", f'{r["set"]}:{r["id"]}', None, x["module"], None, x["refs"], x["tree"]))
        for m in r["mutants"]:
            if m.get("built") and not m.get("noop") and not m.get("duplicate_of") and "v1.1" in m:
                jobs.append(("mutant", f'{r["set"]}:{r["id"]}', m["op"], m["path"], m["v1.1"], x["refs"], x["tree"]))
    print(f"{len(jobs)} files", file=sys.stderr, flush=True)
    with open(OUT, "w") as f, Pool(NW) as p:
        for i, row in enumerate(p.imap_unordered(job, jobs, chunksize=4)):
            f.write(json.dumps(row) + "\n")
            f.flush()
            if i % 250 == 0:
                print(f"{i}/{len(jobs)}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
