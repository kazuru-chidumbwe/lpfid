#!/usr/bin/env python3
"""S44 development check (not held-out): score every S43 parent and stored mutant under oracle v2.0 and v2.1 with the
S43 pairing rule, and list every file whose verdict or divergent-function list differs. Expected: only modules that
define a function name twice differ. One JSON line per file.
usage: s44_regress.py <v2.0.py> <v2.1.py> <s43 arch dir> <out.jsonl> [workers]"""
import glob, importlib.util, json, os, sys
from multiprocessing import Pool
from pathlib import Path

V20, V21, ROOT, OUT = sys.argv[1:5]
NW = int(sys.argv[5]) if len(sys.argv) > 5 else 8


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ORC = {}


def pair(pkg_dir, stem):
    rd = os.path.join(pkg_dir, "ref")
    for d in sorted(os.listdir(rd)) if os.path.isdir(rd) else []:
        if "livepatch-" + d.replace(".", "-").replace("&", "-") == stem:
            return d
    return None


def verdict(o, ko, refs, vml, pkg_dir):
    mod = o.Obj(Path(ko))
    robjs = [o.Obj(Path(p)) for p in refs]
    d = o.compare(mod, robjs, None, vml, pkg_dir if vml else None)
    for x in [mod] + robjs:
        x.f.close()
    return {"overall": d["overall_verdict"], "sympos": d["sympos_verdict"],
            "div": sorted(f["function"] for f in d["divergent_functions"]),
            "keys": d.get("compared_keys", d["compared_functions"])}


def job(args):
    ko, refs, vml, pkg_dir = args
    if not ORC:
        ORC["20"], ORC["21"] = load("o20", V20), load("o21", V21)
    try:
        a = verdict(ORC["20"], ko, refs, vml, pkg_dir)
        b = verdict(ORC["21"], ko, refs, vml, pkg_dir)
    except Exception as e:  # noqa: BLE001
        return {"ko": ko, "error": f"{type(e).__name__}: {e}"[:200]}
    return {"ko": ko, "v20": a, "v21": b,
            "differs": (a["overall"], a["div"], a["sympos"]) != (b["overall"], b["div"], b["sympos"])}


jobs = []
for pkg_dir in sorted(glob.glob(os.path.join(ROOT, "kernel-livepatch-*"))):
    vml = os.path.join(pkg_dir, "vmlinux")
    vml = vml if os.path.exists(vml) else None
    for ko in sorted(glob.glob(os.path.join(pkg_dir, "ko", "*.ko"))):
        stem = os.path.basename(ko)[:-3]
        patch = pair(pkg_dir, stem)
        if not patch:
            continue
        refs = sorted(glob.glob(os.path.join(pkg_dir, "ref", patch, "**", "*.o"), recursive=True))
        if not refs:
            continue
        files = [ko] + sorted(glob.glob(os.path.join(pkg_dir, "mut", stem, "*.ko")))
        jobs += [(f, refs, vml, pkg_dir) for f in files]
print("files", len(jobs), flush=True)
n = d = e = 0
with Pool(NW) as p, open(OUT, "w") as out:
    for r in p.imap_unordered(job, jobs, chunksize=4):
        out.write(json.dumps(r) + "\n")
        n += 1
        d += bool(r.get("differs"))
        e += "error" in r
        if n % 500 == 0:
            print("done", n, "differs", d, "errors", e, flush=True)
print("DONE files", n, "differs", d, "errors", e, flush=True)
