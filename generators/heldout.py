#!/usr/bin/env python3
"""S16 Deviation 4, held-out klp-build set H on the 6.19 pin.
select: from the eligible pool of the committed s12select.py run (out/6.19/candidates.tsv, no failed step) minus the
        40 S11 main fixes, draw random.Random(seed + 2).sample(sorted(pool), 40) with the selection seed. First
        checks that random.Random(seed).sample(sorted(eligible), 40) reproduces the S11 main sample exactly.
build:  for each fix of H, on the four 6.19 worker trees: klp-build stock (s11klp.py recipe), klp-build with only
        fa31c5b01 in objtool (s11_fixobjtool.py recipe), and the R-ind reference (s22refs.py build_ref, unchanged).
Usage (build host): python3 s11_heldout.py select | python3 s11_heldout.py build WORKERS
Output: out/6.19/heldout-h.json; s11-heldout/{stock,fixed}/<cve>/; refs-independent-heldout/6.19/<cve>/
"""
import csv
import importlib.util
import json
import os
import random
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

S12 = Path("/opt/atlas/s12")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


B = load("s12build", S12 / "s12build.py")
SEL = S12 / "out/6.19/selection.json"
HFILE = S12 / "out/6.19/heldout-h.json"
FIX = S12 / "objtool-fa31c5b01.patch"
OUT = S12 / "s11-heldout"


def select() -> int:
    sel = json.loads(SEL.read_text())
    seed = int(sel["seed_hex"], 16)
    with open(S12 / "out/6.19/candidates.tsv") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    eligible = sorted(r["cve"] for r in rows if not r["failed_step"])
    main = sorted(j["cve"] for j in sel["main"])
    again = sorted(random.Random(seed).sample(eligible, min(40, len(eligible))))
    if again != main:
        print("eligible pool does not reproduce the S11 main sample; stop", file=sys.stderr)
        return 2
    pool = sorted(set(eligible) - set(main))
    h = sorted(random.Random(seed + 2).sample(pool, min(40, len(pool))))
    byid = {r["cve"]: r for r in rows}
    doc = {"rule": "random.Random(seed + 2).sample(sorted(eligible - S11 main), 40)", "seed_hex": sel["seed_hex"],
           "vulns_commit": sel["vulns_commit"], "eligible": len(eligible), "pool": len(pool),
           "main_reproduced": True, "heldout": [{"cve": c, "stable_sha": byid[c]["stable_sha"],
                                                  "fixed_in": byid[c]["fixed_in"], "type": byid[c]["type"]} for c in h]}
    if HFILE.exists() and json.loads(HFILE.read_text())["heldout"] != doc["heldout"]:
        print("existing heldout-h.json differs; stop", file=sys.stderr)
        return 2
    HFILE.write_text(json.dumps(doc, indent=1))
    print(len(eligible), "eligible,", len(pool), "in pool,", len(h), "drawn")
    return 0


def klp(job: dict, worker: int, variant: str) -> dict:
    cve, sha = job["cve"], job["stable_sha"]
    dst = OUT / variant / cve
    if (dst / "status.json").exists():
        return json.loads((dst / "status.json").read_text())
    shutil.rmtree(dst, ignore_errors=True)
    (dst / "build").mkdir(parents=True)
    repo = B.PINS["6.19"][2]
    (dst / "fix.patch").write_text(subprocess.run(["git", "-C", str(repo), "show", "--format=", "--no-color", sha],
                                                  check=True, capture_output=True, text=True).stdout)
    src = B.src_copy(worker, "6.19")
    shutil.rmtree(src / "klp-tmp", ignore_errors=True)
    if variant == "fixed":
        p = subprocess.run(["patch", "-p1", "--forward", "-i", str(FIX)], cwd=src, capture_output=True, text=True)
        (dst / "patch-apply.log").write_text(p.stdout + p.stderr + f"rc={p.returncode}\n")
        if p.returncode != 0:
            st = {"cve": cve, "variant": variant, "ok": False, "stage": "objtool patch"}
            (dst / "status.json").write_text(json.dumps(st))
            return st
    name = "lp" + cve.replace("CVE-", "").replace("-", "_")
    env = dict(os.environ, PATH=f"{B.gccbin('gcc-13')}:{os.environ['PATH']}")
    cmd = ["./scripts/livepatch/klp-build", "-T", "--no-replace", f"-j{B.JOBS_PER_WORKER}",
           "-o", str(dst / "build" / f"{name}.ko"), str(dst / "fix.patch")]
    t0 = time.time()
    r = subprocess.run(cmd, cwd=src, env=env, capture_output=True, text=True)
    (dst / "klp-build.log").write_text(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    st = {"cve": cve, "variant": variant, "ok": r.returncode == 0 and any((dst / "build").glob("*.ko")),
          "rc": r.returncode, "seconds": round(time.time() - t0), "worker": worker,
          "objtool_fix": "fa31c5b01" if variant == "fixed" else None}
    (dst / "status.json").write_text(json.dumps(st))
    return st


def build(workers: int) -> int:
    jobs = json.loads(HFILE.read_text())["heldout"]
    S22 = load("s22refs", S12 / "s22refs.py")
    S22.OUT = S12 / "refs-independent-heldout"
    pool: Queue = Queue()
    for w in range(workers):
        pool.put(w)

    def run(job):
        w = pool.get()
        try:
            res = [klp(job, w, "stock"), klp(job, w, "fixed")]
            S22.build_ref({**job, "branch": "6.19"}, w)
        finally:
            pool.put(w)
        print(f"[{time.strftime('%H:%M:%S')}] {job['cve']} stock={res[0]['ok']} fixed={res[1]['ok']}", flush=True)
        return res

    with ThreadPoolExecutor(max_workers=workers) as ex:
        out = list(ex.map(run, jobs))
    print("HELDOUT BUILD DONE", sum(a["ok"] for a, _ in out), "stock,", sum(b["ok"] for _, b in out), "fixed, of", len(out), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(select() if sys.argv[1] == "select" else build(int(sys.argv[2])))
