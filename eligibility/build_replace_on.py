#!/usr/bin/env python3
"""S6b population B3 (S6B-PREREG-2026-10-11.md): the five labelled S12 6.12 fixes rebuilt with kpatch-build v0.9.11
WITHOUT -R (atomic replace on, kpatch's default), and the five labelled S11 6.19 fixes rebuilt with klp-build WITHOUT
--no-replace. Everything else as in s12build.py and s11klp.py. Runs after the held-out H builds release the trees.
Usage (build host): python3 s6b_b3.py
Output: /opt/atlas/lpfid/s6b/b3/{kpatch-replace,klp-replace}/<cve>/
"""
import importlib.util
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

A = Path("/opt/atlas")
S12 = A / "s12"
OUT = A / "lpfid/s6b/b3"
spec = importlib.util.spec_from_file_location("s12build", S12 / "s12build.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
LAB = json.loads((A / "lpfid/s6b/heldout-labels.json").read_text())["rows"]


def kpatch(cve: str, worker: int) -> dict:
    src_res = S12 / "results/v0.9.11-gcc-13/6.12" / cve
    dst = OUT / "kpatch-replace" / cve
    shutil.rmtree(dst, ignore_errors=True)
    (dst / "build").mkdir(parents=True)
    shutil.copy2(src_res / "fix.patch", dst / "fix.patch")
    pin, tree, _ = B.PINS["6.12"]
    src = B.src_copy(worker, "6.12", "gcc-13")
    home = S12 / "work" / f"w{worker}" / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HOME=str(home), CACHEDIR=str(home / ".kpatch"),
               PATH=f"{B.gccbin('gcc-13')}:/opt/atlas/tools/kp/v0.9.11/bin:{os.environ['PATH']}")
    name = "lp" + cve.replace("CVE-", "").replace("-", "_")
    cmd = ["kpatch-build", "--skip-cleanup", "-s", str(src), "-c", str(tree / ".config"), "-v", str(tree / "vmlinux"),
           "-n", name, "-o", str(dst / "build"), f"-j{B.JOBS_PER_WORKER}", str(dst / "fix.patch")]
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    (dst / "kpatch-build.log").write_text(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    st = {"cve": cve, "generator": "kpatch-build v0.9.11", "replace": True, "ok": r.returncode == 0 and any((dst / "build").glob("*.ko")),
          "rc": r.returncode, "seconds": round(time.time() - t0)}
    (dst / "status.json").write_text(json.dumps(st))
    return st


def klp(cve: str, worker: int) -> dict:
    dst = OUT / "klp-replace" / cve
    shutil.rmtree(dst, ignore_errors=True)
    (dst / "build").mkdir(parents=True)
    shutil.copy2(S12 / "results/klp-gcc-13/6.19" / cve / "fix.patch", dst / "fix.patch")
    src = B.src_copy(worker, "6.19")
    shutil.rmtree(src / "klp-tmp", ignore_errors=True)
    env = dict(os.environ, PATH=f"{B.gccbin('gcc-13')}:{os.environ['PATH']}")
    name = "lp" + cve.replace("CVE-", "").replace("-", "_")
    cmd = ["./scripts/livepatch/klp-build", f"-j{B.JOBS_PER_WORKER}", "-o", str(dst / "build" / f"{name}.ko"),
           str(dst / "fix.patch")]
    t0 = time.time()
    r = subprocess.run(cmd, cwd=src, env=env, capture_output=True, text=True)
    (dst / "klp-build.log").write_text(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    st = {"cve": cve, "generator": "klp-build 6.19", "replace": True, "ok": r.returncode == 0 and any((dst / "build").glob("*.ko")),
          "rc": r.returncode, "seconds": round(time.time() - t0)}
    (dst / "status.json").write_text(json.dumps(st))
    return st


def main() -> int:
    from concurrent.futures import ThreadPoolExecutor
    jobs = []
    for r in LAB:
        if r["population"] != "B3":
            continue
        kind, rest = r["id"].split(":", 2)[1], r["id"].split(":", 2)[2]
        jobs.append((kind, rest.split("/")[1]))
    res = [kpatch(c, 9) for k, c in jobs if k == "kpatch-replace"]   # the idle 6.12 tree of worker 9, one at a time
    for s in res:
        print(s, flush=True)
    log = S12 / "s11-heldout.log"
    while "HELDOUT BUILD DONE" not in (log.read_text() if log.exists() else ""):
        time.sleep(300)
    kl = [c for k, c in jobs if k == "klp-replace"]
    with ThreadPoolExecutor(max_workers=4) as ex:
        from queue import Queue
        q: Queue = Queue()
        for w in range(4):
            q.put(w)

        def one(cve):
            w = q.get()
            try:
                return klp(cve, w)
            finally:
                q.put(w)
        res2 = list(ex.map(one, kl))
    for s in res2:
        print(s, flush=True)
    res += res2
    print("B3 DONE", sum(s["ok"] for s in res), "of", len(res), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
