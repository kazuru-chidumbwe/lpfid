#!/usr/bin/env python3
"""S11: build every selected 6.19 fix with the in-tree klp-build (S11-PREREG-2026-10-09.md).

Per job, like s12build.py: the worker's tree is restored to the release tarball and checked; the fix is
passed to scripts/livepatch/klp-build (-T keeps klp-tmp, --no-replace, gcc 13.3.0); klp-build applies the
patch with git apply and reverts it on exit. Writes results/klp-gcc-13/6.19/<cve>/: fix.patch,
klp-build.log, build/*.ko, patched/** (klp-build's own patched objects, its reference), status.json.
A job with status.json is never rebuilt. Build failures are kept.
Usage: python3 s11klp.py WORKERS [--offset N] [--set main|overcap|all]
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

S12 = Path("/opt/atlas/s12")
spec = importlib.util.spec_from_file_location("s12build", S12 / "s12build.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
BRANCH = "6.19"


def build(job: dict, worker: int) -> None:
    cve, sha = job["cve"], job["stable_sha"]
    pin, _, repo = B.PINS[BRANCH]
    dst = S12 / "results" / "klp-gcc-13" / BRANCH / cve
    if (dst / "status.json").exists():
        return
    dst.mkdir(parents=True, exist_ok=True)
    patch = dst / "fix.patch"
    patch.write_text(subprocess.run(["git", "-C", str(repo), "show", "--format=", "--no-color", sha],
                                    check=True, capture_output=True, text=True).stdout)
    src = B.src_copy(worker, BRANCH)
    shutil.rmtree(src / "klp-tmp", ignore_errors=True)
    out = dst / "build"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    name = "lp" + cve.replace("CVE-", "").replace("-", "_")
    env = dict(os.environ, PATH=f"{B.gccbin('gcc-13')}:{os.environ['PATH']}")
    cmd = ["./scripts/livepatch/klp-build", "-T", "--no-replace", f"-j{B.JOBS_PER_WORKER}",
           "-o", str(out / f"{name}.ko"), str(patch)]
    t0 = time.time()
    r = subprocess.run(cmd, cwd=src, capture_output=True, text=True, env=env)
    secs = round(time.time() - t0)
    (dst / "klp-build.log").write_text(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    if (src / "klp-tmp" / "build.log").exists():
        shutil.copy2(src / "klp-tmp" / "build.log", dst / "klp-internal-build.log")
    kos = sorted(out.glob("*.ko"))
    ok = r.returncode == 0 and bool(kos)
    if ok and (src / "klp-tmp" / "patched").exists():
        shutil.copytree(src / "klp-tmp" / "patched", dst / "patched", dirs_exist_ok=True)
    status = {"branch": BRANCH, "pin": pin, "cve": cve, "stable_sha": sha, "generator": "klp-build", "gcc": "gcc-13",
              "set": job["set"], "type": job.get("type"), "ok": ok, "rc": r.returncode, "seconds": secs,
              "modules": [k.name for k in kos], "worker": worker}
    (dst / "status.json").write_text(json.dumps(status, indent=1))
    B.log(f"klp-gcc-13 {BRANCH} {cve} {'OK' if ok else 'FAIL rc=' + str(r.returncode)} {secs}s")


def main() -> int:
    workers = int(sys.argv[1])
    args = sys.argv[2:]
    which = args[args.index("--set") + 1] if "--set" in args else "main"
    offset = int(args[args.index("--offset") + 1]) if "--offset" in args else 0
    sel = json.loads((S12 / "out" / BRANCH / "selection.json").read_text())
    jobs = [{**j, "set": kind} for kind in ("main", "overcap") if which in (kind, "all") for j in sel[kind]]
    B.log(f"START klp-gcc-13 {BRANCH} jobs={len(jobs)} workers={workers}")
    q: Queue = Queue()
    for j in jobs:
        q.put(j)

    def worker(i: int) -> None:
        while not q.empty():
            j = q.get()
            try:
                build(j, i)
            except Exception as e:  # noqa: BLE001
                B.log(f"klp-gcc-13 {BRANCH} {j['cve']} ERROR {e!r}")

    with ThreadPoolExecutor(workers) as ex:
        for i in range(workers):
            ex.submit(worker, i + offset)
    B.log(f"DONE klp-gcc-13 {BRANCH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
