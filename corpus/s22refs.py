#!/usr/bin/env python3
"""S22: independent reference objects for every S12 fix (no kpatch involved).

For each fix: a per-worker copy of the pin tree is restored to the release tarball (same verified
restore as s12build.py), the fix is applied with plain `patch -p1`, and only the touched objects are
compiled with stock make and the pin compiler, with the section flags kpatch documents
(-ffunction-sections -fdata-sections) so section layout is comparable. kpatch's own patched objects
stay available as the second reference; verdicts are reported against both.

Usage: s22refs.py WORKERS [--branches 6.1,6.6,6.12] [--offset 20] [--gcc gcc-13|gcc-14] [--set main|overcap|all]
(gcc-14 output goes to refs-independent-gcc-14, built in the gcc-14 pin tree)
Output: /opt/atlas/s12/refs-independent/<branch>/<cve>/{<path>.o, build.log, status.json}
"""
from __future__ import annotations

import importlib.util
import json
import os
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
OUT = S12 / "refs-independent"
KCFLAGS = "-ffunction-sections -fdata-sections"


def build_ref(job: dict, worker: int, gcc: str = "gcc-13") -> None:
    branch, cve, sha = job["branch"], job["cve"], job["stable_sha"]
    pin, _, repo = B.PINS[branch]
    dst = (OUT if gcc == "gcc-13" else OUT.with_name(OUT.name + "-" + gcc)) / branch / cve
    if (dst / "status.json").exists():
        return
    dst.mkdir(parents=True, exist_ok=True)
    patch = subprocess.run(["git", "-C", str(repo), "show", "--format=", "--no-color", sha],
                           check=True, capture_output=True, text=True).stdout
    (dst / "fix.patch").write_text(patch)
    src = B.src_copy(worker, branch, gcc)
    log = []
    r = subprocess.run(["patch", "-p1", "--fuzz=2", "-d", str(src)], input=patch, capture_output=True, text=True)
    log.append(r.stdout + r.stderr)
    ok, objs = r.returncode == 0, []
    t0 = time.time()
    if ok:
        files = [l.split(" b/", 1)[1] for l in patch.splitlines() if l.startswith("diff --git ")]
        for f in files:
            obj = f[:-2] + ".o"
            m = subprocess.run(["make", "-C", str(src), "-j4", f"CC={gcc}", f"HOSTCC={gcc}", f"KCFLAGS={KCFLAGS}", obj],
                               capture_output=True, text=True)
            log.append(f"== make {obj} rc={m.returncode}\n{m.stdout[-3000:]}{m.stderr[-3000:]}")
            if m.returncode != 0 or not (src / obj).exists():
                ok = False
                continue
            (dst / obj).parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["cp", str(src / obj), str(dst / obj)], check=True)
            objs.append(obj)
    (dst / "build.log").write_text("\n".join(log))
    status = {"branch": branch, "pin": pin, "cve": cve, "stable_sha": sha, "ok": ok, "objects": objs,
              "kcflags": KCFLAGS, "compiler": gcc, "seconds": round(time.time() - t0), "worker": worker}
    (dst / "status.json").write_text(json.dumps(status, indent=1))
    B.log(f"S22 {branch} {cve} {'OK' if ok else 'FAIL'} {len(objs)} objects")


def main() -> int:
    workers = int(sys.argv[1])
    args = sys.argv[2:]
    branches = (args[args.index("--branches") + 1] if "--branches" in args else "6.1,6.6,6.12").split(",")
    offset = int(args[args.index("--offset") + 1]) if "--offset" in args else 20
    gcc = args[args.index("--gcc") + 1] if "--gcc" in args else "gcc-13"
    which = args[args.index("--set") + 1] if "--set" in args else "all"
    q: Queue = Queue()
    for b in branches:
        s = json.loads((S12 / "out" / b / "selection.json").read_text())
        for kind in ("main", "overcap"):
            if which not in (kind, "all"):
                continue
            for j in s[kind]:
                q.put({**j, "branch": b})

    def worker(i: int) -> None:
        while not q.empty():
            j = q.get()
            try:
                build_ref(j, i, gcc)
            except Exception as e:  # noqa: BLE001
                B.log(f"S22 {j['branch']} {j['cve']} ERROR {e!r}")

    with ThreadPoolExecutor(workers) as ex:
        for i in range(workers):
            ex.submit(worker, i + offset)
    B.log("S22 DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
