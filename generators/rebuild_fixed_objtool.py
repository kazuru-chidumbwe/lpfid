#!/usr/bin/env python3
"""S11 control: rebuild given 6.19 fixes with klp-build exactly as s11klp.py does, except that after the worker
tree restore the upstream objtool fix fa31c5b01 ("objtool: Fix data alignment in elf_add_data()", v6.19.9) is
applied to tools/objtool/elf.c. Nothing else changes. Registered in KLP-LOAD-FAILS-2026-10-10.md before the run.
Usage (build host): python3 s11_fixobjtool.py WORKERS CVE [CVE ...]
Writes /opt/atlas/s12/s11-fixobjtool/<cve>/{build/*.ko,klp-build.log,patch-apply.log,status.json}.
"""
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
FIX = S12 / "objtool-fa31c5b01.patch"
OUT = S12 / "s11-fixobjtool"


def build(cve: str, worker: int) -> dict:
    dst = OUT / cve
    shutil.rmtree(dst, ignore_errors=True)
    (dst / "build").mkdir(parents=True)
    src = B.src_copy(worker, "6.19")
    shutil.rmtree(src / "klp-tmp", ignore_errors=True)
    p = subprocess.run(["patch", "-p1", "--forward", "-i", str(FIX)], cwd=src, capture_output=True, text=True)
    (dst / "patch-apply.log").write_text(p.stdout + p.stderr + f"rc={p.returncode}\n")
    if p.returncode != 0:
        return {"cve": cve, "ok": False, "stage": "patch"}
    name = "lp" + cve.replace("CVE-", "").replace("-", "_")
    env = dict(os.environ, PATH=f"{B.gccbin('gcc-13')}:{os.environ['PATH']}")
    cmd = ["./scripts/livepatch/klp-build", "-T", "--no-replace", f"-j{B.JOBS_PER_WORKER}",
           "-o", str(dst / "build" / f"{name}.ko"), str(S12 / "results/klp-gcc-13/6.19" / cve / "fix.patch")]
    t0 = time.time()
    r = subprocess.run(cmd, cwd=src, env=env, capture_output=True, text=True)
    (dst / "klp-build.log").write_text(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    st = {"cve": cve, "ok": r.returncode == 0 and any((dst / "build").glob("*.ko")), "rc": r.returncode,
          "seconds": round(time.time() - t0), "objtool_fix": "fa31c5b01", "worker": worker}
    (dst / "status.json").write_text(json.dumps(st))
    return st


def main():
    workers, cves = int(sys.argv[1]), sys.argv[2:]
    pool: Queue = Queue()
    for w in range(workers):
        pool.put(w)

    def run(cve):
        w = pool.get()
        try:
            st = build(cve, w)
        finally:
            pool.put(w)
        print(f"[{time.strftime('%H:%M:%S')}] {cve} ok={st['ok']} {st.get('seconds', '')}s", flush=True)
        return st

    with ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(run, cves))
    print("FIXOBJTOOL DONE", sum(r["ok"] for r in res), "of", len(res), flush=True)


if __name__ == "__main__":
    main()
