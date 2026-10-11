#!/usr/bin/env python3
"""S11 diagnostic rebuild: build one 6.19 fix with klp-build exactly as s11klp.py does (same worker tree
restore, gcc 13, -T --no-replace), but keep the whole klp-tmp directory, so the .rodata layout can be
followed through objtool's diff object, the kmod object and the final .ko.
Usage (build host): python3 s11_repro_klp.py CVE-ID [WORKER]
Writes /opt/atlas/s12/s11-repro/<cve>/{build,klp-tmp,klp-build.log}.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

S12 = Path("/opt/atlas/s12")
spec = importlib.util.spec_from_file_location("s12build", S12 / "s12build.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)

cve = sys.argv[1]
worker = int(sys.argv[2]) if len(sys.argv) > 2 else 0
patch = S12 / "results/klp-gcc-13/6.19" / cve / "fix.patch"
dst = S12 / "s11-repro" / cve
shutil.rmtree(dst, ignore_errors=True)
(dst / "build").mkdir(parents=True)
src = B.src_copy(worker, "6.19")
shutil.rmtree(src / "klp-tmp", ignore_errors=True)
name = "lp" + cve.replace("CVE-", "").replace("-", "_")
env = dict(os.environ, PATH=f"{B.gccbin('gcc-13')}:{os.environ['PATH']}")
cmd = ["./scripts/livepatch/klp-build", "-T", "--no-replace", f"-j{B.JOBS_PER_WORKER}",
       "-o", str(dst / "build" / f"{name}.ko"), str(patch)]
t0 = time.time()
r = subprocess.run(cmd, cwd=src, env=env, capture_output=True, text=True)
(dst / "klp-build.log").write_text(" ".join(cmd) + "\n" + r.stdout + r.stderr + f"\nrc={r.returncode} {time.time() - t0:.0f}s\n")
shutil.copytree(src / "klp-tmp", dst / "klp-tmp", symlinks=True)
print(cve, "rc", r.returncode, f"{time.time() - t0:.0f}s")
