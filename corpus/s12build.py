#!/usr/bin/env python3
"""S12/S21: build every selected fix as a kpatch module (resumable, parallel workers).

Usage: s12build.py KPATCH_VERSION WORKERS [--gcc gcc-13|gcc-14] [--branches 6.1,6.6,6.12] [--set main|overcap|all] [--offset N]
(--offset: first worker id, so two runners never share a source copy)

Per job writes /opt/atlas/s12/results/<kver>-<gcc>/<branch>/<cve>/:
  fix.patch, kpatch-build.log, *.ko, patched/**.o (kpatch's own reference), patch-hook.o, status.json
A job with status.json is never rebuilt. Build failures are kept (pre-registered rule, step 9).
"""
from __future__ import annotations

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
C = Path("/opt/atlas/livepatch-corpus")
PINS = {
    "6.1": ("6.1.119", C / "linux-second-pin", S12 / "stable"),
    "6.6": ("6.6.47", C / "pilot-work/linux", S12 / "stable"),
    "6.12": ("6.12.51", C / "linux-6.12.51", S12 / "stable612"),
    "5.15": ("5.15.173", C / "linux-5.15.173", S12 / "stable"),   # S12-PREREG Deviation 7
    "6.19": ("6.19", C / "linux-6.19", S12 / "stable619"),  # S11-PREREG Deviation 1 (was 6.19.14)
}
JOBS_PER_WORKER = 4


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S', time.gmtime())}] {msg}"
    print(line, flush=True)
    with (S12 / "build-progress.txt").open("a") as f:
        f.write(line + "\n")


def gccbin(gcc: str) -> Path:
    d = S12 / f"gccbin-{gcc}"
    d.mkdir(parents=True, exist_ok=True)   # race-safe: workers may arrive together (8 Oct, CVE-2025-68261)
    for t in ("gcc", "cc"):
        try:
            os.symlink(f"/usr/bin/{gcc}", d / t)
        except FileExistsError:
            pass
    return d


def pin_tree(branch: str, gcc: str) -> Path:
    """gcc-14 runs (S21 c608faf pair) use a pin tree built with gcc-14; vmlinux must match the compiler."""
    _, tree, _ = PINS[branch]
    return tree if gcc == "gcc-13" else tree.with_name(tree.name + "-" + gcc.replace("-", ""))


PRISTINE = S12 / "pristine"   # official release tarballs extracted: exactly the sources, nothing else


def src_copy(worker: int, branch: str, gcc: str = "gcc-13") -> Path:
    """Per-worker build tree whose sources equal the release tarball before EVERY job.

    First use: a full copy of the pin tree (sources, config and the pin's own build products), so the
    first original build is incremental. Before every job: every file of the pristine tarball tree is
    restored by checksum WITHOUT --delete (build products stay) and WITHOUT preserving times, so any file
    the previous job changed gets a fresh mtime and make rebuilds its objects. Verification: a checksum
    dry run from the tarball tree must report no differing file, else the job aborts.
    (kpatch-build --skip-cleanup leaves the fix applied; 7 Oct incident, deviation 3. An exclusion-list
    approach dropped arch/x86/kernel/vmlinux.lds.S and was abandoned.)"""
    pin = PINS[branch][0]
    tree = pin_tree(branch, gcc)
    pristine = PRISTINE / f"linux-{pin}"
    dst = S12 / "work" / f"w{worker}" / (branch if gcc == "gcc-13" else f"{branch}-{gcc}")
    if not (dst / ".s12-initialised").exists():
        if dst.exists():
            shutil.rmtree(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "-a", f"{tree}/.", f"{dst}/"], check=True)
        (dst / ".s12-initialised").touch()
    subprocess.run(["rsync", "-rlpgoD", "--checksum", f"{pristine}/", f"{dst}/"], check=True)
    left = subprocess.run(["rsync", "-rlc", "--dry-run", "--itemize-changes", f"{pristine}/", f"{dst}/"],
                          check=True, capture_output=True, text=True).stdout
    bad = [l for l in left.splitlines() if l.startswith((">f", "cd", "cL", ">L"))]
    if bad:
        raise RuntimeError(f"source copy {dst} differs from tarball after restore: {bad[:5]}")
    return dst


def build(job: dict, worker: int, kver: str, gcc: str) -> None:
    branch, cve, sha = job["branch"], job["cve"], job["stable_sha"]
    pin, _, repo = PINS[branch]
    tree = pin_tree(branch, gcc)
    dst = Path(os.environ.get("S12_RESULTS", S12 / "results")) / f"{kver}-{gcc}" / branch / cve
    if (dst / "status.json").exists():
        return
    dst.mkdir(parents=True, exist_ok=True)
    patch = dst / "fix.patch"
    patch.write_text(subprocess.run(["git", "-C", str(repo), "show", "--format=", "--no-color", sha],
                                    check=True, capture_output=True, text=True).stdout)
    src = src_copy(worker, branch, gcc)
    home = S12 / "work" / f"w{worker}" / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HOME=str(home), CACHEDIR=str(home / ".kpatch"),
               PATH=f"{gccbin(gcc)}:/opt/atlas/tools/kp/{kver}/bin:{os.environ['PATH']}")
    out = dst / "build"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir()
    name = "lp" + cve.replace("CVE-", "").replace("-", "_")
    cmd = ["kpatch-build", "-R", "--skip-cleanup", "-s", str(src), "-c", str(tree / ".config"),
           "-v", str(tree / "vmlinux"), "-n", name, "-o", str(out), f"-j{JOBS_PER_WORKER}", str(patch)]
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    secs = round(time.time() - t0)
    (dst / "kpatch-build.log").write_text(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    kos = sorted(out.glob("*.ko"))
    ok = r.returncode == 0 and bool(kos)
    tmp = home / ".kpatch/tmp"
    if ok:
        for o in (tmp / "patched").rglob("*.o"):
            rel = o.relative_to(tmp / "patched")
            (dst / "patched" / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(o, dst / "patched" / rel)
        if (tmp / "patch/patch-hook.o").exists():
            shutil.copy2(tmp / "patch/patch-hook.o", dst / "patch-hook.o")
    # kpatch-build's own log of the last step, if present, explains failures
    if (home / ".kpatch/build.log").exists():
        shutil.copy2(home / ".kpatch/build.log", dst / "kpatch-internal-build.log")
    status = {"branch": branch, "pin": pin, "cve": cve, "stable_sha": sha, "kpatch": kver, "gcc": gcc,
              "set": job["set"], "type": job.get("type"), "ok": ok, "rc": r.returncode, "seconds": secs,
              "modules": [k.name for k in kos], "worker": worker}
    (dst / "status.json").write_text(json.dumps(status, indent=1))
    log(f"{kver}-{gcc} {branch} {cve} {'OK' if ok else 'FAIL rc=' + str(r.returncode)} {secs}s")


def main() -> int:
    kver, workers = sys.argv[1], int(sys.argv[2])
    args = sys.argv[3:]
    gcc = args[args.index("--gcc") + 1] if "--gcc" in args else "gcc-13"
    branches = (args[args.index("--branches") + 1] if "--branches" in args else "6.1,6.6,6.12").split(",")
    which = args[args.index("--set") + 1] if "--set" in args else "all"
    offset = int(args[args.index("--offset") + 1]) if "--offset" in args else 0
    jobs = []
    for b in branches:
        sel = S12 / "out" / b / "selection.json"
        if not sel.exists():
            log(f"no selection for {b}; skipped")
            continue
        s = json.loads(sel.read_text())
        for kind in ("main", "overcap"):
            if which in (kind, "all"):
                jobs += [{**j, "branch": b, "set": kind} for j in s[kind]]
    log(f"START {kver}-{gcc} jobs={len(jobs)} workers={workers}")
    q: Queue = Queue()
    for j in jobs:
        q.put(j)

    def worker(i: int) -> None:
        while not q.empty():
            j = q.get()
            try:
                build(j, i, kver, gcc)
            except Exception as e:  # noqa: BLE001
                log(f"{kver}-{gcc} {j['branch']} {j['cve']} ERROR {e!r}")

    with ThreadPoolExecutor(workers) as ex:
        for i in range(workers):
            ex.submit(worker, i + offset)
    log(f"DONE {kver}-{gcc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
