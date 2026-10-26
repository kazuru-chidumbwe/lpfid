#!/usr/bin/env python3
"""S44 addendum A3 for S26: rebuild the S26 references with the S26 builder (`s26-builder` image, ~/s26/work/build_one.sh)
and keep ko/ and ref/ for every package, so the immediate check covers all 164 modules. The rest of each build tree is
removed to bound disk, as S26 did. Control: every rebuilt reference of the 58 modules S26 kept must be byte-identical
to the kept copy (sha256 in s26re/control.txt).
usage: s26_rebuild.py   (writes ~/s44/s26re/)"""
import glob, hashlib, json, os, subprocess, time

H = os.path.expanduser("~")
SAMPLE = json.load(open(f"{H}/s26/s26-sample.json"))
PKGS = [p for series in SAMPLE["sample"].values() for p in series]
WORK = f"{H}/s44/s26re/work"
KEEP = f"{H}/s44/s26re/keep"
LOG = f"{H}/s44/s26re/STATUS"
os.makedirs(WORK, exist_ok=True)
os.makedirs(KEEP, exist_ok=True)
subprocess.run(["cp", f"{H}/s26/work/build_one.sh", f"{H}/s26/work/fix_kpatch.py", WORK])


def log(s):
    with open(LOG, "a") as f:
        f.write(time.strftime("[%Y-%m-%dT%H:%M:%SZ] ", time.gmtime()) + s + "\n")


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


log(f"start {len(PKGS)} packages")
for i, pkg in enumerate(PKGS, 1):
    kd = os.path.join(KEEP, pkg)
    if os.path.exists(os.path.join(kd, "DONE")):
        continue
    t0 = time.time()
    r = subprocess.run(["docker", "run", "--rm", "-v", f"{WORK}:/work", "s26-builder", "bash", "/work/build_one.sh", pkg],
                       capture_output=True, text=True, timeout=14400)
    w = os.path.join(WORK, pkg)
    kos = sorted(glob.glob(os.path.join(w, "ko", "*.ko")))
    refs = sorted(glob.glob(os.path.join(w, "ref", "*", "*.o")))
    os.makedirs(kd, exist_ok=True)
    open(os.path.join(kd, "build.log"), "w").write(r.stdout[-8000:] + "\n---STDERR---\n" + r.stderr[-4000:])
    for sub in ("ko", "ref"):
        if os.path.isdir(os.path.join(w, sub)):
            subprocess.run(["cp", "-r", os.path.join(w, sub), kd])
    subprocess.run(["docker", "run", "--rm", "-v", f"{WORK}:/work", "s26-builder", "rm", "-rf", f"/work/{pkg}"])
    open(os.path.join(kd, "DONE"), "w").write("")
    log(f"[{i}] {pkg} ko={len(kos)} ref={len(refs)} ({round(time.time() - t0)}s)")

# control against the 58 modules S26 kept
with open(f"{H}/s44/s26re/control.txt", "w") as out:
    same = diff = missing = 0
    for k in sorted(glob.glob(f"{H}/s26/results/*/keep/*/")):
        pkg = k.split("/results/")[1].split("/")[0]
        patch = os.path.basename(k.rstrip("/"))
        for o in sorted(glob.glob(os.path.join(k, "ref", "*.o"))):
            n = os.path.join(KEEP, pkg, "ref", patch, os.path.basename(o))
            if not os.path.exists(n):
                missing += 1
                out.write(f"MISSING {pkg} {patch} {os.path.basename(o)}\n")
            elif sha(n) == sha(o):
                same += 1
            else:
                diff += 1
                out.write(f"DIFF {pkg} {patch} {os.path.basename(o)}\n")
        for ko in glob.glob(os.path.join(k, "*.ko")):
            n = os.path.join(KEEP, pkg, "ko", os.path.basename(ko))
            ok = os.path.exists(n) and sha(n) == sha(ko)
            out.write(f"KO {'SAME' if ok else 'DIFF'} {pkg} {os.path.basename(ko)}\n")
    out.write(f"refs same {same} diff {diff} missing {missing}\n")
log("S26 rebuild DONE")
