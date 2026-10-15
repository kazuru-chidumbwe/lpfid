#!/usr/bin/env python3
"""S34 census runner. Reads the frozen package list. Does not discover new packages."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path("/home/test/s34-anolis")
LIST = ROOT / "census-packages.txt"
BASE = "https://mirrors.openanolis.cn/anolis/7.7/Plus"
EXCLUDE = "kernel-hotfix-CVE-2023-0461-4.19.91-25.6-1.0-20230327164636.an7.x86_64.rpm"
PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"
ORACLES = {
    "v13": "/opt/atlas/lpfid/blind-reloc-oracle-v1.3.py",
    "v14": "/opt/atlas/lpfid/blind-reloc-oracle-v1.4.py",
}
BODY = "/opt/atlas/lpfid/body_check.py"
KERN_RE = re.compile(r"-(\d+\.\d+\.\d+-\d+(?:\.\d+)?)-1\.0-\d+\.an7")
CONTAINER = "s34a7"


def run(cmd, **kw):
    print("+", " ".join(cmd) if isinstance(cmd, list) else cmd, flush=True)
    return subprocess.run(cmd, text=True, **kw)


def docker(*args, check=True):
    r = run(["docker", *args], capture_output=True)
    if check and r.returncode != 0:
        sys.stderr.write(r.stdout[-2000:] + r.stderr[-2000:])
        raise SystemExit(r.returncode)
    return r


def ensure_container():
    ps = run(["docker", "ps", "-a", "--filter", f"name=^{CONTAINER}$", "--format", "{{.Status}}"], capture_output=True)
    status = (ps.stdout or "").strip()
    if not status:
        docker("run", "-d", "--name", CONTAINER, "--privileged", "-v", f"{ROOT}:/work", "openanolis/anolisos:8", "sleep", "infinity")
    elif not status.startswith("Up"):
        docker("start", CONTAINER)
    marker = ROOT / "a7-ready"
    if marker.exists():
        return
    script = r"""
set -eux
dnf -y install patch tar xz gzip rpm cpio >/dev/null
rm -f /etc/yum.repos.d/*.repo
MIR=https://mirrors.openanolis.cn/anolis/7.7
if [ ! -x /a7/usr/bin/gcc ]; then
  dnf -y --installroot=/a7 --releasever=7 --nogpgcheck \
    --repofrompath=a7os,$MIR/os/x86_64/os/ \
    --repofrompath=a7plus,$MIR/Plus/x86_64/os/ \
    --enablerepo=a7os,a7plus --setopt=install_weak_deps=False \
    install gcc make bc bison flex elfutils-libelf-devel openssl-devel diffutils patch findutils xz tar gzip perl gawk which glibc-devel cpio rpm >/dev/null
fi
mkdir -p /a7/work
mountpoint -q /a7/work || mount --bind /work /a7/work
chroot /a7 gcc --version | head -1
"""
    r = docker("exec", CONTAINER, "bash", "-lc", script)
    sys.stdout.write(r.stdout)
    marker.write_text("ok\n")


def own(path: Path):
    rel = path.relative_to(ROOT).as_posix()
    run(["docker", "exec", CONTAINER, "chmod", "-R", "a+rX", f"/work/{rel}"], check=True)


def kernel_of(name: str) -> str:
    m = KERN_RE.search(name)
    if not m:
        raise SystemExit(f"cannot parse kernel from {name}")
    return m.group(1)


def prepare_kernel(ver: str):
    dest = ROOT / "kernels" / ver
    ready = dest / "PREPARED"
    if ready.exists():
        own(dest)
        return dest / "tree" / ready.read_text().strip()
    dest.mkdir(parents=True, exist_ok=True)
    rpm = dest / f"kernel-{ver}.an7.src.rpm"
    if not rpm.exists():
        url = f"{BASE}/source/Packages/kernel-{ver}.an7.src.rpm"
        run(["curl", "-fL", "--retry", "3", "-o", str(rpm), url], check=True)
    script = f"""
set -eux
mkdir -p /a7/work
mountpoint -q /a7/work || mount --bind /work /a7/work
VER={ver}
D=/work/kernels/$VER
rm -rf "$D/tree"
mkdir -p "$D/extract" "$D/tree"
cd "$D/extract"
rm -rf ./*
rpm2cpio "$D/kernel-$VER.an7.src.rpm" | cpio -idmu
TAR=$(ls linux-*.tar.xz | head -1)
CFG=$(ls kernel-*-x86_64.config | head -1)
test -n "$TAR" && test -n "$CFG"
tar -C "$D/tree" -xf "$TAR"
SRC=$(echo "$D/tree"/linux-*)
test -d "$SRC"
cp "$D/extract/$CFG" "$SRC/.config"
chroot /a7 bash -lc "cd /work/kernels/$VER/tree/linux-* && make olddefconfig >/tmp/cfg.log 2>&1 && make -j$(nproc) prepare >/tmp/prep.log 2>&1" \
  || {{ echo PREP_FAILED; tail -30 /a7/tmp/prep.log; exit 1; }}
basename "$SRC" > "$D/srcdir"
echo PREPARED
"""
    r = docker("exec", CONTAINER, "bash", "-lc", script)
    sys.stdout.write(r.stdout[-1500:])
    if r.returncode != 0:
        sys.stderr.write(r.stderr[-2000:])
        raise SystemExit(f"prepare failed for {ver}")
    own(dest)
    srcname = (dest / "srcdir").read_text().strip()
    ready.write_text(srcname + "\n")
    return dest / "tree" / srcname


def parse_objects(patch_text: str) -> list[str]:
    paths = []
    for line in patch_text.splitlines():
        m = re.match(r"diff --git a/(.+) b/(.+)", line)
        if not m:
            continue
        path = m.group(2)
        if path.endswith(".c") and not path.startswith("dev/"):
            paths.append(path[:-2] + ".o")
    return list(dict.fromkeys(paths))


def score_package(name: str):
    outdir = ROOT / "results" / name.replace(".rpm", "")
    if (outdir / "result.json").exists():
        print("skip", name, flush=True)
        return
    outdir.mkdir(parents=True, exist_ok=True)
    ver = kernel_of(name)
    rpm_path = ROOT / "rpms" / name
    rpm_path.parent.mkdir(parents=True, exist_ok=True)
    if not rpm_path.exists():
        url = f"{BASE}/x86_64/os/Packages/{name}"
        run(["curl", "-fL", "--retry", "3", "-o", str(rpm_path), url], check=True)
    unpack = ROOT / "unpack" / name.replace(".rpm", "")
    rel_unpack_rm = unpack.relative_to(ROOT).as_posix()
    run(["docker", "exec", CONTAINER, "rm", "-rf", f"/work/{rel_unpack_rm}"], check=True)
    unpack.mkdir(parents=True)
    rel_rpm = rpm_path.relative_to(ROOT).as_posix()
    rel_unpack = unpack.relative_to(ROOT).as_posix()
    ur = run(["docker", "exec", CONTAINER, "bash", "-lc",
              f"mkdir -p /a7/work; mountpoint -q /a7/work || mount --bind /work /a7/work; "
              f"cd /work/{rel_unpack} && rpm2cpio /work/{rel_rpm} | cpio -idmu"],
             capture_output=True)
    if ur.returncode != 0:
        result = {"package": name, "kernel": ver, "status": "UNPACK", "error": (ur.stderr or ur.stdout)[-500:]}
        (outdir / "result.json").write_text(json.dumps(result, indent=1))
        return
    own(unpack)
    kos = list(unpack.rglob("*.ko"))
    patches = list(unpack.rglob("patch"))
    result = {"package": name, "kernel": ver, "n_ko": len(kos), "n_patch": len(patches)}
    if len(kos) != 1 or len(patches) != 1:
        result["status"] = "UNPACK"
        result["error"] = "expected one ko and one patch"
        (outdir / "result.json").write_text(json.dumps(result, indent=1))
        return
    patch_text = patches[0].read_text(errors="replace")
    objects = parse_objects(patch_text)
    result["objects"] = objects
    change = next(unpack.rglob("changeinfo"), None)
    result["changeinfo"] = change.read_text(errors="replace") if change else ""
    if not objects:
        result["status"] = "BUILD_FAIL"
        result["error"] = "patch names no .c file"
        (outdir / "result.json").write_text(json.dumps(result, indent=1))
        return
    try:
        src = prepare_kernel(ver)
    except SystemExit as e:
        result["status"] = "BUILD_FAIL"
        result["error"] = f"kernel prepare: {e}"
        (outdir / "result.json").write_text(json.dumps(result, indent=1))
        return
    rel_patch = (src / "s34.patch").relative_to(ROOT).as_posix()
    run(["docker", "exec", "-i", CONTAINER, "tee", f"/work/{rel_patch}"], input=patch_text, capture_output=True, check=True)
    obj_args = " ".join(objects)
    rel_src = src.relative_to(ROOT).as_posix()
    script = f"""
set -eux
mkdir -p /a7/work
mountpoint -q /a7/work || mount --bind /work /a7/work
cd /work/{rel_src}
patch -p1 --dry-run < s34.patch
patch -p1 < s34.patch
chroot /a7 bash -lc 'cd /work/{rel_src} && make -j$(nproc) KCFLAGS="-ffunction-sections -fdata-sections" {obj_args}' \
  || {{ echo OBJ_FAILED; exit 1; }}
"""
    r = docker("exec", CONTAINER, "bash", "-lc", script, check=False)
    (outdir / "build.log").write_text((r.stdout or "") + "\n" + (r.stderr or ""))
    rev = docker("exec", CONTAINER, "bash", "-lc",
                 f"cd /work/{rel_src} && patch -R -p1 < s34.patch && rm -f s34.patch", check=False)
    (outdir / "build.log").write_text((outdir / "build.log").read_text() + "\n-- reverse --\n" + (rev.stdout or "") + (rev.stderr or ""))
    if r.returncode != 0 or rev.returncode != 0:
        result["status"] = "BUILD_FAIL"
        result["error"] = "object build or patch reverse failed; tree will be rebuilt"
        (outdir / "result.json").write_text(json.dumps(result, indent=1))
        (ROOT / "kernels" / ver / "PREPARED").unlink(missing_ok=True)
        return
    refs = [src / o for o in objects]
    missing = [str(p) for p in refs if not p.exists()]
    if missing:
        result["status"] = "BUILD_FAIL"
        result["error"] = "missing objects " + ",".join(missing)
        (outdir / "result.json").write_text(json.dumps(result, indent=1))
        return
    ko = kos[0]
    env = os.environ.copy()
    env["LPFID_T1"] = "version"
    for key, oracle in ORACLES.items():
        rr = run([PY, oracle, str(ko), *[str(p) for p in refs]], capture_output=True, env=env)
        (outdir / f"{key}.json").write_text(rr.stdout or rr.stderr)
        try:
            result[key] = json.loads(rr.stdout)
        except json.JSONDecodeError:
            result[key] = {"error": "not json", "rc": rr.returncode, "tail": (rr.stdout or rr.stderr)[-400:]}
    br = run([PY, BODY, str(ko), *[str(p) for p in refs]], capture_output=True, env=env)
    (outdir / "body.json").write_text(br.stdout or br.stderr)
    try:
        result["body"] = json.loads(br.stdout)
    except json.JSONDecodeError:
        result["body"] = {"error": "not json", "rc": br.returncode, "tail": (br.stdout or br.stderr)[-400:]}
    kept = outdir / "refs"
    kept.mkdir(exist_ok=True)
    for p in refs:
        shutil.copy2(p, kept / p.name)
    result["status"] = "SCORED"
    (outdir / "result.json").write_text(json.dumps(result, indent=1))
    print("SCORED", name, (result.get("v13") or {}).get("overall_verdict"), flush=True)


def main():
    names = [ln.strip() for ln in LIST.read_text().splitlines() if ln.strip()]
    if EXCLUDE in names or len(names) != 39:
        raise SystemExit(f"frozen list is {len(names)} and must be the 39 census packages")
    ensure_container()
    for name in names:
        try:
            score_package(name)
        except Exception as e:
            outdir = ROOT / "results" / name.replace(".rpm", "")
            outdir.mkdir(parents=True, exist_ok=True)
            (outdir / "result.json").write_text(json.dumps({"package": name, "status": "ERROR", "error": str(e)}, indent=1))
            print("ERROR", name, e, flush=True)


if __name__ == "__main__":
    main()
