#!/usr/bin/env python3
"""S26 orchestrator (host, Testbed A). Per sampled package: build the independent reference in the
s26-builder container, then score each shipped .ko with the host oracle v1.3/v1.4 (binding + addend,
no --vmlinux) and the eligibility pre-scan. Resumable (skips a package whose result.json exists) and
logged. Writes results/<pkg>/result.json. Does NOT disclose anything; a flagged module is reported to
Amazon by the author before Section 7.6 publishes (prereg ethical-slip gate)."""
import glob
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HOME = Path.home() / "s26"
SAMPLE = json.load(open(HOME / "s26-sample.json"))
PKGS = [p for series in SAMPLE["sample"].values() for p in series]
VENV = os.environ.get("S26_PY", "/opt/atlas/venvs/lpfid-oracle-v11/bin/python")
ORACLE_DIR = os.environ.get("S26_ORACLE_DIR", "/opt/atlas/lpfid")
ORA = {"v1.3": f"{ORACLE_DIR}/blind-reloc-oracle-v1.3.py",
       "v1.4": f"{ORACLE_DIR}/blind-reloc-oracle-v1.4.py"}
ELIG = f"{ORACLE_DIR}/pre-revert-scan-v2.py"
WORK = HOME / "work"
RES = HOME / "results"
LOG = HOME / "s26-run.log"
ONLY = sys.argv[1] if len(sys.argv) > 1 else None  # optional: run a single package (test mode)


def log(m):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {m}"
    with open(LOG, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def ref_dir_for(ko_name, w):
    """Find the reference dir built from this module's OWN patch. kpatch names a module
    'livepatch-<patch>' with '.' replaced by '-', and ref dirs are the patch basenames. This matches both
    the old (CVE-2024-47701.0001 -> livepatch-CVE-2024-47701-0001) and new (CVE-2025-21703 ->
    livepatch-CVE-2025-21703) naming by comparing ref-dir-with-dots-as-dashes to the ko stem."""
    stem = ko_name[:-3] if ko_name.endswith(".ko") else ko_name
    rd = w / "ref"
    if rd.is_dir():
        for d in sorted(rd.iterdir()):
            if d.is_dir() and ("livepatch-" + d.name.replace(".", "-").replace("&", "-")) == stem:
                return d
    return None


def score_ko(ko, w):
    """Pair the shipped .ko with the reference objects built from its OWN patch (ref/<patch>/*.o),
    and classify eligibility using the freshly built module (which keeps DWARF) as the --types source."""
    name = os.path.basename(ko)
    refdir = ref_dir_for(name, w)
    m = {"ko": name, "patch": refdir.name if refdir else None}
    refs = sorted(glob.glob(str(refdir / "*.o"))) if refdir else []
    m["ref_n"] = len(refs)
    if not refs:
        m["v1.3"] = m["v1.4"] = "NO_REF"
    else:
        for v, op in ORA.items():
            rr = subprocess.run([VENV, op, ko, *refs], capture_output=True, text=True, timeout=1800)
            try:
                m[v] = json.loads(rr.stdout).get("overall_verdict", "PARSE_ERR")
            except Exception:
                m[v] = "ERROR"
                m[v + "_stderr"] = rr.stderr[-300:]
    types = w / "built" / name  # same-CVE built module, retains DWARF -> klp struct layout
    cmd = [VENV, ELIG] + (["--types", str(types)] if types.exists() else []) + [ko]
    er = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    try:
        ej = json.loads(er.stdout)
        m["eligibility"] = ej.get("pre_class")
        m["is_replace"] = ej.get("is_replace")
        m["uses_shadow"] = ej.get("uses_shadow")
        m["has_callbacks"] = ej.get("has_state_callbacks")
    except Exception:
        m["eligibility"] = "ERROR"
    return m


def main():
    RES.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    pkgs = [ONLY] if ONLY else PKGS
    log(f"RUN start: {len(pkgs)} package(s)")
    for pkg in pkgs:
        rd = RES / pkg
        rd.mkdir(parents=True, exist_ok=True)
        if (rd / "result.json").exists():
            log(f"skip {pkg} (result exists)")
            continue
        log(f"START {pkg}")
        t0 = time.time()
        w = WORK / pkg
        # reuse already-built artifacts if present (e.g. the pilot package); otherwise build.
        if glob.glob(str(w / "ko" / "*.ko")) and glob.glob(str(w / "ref" / "*" / "*.o")):
            log(f"  reusing existing build artifacts for {pkg}")
        else:
            r = subprocess.run(
                ["docker", "run", "--rm", "-v", f"{WORK}:/work", "s26-builder",
                 "bash", "/work/build_one.sh", pkg],
                capture_output=True, text=True, timeout=14400)
            (rd / "build.log").write_text(r.stdout[-8000:] + "\n---STDERR---\n" + r.stderr[-4000:])
        kos = sorted(glob.glob(str(w / "ko" / "*.ko")))
        refs = glob.glob(str(w / "ref" / "*" / "*.o"))  # per-patch reference objects
        if not kos or not refs:
            (rd / "result.json").write_text(json.dumps(
                {"pkg": pkg, "status": "BUILD_FAIL", "ko": len(kos), "ref": len(refs),
                 "secs": round(time.time() - t0)}, indent=1))
            log(f"BUILD_FAIL {pkg} ko={len(kos)} ref={len(refs)} ({round(time.time()-t0)}s)")
            continue
        out = {"pkg": pkg, "status": "SCORED", "ko": len(kos), "ref": len(refs), "modules": []}
        for ko in kos:
            out["modules"].append(score_ko(ko, w))
        out["secs"] = round(time.time() - t0)
        (rd / "result.json").write_text(json.dumps(out, indent=1))
        log(f"DONE {pkg} ({out['secs']}s): " +
            "; ".join(f"{m['ko']} v1.3={m.get('v1.3')} v1.4={m.get('v1.4')} elig={m.get('eligibility')}"
                      for m in out["modules"]))
        # Preserve the ko + reference + full oracle dump for every non-CONSISTENT module, so divergences
        # survive the disk cleanup and can be root-caused (compiler vs representation vs real fault) before
        # any Amazon disclosure. Reference files are world-readable even though root wrote them.
        for mm in out["modules"]:
            if mm.get("v1.3") == "CONSISTENT" and mm.get("v1.4") == "CONSISTENT":
                continue
            patch, name = mm["patch"], mm["ko"]
            kd = rd / "keep" / patch
            (kd / "ref").mkdir(parents=True, exist_ok=True)
            subprocess.run(["cp", str(w / "ko" / name), str(kd)])
            for o in glob.glob(str(w / "ref" / patch / "*.o")):
                subprocess.run(["cp", o, str(kd / "ref")])
            if (w / "built" / name).exists():
                subprocess.run(["cp", str(w / "built" / name), str(kd)])
            rr = subprocess.run([VENV, ORA["v1.4"], str(w / "ko" / name),
                                 *glob.glob(str(w / "ref" / patch / "*.o"))],
                                capture_output=True, text=True)
            (kd / "v14.json").write_text(rr.stdout)
            log(f"  KEPT divergent {name} (v1.3={mm.get('v1.3')} v1.4={mm.get('v1.4')}) -> {kd}")
        # bound disk: drop the per-package build tree. Container writes /work as root,
        # so delete via a throwaway root container (host user cannot rm root-owned files).
        if not ONLY:
            subprocess.run(["docker", "run", "--rm", "-v", f"{WORK}:/work",
                            "s26-builder", "rm", "-rf", f"/work/{pkg}"])
    log("RUN complete")


if __name__ == "__main__":
    main()
