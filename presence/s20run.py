#!/usr/bin/env python3
"""S20: PS3 patch presence test on S12 fixes (runtime host; PS3 venv, angr 9.2.36).

Per built S12 fix and per touched file f (diff split per file; PS3 takes one object pair):
  signatures  from PAIR/<branch>/vuln/<f>.o and PAIR/<branch>/patched/<cve>/<f>.o, both compiled with the
              pin's own flags (s20objs.py; PS3 cannot map lines in -ffunction-sections objects)
  targets     control-vuln   vuln object            must be reported "vuln"
              control-patch  patched object         must be reported "patch"
              module         the livepatch module, SHN_LIVEPATCH symbols set to UNDEF (ko_for_angr.py)
              extra          optional targets from --targets JSON {"<branch>/<cve>": [[id, path], ...]},
                             each adapted the same way (S2 mutants)
A fix is supported when, for every file with signatures, both controls give the expected result.
Each PS3 call has a 900 s limit. Output: one JSON row per fix in OUT/rows/, summary OUT/s20.json.
Usage (from /opt/atlas/tools/ps3/ps3, with its venv):
  python s20run.py EVAL_RESULTS PAIR_DIR OUT [--workers 3] [--targets t.json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
PS3_ONE = Path("/opt/atlas/tools/ps3/ps3/ps3_one.py")
ADAPT = Path("/opt/atlas/s20/ko_for_angr.py")
PY = sys.executable


def split_diff(diff: str) -> dict[str, str]:
    files, cur, buf = {}, None, []
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if cur:
                files[cur] = "\n".join(buf) + "\n"
            cur, buf = line.split(" b/", 1)[1], []
        buf.append(line)
    if cur:
        files[cur] = "\n".join(buf) + "\n"
    return files


def adapt(src: str, dst: Path) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([PY, str(ADAPT), src, str(dst)], check=True, capture_output=True, text=True)
    return str(dst)


def ps3(vuln: str, patched: str, diff: str, targets: list[str]) -> dict:
    try:
        r = subprocess.run([PY, str(PS3_ONE), vuln, patched, diff, *targets], capture_output=True, text=True,
                           timeout=900, cwd=str(PS3_ONE.parent))
    except subprocess.TimeoutExpired:
        return {"error": "timeout 900 s"}
    lines = [json.loads(l) for l in r.stdout.splitlines() if l.startswith("{")]
    sig = next((l for l in lines if l.get("stage") == "signature"), {"error": (r.stderr or "")[-300:]})
    res = {l["target"]: l.get("result", "ERROR " + l.get("error", "")) for l in lines if "target" in l}
    return {"signature": sig, "results": res}


def one(job: dict) -> dict:
    out, row = Path(job["out"]), {k: job[k] for k in ("branch", "cve")}
    rowf = out / "rows" / f"{job['branch']}__{job['cve']}.json"
    if rowf.exists():
        return json.loads(rowf.read_text())
    d = Path(job["dir"])
    work = out / "work" / f"{job['branch']}__{job['cve']}"
    work.mkdir(parents=True, exist_ok=True)
    module = adapt(job["module"], work / "module.ko")
    extra = [(i, adapt(p, work / f"x-{n}.ko")) for n, (i, p) in enumerate(job.get("extra", []))]
    row["files"] = {}
    supported_files = []
    for path, diff in split_diff((d / "fix.patch").read_text(errors="replace")).items():
        obj = path[:-2] + ".o"
        vuln = Path(job["vuln_dir"]) / job["branch"] / "vuln" / obj
        patched = Path(job["vuln_dir"]) / job["branch"] / "patched" / job["cve"] / obj
        if not vuln.exists() or not patched.exists():
            row["files"][obj] = {"skipped": f"missing {'vuln' if not vuln.exists() else 'patched'} object"}
            continue
        df = work / (obj.replace("/", "__") + ".diff")
        df.write_text(diff)
        targets = [str(vuln), str(patched), module] + [p for _, p in extra]
        r = ps3(str(vuln), str(patched), str(df), targets)
        res = r.get("results", {})
        f = {"signature": r.get("signature"), "error": r.get("error"),
             "control_vuln": res.get(str(vuln)), "control_patch": res.get(str(patched)),
             "module": res.get(module), "extra": {i: res.get(p) for i, p in extra}}
        f["has_signatures"] = bool(r.get("signature", {}).get("signature_functions"))
        f["controls_pass"] = f["control_vuln"] == "vuln" and f["control_patch"] == "patch"
        row["files"][obj] = f
        if f["has_signatures"]:
            supported_files.append(f["controls_pass"])
    row["supported"] = bool(supported_files) and all(supported_files)
    rowf.parent.mkdir(parents=True, exist_ok=True)
    rowf.write_text(json.dumps(row, indent=1))
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("vuln_dir")
    ap.add_argument("out")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--targets")
    a = ap.parse_args()
    extra = json.loads(Path(a.targets).read_text()) if a.targets else {}
    jobs = []
    for st in sorted(glob.glob(f"{a.results}/*/*/status.json")):
        s = json.loads(Path(st).read_text())
        kos = sorted(glob.glob(os.path.join(os.path.dirname(st), "build", "*.ko")))
        if not s.get("ok") or not kos:
            continue
        key = f"{s['branch']}/{s['cve']}"
        jobs.append({"branch": s["branch"], "cve": s["cve"], "dir": os.path.dirname(st), "module": kos[0],
                     "vuln_dir": a.vuln_dir, "out": a.out, "extra": extra.get(key, [])})
    with ProcessPoolExecutor(a.workers) as ex:
        rows = list(ex.map(one, jobs))
    sup = [r for r in rows if r["supported"]]
    mod = [f["module"] for r in sup for f in r["files"].values() if f.get("has_signatures")]
    summary = {"fixes": len(rows), "supported": len(sup),
               "supported_by_branch": {b: sum(1 for r in sup if r["branch"] == b) for b in sorted({r["branch"] for r in rows})},
               "no_signatures": sum(1 for r in rows if not any(f.get("has_signatures") for f in r["files"].values())),
               "control_failures": sum(1 for r in rows for f in r["files"].values()
                                       if f.get("has_signatures") and not f.get("controls_pass")),
               "module_on_supported": {v: mod.count(v) for v in sorted(set(map(str, mod)))}}
    Path(a.out, "s20.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
