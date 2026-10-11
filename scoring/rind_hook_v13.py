#!/usr/bin/env python3
"""Rescore every R-ind and R-dev set with oracle v1.3, with the reference set as scored and with the generator's
scaffolding object patch-hook.o added (S16 Deviation 3 addendum). patch-hook.o is taken from the module's own
build directory, where the generator left it. Writes /opt/atlas/s12/oracle/rind-hook-v13.json.
Usage (build host): nice -n 19 python3 rind_hook_v13.py [--workers 6]
"""
import argparse
import glob
import json
import os
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

A = Path("/opt/atlas")
PY = A / "venvs/lpfid-oracle-v11/bin/python"
V13 = A / "lpfid/blind-reloc-oracle-v1.3.py"
C = A / "livepatch-corpus"
PINS = {"6.1": C / "linux-second-pin", "6.6": C / "pilot-work/linux", "6.12": C / "linux-6.12.51",
        "5.15": C / "linux-5.15.173", "6.19": C / "linux-6.19"}


def run(ko, refs, tree, t1):
    env = dict(os.environ, LPFID_DISABLE="")
    if t1:
        env["LPFID_T1"] = t1
    r = subprocess.run([str(PY), str(V13), ko, *refs, "--vmlinux", str(tree / "vmlinux"), "--modules-dir", str(tree)],
                       capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)["overall_verdict"]
    except Exception:
        return "ERROR"


def jobs():
    out = []
    for f in sorted(glob.glob(str(A / "s12/oracle/s21-*-rind.json")) + glob.glob(str(A / "s12/oracle/s21-*-rdev-*.json"))):
        name = Path(f).stem
        gcc14 = "gcc-14" in name
        t1 = "version" if "t1version" in name else None
        for r in json.loads(Path(f).read_text())["rows"]:
            if not (r.get("v1.2") or {}).get("scored"):
                continue
            tree = PINS[r["branch"]]
            if gcc14:
                tree = tree.with_name(tree.name + "-gcc14")
            hook = str(Path(r["dir"]) / "patch-hook.o")
            out.append({"set": name, "id": f"{r['branch']}/{r['cve']}", "ko": r["module"], "refs": r["refs"],
                        "hook": hook if os.path.exists(hook) else None, "tree": tree, "t1": t1, "v12": r["v1.2"]["overall"]})
    return out


def one(j):
    a = run(j["ko"], j["refs"], j["tree"], j["t1"])
    b = run(j["ko"], j["refs"] + [j["hook"]], j["tree"], j["t1"]) if j["hook"] else "NO_HOOK"
    return {"set": j["set"], "id": j["id"], "v12": j["v12"], "v13": a, "v13_hook": b}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    js = jobs()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = list(ex.map(one, js))
    summ = {}
    for s in sorted({r["set"] for r in rows}):
        rs = [r for r in rows if r["set"] == s]
        summ[s] = {"n": len(rs), "v12": dict(Counter(r["v12"] for r in rs)), "v13": dict(Counter(r["v13"] for r in rs)),
                   "v13_hook": dict(Counter(r["v13_hook"] for r in rs)),
                   "changed_by_hook": [f"{r['id']}: {r['v13']} -> {r['v13_hook']}" for r in rs if r["v13"] != r["v13_hook"]]}
    (A / "s12/oracle/rind-hook-v13.json").write_text(json.dumps({"summary": summ, "rows": rows}, indent=1))
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
