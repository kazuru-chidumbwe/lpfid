#!/usr/bin/env python3
"""S20 inputs for PS3: a vulnerable and a patched object per fix, both compiled the way the pin compiles them.

PS3 maps the diff to binary code through each object's DWARF line table. In a relocatable object built with
-ffunction-sections every function starts at address 0, so the ranges of different functions collide and PS3
finds no change site (first attempt, 8 Oct: signatures for 6 of 146 files; archived on the runtime host as
_invalid-run-s12-function-sections). Both objects are therefore built with the pin's own flags:
  vulnerable  every file touched by a selected fix, compiled from the release tarball tree, unpatched
  patched     per fix: the tree restored to the tarball, the fix applied with patch -p1, the touched files compiled
Output: /opt/atlas/s20/pair/<branch>/vuln/<path>.o and /opt/atlas/s20/pair/<branch>/patched/<cve>/<path>.o,
with status.json per branch.
Usage: nice -n 19 python3 s20objs.py [--branches 6.1,6.6,6.12]
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

S12 = Path("/opt/atlas/s12")
spec = importlib.util.spec_from_file_location("s12build", S12 / "s12build.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
OUT = Path("/opt/atlas/s20/pair")
WORKER = 9


def make(src: Path, objs: list[str], env: dict) -> dict[str, str | None]:
    out = {}
    for obj in objs:
        r = subprocess.run(["make", "-C", str(src), "-j4", obj], capture_output=True, text=True, env=env)
        out[obj] = None if r.returncode == 0 and (src / obj).exists() else (r.stderr or r.stdout)[-300:]
    return out


def main() -> int:
    args = sys.argv[1:]
    branches = (args[args.index("--branches") + 1] if "--branches" in args else "6.1,6.6,6.12").split(",")
    env = dict(os.environ, PATH=f"{B.gccbin('gcc-13')}:{os.environ['PATH']}")
    for br in branches:
        sel = json.loads((S12 / "out" / br / "selection.json").read_text())
        fixes = sel["main"] + sel["overcap"]
        files = sorted({f[:-2] + ".o" for e in fixes for f in e.get("files", [])})
        st = {"branch": br, "pin": B.PINS[br][0], "vuln": {}, "patched": {}}
        src = B.src_copy(WORKER, br)   # restored to the release tarball and verified
        for obj, err in make(src, files, env).items():
            if err is None:
                d = OUT / br / "vuln" / obj
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src / obj, d)
            st["vuln"][obj] = err or "ok"
        _, _, repo = B.PINS[br]
        for e in fixes:
            src = B.src_copy(WORKER, br)
            diff = subprocess.run(["git", "-C", str(repo), "show", "--format=", "--no-color", e["stable_sha"]],
                                  check=True, capture_output=True, text=True).stdout
            r = subprocess.run(["patch", "-p1", "--fuzz=2", "-d", str(src)], input=diff, capture_output=True, text=True)
            if r.returncode != 0:
                st["patched"][e["cve"]] = {"patch": r.stdout[-300:]}
                continue
            objs = sorted({f[:-2] + ".o" for f in e.get("files", [])})
            res = make(src, objs, env)
            for obj, err in res.items():
                if err is None:
                    d = OUT / br / "patched" / e["cve"] / obj
                    d.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src / obj, d)
            st["patched"][e["cve"]] = {o: (err or "ok") for o, err in res.items()}
        B.src_copy(WORKER, br)   # leave the tree as the tarball
        (OUT / br).mkdir(parents=True, exist_ok=True)
        (OUT / br / "status.json").write_text(json.dumps(st, indent=1))
        ok_v = sum(1 for v in st["vuln"].values() if v == "ok")
        ok_p = sum(1 for v in st["patched"].values() if isinstance(v, dict) and v and all(x == "ok" for x in v.values()))
        print(br, f"vuln {ok_v}/{len(files)}", f"patched fixes {ok_p}/{len(fixes)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
