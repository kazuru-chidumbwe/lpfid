#!/usr/bin/env python3
"""S21 sweep scoring (TODO item 7b): frozen oracle v1 and frozen v1.1 side by side on one build set.

Held-out set for v1.1 (S16 Deviation 1): no module scored here was seen by either oracle before.
For each built module of RESULTS/<kver>-<gcc>/<branch>/<cve>:
  rkp          v1 and v1.1 on module vs kpatch's patched objects + patch-hook.o, P1 against the pin vmlinux
  ctl_wrong    other fix's references without patch-hook.o (S12-PREREG Deviation 5); must NOT be CONSISTENT
  ctl_noop     byte copy through the mutation write path; must be byte-identical and reproduce the verdict
  same_as_s12  module bytes equal to the S12 (v0.9.11, same gcc) module of the same fix
A module is scored for a version when both controls pass for that version and the run has no error.

Both oracle files are checked against their S16 frozen hashes before any run.
Usage: nice -n 19 python3 s21oracle.py KVER GCC [--workers 2] [--branches 6.1,6.6,6.12] [--reference kp|ind]
       writes /opt/atlas/s12/oracle/s21-<kver>-<gcc>[-<branches>].json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

A = Path("/opt/atlas")
C = A / "livepatch-corpus"
RESULTS = A / "s12/results"
OUT = A / "s12/oracle"
ORACLES = {
    "v1": (["python3"], A / "lpfid/blind-reloc-oracle.py",
           "7d79c9d941c2bc7c11750fe5dd6e16e5afddefe6e84c16bd275b46d0667b843c"),
    "v1.1": ([str(A / "venvs/lpfid-oracle-v11/bin/python")], A / "lpfid/blind-reloc-oracle-v1.1.py",
             "5139e049aa6fc4a1ca1c6641595a9fdd802e7e11d6de058d702cbc7d898d0add"),
}
V12 = (A / "lpfid/blind-reloc-oracle-v1.2.py", "b7731376aac630e0809f643a8d80670ee7d34cdcade323eac8ec5657250e9a3e")
V12_VALIDATION = A / "lpfid/oracle-v12-validation.json"


def gate_v12() -> str:
    """S16 Deviation 2: v1.2 scores held-out modules only once its validation has finished and passed.
    Waits for the validation output; adds v1.2 when it passed, otherwise scores with v1 and v1.1 only."""
    import time
    while not V12_VALIDATION.exists():
        time.sleep(60)
    time.sleep(5)
    ok = json.loads(V12_VALIDATION.read_text())["summary"].get("pass") is True
    if ok:
        ORACLES["v1.2"] = ([str(A / "venvs/lpfid-oracle-v11/bin/python")], V12[0], V12[1])
    return "v1.2 validated, included" if ok else "v1.2 validation failed, not used"


PINS = {"6.1": ("6.1.119", C / "linux-second-pin"), "6.6": ("6.6.47", C / "pilot-work/linux"),
        "6.12": ("6.12.51", C / "linux-6.12.51"), "5.15": ("5.15.173", C / "linux-5.15.173"),
        "6.19": ("6.19", C / "linux-6.19")}  # S11-PREREG Deviation 1 (was 6.19.14)


def tree_of(branch: str, gcc: str) -> Path:
    t = PINS[branch][1]
    return t if gcc == "gcc-13" else t.with_name(t.name + "-" + gcc.replace("-", ""))


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def refs_of(d: Path, hook: bool = True) -> list[str]:
    refs = [str(x) for x in sorted((d / "build" / "patched").rglob("*.o"))] if (d / "build" / "patched").exists() else []
    if not refs:
        refs = [str(x) for x in sorted((d / "patched").rglob("*.o"))] if (d / "patched").exists() else []
    if hook:
        for h in (d / "build" / "patch-hook.o", d / "patch-hook.o"):
            if h.exists():
                refs.append(str(h))
                break
    return refs


def oracle(ver: str, ko: str, refs: list[str], tree: Path) -> dict:
    py, path, _ = ORACLES[ver]
    r = subprocess.run([*py, str(path), ko, *refs, "--vmlinux", str(tree / "vmlinux"),
                        "--modules-dir", str(tree)], capture_output=True, text=True)
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"error": (r.stderr or r.stdout)[-400:]}
    return {"overall": d["overall_verdict"], "multiset": d["multiset_verdict"], "sequence": d["sequence_verdict"],
            "sympos": d["sympos_verdict"], "divergent": d["divergent_functions"]}


REF = "kp"   # "kp": the generator's own patched objects (+ patch-hook.o); "ind": the S22 independent compile


def ind_refs(branch: str, cve: str, gcc: str) -> list[str]:
    if REF == "dev":   # S3: the same compile on the runtime host's toolchain (Debian gcc 13.3.0-16)
        d = A / "s3/refs-devnode" / branch / cve
    else:
        d = A / "s12" / ("refs-independent" if gcc == "gcc-13" else f"refs-independent-{gcc}") / branch / cve
    st = d / "status.json"
    if not st.exists() or not json.loads(st.read_text()).get("ok"):
        return []
    return [str(x) for x in sorted(d.rglob("*.o"))]


def subjects(res: Path, gcc: str, branches: list[str]) -> list[dict]:
    subj = []
    for br in branches:
        for st in sorted((res / br).glob("*/status.json")):
            s = json.loads(st.read_text())
            d = st.parent
            kos = sorted((d / "build").glob("*.ko"))
            if not s.get("ok") or not kos:
                continue
            s12 = sorted((RESULTS / f"v0.9.11-{gcc}" / br / s["cve"] / "build").glob("*.ko"))
            subj.append({"branch": br, "pin": PINS[br][0], "cve": s["cve"], "set": s.get("set"),
                         "type": s.get("type"), "module": str(kos[0]), "module_sha256": sha(kos[0]),
                         "same_as_s12": bool(s12) and sha(s12[0]) == sha(kos[0]),
                         "dir": str(d),
                         "refs": refs_of(d) if REF == "kp" else ind_refs(br, s["cve"], gcc),
                         "refs_nohook": refs_of(d, hook=False) if REF == "kp" else ind_refs(br, s["cve"], gcc)})
    for br in branches:
        same = [x for x in subj if x["branch"] == br]
        for i, x in enumerate(same):
            other = same[(i + 1) % len(same)] if len(same) > 1 else None
            x["wrong_ref_cve"] = other["cve"] if other else None
            x["wrong_refs"] = other["refs_nohook"] if other else []
    return subj


def evaluate(x: dict, gcc: str, tag: str) -> dict:
    tree = tree_of(x["branch"], gcc)
    row = {k: v for k, v in x.items() if k not in ("wrong_refs", "refs_nohook")}
    if not x["refs"]:
        return {**row, "error": "no reference objects" + (" (S22 build failed or missing)" if REF == "ind" else "")}
    noop_dir = OUT / f"noop-{tag}" / x["branch"] / x["cve"]
    noop_dir.mkdir(parents=True, exist_ok=True)
    noop = noop_dir / Path(x["module"]).name
    noop.write_bytes(Path(x["module"]).read_bytes())
    identical = sha(noop) == x["module_sha256"]
    for ver in ORACLES:
        v = oracle(ver, x["module"], x["refs"], tree)
        wr = oracle(ver, x["module"], x["wrong_refs"], tree) if x["wrong_refs"] else {"error": "no other fix"}
        nv = oracle(ver, str(noop), x["refs"], tree)
        cw = {"verdict": wr.get("overall"), "pass": wr.get("overall") not in (None, "CONSISTENT")}
        cn = {"verdict": nv.get("overall"), "identical_bytes": identical,
              "pass": identical and nv.get("overall") == v.get("overall") and "error" not in v}
        row[ver] = {**v, "ctl_wrong": cw, "ctl_noop": cn,
                    "scored": cw["pass"] and cn["pass"] and "error" not in v}
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kver")
    ap.add_argument("gcc")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--branches", default="6.1,6.6,6.12")
    ap.add_argument("--reference", choices=["kp", "ind", "dev"], default="kp")
    a = ap.parse_args()
    v12_note = gate_v12()
    for ver, (_, path, frozen) in ORACLES.items():
        if sha(path) != frozen:
            print(f"{ver} oracle hash is not the frozen {frozen}", file=sys.stderr)
            return 2
    global REF
    REF = a.reference
    branches = a.branches.split(",")
    tag = f"{a.kver}-{a.gcc}"
    res = RESULTS / tag
    jobs = [j for j in sorted(res.glob("*/*/status.json")) if j.parent.parent.name in branches]
    subj = subjects(res, a.gcc, branches)
    if a.branches != "6.1,6.6,6.12":
        tag = f"{tag}-{a.branches.replace(',', '_')}"
    if REF == "ind":
        tag += "-rind"
    if REF == "dev":
        tag += "-rdev-t1" + os.environ.get("LPFID_T1", "strict")
    OUT.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = list(ex.map(lambda x: evaluate(x, a.gcc, tag), subj))
    shutil.rmtree(OUT / f"noop-{tag}", ignore_errors=True)

    def count(rs, key):
        return dict(Counter(key(r) for r in rs))
    summary = {"set": tag, "branches": branches, "v1.2": v12_note, "jobs": len(jobs), "built": len(subj),
               "oracle_sha256": {v: o[2] for v, o in ORACLES.items()},
               "reference": "R-kp (generator's patched objects + patch-hook.o)" if REF == "kp"
               else "R-ind (S22 independent compile, plain make, one section per function)",
               "same_as_s12": sum(1 for r in rows if r.get("same_as_s12")),
               "errors": [f"{r['branch']}/{r['cve']}: {r['error']}" for r in rows if "error" in r]}
    for ver in ORACLES:
        ok = [r for r in rows if ver in r and "error" not in r[ver]]
        sc = [r for r in ok if r[ver]["scored"]]
        summary[ver] = {
            "ran": len(ok), "scored": len(sc),
            "not_scored": [f"{r['branch']}/{r['cve']} wrong={r[ver]['ctl_wrong']['verdict']} "
                           f"noop={r[ver]['ctl_noop']['pass']}" for r in ok if not r[ver]["scored"]],
            "overall": count(sc, lambda r: r[ver]["overall"]),
            "sequence": count(sc, lambda r: r[ver]["sequence"]),
            "multiset": count(sc, lambda r: r[ver]["multiset"]),
            "sympos": count(sc, lambda r: r[ver]["sympos"]),
            "overall_by_branch": count(sc, lambda r: f"{r['branch']} {r[ver]['overall']}"),
            "alarms": [f"{r['branch']}/{r['cve']} {r[ver]['overall']}" for r in sc
                       if r[ver]["overall"] != "CONSISTENT"],
        }
    both = [r for r in rows if all(v in r and r[v].get("scored") for v in ORACLES)]
    summary["changed_v1_to_v11"] = [f"{r['branch']}/{r['cve']}: {r['v1']['overall']} -> {r['v1.1']['overall']}"
                                    for r in both if r["v1"]["overall"] != r["v1.1"]["overall"]]
    if "v1.2" in ORACLES:
        both12 = [r for r in rows if all(v in r and r[v].get("scored") for v in ("v1.1", "v1.2"))]
        summary["changed_v11_to_v12"] = [f"{r['branch']}/{r['cve']}: {r['v1.1']['overall']} -> {r['v1.2']['overall']}"
                                         for r in both12 if r["v1.1"]["overall"] != r["v1.2"]["overall"]]
    (OUT / f"s21-{tag}.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
