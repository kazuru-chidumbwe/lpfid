#!/usr/bin/env python3
"""S2: operator mutants on the S12 real-fix modules and the fixture corpus (TODO item 8; S2-PREREG-2026-10-08).

Subjects
  s12       the 123 built S12 modules (kpatch v0.9.11, gcc-13), reference R-kp, P1 against the pin vmlinux
  fixtures  the 78 fixture goods of the S16 recheck (goods-recheck.json), their own references
Operators (pilot/scripts/lpfid-mutate.py, frozen hash below; imported, not re-run per mutant)
  swap, addend, sympos (vmlinux-guided), dropcall, constant; redirect by the S1 rule
  (callee i -> callee i+1, applied with perturb-plt32-redirect.py)
Site rules (fixed before any S2 mutant is scored)
  - a site whose function is defined in the module's kpatch scaffolding (patch-hook.o functions) is excluded;
    a site with no enclosing function is excluded (redirect sites carry no function and are kept)
  - per module and operator, up to K=10 sites drawn with random.Random(f"20261008:{subject}:{op}")
  - inside-hunk: the site's function (suffixes .cold/.part.N/.isra.N/.constprop.N removed) is a function the
    fix's diff changes (S12 selection.json "functions"); outside-hunk otherwise; "n/a" for redirect and fixtures
Mutant quality
  - noop: mutant bytes equal the parent -> discarded, counted
  - sympos-equivalent sites: counted per module, never mutated
  - duplicate: mutant bytes equal an earlier mutant of the same parent -> counted once (dedup), both reported
Oracles: frozen v1 (system python) and frozen v1.1 (venv python), both hashes checked first.
Detected = overall verdict DIVERGENT or LOAD_FAIL. Mutants are kept under /opt/atlas/s2/mut for the
baseline runner (runtime host).
Usage: nice -n 19 /opt/atlas/venvs/lpfid-oracle-v11/bin/python s2run.py [--workers 3] [--subjects s12,fixtures]
       writes /opt/atlas/s2/s2-<subjects>.json
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import json
import random
import re
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

A = Path("/opt/atlas")
C = A / "livepatch-corpus"
S2 = A / "s2"
MUT = S2 / "mut"
RES = A / "s12/results/v0.9.11-gcc-13"
MUTATE = A / "lpfid/lpfid-mutate.py"
PERTURB = A / "repos/livepatch-differential-harness/pilot/scripts/perturb-plt32-redirect.py"
V11PY = A / "venvs/lpfid-oracle-v11/bin/python"
ORACLES = {
    "v1": ("python3", A / "lpfid/blind-reloc-oracle.py",
           "7d79c9d941c2bc7c11750fe5dd6e16e5afddefe6e84c16bd275b46d0667b843c"),
    "v1.1": (str(V11PY), A / "lpfid/blind-reloc-oracle-v1.1.py",
             "5139e049aa6fc4a1ca1c6641595a9fdd802e7e11d6de058d702cbc7d898d0add"),
}
FROZEN = {MUTATE: "258d0da5a40144e6aa3a19b565e988fed967a93ed29edc98ef39acb9da986bf4",
          PERTURB: "8b57d886b5e06bf48db751f74ee48ec96546848fa3ced758e88acf43c844eed2"}
OPS = ["redirect", "swap", "addend", "sympos", "dropcall", "constant"]
K = 10
S12_TREES = {"6.1": C / "linux-second-pin", "6.6": C / "pilot-work/linux", "6.12": C / "linux-6.12.51"}
FIX_TREES = {"5.16.10": C / "linux-dirtypipe", "6.1.119": C / "linux-second-pin", "6.6.47": C / "pilot-work/linux"}
SUFFIX = re.compile(r"\.(cold|part\.\d+|isra\.\d+|constprop\.\d+|llvm\.\d+)$")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load_mutate():
    spec = importlib.util.spec_from_file_location("lpfid_mutate", MUTATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    real = m.oracle_module()
    cached = functools.lru_cache(maxsize=8)(real.symbol_index)

    class O:
        symbol_index = staticmethod(cached)
    m.oracle_module = lambda: O
    return m


M = None
ENV_LOCK = __import__('threading').Lock()


def sites_for(mod, op: str, vmlinux: Path) -> list[dict]:
    """lpfid-mutate reads LPFID_VMLINUX from the environment; workers use different pins, so serialise."""
    import os
    with ENV_LOCK:
        os.environ["LPFID_VMLINUX"] = str(vmlinux)
        return M.sites(mod, op)


def hook_functions(hook: Path | None) -> set[str]:
    if not hook or not hook.exists():
        return set()
    out = subprocess.run(["readelf", "-sW", str(hook)], capture_output=True, text=True).stdout
    return {l.split()[-1] for l in out.splitlines() if " FUNC " in l and len(l.split()) >= 8}


def base_name(fn: str | None) -> str | None:
    if not fn:
        return None
    while SUFFIX.search(fn):
        fn = SUFFIX.sub("", fn)
    return fn


def oracle(ver: str, ko: str, refs: list[str], tree: Path) -> dict:
    py, path, _ = ORACLES[ver]
    r = subprocess.run([py, str(path), ko, *refs, "--vmlinux", str(tree / "vmlinux"), "--modules-dir", str(tree)],
                       capture_output=True, text=True)
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"error": (r.stderr or r.stdout)[-300:]}
    return {"overall": d["overall_verdict"], "multiset": d["multiset_verdict"], "sequence": d["sequence_verdict"],
            "sympos": d["sympos_verdict"]}


def subjects(which: list[str]) -> list[dict]:
    subj = []
    if "s12" in which:
        changed = {}
        for br in S12_TREES:
            sel = json.loads((A / "s12/out" / br / "selection.json").read_text())
            for e in sel["main"] + sel["overcap"]:
                changed[(br, e["cve"])] = {f.split(":", 1)[1] for f in e.get("functions", [])}
        for br, tree in S12_TREES.items():
            for st in sorted((RES / br).glob("*/status.json")):
                s = json.loads(st.read_text())
                kos = sorted((st.parent / "build").glob("*.ko"))
                if not s.get("ok") or not kos:
                    continue
                d = st.parent
                refs = [str(x) for x in sorted((d / "patched").rglob("*.o"))]
                hook = d / "patch-hook.o"
                if hook.exists():
                    refs.append(str(hook))
                subj.append({"set": "s12", "id": f"{br}/{s['cve']}", "module": str(kos[0]), "refs": refs,
                             "tree": str(tree), "hook": str(hook) if hook.exists() else None,
                             "changed": sorted(changed.get((br, s["cve"]), set()))})
    if "fixtures" in which:
        goods = json.loads((A / "lpfid-fixtures/goods-recheck.json").read_text())["rows"]
        for g in goods:
            hook = next((r for r in g["refs"] if r.endswith("patch-hook.o")), None)
            subj.append({"set": "fixtures", "id": f"{g['pin']}/{g['kind']}/{g['name']}", "module": g["module"],
                         "refs": g["refs"], "tree": str(FIX_TREES[g["pin"]]), "hook": hook, "changed": None})
    return subj


def plt32_callees(ko: Path) -> list[str]:  # S1 rule, identical to lab/fixtures/s1mutants.py
    out = subprocess.run(["readelf", "-rW", str(ko)], capture_output=True, text=True).stdout
    cs: list[str] = []
    for line in out.splitlines():
        if "R_X86_64_PLT32" in line:
            m = re.search(r"R_X86_64_PLT32\s+\S+\s+(\S+)", line)
            if m:
                s = m.group(1).split("-")[0].split("+")[0].strip()
                if s and s not in cs:
                    cs.append(s)
    return cs


def run_subject(x: dict) -> dict:
    parent = Path(x["module"])
    tree = Path(x["tree"])
    vml = tree / "vmlinux"
    pbytes = parent.read_bytes()
    hooks = hook_functions(Path(x["hook"])) if x["hook"] else set()
    changed = set(x["changed"]) if x["changed"] is not None else None
    out_dir = MUT / x["set"] / x["id"].replace("/", "__")
    out_dir.mkdir(parents=True, exist_ok=True)
    seen: dict[str, str] = {}
    rows, counts = [], {}
    base = M.Mod(parent)
    counts["sympos_equivalent_sites"] = len(sites_for(base, "sympos-equivalent", vml))
    for op in OPS:
        if op == "redirect":
            cs = plt32_callees(parent)
            all_sites = [{"src": s, "dst": cs[(i + 1) % len(cs)]} for i, s in enumerate(cs)] if len(cs) > 1 else []
            elig = list(range(len(all_sites)))
        else:
            all_sites = sites_for(M.Mod(parent), op, vml)
            elig = [i for i, s in enumerate(all_sites)
                    if s.get("function") or op == "sympos"]
            elig = [i for i in elig if all_sites[i].get("function") not in hooks]
        pick = sorted(random.Random(f"20261008:{x['id']}:{op}").sample(elig, min(K, len(elig))))
        counts[op] = {"sites": len(all_sites), "eligible": len(elig), "drawn": len(pick)}
        for i in pick:
            site = all_sites[i]
            dst = out_dir / f"{op}-{i}.ko"
            if op == "redirect":
                r = subprocess.run(["python3", str(PERTURB), str(parent), str(dst), site["src"], site["dst"]],
                                   capture_output=True, text=True)
                if r.returncode != 0 or not dst.exists():
                    rows.append({"op": op, "site_index": i, "site": site, "built": False,
                                 "note": (r.stderr or r.stdout)[-160:]})
                    continue
            else:
                try:
                    m = M.Mod(parent)
                    M.apply(m, op, site)
                    dst.write_bytes(bytes(m.data))
                except Exception as e:  # noqa: BLE001 - recorded, not hidden
                    rows.append({"op": op, "site_index": i, "site": site, "built": False, "note": repr(e)[-160:]})
                    continue
            mb = dst.read_bytes()
            h = hashlib.sha256(mb).hexdigest()
            fn = base_name(site.get("function"))
            hunk = "n/a" if changed is None or op in ("redirect", "sympos") else (
                "inside" if fn in changed else "outside")
            row = {"op": op, "site_index": i, "site": site, "built": True, "sha256": h, "path": str(dst),
                   "noop": mb == pbytes, "duplicate_of": seen.get(h), "hunk": hunk}
            seen.setdefault(h, f"{op}-{i}")
            if not row["noop"] and not row["duplicate_of"]:
                for ver in ORACLES:
                    row[ver] = oracle(ver, str(dst), x["refs"], tree)
            rows.append(row)
    return {"set": x["set"], "id": x["id"], "module_sha256": hashlib.sha256(pbytes).hexdigest(),
            "hook_functions": len(hooks), "counts": counts, "mutants": rows}


def detected(v: dict) -> bool:
    return v.get("overall") in ("DIVERGENT", "LOAD_FAIL")


def main() -> int:
    global M
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--subjects", default="s12,fixtures")
    a = ap.parse_args()
    for p, h in {**FROZEN, **{o[1]: o[2] for o in ORACLES.values()}}.items():
        if sha(p) != h:
            print(f"{p}: hash {sha(p)} is not the frozen {h}", file=sys.stderr)
            return 2
    M = load_mutate()
    which = a.subjects.split(",")
    subj = subjects(which)
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        res = list(ex.map(run_subject, subj))
    summary: dict = {"subjects": Counter(r["set"] for r in res), "K": K,
                     "hashes": {**{p.name: h for p, h in FROZEN.items()}, **{v: o[2] for v, o in ORACLES.items()}}}
    for s in which:
        rs = [r for r in res if r["set"] == s]
        muts = [m for r in rs for m in r["mutants"]]
        built = [m for m in muts if m["built"]]
        scored = [m for m in built if not m["noop"] and not m["duplicate_of"]]
        per = {}
        for op in OPS:
            ms = [m for m in scored if m["op"] == op]
            raw = [m for m in built if m["op"] == op and not m["noop"]]
            per[op] = {"drawn": sum(r["counts"][op]["drawn"] for r in rs),
                       "build_fail": sum(1 for m in muts if m["op"] == op and not m["built"]),
                       "noop": sum(1 for m in built if m["op"] == op and m["noop"]),
                       "duplicates": sum(1 for m in built if m["op"] == op and m["duplicate_of"]),
                       "scored_dedup": len(ms), "scored_raw": len(raw)}
            for ver in ORACLES:
                ok = [m for m in ms if "error" not in m[ver]]
                per[op][ver] = {"errors": len(ms) - len(ok), "detected": sum(detected(m[ver]) for m in ok),
                                "multiset_div": sum(m[ver]["multiset"] == "DIVERGENT" for m in ok),
                                "sequence_div": sum(m[ver]["sequence"] == "DIVERGENT" for m in ok),
                                "by_hunk": {h: f"{sum(detected(m[ver]) for m in ok if m['hunk'] == h)}/"
                                               f"{sum(1 for m in ok if m['hunk'] == h)}"
                                            for h in sorted({m["hunk"] for m in ok})},
                                "overall": dict(Counter(m[ver]["overall"] for m in ok))}
        summary[s] = {"modules": len(rs), "sympos_equivalent_sites": sum(r["counts"]["sympos_equivalent_sites"] for r in rs),
                      "per_operator": per,
                      "v1_v11_disagree": [f"{r['id']} {m['op']}-{m['site_index']}: {m['v1'].get('overall')} vs "
                                          f"{m['v1.1'].get('overall')}" for r in rs for m in r["mutants"]
                                          if "v1" in m and m["v1"].get("overall") != m["v1.1"].get("overall")]}
    tag = "-".join(which)
    (S2 / f"s2-{tag}.json").write_text(json.dumps({"summary": summary, "rows": res}, indent=1, default=list))
    print(json.dumps(summary, indent=1, default=list))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
