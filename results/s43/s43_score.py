#!/usr/bin/env python3
"""S43 scorer (internal/S43-PREREG-2026-10-21.md): one package directory <out>/<pkg>/{ko,ref/<patch>,vmlinux?}.
Pairs every shipped module with the reference built from its own patch (S26 rule), scores the unmodified module with
oracle v2.0 (and v1.8 = v2.0 with its six new rules off, recorded beside it), then draws and scores the registered
mutants: at most ten sites per operator and module, seed "20261043:<pkg>/<module>:<op>", sites in functions the
oracle compares (module and reference both define them), scaffolding excluded. Mutants that are byte-identical to the
parent, duplicates, or in a registered equivalence class are set aside before scoring. Appends one JSON line.
usage: s43_score.py <oracle-v2.0.py> <lpfid-mutate.py> <pkg_dir> <results.jsonl>"""
import glob, hashlib, importlib.util, json, os, random, sys
from pathlib import Path

ORC_P, MU_P, PKG_DIR, RESULTS = sys.argv[1:5]
os.environ["LPFID_ORACLE"] = ORC_P
pkg = os.path.basename(PKG_DIR.rstrip("/"))
vml = os.path.join(PKG_DIR, "vmlinux")
vml = vml if os.path.exists(vml) else None
if vml:
    os.environ["LPFID_VMLINUX"] = vml


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ORC = load("orc20", ORC_P)
MU = load("mutate", MU_P)
BASE = set(ORC.DISABLED)
NEW = ("CLN", "RODN", "RBC", "RF2", "T1F", "P1F")
SCAFFOLD = {"init_module", "cleanup_module", "__pfx_init_module", "__pfx_cleanup_module"}
K = 10
OPS_COMMON = ["redirect1", "swap", "addend", "dropcall", "rodsec", "sibling"]
OPS_X86_VML = ["sympos", "clonerb-klp"]          # need the exact-build vmlinux
EQUIV = ("clone-indistinguishable", "sibling-indistinguishable")


def verdict(ko, refs, disabled=()):
    mod = ORC.Obj(Path(ko))
    robjs = [ORC.Obj(Path(p)) for p in refs]
    ORC.DISABLED.clear()
    ORC.DISABLED.update(BASE | set(disabled))
    d = ORC.compare(mod, robjs, None, vml, PKG_DIR if vml else None)
    out = {"overall": d["overall_verdict"], "sympos": d["sympos_verdict"], "funcs": d["functions_compared"],
           "compared": d["compared_functions"], "div": sorted(f["function"] for f in d["divergent_functions"]),
           "scaffold_div": [f["function"] for f in d.get("scaffolding_divergences", [])],
           "toolchain_inconclusive": d.get("toolchain_inconclusive_functions"),
           "sympos_findings": d.get("sympos_findings", [])[:5]}
    for o in [mod] + robjs:
        o.f.close()
    return out


def pair(stem):
    rd = os.path.join(PKG_DIR, "ref")
    for d in sorted(os.listdir(rd)) if os.path.isdir(rd) else []:
        if "livepatch-" + d.replace(".", "-").replace("&", "-") == stem:
            return d
    return None


rec = {"pkg": pkg, "has_vmlinux": bool(vml), "modules": []}
for ko in sorted(glob.glob(os.path.join(PKG_DIR, "ko", "*.ko"))):
    stem = os.path.basename(ko)[:-3]
    patch = pair(stem)
    refs = sorted(glob.glob(os.path.join(PKG_DIR, "ref", patch, "**", "*.o"), recursive=True)) if patch else []
    m = {"ko": stem, "patch": patch, "ref_n": len(refs)}
    if not refs:
        m["status"] = "NO_REF"
        rec["modules"].append(m)
        continue
    try:
        m["v20"] = verdict(ko, refs)
        m["v18"] = verdict(ko, refs, NEW)
    except Exception as e:  # noqa: BLE001
        m["status"] = f"ERROR {type(e).__name__}: {e}"[:300]
        rec["modules"].append(m)
        continue
    compared = set(m["v20"]["compared"]) - SCAFFOLD
    parent = Path(ko).read_bytes()
    is_a64 = MU.Mod(Path(ko)).aarch64
    ops = OPS_COMMON + ([] if is_a64 or not vml else OPS_X86_VML)
    mdir = Path(PKG_DIR) / "mut" / stem
    mdir.mkdir(parents=True, exist_ok=True)
    m["ops"] = {}
    for op in ops:
        try:
            sites = MU.sites(MU.Mod(Path(ko)), op)
        except SystemExit as e:
            m["ops"][op] = {"error": str(e)}
            continue
        if op == "sympos":   # position sites are klp symbols (other valid copies only, with the pin vmlinux)
            elig = list(range(len(sites)))
        else:
            elig = [i for i, s in enumerate(sites) if s.get("function") in compared and s.get("function") not in SCAFFOLD]
        pick = sorted(random.Random(f"20261043:{pkg}/{stem}:{op}").sample(elig, min(K, len(elig))))
        rows, seen = [], {}
        for i in pick:
            site = sites[i]
            row = {"site_index": i, "site": {k: v for k, v in site.items() if k not in ("insn_file_off",)}}
            if site.get("equivalent") in EQUIV:
                row["excluded"] = site["equivalent"]
                rows.append(row)
                continue
            mm = MU.Mod(Path(ko))
            try:
                MU.apply(mm, op, site)
            except SystemExit as e:
                row["excluded"] = f"apply-fail: {e}"
                rows.append(row)
                continue
            b = bytes(mm.data)
            h = hashlib.sha256(b).hexdigest()
            if b == parent:
                row["excluded"] = "noop"
            elif h in seen:
                row["excluded"] = f"duplicate of {seen[h]}"
            else:
                seen[h] = i
                p = mdir / f"{op}-{i}.ko"
                p.write_bytes(b)
                try:
                    row["v20"] = verdict(p, refs)
                    row["v18"] = verdict(p, refs, NEW)
                except Exception as e:  # noqa: BLE001
                    row["excluded"] = f"score-error {type(e).__name__}: {e}"[:200]
            rows.append(row)
        m["ops"][op] = {"sites": len(sites), "eligible": len(elig), "drawn": len(pick), "mutants": rows}
    rec["modules"].append(m)

with open(RESULTS, "a") as f:
    f.write(json.dumps(rec) + "\n")
print(pkg, "modules", len(rec["modules"]),
      "consistent", sum(1 for x in rec["modules"] if x.get("v20", {}).get("overall") == "CONSISTENT"))
