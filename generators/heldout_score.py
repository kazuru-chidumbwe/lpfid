#!/usr/bin/env python3
"""S16 Deviation 4: score the held-out klp-build set H (s11_heldout.py) with oracle v1.3 and v1.4 against R-ind.

Labels (oracle-free, pyelftools only): for every function defined in both the stock and the fixed-objtool module of a
fix, the relocations in its code that point into a .rodata* section are taken in offset order, and each target is
read as a C string (up to NUL). The stock module is FAULTY when a pair reaches different bytes or the two lists
differ in length, otherwise CLEAN. Fixed-objtool modules are CLEAN for this fault class.
Mutants: for each fixed-objtool module, one mutant per .rodata relocation in a patched function, r_addend + 1
(the target moves one byte into its string); a mutant whose target bytes do not change is reported as equivalent.
These two measure consistency only (RC and the label test the same property; S16 Deviation 4 amendment).
Operator mutants (amendment, non-masking check): the registered S2 generator (lab/s2/s2run.py run_subject: K=10 sites
per operator, random.Random(f"20261008:{id}:{op}"), no-op and duplicate mutants removed) with operators redirect,
swap, addend, sympos, dropcall on every fixed-objtool module; pass when v1.4 detects every mutant v1.3 detects.
Usage (build host, oracle venv): s11_heldout_score.py [--workers 6]
Writes /opt/atlas/s12/oracle/s11-heldout-score.json.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import struct
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

A = Path("/opt/atlas")
S12 = A / "s12"
PY = A / "venvs/lpfid-oracle-v11/bin/python"
ORACLES = {"v1.3": A / "lpfid/blind-reloc-oracle-v1.3.py", "v1.4": A / "lpfid/blind-reloc-oracle-v1.4.py"}
SHA = {"v1.3": "c6add9ab14d994cf6d7920ff6d6820840c9fa554001727865990957b9e200133",
       "v1.4": "b6496d03866701c15d71366d7322f8d5b7f2ee71e1bb2b5394054099d1d0ed29"}
TREE = A / "livepatch-corpus/linux-6.19"
H = S12 / "s11-heldout"
IND = S12 / "refs-independent-heldout/6.19"
MUT = S12 / "s11-heldout-mutants"
OPMUT = S12 / "s11-heldout-opmutants"
MUTATE = A / "lpfid/lpfid-mutate.py"
OPS = ("redirect", "swap", "addend", "sympos", "dropcall")  # S2 operators; constant changes no relocation
DET = {"DIVERGENT", "LOAD_FAIL"}


def rodata_rows(path: Path) -> dict[str, list[tuple]]:
    """function -> [(offset in function, rela section index, entry index, target section, target pos, C string)]."""
    e = ELFFile(open(path, "rb"))
    syms = list(e.get_section_by_name(".symtab").iter_symbols())
    funcs = [(s.name, s["st_shndx"], s["st_value"], s["st_size"]) for s in syms
             if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] and isinstance(s["st_shndx"], int)]
    out: dict[str, list[tuple]] = {}
    for ri, rs in enumerate(e.iter_sections()):
        if not isinstance(rs, RelocationSection):
            continue
        if rs.name.startswith(".klp.rela."):
            tgt = rs.name.split(".", 4)[-1]
            tidx = e.get_section_index(tgt) if e.get_section_by_name(tgt) else None
        else:
            tidx = rs["sh_info"]
        for k, r in enumerate(rs.iter_relocations()):
            sym = syms[r["r_info_sym"]]
            sh = sym["st_shndx"]
            if not isinstance(sh, int) or not 0 < sh < e.num_sections():
                continue
            sec = e.get_section(sh)
            if not sec.name.startswith(".rodata") or r["r_info_type"] == 0:
                continue
            pos = sym["st_value"] + r["r_addend"]
            d = sec.data()
            end = d.find(b"\0", pos)
            text = d[pos:end if end >= 0 else len(d)]
            for name, fsh, lo, size in funcs:
                if fsh == tidx and lo <= r["r_offset"] < lo + size:
                    out.setdefault(name, []).append((r["r_offset"] - lo, ri, k, sh, pos, text))
                    break
    return {n: sorted(v) for n, v in out.items()}


def label(stock: Path, fixed: Path) -> dict:
    a, b = rodata_rows(stock), rodata_rows(fixed)
    diff = []
    for fn in sorted(set(a) & set(b)):
        if len(a[fn]) != len(b[fn]):
            diff.append(f"{fn}: {len(a[fn])} vs {len(b[fn])} rows")
            continue
        n = sum(1 for x, y in zip(a[fn], b[fn]) if x[5] != y[5])
        if n:
            diff.append(f"{fn}: {n} of {len(a[fn])} reach different bytes")
    return {"label": "FAULTY" if diff else "CLEAN", "evidence": diff}


def oracle(ver: str, ko: str, refs: list[str], functions: list[str] | None = None) -> str:
    extra = ["--functions", ",".join(functions)] if functions else []
    r = subprocess.run([str(PY), str(ORACLES[ver]), ko, *refs, "--vmlinux", str(TREE / "vmlinux"),
                        "--modules-dir", str(TREE), *extra], capture_output=True, text=True)
    try:
        return json.loads(r.stdout)["overall_verdict"]
    except (json.JSONDecodeError, KeyError):
        return "ERROR"


def mutants(fixed: Path, cve: str) -> list[dict]:
    """One +1 r_addend mutant per .rodata relocation in a function; written under MUT/<cve>/."""
    e = ELFFile(open(fixed, "rb"))
    rels = list(e.iter_sections())
    out = []
    d = MUT / cve
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    raw = fixed.read_bytes()
    for fn, rows in rodata_rows(fixed).items():
        for off, ri, k, sh, pos, text in rows:
            rs = rels[ri]
            ent = rs["sh_offset"] + k * rs["sh_entsize"]
            addend = struct.unpack_from("<q", raw, ent + 16)[0]
            m = bytearray(raw)
            struct.pack_into("<q", m, ent + 16, addend + 1)
            sec = e.get_section(sh).data()
            end = sec.find(b"\0", pos + 1)
            new = sec[pos + 1:end if end >= 0 else len(sec)]
            p = d / f"{fn}+{off:#x}.ko"
            p.write_bytes(bytes(m))
            out.append({"cve": cve, "function": fn, "site": off, "module": str(p), "equivalent": new == text})
    return out


def func_names(path: str) -> set[str]:
    e = ELFFile(open(path, "rb"))
    return {x.name for x in e.get_section_by_name(".symtab").iter_symbols()
            if x["st_info"]["type"] == "STT_FUNC" and x["st_size"] and isinstance(x["st_shndx"], int)}


def s2_module():
    """The registered S2 mutant generator (lab/s2/s2run.py on the build host), with v1.3 and v1.4 as its oracles."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("s2run", A / "s2/s2run.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    for p, h in m.FROZEN.items():
        if m.sha(p) != h:
            raise SystemExit(f"{p}: not the frozen mutation tool")
    m.ORACLES = {v: (str(PY), ORACLES[v], SHA[v]) for v in ORACLES}
    m.OPS = list(OPS)
    m.MUT = OPMUT
    m.M = m.load_mutate()
    return m


def wilson(k: int, n: int) -> list[float] | None:
    if not n:
        return None
    z, p = 1.96, k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(c - h, 4), round(c + h, 4)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    import hashlib
    for v, p in ORACLES.items():
        if hashlib.sha256(p.read_bytes()).hexdigest() != SHA[v]:
            raise SystemExit(f"{v} hash is not the frozen {SHA[v]}")
    hdoc = json.loads((S12 / "out/6.19/heldout-h.json").read_text())
    fixes = hdoc["heldout"]
    subj, muts = [], []
    for f in fixes:
        c = f["cve"]
        st = [json.loads((H / v / c / "status.json").read_text()) if (H / v / c / "status.json").exists() else {}
              for v in ("stock", "fixed")]
        refs = sorted(str(p) for p in (IND / c).rglob("*.o"))
        ok_ref = (IND / c / "status.json").exists() and json.loads((IND / c / "status.json").read_text()).get("ok")
        row = {"cve": c, "stock_built": bool(st[0].get("ok")), "fixed_built": bool(st[1].get("ok")), "ref": bool(ok_ref)}
        if row["stock_built"] and row["fixed_built"] and ok_ref:
            sk, fk = next((H / "stock" / c / "build").glob("*.ko")), next((H / "fixed" / c / "build").glob("*.ko"))
            row.update(stock=str(sk), fixed=str(fk), refs=refs, **label(sk, fk))
            muts += mutants(fk, c)
        subj.append(row)
    scored = [r for r in subj if "label" in r]
    jobs = [("stock", r) for r in scored] + [("fixed", r) for r in scored]

    def run(job):
        kind, r = job
        return kind, r["cve"], {v: oracle(v, r[kind], r["refs"]) for v in ORACLES}

    def run_mut(m):
        r = next(x for x in scored if x["cve"] == m["cve"])
        return {**m, **{v: oracle(v, m["module"], r["refs"]) for v in ORACLES}}

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        res = list(ex.map(run, jobs))
        mres = list(ex.map(run_mut, muts))
        S2 = s2_module()
        osub = [{"set": "heldout-fixed", "id": r["cve"], "module": r["fixed"], "refs": r["refs"],
                 "tree": str(TREE), "hook": None, "changed": None} for r in scored]
        ores_subj = list(ex.map(S2.run_subject, osub))
    ores = [{**m, "cve": x["id"]} for x in ores_subj for m in x["mutants"]
            if m.get("built") and not m["noop"] and not m["duplicate_of"]]
    det = lambda m, v: (m.get(v) or {}).get("overall") in DET  # noqa: E731
    common = {r["cve"]: sorted(func_names(r["fixed"]) & set().union(*(func_names(p) for p in r["refs"]))) for r in scored}
    fixed_of = {r["cve"]: r["fixed"] for r in scored}

    def visible(m):
        return {**m, "visible": oracle("v1.3", m["path"], [fixed_of[m["cve"]]], common[m["cve"]]) in DET}

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        ores = list(ex.map(visible, ores))
    for kind, c, v in res:
        next(r for r in scored if r["cve"] == c)[f"{kind}_verdict"] = v
    summ = {"fixes": len(subj), "stock_built": sum(r["stock_built"] for r in subj),
            "fixed_built": sum(r["fixed_built"] for r in subj), "scored": len(scored),
            "labels": dict(Counter(r["label"] for r in scored))}
    groups = {"stock FAULTY": [r["stock_verdict"] for r in scored if r["label"] == "FAULTY"],
              "stock CLEAN": [r["stock_verdict"] for r in scored if r["label"] == "CLEAN"],
              "fixed": [r["fixed_verdict"] for r in scored]}
    nonequiv = [m for m in mres if not m["equivalent"]]
    for v in ORACLES:
        g = {}
        for name, vs in groups.items():
            k = sum(1 for x in vs if x[v] in DET)
            g[name] = {"flagged": k, "n": len(vs), "wilson95": wilson(k, len(vs)),
                       "verdicts": dict(Counter(x[v] for x in vs))}
        k = sum(1 for m in nonequiv if m[v] in DET)
        g["mutants +1"] = {"detected": k, "n": len(nonequiv), "wilson95": wilson(k, len(nonequiv)),
                           "equivalent_excluded": len(mres) - len(nonequiv)}
        summ[v] = g
    pok = {r["cve"] for r in scored if r["fixed_verdict"]["v1.4"] == "CONSISTENT"}
    masked = [f"{m['cve']} {m['op']}-{m['site_index']}" for m in ores
              if m["visible"] and m["cve"] in pok and not det(m, "v1.4")]
    per_op = {}
    for op in OPS:
        vis = [m for m in ores if m["op"] == op and m["visible"] and m["cve"] in pok]
        k = sum(1 for m in vis if det(m, "v1.4"))
        per_op[op] = {"visible_on_consistent_parents": len(vis), "v1.4_detected": k, "wilson95": wilson(k, len(vis)),
                      "invisible": sum(1 for m in ores if m["op"] == op and not m["visible"])}
    summ["operator_mutants"] = {"scored": len(ores), "parents_v14_consistent": len(pok),
                                "counts": {x["id"]: x["counts"] for x in ores_subj},
                                "per_op": per_op, "masked": masked, "pass": not masked}
    summ["alarms_v14_on_clean"] = [f"{r['cve']} stock={r['stock_verdict']['v1.4']} fixed={r['fixed_verdict']['v1.4']}"
                                   for r in scored if r["label"] == "CLEAN" and
                                   (r["stock_verdict"]["v1.4"] in DET or r["fixed_verdict"]["v1.4"] in DET)]
    summ["alarms_v14_on_fixed_of_faulty"] = [r["cve"] for r in scored if r["label"] == "FAULTY" and r["fixed_verdict"]["v1.4"] in DET]
    out = {"summary": summ, "subjects": subj, "mutants": mres, "operator_mutants": ores}
    (S12 / "oracle/s11-heldout-score.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps(summ, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
