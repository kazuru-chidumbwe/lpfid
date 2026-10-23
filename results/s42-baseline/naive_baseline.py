#!/usr/bin/env python3
"""Same-toolchain baseline: relocation-masked function bytes plus the plain
relocation multiset. No normalisation rule is applied.

Registered in S42-PREREG-2026-10-21.md item 7. Read-only on the inputs.
"""
import glob
import json
import os
import time
from collections import Counter

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

PARENTS = "/opt/atlas/s12-eval/results/v0.9.11-gcc-13"
INDEP = "/opt/atlas/replica-testbedb/s12/refs-independent"
MUT = "/opt/atlas/s12-eval/s2/mut/s12"
OUT = "/opt/atlas/s42-naive"
# Relocation field widths used to mask the bytes a relocation overwrites.
FIELD = {1: 8, 2: 4, 4: 4, 9: 4, 10: 4, 11: 4, 41: 4, 42: 4}

_CACHE = {}


def _load(path):
    elf = ELFFile(open(path, "rb"))
    symtab = elf.get_section_by_name(".symtab")
    syms = list(symtab.iter_symbols()) if symtab else []
    masks = {}
    rels = {}
    nreloc = 0
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        if sec.name.startswith(".klp.rela."):
            target = sec.name.split(".", 4)[-1]
            tsec = elf.get_section_by_name(target)
            tidx = elf.get_section_index(target) if tsec is not None else None
        else:
            tidx = sec["sh_info"]
        if not isinstance(tidx, int):
            continue
        m = masks.setdefault(tidx, set())
        bag = rels.setdefault(tidx, [])
        for r in sec.iter_relocations():
            nreloc += 1
            width = FIELD.get(r["r_info_type"], 4 if r["r_info_type"] else 0)
            m.update(range(r["r_offset"], r["r_offset"] + width))
            sym = syms[r["r_info_sym"]] if r["r_info_sym"] < len(syms) else None
            name = sym.name if sym is not None and sym.name else ""
            addend = r["r_addend"] if "r_addend" in r.entry else 0
            bag.append((r["r_offset"], int(r["r_info_type"]), name, int(addend)))
    funcs = {}
    dup = 0
    for s in syms:
        if s["st_info"]["type"] != "STT_FUNC" or not s["st_size"]:
            continue
        if not isinstance(s["st_shndx"], int):
            continue
        if s.name in funcs:
            dup += 1
            continue
        sh, start, size = s["st_shndx"], s["st_value"], s["st_size"]
        sec = elf.get_section(sh)
        data = sec.data()
        if start + size > len(data):
            continue
        raw = bytearray(data[start:start + size])
        for off in masks.get(sh, ()):
            i = off - start
            if 0 <= i < len(raw):
                raw[i] = 0
        bag = Counter()
        for off, rtype, name, addend in rels.get(sh, ()):
            if start <= off < start + size:
                bag[(rtype, name, addend)] += 1
        funcs[s.name] = (bytes(raw), tuple(sorted(bag.items())))
    return funcs, nreloc, dup


def load(path):
    if path not in _CACHE:
        _CACHE[path] = _load(path)
    return _CACHE[path]


def refs_for(paths):
    merged = {}
    dropped = set()
    nreloc = 0
    for p in paths:
        funcs, nr, _dup = load(p)
        nreloc += nr
        for name, rec in funcs.items():
            if name in dropped:
                continue
            if name in merged and merged[name] != rec:
                dropped.add(name)
                del merged[name]
            else:
                merged.setdefault(name, rec)
    return merged, nreloc


def compare(mod, refs):
    common = set(mod) & set(refs)
    byte_n = reloc_n = 0
    for name in common:
        mb, mr = mod[name]
        rb, rr = refs[name]
        if mb != rb:
            byte_n += 1
        if mr != rr:
            reloc_n += 1
    if not common:
        verdict = "NO_COMMON"
    elif byte_n or reloc_n:
        verdict = "DIVERGENT"
    else:
        verdict = "CONSISTENT"
    return {
        "verdict": verdict,
        "common": len(common),
        "byte": byte_n,
        "reloc": reloc_n,
    }


def cells():
    out = []
    for kdir in sorted(os.listdir(PARENTS)):
        kd = os.path.join(PARENTS, kdir)
        if not os.path.isdir(kd):
            continue
        for cve in sorted(os.listdir(kd)):
            kos = glob.glob(os.path.join(kd, cve, "build", "*.ko"))
            if not kos:
                continue
            patched = sorted(glob.glob(os.path.join(kd, cve, "patched", "**", "*.o"), recursive=True))
            indep = sorted(glob.glob(os.path.join(INDEP, kdir, cve, "**", "*.o"), recursive=True))
            out.append((kdir, cve, kos[0], patched, indep))
    return out


def tally(rows, key):
    c = Counter(r[key] for r in rows)
    return dict(c)


def main():
    os.makedirs(OUT, exist_ok=True)
    faithful = cells()
    print("faithful", len(faithful), flush=True)
    if not faithful:
        raise SystemExit("no modules")
    kdir, cve, ko, patched, indep = faithful[0]
    funcs, nreloc, dup = load(ko)
    print("sample", cve, "funcs", len(funcs), "relocs", nreloc, "dup", dup, flush=True)
    if nreloc == 0:
        raise SystemExit("sample module has no relocations; the reader missed .klp.rela")
    shown = 0
    for name, (_b, bag) in funcs.items():
        if bag:
            print("sample_func", name, "reloc", bag[0], flush=True)
            shown += 1
        if shown >= 2:
            break

    frows = []
    t0 = time.time()
    for kdir, cve, ko, patched, indep in faithful:
        mod, _nr, _d = load(ko)
        rec = {"kdir": kdir, "cve": cve, "ko": ko}
        if patched:
            pref, _n = refs_for(patched)
            rec["parent"] = compare(mod, pref)
        else:
            rec["parent"] = {"verdict": "NO_REF"}
        if indep:
            iref, _n = refs_for(indep)
            rec["indep"] = compare(mod, iref)
        else:
            rec["indep"] = {"verdict": "NO_REF"}
        frows.append(rec)
    print("faithful_done", round(time.time() - t0, 1), "parent", tally(frows, "parent") if False else "", flush=True)
    print("faithful_parent", Counter(r["parent"]["verdict"] for r in frows), flush=True)
    print("faithful_indep", Counter(r["indep"]["verdict"] for r in frows), flush=True)
    with open(os.path.join(OUT, "faithful.jsonl"), "w") as fh:
        for r in frows:
            fh.write(json.dumps(r) + "\n")

    mrows_path = os.path.join(OUT, "mutants.jsonl")
    mf = open(mrows_path, "w")
    n = 0
    t1 = time.time()
    summary = Counter()
    for kdir, cve, _ko, patched, indep in faithful:
        cell = os.path.join(MUT, kdir + "__" + cve)
        if not os.path.isdir(cell):
            continue
        pref = refs_for(patched)[0] if patched else None
        iref = refs_for(indep)[0] if indep else None
        for dirpath, _dirs, files in os.walk(cell):
            for fn in files:
                if not fn.endswith(".ko"):
                    continue
                path = os.path.join(dirpath, fn)
                mod, _nr, _d = load(path)
                rec = {"kdir": kdir, "cve": cve, "ko": path, "op": fn.split("-")[0]}
                rec["parent"] = compare(mod, pref) if pref is not None else {"verdict": "NO_REF"}
                rec["indep"] = compare(mod, iref) if iref is not None else {"verdict": "NO_REF"}
                summary[(rec["op"], rec["parent"]["verdict"], rec["indep"]["verdict"])] += 1
                mf.write(json.dumps(rec) + "\n")
                n += 1
                if n % 500 == 0:
                    print("mutants", n, round(time.time() - t1, 1), flush=True)
    mf.close()
    print("mutants_done", n, round(time.time() - t1, 1), flush=True)
    by = {}
    for (op, vp, vi), k in sorted(summary.items()):
        by.setdefault(op, Counter())
        by[op][("parent", vp)] += k
        by[op][("indep", vi)] += k
    for op, c in sorted(by.items()):
        print("OP", op, dict(c), flush=True)


if __name__ == "__main__":
    main()
