#!/usr/bin/env python3
"""S41 operator `sibling` (internal/S41-PREREG-2026-10-20.md): rebind one site from a numbered local the module
defines to a sibling copy of the same base name in the module's own symbol table (both halves of an AArch64
ADRP/lo12 pair). Up to ten sites per module, seeded per module, scaffolding functions excluded, functions the
oracle compares only. A sibling whose content tag equals the original's is `sibling-indistinguishable`.
Writes the mutants and replay jobs (kp and independent references) for rescore18.py.
usage: gen_sibling.py <oracle-v1.8.py> <jobs.jsonl in> <outdir> <jobs-sibling.jsonl out>"""
import importlib.util, json, os, random, re, struct, sys
from pathlib import Path
from elftools.elf.elffile import ELFFile

ORC, JOBS, OUTDIR, OUTJ = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("orc18", ORC)
orc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orc)
NUM = re.compile(r"^(.*)\.(\d+)$")
SCAFFOLD = {"init_module", "cleanup_module", "__pfx_init_module", "__pfx_cleanup_module"}

parents = {}
for l in open(JOBS):
    j = json.loads(l)
    if j["set"] in ("s12-kp", "s21-v0.9.11-gcc-13-rind"):
        parents.setdefault(j["id"], {})[j["set"]] = j


def candidate_sites(ko, compared, hook_funcs):
    out = []
    with open(ko, "rb") as fh:
        e = ELFFile(fh)
        syms = list(e.get_section_by_name(".symtab").iter_symbols())
        by_base = {}
        for i, s in enumerate(syms):
            m = NUM.match(s.name)
            if m and isinstance(s["st_shndx"], int) and s["st_shndx"] > 0 and s["st_size"] \
                    and s["st_info"]["type"] in ("STT_OBJECT", "STT_NOTYPE"):
                by_base.setdefault(m.group(1), []).append(i)
        for sec in e.iter_sections():
            if sec["sh_type"] != "SHT_RELA" or not sec.name.startswith(".rela.text."):
                continue
            func = sec.name[len(".rela.text."):]
            if func not in compared or func in SCAFFOLD or func in hook_funcs:
                continue
            groups = {}
            for k, r in enumerate(sec.iter_relocations()):
                si = r["r_info_sym"]
                m = NUM.match(syms[si].name)
                if m and len(by_base.get(m.group(1), [])) > 1 and si in by_base[m.group(1)]:
                    groups.setdefault((si, r["r_offset"] >> 4), []).append(k)
            for (si, _), ks in sorted(groups.items()):
                base = NUM.match(syms[si].name).group(1)
                for sib in by_base[base]:
                    if sib != si:
                        out.append((sec["sh_offset"], sec["sh_entsize"], ks, si, sib, func,
                                    syms[si].name, syms[sib].name,
                                    (syms[si]["st_shndx"], syms[si]["st_value"], syms[si]["st_size"]),
                                    (syms[sib]["st_shndx"], syms[sib]["st_value"], syms[sib]["st_size"])))
                        break
    return out


jobs, stats = [], {"modules": 0, "with_sites": 0, "sites": 0, "drawn": 0, "indistinguishable": 0}
for pid, ps in sorted(parents.items()):
    kp = ps.get("s12-kp")
    if not kp:
        continue
    stats["modules"] += 1
    ko = kp["module"]
    mod = orc.Obj(Path(ko))
    refs = [orc.Obj(Path(p)) for p in kp["refs"]]
    rfuncs = set()
    hook = set()
    for r in refs:
        fs = set(r.functions())
        if r.path.name == "patch-hook.o":
            hook |= fs
        else:
            rfuncs |= fs
    compared = set(mod.functions()) & rfuncs
    cand = candidate_sites(ko, compared, hook)
    stats["sites"] += len(cand)
    if cand:
        stats["with_sites"] += 1
    rng = random.Random(f"{os.path.basename(ko)}:sibling")
    draw = rng.sample(cand, min(10, len(cand)))
    for k, (off, esz, ks, si, sib, func, frm, to, a, b) in enumerate(draw):
        stats["drawn"] += 1
        same = mod._content_tag(*a) == mod._content_tag(*b)
        if same:
            stats["indistinguishable"] += 1
        d = Path(OUTDIR) / pid.replace("/", "__")
        d.mkdir(parents=True, exist_ok=True)
        mko = d / f"sibling-{k}.ko"
        data = bytearray(open(ko, "rb").read())
        for kk in ks:
            p = off + kk * esz + 8
            info = struct.unpack_from("<Q", data, p)[0]
            struct.pack_into("<Q", data, p, (sib << 32) | (info & 0xffffffff))
        mko.write_bytes(bytes(data))
        meta = {"function": func, "from": frm, "to": to, "indistinguishable": same}
        for set_, src in (("sibling-kp", kp), ("sibling-ind", ps.get("s21-v0.9.11-gcc-13-rind"))):
            if src:
                jobs.append({**{k2: v for k2, v in src.items() if k2 not in ("set", "id", "module")},
                             "set": set_, "id": f"{pid} sibling-{k}", "module": str(mko), "meta": meta})
    for o in [mod] + refs:
        o.f.close()

with open(OUTJ, "w") as f:
    for j in jobs:
        f.write(json.dumps(j) + "\n")
print(json.dumps(stats))
