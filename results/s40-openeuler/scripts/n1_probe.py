#!/usr/bin/env python3
"""N1 probe: does the binding oracle detect a relocation rebound to a sibling numbered copy of the same local
(descriptor.30281 -> descriptor.30290)? For each function the oracle compares in one package dir, find
relocations whose target is a numbered local (name.<digits>) with a sibling of the same base name in the
module's symbol table; rebind one site (both halves of an ADRP/lo12 pair on AArch64) to the sibling, and score
the mutant with the unchanged oracle, as s40_score.py does.
usage: n1_probe.py <oracle.py> <python> <pkg_out_dir> <results.jsonl> [max_per_module]"""
import sys, os, re, glob, json, struct, subprocess, shutil, tempfile
from elftools.elf.elffile import ELFFile

ORC, PY, OUTDIR, RESULTS = sys.argv[1:5]
CAP = int(sys.argv[5]) if len(sys.argv) > 5 else 10
NUM = re.compile(r"^(.*)\.(\d+)$")


def score(ko):
    refs = sorted(glob.glob(os.path.join(OUTDIR, "ref", "**", "*.o"), recursive=True))
    cmd = [PY, ORC, ko] + refs
    if os.path.exists(os.path.join(OUTDIR, "vmlinux")):
        cmd += ["--vmlinux", os.path.join(OUTDIR, "vmlinux"), "--modules-dir", OUTDIR]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3000)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"overall_verdict": "ERROR"}


def sites(ko):
    """(rela section file offset, entry index list, from_sym, to_symidx, to_name, function) per candidate site."""
    out = []
    with open(ko, "rb") as fh:
        e = ELFFile(fh)
        symtab = e.get_section_by_name(".symtab")
        syms = list(symtab.iter_symbols())
        by_base = {}
        for i, s in enumerate(syms):
            m = NUM.match(s.name)
            if m and s["st_shndx"] != "SHN_UNDEF" and s["st_info"]["type"] in ("STT_OBJECT", "STT_NOTYPE"):
                by_base.setdefault(m.group(1), []).append(i)
        for sec in e.iter_sections():
            if sec["sh_type"] != "SHT_RELA" or not sec.name.startswith(".rela.text."):
                continue
            func = sec.name[len(".rela.text."):]
            ents = list(sec.iter_relocations())
            groups = {}
            for k, r in enumerate(ents):
                n = syms[r["r_info_sym"]].name
                m = NUM.match(n)
                if m and len(by_base.get(m.group(1), [])) > 1:
                    # one site = the relocations naming this symbol at adjacent offsets (ADRP + lo12 pair)
                    groups.setdefault((r["r_info_sym"], r["r_offset"] >> 4), []).append(k)
            for (symi, _), ks in groups.items():
                m = NUM.match(syms[symi].name)
                sib = [j for j in by_base[m.group(1)] if j != symi][0]
                out.append((sec["sh_offset"], sec["sh_entsize"], ks, syms[symi].name, sib, syms[sib].name, func))
    return out


def main():
    base_v = {}
    for ko in sorted(glob.glob(os.path.join(OUTDIR, "ko", "*.ko"))):
        cand = sites(ko)
        base = score(ko)
        base_div = {f.get("function") for f in base.get("divergent_functions", [])}
        compared = set(base.get("compared_functions") or [])
        n = 0
        for (off, esz, ks, frm, sib, to, func) in cand:
            if n >= CAP or (compared and func not in compared):
                continue
            n += 1
            tmp = tempfile.mkdtemp()
            mko = os.path.join(tmp, os.path.basename(ko))
            shutil.copy(ko, mko)
            with open(mko, "r+b") as fh:
                for k in ks:
                    p = off + k * esz + 8                      # Elf64_Rela.r_info
                    fh.seek(p)
                    info = struct.unpack("<Q", fh.read(8))[0]
                    fh.seek(p)
                    fh.write(struct.pack("<Q", (sib << 32) | (info & 0xffffffff)))
            d = score(mko)
            dv = {f.get("function") for f in d.get("divergent_functions", [])}
            rec = {"pkg": os.path.basename(OUTDIR.rstrip("/")), "ko": os.path.basename(ko), "function": func,
                   "from": frm, "to": to, "relocs": len(ks), "verdict": d.get("overall_verdict"),
                   "multiset": d.get("multiset_verdict"), "sequence": d.get("sequence_verdict"),
                   "func_flagged": func in dv, "func_flagged_at_baseline": func in base_div}
            with open(RESULTS, "a") as f:
                f.write(json.dumps(rec) + "\n")
            print(json.dumps(rec))
            shutil.rmtree(tmp)
        print(f"{os.path.basename(ko)}: candidate sites {len(cand)}, mutated {n}")


main()
