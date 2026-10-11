#!/usr/bin/env python3
"""S11 diagnostic: follow the string relocations of one function through klp-build's stages.
For each object given, print the .rodata* sections (flags, alignment, size) and, for every relocation in the
function's code that targets a .rodata* section symbol, the addend and the C string found at that addend.
Usage: python klp_stage_trace.py FUNCTION OBJ [OBJ ...]   (oracle venv, pyelftools)
"""
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

fn, objs = sys.argv[1], sys.argv[2:]
for path in objs:
    e = ELFFile(open(path, "rb"))
    print("=====", path)
    for i, s in enumerate(e.iter_sections()):
        if s.name.startswith(".rodata"):
            print(f"  [{i}] {s.name} flags={s['sh_flags']:#x} align={s['sh_addralign']} entsize={s['sh_entsize']} size={s['sh_size']:#x}")
    syms = list(e.get_section_by_name(".symtab").iter_symbols())
    f = [s for s in syms if s.name == fn and s["st_info"]["type"] == "STT_FUNC"]
    if not f:
        print("  function not found")
        continue
    f = f[0]
    shndx, lo, hi = f["st_shndx"], f["st_value"], f["st_value"] + f["st_size"]
    for rs in e.iter_sections():
        if not isinstance(rs, RelocationSection):
            continue
        tgt = rs.name.split(".", 4)[-1] if rs.name.startswith(".klp.rela.") else None
        tidx = e.get_section_index(tgt) if tgt else rs["sh_info"]
        if tidx != shndx:
            continue
        for r in rs.iter_relocations():
            if not lo <= r["r_offset"] < hi:
                continue
            sym = syms[r["r_info_sym"]]
            if not isinstance(sym["st_shndx"], int) or not 0 < sym["st_shndx"] < e.num_sections():
                continue
            sec = e.get_section(sym["st_shndx"])
            if not sec.name.startswith(".rodata"):
                continue
            pos = sym["st_value"] + r["r_addend"]
            d = sec.data()
            end = d.find(b"\0", pos)
            prev = d[pos - 1:pos] if pos > 0 else b""
            print(f"  +{r['r_offset'] - lo:#06x} type={r['r_info_type']} {sec.name}+{pos:#x} "
                  f"prev={prev.hex() or '-'} str={d[pos:end][:60]!r}")
