#!/usr/bin/env python3
"""Redirect every PLT32 reloc for SYM_SRC to SYM_DST's symbol index (one-way).

Section-aware. Enumerates every SHT_RELA section that relocates an executable
section (SHF_EXECINSTR) plus kpatch ``.klp.rela.*`` sections -- not only
``.rela.text``. Modules built with -ffunction-sections (notably kpatch-build
output) keep their call relocations in ``.rela.text.<func>`` /
``.rela.text.unlikely`` / ``.rela.init.text`` and ``.klp.rela.*``; a
``.rela.text``-only mutator finds nothing there and silently writes a mutant
byte-identical to its parent (a no-op that the structural oracle then, quite
correctly, reports as "no redirect present"). Keying is by
(rela-section, entry-index): r_offset is section-relative and collides across
sections, so it must never be the sole key.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

R_X86_64_PLT32 = 4


def is_exec_reloc_section(elf: ELFFile, sec: RelocationSection) -> bool:
    """True for a RELA section that relocates executable code (or a klp rela)."""
    if sec.name.startswith(".klp.rela."):
        return True
    info = sec.header["sh_info"]
    if not info:
        return False
    target = elf.get_section(info)
    return bool(target and (target.header["sh_flags"] & SH_FLAGS.SHF_EXECINSTR))


def symtab_index(elf: ELFFile, name: str) -> int | None:
    """Index of `name` in .symtab, preferring an undefined (extern) reference."""
    st = elf.get_section_by_name(".symtab")
    if st is None:
        return None
    fallback: int | None = None
    for i, sym in enumerate(st.iter_symbols()):
        if sym.name != name:
            continue
        if sym["st_shndx"] == "SHN_UNDEF":
            return i
        if fallback is None:
            fallback = i
    return fallback


def main() -> int:
    if len(sys.argv) != 5:
        print(f"usage: {sys.argv[0]} SRC.ko DST.ko SRC_SYM DST_SYM", file=sys.stderr)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    src_sym, dst_sym = sys.argv[3], sys.argv[4]

    data = bytearray(src.read_bytes())
    have_src = False
    n = 0
    per_section: dict[str, int] = {}

    with src.open("rb") as f:
        elf = ELFFile(f)
        dst_idx = symtab_index(elf, dst_sym)
        if dst_idx is None:
            print(f"dst symbol {dst_sym!r} not in .symtab of {src}", file=sys.stderr)
            return 1
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection) or not is_exec_reloc_section(elf, sec):
                continue
            symtab = elf.get_section(sec.header["sh_link"])
            base = sec.header["sh_offset"]
            entsize = sec.header["sh_entsize"] or 24
            for i, rel in enumerate(sec.iter_relocations()):
                if rel["r_info_type"] != R_X86_64_PLT32:
                    continue
                if symtab.get_symbol(rel["r_info_sym"]).name != src_sym:
                    continue
                have_src = True
                ent = base + i * entsize
                info = struct.unpack_from("<Q", data, ent + 8)[0]
                r_type = info & 0xFFFFFFFF
                struct.pack_into("<Q", data, ent + 8, (dst_idx << 32) | r_type)
                n += 1
                per_section[sec.name] = per_section.get(sec.name, 0) + 1

    if not have_src:
        print(f"no PLT32 sites for {src_sym!r} in {src}", file=sys.stderr)
        return 1

    dst.write_bytes(data)
    secs = ", ".join(f"{k}:{v}" for k, v in sorted(per_section.items()))
    print(f"redirected {n} PLT32 site(s) {src_sym} -> {dst_sym} (idx {dst_idx}) [{secs}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
