#!/usr/bin/env python3
"""S25 instruction-level check, v1.5 = body_check.py plus rule RF.

RF: if the only differences in a function are at the entry, where the module has a
five-byte call (masked e8 ....) / mnemonic call and the reference has the five-byte
nop 0f1f440000 / mnemonic nop, accept the function as equal. Disable with
LPFID_DISABLE=RF.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

VERSION = "1.5"
FIELD = {1: 8, 2: 4, 4: 4, 9: 4, 10: 4, 11: 4, 41: 4, 42: 4}
DISABLED = set(filter(None, os.environ.get("LPFID_DISABLE", "").split(",")))
NOP5 = bytes.fromhex("0f1f440000")


class Obj:
    def __init__(self, path: Path):
        self.path = path
        self.elf = ELFFile(open(path, "rb"))
        st = self.elf.get_section_by_name(".symtab")
        self.syms = list(st.iter_symbols()) if st else []
        self._masks: dict[int, set[int]] = {}

    def functions(self) -> dict[str, tuple[int, int, int]]:
        out = {}
        for s in self.syms:
            if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] and isinstance(s["st_shndx"], int):
                out.setdefault(s.name, (s["st_shndx"], s["st_value"], s["st_size"]))
        return out

    def mask(self, shndx: int) -> set[int]:
        if shndx not in self._masks:
            m: set[int] = set()
            for sec in self.elf.iter_sections():
                if not isinstance(sec, RelocationSection):
                    continue
                if sec.name.startswith(".klp.rela."):
                    t = sec.name.split(".", 4)[-1]
                    tidx = self.elf.get_section_index(t) if self.elf.get_section_by_name(t) else None
                else:
                    tidx = sec["sh_info"]
                if tidx != shndx:
                    continue
                for r in sec.iter_relocations():
                    n = FIELD.get(r["r_info_type"], 4 if r["r_info_type"] else 0)
                    m.update(range(r["r_offset"], r["r_offset"] + n))
            self._masks[shndx] = m
        return self._masks[shndx]

    def insns(self, loc: tuple[int, int, int]) -> list[tuple[int, str, bytes]]:
        shndx, start, size = loc
        data = self.elf.get_section(shndx).data()[start:start + size]
        m = self.mask(shndx)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.skipdata = True
        out = []
        for ins in md.disasm(data, 0):
            b = bytes(0 if (start + ins.address + i) in m else ins.bytes[i] for i in range(ins.size))
            out.append((ins.address, ins.mnemonic, b))
        return out


def is_fentry_pair(x, y) -> bool:
    """Module call-with-reloc vs reference five-byte nop at the same offset."""
    if x is None or y is None:
        return False
    if x[0] != y[0]:
        return False
    # masked call is e8 00 00 00 00; nop is 0f 1f 44 00 00
    callish = x[1] == "call" and len(x[2]) == 5 and x[2][0] == 0xE8
    nopish = y[1] == "nop" and y[2] == NOP5
    callish2 = y[1] == "call" and len(y[2]) == 5 and y[2][0] == 0xE8
    nopish2 = x[1] == "nop" and x[2] == NOP5
    return (callish and nopish) or (callish2 and nopish2)


def diff(a, b) -> list[str]:
    out = []
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else None
        y = b[i] if i < len(b) else None
        if x is None or y is None or x[1:] != y[1:]:
            if "RF" not in DISABLED and is_fentry_pair(x, y):
                continue
            fx = f"{x[0]:#x} {x[1]} {x[2].hex()}" if x else "-"
            fy = f"{y[0]:#x} {y[1]} {y[2].hex()}" if y else "-"
            out.append(f"module {fx} | reference {fy}")
    return out


def main() -> int:
    args = sys.argv[1:]
    only = None
    if "--functions" in args:
        i = args.index("--functions")
        only = set(args[i + 1].split(","))
        del args[i:i + 2]
    mod = Obj(Path(args[0]))
    refs = [Obj(Path(p)) for p in args[1:]]
    mf = mod.functions()
    rall: dict[str, list] = {}
    for r in refs:
        for name, loc in r.functions().items():
            rall.setdefault(name, []).append((r, loc))
    common = sorted(n for n in mf if n in rall and (only is None or n in only))
    divergent = []
    for name in common:
        mi = mod.insns(mf[name])
        best = None
        for r, loc in rall[name]:
            d = diff(mi, r.insns(loc))
            if best is None or len(d) < len(best):
                best = d
        if best:
            divergent.append({"function": name, "differences": len(best), "first": best[:5]})
    verdict = "NO_COMMON_FUNCTIONS" if not common else ("DIVERGENT" if divergent else "CONSISTENT")
    print(json.dumps({"check": f"body-check {VERSION}", "verdict": verdict, "functions_compared": len(common),
                      "divergent_functions": divergent}, indent=1))
    return 0 if verdict == "CONSISTENT" else (1 if verdict == "DIVERGENT" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
