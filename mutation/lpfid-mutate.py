#!/usr/bin/env python3
"""LPFid mutation operators for livepatch modules (x86-64 ELF relocatable .ko).

Each operator models a class of fidelity fault (see the paper's taxonomy). The tool
never decides whether a fault is detected; it only writes the mutant and describes
the site it changed.

Operators
  redirect  a call relocation binds a different callee           (binding)
  swap      two call relocations in one function swap callees    (binding; invisible to multiset)
  addend    a data/PC-relative relocation points 8 bytes further (data/addend; cf. kpatch f5f5479)
  sympos    a klp symbol's position selects another copy of a duplicated name (binding; cf. kpatch c608faf);
            needs LPFID_VMLINUX, else falls back to ,N -> ,N+1 (mostly equivalent or load-failing)
  dropcall  a call is replaced by a 5-byte NOP, relocation voided (scope)
  constant  an immediate operand without relocation changes by +1 (body; no relocation changes)

Usage
  lpfid-mutate.py list OP SRC.ko                -> JSON list of candidate sites
  lpfid-mutate.py apply OP SITE_INDEX SRC.ko DST.ko -> writes DST.ko, prints JSON site description
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import struct
import sys
from pathlib import Path

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

R_NONE, R_64, R_PC32, R_PLT32, R_32, R_32S = 0, 1, 2, 4, 10, 11
RELA_SIZE = 24
KLP_SYM = re.compile(r"^\.klp\.sym\.[^.]+\.[^,]+,(\d+)$")
KLP_SYM_FULL = re.compile(r"^\.klp\.sym\.(?P<obj>[^.]+)\.(?P<name>[^,]+),(?P<pos>\d+)$")
NOP5 = bytes([0x0F, 0x1F, 0x44, 0x00, 0x00])


def oracle_module():
    """The oracle's symbol index (kallsyms order) is reused so operator and oracle agree on positions."""
    spec = importlib.util.spec_from_file_location("lpfid_oracle", Path(__file__).with_name("blind-reloc-oracle.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Mod:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        self.elf = ELFFile(open(path, "rb"))
        self.symtab = self.elf.get_section_by_name(".symtab")
        self.syms = list(self.symtab.iter_symbols())

    def exec_relas(self):
        """Yield (rela_sec, index, target_section_index, rela) for relocations applying to code."""
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            if sec.name.startswith(".klp.rela."):
                tname = sec.name.split(".", 4)[-1] if sec.name.count(".") >= 4 else ""
                tidx = self.elf.get_section_index(tname) if tname and self.elf.get_section_by_name(tname) else None
            else:
                tidx = sec["sh_info"]
            if tidx is None:
                continue
            tsec = self.elf.get_section(tidx)
            if not (tsec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR):
                continue
            for i, r in enumerate(sec.iter_relocations()):
                yield sec, i, tidx, r

    def func_at(self, shndx: int, off: int) -> str | None:
        for s in self.syms:
            if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == shndx and s["st_size"] \
                    and s["st_value"] <= off < s["st_value"] + s["st_size"]:
                return s.name
        return None

    def rela_file_off(self, sec, i: int) -> int:
        return sec["sh_offset"] + i * (sec["sh_entsize"] or RELA_SIZE)

    def sym_name(self, idx: int) -> str:
        return self.syms[idx].name


def sites(m: Mod, op: str) -> list[dict]:
    out: list[dict] = []
    if op in ("redirect", "swap", "dropcall"):
        calls = [(s, i, t, r) for s, i, t, r in m.exec_relas() if r["r_info_type"] == R_PLT32]
        if op == "redirect":
            names = []
            for _, _, _, r in calls:
                n = m.sym_name(r["r_info_sym"])
                if n and n not in names:
                    names.append(n)
            for k, n in enumerate(names):
                if len(names) > 1:
                    out.append({"src": n, "dst": names[(k + 1) % len(names)]})
        elif op == "swap":
            by_func: dict = {}
            for s, i, t, r in calls:
                by_func.setdefault((t, m.func_at(t, r["r_offset"])), []).append((s, i, r))
            for (t, fn), lst in by_func.items():
                for a in range(len(lst)):
                    for b in range(a + 1, len(lst)):
                        if lst[a][2]["r_info_sym"] != lst[b][2]["r_info_sym"]:
                            out.append({"function": fn, "rela": lst[a][0].name, "i": lst[a][1], "j": lst[b][1],
                                        "a": m.sym_name(lst[a][2]["r_info_sym"]), "b": m.sym_name(lst[b][2]["r_info_sym"])})
                            break
        else:  # dropcall
            for s, i, t, r in calls:
                tsec = m.elf.get_section(t)
                pos = tsec["sh_offset"] + r["r_offset"] - 1
                if r["r_offset"] >= 1 and m.data[pos] == 0xE8:
                    out.append({"rela": s.name, "i": i, "callee": m.sym_name(r["r_info_sym"]),
                                "function": m.func_at(t, r["r_offset"]), "insn_file_off": pos})
    elif op == "addend":
        for s, i, t, r in m.exec_relas():
            if r["r_info_type"] in (R_PC32, R_32S, R_32, R_64):
                out.append({"rela": s.name, "i": i, "type": r["r_info_type"], "target": m.sym_name(r["r_info_sym"]),
                            "function": m.func_at(t, r["r_offset"]), "addend": r["r_addend"]})
    elif op == "sympos":
        # With LPFID_VMLINUX set, only names that have two or more copies in the pin's vmlinux are mutated,
        # and the new position is another valid copy (a silent wrong binding). Position changes on unique
        # names bind the same symbol (equivalent mutants) or fail to load; they are listed under
        # "sympos-equivalent" so they can be counted, not scored.
        vml = os.environ.get("LPFID_VMLINUX")
        index = oracle_module().symbol_index(vml, by_address=True) if vml else None
        for k, s in enumerate(m.syms):
            mm = KLP_SYM_FULL.match(s.name or "")
            if not mm:
                continue
            obj, name, pos = mm.group("obj"), mm.group("name"), int(mm.group("pos"))
            if index is None:
                if pos < 9:
                    out.append({"sym_index": k, "name": s.name, "new_pos": str(pos + 1)})
                continue
            copies = len(index.get(name, [])) if obj == "vmlinux" else 0
            if copies >= 2 and 1 <= pos <= 9:
                for new in range(1, min(copies, 9) + 1):
                    if new != pos:
                        out.append({"sym_index": k, "name": s.name, "new_pos": str(new), "copies": copies})
    elif op == "sympos-equivalent":
        vml = os.environ.get("LPFID_VMLINUX")
        index = oracle_module().symbol_index(vml, by_address=True) if vml else {}
        for k, s in enumerate(m.syms):
            mm = KLP_SYM_FULL.match(s.name or "")
            if mm and mm.group("obj") == "vmlinux" and len(index.get(mm.group("name"), [])) == 1:
                out.append({"sym_index": k, "name": s.name, "copies": 1})
    elif op == "constant":
        out.extend(constant_sites(m))
    else:
        raise SystemExit(f"unknown operator {op}")
    return out


def constant_sites(m: Mod) -> list[dict]:
    try:
        import capstone
    except ImportError:
        raise SystemExit("constant operator needs python3-capstone")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    reloc_spans: dict[int, list[tuple[int, int]]] = {}
    for _, _, t, r in m.exec_relas():
        width = 8 if r["r_info_type"] == R_64 else 4
        reloc_spans.setdefault(t, []).append((r["r_offset"], r["r_offset"] + width))
    out = []
    for s in m.syms:
        if s["st_info"]["type"] != "STT_FUNC" or not s["st_size"] or not isinstance(s["st_shndx"], int):
            continue
        sec = m.elf.get_section(s["st_shndx"])
        if not (sec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR):
            continue
        base = sec["sh_offset"] + s["st_value"]
        code = bytes(m.data[base: base + s["st_size"]])
        for ins in md.disasm(code, s["st_value"]):
            imms = [o.imm for o in ins.operands if o.type == capstone.x86.X86_OP_IMM]
            if not imms or ins.mnemonic.startswith(("call", "j", "ret", "nop", "endbr")):
                continue
            imm = imms[0]
            for width in (1, 4):
                try:
                    enc = imm.to_bytes(width, "little", signed=True)
                except OverflowError:
                    continue
                if bytes(ins.bytes[-width:]) == enc:
                    lo = ins.address + ins.size - width
                    spans = reloc_spans.get(s["st_shndx"], [])
                    if any(a < lo + width and lo < b for a, b in spans):
                        break
                    out.append({"function": s.name, "insn": f"{ins.mnemonic} {ins.op_str}",
                                "file_off": sec["sh_offset"] + lo, "width": width, "imm": imm})
                    break
    return out


def apply(m: Mod, op: str, site: dict) -> None:
    d = m.data
    if op == "swap":
        sec = m.elf.get_section_by_name(site["rela"])
        oi, oj = m.rela_file_off(sec, site["i"]), m.rela_file_off(sec, site["j"])
        ii = struct.unpack_from("<Q", d, oi + 8)[0]
        ij = struct.unpack_from("<Q", d, oj + 8)[0]
        struct.pack_into("<Q", d, oi + 8, (ij & ~0xFFFFFFFF) | (ii & 0xFFFFFFFF))
        struct.pack_into("<Q", d, oj + 8, (ii & ~0xFFFFFFFF) | (ij & 0xFFFFFFFF))
    elif op == "addend":
        sec = m.elf.get_section_by_name(site["rela"])
        o = m.rela_file_off(sec, site["i"])
        struct.pack_into("<q", d, o + 16, struct.unpack_from("<q", d, o + 16)[0] + 8)
    elif op == "dropcall":
        sec = m.elf.get_section_by_name(site["rela"])
        o = m.rela_file_off(sec, site["i"])
        d[site["insn_file_off"]: site["insn_file_off"] + 5] = NOP5
        info = struct.unpack_from("<Q", d, o + 8)[0]
        struct.pack_into("<Q", d, o + 8, (info & ~0xFFFFFFFF) | R_NONE)
    elif op == "sympos":
        strtab = m.elf.get_section(m.symtab["sh_link"])
        s = m.syms[site["sym_index"]]
        name_off = strtab["sh_offset"] + s["st_name"]
        old = site["name"].encode()
        assert bytes(d[name_off: name_off + len(old)]) == old
        assert len(site["new_pos"]) == 1 and old[-2:-1] == b","  # single-digit positions only
        d[name_off + len(old) - 1] = ord(site["new_pos"])
    elif op == "constant":
        o, w = site["file_off"], site["width"]
        v = int.from_bytes(d[o:o + w], "little", signed=True) + 1
        lim = 1 << (8 * w - 1)
        v = v if -lim <= v < lim else -lim
        d[o:o + w] = v.to_bytes(w, "little", signed=True)
    else:
        raise SystemExit(f"apply not implemented for {op} (use perturb-plt32-redirect.py)")


def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "list":
        print(json.dumps(sites(Mod(Path(sys.argv[3])), sys.argv[2])))
        return 0
    if len(sys.argv) == 6 and sys.argv[1] == "apply":
        op, idx, src, dst = sys.argv[2], int(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5])
        m = Mod(src)
        site = sites(m, op)[idx]
        apply(m, op, site)
        dst.write_bytes(bytes(m.data))
        print(json.dumps({"op": op, "site": site, "noop": bytes(m.data) == src.read_bytes()}))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
