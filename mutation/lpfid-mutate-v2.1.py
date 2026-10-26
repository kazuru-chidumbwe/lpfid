#!/usr/bin/env python3
"""LPFid mutation operators for livepatch modules (x86-64 ELF relocatable .ko), v2.1.

v2.1 = v2.0 (sha256 d3068950781d9a17...) plus one change, pre-registered in internal/S44-PREREG-2026-10-24.md
after the S43 classification (lab/s43/S43-MISS-CLASSIFY-2026-10-24.md):
  rodsec also skips a section whose flags mark it a merge pool (SHF_STRINGS or SHF_MERGE), whatever its name.
         GCC names merged-string sections .rodata.<function>.str1.8, which the name rule did not skip.
Every other operator is unchanged.

v2.0 header follows.

LPFid mutation operators for livepatch modules (x86-64 ELF relocatable .ko).

Each operator models a class of fidelity fault (see the paper's taxonomy). The tool
never decides whether a fault is detected; it only writes the mutant and describes
the site it changed.

Operators
  redirect  every call relocation naming one callee binds another callee, module-wide (binding; S1 rule)
  redirect1 one call relocation inside one non-scaffolding function binds the next distinct callee (binding;
            S42). Sites whose source or destination is infrastructure (INFRA) carry stratum "infra".
  clonerb   one code relocation to a compiler clone (base.isra.N, .constprop.N, .part.N, .cold.N, .localalias.N,
            klp-decorated or not) binds a sibling clone of the same base already in the symbol table (binding;
            S42). A site whose two clones are both defined with byte-identical bodies is marked
            "clone-indistinguishable".
  rodsec    one code relocation through the section symbol of a named .rodata.<x> section (not .rodata.str*,
            .rodata.cst*) binds the section symbol of another such section, addend kept (binding; S42). On AArch64
            the other half of an ADRP/lo12 pair (same symbol and addend, same function, within 16 bytes) moves too.
  clonerb-klp  a .klp.sym.vmlinux.<clone>,<pos> symbol used by exactly one relocation is renamed in place to a
            sibling clone of the same base and kind that the pin's vmlinux defines (needs LPFID_VMLINUX), with the
            sibling's position (0 if unique). Only when the new name fits the old string and no other symbol name
            shares those string bytes (binding; S42 addendum 1).
  sibling   the S41 rule: in a function's .rela.text.<fn>, the relocations naming one numbered local (base.N, a
            sized STT_OBJECT or STT_NOTYPE) within one 16-byte window move to a sibling numbered local of the same
            base the module defines (both halves of an AArch64 ADRP/lo12 pair); sites whose two copies have equal
            N1C content tags are marked "sibling-indistinguishable" (binding; S41, ported in S42 addendum 2).
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
CLONE = re.compile(r"^(?P<base>.+?\.(?:isra|constprop|part|cold|localalias))\.(?P<n>\d+)(?P<pos>,\d+)?$")
# S42: callees that are build or livepatch infrastructure rather than code of the fix
INFRA = re.compile(r"^(__fentry__|__x86_|__sanitizer_|__stack_chk_fail|__pfx_|klp_|__ubsan_|__asan_|__kcsan_|"
                   r"__tsan_|_mcount$|__cfi_|__x86_indirect_)")

# AArch64 (S37). Call sites are CALL26/JUMP26 (one 32-bit BL/B instruction at the relocation offset, no x86
# -1 opcode byte). dropcall writes the 4-byte AArch64 NOP 0xd503201f and voids the relocation to NONE.
A_NONE, A_ABS64, A_ABS32, A_PREL64, A_PREL32 = 256, 257, 258, 260, 261
A_ADR_HI21, A_ADD_LO12, A_JUMP26, A_CALL26 = 275, 277, 282, 283
A_LDST_LO12 = {278, 284, 285, 286, 299}
A_CALL = {A_CALL26, A_JUMP26}
A_ADDEND = {A_ABS64, A_ABS32, A_PREL64, A_PREL32, A_ADD_LO12} | A_LDST_LO12
AARCH64_NOP = bytes([0x1F, 0x20, 0x03, 0xD5])  # 0xd503201f, little-endian


def oracle_module():
    """The oracle's symbol index (kallsyms order) is reused so operator and oracle agree on positions."""
    # S42: the oracle is named by LPFID_ORACLE, else the newest frozen version in ../oracle (the repo layout)
    path = os.environ.get("LPFID_ORACLE")
    if not path:
        cands = sorted((Path(__file__).resolve().parent.parent / "oracle").glob("blind-reloc-oracle-v*.py"),
                       key=lambda p: [int(x) for x in re.findall(r"\d+", p.stem.split("-v")[-1])])
        path = str(cands[-1]) if cands else str(Path(__file__).with_name("blind-reloc-oracle.py"))
    spec = importlib.util.spec_from_file_location("lpfid_oracle", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Mod:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        self.elf = ELFFile(open(path, "rb"))
        self.aarch64 = self.elf.header["e_machine"] == "EM_AARCH64"
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
    if op in ("redirect", "redirect1", "swap", "dropcall"):
        callset = A_CALL if m.aarch64 else {R_PLT32}
        calls = [(s, i, t, r) for s, i, t, r in m.exec_relas() if r["r_info_type"] in callset]
        if op == "redirect":
            names = []
            for _, _, _, r in calls:
                n = m.sym_name(r["r_info_sym"])
                if n and n not in names:
                    names.append(n)
            for k, n in enumerate(names):
                if len(names) > 1:
                    out.append({"src": n, "dst": names[(k + 1) % len(names)]})
        elif op == "redirect1":
            names = []
            for _, _, _, r in calls:
                n = m.sym_name(r["r_info_sym"])
                if n and n not in names:
                    names.append(n)
            for s_, i, t, r in calls:
                fn = m.func_at(t, r["r_offset"])
                src = m.sym_name(r["r_info_sym"])
                if not fn or not src or len(names) < 2:
                    continue
                dst = names[(names.index(src) + 1) % len(names)]
                out.append({"function": fn, "rela": s_.name, "i": i, "src": src, "dst": dst,
                            "stratum": "infra" if INFRA.match(src) or INFRA.match(dst) else "fix"})
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
                if m.aarch64:
                    pos = tsec["sh_offset"] + r["r_offset"]          # BL/B is the 32-bit word at the reloc offset
                    word = int.from_bytes(m.data[pos:pos + 4], "little")
                    if (word >> 26) & 0x3F in (0x05, 0x25):          # B (000101b) / BL (100101b)
                        out.append({"rela": s.name, "i": i, "callee": m.sym_name(r["r_info_sym"]),
                                    "function": m.func_at(t, r["r_offset"]), "insn_file_off": pos})
                else:
                    pos = tsec["sh_offset"] + r["r_offset"] - 1      # x86 call rel32 opcode 0xE8
                    if r["r_offset"] >= 1 and m.data[pos] == 0xE8:
                        out.append({"rela": s.name, "i": i, "callee": m.sym_name(r["r_info_sym"]),
                                    "function": m.func_at(t, r["r_offset"]), "insn_file_off": pos})
    elif op == "clonerb":
        def bare(k):
            sy = m.syms[k]
            if sy["st_info"]["type"] == "STT_SECTION" and isinstance(sy["st_shndx"], int) and sy["st_shndx"]:
                sn = m.elf.get_section(sy["st_shndx"]).name   # a local clone is reached through .text.<clone>
                return sn[len(".text."):] if sn.startswith(".text.") else ""
            mm = KLP_SYM_FULL.match(sy.name or "")
            return (mm.group("obj") + ":" + mm.group("name") + "," + mm.group("pos")) if mm else sy.name
        by_base: dict = {}
        for k, sy in enumerate(m.syms):
            b = bare(k)
            obj, _, rest = b.rpartition(":") if ":" in (b or "") else ("", "", b)
            cm = CLONE.match(rest or "")
            if cm:
                by_base.setdefault((obj, cm.group("base")), []).append(k)
        for s_, i, t, r in m.exec_relas():
            k = r["r_info_sym"]
            b = bare(k)
            obj, _, rest = b.rpartition(":") if ":" in (b or "") else ("", "", b)
            cm = CLONE.match(rest or "")
            fn = m.func_at(t, r["r_offset"])
            if not cm or not fn:
                continue
            kind = m.syms[k]["st_info"]["type"] == "STT_SECTION"
            def usable(k2):
                sy2 = m.syms[k2]
                if (sy2["st_info"]["type"] == "STT_SECTION") == kind:
                    return True
                # a section-symbol site may point at the sibling's function symbol at the start of its own
                # section when that section has no section symbol (same address, addend kept)
                return kind and sy2["st_info"]["type"] == "STT_FUNC" and sy2["st_value"] == 0
            sibs = [k2 for k2 in by_base.get((obj, cm.group("base")), []) if k2 != k and bare(k2) != b and usable(k2)]
            sibs.sort(key=lambda k2: (m.syms[k2]["st_info"]["type"] == "STT_SECTION") != kind)
            for k2 in sibs:
                a, b2 = m.syms[k], m.syms[k2]
                same = False
                if isinstance(a["st_shndx"], int) and isinstance(b2["st_shndx"], int) and a["st_size"] and b2["st_size"]:
                    da = m.elf.get_section(a["st_shndx"]).data()[a["st_value"]:a["st_value"] + a["st_size"]]
                    db = m.elf.get_section(b2["st_shndx"]).data()[b2["st_value"]:b2["st_value"] + b2["st_size"]]
                    same = da == db
                out.append({"function": fn, "rela": s_.name, "i": i, "src": b, "dst": bare(k2),
                            "dst_index": k2, "equivalent": "clone-indistinguishable" if same else None})
                break
    elif op == "clonerb-klp":
        vml = os.environ.get("LPFID_VMLINUX")
        if not vml:
            raise SystemExit("clonerb-klp needs LPFID_VMLINUX")
        index = oracle_module().symbol_index(vml, by_address=True)
        uses: dict = {}
        for _, _, _, r in m.exec_relas():
            uses[r["r_info_sym"]] = uses.get(r["r_info_sym"], 0) + 1
        strtab = m.elf.get_section(m.symtab["sh_link"])
        spans = sorted((sy["st_name"], sy["st_name"] + len((sy.name or "").encode()) + 1) for sy in m.syms if sy.name)
        for k, sy in enumerate(m.syms):
            mm = KLP_SYM_FULL.match(sy.name or "")
            if not mm or mm.group("obj") != "vmlinux" or uses.get(k) != 1:
                continue
            cm = CLONE.match(mm.group("name"))
            if not cm:
                continue
            base = cm.group("base")
            sibs = sorted(n for n in index if n != mm.group("name") and CLONE.match(n) and CLONE.match(n).group("base") == base)
            lo, hi = sy["st_name"], sy["st_name"] + len(sy.name.encode()) + 1
            shared = any(a < hi and b > lo and (a, b) != (lo, hi) for a, b in spans)
            for sname in sibs:
                pos = 0 if len(index[sname]) == 1 else 1
                new = f".klp.sym.vmlinux.{sname},{pos}"
                if len(new.encode()) <= len(sy.name.encode()) and not shared:
                    fn = None
                    for s_, i, t, r in m.exec_relas():
                        if r["r_info_sym"] == k:
                            fn = m.func_at(t, r["r_offset"])
                    out.append({"function": fn, "sym_index": k, "src": sy.name, "dst": new,
                                "strtab_file_off": strtab["sh_offset"] + lo, "old_len": len(sy.name.encode())})
                    break
    elif op == "sibling":
        NUMB = re.compile(r"^(.*)\.(\d+)$")
        by_base: dict = {}
        for k, sy in enumerate(m.syms):
            mm = NUMB.match(sy.name or "")
            if mm and isinstance(sy["st_shndx"], int) and sy["st_shndx"] > 0 and sy["st_size"] \
                    and sy["st_info"]["type"] in ("STT_OBJECT", "STT_NOTYPE"):
                by_base.setdefault(mm.group(1), []).append(k)
        orc = None
        for sec in m.elf.iter_sections():
            if sec["sh_type"] != "SHT_RELA" or not sec.name.startswith(".rela.text."):
                continue
            func = sec.name[len(".rela.text."):]
            groups: dict = {}
            for k, r in enumerate(sec.iter_relocations()):
                si = r["r_info_sym"]
                mm = NUMB.match(m.syms[si].name or "")
                if mm and len(by_base.get(mm.group(1), [])) > 1 and si in by_base[mm.group(1)]:
                    groups.setdefault((si, r["r_offset"] >> 4), []).append(k)
            for (si, _), ks in sorted(groups.items()):
                base = NUMB.match(m.syms[si].name).group(1)
                for sib in by_base[base]:
                    if sib == si:
                        continue
                    if orc is None:
                        orc = oracle_module().Obj(m.path)
                    a, b = m.syms[si], m.syms[sib]
                    same = orc._content_tag(a["st_shndx"], a["st_value"], a["st_size"]) == \
                        orc._content_tag(b["st_shndx"], b["st_value"], b["st_size"])
                    out.append({"function": func, "rela": sec.name, "idx": ks, "src": m.syms[si].name,
                                "dst": m.syms[sib].name, "dst_index": sib,
                                "equivalent": "sibling-indistinguishable" if same else None})
                    break
        if orc is not None:
            orc.f.close()
    elif op == "rodsec":
        named = {}
        for k, sy in enumerate(m.syms):
            if sy["st_info"]["type"] == "STT_SECTION" and isinstance(sy["st_shndx"], int) and sy["st_shndx"]:
                nm = m.elf.get_section(sy["st_shndx"]).name
                pool = m.elf.get_section(sy["st_shndx"])["sh_flags"] & (SH_FLAGS.SHF_STRINGS | SH_FLAGS.SHF_MERGE)
                if nm.startswith(".rodata.") and not nm.startswith((".rodata.str", ".rodata.cst")) and not pool:
                    named[k] = nm
        for s_, i, t, r in m.exec_relas():
            k = r["r_info_sym"]
            fn = m.func_at(t, r["r_offset"])
            if k not in named or not fn:
                continue
            others = [k2 for k2 in sorted(named) if named[k2] != named[k]]
            if others:
                k2 = others[(sorted(named).index(k)) % len(others)]
                idx = [i]
                if m.aarch64:   # move the other half of an ADRP/lo12 pair with it
                    for s2, i2, t2, r2 in m.exec_relas():
                        if s2.name == s_.name and i2 != i and r2["r_info_sym"] == k and r2["r_addend"] == r["r_addend"] \
                                and abs(r2["r_offset"] - r["r_offset"]) <= 16 and m.func_at(t2, r2["r_offset"]) == fn:
                            idx.append(i2)
                out.append({"function": fn, "rela": s_.name, "idx": sorted(idx), "src": named[k], "dst": named[k2],
                            "dst_index": k2})
    elif op == "addend":
        addset = A_ADDEND if m.aarch64 else (R_PC32, R_32S, R_32, R_64)
        for s, i, t, r in m.exec_relas():
            if r["r_info_type"] in addset:
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


def constant_sites_arm64(m: Mod) -> list[dict]:
    """AArch64 body-class operator: an ADD/SUB-immediate instruction (bits[28:24]=10001) whose 4 bytes carry no
    relocation; the mutant bumps its imm12 field. No relocation changes, so it is the binding checks' blind
    spot, exactly as on x86-64."""
    try:
        import capstone
    except ImportError:
        raise SystemExit("constant operator needs python3-capstone")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    reloc_words: dict[int, set] = {}
    for _, _, t, r in m.exec_relas():
        reloc_words.setdefault(t, set()).add(r["r_offset"] & ~3)
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
            if ins.mnemonic not in ("add", "sub", "adds", "subs"):
                continue
            word = int.from_bytes(ins.bytes, "little")
            if (word >> 24) & 0x1F != 0x11:          # ADD/SUB (immediate) encoding
                continue
            if ins.address in reloc_words.get(s["st_shndx"], ()):
                continue
            out.append({"function": s.name, "insn": f"{ins.mnemonic} {ins.op_str}",
                        "file_off": sec["sh_offset"] + ins.address, "imm12": (word >> 10) & 0xFFF})
    return out


def constant_sites(m: Mod) -> list[dict]:
    if m.aarch64:
        return constant_sites_arm64(m)
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
    if op == "redirect":
        # repoint every call relocation binding `src` to `dst` (arch-neutral: rewrite the r_info symbol index)
        dst_idx = next((k for k, s in enumerate(m.syms) if s.name == site["dst"]), None)
        if dst_idx is None:
            raise SystemExit("redirect: dst symbol not found")
        callset = A_CALL if m.aarch64 else {R_PLT32}
        for sec, i, t, r in m.exec_relas():
            if r["r_info_type"] in callset and m.sym_name(r["r_info_sym"]) == site["src"]:
                o = m.rela_file_off(sec, i)
                info = struct.unpack_from("<Q", d, o + 8)[0]
                struct.pack_into("<Q", d, o + 8, (dst_idx << 32) | (info & 0xFFFFFFFF))
    elif op == "clonerb-klp":
        b = site["dst"].encode() + b"\0" * (site["old_len"] - len(site["dst"].encode()) + 1)
        d[site["strtab_file_off"]:site["strtab_file_off"] + len(b)] = b
    elif op in ("clonerb", "rodsec", "sibling"):
        sec = m.elf.get_section_by_name(site["rela"])
        for i in site.get("idx", [site.get("i")]):
            o = m.rela_file_off(sec, i)
            info = struct.unpack_from("<Q", d, o + 8)[0]
            struct.pack_into("<Q", d, o + 8, (site["dst_index"] << 32) | (info & 0xFFFFFFFF))
    elif op == "redirect1":
        dst_idx = next((k for k, s in enumerate(m.syms) if s.name == site["dst"]), None)
        if dst_idx is None:
            raise SystemExit("redirect1: dst symbol not found")
        sec = m.elf.get_section_by_name(site["rela"])
        o = m.rela_file_off(sec, site["i"])
        info = struct.unpack_from("<Q", d, o + 8)[0]
        struct.pack_into("<Q", d, o + 8, (dst_idx << 32) | (info & 0xFFFFFFFF))
    elif op == "swap":
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
        if m.aarch64:
            d[site["insn_file_off"]: site["insn_file_off"] + 4] = AARCH64_NOP
            newtype = A_NONE
        else:
            d[site["insn_file_off"]: site["insn_file_off"] + 5] = NOP5
            newtype = R_NONE
        info = struct.unpack_from("<Q", d, o + 8)[0]
        struct.pack_into("<Q", d, o + 8, (info & ~0xFFFFFFFF) | newtype)
    elif op == "sympos":
        strtab = m.elf.get_section(m.symtab["sh_link"])
        s = m.syms[site["sym_index"]]
        name_off = strtab["sh_offset"] + s["st_name"]
        old = site["name"].encode()
        assert bytes(d[name_off: name_off + len(old)]) == old
        assert len(site["new_pos"]) == 1 and old[-2:-1] == b","  # single-digit positions only
        d[name_off + len(old) - 1] = ord(site["new_pos"])
    elif op == "constant":
        if m.aarch64:
            o = site["file_off"]
            word = int.from_bytes(d[o:o + 4], "little")
            new = ((word >> 10) & 0xFFF) + 1 & 0xFFF           # bump imm12, wrap in field
            word = (word & ~(0xFFF << 10)) | (new << 10)
            d[o:o + 4] = word.to_bytes(4, "little")
        else:
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
