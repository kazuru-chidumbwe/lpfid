#!/usr/bin/env python3
"""Blind reference-differential relocation oracle for livepatch modules, v1.6.

v1.6 = the frozen v1.5 plus one rule, added by a dated deviation after the S26 Amazon draw
showed 57 of 58 DIVERGENT modules differed only in loader scaffolding:
  RS  after RF, functions named init_module, cleanup_module, __pfx_init_module or
      __pfx_cleanup_module are excluded from the overall / multiset / sequence verdicts
      (still listed under scaffolding_divergences when they would have been divergent).
      Livepatch modules carry klp registration under those names; pairing them with a
      patched object's own init/exit is the scaffolding class of Sections 7.2 and 7.6.
Disable with LPFID_DISABLE=RS. Source v1.5 sha256: e8a402134394c86947950f2a58d8b2c2e2ce179f405e2aa31258752e833b8aa0.

v1.5 header follows.

Blind reference-differential relocation oracle for livepatch modules, v1.5.

v1.5 = the frozen v1.4 plus one rule, added by a dated deviation in S34 (15 Oct 2026) after the
OpenAnolis 7.7 census showed 27 of 39 patched functions differ only at the fentry probe:
  RF  after R0 drops R_X86_64_NONE, if a function's only relocation difference is that the module
      has one extra PC32:__fentry__ row (n_mod == n_ref + 1, only_in_module == ["PC32:__fentry__"],
      only_in_reference empty), accept the function as equal. The reference's matching NONE to
      __fentry__ was dropped by R0; the live call and the five-byte nop are the same probe site.
Disable with LPFID_DISABLE=RF. Source v1.4 sha256: 3d44077fd13816b8c5051fe394ed448cdd1f2d067c4294e385d5397028b6ce04.

v1.4 header follows.

Blind reference-differential relocation oracle for livepatch modules, v1.4.

v1.4 = the frozen v1.3 plus three rules, added by a dated deviation in S16 (Deviation 4, 11 Oct 2026) after the
klp-build modules of S11 showed that v1.3 flags 24 of 27 modules without a generator fault, through three
differences of representation in klp-build's linked module (lab/s11/KLP-LOAD-FAILS-2026-10-10.md):
  R0  relocations of type R_X86_64_NONE are dropped on both sides. Applying one changes nothing, so dropping it
      cannot hide an effect: a missing real relocation still leaves the reference's row unmatched.
  RB  every target in __bug_table (a named __bug_table_N entry or the section plus an offset) is one label.
  RC  when a function's two sequences have equal length and differ only where the module points at an anonymous
      .rodata offset, each such pair is accepted if the module's bytes there equal the reference target's bytes
      over the reference target's extent (a string up to and including its NUL, or the symbol's size). A pointer
      into the middle of a string, or at other data, still differs.
Each can be switched off with LPFID_DISABLE=R0,RB,RC; all three off gives the v1.3 behaviour.

v1.3 header follows.

Blind reference-differential relocation oracle for livepatch modules, v1.3.

v1.3 = the frozen v1.2 plus one rule, added by a dated deviation in S16 (Deviation 3) after the held-out 5.15 arm
showed one false alarm in every kpatch release (CVE-2026-80664, xt_nat, 10 Oct 2026):
  DUP when the references define a function name more than once (a patched object that is a loadable module has
      init_module and cleanup_module, and so has the generator's scaffolding object), the module's function is
      paired with the definition whose relocation multiset is closest to its own, instead of the first one in
      argument order. Names defined once are paired as before.
It can be switched off with LPFID_DISABLE=DUP, which gives the v1.2 behaviour.

v1.2 header follows.

Blind reference-differential relocation oracle for livepatch modules, v1.2.

v1.2 = the frozen v1.1 plus two changes, added by a dated deviation in S16 after the S2 operator mutants exposed
two blind spots (9 Oct 2026, lab/s2/MISSES-2026-10-09.md):
  N3M replaces N3. N3 turned any leading "word: " of a referenced string into "<pfx>: ", so a reference shifted
      into a colon-terminated word ("focaltech: x" -> "h: x") compared equal. N3M absorbs only the pr_fmt prefix
      it exists for: a module string whose prefix is the module's own name (.modinfo name=), and a reference
      string whose prefix differs but whose text after the prefix equals such a module string.
  ALT the relocations in the replacement code of every .altinstructions entry whose original instruction lies
      in a compared function are compared too (alternatives are patched into the function at run time).
Both can be switched off with LPFID_DISABLE=N3M,ALT, which gives the v1.1 behaviour.

v1.1 header follows.

v1.1 = the frozen v1 (S16, sha256 7d79c9d9...843c) plus two canonicalisation rules, added by a dated
deviation in S16 after the S9 root cause of the S12 false alarms (8 Oct 2026):
  N4  the offset of a PC-relative target is computed from the length of the instruction that holds the
      relocated field (addend + end of instruction - field offset), decoded with capstone, instead of
      assuming that the field ends the instruction (addend + 4). Instructions with a trailing immediate
      (cmpb $imm, x(%rip); movl $imm32, x(%rip)) otherwise resolve to the neighbouring symbol.
  N5  a named symbol defined in a string section (kpatch keeps .LCn labels) is replaced by the string it
      points at, as v1 already does for section symbols into string sections.
Both can be switched off with LPFID_DISABLE=N4,N5, which gives the v1 behaviour.

The oracle is NOT told which fault (if any) was injected. It receives:
  - MODULE.ko     the livepatch module under test
  - REF.o [...]   an independent reference compile of the same source
                  (kpatch: the patched kernel object(s) from the patched build;
                   in-tree samples: a separate compile of the module source)

For every function present in both, it extracts the relocations that fall
inside the function body and compares them after normalisation:
  - target symbol name, with kpatch/klp decoration removed
    (".klp.sym.vmlinux.kfree,0" -> "kfree"; kpatch "kfree.cold" kept as is)
  - section-symbol targets into string sections replaced by the referenced
    string bytes (string merging moves addends between builds)
  - other section-symbol targets replaced by the section's name family
    (".rodata.foo" -> ".rodata")

Two comparison modes:
  multiset  per-function Counter of (type, target)        -- robust to reordering
  sequence  per-function list of (type, target) by offset -- catches swaps

Binding check P1 (sympos), when --vmlinux is given: every ".klp.sym.<obj>.<name>,N" relocation is
resolved the way the kernel does it (N-th symbol of that name in kallsyms order, N=0 meaning the name
must be unique) against the pin's vmlinux (or <obj>.ko under --modules-dir), and the chosen copy must be
defined in the same source file as the reference object of the function holding the relocation.
N0 strips ",N" for the relocation comparison, so without P1 a wrong position is invisible.

Prints one JSON object and exits 0 if CONSISTENT, 1 if DIVERGENT, 2 on error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

try:
    import capstone  # pinned 5.0.7 (harness requirements)
except ImportError:  # N4 cannot run without it
    capstone = None

RTYPE = {2: "PC32", 4: "PLT32", 9: "GOTPCREL", 10: "32", 11: "32S", 1: "64", 42: "REX_GOTPCRELX", 41: "GOTPCRELX"}
KLP_SYM = re.compile(r"^\.klp\.sym\.[^.]+\.(?P<name>[^,]+),\d+$")
KLP_SYM_FULL = re.compile(r"^\.klp\.sym\.(?P<obj>[^.]+)\.(?P<name>[^,]+),(?P<pos>\d+)$")
# compiler-generated suffixes that legitimately differ between builds
LOCAL_SUFFIX = re.compile(r"\.(isra|constprop|part|cold|localalias)\.\d+$|\.cold$")
IGNORE_TARGETS: set[str] = set()  # compare every target; ignoring any would be a blind spot


NUM_SUFFIX = re.compile(r"\.\d+$")
PRFMT = re.compile(r"^((?:\x01.)?)[A-Za-z0-9_\-]+: ")
GCC_VER = re.compile(r"GCC: \([^)]*\) (\d+\.\d+\.\d+)")
CLANG_VER = re.compile(r"clang version (\d+\.\d+\.\d+)")
PC_REL = {2, 4, 41, 42}  # PC32, PLT32, GOTPCRELX, REX_GOTPCRELX: addend carries -4

# S37 (arm64/AArch64): relocation-type decoding. The naming rules N0-N5, the string/section-family rule and the
# effective-offset handling carry over unchanged; only the type decode is architecture specific. On AArch64 the
# addend is the true offset into the target, so no AArch64 type is in PC_REL (the x86 end-of-instruction -4 bias
# does not apply). S+A branches and data resolve as off = addend. Frozen in internal/S37-PREREG-2026-10-19.md.
AARCH64_NONE = 256
AARCH64_ADRP = {275, 276}            # ADR_PREL_PG_HI21[_NC]: page (hi21)
AARCH64_LO12 = {277, 278, 284, 285, 286, 299}  # ADD/LDST{8,16,32,64,128}_ABS_LO12_NC: page offset (lo12)
RTYPE_AARCH64 = {
    256: "NONE", 257: "ABS64", 258: "ABS32", 259: "ABS16",
    260: "PREL64", 261: "PREL32", 262: "PREL16", 273: "LD_PREL_LO19",
    275: "ADR_PG_HI21", 276: "ADR_PG_HI21_NC",
    277: "ADD_LO12", 278: "LDST8_LO12", 284: "LDST16_LO12",
    285: "LDST32_LO12", 286: "LDST64_LO12", 299: "LDST128_LO12",
    279: "TSTBR14", 280: "CONDBR19", 282: "JUMP26", 283: "CALL26",
}


def _pair_adrp_lo12(raw):
    """S37: combine an ADRP (page, HI21) with the following ADD/LDST lo12 that shares its resolved target into
    one ADDR binding, so the page/lo12 representation split is normalised away while target identity and total
    offset are kept. ADRP and its lo12 always name the same symbol with the same addend, so pairing is by equal
    resolved target; the match is greedy on the next unconsumed lo12 and is applied identically to module and
    reference, so it never introduces a divergence of its own. A lo12 with no preceding ADRP, or an ADRP with no
    matching lo12, is kept as its own ADDR binding so nothing is silently dropped. raw rows: (off, typenum,
    label, target)."""
    consumed, out = set(), []
    for i, (off, rt, label, t) in enumerate(raw):
        if i in consumed:
            continue
        if rt in AARCH64_ADRP:
            for j in range(i + 1, len(raw)):
                if j not in consumed and raw[j][1] in AARCH64_LO12 and raw[j][3] == t:
                    consumed.add(j)
                    break
            out.append((off, -1, "ADDR", t))
        elif rt in AARCH64_LO12:
            out.append((off, -1, "ADDR", t))
        else:
            out.append((off, rt, label, t))
    return out

# Normalisation rules, frozen before any real-fix evaluation (S16). Each can be
# disabled for the ablation (S15) through LPFID_DISABLE=N1,N2,... in the environment.
import os
DISABLED = set(filter(None, os.environ.get("LPFID_DISABLE", "").split(",")))


BUG_LABEL = re.compile(r"^(sec:)?__bug_table(_\d+)?([+-]0x[0-9a-f]+)?$")


class Label(str):
    """A target label that also records where the target bytes are (v1.4 RC); compares as the plain label."""
    obj = None
    shndx = None
    pos = None
    size = None


def norm_name(name: str) -> str:
    m = KLP_SYM.match(name)
    if m and "N0" not in DISABLED:          # N0: strip klp relocation decoration
        name = m.group("name")
    if "N1" not in DISABLED:                # N1: compiler-numbered locals (__key.198 -> __key.N)
        name = NUM_SUFFIX.sub(".N", name)
    return name


def section_family(name: str) -> str:
    for fam in (".rodata.str", ".rodata", ".data", ".bss", ".text", ".init", ".exit"):
        if name.startswith(fam):
            return fam
    return name


def read_cstring(sec_data: bytes, off: int) -> str:
    end = sec_data.find(b"\0", off)
    if end < 0:
        end = len(sec_data)
    return sec_data[off:end].decode("latin-1")


class Obj:
    def __init__(self, path: Path):
        self.path = path
        self.f = path.open("rb")
        self.elf = ELFFile(self.f)
        # S37: architecture of this object. The relocation-type decode is the only architecture-specific step.
        self.aarch64 = self.elf.header["e_machine"] in ("EM_AARCH64", 183)
        self.saw_unknown_reloc = False
        # Performance (S16 Deviation 5, 12 Oct 2026): cache sections by index. ELFFile.get_section reparses the
        # section header from the stream on every call, and iter_sections / get_section_by_name both go through it;
        # against a whole-kernel vmlinux.o reference (huge section table) the oracle reparsed sections ~1.7M times
        # per run. The ELF is immutable during a run, so a cached Section is identical - verdicts unchanged.
        _elf_get_section = self.elf.get_section
        self._sec_cache: dict = {}

        def _cached_get_section(n, _c=self._sec_cache, _g=_elf_get_section):
            if n not in _c:
                _c[n] = _g(n)
            return _c[n]

        self.elf.get_section = _cached_get_section
        self.symtab: SymbolTableSection = self.elf.get_section_by_name(".symtab")
        self.syms = list(self.symtab.iter_symbols()) if self.symtab else []
        self._ends: dict[int, dict[int, int]] = {}
        self.n4_fallbacks = 0

    def insn_end(self, shndx: int, off: int) -> int | None:
        """N4: end offset of the instruction that contains byte off of section shndx (None if undecodable)."""
        if shndx not in self._ends:
            ends: dict[int, int] = {}
            sec = self.elf.get_section(shndx)
            if capstone is not None and sec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                md.skipdata = True
                for ins in md.disasm(sec.data(), 0):
                    for k in range(ins.address, ins.address + ins.size):
                        ends[k] = ins.address + ins.size
            self._ends[shndx] = ends
        return self._ends[shndx].get(off)

    def source_file(self) -> str | None:
        """Basename of the first STT_FILE symbol (the translation unit of a single-TU object)."""
        # Performance (S16 performance deviation, 12 Oct 2026): memoize. source_file is a pure function of the
        # object (the first STT_FILE symbol), yet compare() calls it once per matched reference function - 2676
        # times on one object against a whole-kernel vmlinux.o reference, ~111 s of a run. Cache the one scan;
        # the object is immutable during a run, so the cached value is identical - verdicts unchanged.
        try:
            return self._source_file_cache
        except AttributeError:
            pass
        self._source_file_cache = None
        for s in self.syms:
            if s["st_info"]["type"] == "STT_FILE" and s.name:
                self._source_file_cache = os.path.basename(s.name)
                break
        return self._source_file_cache

    def function_at(self, shndx: int, off: int) -> str | None:
        for s in self.syms:
            if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == shndx and s["st_size"] \
                    and s["st_value"] <= off < s["st_value"] + s["st_size"]:
                return s.name
        return None

    def klp_relocs(self):
        """(function in module or None, symbol name) for every relocation in a .klp.rela section."""
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection) or not sec.name.startswith(".klp.rela."):
                continue
            tgt_name = sec.name.split(".", 4)[-1] if sec.name.count(".") >= 4 else ""
            tgt_idx = (self.elf.get_section_index(tgt_name)
                       if tgt_name and self.elf.get_section_by_name(tgt_name) else None)
            for r in sec.iter_relocations():
                yield (self.function_at(tgt_idx, r["r_offset"]) if tgt_idx is not None else None,
                       self.syms[r["r_info_sym"]].name)

    def functions(self) -> dict[str, tuple[int, int, int]]:
        """name -> (section index, start, size) for defined FUNC symbols with size."""
        out = {}
        for s in self.syms:
            if s["st_info"]["type"] != "STT_FUNC" or s["st_size"] == 0:
                continue
            shndx = s["st_shndx"]
            if not isinstance(shndx, int):
                continue
            out.setdefault(s.name, (shndx, s["st_value"], s["st_size"]))
        return out

    def _func_index(self) -> dict:
        """Performance (S16 Deviation 7, 12 Oct 2026): index FUNC/OBJECT symbols by section, once per object, in
        symbol-table order. _symbol_at used to scan the whole symbol table on every section-relative target;
        against a whole-kernel vmlinux.o (~369k symbols) that was O(symbols) per call. The index holds the same
        symbols in the same order, so _symbol_at makes the identical choice - verdicts unchanged."""
        idx = getattr(self, "_func_index_cache", None)
        if idx is None:
            idx = {}
            for s in self.syms:
                if s["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT"):
                    idx.setdefault(s["st_shndx"], []).append((s["st_value"], s["st_size"], s.name))
            self._func_index_cache = idx
        return idx

    def _symbol_at(self, shndx: int, off: int) -> tuple[str, int] | None:
        """(name, start) of the FUNC/OBJECT symbol in section shndx that covers offset off."""
        best = None
        for start, size, name in self._func_index().get(shndx, ()):
            if start == off or (size and start <= off < start + size):
                if best is None or start == off:
                    best = (name, start)
        return best

    @staticmethod
    def _with_offset(name: str, delta: int) -> str:
        """A1: the offset inside the target is part of the binding (sym+8 is not sym+0)."""
        if "A1" in DISABLED or delta == 0:
            return name
        return f"{name}{delta:+#x}"

    def target(self, sym, addend: int, rtype: int = 0, tail: int = 4) -> str:
        label = self._target_v13(sym, addend, rtype, tail)
        if "RB" not in DISABLED and BUG_LABEL.match(label):
            label = "__bug_table"
        lab = Label(label)
        lab.obj = self
        off = addend + tail if rtype in PC_REL else addend
        shndx = sym["st_shndx"]
        if isinstance(shndx, int) and 0 < shndx < self.elf.num_sections():
            lab.shndx = shndx
            if sym["st_info"]["type"] == "STT_SECTION":
                lab.pos = off
            else:
                lab.pos = sym["st_value"] + off
                lab.size = sym["st_size"] - off if sym["st_size"] > off else None
        return lab

    def _target_v13(self, sym, addend: int, rtype: int = 0, tail: int = 4) -> str:
        # Effective offset into the target: PC-relative relocations carry -(end of instruction - field) in
        # the addend; that is -4 unless the instruction ends with an immediate (N4 supplies the real tail).
        off = addend + tail if rtype in PC_REL else addend
        if sym["st_info"]["type"] == "STT_SECTION":
            sec = self.elf.get_section(sym["st_shndx"])
            fam = section_family(sec.name)
            if sec.name.startswith(".rodata.str") or (sec["sh_flags"] & SH_FLAGS.SHF_STRINGS):
                data = sec.data()
                if 0 <= off < len(data):
                    text = read_cstring(data, off)
                    if "N3M" in DISABLED and "N3" not in DISABLED:   # v1.1 N3 (N3M handles prefixes in compare)
                        text = PRFMT.sub(r"\1<pfx>: ", text)
                    return f'str:"{text}"'
            if "N2" not in DISABLED:                  # N2: section+offset -> symbol it points at
                hit = self._symbol_at(sym["st_shndx"], off)
                if hit:
                    return self._with_offset(norm_name(hit[0]), off - hit[1])
            return self._with_offset(f"sec:{fam}", off)
        shndx = sym["st_shndx"]
        if "N5" not in DISABLED and isinstance(shndx, int) and 0 < shndx < self.elf.num_sections():
            sec = self.elf.get_section(shndx)
            if sec.name.startswith(".rodata.str") or (sec["sh_flags"] & SH_FLAGS.SHF_STRINGS):
                data = sec.data()
                pos = sym["st_value"] + off
                if 0 <= pos < len(data):
                    text = read_cstring(data, pos)
                    if "N3M" in DISABLED and "N3" not in DISABLED:
                        text = PRFMT.sub(r"\1<pfx>: ", text)
                    return f'str:"{text}"'
        return self._with_offset(norm_name(sym.name), off)

    def module_name(self) -> str | None:
        """N3M: the module's own name from .modinfo (name=...), None for an object file."""
        sec = self.elf.get_section_by_name(".modinfo")
        if sec is None:
            return None
        for item in sec.data().split(b"\0"):
            if item.startswith(b"name="):
                return item[5:].decode("latin-1")
        return None

    def _sym_target(self, r) -> tuple[int, int] | None:
        """(section index, offset) a relocation points at: symbol value (0 for a section symbol) plus addend."""
        sym = self.syms[r["r_info_sym"]]
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int) or shndx == 0:
            return None
        base = 0 if sym["st_info"]["type"] == "STT_SECTION" else sym["st_value"]
        return shndx, base + r["r_addend"]

    def alt_entries(self) -> list[tuple[int, int, int, int]]:
        """ALT: (instr section, instr offset, replacement section, replacement offset, replacement length) per
        .altinstructions entry, from its relocations; the entry size comes from the spacing of the entries,
        and replacementlen is the last byte of an entry in every struct alt_instr layout (5.x to 6.x)."""
        if hasattr(self, "_alt"):
            return self._alt
        self._alt = []
        sec = self.elf.get_section_by_name(".altinstructions")
        rela = None
        for s in self.elf.iter_sections():
            if isinstance(s, RelocationSection) and s.name in (".rela.altinstructions", ".klp.rela.vmlinux..altinstructions"):
                rela = s
                break
        if sec is None or rela is None:
            return self._alt
        rels = sorted(rela.iter_relocations(), key=lambda r: r["r_offset"])
        bases = sorted({r["r_offset"] for r in rels if r["r_offset"] % 2 == 0})
        starts = [o for o in bases if o + 4 in bases]
        if not starts:
            return self._alt
        gaps = Counter(b - a for a, b in zip(starts, starts[1:]))
        size = gaps.most_common(1)[0][0] if gaps else sec["sh_size"]
        data = sec.data()
        by_off = {r["r_offset"]: r for r in rels}
        for b in range(0, sec["sh_size"] - size + 1, size):
            ri, rr = by_off.get(b), by_off.get(b + 4)
            if ri is None or rr is None:
                continue
            ti, tr = self._sym_target(ri), self._sym_target(rr)
            if ti is None or tr is None:
                continue
            self._alt.append((ti[0], ti[1], tr[0], tr[1], data[b + size - 1]))
        return self._alt

    def alt_rows(self, shndx: int, start: int, size: int) -> list[tuple[str, str]]:
        """ALT: relocations of the replacement code of every alternative whose instruction lies in the function."""
        rows = []
        for ish, ioff, rsh, roff, rlen in self.alt_entries():
            if ish == shndx and start <= ioff < start + size:
                rows += [("alt:" + t, x) for _, t, x in self.relocs_in(rsh, roff, rlen)]
        return rows

    def compilers(self) -> set[str]:
        """Compiler identities from .comment. T1 strict (default): the full banner,
        e.g. 'GCC: (Debian 13.3.0-16) 13.3.0', because two distribution builds of the
        same gcc version can generate different code. LPFID_T1=version keeps only
        the version number (used for the cross-toolchain benign-variation study, S3)."""
        sec = self.elf.get_section_by_name(".comment")
        if sec is None:
            return set()
        text = sec.data().decode("latin-1")
        if os.environ.get("LPFID_T1", "strict") == "version":
            return {f"gcc-{v}" for v in GCC_VER.findall(text)} | {f"clang-{v}" for v in CLANG_VER.findall(text)}
        return {" ".join(b.split()) for b in text.split("\x00") if b.strip().startswith(("GCC:", "clang version", "Ubuntu clang", "Debian clang"))}

    def _reloc_sections_by_target(self) -> dict:
        """Performance (S16 Deviation 6, 12 Oct 2026): map target section index -> its relocation sections, built
        once per object. relocs_in used to scan every section on each call; against a whole-kernel vmlinux.o
        (~280k sections) with one call per compared function that was O(sections) per call (~59M iterations). The
        map is built from the same sections in the same index order, so relocs_in processes the identical reloc
        sections in the identical order - verdicts unchanged."""
        m = getattr(self, "_reloc_map_cache", None)
        if m is None:
            m = {}
            for sec in self.elf.iter_sections():
                if not isinstance(sec, RelocationSection):
                    continue
                if sec.name.startswith(".klp.rela."):
                    # .klp.rela.<obj>.<section>: applies to the named section
                    tgt_name = sec.name.split(".", 4)[-1] if sec.name.count(".") >= 4 else ""
                    tgt = self.elf.get_section_by_name(tgt_name) if tgt_name else None
                    tgt_idx = self.elf.get_section_index(tgt_name) if tgt is not None else None
                else:
                    tgt_idx = sec["sh_info"]
                m.setdefault(tgt_idx, []).append(sec)
            self._reloc_map_cache = m
        return m

    def relocs_in(self, shndx: int, start: int, size: int) -> list[tuple[int, str, str]]:
        """(offset, type, target) for relocations applying to [start, start+size) of section shndx."""
        aa = self.aarch64
        tbl = RTYPE_AARCH64 if aa else RTYPE
        raw = []  # (off, typenum, label, target)
        for sec in self._reloc_sections_by_target().get(shndx, ()):
            for r in sec.iter_relocations():
                off = r["r_offset"]
                if not (start <= off < start + size):
                    continue
                rt = r["r_info_type"]
                if "R0" not in DISABLED and (rt == 0 or (aa and rt == AARCH64_NONE)):  # NONE has no effect
                    continue
                sym = self.syms[r["r_info_sym"]]
                tail = 4
                if "N4" not in DISABLED and rt in PC_REL:   # x86 only; no AArch64 type is in PC_REL
                    end = self.insn_end(shndx, off)
                    if end is None or not 4 <= end - off <= 12:
                        self.n4_fallbacks += 1
                    else:
                        tail = end - off
                t = self.target(sym, r["r_addend"], rt, tail)
                if t in IGNORE_TARGETS:
                    continue
                label = tbl.get(rt)
                if label is None:   # unknown type: never a silent CONSISTENT (S37 deviations policy)
                    label = ("AARCH64_UNK_%d" % rt) if aa else str(rt)
                    self.saw_unknown_reloc = True
                raw.append((off - start, rt, label, t))
        raw.sort()
        if aa and "AAPAIR" not in DISABLED:
            raw = _pair_adrp_lo12(raw)
        return [(off, label, t) for off, rt, label, t in raw]


_SYMINDEX: dict = {}


def symbol_index(path: str, by_address: bool) -> dict:
    """name -> [(address, source file basename or None for globals)] in kallsyms order.
    vmlinux: kallsyms is sorted by address. Modules: module kallsyms follow the symtab order."""
    if path in _SYMINDEX:
        return _SYMINDEX[path]
    import pickle, hashlib, tempfile
    cache = None
    try:  # disk cache: parse a large vmlinux symtab once, reuse across processes (keyed on path+mtime)
        key = hashlib.md5(("%s:%d:%d" % (path, int(os.path.getmtime(path)), by_address)).encode()).hexdigest()
        cache = os.path.join(tempfile.gettempdir(), "lpfid-symidx-%s.pkl" % key)
        if os.path.exists(cache):
            with open(cache, "rb") as cf:
                out = pickle.load(cf)
            _SYMINDEX[path] = out
            return out
    except Exception:
        cache = cache if isinstance(cache, str) else None
    idx: dict = {}
    with open(path, "rb") as f:
        st = ELFFile(f).get_section_by_name(".symtab")
        cur_file = None
        for i, sym in enumerate(st.iter_symbols()):
            typ, bind = sym["st_info"]["type"], sym["st_info"]["bind"]
            if typ == "STT_FILE":
                cur_file = os.path.basename(sym.name) if sym.name else None
                continue
            if typ not in ("STT_FUNC", "STT_OBJECT", "STT_NOTYPE") or not sym.name or sym["st_shndx"] == "SHN_UNDEF":
                continue
            idx.setdefault(sym.name, []).append((sym["st_value"], cur_file if bind == "STB_LOCAL" else None, i))
    out = {}
    for name, rows in idx.items():
        rows.sort(key=(lambda r: (r[0], r[2])) if by_address else (lambda r: r[2]))
        out[name] = [(a, f) for a, f, _ in rows]
    _SYMINDEX[path] = out
    if cache:
        try:
            with open(cache, "wb") as cf:
                pickle.dump(out, cf)
        except Exception:
            pass
    return out


def sympos_check(mod: Obj, rfiles: dict, vmlinux: str | None, modules_dir: str | None) -> dict:
    """P1: does each klp symbol position select the copy defined in the reference function's file?"""
    if "P1" in DISABLED or not vmlinux:
        return {"sympos_verdict": "NOT_CHECKED", "sympos_findings": [], "sympos_checked": 0}
    findings, seen = [], set()
    for func, symname in mod.klp_relocs():
        m = KLP_SYM_FULL.match(symname or "")
        if not m or (func, symname) in seen:
            continue
        seen.add((func, symname))
        obj, name, pos = m.group("obj"), m.group("name"), int(m.group("pos"))
        if obj == "vmlinux":
            index = symbol_index(vmlinux, by_address=True)
        else:
            cand = list(Path(modules_dir).rglob(f"{obj}.ko")) if modules_dir else []
            if not cand:
                findings.append({"function": func, "symbol": symname, "status": "INCONCLUSIVE", "why": f"no {obj}.ko"})
                continue
            index = symbol_index(str(cand[0]), by_address=False)
        copies = index.get(name, [])
        want = rfiles.get(func) if func else None
        row = {"function": func, "symbol": symname, "copies": len(copies), "expected_file": want}
        if not copies:
            row.update(status="LOAD_FAIL", why="symbol not found")
        elif pos == 0:
            row.update(status="CONSISTENT" if len(copies) == 1 else "LOAD_FAIL",
                       why="unique" if len(copies) == 1 else "sympos 0 but name is ambiguous")
        elif pos > len(copies):
            row.update(status="LOAD_FAIL", why=f"sympos {pos} > {len(copies)} copies")
        else:
            bound_file = copies[pos - 1][1]
            row["bound_file"] = bound_file
            if len(copies) == 1:
                row.update(status="CONSISTENT", why="only one copy")
            elif want is None or sum(1 for _, f in copies if f == want) != 1:
                row.update(status="INCONCLUSIVE", why="expected file unknown or not unique among copies")
            elif bound_file == want:
                row.update(status="CONSISTENT", why="binds the copy in the reference file")
            else:
                row.update(status="DIVERGENT", why=f"binds the copy in {bound_file}; reference function is in {want}")
        findings.append(row)
    sts = {f["status"] for f in findings}
    verdict = ("NOT_APPLICABLE" if not findings else "DIVERGENT" if "DIVERGENT" in sts else
               "LOAD_FAIL" if "LOAD_FAIL" in sts else "INCONCLUSIVE" if "INCONCLUSIVE" in sts else "CONSISTENT")
    return {"sympos_verdict": verdict, "sympos_findings": [f for f in findings if f["status"] != "CONSISTENT"],
            "sympos_checked": len(findings)}


def _rc_index(obj):
    # RC (performance): index the reference object's sized STT_OBJECT symbols by section, in symbol-table
    # order, so the first covering symbol is the one the earlier linear scan over obj.syms returned.
    idx = getattr(obj, '_rc_cover_idx', None)
    if idx is None:
        idx = {}
        for s in obj.syms:
            if s['st_info']['type'] == 'STT_OBJECT' and s['st_size']:
                idx.setdefault(s['st_shndx'], []).append((s['st_value'], s['st_size']))
        obj._rc_cover_idx = idx
    return idx


def _rc_secdata(obj, shndx):
    # RC (performance): read each section of an object once and cache the bytes.
    cache = getattr(obj, '_rc_secdata_cache', None)
    if cache is None:
        cache = {}
        obj._rc_secdata_cache = cache
    if shndx not in cache:
        cache[shndx] = obj.elf.get_section(shndx).data()
    return cache[shndx]


def rc_same(lm, lr) -> bool:
    """v1.4 RC: the module target is an anonymous .rodata offset and its bytes equal the reference target's bytes
    over the reference target's extent (string up to and including NUL, or the symbol's size)."""
    if not (isinstance(lm, Label) and isinstance(lr, Label)) or lm.shndx is None or lr.shndx is None:
        return False
    if not str(lm).startswith("sec:.rodata"):
        return False
    msec, rsec = lm.obj.elf.get_section(lm.shndx), lr.obj.elf.get_section(lr.shndx)
    if not msec.name.startswith(".rodata") or rsec["sh_type"] == "SHT_NOBITS":
        return False
    rdata = _rc_secdata(lr.obj, lr.shndx)
    size = lr.size
    if not size:   # section-relative target: the reference object that covers it gives the extent
        for st_value, st_size in _rc_index(lr.obj).get(lr.shndx, ()):
            if st_value <= lr.pos < st_value + st_size:
                size = st_value + st_size - lr.pos
                break
    if size:
        want = rdata[lr.pos:lr.pos + size]
    elif str(lr).startswith('str:"') or rsec.name.startswith(".rodata.str") or (rsec["sh_flags"] & SH_FLAGS.SHF_STRINGS):
        end = rdata.find(b"\0", lr.pos)
        want = rdata[lr.pos:end + 1] if end >= 0 else b""
    else:
        return False
    if not want:
        return False
    mdata = _rc_secdata(lm.obj, lm.shndx)
    return mdata[lm.pos:lm.pos + len(want)] == want


def compare(mod: Obj, refs: list[Obj], only: set[str] | None, vmlinux: str | None = None,
            modules_dir: str | None = None) -> dict:
    mfuncs = mod.functions()
    rfuncs: dict[str, tuple[Obj, tuple[int, int, int]]] = {}
    rall: dict[str, list[tuple[Obj, tuple[int, int, int]]]] = {}
    for r in refs:
        for name, loc in r.functions().items():
            rfuncs.setdefault(name, (r, loc))
            rall.setdefault(name, []).append((r, loc))
    common = sorted(n for n in mfuncs if n in rfuncs and (only is None or n in only))
    rows_m, rows_r = {}, {}
    dup_pairings = []
    for name in common:
        rows_m[name] = [(t, x) for _, t, x in mod.relocs_in(*mfuncs[name])]
        cands = rall[name] if "DUP" not in DISABLED else rall[name][:1]
        best = None
        for r_obj, r_loc in cands:
            rr = [(t, x) for _, t, x in r_obj.relocs_in(*r_loc)]
            if "ALT" not in DISABLED:
                rr_alt = rr + r_obj.alt_rows(*r_loc)
            else:
                rr_alt = rr
            mm = Counter(rows_m[name] + (mod.alt_rows(*mfuncs[name]) if "ALT" not in DISABLED else []))
            dist = sum(((mm - Counter(rr_alt)) + (Counter(rr_alt) - mm)).values())
            if best is None or dist < best[0]:
                best = (dist, r_obj, r_loc, rr)
        _, r_obj, r_loc, rows_r[name] = best
        if len(cands) > 1:
            dup_pairings.append({"function": name, "candidates": [str(c[0].path) for c in cands], "chosen": str(r_obj.path)})
        rfuncs[name] = (r_obj, r_loc)
        if "ALT" not in DISABLED:
            rows_m[name] += mod.alt_rows(*mfuncs[name])
            rows_r[name] += rfuncs[name][0].alt_rows(*rfuncs[name][1])
    raw_m = {n: list(rs) for n, rs in rows_m.items()}
    raw_r = {n: list(rs) for n, rs in rows_r.items()}
    if "N3M" not in DISABLED and "N3" not in DISABLED:
        own = mod.module_name()
        def split(x):
            m = PRFMT.match(x[5:-1]) if x.startswith('str:"') else None
            return (m.group(0)[len(m.group(1)):-2], x[5:5 + len(m.group(1))], x[5 + m.end():-1]) if m else None
        rest_own = set()
        for rs in rows_m.values():
            for _, x in rs:
                p = split(x)
                if p and own and p[0] == own:
                    rest_own.add((p[1], p[2]))
        def canon(x, is_module):
            p = split(x)
            if not p or not own:
                return x
            word, lvl, rest = p
            if word == own or (not is_module and (lvl, rest) in rest_own):
                return f'str:"{lvl}<pfx>: {rest}"'
            return x
        rows_m = {n: [(t, canon(x, True)) for t, x in rs] for n, rs in rows_m.items()}
        rows_r = {n: [(t, canon(x, False)) for t, x in rs] for n, rs in rows_r.items()}
    results = []
    for name in common:
        m_seq = rows_m[name]
        r_seq = rows_r[name]
        m_ms, r_ms = Counter(m_seq), Counter(r_seq)
        results.append({
            "function": name,
            "n_mod": len(m_seq), "n_ref": len(r_seq),
            "multiset_equal": m_ms == r_ms,
            "sequence_equal": m_seq == r_seq,
            "only_in_module": sorted(f"{t}:{x}" for t, x in (m_ms - r_ms).elements()),
            "only_in_reference": sorted(f"{t}:{x}" for t, x in (r_ms - m_ms).elements()),
        })
    rc_pairs = 0
    if "RC" not in DISABLED:
        for res in results:
            if res["multiset_equal"] and res["sequence_equal"]:
                continue
            n = res["function"]
            cm, cr, rm, rr = rows_m[n], rows_r[n], raw_m[n], raw_r[n]
            if len(cm) != len(cr):
                continue
            k, ok = 0, True
            for i in range(len(cm)):
                if cm[i] == cr[i]:
                    continue
                if cm[i][0] == cr[i][0] and rc_same(rm[i][1], rr[i][1]):
                    k += 1
                    continue
                ok = False
                break
            if ok:
                res.update(multiset_equal=True, sequence_equal=True, only_in_module=[], only_in_reference=[], rc_pairs=k)
                rc_pairs += k
    rf_pairs = 0
    if "RF" not in DISABLED:
        for res in results:
            if res["multiset_equal"] and res["sequence_equal"]:
                continue
            om = res.get("only_in_module") or []
            oref = res.get("only_in_reference") or []
            if oref:
                continue
            if res.get("n_mod") != res.get("n_ref", -1) + 1:
                continue
            if om == ["PC32:__fentry__"]:
                res.update(multiset_equal=True, sequence_equal=True, only_in_module=[], only_in_reference=[], rf_pairs=1)
                rf_pairs += 1
    SCAFFOLD = {"init_module", "cleanup_module", "__pfx_init_module", "__pfx_cleanup_module"}
    scaffolding_divergences = []
    rs_excluded = 0
    if "RS" not in DISABLED:
        kept = []
        for res in results:
            if res["function"] in SCAFFOLD:
                if not (res["multiset_equal"] and res["sequence_equal"]):
                    scaffolding_divergences.append(res)
                    rs_excluded += 1
                # drop from fidelity results whether equal or not
                continue
            kept.append(res)
        results = kept
    mod_cc = mod.compilers()
    ref_cc = set().union(*(r.compilers() for r in refs)) if refs else set()
    toolchain_ok = "T1" in DISABLED or not mod_cc or not ref_cc or bool(mod_cc & ref_cc)
    verdict = lambda key: ("INCONCLUSIVE_TOOLCHAIN" if not toolchain_ok else
                           ("CONSISTENT" if results and all(r[key] for r in results) else
                            ("DIVERGENT" if results else "NO_COMMON_FUNCTIONS")))
    rfiles = {name: r_obj.source_file() for name, (r_obj, _) in rfuncs.items()}
    p1 = sympos_check(mod, rfiles, vmlinux, modules_dir)
    seq_v = verdict("sequence_equal")
    order = ["DIVERGENT", "LOAD_FAIL", "INCONCLUSIVE_TOOLCHAIN", "NO_COMMON_FUNCTIONS", "INCONCLUSIVE", "CONSISTENT"]
    p1v = p1["sympos_verdict"] if p1["sympos_verdict"] in order else "CONSISTENT"
    return {
        "overall_verdict": min((seq_v, p1v), key=order.index),
        **p1,
        "module_compilers": sorted(mod_cc),
        "reference_compilers": sorted(ref_cc),
        "multiset_verdict": verdict("multiset_equal"),
        "sequence_verdict": verdict("sequence_equal"),
        "module": str(mod.path),
        "references": [str(r.path) for r in refs],
        "functions_compared": len(results),
        "compared_functions": sorted({r["function"] for r in results}),
        "oracle_version": "1.7",
        "arch": "aarch64" if mod.aarch64 else "x86-64",
        "unknown_reloc_types": mod.saw_unknown_reloc or any(r.saw_unknown_reloc for r in refs),
        "rc_pairs": rc_pairs,
        "rf_pairs": rf_pairs,
        "rs_excluded": rs_excluded,
        "scaffolding_divergences": scaffolding_divergences,
        "dup_pairings": dup_pairings,
        "n4_active": "N4" not in DISABLED and capstone is not None,
        "n4_fallbacks": mod.n4_fallbacks + sum(r.n4_fallbacks for r in refs),
        "functions_in_module_not_in_reference": sorted(set(mfuncs) - set(rfuncs)),
        "divergent_functions": [r for r in results if not (r["multiset_equal"] and r["sequence_equal"])],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("module")
    ap.add_argument("refs", nargs="+")
    ap.add_argument("--functions", help="comma-separated function names to compare (default: all common)")
    ap.add_argument("--mode", choices=("multiset", "sequence", "overall"), default="multiset",
                    help="mode that sets the exit code")
    ap.add_argument("--vmlinux", default=os.environ.get("LPFID_VMLINUX"), help="pin vmlinux for the P1 sympos check")
    ap.add_argument("--modules-dir", default=os.environ.get("LPFID_MODULES_DIR"),
                    help="pin build tree, for klp symbols in modules (P1)")
    a = ap.parse_args()
    if "N4" not in DISABLED and capstone is None:
        print(json.dumps({"error": "N4 needs capstone (pip install capstone==5.0.7) or LPFID_DISABLE=N4"}))
        return 2
    try:
        mod = Obj(Path(a.module))
        refs = [Obj(Path(p)) for p in a.refs]
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": str(e)}))
        return 2
    only = set(a.functions.split(",")) if a.functions else None
    out = compare(mod, refs, only, a.vmlinux, a.modules_dir)
    print(json.dumps(out, indent=1))
    verdict = out[f"{a.mode}_verdict"]
    return 0 if verdict == "CONSISTENT" else (1 if verdict == "DIVERGENT" else 2)  # 2 = inconclusive or error


if __name__ == "__main__":
    raise SystemExit(main())
