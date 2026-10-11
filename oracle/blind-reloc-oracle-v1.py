#!/usr/bin/env python3
"""Blind reference-differential relocation oracle for livepatch modules.

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

# Normalisation rules, frozen before any real-fix evaluation (S16). Each can be
# disabled for the ablation (S15) through LPFID_DISABLE=N1,N2,... in the environment.
import os
DISABLED = set(filter(None, os.environ.get("LPFID_DISABLE", "").split(",")))


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
        self.symtab: SymbolTableSection = self.elf.get_section_by_name(".symtab")
        self.syms = list(self.symtab.iter_symbols()) if self.symtab else []

    def source_file(self) -> str | None:
        """Basename of the first STT_FILE symbol (the translation unit of a single-TU object)."""
        for s in self.syms:
            if s["st_info"]["type"] == "STT_FILE" and s.name:
                return os.path.basename(s.name)
        return None

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

    def _symbol_at(self, shndx: int, off: int) -> tuple[str, int] | None:
        """(name, start) of the FUNC/OBJECT symbol in section shndx that covers offset off."""
        best = None
        for s in self.syms:
            if s["st_shndx"] != shndx or s["st_info"]["type"] not in ("STT_FUNC", "STT_OBJECT"):
                continue
            start, size = s["st_value"], s["st_size"]
            if start == off or (size and start <= off < start + size):
                if best is None or s["st_value"] == off:
                    best = (s.name, start)
        return best

    @staticmethod
    def _with_offset(name: str, delta: int) -> str:
        """A1: the offset inside the target is part of the binding (sym+8 is not sym+0)."""
        if "A1" in DISABLED or delta == 0:
            return name
        return f"{name}{delta:+#x}"

    def target(self, sym, addend: int, rtype: int = 0) -> str:
        # Effective offset into the target: PC-relative relocations carry -4 in the addend.
        off = addend + 4 if rtype in PC_REL else addend
        if sym["st_info"]["type"] == "STT_SECTION":
            sec = self.elf.get_section(sym["st_shndx"])
            fam = section_family(sec.name)
            if sec.name.startswith(".rodata.str") or (sec["sh_flags"] & SH_FLAGS.SHF_STRINGS):
                data = sec.data()
                if 0 <= off < len(data):
                    text = read_cstring(data, off)
                    if "N3" not in DISABLED:      # N3: pr_fmt module-name prefix
                        text = PRFMT.sub(r"\1<pfx>: ", text)
                    return f'str:"{text}"'
            if "N2" not in DISABLED:                  # N2: section+offset -> symbol it points at
                hit = self._symbol_at(sym["st_shndx"], off)
                if hit:
                    return self._with_offset(norm_name(hit[0]), off - hit[1])
            return self._with_offset(f"sec:{fam}", off)
        return self._with_offset(norm_name(sym.name), off)

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

    def relocs_in(self, shndx: int, start: int, size: int) -> list[tuple[int, str, str]]:
        """(offset, type, target) for relocations applying to [start, start+size) of section shndx."""
        rows = []
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
            if tgt_idx != shndx:
                continue
            for r in sec.iter_relocations():
                off = r["r_offset"]
                if not (start <= off < start + size):
                    continue
                sym = self.syms[r["r_info_sym"]]
                t = self.target(sym, r["r_addend"], r["r_info_type"])
                if t in IGNORE_TARGETS:
                    continue
                rows.append((off - start, RTYPE.get(r["r_info_type"], str(r["r_info_type"])), t))
        rows.sort()
        return rows


_SYMINDEX: dict = {}


def symbol_index(path: str, by_address: bool) -> dict:
    """name -> [(address, source file basename or None for globals)] in kallsyms order.
    vmlinux: kallsyms is sorted by address. Modules: module kallsyms follow the symtab order."""
    if path in _SYMINDEX:
        return _SYMINDEX[path]
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


def compare(mod: Obj, refs: list[Obj], only: set[str] | None, vmlinux: str | None = None,
            modules_dir: str | None = None) -> dict:
    mfuncs = mod.functions()
    rfuncs: dict[str, tuple[Obj, tuple[int, int, int]]] = {}
    for r in refs:
        for name, loc in r.functions().items():
            rfuncs.setdefault(name, (r, loc))
    common = sorted(n for n in mfuncs if n in rfuncs and (only is None or n in only))
    results = []
    for name in common:
        m_rows = mod.relocs_in(*mfuncs[name])
        r_obj, r_loc = rfuncs[name]
        r_rows = r_obj.relocs_in(*r_loc)
        m_seq = [(t, x) for _, t, x in m_rows]
        r_seq = [(t, x) for _, t, x in r_rows]
        m_ms, r_ms = Counter(m_seq), Counter(r_seq)
        results.append({
            "function": name,
            "n_mod": len(m_seq), "n_ref": len(r_seq),
            "multiset_equal": m_ms == r_ms,
            "sequence_equal": m_seq == r_seq,
            "only_in_module": sorted(f"{t}:{x}" for t, x in (m_ms - r_ms).elements()),
            "only_in_reference": sorted(f"{t}:{x}" for t, x in (r_ms - m_ms).elements()),
        })
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
