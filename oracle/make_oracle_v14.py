#!/usr/bin/env python3
"""Derive blind-reloc-oracle-v1.4.py from the frozen v1.3 (S16 Deviation 4). Edits are exact-match replacements;
the script fails if any anchor is missing, so the result is v1.3 plus the listed changes and nothing else."""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
src = (HERE / "blind-reloc-oracle-v1.3.py").read_bytes().decode()
assert hashlib.sha256(src.encode()).hexdigest() == "c6add9ab14d994cf6d7920ff6d6820840c9fa554001727865990957b9e200133", "v1.3 hash"

HEADER = '''"""Blind reference-differential relocation oracle for livepatch modules, v1.4.

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

'''

edits = [
    # header
    ('"""Blind reference-differential relocation oracle for livepatch modules, v1.3.\n', HEADER + "Blind reference-differential relocation oracle for livepatch modules, v1.3.\n"),
    # label type that remembers where the target bytes are
    ("def norm_name(name: str) -> str:\n",
     'BUG_LABEL = re.compile(r"^(sec:)?__bug_table(_\\d+)?([+-]0x[0-9a-f]+)?$")\n\n\n'
     "class Label(str):\n"
     '    """A target label that also records where the target bytes are (v1.4 RC); compares as the plain label."""\n'
     "    obj = None\n    shndx = None\n    pos = None\n    size = None\n\n\n"
     "def norm_name(name: str) -> str:\n"),
    # target(): keep v1.3 as _target_v13, wrap it
    ("    def target(self, sym, addend: int, rtype: int = 0, tail: int = 4) -> str:\n",
     "    def target(self, sym, addend: int, rtype: int = 0, tail: int = 4) -> str:\n"
     "        label = self._target_v13(sym, addend, rtype, tail)\n"
     '        if "RB" not in DISABLED and BUG_LABEL.match(label):\n'
     '            label = "__bug_table"\n'
     "        lab = Label(label)\n"
     "        lab.obj = self\n"
     "        off = addend + tail if rtype in PC_REL else addend\n"
     '        shndx = sym["st_shndx"]\n'
     "        if isinstance(shndx, int) and 0 < shndx < self.elf.num_sections():\n"
     "            lab.shndx = shndx\n"
     '            if sym["st_info"]["type"] == "STT_SECTION":\n'
     "                lab.pos = off\n"
     "            else:\n"
     '                lab.pos = sym["st_value"] + off\n'
     '                lab.size = sym["st_size"] - off if sym["st_size"] > off else None\n'
     "        return lab\n\n"
     "    def _target_v13(self, sym, addend: int, rtype: int = 0, tail: int = 4) -> str:\n"),
    # R0 in relocs_in
    ("                off = r[\"r_offset\"]\n                if not (start <= off < start + size):\n                    continue\n",
     "                off = r[\"r_offset\"]\n                if not (start <= off < start + size):\n                    continue\n"
     '                if r["r_info_type"] == 0 and "R0" not in DISABLED:   # v1.4 R0: R_X86_64_NONE has no effect\n'
     "                    continue\n"),
    # keep raw rows before N3M canonicalisation
    ('    if "N3M" not in DISABLED and "N3" not in DISABLED:\n        own = mod.module_name()\n',
     "    raw_m = {n: list(rs) for n, rs in rows_m.items()}\n    raw_r = {n: list(rs) for n, rs in rows_r.items()}\n"
     '    if "N3M" not in DISABLED and "N3" not in DISABLED:\n        own = mod.module_name()\n'),
    # RC after the per-function results
    ("    mod_cc = mod.compilers()\n",
     '    rc_pairs = 0\n    if "RC" not in DISABLED:\n'
     "        for res in results:\n"
     '            if res["multiset_equal"] and res["sequence_equal"]:\n                continue\n'
     '            n = res["function"]\n'
     "            cm, cr, rm, rr = rows_m[n], rows_r[n], raw_m[n], raw_r[n]\n"
     "            if len(cm) != len(cr):\n                continue\n"
     "            k, ok = 0, True\n"
     "            for i in range(len(cm)):\n"
     "                if cm[i] == cr[i]:\n                    continue\n"
     "                if cm[i][0] == cr[i][0] and rc_same(rm[i][1], rr[i][1]):\n                    k += 1\n                    continue\n"
     "                ok = False\n                break\n"
     "            if ok:\n"
     '                res.update(multiset_equal=True, sequence_equal=True, only_in_module=[], only_in_reference=[], rc_pairs=k)\n'
     "                rc_pairs += k\n"
     "    mod_cc = mod.compilers()\n"),
    ('        "oracle_version": "1.3",\n', '        "oracle_version": "1.4",\n        "rc_pairs": rc_pairs,\n'),
    # rc_same helper before compare()
    ("def compare(mod: Obj, refs: list[Obj], only: set[str] | None, vmlinux: str | None = None,\n",
     "def rc_same(lm, lr) -> bool:\n"
     '    """v1.4 RC: the module target is an anonymous .rodata offset and its bytes equal the reference target\'s bytes\n'
     "    over the reference target's extent (string up to and including NUL, or the symbol's size).\"\"\"\n"
     "    if not (isinstance(lm, Label) and isinstance(lr, Label)) or lm.shndx is None or lr.shndx is None:\n        return False\n"
     '    if not str(lm).startswith("sec:.rodata"):\n        return False\n'
     "    msec, rsec = lm.obj.elf.get_section(lm.shndx), lr.obj.elf.get_section(lr.shndx)\n"
     '    if not msec.name.startswith(".rodata") or rsec["sh_type"] == "SHT_NOBITS":\n        return False\n'
     "    rdata = rsec.data()\n"
     "    size = lr.size\n"
     "    if not size:   # section-relative target: the reference object that covers it gives the extent\n"
     "        for s in lr.obj.syms:\n"
     '            if s["st_shndx"] == lr.shndx and s["st_info"]["type"] == "STT_OBJECT" and s["st_size"] \\\n'
     '                    and s["st_value"] <= lr.pos < s["st_value"] + s["st_size"]:\n'
     '                size = s["st_value"] + s["st_size"] - lr.pos\n'
     "                break\n"
     "    if size:\n        want = rdata[lr.pos:lr.pos + size]\n"
     '    elif str(lr).startswith(\'str:"\') or rsec.name.startswith(".rodata.str") or (rsec["sh_flags"] & SH_FLAGS.SHF_STRINGS):\n'
     '        end = rdata.find(b"\\0", lr.pos)\n'
     "        want = rdata[lr.pos:end + 1] if end >= 0 else b\"\"\n"
     "    else:\n        return False\n"
     "    if not want:\n        return False\n"
     "    mdata = msec.data()\n"
     "    return mdata[lm.pos:lm.pos + len(want)] == want\n\n\n"
     "def compare(mod: Obj, refs: list[Obj], only: set[str] | None, vmlinux: str | None = None,\n"),
]
out = src
for old, new in edits:
    if out.count(old) != 1:
        sys.exit(f"anchor not unique or missing ({out.count(old)}): {old[:70]!r}")
    out = out.replace(old, new)
(HERE / "blind-reloc-oracle-v1.4.py").write_text(out, newline="")
print("v1.4 sha256", hashlib.sha256(out.encode()).hexdigest())
