#!/usr/bin/env python3
"""Make blind-reloc-oracle-v1.5.py from v1.4 by adding rule RF (S34 deviation)."""
from __future__ import annotations

import hashlib
import pathlib
import sys

SRC = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/atlas/lpfid/blind-reloc-oracle-v1.4.py")
DST = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "/opt/atlas/lpfid/blind-reloc-oracle-v1.5.py")

text = SRC.read_text(encoding="utf-8")
h = hashlib.sha256(text.encode()).hexdigest()

# 1) Extend the opening docstring with RF (keep it inside the existing triple-quoted string).
old_open = '"""Blind reference-differential relocation oracle for livepatch modules, v1.4.'
new_open = (
    '"""Blind reference-differential relocation oracle for livepatch modules, v1.5.\n\n'
    "v1.5 = the frozen v1.4 plus one rule, added by a dated deviation in S34 (15 Oct 2026) after the\n"
    "OpenAnolis 7.7 census showed 27 of 39 patched functions differ only at the fentry probe:\n"
    "  RF  after R0 drops R_X86_64_NONE, if a function's only relocation difference is that the module\n"
    '      has one extra PC32:__fentry__ row (n_mod == n_ref + 1, only_in_module == ["PC32:__fentry__"],\n'
    "      only_in_reference empty), accept the function as equal. The reference's matching NONE to\n"
    "      __fentry__ was dropped by R0; the live call and the five-byte nop are the same probe site.\n"
    "Disable with LPFID_DISABLE=RF. Source v1.4 sha256: "
    + h
    + ".\n\n"
    "v1.4 header follows.\n\n"
    "Blind reference-differential relocation oracle for livepatch modules, v1.4."
)
if old_open not in text:
    sys.exit("v1.4 opening docstring not found")
text = text.replace(old_open, new_open, 1)

# 2) Insert RF pass after RC.
needle = """            if ok:
                res.update(multiset_equal=True, sequence_equal=True, only_in_module=[], only_in_reference=[], rc_pairs=k)
                rc_pairs += k
    mod_cc = mod.compilers()"""

insert = """            if ok:
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
    mod_cc = mod.compilers()"""

if needle not in text:
    sys.exit("RC insertion point not found")
text = text.replace(needle, insert, 1)

text = text.replace('"oracle_version": "1.4"', '"oracle_version": "1.5"', 1)
text = text.replace('"rc_pairs": rc_pairs,', '"rc_pairs": rc_pairs,\n        "rf_pairs": rf_pairs,', 1)

DST.write_text(text, encoding="utf-8")
# compile check
compile(text, str(DST), "exec")
print("wrote", DST, "ok compile; v1.4 sha256", h)
