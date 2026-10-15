#!/usr/bin/env python3
"""Make blind-reloc-oracle-v1.6.py from v1.5 by adding rule RS (scaffolding scope)."""
from __future__ import annotations

import hashlib
import pathlib
import sys

SRC = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/atlas/lpfid/blind-reloc-oracle-v1.5.py")
DST = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "/opt/atlas/lpfid/blind-reloc-oracle-v1.6.py")

text = SRC.read_text(encoding="utf-8")
h = hashlib.sha256(text.encode()).hexdigest()

old_open = '"""Blind reference-differential relocation oracle for livepatch modules, v1.5.'
new_open = (
    '"""Blind reference-differential relocation oracle for livepatch modules, v1.6.\n\n'
    "v1.6 = the frozen v1.5 plus one rule, added by a dated deviation after the S26 Amazon draw\n"
    "showed 57 of 58 DIVERGENT modules differed only in loader scaffolding:\n"
    "  RS  after RF, functions named init_module, cleanup_module, __pfx_init_module or\n"
    "      __pfx_cleanup_module are excluded from the overall / multiset / sequence verdicts\n"
    "      (still listed under scaffolding_divergences when they would have been divergent).\n"
    "      Livepatch modules carry klp registration under those names; pairing them with a\n"
    "      patched object's own init/exit is the scaffolding class of Sections 7.2 and 7.6.\n"
    "Disable with LPFID_DISABLE=RS. Source v1.5 sha256: "
    + h
    + ".\n\n"
    "v1.5 header follows.\n\n"
    "Blind reference-differential relocation oracle for livepatch modules, v1.5."
)
if old_open not in text:
    sys.exit("v1.5 opening docstring not found")
text = text.replace(old_open, new_open, 1)

needle = """            if om == ["PC32:__fentry__"]:
                res.update(multiset_equal=True, sequence_equal=True, only_in_module=[], only_in_reference=[], rf_pairs=1)
                rf_pairs += 1
    mod_cc = mod.compilers()"""

insert = """            if om == ["PC32:__fentry__"]:
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
    mod_cc = mod.compilers()"""

if needle not in text:
    sys.exit("RF insertion point not found")
text = text.replace(needle, insert, 1)

# Verdict already uses `results`; after RS it is scaffolding-free.
text = text.replace('"oracle_version": "1.5"', '"oracle_version": "1.6"', 1)
text = text.replace(
    '"rf_pairs": rf_pairs,',
    '"rf_pairs": rf_pairs,\n        "rs_excluded": rs_excluded,\n        "scaffolding_divergences": scaffolding_divergences,',
    1,
)

# Ensure locals exist when RS disabled
# After insert, rs_excluded and scaffolding_divergences only set inside `if RS` block when RS not disabled.
# When RS IS disabled, we never define them — fix by always initializing before the if.
# Already initialized before `if "RS" not in DISABLED`. Good.

DST.write_text(text, encoding="utf-8")
compile(text, str(DST), "exec")
print("wrote", DST, "ok compile; v1.5 sha256", h)
