#!/usr/bin/env python3
"""S11: severity of the 62 wrong string pointers in the 7 klp-build modules (objtool elf_add_data bug).
For each pointer: the intended string (reference), the bytes the module actually points at (up to the next NUL),
and the printf conversion specifiers of both, so a pointer that changes the specifier sequence (printk would
consume its arguments differently) is separated from one that only changes text.
Reads /opt/atlas/s12/oracle/s11-klp-rind-v13-rodata-offsets.json; writes s11-klp-string-severity.json.
Run with the oracle venv on the build host.
"""
import glob
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/opt/atlas/s12")
import klp_rind_equiv as E  # noqa: E402

# printf conversions as the kernel's vsnprintf reads them (flags, width, precision, length, conversion);
# %p is followed by an optional extension letter group (pI4, pS, pV, ...), %% is a literal.
SPEC = re.compile(r"%(?:%|[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|z|t|j|L)?([diouxXcspn])([A-Za-z0-9]*)?)")


def specs(s: str) -> list[str]:
    out = []
    for m in SPEC.finditer(s):
        if m.group(0) == "%%":
            continue
        conv = m.group(1)
        star = m.group(0).count("*")
        out += ["*"] * star + [conv + (m.group(2)[:2] if conv == "p" and m.group(2) else "")]
    return out


def cstr(data: bytes, pos: int) -> str:
    end = data.find(b"\0", pos)
    return data[pos:end if end >= 0 else len(data)].decode("latin-1")


rows = json.load(open("/opt/atlas/s12/oracle/s11-klp-rind-v13-rodata-offsets.json"))["rows"]
out, tally = [], Counter()
for r in rows:
    if r["kind"] != "RODATA":
        continue
    ko = glob.glob(f"/opt/atlas/s12/results/klp-gcc-13/6.19/{r['cve']}/build/*.ko")[0]
    mod = E.RawObj(Path(ko))
    data = mod.elf.get_section_by_name(".rodata").data()
    landed = cstr(data, int(r["addend"], 16))
    t = r["ref_target"]
    intended = t[5:-1] if t.startswith('str:"') else None
    if intended is None:
        kind = "NON_STRING_TARGET"
    else:
        si, sl = specs(intended), specs(landed)
        if not si and not sl:
            kind = "TEXT_ONLY_NO_SPECIFIERS"
        elif si == sl:
            kind = "TEXT_ONLY_SAME_SPECIFIERS"
        elif sl == si[len(si) - len(sl):] if sl else False:
            kind = "SPECIFIERS_DROPPED_FROM_FRONT"
        else:
            kind = "SPECIFIERS_CHANGED"
    tally[kind] += 1
    out.append({**r, "intended": intended, "landed": landed, "kind": kind,
                "intended_specs": specs(intended) if intended else None, "landed_specs": specs(landed)})
json.dump({"tally": dict(tally), "rows": out}, open("/opt/atlas/s12/oracle/s11-klp-string-severity.json", "w"), indent=1)
print(dict(tally))
for o in out:
    if o["kind"] not in ("TEXT_ONLY_SAME_SPECIFIERS", "TEXT_ONLY_NO_SPECIFIERS"):
        print(o["cve"], o["function"], o["site"], o["kind"], o["intended_specs"], "->", o["landed_specs"])
        print("   intended:", repr(o["intended"])[:110])
        print("   landed:  ", repr(o["landed"])[:110])
