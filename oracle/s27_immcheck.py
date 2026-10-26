#!/usr/bin/env python3
"""S27 immediate-multiset check (one level below the binding oracle).

For every function present in both the module and the independent reference (exact-name match, exactly
as blind-reloc-oracle.py compare() pairs them), collect the multiset and the offset-ordered sequence of
instruction-immediate operand VALUES that overlap no relocation field. Relocation-covered bytes are the
binding oracle's domain and are excluded here. Control-transfer instructions (call/j*/ret/nop/endbr/...)
are skipped, matching the domain the `constant` mutation operator perturbs (lpfid-mutate.py). A function
diverges when the multiset (multiset mode) or the ordered sequence (sequence mode) differs.

Normalisation is a minimal, switch-offable rule set frozen on fixtures before any real scoring
(S27-PREREG). Disable individual rules for the ablation with S27_DISABLE=IMM-FRAME,...

Reuses Obj from blind-reloc-oracle.py for ELF parsing, function ranges and relocation extraction, so the
two checks see identical function boundaries and identical relocation coverage.
"""
import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path

import capstone as cap

ORACLE_DIR = os.environ.get("S27_ORACLE_DIR", "/opt/atlas/s2test")
_spec = importlib.util.spec_from_file_location("bro", os.path.join(ORACLE_DIR, "blind-reloc-oracle.py"))
_bro = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_bro)
Obj = _bro.Obj

# Relocation field widths in bytes, keyed by the RTYPE names blind-reloc-oracle.py reports.
RTYPE_WIDTH = {"PC32": 4, "PLT32": 4, "GOTPCREL": 4, "GOTPCRELX": 4, "REX_GOTPCRELX": 4,
               "32": 4, "32S": 4, "64": 8, "PC64": 8, "16": 2, "8": 1}
# Control-transfer / no-operand mnemonics excluded from the immediate domain (matches the mutator).
CF_PREFIX = ("call", "j", "ret", "nop", "endbr", "loop", "iret", "syscall", "sysret", "int", "ud2", "hlt")

DISABLED = set(filter(None, os.environ.get("S27_DISABLE", "").split(",")))

_md = cap.Cs(cap.CS_ARCH_X86, cap.CS_MODE_64)
_md.detail = True


def _covered(obj, loc):
    """Relocation byte ranges within a function, as [start_rel, end_rel) offsets relative to the function."""
    out = []
    for off_rel, rtype, _tgt in obj.relocs_in(*loc):
        out.append((off_rel, off_rel + RTYPE_WIDTH.get(rtype, 4)))
    return out


def _overlaps(io, iw, ranges):
    for a, b in ranges:
        if io < b and a < io + iw:
            return True
    return False


def _keep(ins, _imm):
    """Frozen normalisation. True = count this immediate; False = normalise it away."""
    if "IMM-FRAME" not in DISABLED:
        # Stack-frame adjustment immediates (sub/add rsp|esp, N) carry a frame size, not a program constant.
        ops = ins.operands
        if ins.mnemonic in ("sub", "add") and ops and ops[0].type == cap.x86.X86_OP_REG \
                and ins.reg_name(ops[0].reg) in ("rsp", "esp"):
            return False
    return True


def immediates(obj):
    """name -> {'ms': Counter(value->n), 'seq': [value...], 'decoded': bool}."""
    out = {}
    for name, loc in obj.functions().items():
        shndx, start, size = loc
        sec = obj.elf.get_section(shndx)
        data = sec.data()[start:start + size]
        ranges = _covered(obj, loc)
        ms, seq = Counter(), []
        consumed = 0
        for ins in _md.disasm(data, 0):
            consumed = ins.address + ins.size
            if ins.mnemonic.startswith(CF_PREFIX):
                continue
            enc = ins.encoding
            io, iw = ins.address + enc.imm_offset, enc.imm_size  # function-relative immediate byte range
            for o in ins.operands:
                if o.type != cap.x86.X86_OP_IMM:
                    continue
                if iw and _overlaps(io, iw, ranges):
                    continue  # relocation-covered: binding oracle's domain
                if not _keep(ins, o.imm):
                    continue
                ms[o.imm] += 1
                seq.append((ins.address, o.imm))
        seq.sort()
        out[name] = {"ms": ms, "seq": [v for _, v in seq], "decoded": consumed >= size}
    return out


def compare(mod, refs):
    """Mirror blind-reloc-oracle.py compare() pairing, over immediates instead of relocations."""
    mimm = immediates(mod)
    rimm = {}
    for r in refs:
        for name, d in immediates(r).items():
            rimm.setdefault(name, d)
    common = sorted(n for n in mimm if n in rimm)
    results, undecoded = [], []
    for name in common:
        m, r = mimm[name], rimm[name]
        if not (m["decoded"] and r["decoded"]):
            undecoded.append(name)
        ms_eq = m["ms"] == r["ms"]
        seq_eq = m["seq"] == r["seq"]
        if not (ms_eq and seq_eq):
            results.append({
                "function": name, "n_mod": sum(m["ms"].values()), "n_ref": sum(r["ms"].values()),
                "multiset_equal": ms_eq, "sequence_equal": seq_eq,
                "only_in_module": sorted((Counter(m["ms"]) - Counter(r["ms"])).elements()),
                "only_in_reference": sorted((Counter(r["ms"]) - Counter(m["ms"])).elements()),
            })
    mod_cc, ref_cc = mod.compilers(), set().union(*(r.compilers() for r in refs)) if refs else set()
    toolchain_ok = "T1" in DISABLED or not mod_cc or not ref_cc or bool(mod_cc & ref_cc)

    # `results` holds only the divergent functions, so "all consistent" == no divergent function.
    ms_v = "CONSISTENT" if (toolchain_ok and common and not any(not d["multiset_equal"] for d in results)) \
        else ("DIVERGENT" if (toolchain_ok and common and any(not d["multiset_equal"] for d in results))
              else ("NO_COMMON_FUNCTIONS" if toolchain_ok and not common else "INCONCLUSIVE_TOOLCHAIN"))
    seq_v = "CONSISTENT" if (toolchain_ok and common and not any(not d["sequence_equal"] for d in results)) \
        else ("DIVERGENT" if (toolchain_ok and common and any(not d["sequence_equal"] for d in results))
              else ("NO_COMMON_FUNCTIONS" if toolchain_ok and not common else "INCONCLUSIVE_TOOLCHAIN"))
    return {
        "module": str(mod.path), "references": [str(r.path) for r in refs],
        "module_compilers": sorted(mod_cc), "reference_compilers": sorted(ref_cc),
        "multiset_verdict": ms_v, "sequence_verdict": seq_v,
        "functions_compared": len(common),
        "functions_in_module_not_in_reference": sorted(set(mimm) - set(rimm)),
        "undecoded_functions": undecoded,
        "divergent_functions": results,
    }


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("module")
    ap.add_argument("refs", nargs="+")
    ap.add_argument("--mode", choices=("multiset", "sequence"), default="multiset")
    a = ap.parse_args()
    try:
        mod = Obj(Path(a.module))
        refs = [Obj(Path(p)) for p in a.refs]
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": str(e)}))
        return 2
    out = compare(mod, refs)
    print(json.dumps(out, indent=1))
    return 0 if out[f"{a.mode}_verdict"] == "CONSISTENT" else 1


if __name__ == "__main__":
    sys.exit(main())
