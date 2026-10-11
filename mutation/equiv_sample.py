#!/usr/bin/env python3
"""Mechanical check of section 4.3 (3): a seeded random sample of 30 detected real-fix addend mutants. For each,
the instruction that holds the shifted relocation is decoded (capstone) and classified by how it uses the address:
read (memory operand read), write (memory operand written), address (lea or immediate, the address is computed
and passed on), or other. An addend mutant whose relocation sits in a read or write moves the access to another
location 8 bytes away and is not equivalent; one whose address is only computed is not equivalent unless the
value is never used, which this check cannot see and reports apart.

Usage (build host, lpfid venv): python3 equiv_sample.py S2JSON OUT.json
"""
import json
import random
import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM
from elftools.elf.elffile import ELFFile

s2 = json.load(open(sys.argv[1]))["rows"]
cands = []
for r in s2:
    if r["set"] != "s12":
        continue
    for m in r["mutants"]:
        if m["op"] == "addend" and m.get("built") and not m.get("noop") and not m.get("duplicate_of") \
                and m.get("v1.1", {}).get("overall") == "DIVERGENT":
            cands.append(m)
sample = random.Random(20261010).sample(cands, 30)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
out = []
for m in sample:
    site = m["site"]
    with open(m["path"], "rb") as f:
        e = ELFFile(f)
        rs = e.get_section_by_name(site["rela"])
        rel = list(rs.iter_relocations())[site["i"]]
        text = e.get_section(rs["sh_info"])
        data = text.data()
        off = rel["r_offset"]
        kind, insn_txt = "other", None
        for start in range(max(0, off - 15), off + 1):
            for insn in md.disasm(data[start:start + 16], start):
                if insn.address <= off < insn.address + insn.size:
                    insn_txt = f"{insn.mnemonic} {insn.op_str}"
                    if insn.mnemonic.startswith("lea") or not any(op.type == X86_OP_MEM for op in insn.operands):
                        kind = "address"
                    else:
                        regs_read, regs_write = insn.regs_access()
                        dst = insn.operands[0]
                        kind = "write" if dst.type == X86_OP_MEM and insn.mnemonic.startswith(("mov", "add", "sub", "or", "and", "inc", "dec", "xchg")) else "read"
                break
            if insn_txt:
                break
    out.append({"path": m["path"], "function": site["function"], "target": site["target"], "insn": insn_txt, "kind": kind})
from collections import Counter
summary = dict(Counter(o["kind"] for o in out))
json.dump({"population": len(cands), "sample": 30, "seed": 20261010, "kinds": summary, "rows": out}, open(sys.argv[2], "w"), indent=1)
print(len(cands), summary)
