#!/usr/bin/env python3
"""Address check for alarms classified as one address named two ways (25 Oct 2026).

For one function, resolve every relocation in the module and in the reference to the target it denotes, then compare.
Rules, fixed before any case was run:
  R1  named symbol + addend            -> (symbol name, effective offset); `.klp.sym.<obj>.<name>,<pos>` -> <name>
  R2  section symbol + offset a        -> (symbol of that section whose [value, value+size] contains a, a - value);
                                          a range that contains a strictly wins over one that ends exactly at a
  R3  AArch64 ADRP/ADD lo12 pair       -> one address; an unrelocated `add xd, xd, #imm` on the same register within
                                          the next two instructions is folded into the offset (ADRP entries dropped)
  R4  x86-64 PC-relative               -> effective offset = addend + (instruction end - field offset)
  R6  target in a string section (SHF_STRINGS) -> ("str", the NUL-terminated text at that offset), the binding
                                          check's own string rule (Table 3, "always")
  R5  code target with no symbol       -> its bytes up to and including the first `ud2`, which must hold no
                                          relocation; two such targets are equal when the bytes are equal
The relocation sequence is cut at every call; the address targets loaded between two calls are compared as
multisets, segment by segment, and the calls in order. SAME = every segment equal after resolution.
usage: addr_equiv.py <arch x86_64|aarch64> <function> <module> <reference.o> [label]"""
import json, sys
from collections import Counter
import capstone as cap
from elftools.elf.elffile import ELFFile

ARCH, FN, MOD, REF = sys.argv[1:5]
LABEL = sys.argv[5] if len(sys.argv) > 5 else ""
X86_CALL = {4}                    # PLT32
A64_CALL = {282, 283}             # JUMP26, CALL26
A64_ADRP = {275, 276}             # ADR_PREL_PG_HI21(_NC)
A64_LO12 = {277, 278, 284, 285, 286, 299}   # ADD_ABS_LO12_NC, LDST*_ABS_LO12_NC


def md():
    if ARCH == "x86_64":
        return cap.Cs(cap.CS_ARCH_X86, cap.CS_MODE_64)
    return cap.Cs(cap.CS_ARCH_ARM64, cap.CS_MODE_ARM)


class Obj:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.e = ELFFile(self.f)
        self.syms = list(self.e.get_section_by_name(".symtab").iter_symbols())
        self.md = md()
        self.md.detail = True

    def func(self):
        c = [s for s in self.syms if s.name == FN and s["st_info"]["type"] == "STT_FUNC"
             and isinstance(s["st_shndx"], int) and s["st_size"]]
        if len(c) != 1:
            raise SystemExit(f"{FN}: {len(c)} definitions")
        return c[0]

    def relocs(self, shndx, lo=0, hi=1 << 62):
        out = []
        for sec in self.e.iter_sections():
            if sec["sh_type"] in ("SHT_RELA", "SHT_REL") and sec["sh_info"] == shndx:
                for r in sec.iter_relocations():
                    if lo <= r["r_offset"] < hi:
                        out.append(r)
        return sorted(out, key=lambda r: r["r_offset"])

    def insn_at(self, shndx, off):
        data = self.e.get_section(shndx).data()
        for start in range(max(0, off - 15), off + 1):
            for i in self.md.disasm(data[start:start + 16], start):
                if i.address <= off < i.address + i.size:
                    return i
                break
        return None

    def resolve_section(self, shndx, a):
        inside, at_end = [], []
        for s in self.syms:
            if s["st_shndx"] == shndx and s["st_info"]["type"] in ("STT_OBJECT", "STT_FUNC") and s.name:
                v, z = s["st_value"], s["st_size"]
                if v <= a < v + z:
                    inside.append(s)
                elif z and a == v + z:
                    at_end.append(s)
        sec0 = self.e.get_section(shndx)
        if sec0["sh_flags"] & 0x20:                              # SHF_STRINGS
            d = sec0.data()
            return ("str", d[a:d.find(bytes(1), a)].decode("latin-1"), 0), "R6"
        c = inside or at_end
        if c:
            s = c[0]
            return ("sym", s.name, a - s["st_value"]), "R2" + ("" if inside else " (end)")
        sec = self.e.get_section(shndx)
        if sec["sh_flags"] & 0x4 and ARCH == "x86_64":          # SHF_EXECINSTR: code with no symbol
            data = sec.data()
            end = data.find(b"\x0f\x0b", a)
            if 0 <= end - a <= 32 and not self.relocs(shndx, a, end + 2):
                return ("code", data[a:end + 2].hex(), 0), "R5"
        return ("sec", sec.name, a), "unresolved"


def entries(o):
    f = o.func()
    sh, lo, hi = f["st_shndx"], f["st_value"], f["st_value"] + f["st_size"]
    data = o.e.get_section(sh).data()
    out = []
    for r in o.relocs(sh, lo, hi):
        t, off, a = r["r_info_type"], r["r_offset"], r["r_addend"]
        s = o.syms[r["r_info_sym"]]
        if ARCH == "aarch64" and t in A64_ADRP:
            continue
        rule = "R1"
        if ARCH == "x86_64":
            i = o.insn_at(sh, off)
            if t in (2, 4) and i is not None:
                a += (i.address + i.size) - off
                rule += "+R4"
            is_call = i is not None and i.mnemonic == "call"
        else:
            is_call = t in A64_CALL
            if t in A64_LO12:
                rule = "R3"
                reg = data[off] & 0x1F                      # Rd of the ADD
                for k in (4, 8):
                    w = int.from_bytes(data[off + k:off + k + 4], "little")
                    if (w & 0xFF800000) == 0x91000000 and (w & 0x1F) == reg and ((w >> 5) & 0x1F) == reg \
                            and not o.relocs(sh, off + k, off + k + 4):
                        a += ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)
                        rule += " (+add)"
                        break
        if s["st_info"]["type"] == "STT_SECTION":
            tgt, how = o.resolve_section(s["st_shndx"], a)
            rule += "," + how
        else:
            n = s.name
            if n.startswith(".klp.sym."):
                n = n.split(".", 4)[4].rsplit(",", 1)[0]
            tgt = ("sym", n, a)
        out.append({"off": off, "type": t, "call": is_call, "target": list(tgt), "rule": rule})
    return out


def segments(es):
    segs, cur = [], Counter()
    for e in es:
        if e["call"]:
            segs.append((cur, tuple(e["target"])))
            cur = Counter()
        else:
            cur[tuple(e["target"])] += 1
    segs.append((cur, None))
    return segs


m, r = entries(Obj(MOD)), entries(Obj(REF))
sm, sr = segments(m), segments(r)
same = len(sm) == len(sr) and all(a == b for a, b in zip(sm, sr))
diff = [i for i, (a, b) in enumerate(zip(sm, sr)) if a != b]
print(json.dumps({"label": LABEL, "function": FN, "arch": ARCH, "module_relocs": len(m), "reference_relocs": len(r),
                  "segments": [len(sm), len(sr)], "differing_segments": diff,
                  "unresolved": [e for e in m + r if "unresolved" in e["rule"]],
                  "rules_used": sorted(Counter(e["rule"] for e in m + r).items()),
                  "verdict": "SAME" if same else "DIFFERENT"}))
if not same:
    for i in diff[:5]:
        print("  segment", i, "module", dict(sm[i][0]), sm[i][1], file=sys.stderr)
        print("  segment", i, "reference", dict(sr[i][0]), sr[i][1], file=sys.stderr)
