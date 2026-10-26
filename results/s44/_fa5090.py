"""Relocations of svm_set_x2apic_msr_interception in each CVE-2023-5090 census module and its reference.

Prints every (type, target) pair that is in one side and not the other, with section-relative targets resolved to the
data symbol that covers that offset, so a naming difference shows as the same object on both sides.
"""
import sys, glob, os
from collections import Counter
from elftools.elf.elffile import ELFFile

FN = "svm_set_x2apic_msr_interception"


def pairs(path):
    e = ELFFile(open(path, "rb"))
    st = e.get_section_by_name(".symtab")
    syms = list(st.iter_symbols())
    f = [s for s in syms if s.name == FN and s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] != "SHN_UNDEF"][0]
    fsec, lo, hi = f["st_shndx"], f["st_value"], f["st_value"] + f["st_size"]
    objs = {}
    for s in syms:
        if s["st_info"]["type"] == "STT_OBJECT" and isinstance(s["st_shndx"], int):
            objs.setdefault(s["st_shndx"], []).append(s)
    out = Counter()
    for sec in e.iter_sections():
        if sec["sh_type"] != "SHT_RELA" or sec["sh_info"] != fsec:
            continue
        for r in sec.iter_relocations():
            if not lo <= r["r_offset"] < hi:
                continue
            s = syms[r["r_info_sym"]]
            a = r["r_addend"]
            if s["st_info"]["type"] == "STT_SECTION":
                tsec = s["st_shndx"]
                name = "sec:" + e.get_section(tsec).name
                cover = [o.name for o in objs.get(tsec, []) if o["st_value"] <= a < o["st_value"] + max(o["st_size"], 1)]
                tgt = "%s%+#x%s" % (name, a, (" [=" + cover[0] + "]") if cover else "")
            else:
                tgt = "%s%+#x" % (s.name, a)
            out[(r["r_info_type"], tgt)] += 1
    return out


for pkg in sys.argv[1:]:
    base = os.path.expanduser("~/s44/x86/" + pkg)
    ko = pairs(base + "/ko/livepatch-CVE-2023-5090.ko")
    ref = pairs(glob.glob(base + "/ref/CVE-2023-5090/*.o")[0])
    print("==", pkg, "ko", sum(ko.values()), "ref", sum(ref.values()))
    for k in sorted(set(ko) | set(ref)):
        if ko[k] != ref[k]:
            print("   ko %d ref %d  type %d  %s" % (ko[k], ref[k], k[0], k[1]))
