"""Read-only: classify the five AArch64 S43 misses on refetched modules (24 Oct 2026).
1. Identity: the frozen mutator's site lists on the refetched modules must equal the S43 record.
2. dropcall-34: FUNC symbols in .text.memcpy_sglist, their STT_FILE, and which one holds offset 732.
3. rodsec 1/27/31/32/38: the string the original and the moved relocation reach, and the oracle rows.
usage: _miss9_a64.py <oracle-v2.0.py> <lpfid-mutate.py> <results-aarch64.jsonl> <a64 dir>"""
import importlib.util, json, sys
from pathlib import Path

ORC_P, MU_P, RES, A64 = sys.argv[1:5]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ORC = load("orc20", ORC_P)
MU = load("mutate", MU_P)
PKGS = {"kernel-livepatch-6.12.80-105.147": "6.12.80-105.147", "kernel-livepatch-6.1.141-165.249": "6.1.141-165.249"}
rec = {}
for line in open(RES):
    r = json.loads(line)
    if r.get("pkg") in PKGS:
        rec[r["pkg"]] = r


def ko_path(pkg, stem):
    return next(Path(A64, pkg).glob(f"var/lib/kpatch/*/{stem}.ko"))


print("== 1. identity against the S43 record ==")
for pkg, r in rec.items():
    on_disk = sorted(p.stem for p in Path(A64, pkg).glob("var/lib/kpatch/*/*.ko"))
    print(pkg, "modules recorded", len(r["modules"]), "on disk", len(on_disk),
          "names equal", sorted(m["ko"] for m in r["modules"]) == on_disk)
    for m in r["modules"]:
        mod = MU.Mod(ko_path(pkg, m["ko"]))
        bad = []
        for op, d in m.get("ops", {}).items():
            if "sites" not in d:
                continue
            sites = MU.sites(mod, op)
            if len(sites) != d["sites"]:
                bad.append(f"{op}: count {len(sites)} vs {d['sites']}")
                continue
            for x in d["mutants"]:
                got = {k: v for k, v in sites[x["site_index"]].items() if k != "insn_file_off"}
                if got != x["site"]:
                    bad.append(f"{op}[{x['site_index']}] descriptor differs")
        print("  ", m["ko"], "sites identical" if not bad else bad)

print("== 2. dropcall-34, memcpy_sglist ==")
ko = ko_path("kernel-livepatch-6.12.80-105.147", "livepatch-CVE-2026-31431")
o = ORC.Obj(ko)
last_file = None
copies = []
for s in o.syms:
    t = s["st_info"]["type"]
    if t == "STT_FILE":
        last_file = s.name
    elif t == "STT_FUNC" and s.name == "memcpy_sglist":
        copies.append((s["st_shndx"], s["st_value"], s["st_size"], last_file))
for c in copies:
    print("  copy shndx", c[0], "range", (c[1], c[1] + c[2]), "file", c[3], "holds 732", c[1] <= 732 < c[1] + c[2])
sec = o.elf.get_section(copies[0][0])
data = sec.data()
if len(copies) == 2:
    a, b = copies
    print("  copies byte-identical", data[a[1]:a[1] + a[2]] == data[b[1]:b[1] + b[2]], "section size", sec["sh_size"])
print("  functions() keeps", o.functions()["memcpy_sglist"])
o.f.close()

print("== 3. rodsec, livepatch-CVE-2025-39677 ==")
ko = ko_path("kernel-livepatch-6.1.141-165.249", "livepatch-CVE-2025-39677")
o = ORC.Obj(ko)
miss = [s for m in rec["kernel-livepatch-6.1.141-165.249"]["modules"] if m["ko"] == "livepatch-CVE-2025-39677"
        for s in m["ops"]["rodsec"]["mutants"] if s.get("v20", {}).get("overall") == "CONSISTENT"]


def cstr(secname, off):
    d = o.elf.get_section_by_name(secname).data()
    end = d.find(b"\0", off)
    return d[off:end if end >= 0 else len(d)]


for x in miss:
    s = x["site"]
    rs = o.elf.get_section_by_name(s["rela"])
    rels = list(rs.iter_relocations())
    loc = o.functions()[s["function"]]
    print(f"  site {x['site_index']} {s['function']} {s['src']} -> {s['dst']}")
    for i in s["idx"]:
        r = rels[i]
        a = r["r_addend"]
        inside = loc[1] <= r["r_offset"] < loc[1] + loc[2]
        print(f"    rela {i} off {r['r_offset']} type {r['r_info_type']} addend {a} inside-fn {inside}")
        print(f"      src string {cstr(s['src'], a)!r}")
        dsz = o.elf.get_section_by_name(s["dst"])["sh_size"]
        print(f"      dst string {cstr(s['dst'], a)!r}" if a < dsz else f"      dst addend past end (size {dsz})")
o.f.close()
