#!/usr/bin/env python3
"""PRE(B): struct-aware revert-eligibility scan for Linux livepatch .ko artifacts (eligibility check v2.1, S42).

v2.1 = v2 plus three changes (S42, after review):
  E1 a static klp_object whose klp_object or klp_callbacks layout is missing is UNDETERMINED for CALLBACKS.
  E2 the run-time REPLACE scan covers every function that calls klp_enable_patch as well as the init names; a
     register byte store at offsetof(struct klp_patch, replace) there is UNDETERMINED.
  E3 a non-x86-64 module without a static klp_patch is UNDETERMINED for the run-time REPLACE scan.

v2 header follows.

v1 (pre-revert-scan.py) matched symbol names and strings; it found every shadow-variable and system-state hazard but
missed callbacks and atomic replace, which are data-initialised struct fields with no telltale name (S6, 7 Oct 2026).
v2 reads the layouts of struct klp_patch, klp_object, klp_callbacks and klp_object_ext from the module's own DWARF
debug information and inspects relocations, bytes and stores at those field offsets. It covers the three ways
livepatch modules are produced:
  in-tree / hand-written  static struct klp_patch and klp_object arrays in .data
  kpatch-build            callbacks in .kpatch.callbacks.* sections; klp_patch filled at run time by the patch hook
  klp-build               callbacks in .init.klp_objects (struct klp_object_ext); klp_patch filled at run time
Hazards (any one makes the module OUT_OF_SCOPE for a total-revert check):
  SHADOW     the module imports klp_shadow_* or kpatch_shadow_*
  STATES     the module imports klp_get_state / klp_get_prev_state, or a static klp_patch has a non-NULL .states
  CALLBACKS  a callback pointer field (pre_patch, post_patch, pre_unpatch, post_unpatch) of a static klp_object or
             of a .init.klp_objects entry is relocated or non-zero, or a .kpatch.callbacks.* section is non-empty
  REPLACE    a static klp_patch has a non-zero .replace byte, or code stores to .replace of a static klp_patch, or
             the module's init code stores a non-zero immediate byte at offsetof(struct klp_patch, replace) (the
             run-time klp_patch of kpatch-build and klp-build modules)
Without DWARF for struct klp_patch the struct-dependent hazards are reported as undetermined, never as absent.
Prints one JSON object per module.
Type information: the module's own DWARF; if it has none, --types OBJ, an object of the same kernel build with debug
information (e.g. kernel/livepatch/core.o, or vmlinux from the distribution's debuginfo package).
Usage: pre-revert-scan-v2.py [--types OBJ] MODULE.ko [MODULE.ko ...]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

SHADOW = ("klp_shadow_alloc", "klp_shadow_get", "klp_shadow_get_or_alloc", "klp_shadow_free", "klp_shadow_free_all",
          "kpatch_shadow_alloc", "kpatch_shadow_get", "kpatch_shadow_free")
STATE_FUNCS = ("klp_get_state", "klp_get_prev_state")
CB_FIELDS = ("pre_patch", "post_patch", "pre_unpatch", "post_unpatch")
STRUCTS = ("klp_patch", "klp_object", "klp_callbacks", "klp_object_ext")
INIT_NAMES = ("init_module", "livepatch_mod_init", "patch_init")
PC_REL = {2, 4, 41, 42}
VERSION = "2.1"


def dwarf_layouts(elf: ELFFile) -> tuple[dict, dict]:
    """struct name -> {"size": n, "members": {name: (offset, type_die)}}; variable name -> struct name."""
    structs: dict = {}
    variables: dict = {}
    if not elf.has_dwarf_info():
        return structs, variables
    dw = elf.get_dwarf_info()

    def strip(die):
        while die is not None and die.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
            die = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
        return die

    for cu in dw.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_structure_type" and "DW_AT_name" in die.attributes and die.has_children:
                name = die.attributes["DW_AT_name"].value.decode()
                if name in STRUCTS and name not in structs:
                    mem = {}
                    for ch in die.iter_children():
                        if ch.tag == "DW_TAG_member" and "DW_AT_name" in ch.attributes \
                                and "DW_AT_data_member_location" in ch.attributes:
                            loc = ch.attributes["DW_AT_data_member_location"].value
                            if isinstance(loc, int):
                                t = ch.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in ch.attributes else None
                                mem[ch.attributes["DW_AT_name"].value.decode()] = (loc, t)
                    structs[name] = {"size": die.attributes.get("DW_AT_byte_size").value
                                     if "DW_AT_byte_size" in die.attributes else None, "members": mem}
            elif die.tag == "DW_TAG_variable" and "DW_AT_name" in die.attributes and "DW_AT_type" in die.attributes:
                t = strip(die.get_DIE_from_attribute("DW_AT_type"))
                if t is not None and t.tag == "DW_TAG_array_type":
                    t = strip(t.get_DIE_from_attribute("DW_AT_type"))
                if t is not None and t.tag == "DW_TAG_structure_type" and "DW_AT_name" in t.attributes:
                    sname = t.attributes["DW_AT_name"].value.decode()
                    if sname in ("klp_patch", "klp_object"):
                        variables[die.attributes["DW_AT_name"].value.decode()] = sname
    return structs, variables


class Module:
    def __init__(self, path: Path):
        self.path = path
        self.elf = ELFFile(open(path, "rb"))
        st = self.elf.get_section_by_name(".symtab")
        self.syms = list(st.iter_symbols()) if st else []
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def undefined(self) -> set[str]:
        return {s.name for s in self.syms if s["st_shndx"] == "SHN_UNDEF" and s.name}

    def sym(self, name: str):
        for s in self.syms:
            if s.name == name and isinstance(s["st_shndx"], int) and s["st_shndx"] > 0:
                return s
        return None

    def relocs(self):
        """(rela section, target section index, relocation) for every relocation."""
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            if sec.name.startswith(".klp.rela."):
                t = sec.name.split(".", 4)[-1]
                tidx = self.elf.get_section_index(t) if self.elf.get_section_by_name(t) else None
            else:
                tidx = sec["sh_info"]
            for r in sec.iter_relocations():
                yield sec, tidx, r

    def reloc_at(self, shndx: int, off: int) -> bool:
        return any(tidx == shndx and r["r_offset"] == off for _, tidx, r in self.relocs())

    def bytes_at(self, shndx: int, off: int, n: int) -> bytes:
        sec = self.elf.get_section(shndx)
        if sec["sh_type"] == "SHT_NOBITS":
            return b"\0" * n
        return sec.data()[off:off + n]

    def insn_end(self, shndx: int, off: int) -> int | None:
        sec = self.elf.get_section(shndx)
        for ins in self.md.disasm(sec.data(), 0):
            if ins.address <= off < ins.address + ins.size:
                return ins.address + ins.size
        return None

    def code_targets(self, shndx: int, lo: int, hi: int) -> list[tuple[int, str, int]]:
        """(relocation offset, target symbol name, effective offset into the target) for code relocations that
        reach [lo, hi) of data section shndx, either through a section symbol or a symbol defined there."""
        out = []
        for _, tidx, r in self.relocs():
            if tidx is None or not (self.elf.get_section(tidx)["sh_flags"] & 0x4):  # SHF_EXECINSTR
                continue
            s = self.syms[r["r_info_sym"]]
            if s["st_shndx"] != shndx:
                continue
            tail = 0
            if r["r_info_type"] in PC_REL:
                end = self.insn_end(tidx, r["r_offset"])
                tail = (end - r["r_offset"]) if end else 4
            eff = s["st_value"] + r["r_addend"] + tail
            if lo <= eff < hi:
                out.append((r["r_offset"], s.name, eff))
        return out

    def enable_callers(self) -> set[str]:
        """E2: functions that hold a call relocation to klp_enable_patch."""
        out = set()
        for _, tidx, r in self.relocs():
            t = self.syms[r["r_info_sym"]]
            if t.name and t.name.endswith("klp_enable_patch") and tidx is not None:
                for s in self.syms:
                    if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == tidx and s["st_size"] \
                            and s["st_value"] <= r["r_offset"] < s["st_value"] + s["st_size"]:
                        out.add(s.name)
        return out

    def init_stores(self, disp: int, unknown: list | None = None) -> list[str]:
        """Byte stores of a non-zero immediate at [reg + disp] in the module's init function(s) and in every
        function that calls klp_enable_patch (E2); register byte stores there go to unknown."""
        hits = []
        scope = set(INIT_NAMES) | self.enable_callers()
        for s in self.syms:
            if s["st_info"]["type"] != "STT_FUNC" or s.name not in scope or not isinstance(s["st_shndx"], int):
                continue
            data = self.elf.get_section(s["st_shndx"]).data()[s["st_value"]:s["st_value"] + s["st_size"]]
            for ins in self.md.disasm(data, s["st_value"]):
                if ins.mnemonic != "mov" or len(ins.operands) != 2:
                    continue
                dst, src = ins.operands
                if dst.type == capstone.x86.X86_OP_MEM and dst.size == 1 and src.type == capstone.x86.X86_OP_IMM \
                        and dst.mem.disp == disp and dst.mem.base != 0 and src.imm != 0:
                    hits.append(f"{s.name}+{ins.address - s['st_value']:#x}: {ins.mnemonic} {ins.op_str}")
                elif unknown is not None and dst.type == capstone.x86.X86_OP_MEM and dst.size == 1 \
                        and src.type == capstone.x86.X86_OP_REG and dst.mem.disp == disp and dst.mem.base != 0:
                    unknown.append(f"REPLACE (register store {s.name}+{ins.address - s['st_value']:#x}: "
                                   f"{ins.mnemonic} {ins.op_str})")
        return hits


def enable_patch_arg(m: "Module") -> tuple[int, int] | None:
    """(section index, offset) of the object passed as the first argument to klp_enable_patch in init code."""
    for s in m.syms:
        if s["st_info"]["type"] != "STT_FUNC" or s.name not in INIT_NAMES or not isinstance(s["st_shndx"], int):
            continue
        shndx, lo, hi = s["st_shndx"], s["st_value"], s["st_value"] + s["st_size"]
        rel = {r["r_offset"]: r for _, tidx, r in m.relocs() if tidx == shndx and lo <= r["r_offset"] < hi}
        data = m.elf.get_section(shndx).data()[lo:hi]
        last_rdi = None
        for ins in m.md.disasm(data, lo):
            fields = [o for o in rel if ins.address < o < ins.address + ins.size]
            if ins.mnemonic in ("mov", "lea") and ins.op_str.startswith("rdi,") and fields:
                r = rel[fields[0]]
                t = m.syms[r["r_info_sym"]]
                tail = (ins.address + ins.size - fields[0]) if r["r_info_type"] in PC_REL else 0
                if isinstance(t["st_shndx"], int) and t["st_shndx"] > 0:
                    last_rdi = (t["st_shndx"], t["st_value"] + r["r_addend"] + tail)
            elif ins.mnemonic in ("mov", "lea", "xor", "pop") and ins.op_str.startswith(("rdi,", "edi,")):
                last_rdi = None
            if ins.mnemonic in ("call", "jmp") and fields:
                if m.syms[rel[fields[0]]["r_info_sym"]].name == "klp_enable_patch" and last_rdi:
                    return last_rdi
    return None


def scan(path: Path, types: Path | None = None) -> dict:
    m = Module(path)
    structs, variables = dwarf_layouts(m.elf)
    layout_source = "module DWARF" if "klp_patch" in structs else "none"
    if "klp_patch" not in structs and types is not None:
        extra, _ = dwarf_layouts(ELFFile(open(types, "rb")))
        for k, v in extra.items():
            structs.setdefault(k, v)
        layout_source = f"types object {types.name}" if "klp_patch" in structs else "none"
    statics = []   # (label, kind, section index, offset, size) of static klp_patch / klp_object instances
    for var, sname in variables.items():
        s = m.sym(var)
        if s is not None:
            statics.append((var, sname, s["st_shndx"], s["st_value"], s["st_size"]))
    kp0 = structs.get("klp_patch")
    if not any(k == "klp_patch" for _, k, *_ in statics) and kp0:
        arg = enable_patch_arg(m)
        if arg and m.elf.get_section(arg[0])["sh_flags"] & 0x1:   # SHF_WRITE: a static object, not code
            statics.append(("patch(arg of klp_enable_patch)", "klp_patch", arg[0], arg[1], kp0["size"] or 0))
            if "objs" in kp0["members"]:
                po = arg[1] + kp0["members"]["objs"][0]
                for _, tidx, r in m.relocs():
                    if tidx == arg[0] and r["r_offset"] == po:
                        t = m.syms[r["r_info_sym"]]
                        if isinstance(t["st_shndx"], int) and t["st_shndx"] > 0:
                            ko0 = structs.get("klp_object")
                            start = t["st_value"] + r["r_addend"]
                            size = t["st_size"] if t["st_info"]["type"] == "STT_OBJECT" and t["st_size"] else (ko0["size"] or 0) if ko0 else 0
                            statics.append(("objs(of patch)", "klp_object", t["st_shndx"], start, size))
    und = m.undefined()
    ev: dict[str, list[str]] = {"SHADOW": [], "STATES": [], "CALLBACKS": [], "REPLACE": []}
    ev["SHADOW"] = sorted(und & set(SHADOW))
    ev["STATES"] = sorted(und & set(STATE_FUNCS))
    undetermined = []
    kp = structs.get("klp_patch")
    ko = structs.get("klp_object")
    cb = structs.get("klp_callbacks")
    # kpatch-build: callbacks live in their own sections
    for f in CB_FIELDS:   # the patch hook's own test: the callback array between start and end is not empty
        a, b = m.sym(f"__kpatch_callbacks_{f}"), m.sym(f"__kpatch_callbacks_{f}_end")
        if a is not None and b is not None and b["st_value"] > a["st_value"]:
            ev["CALLBACKS"].append(f"__kpatch_callbacks_{f}: {b['st_value'] - a['st_value']} bytes")
    # klp-build: struct klp_object_ext entries in .init.klp_objects
    ext, kx = m.elf.get_section_by_name(".init.klp_objects"), structs.get("klp_object_ext")
    if ext is not None:
        if kx and cb and kx["size"] and "callbacks" in kx["members"]:
            idx = m.elf.get_section_index(".init.klp_objects")
            base = kx["members"]["callbacks"][0]
            for i in range(ext["sh_size"] // kx["size"]):
                for f in CB_FIELDS:
                    if f in cb["members"]:
                        off = i * kx["size"] + base + cb["members"][f][0]
                        if m.reloc_at(idx, off) or any(m.bytes_at(idx, off, 8)):
                            ev["CALLBACKS"].append(f".init.klp_objects[{i}].callbacks.{f}")
        else:
            undetermined.append("CALLBACKS (klp_object_ext layout not in DWARF)")
    # static struct klp_patch / klp_object variables (in-tree and hand-written modules)
    for var, sname, shndx, base, size in statics:
        if sname == "klp_object" and not (ko and cb and ko["size"] and "callbacks" in ko["members"]):
            undetermined.append(f"CALLBACKS ({var}: klp_object or klp_callbacks layout not available)")   # E1
        if sname == "klp_object" and ko and cb and ko["size"] and "callbacks" in ko["members"]:
            for i in range(max(size // ko["size"], 1)):
                for f in CB_FIELDS:
                    if f in cb["members"]:
                        off = base + i * ko["size"] + ko["members"]["callbacks"][0] + cb["members"][f][0]
                        if m.reloc_at(shndx, off) or any(m.bytes_at(shndx, off, 8)):
                            ev["CALLBACKS"].append(f"{var}[{i}].callbacks.{f}")
                        for t in m.code_targets(shndx, off, off + 8):
                            ev["CALLBACKS"].append(f"store to {var}[{i}].callbacks.{f} at code {t[0]:#x}")
        if sname == "klp_patch" and kp:
            if "replace" in kp["members"]:
                off = base + kp["members"]["replace"][0]
                if any(m.bytes_at(shndx, off, 1)):
                    ev["REPLACE"].append(f"{var}.replace initialised non-zero")
                for t in m.code_targets(shndx, off, off + 1):
                    ev["REPLACE"].append(f"store to {var}.replace at code {t[0]:#x}")
            if "states" in kp["members"]:
                off = base + kp["members"]["states"][0]
                if m.reloc_at(shndx, off) or any(m.bytes_at(shndx, off, 8)):
                    ev["STATES"].append(f"{var}.states non-NULL")
    # run-time klp_patch (kpatch-build patch hook, klp-build init.c): non-zero byte store at offsetof(replace)
    if m.elf.header["e_machine"] not in ("EM_X86_64", 62):
        if not any(k == "klp_patch" for _, k, *_ in statics):   # E3: only the run-time klp_patch needs the scan
            undetermined.append("REPLACE (run-time scan decodes x86-64 only)")
    elif kp and "replace" in kp["members"]:
        ev["REPLACE"] += m.init_stores(kp["members"]["replace"][0], undetermined)
    else:
        undetermined.append("REPLACE and static CALLBACKS (no struct klp_patch layout: module has no DWARF and no --types)")
    hazards = {k: bool(v) for k, v in ev.items()}
    out_of_scope = any(hazards.values())
    return {"scanner": f"pre-revert-scan-v2 {VERSION}", "module": str(path),
            "pre_class": "OUT_OF_SCOPE" if out_of_scope else ("UNDETERMINED" if undetermined else "SOUND"),
            "uses_shadow": hazards["SHADOW"], "has_state_callbacks": hazards["CALLBACKS"],
            "is_replace": hazards["REPLACE"], "uses_klp_states": hazards["STATES"],
            "evidence": ev, "undetermined": undetermined,
            "layout_source": layout_source,
            "layout": {k: {"size": v["size"], **{f: v["members"][f][0] for f in v["members"]
                                                 if f in CB_FIELDS + ("callbacks", "replace", "states")}}
                       for k, v in structs.items()}}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    args = sys.argv[1:]
    types = None
    if "--types" in args:
        i = args.index("--types")
        types = Path(args[i + 1])
        del args[i:i + 2]
    for p in args:
        try:
            print(json.dumps(scan(Path(p), types)))
        except Exception as e:  # noqa: BLE001 - reported per module
            print(json.dumps({"module": p, "error": repr(e)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
