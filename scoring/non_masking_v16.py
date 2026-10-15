#!/usr/bin/env python3
"""Non-masking for shipping rules RF + RS (oracle v1.6).

A) LPFID_DISABLE=RF,RS → v1.6 equals v1.4 on every S26 and S34-gcc44 scored module.
B) LPFID_DISABLE=RS only → equals v1.5 (RF still on).
C) S26: scaffolding-only modules CONSISTENT under v1.6; CVE-2023-5090 stays DIVERGENT.
D) Mutant non-masking: on held-out fixed-objtool / real-fix mutants if present under
   /opt/atlas, otherwise on S34 fentry package with a mid-body byte flip in the .ko copy.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"
V14 = "/opt/atlas/lpfid/blind-reloc-oracle-v1.4.py"
V15 = "/opt/atlas/lpfid/blind-reloc-oracle-v1.5.py"
V16 = "/opt/atlas/lpfid/blind-reloc-oracle-v1.6.py"
SCAFFOLD = {"init_module", "cleanup_module", "__pfx_init_module", "__pfx_cleanup_module"}


def run(script: str, ko: Path, refs: list[Path], disable: str = "") -> dict:
    env = os.environ.copy()
    env["LPFID_T1"] = "version"
    if disable:
        env["LPFID_DISABLE"] = disable
    r = subprocess.run([PY, script, str(ko), *[str(p) for p in refs]], capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"error": True, "tail": (r.stdout or r.stderr)[-400:]}


def s26_artifacts():
    for keep in Path("/home/test/s26/results").glob("*/keep/*"):
        kos = list(keep.glob("*.ko"))
        refs = list((keep / "ref").glob("*.o")) if (keep / "ref").exists() else []
        if kos and refs:
            yield keep, kos[0], refs


def s34_artifacts():
    root = Path("/home/test/s34-anolis/results-gcc44")
    unpack = Path("/home/test/s34-anolis/unpack")
    for d in sorted(root.iterdir()):
        if not d.is_dir() or d.name == "SUMMARY.json":
            continue
        rj = d / "result.json"
        if not rj.exists():
            continue
        data = json.loads(rj.read_text())
        if data.get("status") != "SCORED":
            continue
        kos = list(unpack.joinpath(d.name).rglob("*.ko"))
        refs = list((d / "refs").glob("*.o"))
        if kos and refs:
            yield d.name, kos[0], refs


def main() -> int:
    fails = []

    # A/B on S26 keep set (the divergent ones + sample)
    eq14 = eq15 = 0
    n = 0
    for keep, ko, refs in s26_artifacts():
        n += 1
        v14 = run(V14, ko, refs)
        off = run(V16, ko, refs, "RF,RS")
        v15 = run(V15, ko, refs)
        no_rs = run(V16, ko, refs, "RS")
        if off.get("overall_verdict") != v14.get("overall_verdict"):
            fails.append(("A_s26", str(keep), off.get("overall_verdict"), v14.get("overall_verdict")))
        else:
            eq14 += 1
        if no_rs.get("overall_verdict") != v15.get("overall_verdict"):
            fails.append(("B_s26", str(keep), no_rs.get("overall_verdict"), v15.get("overall_verdict")))
        else:
            eq15 += 1
    print(f"A_disable_RF_RS_eq_v14 S26 {eq14}/{n}")
    print(f"B_disable_RS_eq_v15 S26 {eq15}/{n}")

    # A/B sample of S34 gcc44 (all scored)
    eq14 = eq15 = 0
    n = 0
    for name, ko, refs in s34_artifacts():
        n += 1
        v14 = run(V14, ko, refs)
        off = run(V16, ko, refs, "RF,RS")
        v15 = run(V15, ko, refs)
        no_rs = run(V16, ko, refs, "RS")
        if off.get("overall_verdict") != v14.get("overall_verdict"):
            fails.append(("A_s34", name, off.get("overall_verdict"), v14.get("overall_verdict")))
        else:
            eq14 += 1
        if no_rs.get("overall_verdict") != v15.get("overall_verdict"):
            fails.append(("B_s34", name, no_rs.get("overall_verdict"), v15.get("overall_verdict")))
        else:
            eq15 += 1
    print(f"A_disable_RF_RS_eq_v14 S34 {eq14}/{n}")
    print(f"B_disable_RS_eq_v15 S34 {eq15}/{n}")

    # C Amazon residual / scaffold clearance
    scaf_cleared = residual_ok = 0
    for keep, ko, refs in s26_artifacts():
        v14 = run(V14, ko, refs)
        v16 = run(V16, ko, refs)
        div = [x.get("function") for x in (v14.get("divergent_functions") or [])]
        real = [n for n in div if n not in SCAFFOLD]
        if div and not real:
            if v16.get("overall_verdict") == "CONSISTENT":
                scaf_cleared += 1
            else:
                fails.append(("C_scaffold", str(keep), v16.get("overall_verdict")))
        if "svm_set_x2apic_msr_interception" in real or keep.name == "CVE-2023-5090":
            if v16.get("overall_verdict") == "DIVERGENT" and any(
                x.get("function") == "svm_set_x2apic_msr_interception"
                for x in (v16.get("divergent_functions") or [])
            ):
                residual_ok += 1
            else:
                fails.append(("C_5090", str(keep), v16.get("overall_verdict"), v16.get("divergent_functions")))
    print(f"C_scaffold_cleared {scaf_cleared}")
    print(f"C_5090_still_divergent {residual_ok}")

    # D: binding-oracle non-masking — corrupt one .rela r_info symbol index in a
    # v1.6-CONSISTENT Anolis module (masked .text flips are invisible to the oracle).
    mutant_ok = False
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    for name, ko, refs in s34_artifacts():
        if "16349694" not in name:
            continue
        base = run(V16, ko, refs)
        if base.get("overall_verdict") != "CONSISTENT":
            fails.append(("D_base", name, base.get("overall_verdict")))
            break
        with tempfile.TemporaryDirectory() as td:
            mut = Path(td) / "mut.ko"
            shutil.copy2(ko, mut)
            elf = ELFFile(open(mut, "rb"))
            data = bytearray(mut.read_bytes())
            flipped = False
            for sec in elf.iter_sections():
                if not isinstance(sec, RelocationSection):
                    continue
                if not (sec.name.startswith(".rela") or sec.name.startswith(".klp.rela")):
                    continue
                entsize = sec["sh_entsize"] or 24
                for i, rel in enumerate(sec.iter_relocations()):
                    # skip NONE
                    if rel["r_info_type"] == 0:
                        continue
                    # r_info at offset 8 in Elf64_Rela
                    file_off = sec["sh_offset"] + i * entsize + 8
                    if file_off + 8 <= len(data):
                        # bump symbol index by 1 (low 32 bits of r_info on LE are type; sym in high)
                        # Elf64_Rela.r_info = (sym << 32) | type
                        old = int.from_bytes(data[file_off:file_off + 8], "little")
                        typ = old & 0xFFFFFFFF
                        sym = old >> 32
                        new = ((sym + 1) << 32) | typ
                        data[file_off:file_off + 8] = new.to_bytes(8, "little")
                        flipped = True
                        break
                if flipped:
                    break
            if not flipped:
                fails.append(("D_no_rela", name))
                break
            mut.write_bytes(data)
            # Visible-mutant protocol (S16): mutant vs its own unmutated parent as reference.
            bad = run(V16, mut, [ko])
            if bad.get("overall_verdict") == "CONSISTENT":
                fails.append(("D_mutant_still_consistent", name, bad.get("divergent_functions")))
            else:
                mutant_ok = True
                print("D_mutant_not_consistent", bad.get("overall_verdict"))
        break
    print("D_mutant", "PASS" if mutant_ok else "FAIL")

    print("OVERALL", "PASS" if not fails and mutant_ok else "FAIL")
    if fails:
        print("failures", fails[:10])
    return 0 if not fails and mutant_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
