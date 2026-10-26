# LPFid: fidelity checks for Linux livepatch modules

A livepatch module can load, report itself enabled and finish its transition while the fix it was built from is not in effect. LPFid checks a built module against an independent compile of the same fix and reports where the two disagree. It needs no knowledge of which fault, if any, is present. This repository holds the checks, the scripts that built and scored every module, and the result files behind the paper "Loaded but Not Fixed: An Empirical Study of Livepatch Fidelity in Linux" (Kazuru).

License: MIT, see [`LICENSE`](LICENSE).

## Try it

```bash
git clone https://github.com/kazuru-chidumbwe/lpfid.git
cd lpfid
git checkout v1.2.0
python3 -m pip install pyelftools capstone==5.0.7

python3 oracle/blind-reloc-oracle-v2.1.py MODULE.ko REF.o [REF.o ...] \
    --vmlinux PIN/vmlinux --modules-dir PIN
```

The oracle prints a JSON report and exits 0 when the module is consistent with the reference objects and 1 when it diverges. It reads x86-64 and AArch64 objects. Python 3.11 or later. `oracle/blind-reloc-oracle-v2.1.py` is the census oracle and `oracle/blind-reloc-oracle-v2.0.py` the held-out oracle. Earlier versions stay in `oracle/` for the scores that used them.

## How to cite

```text
Seke Kazuru. LPFid: fidelity checks for Linux livepatch modules.
https://github.com/kazuru-chidumbwe/lpfid
Tag: v1.2.0
```

The concept DOI https://doi.org/10.5281/zenodo.23408955 resolves to the latest version. `CITATION.cff` carries the same metadata.

## The checks

| Check | File | What it decides |
| --- | --- | --- |
| Binding oracle | `oracle/blind-reloc-oracle-v2.1.py` | Whether each relocation in a patched function binds the same symbol, at the same addend, as the reference; with `--vmlinux`, whether every symbol position resolves to the copy defined in the right source file. Version 2.1 compares every definition of a function name the module defines twice, each against the reference definition from the same source file. Version 2.0 is the held-out oracle and version 1.8 the frozen version before it |
| Immediate check | `oracle/s27_immcheck.py` | Whether each patched function carries the same instruction immediates as the reference, outside relocation fields and control-transfer instructions. It reads ELF objects through `oracle/blind-reloc-oracle-v1.py`; set `S27_ORACLE_DIR` to a directory holding that file as `blind-reloc-oracle.py`, and `S27_DISABLE=T1,IMM-FRAME` for the setting the paper reports |
| Byte comparison | `oracle/body_check_v16.py` | Whether the patched functions' instruction bytes match the reference after relocation fields are masked, which also shows instruction order |
| Eligibility check | `eligibility/` | Whether a module can be tested by reverting it (shadow variables, callbacks, atomic replace and system states make a revert unsafe) |
| Behavioural check | `behavioural/` | Whether a probe sees the fix in a virtual machine before loading, after enabling and after disabling; one contract per fix in `behavioural/contracts/` |

The binding oracle's rules can be switched off one at a time with `LPFID_DISABLE` (for example `LPFID_DISABLE=N1C`, which gives v1.7 exactly). Earlier versions stay in `oracle/` so every reported score can be reproduced with the version that produced it. `preregistration/S16-oracle-freeze.md` lists the SHA-256 of each early version, and `preregistration/S43-heldout.md` and `preregistration/S44-census.md` those of versions 2.0 and 2.1. `oracle/blind-reloc-oracle-v1.py` is stored with LF line endings; with the CRLF endings of the copy the immediate check ran with, its SHA-256 is the 7d79c9d9… that `preregistration/S44-census.md` records.

## Layout

| Directory | Contents |
| --- | --- |
| `corpus/` | Fix selection from the kernel CNA records, the build runner, the independent reference compiles and the klp-build runner |
| `mutation/` | The operators that edit built modules. `mutation/lpfid-mutate-v2.1.py` is the operator file frozen for the census and `mutation/lpfid-mutate-v2.0.py` the one frozen for the held-out draw. Earlier operators remain in `mutation/lpfid-mutate.py` |
| `scoring/` | Scoring of each build set with every oracle version, the ablation and the cost measurement |
| `runtime/` | The loader check in a virtual machine and the end-to-end check of the wrong `pwq_cache` binding (CVE-2026-43074) |
| `generators/` | The kpatch-build and klp-build comparison, including the objtool string fault in klp-build on Linux 6.19 |
| `presence/` | The patch presence test runs |
| `faults/` | The codebook and coding of kpatch's defect history |
| `figures/` | The scripts that draw the paper's figures |
| `results/` | Every result file the paper reports (map below) |
| `preregistration/` | The plans, each committed before the runs it governs, with their addenda |

`MANIFEST.sha256` lists the SHA-256 of every file.

## Paper claims and files

| Claim | Files |
| --- | --- |
| What the loader and livepatch core accept (Section 7.2) | `results/loader-s2-analysis.json`, `results/loader-fixtures-analysis.json`, `runtime/` |
| The wrong `pwq_cache` binding from kpatch-build v0.9.10 (Section 7.3) | `results/case-43074.md`, `runtime/case-43074/` |
| The klp-build string fault on Linux 6.19 (Section 7.3) | `results/generators/`, `results/klp-6.19/` |
| Amazon Linux 2023 x86-64, design draw (Section 7.4) | `results/s44/bind-s26re.jsonl`, `results/s44/s26re_bind.py`, `results/s44/S26-KEEP-OVERWRITE.md`, `results/s26/` |
| Amazon Linux 2023 AArch64, design draw (Section 7.4) | `results/s39-aarch64/` |
| OpenAnolis 7.7 (Section 7.4) | `results/s34-patched-functions.json`, `results/s34/` |
| openEuler hotpatches (Section 7.4) | `results/s40-openeuler/`, `results/s44/body-openeuler-x86.txt` |
| Immediate check on shipped x86-64 modules (Section 7.4) | `results/s44/imm-x86.jsonl`, `results/s44/imm-s26.jsonl`, `results/s44/s44_imm.py`, `results/s44/_imm_tally.py` |
| Byte comparison on shipped x86-64 modules (Section 7.4) | `results/s44/body-x86.jsonl`, `results/s44/body-s26.jsonl`, `results/s44/s44_body.py`, `results/s44/s26_body.py`, `results/s44/body-openeuler-x86.txt`, `results/s34/body-gcc44-functions.txt` |
| CVE-2023-5090 and `pinctrl_enable`, one address named two ways (Section 7.4) | `results/s44/fa5090.txt`, `results/s44/_fa5090.py`, `results/s45/S45-ADDRESS-CHECK.md`, `results/s45/addr_equiv.py`, `results/s45/addr-run1.txt`, `results/s45/addr-design-shipped.txt` |
| Injected faults, x86-64 and AArch64 (Section 7.5.1) | `results/s2-operator-mutants.json`, `results/arm64/`, `scoring/` |
| `sibling` operator and the v1.8 replay (Section 7.5.1) | `results/s41-oracle-v18/` |
| Same-toolchain comparison with no normalisation rule (Section 7.5.1) | `results/s42-baseline/` |
| Immediate check on the constant mutants (Sections 5.6 and 7.5.1) | `results/s27/`, `oracle/s27_immcheck.py` |
| Six-operator campaign re-scored with the census oracle | `results/s45/S45-S2-V21-RESCORE.md`, `results/s45/s2-v21.jsonl` |
| Held-out draw and the classification of its nine misses (Section 7.5.2) | `results/s43/`, `preregistration/S43-heldout.md`, `oracle/blind-reloc-oracle-v2.0.py` |
| Census of the remaining Amazon Linux 2023 packages (Section 7.5.3) | `results/s44/`, `preregistration/S44-census.md`, `oracle/blind-reloc-oracle-v2.1.py`, `mutation/lpfid-mutate-v2.1.py` |

## Reproducing the builds

The builds used kpatch-build v0.9.7 to v0.9.11 and the in-tree klp-build of Linux 6.19 with gcc 13.3.0. The shipped-module references use each distribution's own compiler and kernel configuration, as the pre-registrations state; `results/s44/Dockerfile.s39` is the AArch64 builder. The loader and behavioural checks need QEMU with KVM. The scripts carry the paths of the machines used in the study; set them for yours first.
