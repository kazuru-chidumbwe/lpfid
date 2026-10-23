# LPFid: fidelity checks for Linux livepatch modules

A livepatch module can load, report itself enabled and finish its transition while the fix it was built from is not in effect. LPFid checks a built module against an independent compile of the same fix and reports where the two disagree. It needs no knowledge of which fault, if any, is present. This repository holds the checks, the scripts that built and scored every module, and the result files behind the paper "Loaded but Not Fixed: Test Oracles for the Fidelity of Linux Livepatch Modules" (Kazuru).

License: MIT, see [`LICENSE`](LICENSE).

## Try it

```bash
git clone https://github.com/kazuru-chidumbwe/lpfid.git
cd lpfid
git checkout v1.1.0
python3 -m pip install pyelftools capstone==5.0.7

python3 oracle/blind-reloc-oracle-v2.0.py MODULE.ko REF.o [REF.o ...] \
    --vmlinux PIN/vmlinux --modules-dir PIN
```

The oracle prints a JSON report and exits 0 when the module is consistent with the reference objects and 1 when it diverges. It reads x86-64 and AArch64 objects. Python 3.11 or later. `oracle/blind-reloc-oracle-v2.0.py` is the held-out oracle. Earlier versions stay in `oracle/` for the scores that used them.

## How to cite

```text
Seke Kazuru. LPFid: test oracles for the fidelity of Linux livepatch modules.
https://github.com/kazuru-chidumbwe/lpfid
Tag: v1.1.0
https://doi.org/10.5281/zenodo.23588997
```

The concept DOI https://doi.org/10.5281/zenodo.23408955 resolves to the latest version. `CITATION.cff` carries the same metadata.

## The checks

| Check | File | What it decides |
| --- | --- | --- |
| Binding oracle | `oracle/blind-reloc-oracle-v2.0.py` | Whether each relocation in a patched function binds the same symbol, at the same addend, as the reference; with `--vmlinux`, whether every symbol position resolves to the copy defined in the right source file. This is the oracle in the held-out trial. `oracle/blind-reloc-oracle-v1.8.py` is the previous frozen version |
| Instruction check | `oracle/body_check_v16.py` | Whether the patched functions' instructions match the reference after relocation fields are masked |
| Eligibility check | `eligibility/` | Whether a module can be tested by reverting it (shadow variables, callbacks, atomic replace and system states make a revert unsafe) |
| Behavioural check | `behavioural/` | Whether a probe sees the fix in a virtual machine before loading, after enabling and after disabling; one contract per fix in `behavioural/contracts/` |

The binding oracle's rules can be switched off one at a time with `LPFID_DISABLE` (for example `LPFID_DISABLE=N1C`, which gives v1.7 exactly). Earlier versions stay in `oracle/` so every reported score can be reproduced with the version that produced it; `preregistration/S16-oracle-freeze.md` lists each version's SHA-256 and the validation it passed before it scored anything new.

## Layout

| Directory | Contents |
| --- | --- |
| `corpus/` | Fix selection from the kernel CNA records, the build runner, the independent reference compiles and the klp-build runner |
| `mutation/` | The operators that edit built modules. `mutation/lpfid-mutate-v2.0.py` is the operator file frozen for the held-out trial. Earlier operators remain in `mutation/lpfid-mutate.py` |
| `scoring/` | Scoring of each build set with every oracle version, the ablation and the cost measurement |
| `runtime/` | The loader check in a virtual machine and the end-to-end check of the wrong `pwq_cache` binding (CVE-2026-43074) |
| `generators/` | The kpatch-build and klp-build comparison, including the objtool string fault in klp-build on Linux 6.19 |
| `presence/` | The patch presence test runs |
| `faults/` | The codebook and coding of kpatch's defect history |
| `results/` | Every result file the paper reports (map below) |
| `preregistration/` | The plans, each committed before the runs it governs, with their addenda |

`MANIFEST.sha256` lists the SHA-256 of every file.

## Paper claims and files

| Claim | Files |
| --- | --- |
| Injected faults, x86-64 (Section 7.4) | `results/s2-operator-mutants.json`, `scoring/` |
| Injected faults, AArch64 (Section 7.4) | `results/arm64/` |
| `sibling` operator and the v1.8 replay of every recorded comparison (Section 7.4) | `results/s41-oracle-v18/` |
| Held-out klp-build modules (Section 7.4) | `results/klp-6.19/` |
| Amazon Linux 2023 x86-64, 163 of 164 patched functions (Section 7.6) | `results/s26-v16-SUMMARY.json`, `results/s26/` |
| Amazon Linux 2023 AArch64, 123 of 123 modules (Section 7.6) | `results/s39-aarch64/` |
| OpenAnolis 7.7, 38 of 38 on the patched functions (Section 7.6) | `results/s34-patched-functions.json`, `results/s34/` |
| openEuler SysCare hotpatches (Section 7.6) | `results/s40-openeuler/` |
| Held-out trial, both architectures (Section 7.7) | `results/s43/`, `preregistration/S43-heldout.md`, `oracle/blind-reloc-oracle-v2.0.py` |
| Same-toolchain comparison with no normalisation rule (Section 7.4) | `results/s42-baseline/` |

## Reproducing the builds

The builds used kpatch-build v0.9.7 to v0.9.11 and the in-tree klp-build of Linux 6.19 with gcc 13.3.0. The shipped-module references use each distribution's own compiler and kernel configuration, as the pre-registrations state. The loader and behavioural checks need QEMU with KVM. The scripts carry the paths of the machines used in the study; set them for yours first.
