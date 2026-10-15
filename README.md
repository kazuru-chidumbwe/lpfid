# LPFid

A livepatch module can load, report itself enabled and finish its transition while the fix it was built from is not actually in effect. LPFid checks for that. It accompanies the paper "Loaded but Not Fixed: Test Oracles for the Fidelity of Linux Livepatch Modules" by Seke Kazuru, and this repository holds the checks, the scripts that built and scored every module, and the run records behind the reported numbers.

## The checks

- **Binding oracle** (`oracle/`). Compares the relocations of each patched function in a module with an independent compile of the same fix, and with the sympos check confirms that every symbol position points at the copy defined in the right source file. It needs no knowledge of which fault, if any, was injected. Each version is a separate file; `preregistration/S16-oracle-freeze.md` gives every version's SHA-256, the reason it was added and the validation it passed before it scored anything new.
- **Eligibility check** (`eligibility/`). Decides whether a module can be tested by reverting it: shadow variables, callbacks, atomic replace and system states make a revert unsafe. The second version reads the struct layouts from the module's DWARF, or from any object of the same kernel build that has debug information.
- **Behavioural check** (`behavioural/`). Boots the pin in a virtual machine and runs a small probe before loading, after enabling and after disabling the module. It needs a contract per fix; the three used in the paper are in `behavioural/contracts/`.

## What else is here

| Directory | Contents |
| --- | --- |
| `corpus/` | Fix selection from the kernel CNA records, the build runner that restores each tree from the release tarball before every job, the independent reference compiles, and the klp-build runner |
| `mutation/` | The six operators that edit built modules (`redirect`, `swap`, `sympos`, `addend`, `dropcall`, `constant`) and the runner that applies them |
| `scoring/` | Scoring of each build set with every oracle version, the ablation and the cost measurement |
| `runtime/` | The loader check in a virtual machine and the end-to-end check of the wrong `pwq_cache` binding (CVE-2026-43074) |
| `generators/` | The kpatch-build and klp-build comparison, including the analysis of the objtool string fault in klp-build on Linux 6.19 and its run-time demonstration |
| `presence/` | The patch presence test runs |
| `faults/` | The codebook and coding of kpatch's defect history |
| `results/` | Every result file the paper reports. `results/s26` is the Amazon Linux 2023 draw: the verdict for every module, and the shipped module and reference objects retained for each divergence. `results/s34` is the OpenAnolis 7.7 census: every module, its reference objects and its verdicts |
| `preregistration/` | The plans, each committed before the runs it governs, with every dated deviation. `S26-shipped-amazon.md` and `S34-shipped-anolis.md` are the shipped-module plans |

`MANIFEST.sha256` lists the SHA-256 of every file.

## Running it

The oracle and the eligibility check need Python 3.11 or later with `pyelftools` and `capstone` 5.0.7. The builds used kpatch-build v0.9.7 to v0.9.11 and the in-tree klp-build of Linux 6.19, all with gcc 13.3.0; the loader and behavioural checks need QEMU with KVM. The scripts carry the paths of the machines used in the study, so set them for yours first.

To check one module against its reference objects:

```
python3 oracle/blind-reloc-oracle-v1.3.py MODULE.ko REF.o [REF.o ...] --vmlinux PIN/vmlinux --modules-dir PIN
```

It prints a JSON report and exits 0 when the module is consistent with the references, 1 when it diverges.

## Availability

The modules, reference objects, injected faults, pre-registrations and result files that support the paper are in this repository. The version of record will be archived on Zenodo [TBD: Zenodo DOI].

## Licence

MIT, see `LICENSE`. If you use LPFid, please cite it with the metadata in `CITATION.cff`.
