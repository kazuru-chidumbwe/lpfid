# LPFid

A livepatch module can load, report itself enabled and finish its transition while the fix it was built from is not actually in effect. LPFid checks for that. It accompanies the paper "Loaded but Not Fixed: Test Oracles for the Fidelity of Linux Livepatch Modules" by Seke Kazuru, and this repository holds the checks, the scripts that built and scored every module, and the run records behind the reported numbers.

**Version of record:** [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23409014.svg)](https://doi.org/10.5281/zenodo.23409014)  
Release `v1.0.1` → https://doi.org/10.5281/zenodo.23409014 (concept DOI for all versions: https://doi.org/10.5281/zenodo.23408955; first deposit `v1.0.0` → https://doi.org/10.5281/zenodo.23408956).

## The checks

- **Binding oracle** (`oracle/`). Compares the relocations of each patched function in a module with an independent compile of the same fix, and with the sympos check confirms that every symbol position points at the copy defined in the right source file. It needs no knowledge of which fault, if any, was injected. Each version is a separate file; `preregistration/S16-oracle-freeze.md` gives every version's SHA-256, the reason it was added and the validation it passed before it scored anything new. **Shipping for Section 7.6:** `blind-reloc-oracle-v1.6.py` (rules RF + RS). Disable either rule with `LPFID_DISABLE=RF`, `LPFID_DISABLE=RS`, or `LPFID_DISABLE=RF,RS`.
- **Body / instruction check** (`oracle/body_check_v16.py`, paired with v1.6). Earlier freezes keep `body_check.py` / `body_check_v15.py`.
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
| `results/` | Every result file the paper reports. `results/s26/` is the Amazon Linux 2023 draw (per-module verdicts and retained objects for divergences). `results/s26-v16-SUMMARY.json` is the Section 7.6 automated rate under oracle v1.6 (**163/164 CONSISTENT**; one `.rodata` residual). `results/s34/` is the OpenAnolis 7.7 census trees. `results/s34-gcc44-SUMMARY.json` is the release-matched gcc 4.8.5-44 / oracle v1.5 census used with RF in Section 7.6 |
| `preregistration/` | Plans committed before the runs they govern, with dated deviations. `S26-shipped-amazon.md` and `S34-shipped-anolis.md` are the shipped-module plans. `S34-DEVIATION-gcc44-RF.md` (oracle v1.5, rule RF) and `S26-DEVIATION-RS-v16.md` (oracle v1.6, rule RS); Deviations 5–6 in `S16-oracle-freeze.md` |

`MANIFEST.sha256` lists the SHA-256 of every file.

## Running it

The oracle and the eligibility check need Python 3.11 or later with `pyelftools` and `capstone` 5.0.7. The builds used kpatch-build v0.9.7 to v0.9.11 and the in-tree klp-build of Linux 6.19, all with gcc 13.3.0; OpenAnolis S34 scoring also used the package-matched gcc 4.8.5-44.0.1. The loader and behavioural checks need QEMU with KVM. The scripts carry the paths of the machines used in the study, so set them for yours first.

To check one module against its reference objects with the **shipping** oracle (v1.6):

```
python3 oracle/blind-reloc-oracle-v1.6.py MODULE.ko REF.o [REF.o ...] --vmlinux PIN/vmlinux --modules-dir PIN
```

It prints a JSON report and exits 0 when the module is consistent with the references, 1 when it diverges. Earlier freezes remain in `oracle/` for score reproduction (`v1.3` … `v1.5`).

## Paper claims → files (Section 7.6)

| Claim | File / tool |
| --- | --- |
| Amazon 163/164 CONSISTENT under v1.6 | `results/s26-v16-SUMMARY.json`, `oracle/blind-reloc-oracle-v1.6.py` |
| Amazon residual CVE-2023-5090 | same summary `residual[]`; objects under `results/s26/` |
| OpenAnolis gcc44 / RF census | `results/s34-gcc44-SUMMARY.json`, `oracle/blind-reloc-oracle-v1.5.py` |
| RF / RS freeze rationale | `preregistration/S34-DEVIATION-gcc44-RF.md`, `preregistration/S26-DEVIATION-RS-v16.md`, `preregistration/S16-oracle-freeze.md` |

## Availability

The modules, reference objects, injected faults, pre-registrations and result files that support the paper are in this repository and archived on Zenodo:

- Version DOI (release `v1.0.1`): https://doi.org/10.5281/zenodo.23409014  
- Concept DOI (all versions): https://doi.org/10.5281/zenodo.23408955  
- First deposit (`v1.0.0`): https://doi.org/10.5281/zenodo.23408956  
- GitHub: https://github.com/kazuru-chidumbwe/lpfid

## Licence

MIT, see `LICENSE`. If you use LPFid, please cite it with the metadata in `CITATION.cff`.
