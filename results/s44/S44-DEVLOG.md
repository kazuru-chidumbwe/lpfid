# S44 development log

Development data for oracle v2.1. Nothing here is held-out. Protocol: `preregistration/S44-census.md`.

## 24 Oct 2026: v2.0 against v2.1 on the S43 x86-64 objects

Script `results/s44/s44_regress.py`, Testbed B, 12 workers, `/opt/atlas/venvs/lpfid-oracle-v11` (capstone 5.0.7,
pyelftools 0.33), the S43 pairing rule. Oracle v2.0 `7686843c93f5cb58`, v2.1 `6d63c19d5cf2b084`. Result
`results/s44/regress-x86-2026-10-24.jsonl` (sha256 `2e1e424b62dc5d70`).

- Files: 3,884, the 110 unmodified modules and every stored mutant. Errors: 0.
- The v2.0 verdict reproduces the verdict recorded in `results/s43/results-x86_64.jsonl` on 3,884 of 3,884
  files.
- v2.1 differs from v2.0 on 3 files, the three x86-64 S43 misses, each CONSISTENT under v2.0 and DIVERGENT under
  v2.1 in `memcpy_sglist@algif_aead.c`: `swap-39`, `addend-62`, `addend-63` of `livepatch-CVE-2026-31431` on
  `kernel-livepatch-6.12.74-98.124`.
- v2.1 raises no alarm on the 110 unmodified modules.

An earlier run of the same script under the system Python, which has no capstone, so that N4 fell back, is archived
as invalid on Testbed B (`~/s44/invalid/`). Its counts were the same (3,884 files, 3 differences); it is not used.

Not run: the AArch64 S43 objects. Their references were on the terminated Graviton host. The five AArch64 misses are
classified in `results/s43/S43-MISS-CLASSIFY-2026-10-24.md` from the refetched modules.

## 24 Oct 2026: S26 Amazon x86-64 under v2.1

The shipped modules of all 30 S26 packages were fetched again on Testbed B (`~/s44/dev-s26/`, `s26-builder` image):
164 modules, as S26 scored. Two define a function name twice, both `memcpy_sglist` in `livepatch-CVE-2026-31431`
(`6.1.164-196.303`, `6.12.68-92.122`); no other S26 module does, so MDUP cannot change any other S26 verdict. Both
have kept references (`~/s26/results/<pkg>/keep/CVE-2026-31431/ref/`). Under v2.0 and v2.1 both are CONSISTENT on the
patched functions (scaffolding `init_module`, `cleanup_module` as before). v2.1 compares `memcpy_sglist` against
`authencesn.o` and `memcpy_sglist@algif_aead.c` against `algif_aead.o`. The Section 7.6 count of 163 of 164 holds
under v2.1 with both definitions compared.

## 24 Oct 2026: S39 Amazon AArch64 under v2.1

The shipped modules of the 24 S39 packages were fetched again on Testbed B (`~/s44/dev-s39/`): 123 modules, as S39
scored. None defines a function name twice, so MDUP cannot change any S39 verdict, and no S39 reference needs a
rebuild.

## 24 Oct 2026: every other development corpus under v2.1

Repeated FUNC names counted on Testbed B (pyelftools, mutant directories excluded):

| Corpus | Modules | Define a name twice |
| --- | --- | --- |
| openEuler hotpatches (`~/s40/**/ko/`) | 16 | 0 |
| OpenAnolis (`~/s34-anolis`) | 79 | 0 |
| kpatch-build real fixes and version sweep (`/opt/atlas/s12/results/*/*/*/build/lp*.ko`) | 476 | 0 |
| klp-build 6.19 (`/opt/atlas/s12/results/klp-gcc-13`) | 61 | 0 |
| klp-build held-out 6.19 (`/opt/atlas/s12/s11-heldout`) | 72 | 0 |
| klp-build objtool control (`/opt/atlas/s12/s11-fixobjtool`) | 9 | 0 |

The `~/s40` target-module objects (`nf_tables.ko`, `drm.ko`) repeat names but are not livepatch modules. MDUP cannot
change a verdict in any of these corpora. With S26 and S39 above, no development number of Sections 7.2 to 7.6 moves
under v2.1.
