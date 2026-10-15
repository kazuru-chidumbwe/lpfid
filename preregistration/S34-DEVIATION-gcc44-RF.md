# S34 deviation: gcc 4.8.5-44.0.1 references and oracle rule RF (15 Oct 2026)

Dated after the census root cause in `preregistration/S34-divergence-rootcause.md`. Completed on Testbed B (`~/s34-anolis/results-gcc44/`). Summary in this repository: `results/s34-gcc44-SUMMARY.json`.

## Why

1. The registered comparison used `LPFID_T1=version` because the Anolis 7.7 `os` repository's gcc was 4.8.5-39.0.1 while every shipped module banner is 4.8.5-44.0.1. That release is in `updates/` (`gcc-4.8.5-44.0.1.an7.x86_64.rpm` and companions). Rebuilding every reference with 44.0.1 removes the release-only soft spot.
2. On 27 of 39 packages the patched function differs only at the fentry probe: module `PC32:__fentry__` (live `call`), reference `R_X86_64_NONE` to `__fentry__` (five-byte nop). After rule R0 drops NONE, v1.4 reports one extra module row (`PC32:__fentry__`) and empty `only_in_reference`. That is a representation class, not a fix fault.

## Change

1. Install gcc 4.8.5-44.0.1 into the S34 `/a7` rootfs from Anolis 7.7 updates.
2. Rebuild every census reference object with that gcc; score into `~/s34-anolis/results-gcc44/` (original `results/` kept; package trees under `results/s34/` in this repository are the first census).
3. Oracle **v1.5** = v1.4 + rule **RF**: if a function's only relocation difference is `only_in_module == ["PC32:__fentry__"]`, `only_in_reference` empty, and `n_mod == n_ref + 1`, accept the function. Disable with `LPFID_DISABLE=RF`.
4. **body_check v1.5**: if the only instruction differences are the entry call/nop pair above, accept the function. Disable with `LPFID_DISABLE=RF`.

| File | SHA-256 (LF) |
| --- | --- |
| `oracle/blind-reloc-oracle-v1.5.py` | e8a402134394c86947950f2a58d8b2c2e2ce179f405e2aa31258752e833b8aa0 |
| `oracle/body_check_v15.py` | 974cd4d4bf7986ee2ddc9137d716ede2fc00eaa4dab48b928e2a487ce43cebba |
| Source v1.4 | b6496d03866701c15d71366d7322f8d5b7f2ee71e1bb2b5394054099d1d0ed29 |

## Non-masking (PASS, 15 Oct 2026)

- **A** `LPFID_DISABLE=RF`: live v1.5 overall_verdict equals live v1.4 on every scored package.
- **B** On an RF-accepted package (16349694), body_check v1.5 is CONSISTENT with RF and DIVERGENT with RF disabled.
- **C** No package whose v1.4 divergent patched functions include a non-fentry shape becomes package-CONSISTENT under RF solely by over-clearing those shapes.

Script: `scoring/non_masking_check_rf.py`.

## Final census (`results/s34-gcc44-SUMMARY.json`)

| Scope | v1.4 (gcc44) | v1.5 / body v1.5 |
| --- | --- | --- |
| Packages scored | 38 (1 BUILD_FAIL: CVE-2023-0461 on 4.19.91-26.6) | same |
| Package overall | 6 CONSISTENT / 32 DIVERGENT | 21 CONSISTENT / 17 DIVERGENT |
| Patched function (ignore `init_module` / `cleanup_module`) | 12 CONSISTENT / 26 DIVERGENT | **38 / 38 CONSISTENT** |
| `rf_pairs` total | — | 26 |

All 17 residual package-level DIVERGENT under v1.5 are CVE-2023-35788 scaffolding. RF does not clear them. No patched function remains divergent.
