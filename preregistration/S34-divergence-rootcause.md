# S34 divergence root cause (15 Oct 2026)

Census of the 39 OpenAnolis 7.7 kernel-hotfix packages named in `internal/S34-PREREG-2026-10-15.md`. The feasibility package is not in this denominator. Result files: Testbed B `~/s34-anolis/results/*/result.json`, with `v13.json`, `v14.json`, `body.json` and the reference objects under `refs/`.

## Population

39 packages, 39 modules, 17 builds of kernel 4.19.91. Four hotfixes: CVE-2023-0461 (19), CVE-2023-35788 (17), CVE-2023-35001 (2), 16349694 (1). Every reference object built. No package is a build failure.

Every module `.comment` is `GCC: (GNU) 4.8.5 20150623 (Anolis 4.8.5-44.0.1)`. Every reference `.comment` is `GCC: (GNU) 4.8.5 20150623 (Anolis 4.8.5-39.0.1)`. The registered rule is `LPFID_T1=version`.

## Verdicts

Binding oracle v1.3, binding oracle v1.4 and `body_check.py` agree on every package: 6 CONSISTENT, 33 DIVERGENT.

| Hotfix | Compared functions | Divergent functions | Packages |
| --- | --- | --- | --- |
| 16349694 | 1 | `ioc_qos_write` | 1 |
| CVE-2023-0461 | 1 | none | 5 |
| CVE-2023-0461 | 1 | `inet_csk_listen_start` | 14 |
| CVE-2023-35001 | 1 | none | 1 |
| CVE-2023-35001 | 1 | `nft_byteorder_eval` | 1 |
| CVE-2023-35788 | 3 | `init_module`, `cleanup_module` | 6 |
| CVE-2023-35788 | 3 | `init_module`, `cleanup_module`, `fl_set_geneve_opt` | 11 |

The patched function was compared in every package. It matches on 12 packages. On the other 27 it is the only patched-function alarm.

## Patched functions

For each of those 27, the instruction check reports one difference, at offset 0: the module is `call` (`e8 00 00 00 00` with the relocation bytes masked) and the reference is the five-byte nop `0f 1f 44 00 00`. The binding oracle's only relocation difference on that function is `PC32:__fentry__` in the module against `0:__fentry__-0x4` in the reference. Relocation type 0 is `R_X86_64_NONE`.

Checked with `readelf -rW` on one pair of each kind. Divergent pair `kernel-hotfix-CVE-2023-0461-4.19.91-26-1.0-20230327174446`: the reference object's `__fentry__` relocations are `R_X86_64_NONE` with addend -4; the module also has `R_X86_64_PC32` to `__fentry__` with addend -4. Consistent pair `kernel-hotfix-CVE-2023-0461-4.19.91-25.6-1.0-20230327221656`: both sides are `R_X86_64_PC32` to `__fentry__` with addend -4, and both checks say CONSISTENT. The compiler release differs on that pair as on every other pair, and the function still matches. The release gap is not a further difference in the fix.

## Scaffolding

All 39 modules contain `patch_exit`, `patch_find_object_by_name`, `patch_free_livepatch`, `patch_free_scaffold` and `patch_init`, which are not in the reference. Those symbols do not by themselves make the verdict DIVERGENT. On the 17 CVE-2023-35788 modules the oracle pairs `init_module` and `cleanup_module` with the patched object's own functions (`cls_fl_ops`, `register_tcf_proto_ops`, `unregister_tcf_proto_ops`). That is the scaffolding class already recorded for Amazon Linux in `internal/S26-DIVERGENCE-ROOTCAUSE-2026-10-13.md`. On 6 of those 17 the patched function `fl_set_geneve_opt` matches.

## Class

No patched function differs in any instruction other than the `__fentry__` entry. The class is a difference between this reference build and the shipped module's fentry relocation, plus the scaffolding pairing, not a fault in the shipped fix. The pre-registered vendor report was not triggered.


## Addendum: gcc-44 rebuild and rule RF (15 Oct 2026)

See `preregistration/S34-DEVIATION-gcc44-RF.md` and `results/s34-gcc44-SUMMARY.json`.

Under release-matched gcc 4.8.5-44.0.1 references and oracle / body-check version 1.5, every patched function on the 38 scored packages is CONSISTENT (26 functions accepted solely by RF). One package failed to rebuild (CVE-2023-0461 on 4.19.91-26.6) and stays a BUILD_FAIL. The 17 residual package-scope DIVERGENT verdicts are CVE-2023-35788 `init_module` / `cleanup_module` scaffolding only.
