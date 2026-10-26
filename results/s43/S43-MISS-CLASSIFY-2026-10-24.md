# S43 miss classification, 24 Oct 2026

Read-only analysis of the nine held-out misses. No rule, operator, recipe or scored count changes. The S43 counts in
`S43-RESULT-2026-10-21.md` stay as scored under frozen v2.0, and the nine stay in their denominators.

| Group | Mutants | Classification |
| --- | --- | --- |
| `memcpy_sglist`, CVE-2026-31431 | x86-64 swap 39, addend 62, addend 63; AArch64 dropcall 34 | Oracle coverage failure: second definition of a repeated function name is not compared |
| `.rodata.<fn>.str1.8`, CVE-2025-39677 | AArch64 rodsec 1, 27, 31, 32, 38 | Content-equivalent rebinding: the moved reference reaches a byte-identical string |

## Objects

- x86-64: the scored files on Testbed B, `~/s43/x86/kernel-livepatch-6.12.74-98.124/`.
- AArch64: the Graviton host is terminated. The packages were fetched again on 24 Oct from Amazon's `kernel-livepatch`
  repository in the `s26-builder` image (the stock `amazonlinux:2023` image does not carry that repository and lists
  only the empty `1.0-0` release). Releases: `6.12.80-105.147` 1.0-9, `6.1.141-165.249` 1.0-3. All 25 scored packages
  were fetched: 121 modules, as scored. Identity: the frozen mutator (`d3068950781d9a17`) on the refetched modules
  gives, for every module of the two miss packages and every operator, the same site count and the same descriptor
  for every drawn site as `from-t4g/results-aarch64.jsonl`. Script `results/s43/_miss9_a64.py`; files on Testbed B under
  `~/s43/miss9/`. Oracle `7686843c93f5cb58`.

## memcpy_sglist: oracle coverage failure

The module patches two target modules, `authencesn` and `algif_aead`. Each defines a static `memcpy_sglist`, and both
replacement copies are linked into one section, `.text.memcpy_sglist`:

| Arch | Section size | First copy (`authencesn.c`) | Second copy (`algif_aead.c`) | Copies byte-identical |
| --- | --- | --- | --- | --- |
| x86-64 | 0x23c | [16, 284) | [304, 572) | yes |
| AArch64 | 784 | [0, 392) | [392, 784) | yes |

Every missed site is inside the second copy: x86-64 swap offsets 505 and 563, addend offsets 393 and 400; AArch64
dropcall offset 732. None is past a function symbol. The 21 Oct reading ("past the end of the symbol") checked the
offsets against the first copy only and is withdrawn.

Cause: `Obj.functions()` in oracle v2.0 (`oracle/blind-reloc-oracle-v2.0.py:335`) keys functions by name with
`setdefault`. The second definition of a name in the module is never compared. The mutator draws sites in both copies,
because it attributes a site by section and function name.

Exposure in the held-out draw: 1 of 110 x86-64 modules and 1 of 121 AArch64 modules define a FUNC name twice. Both are
this livepatch.

Exposure in development data: of the 58 S26 Amazon x86-64 modules kept locally (`repos/lpfid/results/s26/*/keep/`),
2 define a FUNC name twice, both `memcpy_sglist` in `livepatch-CVE-2026-31431` (`6.1.164-196.303`,
`6.12.68-92.122`). Their Section 7.6 verdicts covered the first copy only. The two 6.18 copies of that livepatch
define it once. The other 106 S26 modules are not on this PC and were not checked.

## .rodata.<fn>.str1.8: content-equivalent rebinding

The `rodsec` operator skips sections named `.rodata.str*` and `.rodata.cst*`. GCC names these merged-string sections
`.rodata.<function>.str1.8` (both carry `SHF_STRINGS`), so the filter did not skip them. Each mutant moves an
ADRP/lo12 pair to another section symbol with the addend kept:

| Site | Function | Moves | Addend | String reached, before and after |
| --- | --- | --- | --- | --- |
| 1 | `codel_change` | `.rodata.codel_reset.str1.8` to `.rodata.sch_tree_lock.str1.8` | 32 | `RTNL: assertion failed at %s (%d)\n` |
| 27 | `hhf_change` | `.rodata.hhf_change.str1.8` to `.rodata.pie_reset.str1.8` | 32 | `RTNL: assertion failed at %s (%d)\n` |
| 31 | `hhf_change` | same | 32 | `RTNL: assertion failed at %s (%d)\n` |
| 32 | `hhf_change` | same | 0 | `include/net/sch_generic.h` |
| 38 | `pie_change` | `.rodata.pie_reset.str1.8` to `.rodata.codel_reset.str1.8` | 0 | `include/net/sch_generic.h` |

All ten relocations are inside their function symbols. In every case the original and the moved reference reach the
same bytes: an RTNL assertion message and the file name `include/net/sch_generic.h`, emitted once per function
section. The oracle reads a string target as its text (Section 5.2.2), so it returns CONSISTENT by design. Each mutant
points at a different copy of an identical constant string. How the instructions use the pointer was not decoded.

## What this note does not change

No scored count, rule, operator or recipe. A version that compares every definition of a repeated name, or an operator
that skips `.str` sections by flag rather than by name, would be a new version and needs a new held-out draw.
