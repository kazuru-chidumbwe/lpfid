# S45: six-operator campaign re-scored under the census checker v2.1 (25 Oct 2026)

Confirmation that the 7.5.1 rates, measured with development checkers, hold under v2.1. `rescore_s2_v21.py` on
Testbed B (`~/s45`), S2 pairing (kpatch's own patched objects plus `patch-hook.o`, pin `vmlinux` and tree).
Output `s2-v21.jsonl`, 8,414 rows, sha256 388e443d1322, 0 errors.

| | v1.1 recorded | v2.1 |
|---|---|---|
| Unmodified parents (123 real-fix + 78 fixtures) | | 201 CONSISTENT |
| Real-fix addend | 768 + 3 CONSISTENT | 771 DIVERGENT |
| Real-fix redirect | 1,216 + 1 CONSISTENT | 1,216 + 1 CONSISTENT |
| Real-fix swap / dropcall / sympos | 1,118 / 1,135 / 32 | same |
| Real-fix constant | 1,111 CONSISTENT | same (out of the binding check's scope) |
| Fixture addend | 620 + 13 CONSISTENT | 633 DIVERGENT |
| Fixture redirect / swap / dropcall / sympos | 568 / 583 / 628 / 6 | same |

No verdict goes from DIVERGENT to CONSISTENT. The 16 changes all go the other way: the three real-fix addend mutants
that the string-prefix rule already recovers in the paper's 771 of 771, and 13 fixture addend mutants. The one
real-fix redirect that stays CONSISTENT is CVE-2024-47674 `redirect-9`, the equivalent mutant of `lab/s2/` (edits
an `.altinstr_replacement` that no `.altinstructions` entry points at). The manuscript's 7.5.1 counts therefore hold
under v2.1 unchanged: 2,366 of 2,366 binding, 771 of 771 addend, 1,135 of 1,135 dropped calls, 0 of 123 false
alarms.
