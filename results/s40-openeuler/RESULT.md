# S40 result: openEuler SysCare hotpatches (21 Oct 2026)

Pre-registration: `preregistration/S40-shipped-openeuler.md` (A1 units, A2 seen-before list, A3 release compiler and its
counting rule). Scorer `s40_score18.py`: one process, oracle v1.8 and v1.7 (N1C disabled) per module. Its v1.7
column reproduces every verdict of the original v1.7 run (`s40.<arch>.results.jsonl`), on both architectures.

## Counted verdicts (6.6: exact compiler rebuild; 4.19 and 5.10: release OS-repository compiler, A3)

| Kernel | x86-64 unit | funcs | verdict | AArch64 unit | funcs | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| 4.19 20.03-SP4 | ACC-1-7 | 10 | DIVERGENT `pinctrl_enable` | ACC-1-6 | 9 | DIVERGENT `pinctrl_enable` |
| 5.10 22.03-SP1 | ACC-1-17 | 24 | CONSISTENT | ACC-1-17 | 27 | CONSISTENT |
| 5.10 22.03-SP2 | ACC-1-9 | 12 | CONSISTENT | ACC-1-9 | 12 | CONSISTENT |
| 5.10 22.03-SP3 | ACC-1-12 | 26 | CONSISTENT | ACC-1-12 | 28 | CONSISTENT |
| 5.10 22.03-SP4 | ACC-1-6 | 16 | CONSISTENT | ACC-1-5 | 9 | CONSISTENT |
| 6.6 24.03 | ACC-1-6 | 22 | CONSISTENT | ACC-1-8 | 14 | CONSISTENT |
| 6.6 24.03-SP1 | ACC-1-4 | 10 | CONSISTENT | ACC-1-3 | 3 | CONSISTENT |

Totals: 12 of 14 modules consistent; 220 of 222 patched functions (x86-64 119/120, AArch64 101/102). Sympos
CONSISTENT on all 14. v1.8 and v1.7 agree on every module (no `changed`). Files: `results/s40-v18-a3.<arch>.jsonl`,
`results/s40-v18-update.<arch>.jsonl` (6.6 rows are counted from here).

Both residuals are representation differences, root-caused in `divergence-rootcause.md`: x86-64
refcount-overflow stub at a different offset of the concatenated `.text..refcount`; AArch64 dynamic-debug
descriptor named directly vs `__verbose` + offset. Same bindings, same argument registers.

## Update-compiler arm (sensitivity, verdicts seen before A3)

Release compilers: 20.03-SP4 gcc 7.3.0 (2020033101.58), 22.03-SP1 10.3.1-20, SP2-SP4 the release builds of
10.3.1 (`s40.a3.<arch>.run.log`). The update repositories carry 10.3.1-28 for 22.03-SP1 (checked in the images on
both hosts). With the update compiler, 22.03-SP1 also diverges: `ip6_finish_output2` (x86-64), and
`ip6_finish_output2` + `unix_stream_sendpage` (AArch64). Every other unit has the same verdict under both compilers.

## Opened-before-scoring packages (A1 item 4)

24.03 ACC-1-7 x86-64: CONSISTENT, 24 functions (sympos not checked: no debug vmlinux in that unit's directory).
Remaining four (24.03 ACC-1-8 x86-64; 20.03-SP4 ACC-1-7, 22.03-SP4 ACC-1-6, 24.03-SP1 ACC-1-4 AArch64): running,
`s40_run_sens.sh`, results `s40-v18-sens.<arch>.jsonl`.

