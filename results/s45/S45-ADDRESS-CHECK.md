# Address check for the alarms classified as one address named two ways, 25 Oct 2026

CVE-2023-5090 and `pinctrl_enable` had been classified by hand as representation differences. This replaces the
hand classification with a mechanical check.

Script `results/s45/addr_equiv.py` (rules R1 to R6 in its header). It resolves every relocation of the flagged function
in the module and in the reference to the target it denotes (symbol and byte offset; a string by its text; a
symbol-less code stub by its bytes up to `ud2`), cuts the sequence at calls, and compares segment by segment.
Run on Testbed B, venv `/opt/atlas/venvs/lpfid-oracle-v11`, output `addr-run1.txt`.

Two fixes before the counted run, both after a first run on the same cases: the `.klp.sym` name was stripped of
`.klp.sym.` but not of the object name (bug), and string targets had no rule, so R6 was added as the binding
check's own string rule (Table 3, "always"). No rule was changed after the counted run.

| Case | Module and reference relocations | Verdict | Rules that resolved the difference |
| --- | --- | --- | --- |
| CVE-2023-5090, 5 census modules (6.1.49-69.116, 6.1.49-70.116, 6.1.52-71.125, 6.1.55-75.123, 6.1.59-84.139) | 7 / 7 each | SAME | R2 end: `.rodata.direct_access_msrs+0x170` = `direct_access_msrs+0x170` |
| CVE-2023-5090, design draw (6.1.56-82.125) | 7 / 7 | SAME | same; rerun 26 Oct on the module as shipped (`addr-design-shipped-2026-10-26.txt`), SAME, after the kept copy proved to be the local build (`results/s44/S26-KEEP-OVERWRITE-2026-10-26.md`) |
| openEuler 20.03-SP4 ACC-1-7 x86-64, `pinctrl_enable` | 52 / 52 | SAME | R5: refcount stubs at different offsets, same bytes, no relocations |
| openEuler 20.03-SP4 ACC-1-7 AArch64 (sensitivity-arm objects), `pinctrl_enable` | 52 / 52 | SAME | R3 with folded `add #imm`: `__verbose+0xe0/0x118/0x150` = `descriptor.30281/.30286/.30290` |
| Control: all 9 injected mutants of `livepatch-CVE-2023-5090` on 6.1.49-69.116 (5 addend, 1 dropcall, 2 redirect1, 1 swap) | 7 / 7 | DIFFERENT, 9 of 9 | n/a |

The counted AArch64 openEuler unit (ACC-1-6) was scored on the Graviton host and its objects are gone. The
ACC-1-7 AArch64 objects (sensitivity arm, copied home 23 Oct) show the same divergence in the same function by the
same mechanism (`lab/s40/S40-DIVERGENCE-ROOTCAUSE-2026-10-20.md`), and are the AArch64 case checked here.
