# S26 keep step: the kept module was the local build, not the shipped one (26 Oct 2026)

## Finding

The S26 rebuild control (`s26re-control-2026-10-26.txt`) compares the 58 modules S26 kept with the same modules
extracted again from the binary rpm. References: 1,302 of 1,304 byte-identical; the 2 that differ are `kheaders.o`
(the kernel's embedded header archive), not livepatch code. Modules: 57 of 58 differ.

`s26re_kocheck.sh` (`s26re-kocheck-2026-10-26.txt`) compares every non-debug section, the symbol table and the
disassembly: 1 of 58 the same, 57 differ in `.note.gnu.build-id`, symbols and `.klp.rela.*` sections, some also in
code (`disasm`).

## Root cause

`s26_run.py` (Testbed B `~/s26/`), keep step for every module that v1.3 or v1.4 did not call CONSISTENT:

    cp w/ko/<name>    keep/<patch>/      # shipped module, extracted from the binary rpm
    cp w/built/<name> keep/<patch>/      # module built locally by kpatch-build (kept for DWARF), SAME file name

The second copy overwrites the first, so every `keep/<patch>/<name>.ko` is the local build.

## What it touched

| Result | Module read | Status |
| --- | --- | --- |
| S26 v1.3, v1.4 verdicts (`result.json`) | shipped (`w/ko`, scored before the keep step) | valid |
| S26 `keep/*/v14.json` root-cause dumps | shipped (`w/ko`) | valid |
| S26 v1.6 rescore (`rescore_s26_v16.py`, `s26-v16-SUMMARY.json`), the 58 kept modules | local build | replaced by `bind-s26re-2026-10-26.jsonl` |
| S26 v1.6 rescore, the 106 others | v1.4 verdict carried over (shipped) | valid |
| A3 byte comparison, s26keep 58 rows (`body-x86-2026-10-25.jsonl`, corpus S26) | local build | replaced by `body-s26-2026-10-25.jsonl` (164 shipped, all CONSISTENT) |
| A4 immediate check, s26keep 58 rows (`imm-x86-2026-10-25.jsonl`, corpus S26) | local build | replaced by `imm-s26-2026-10-25.jsonl` (164 shipped, all CONSISTENT after RS) |
| Address check, design-draw CVE-2023-5090 (`addr-run1.txt`) | local build | rerun on the shipped module: SAME (`results/s45/addr-design-shipped-2026-10-26.txt`) |

## Replacement runs (all on modules extracted again from the rpm, `~/s44/s26re/keep/<pkg>/ko`)

- `s26re_bind.py`: oracle v1.6 (`LPFID_T1=version`) and census checker v2.1 on all 164, against the rebuilt
  references. Started 04:22 UTC; Testbed B went off the tailnet at 04:37 and rebooted (65 rows written, kept as
  `bind-s26re-2026-10-26.INVALID-partial-reboot.jsonl`); restarted from scratch 05:28 UTC.
- `s26_body.py` and `s44_imm.py s26re` read the same extracted modules.
