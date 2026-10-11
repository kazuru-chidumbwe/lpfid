# S6b pre-registration: eligibility check v2 on held-out populations (11 Oct 2026)

Written and committed before any held-out module is labelled, built or scanned. Plan item S6b (RQ3, manuscript 5.x eligibility check, 7.4). The S6 result and its root cause: `lab/PRE-REAL-RESULT-2026-10-07.md`.

## Check under test

- v1: `pilot/scripts/pre-revert-scan.py` as in S6 (symbol names and strings).
- v2: `pilot/scripts/pre-revert-scan-v2.py`, harness commit 40af3cb, SHA-256 ef82b9e7cbb64a7e14b07e156a79bd4542a24ddb305ddda9920800e0ba1ea9cf, frozen now. Struct layouts from the module's DWARF, else from a types object of the same kernel build (`--types`, here the pin's `kernel/livepatch/core.o`). Hazards: SHADOW, STATES, CALLBACKS, REPLACE (rules in the script header). A module without type information is UNDETERMINED for the struct hazards.
- v2 was written after seeing the S6 population; on its 51 scanned modules it agrees with every label (recall 31/31, specificity 20/20; `/opt/atlas/lpfid/s6b-dev-fit-score.json`). That is a fit and is reported as such.

## Labels

Mechanical, from source only: `lab/s6b/label_source.py`, which implements the S6 protocol rules (`pilot/results/LP-PRE-REAL/LABEL-PROTOCOL.md`). Checked before any held-out use against the 60 hand-made S6 labels: 60 of 60 agree on every hazard and the class (`lab/s6b/check_labeller.py`). REPLACE for generator-built modules is fixed by the recorded build flag. Labels for every held-out module are written and committed (`lab/s6b/heldout-labels.json`, with SHA-256) before it is built or scanned.

## Held-out populations

- **B1, same upstream sources on new pins (layout robustness).** Every livepatch module source in `samples/livepatch/` and `tools/testing/selftests/livepatch/test_modules/` at tags v6.12 and v6.19, built as external modules with debug information against the 6.12.51 and 6.19 pins. Target modules are excluded by the protocol rule. Sources new since the S6 tags (`test_klp_syscall.c`, `test_klp_kprobe.c`) are reported separately.
- **B1s, the same modules stripped of debug information** (`strip --strip-debug`), scanned with `--types` set to the pin's `kernel/livepatch/core.o`.
- **B2, production-like modules (false alarms).** The 123 S12 kpatch-build modules and the 34 S11 klp-build modules, and the held-out H modules (S16 Deviation 4) when built. Labels from the fix diff's added lines; REPLACE 0 by build flag (kpatch-build `-R`, klp-build `--no-replace`).
- **B3, atomic replace on (positives for the run-time replace rule, which no S6 module exercises).** Five fixes from the S12 6.12.51 sample (the first five built ones in CVE order) rebuilt with kpatch-build v0.9.11 without `-R`, and five fixes from the S11 6.19 sample (the first five built ones in CVE order) rebuilt with klp-build without `--no-replace`; REPLACE 1 by build flag, the other labels from the fix diff.

## Measures

Per population, v1 and v2 side by side: class confusion (positive = OUT_OF_SCOPE), recall, precision and specificity with Wilson 95% intervals, per-hazard confusion, and the number of UNDETERMINED modules (reported, counted as OUT_OF_SCOPE as in S6). Every disagreement is root-caused. Results are reported per artifact and per unique source.

## Rules

No rule above changes after the first held-out module is built. A runner fault means the run is archived as invalid and rerun. Builds that fail are reported with their cause, not forced.

## Labels committed (11 Oct 2026, before any held-out build or scan)

`lab/s6b/heldout-labels.json`, SHA-256 67020ea87f0bb40b58eee98fe95eabd8b7d5e9ef866c12d9b41fa6eb929b1d64, written by `lab/s6b/make_heldout_labels.py`. B1: 24 modules (18 OUT_OF_SCOPE, 6 PASSES_PRE), B1s: the same 24 stripped, B3: 10 (OUT_OF_SCOPE by the replace flag), B2: 231, all PASSES_PRE. B2 holds every kpatch-build v0.9.11 gcc-13 module built (the S12 sample and the 5.15 arm of the version sweep), the 34 S11 klp-build modules and the 40 held-out H fixes; this is wider than the 123 + 34 named above, and every row is reported. 13 sources excluded as target modules.

## Amendment (11 Oct 2026, before any held-out scan was scored into the paper): what the labeller shows, and two independent checks

- The mechanical labeller applies the same written rules as the September hand labels; its 60 of 60 agreement shows the rules are applied consistently and the labels are reproducible, not that an independent rater would agree. It is reported as a consistency check, never as a second rater.
- Independent check 1 (run time, REPLACE only): every B1 and B3 module that loads is loaded on its pin in a virtual machine on the runtime host, and `/sys/kernel/livepatch/<patch>/replace` is read after the transition. The kernel's value is compared with the label and with v1 and v2. The other hazards have no kernel readout.
- Independent check 2 (human, all hazards): a second coder labels a random sample from source with the written rules, blind to the labels and the scanners: 12 of the B1 sources (unique source per pin, `random.Random(20261011)`) and 15 B2 fix diffs (same seed). Cohen's kappa per hazard and for the class, with 95% intervals.

## Amendment: population B4, arm64 (11 Oct 2026, before any B4 module is built, labelled or scanned)

- Machine: an AWS EC2 t4g.small (Graviton, aarch64), Ubuntu 24.04, kernel 6.17.0-1017-aws (CONFIG_LIVEPATCH=y, DEBUG_INFO=y, no lockdown, Secure Boot off).
- Population: every livepatch module source in `samples/livepatch/` and `tools/testing/selftests/livepatch/test_modules/` at mainline tag v6.17, built natively as external modules against the running kernel's headers (gcc 13.3.0). Target modules excluded by the protocol rule. Labels by `lab/s6b/label_source.py`, written before any scan.
- Scans: v1 and the frozen v2 (no change), layouts from the modules' own DWARF.
- Run time: each module loaded alone on the running kernel, `/sys/kernel/livepatch/<patch>/replace` read after the transition (and with `replace=1` for the parameter-controlled ones), then disabled and removed before the next.
- Known before running: v2 finds code that stores to `klp_patch.replace` with x86-64 instruction decoding and x86-64 relocation types, so those rules are not expected to work on arm64; static initialisers and section- and symbol-based rules are architecture-independent. Every result is reported; B4 measures portability, and the paper's claims about v2 remain x86-64 claims.
- Scoring rule for B4 (added before any B4 scan): v2 is scored on arm64 only through its architecture-neutral evidence (static initialisers of `klp_patch` and `klp_object`, `.init.klp_objects`, `__kpatch_callbacks_*` symbols, imported symbols). A REPLACE label whose only source is a store in code (a module parameter, for example) is reported as "not testable on arm64 with v2's x86-64 code rules" and is excluded from v2's B4 accuracy, whether v2 finds it or not. The paper states B4 as a test of the architecture-neutral rules only.
