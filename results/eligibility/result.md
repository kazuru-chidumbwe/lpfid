# S6b: eligibility check v2 on held-out populations, interim (11 Oct 2026)

Pre-registration: `internal/S6B-PREREG-2026-10-11.md`; labels `heldout-labels.json` (SHA-256 67020ea8...), committed before any build or scan. Scanners: v1 = `pre-revert-scan.py` at harness tag v0.2.2 (the S6 version, SHA-256 52ad419f...), v2 = `pre-revert-scan-v2.py` (harness 40af3cb, ef82b9e7...). Runner `s6b_run.py`; scores `score-interim-2026-10-11.json` (copy of the build host `/opt/atlas/lpfid/s6b/score.json`). Positive class = OUT_OF_SCOPE.

| Population | n | v1 recall | v1 specificity | v2 recall | v2 specificity | v2 undetermined |
| --- | ---: | --- | --- | --- | --- | ---: |
| B1: in-tree sources on 6.12.51 and 6.19, with debug info | 24 | 12/18 | 6/6 | 18/18 (Wilson 0.82 to 1) | 6/6 | 0 |
| B1s: the same modules stripped, `--types` = pin `kernel/livepatch/core.o` | 24 | 12/18 | 6/6 | 18/18 | 6/6 | 0 |
| B2: real-fix modules (kpatch S12 and 5.15 arm, klp-build S11) | 191 | n/a | 191/191 | n/a | 191/191 (0.98 to 1) | 0 |

- v2 agrees with every label on every hazard in B1 and B1s; no disagreement to root-cause.
- v1 misses the same class as in S6: every module whose only hazard is callbacks (callbacks-demo, test_klp_callbacks_demo, test_klp_callbacks_demo2 on both pins), and in the three state modules it finds only STATES (callbacks and replace missed; class right).
- B2: no false alarm from either version on 191 modules built by both generators.
- Pending: B3 (replace on: 5 kpatch-build without -R, 5 klp-build without --no-replace), the 40 held-out H stock modules in B2. Then final score and manuscript text (7.x eligibility, 5.x unchanged).

## Independent check 1: the kernel's own `replace` (11 Oct 2026)

`runtime_replace.sh` on the runtime host: each B1 module booted alone on its pin under KVM, `/sys/kernel/livepatch/<patch>/replace` read after the transition; the two modules whose replace is a module parameter were also loaded with `replace=1`. Outputs `runtime-replace/replace.tsv`, `replace-param.tsv`, comparison `runtime-replace/compare.json`.

- All 24 modules loaded, reported `enabled` and completed the transition.
- Kernel value: 1 for test_klp_state, state2, state3 (static), and for test_klp_atomic_replace and test_klp_callbacks_demo2 with `replace=1` (0 at their default); 0 for the other 14 on each pin.
- Agreement with the kernel (a module counts as replace when any parameter setting gives 1): label 24/24, v2 24/24, v1 16/24 (v1 misses test_klp_callbacks_demo2 and the three state modules on both pins).
- This check depends neither on the labelling rules nor on either scanner. B3 (kpatch-build and klp-build with replace on) is added when those builds exist.

## B4: arm64 (11 Oct 2026)

AWS EC2 t4g.small (Graviton), Ubuntu 24.04, kernel 6.17.0-1017-aws; 12 livepatch modules from mainline v6.17 `samples/livepatch` and selftest `test_modules`, built natively (gcc 13.3.0) with DWARF; labels `b4/b4-labels.json` (SHA-256 5404c2b6...) committed before any build; scores `b4/b4-score.json`; run time `b4/runtime-replace.tsv`. Scored under the registered rule: v2 only through its architecture-neutral evidence.

| Hazard | v1 | v2 (architecture-neutral rules) |
| --- | --- | --- |
| SHADOW (2 modules) | 2/2 | 2/2 |
| CALLBACKS (6) | 0/6 | 6/6 |
| REPLACE by static initialiser (3) | 0/3 | 3/3 |
| STATES (3) | 3/3 | 3/3 |
| False alarms (any hazard) | 0 | 0 |

- Not testable on arm64, as registered: REPLACE set through a module parameter (test_klp_atomic_replace, test_klp_callbacks_demo2). v2's code-store rules (x86-64 decoding and relocation types) found nothing there, so on arm64 v2 calls test_klp_atomic_replace eligible (its only hazard); test_klp_callbacks_demo2 is still flagged through its callbacks. v1 flags test_klp_atomic_replace through the string "replace".
- Kernel readout: all 12 loaded, enabled and completed the transition; `replace` = 1 for test_klp_state, state2, state3, and for the two parameter modules with `replace=1` (0 at default); 0 elsewhere; label agrees 12/12. All modules disabled and removed afterwards; no oops.
- Reading: v2's architecture-neutral rules carry over to arm64 unchanged; its run-time replace rule does not, and the paper states v2's claims for code-set replace as x86-64 claims.
