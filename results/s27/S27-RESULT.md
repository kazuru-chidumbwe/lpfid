# S27 result: immediate-multiset check, 14 Oct 2026

Follows S27-PREREG-2026-10-14.md (rule frozen before scoring). Run on Developer Node, detached;
outputs at `/opt/atlas/s27-out/` (SUMMARY.json, freeze.json, rows.jsonl). Check and runner archived
here (`s27_immcheck.py`, `s27_run.py`). Reuses the frozen binding oracle's `Obj` for ELF parsing,
function ranges and relocation coverage; adds capstone decode of each function's non-relocation
instruction immediates.

## Corpus

- Detection: the 1,111 constant mutants of the 123 real-fix modules (6.1.119, 6.6.47, 6.12.51),
  each scored against its independent reference `refs-independent/<pin>/<CVE>/**/*.o`. 1,111 scored,
  0 without a reference.
- False alarms, same toolchain: 122 unmodified gcc-13 parent modules vs the gcc-13 reference.
- False alarms, cross toolchain: 33 gcc-14 parent modules vs the gcc-13 reference (the version-sweep
  pairs already built).
- Toolchain gate disabled throughout so the immediate comparison always runs; the same-vs-cross
  toolchain contrast is the measurement, not a gate verdict.

## Numbers

| Measure | frame OFF (no normalisation) | frame ON (IMM-FRAME) |
| --- | --- | --- |
| Detection, constant mutants | 1111/1111 = 100% (99.66 to 100) | 1024/1111 = 92.17% (90.44 to 93.61) |
| False alarms, same toolchain | 0/122 = 0% (0.0 to 3.05) | 0/122 = 0% (0.0 to 3.05) |
| False alarms, cross toolchain | 12/33 = 36.4% (22.2 to 53.4) | 11/33 = 33.3% (19.8 to 50.4) |

Equivalent-mutant reachability pass excluded 0 (a changed immediate is visible to the static check
whether or not its block is reachable; no mutant sat in an unreachable block).

## Reading

The check **closes the body/constant blind spot when the reference is built with the delivered
module's own toolchain**: 100% detection, 0 false alarms on 122 same-toolchain faithful modules. This
is the setting a generator's own post-build self-check occupies (its own patched objects, the kernel's
pinned compiler), and it is the S26 shipped-distribution setting.

It is **not robust across toolchains**: a reference built by a different gcc version lights up ~a third
of faithful modules, each a benign code-generation difference in immediate constants (folded constants,
structure offsets, error codes), e.g. `ah6_output` where gcc-14 carries immediates 0, 24, -22 that
gcc-13 does not. The IMM-FRAME rule (drop stack-frame-adjust immediates) barely moves the cross-toolchain
rate (36%→33%) because the variation is broad, not frame-size-dominated, while it hides 87 frame-targeting
constant mutants. We therefore do **not** adopt IMM-FRAME; the reported check is frame OFF, with the
ablation shown for transparency.

## Decision-rule outcome (per prereg)

**Mixed / measured operating point**, not the single "strong" label: 100% detection and 0 same-toolchain
false alarms (strong-side) together with a 36% cross-toolchain false-alarm rate (limit-side). The body
class is detectable by a static check under same-toolchain pinning; without pinning the blind spot is
intrinsic to a build-differential oracle. This replaces the former 04-fidelity / Section 8.1 claim that
the body class is "covered by the behavioural check" (which caught 0 of 14).

## Fixture freeze (repaired 14 Oct 2026)

The fixture-freeze phase first located only 3 of 78 fixtures because its parent and reference path globs
were wrong (they pointed at the S12 real-fix references, not the S1 fixture tree). Repaired to the real
layout, parents at `s1full/parents/<ver>/<name>/<name>.ko` and references at
`s1full/refs/<ver>/<mid>/<name>/`, the phase now scores 51 of the 78 fixtures (the other 27 lack a built
parent in the tree). All 51 are CONSISTENT under both frame OFF and frame ON, so on the design set
IMM-FRAME introduces no false alarm, and the pre-registered rule is frozen ON there
(`frozen_rule: IMM-FRAME_ON`, `freeze.json`, backup `freeze.json.bak-hollow`).

This is the pre-registration, made on the fixtures before the real corpus was scored. The held-out
ablation then showed IMM-FRAME hides 87 of the 1,111 real constant mutants while clearing almost none of
the cross-toolchain false alarms (36.4% to 33.3%), so the reported operating point is frame OFF. The
headline is unaffected: both configurations are computed for every mutant and faithful module, and the
operating-point choice is made transparently from the ablation, now on a freeze that is grounded in 51
fixtures rather than a hollow one.
