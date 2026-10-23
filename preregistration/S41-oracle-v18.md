# S41 pre-registration: oracle v1.8 (numbered-local identity) and the `sibling` operator

Frozen 20 Oct 2026, before any module is scored with v1.8. Rule N1
rewrites every compiler number (`descriptor.30281`, `__func__.6`, `CSWTCH.373`) to `.N`, so a relocation rebound to
a sibling numbered copy of the same local compares equal. Probe on two openEuler x86-64 units: 0 of 4 such
rebindings detected. This is the class of kpatch defect 901445a (`__UNIQUE_ID()` copies differing in counter
digits), which the taxonomy places under Binding. The author chose to fix it rather than state it as a limit.

## Rule N1C (v1.8)

N1 is kept, and a numbered local whose copy is identifiable is labelled by its content as well as its base name:
`base.N#<digest>`, where the digest is sha256 (first 12 hex digits) over
- the object's size and bytes (for a no-bits object, the size only), and
- the relocations inside the object, in offset order, each as (type, normalised target) computed with the v1.7
  rules and without content tags (no recursion).

A copy is identifiable on one side when the relocation names the numbered symbol itself, or names a section
symbol plus an offset that falls exactly at the start of that symbol and the target is not an AArch64
section-anchor reference. On AArch64 a section-symbol reference into a section holding more than one sized object
is treated as an anchor (GCC may complete the address with an unrelocated add), so it carries no content tag.
x86-64 relocations carry the full offset, so this restriction does not apply there.

Per compared function and base name: if any relocation to that base on either side has no content tag (a
`.klp.sym` binding to the kernel's copy, an anchor, a zero-size symbol), the tags of that base are removed on
both sides and the v1.7 comparison applies to it. Kernel copies bound by `.klp.sym` remain the sympos check's
responsibility. Zero-filled copies of equal size (`__key` in `.bss`) have equal tags and stay indistinguishable;
this is reported as the residual limit.

N1C can be switched off with LPFID_DISABLE=N1C, which gives v1.7 exactly. No other rule changes.

## Operator `sibling` (new)

Rebind one site from a numbered local the module defines to a sibling copy of the same base name defined in the
module's symbol table (both halves of an AArch64 ADRP/lo12 pair). Sites are drawn as in Section 6.3: up to ten
per module, seeded per module, scaffolding excluded, functions the oracle compares only. Equivalent mutants:
a sibling with byte-identical content and identical inner relocations (e.g. two `__key` copies) is classed
`sibling-indistinguishable` and reported separately, never in the detection denominator (Section 4.3 rule 3
does not apply, because the binding does change).

## Evaluation (all static, all corpora rescored with v1.8)

1. Detection of `sibling` on the 123 real-fix modules against kpatch's objects and against the independent
   compile, v1.7 and v1.8, with Wilson intervals and McNemar on the paired mutants.
2. Every other operator re-scored with v1.8: detection must not fall; any change is reported.
3. False alarms re-scored with v1.8 on every set the paper reports: 123 real-fix unmodified modules (both
   references), fixtures, version sweep (292/291), 5.15 arm, gcc-14 arm, Debian-gcc benign rebuilds, klp-build
   6.19 (34 + 36 held-out), Amazon x86-64 (164), OpenAnolis (38), Amazon AArch64 (S39/S39b), S37 arm64 corpus,
   and S40 when it lands. Every new alarm is root-caused and reported; no rule is added after scoring.
4. Ablation row for N1C; cost (median time per module).

## Reporting

The paper reports v1.8 as the oracle, states N1C and the residual limit in Section 5.2.2, adds `sibling` to the
operator set with its v1.7 and v1.8 rates, and keeps every v1.7 number that v1.8 changes beside its v1.8 value
in the supplementary material.

## Implementation correction C1 (20 Oct, before any v1.8 result is used)

The first implementation tagged every symbol with a numeric suffix, including function clones
(`kzalloc.constprop.0`, `ptype_get_idx.isra.0`), which the rule above does not cover: it concerns numbered
local data. Tagging a function by its bytes made a change inside a called clone appear in every caller (seen in
the first replay: kpatch's `patch_init` differing in redirect mutants, and two `constant` mutants inside
`ptype_get_idx.isra.0` reported through `ptype_seq_next`). N1C now tags `STT_OBJECT` symbols only. The first
replay and sibling scores are archived as invalid and everything is rerun.
