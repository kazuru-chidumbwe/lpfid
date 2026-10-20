# S37 pre-registration: reference-differential binding oracle on arm64 (AArch64)

Frozen 19 Oct 2026, before any arm64 livepatch module is scored by the binding oracle. This registers the
design, the AArch64 relocation rules, the sample, the operators and the success criterion in advance, so the
arm64 result is a cross-architecture extension of the central check and not a post-hoc fit.

## Motivation

The reference-differential binding oracle's relocation rules and the klp-build comparison are x86-64. The
eligibility check is already validated on arm64 (S6B: Graviton, Ubuntu 6.17; 14 hazards over 12 in-tree
modules, no false alarm, only the replace-flag-in-code rule x86-64 specific). S37 extends the binding oracle,
the paper's central check, to arm64, to establish that its approach generalises to a second architecture.

## Host, pin and toolchain (recorded before the draw)

- Host: an arm64 host. Record hostname, uname -m
  (expect aarch64), CPU, RAM.
- Kernel pin: one arm64 stable release with CONFIG_LIVEPATCH=y, built natively. Record the exact release, the
  config, and the full aarch64 gcc and binutils banners from the objects' .comment sections.
- A module, its reference and its scoring share one host and one toolchain, as on x86-64 (Section 6.8).

## Subjects (frozen scope, pre-draw)

- In-tree livepatch modules: the kernel's `samples/livepatch/*.ko` and the livepatch selftest modules under
  `lib/livepatch/` (`test_klp_*`), built natively for the arm64 pin. These are the arm64 counterpart of the
  51 in-tree x86-64 fixtures (Section 6.1); they carry `.klp.rela` relocations into the kernel, which is what
  the binding oracle checks. The set that builds on arm64 with CONFIG_LIVEPATCH is the fixture set; the exact
  count is recorded after the build, and every module that builds stays in the denominator.
- Generator-produced arm64 modules are out of scope unless a generator is confirmed to build them. kpatch-build
  arm64 support is experimental and klp-build is x86-64 only in 6.19. If, and only if, kpatch-build builds
  arm64 modules from the real-fix selection rule on this pin, a real-fix arm is added under the same selection
  and seed as S12; this is recorded as a registered optional arm, built before it is scored.

## Reference

For each in-tree module, an independent compile of the same source (a separate native build of the sample
source on the pin), serving as the reproducible-build control, exactly as Section 5.2.3 treats in-tree
fixtures. No generator is in this path.

## AArch64 relocation normalisation (frozen rules, specified before scoring)

The oracle maps each relocation to (type-class, normalised target, effective offset). The naming rules N0 to
N5, the string/section-family rule and the effective-offset rule A1 (Section 5.2.2) carry over unchanged; only
the relocation-type decoding is architecture specific and is fixed here:

- Branches: `R_AARCH64_CALL26`, `R_AARCH64_JUMP26`, `R_AARCH64_CONDBR19`, `R_AARCH64_TSTBR14`,
  `R_AARCH64_LD_PREL_LO19` -> class BRANCH/PC-REL; target = symbol, offset = addend. AArch64 branch and
  PC-relative offsets are taken from the instruction's own address, so the x86-64 N4 end-of-instruction bias
  does not apply and is not used on this architecture.
- Symbol address via ADRP + ADD/LDST: `R_AARCH64_ADR_PREL_PG_HI21` (page, hi21) paired with
  `R_AARCH64_ADD_ABS_LO12_NC` or `R_AARCH64_LDST{8,16,32,64,128}_ABS_LO12_NC` (page offset, lo12) -> combined
  into one binding (class ADDR; target = symbol; effective offset = addend), so the page/lo12 representation
  split is normalised away while target identity and total offset are kept. This is the AArch64 counterpart of
  the x86-64 effective-offset handling; it is the one substantive new rule.
- Absolute and relative data: `R_AARCH64_ABS64/32/16`, `R_AARCH64_PREL64/32/16` -> class DATA; target =
  symbol, offset = addend.
- GOT/PLT/TLS types, if present in a livepatch module, are decoded to the same (class, target, offset) by
  naming normalisation; any relocation type not in this list makes the function's verdict INCONCLUSIVE, never
  a silent CONSISTENT (the toolchain and unknown-type guards of Section 5.2.1).

## Fault operators

redirect, swap, addend, dropcall, and sympos where a referenced name has more than one copy in the pin's
`vmlinux`, applied to the built arm64 modules exactly as Section 6.3 (edit the built module, up to ten sites
per operator and module, seed fixed per module and operator). `dropcall` writes the AArch64 NOP
(`0xd503201f`) over the call and voids its branch relocation. `constant` (the body class) is included to
confirm the binding oracle's blind spot is the same on arm64 and to exercise the immediate-differential check.

## Equivalent mutants, controls, metrics

- Equivalent mutants handled per Section 4.3: single-copy position sites enumerated and not mutated; mutants
  byte-identical to their parent discarded; a divergent-but-behaviour-preserving edit counted as detected.
- Two oracle controls per run (Section 6.7): a wrong-reference run must not be CONSISTENT; an unedited copy
  through the mutation path must be byte-identical and keep the module's own verdict. A build canary builds one
  module twice and must give identical symbols and relocations.
- Metrics: detection rate per operator and fault class, false-alarm rate on the unmodified in-tree modules,
  each with a Wilson 95% interval, in both multiset and sequence modes. Reported beside the x86-64 fixture
  rates.

## Success criterion (registered)

The binding oracle on arm64 detects the non-equivalent redirect, swap, addend and dropcall mutants at rates
whose Wilson intervals overlap the x86-64 fixture rates (target 100%), with zero false alarms on the
unmodified in-tree modules. The constant mutants are the declared blind spot (0 detection), as on x86-64. This
establishes that the oracle generalises to a second architecture. A shortfall is reported as found, with root
cause, and never papered over.

## Deviations policy

The AArch64 rules above are frozen before scoring. A relocation type met during the run that is not listed is
reported and left INCONCLUSIVE until a rule is added; any such rule is a dated deviation with a masking proof
(it must not reduce detection of any mutant the frozen rules detect), exactly as RF and RS on x86-64.

## Archive

The arm64 rule set, the modules, the references, the mutants and the verdicts are archived to `results/arm64/`
in the lpfid repository with this pre-registration, and the result updates Section 7.4 (a cross-architecture
paragraph) and Section 9.3 (the external-validity caveat narrows from "binding oracle is x86-64" to "both
static checks are evaluated on two architectures").

## Registered deviations (dated, before any module is scored)

**D1 Pin forced to Linux 6.19 (19 Oct 2026).** The prereg named "one arm64 stable release with
CONFIG_LIVEPATCH=y". arm64 selects `HAVE_LIVEPATCH` only once arm64 reliable stacktrace is in the tree. On the
corpus trees, `arch/arm64/Kconfig` in 6.12.51 does not `select HAVE_LIVEPATCH`, and 6.19 does (it selects both
`HAVE_LIVEPATCH` and `HAVE_RELIABLE_STACKTRACE`). The arm64 pin is therefore Linux 6.19, the first corpus
stable with arm64 livepatch, which is also the klp-build cross-generator pin (Section 6.2). Recorded before any
module is scored.

**D2 Cross-build on Testbed B, runtime leg deferred (19 Oct 2026).** The prereg specified a native arm64 host
build. The provisioned arm64 runtime host (2 GiB RAM) cannot link an arm64 `vmlinux` without OOM, so a
native kernel build is infeasible on it. The kernel, the in-tree subject modules and the independent reference
are cross-compiled on Testbed B with `aarch64-linux-gnu-gcc-13` (13.3.0), the exact version of Testbed B's
native gcc 13.3.0. The module and its reference share this one cross-toolchain, so the reproducible-build
control of Section 5.2.3 holds unchanged: the reference is still an independent second compile of the same
source with the same toolchain, and differs from the module only where the bytes differ. The binding oracle is
a static ELF comparison and is architecture-neutral, so it runs on Testbed B over the AArch64 objects. The
toolchain banner read from `.comment` is the `aarch64-linux-gnu` cross banner, identical on module and
reference. The runtime leg (boot the arm64 pin, `insmod`, read `enabled` and transition) is deferred to the
2 GiB arm64 host and reported separately; it is not part of the binding-oracle verdict and does not gate the
success criterion. The arm64 build is out-of-tree (`O=`), leaving the existing x86-64 6.19 build in place.

**D3 In-tree samples do not exercise the binding oracle; subjects revised (19 Oct 2026).** Validation before any
scoring falsified the subject premise in "Subjects". The seven in-tree `samples/livepatch/*.ko`, cross-built
for the 6.19 arm64 pin, carry no `.klp.rela.*` sections and no `.klp.sym`/`SHN_LIVEPATCH` symbols: their
replacement functions reference only exported symbols (for example `klp_enable_patch` as an ordinary `UND`
relocation). The livepatch ELF form that the binding oracle checks is produced by a generator
(kpatch-build/klp-build) that rewrites references to unexported and local symbols into `.klp.rela`; the in-tree
modules never pass through a generator, so they hold none. Confirmed by `readelf -SW`/`-sW` on all seven, and by
contrast with a genuine x86-64 kpatch fixture, which carries `.klp.rela.vmlinux..text.*`. Consequence:
  - The in-tree samples are retained only as the **AArch64 decode-validation and ordinary-relocation control
    set**. Their ordinary relocations do exercise every frozen AArch64 decode rule (`CALL26` branches,
    `ADR_PREL_PG_HI21`+`ADD/LDST*_ABS_LO12_NC` page/lo12 pairs, `ABS64/32`, `PREL32`), so they validate the
    decode and the redirect/addend/dropcall differential on real arm64 objects, with the registered zero
    false-alarm requirement. They do not test the `.klp.rela`/sympos layer.
  - The **binding-oracle subject set proper** is generator-produced arm64 modules carrying `.klp.rela`. The
    registered generator is kpatch-build (its source has aarch64 handling and honours `TARGET_ARCH=aarch64`
    with `CROSS_COMPILE=aarch64-linux-gnu-`). This is the prereg's already-registered optional arm, now
    promoted to the primary binding-oracle subject source on arm64, under the same selection rule and seed as
    S12 where a real-fix arm is built.
  - Any arm64 binding-oracle detection/false-alarm number in Section 7.4 is reported only over generated
    klp.rela modules. The decode-validation result over the in-tree samples is reported separately and labelled
    as decode validation, never as the klp binding result. The paper describes arm64 as in progress until these
    numbers exist.
