# S43 pre-registration: held-out trial of oracle v2.0 on never-opened shipped livepatches

Frozen 21 Oct 2026 and committed before any drawn package is fetched for evaluation.

Purpose. The only held-out test of v2.0. Every earlier corpus is development data (S42). S43 measures, on packages
never opened before, both false alarms (unmodified shipped modules) and detection (seeded injected faults in those
same modules), with v2.0, the operators and both reference recipes frozen by hash before any package of the draw is
fetched for evaluation.

## Frozen before any package of the draw is fetched

| Artefact | File | sha256 |
| --- | --- | --- |
| Binding oracle v2.0 | `oracle/blind-reloc-oracle-v2.0.py` | 7686843c93f5cb5840a9589cb00f525ebc6c18cbb70cbd4a9f366f403f3e318c |
| Operators (incl. `sibling` ported from S41, `rodsec` AArch64 pairs, `clonerb-klp`) | `mutation/lpfid-mutate-v2.0.py` | d3068950781d9a17660361cb08712d028858cf3be4dd126dac4d3104311e7738 |
| Scorer | `results/s43/s43_score.py` | c9a04dbf9c33f2a1a23d2000af489c96f854a7fc185e3041113d22bc90188d63 |
| x86-64 reference recipe | `results/s43/s43_build_one_x86.sh` + `results/s43/fix_kpatch.py` | a45419ec350039e7de03de1ef31b1b6b2840974d63ad344d4c3224dd84e2d9f0 / 711c58ca5d561d73bed1b0e8162d71fb2ea342312548fa4d0925a055a5ac8f86 |
| AArch64 reference recipe | `results/s43/s43_pkg_arm64.sh`, compiler pin `results/s43/s43_gccpin.sh`, kpatch headers `~/s39/kpatch-inc` (kpatch v0.9.10 `kmod/patch`) | 10e5620feb5acbb04bec60dd614eed066f73d2b75aee3b87a482fd96d2451c8d / 342d9e0e3e6840dba491d9fd9f57c4a8aba49b807ba7b7b8b18f76ece47d6861 |
| Runners | `results/s43/s43_run_arm64.sh`, `results/s43/s43_run_x86.sh` | fc86477a803d64192d48a15a4839472a098081a572dc8952536e6c8d6657ad47 / 17aec327d1ce480e1834f841e4b18085bdecad5ade5919abc5345d413f3851f9 |
| Frames, exclusions, draw | `results/s43/frame-x86_64.txt`, `frame-aarch64.txt`, `opened.txt`, `draw.json` (`s43_draw.py`) | 3cef4a20665dc44f2a6d0f12213666eb76950fdb6338b7c9ee4cff55366fe6ec (draw.json) |

## Population, exclusions and draw

- Frame: the `kernel-livepatch-*` package names Amazon Linux 2023 lists for x86_64 and for aarch64 on the day of
  the draw (`dnf repoquery`, names only; no package is downloaded to build the frame). Recorded with the listing
  date. Listed 2026-10-21: 173 packages for each architecture (6.1: 102, 6.12: 46, 6.18: 25; the same names on both), plus two repository-configuration packages that are not livepatches.
- Excluded: every package ever opened in this project on either architecture (the S26 and S39 draws, the S41
  rebuilds, and every package name found on Testbed B, the t4g or in the notes): 53 names, excluded from
  both draws. Unopened: 6.1 82, 6.12 28, 6.18 10 (each architecture). List: `results/s43/opened.txt`.
- Draw: per architecture, ten packages from each of the 6.1, 6.12 and 6.18 series (all of a series if it has fewer
  than ten unopened), seed 43, over the series-sorted unopened list, as in S26 and S39. Recorded in
  `results/s43/draw.json` before any package is fetched: 30 packages per architecture (6.18 contributes all ten of its
  unopened packages), 15 package names in both draws.
- A package that fails to download, has no source rpm, or whose reference does not build stays in the
  denominator of the support rate and is reported with its cause. No package is replaced after the draw.

## Subjects and references

Every shipped `livepatch-*.ko` in a drawn package (CVE-named and code-named), paired with the reference built from
its own patch by the frozen recipe for its architecture, with the compiler the kernel or module records (strict
toolchain rule, v2.0 T1F). Scaffolding is excluded by RS. x86-64: the exact-build debuginfo `vmlinux` is
installed by the recipe and passed to v2.0 with the debug objects of the kernel modules the livepatches bind into,
so the sympos check runs. AArch64 references are built with kpatch's headers on the include path and with the gcc
release the modules record when it differs from the container's (searched in the current repositories, then in
each AL2023 release of `releasemd.xml`, newest first); when it cannot be found the module is built with the
container's compiler and v2.0's strict toolchain gate decides. AArch64: Amazon publishes no exact-build
debug `vmlinux`; sympos is NOT_CHECKED and the report says so.

## Injected faults (detection)

On every subject module, before scoring, with the frozen operators: `redirect1`, `swap`, `addend`, `dropcall`,
`rodsec`, `sibling`, and on x86-64 `sympos` (with the pin `vmlinux`, other valid copies only). Sibling-clone
rebinding is measured as an opportunity count: on x86-64, every klp clone symbol whose base has a sibling clone of
the same kind in the exact-build `vmlinux` is an opportunity, and each single-use one is injected by renaming the
symbol in place to the sibling (`clonerb-klp`, S42 addendum, before this freeze). Development data showed 0 such
opportunities in 41 klp clone symbols (S42 DEVLOG), so a count of zero is an expected result and is reported as such. At most
ten sites per operator and module, seed `20261043:<package>/<module>:<operator>`, sites in functions the oracle
compares, scaffolding excluded, sites without a function excluded; `redirect1` keeps its infrastructure stratum.
Excluded from denominators by rules fixed here, before scoring: byte-identical and duplicate mutants, `noop`,
`clone-indistinguishable`, `sibling-indistinguishable`, `sympos-equivalent`.

## Outcomes

1. False alarms: unmodified modules not CONSISTENT under v2.0, per module and per patched function, with Wilson 95%
   and a package-level bootstrap (2,000 resamples, seed 43). Every alarm is root-caused and reported as it falls.
2. Detection per operator: mutants reported DIVERGENT or LOAD_FAIL over non-excluded mutants, counted on mutants
   whose parent is CONSISTENT (mutants of a non-consistent parent are reported separately), with Wilson 95% and the
   package-level bootstrap; per-module and pooled.
3. Support: packages and modules that reach a verdict, with causes for the rest.
4. Site availability per operator (how many modules offer at least one site).

## Rules after the freeze

Nothing in v2.0, the operators or the recipes changes after the first package is fetched. A pipeline failure that
stops a package is fixed only if the fix does not touch the oracle, the operators or the reference recipe, is
applied to every package, and is logged with what had been seen; otherwise the package is reported as failed.
