# S44 pre-registration: held-out census of oracle v2.1 on never-opened shipped livepatches

Frozen 24 Oct 2026 and committed before any package of the census is fetched for evaluation.

Purpose. The held-out test of oracle v2.1 and operators v2.1. S43 remains the held-out trial of v2.0, scored as
frozen; nothing here rescores it. The S43 classification (`results/s43/S43-MISS-CLASSIFY-2026-10-24.md`) found two
defects: v2.0 compares only the first definition of a function name that a module defines twice, and `rodsec` drew
sites in merged-string sections whose names do not start `.rodata.str`. v2.1 changes exactly those two things.
Every S43 file, every development corpus and the v2.0/v2.1 regression on the S43 objects are development data for
v2.1.

## Changes from S43

| Change | Rule |
| --- | --- |
| Oracle v2.1, rule MDUP | When a module defines a function name more than once, every definition is compared. Each is keyed `name@file` by its preceding `STT_FILE`, paired with the reference definitions of that name in the same file (P1F rule), falling back to all of them; DUP chooses among the candidates. klp relocations inside a definition are checked by sympos against that definition's pairing. A name defined once is compared as in v2.0. `LPFID_DISABLE=MDUP` gives v2.0. |
| Operators v2.1, `rodsec` | A section flagged `SHF_STRINGS` or `SHF_MERGE` is skipped whatever its name. Every other operator is unchanged. |
| Seed | `20261044:<package>/<module>:<operator>`. |
| Population | A census of every unopened package, not a draw. |

## Development evidence seen before this freeze

- S43 x86-64 objects on Testbed B, 3,884 files (110 parents and every stored mutant), scored under v2.0 and v2.1 in
  the S43 environment (`/opt/atlas/venvs/lpfid-oracle-v11`, capstone 5.0.7, pyelftools 0.33): result recorded in
  `results/s44/S44-DEVLOG.md` before the first census package is fetched. A first run under the system Python, without
  capstone, is archived as invalid on Testbed B (`~/s44/invalid/`).
- Exposure: 1 of 110 S43 x86-64 modules, 1 of 121 S43 AArch64 modules and 2 of the 58 locally kept S26 modules define
  a function name twice; all four are the CVE-2026-31431 livepatch (`memcpy_sglist`).

## Frozen before any census package is fetched

| Artefact | File | sha256 |
| --- | --- | --- |
| Binding oracle v2.1 | `oracle/blind-reloc-oracle-v2.1.py` (built from v2.0 by `results/s44/make_v21.py`) | 6d63c19d5cf2b084982ccc5612095f6c676755895f6bf946e5f4c4bf344d7dff |
| Operators v2.1 | `mutation/lpfid-mutate-v2.1.py` | f90337f3390210de23cae744d7033645421381e6695d052aca5e3d7e9caaee1b |
| Scorer | `results/s44/s44_score.py` | 5f2d86a1623e4ccf9d6c11d99ac5919976fb8567c6c3734f7706a4fcff772c82 |
| x86-64 reference recipe (unchanged from S43) | `results/s43/s43_build_one_x86.sh` + `results/s43/fix_kpatch.py` | a45419ec350039e7de03de1ef31b1b6b2840974d63ad344d4c3224dd84e2d9f0 / 711c58ca5d561d73bed1b0e8162d71fb2ea342312548fa4d0925a055a5ac8f86 |
| AArch64 reference recipe (unchanged from S43) | `results/s43/s43_pkg_arm64.sh`, `results/s43/s43_gccpin.sh`, builder `results/s44/Dockerfile.s39`, kpatch v0.9.10 `kmod/patch` headers | 10e5620feb5acbb04bec60dd614eed066f73d2b75aee3b87a482fd96d2451c8d / 342d9e0e3e6840dba491d9fd9f57c4a8aba49b807ba7b7b8b18f76ece47d6861 |
| Runners | `results/s44/s44_run_x86.sh`, `results/s44/s44_run_arm64.sh` | c85f8c81441698176fea85375201c5b8d654f4fdf02717e5658d91af36ce6068 / c01b6a8cb5780e110e11e81d753835c30c44052af8b6bc452b8df7fd7f9054d7 |
| Frame (both architectures) | `results/s44/frame-x86_64-2026-10-24.txt`, `frame-aarch64-2026-10-24.txt` | 8fd38fa7d8407a2c910d79bab6a0736e21d114b7d924d31cd8573dbfe071058f (identical) |
| Census list (both architectures) | `results/s44/census-x86_64-2026-10-24.txt`, `census-aarch64-2026-10-24.txt` | 940f57fcf1208003af7c03f97da17e7a74c04daede396647f5721e0462c0e9fe (identical) |

## Population

- Frame: the `kernel-livepatch-*` names Amazon Linux 2023 lists for each architecture on 24 Oct 2026, by the S43
  rule (`dnf repoquery`, names only). 173 livepatch names per architecture, the same on both, plus two repository
  packages that are not livepatches. No name is new since the S43 frame of 21 Oct.
- Excluded: the 53 names opened before S43 (`results/s43/opened.txt`) and the 45 names of the S43 draw
  (`results/s43/draw.json`), on both architectures.
- Census: every remaining name, 75 per architecture (6.1: 64, 6.12: 11; no 6.18 name remains). The same 75 names on
  both architectures. The `kernel-livepatch` repository lists module releases for 57 of the 75 on x86-64 and 51 on
  AArch64. A name with no module release is fetched like any other, and is reported as not scored with its cause,
  as in S43 (`no-ko` or `MISSING_SOURCES`). No package is added or replaced.
- Release: the newest release of each package on the day it is fetched, recorded with its rpm file name.

## Subjects, references, injected faults

As S43, with the frozen recipes, the strict toolchain rule, RS scaffolding exclusion, the exact-build `vmlinux` and
target-module debug objects on x86-64, and sympos NOT_CHECKED on AArch64. Operators, site rules, exclusion classes and
the limit of ten sites per operator and module are those of S43, with operators v2.1 and the S44 seed. The v2.0
verdict (MDUP off) is recorded beside every v2.1 verdict.

## Strata

- *Design stratum D*: a module whose patch name contains `CVE-2026-31431`, or whose v2.1 compared functions include
  `memcpy_sglist`. v2.1 was designed on this fix. Its results are reported as replication of the design case, not as
  held-out evidence.
- *Primary stratum H*: every other module. The held-out claims of the paper rest on H only.
- MDUP exposure (modules that define a function name twice, and the pairings v2.1 made) is reported for D and H
  separately. If H has no such module, the report says the census did not exercise MDUP outside its design case.

## Outcomes

For H and for D separately, per architecture:

1. False alarms: unmodified modules not CONSISTENT under v2.1, per module and per patched function, with Wilson 95%,
   a package-level bootstrap and a fix-level bootstrap (clusters by patch name; 2,000 resamples each, seed 44). Every
   alarm is root-caused and reported as it falls.
2. Detection per operator, on mutants whose parent is CONSISTENT (others reported separately), with Wilson 95% and
   both bootstraps; per module and pooled. Every miss is classified with the S43 procedure.
3. Support: packages and modules that reach a verdict, with a cause for each one that does not.
4. Site availability per operator.
5. The v2.0 verdict beside each v2.1 verdict, and every file on which they differ.

## Rules after the freeze

Nothing in v2.1, the operators, the scorer or the recipes changes after the first census package is fetched. A
pipeline failure that stops a package is fixed only if the fix does not touch the oracle, the operators or the
reference recipe, is applied to every package, and is logged with what had been seen; otherwise the package is
reported as failed. A defect found in the census is reported in the S44 result. It is not fixed inside S44.

## Hosts

x86-64: Testbed B, Docker image `s26-builder`, scoring in `/opt/atlas/venvs/lpfid-oracle-v11`. AArch64: Oracle Cloud
Ampere A1, Docker image built from `results/s44/Dockerfile.s39`, scoring in a venv with pyelftools 0.33 and capstone 5.0.7,
host and image recorded in the S44 status file before the first package.

Host note, 24 Oct 2026, before the first AArch64 package is fetched: the AArch64 half runs on AWS Graviton instead of
Oracle Ampere, the host type S43 used. Instance `i-068b1e4318db874d4`, t4g.xlarge, eu-north-1, Ubuntu 24.04 arm64
(`ami-07cd1a6d41a758ba6`), 100 GiB. Builder image from `results/s44/Dockerfile.s39`, kpatch headers from kpatch
v0.9.10 (`903dfe2b`) `kmod/patch`, venv pyelftools 0.33 and capstone 5.0.7. No frozen file changes; their hashes on
the host match the table above.

## Addendum A1, 24 Oct 2026, 13:35 UTC (commit e08a368a), after an interim look, before the final reduction

Seen when this was written: the interim reduction of the first 23 x86-64 packages at 12:59 UTC, recorded in
`results/s44/S44-RESULT-2026-10-24.md` (pooled: 59 unmodified modules, 0 alarms; every scored mutant detected; 3
modules in D), and the STATUS lines of both runs, which give per package the number of modules and of CONSISTENT
modules. No per-fix or per-stratum count of the census had been computed. The change makes the stated bound wider.

Amazon ships the same fixes in many kernel builds, so modules are not independent tests, and with zero alarms a
bootstrap interval is [0, 0] and bounds nothing. The primary false-alarm bound is therefore stated per distinct fix:
a fix is identified by its patch name (the `ref/<patch>` the scorer pairs, CVE or code name), it counts as alarming
when any of its unmodified modules is not CONSISTENT, and the bound is the Wilson 95% interval over the number of
distinct fixes, for H and for D separately. Module-level and function-level rates and both bootstraps stay as
secondary outcomes. The same per-fix count is computed for S43 and reported beside it. Nothing else changes.

## Addendum A2, 24 Oct 2026, 13:49 UTC (commit ff5a664c), after an interim look, before the final reduction

Seen when this was written: the same as for A1, and the STATUS lines up to 28 x86-64 and 10 AArch64 packages. The
seen-fix list was built from earlier corpora only; no census fix had been matched against it. The change narrows the
population the held-out claim rests on.

An unopened package can carry a fix that an earlier corpus already held, and every earlier corpus is development
data for v2.1. Stratum H is therefore split by fix:

- *Seen fixes*: `results/s44/seen-fixes-2026-10-24.json` (sha256 bf2fb21729318485bc5e628767ef02de21e9ef3f5cc69adfd5bde696bc5ab97e),
  built by `results/s44/seen_fixes.py` (sha256 8d1e356a90165525d9718446d4a716db79f3e57a0adeb45d7537a150b8c7a545) from
  S26, S39, both S43 arms, and the CVE identifiers in the S11, S12, S21, S30 and S34 records: 267 fix keys and 177
  compared Amazon functions. A fix key is the CVE identifier in the patch name, otherwise the code name in lower case
  without its kernel-series suffix. openEuler hotpatches carry no per-fix name and are not in the list.
- *H-new*: modules of stratum H whose fix key is not a seen fix. The held-out claims of the paper rest on H-new.
- *H-seen*: the other modules of H, reported as new builds of seen fixes, not as unseen fixes.
- Secondary, for H-new: the modules none of whose compared functions is a seen function.

Every outcome of the protocol, including the per-fix bound of A1, is reported for H-new, H-seen and D. Nothing else
changes.

## Addendum A3, 25 Oct 2026, after the final reduction, before any instruction-level verdict on Amazon modules

Seen when this was written: every binding verdict of S26, S43 and S44 (Sections 7.4 and 7.5 of the manuscript). No
instruction-level check had been run on any Amazon module. This addendum adds a secondary analysis and changes no
outcome above.

The binding verdict covers relocations only. To test the instruction bytes that carry no relocation, the
immediate-differential check `body_check_v16.py` (sha256 of the LF file 1c25eb4bb2c03c24…, as on Testbed B at
`oracle/body_check_v16.py`) is run on every unmodified x86-64 Amazon module of S26 (164), S43 (110) and
S44 (232), against the same reference objects the binding verdict used. Module and reference were built with the
same compiler release, the condition under which the check was validated (Section 7.5.1). Generator scaffolding is
excluded by its rule RS, as in the binding verdict. Reported: modules and patched functions CONSISTENT, DIVERGENT or
without a common function, per corpus, with Wilson 95% intervals and the per-fix count of A1. Every DIVERGENT
function is root-caused from the differing instructions. AArch64 is not covered, because the check decodes x86-64
only. Script: `results/s44/s44_body.py`.

## Addendum A4, 25 Oct 2026, before any verdict of the validated immediate check on shipped modules was tallied

Correction to A3. The check validated in Section 7.5.1 (1,111 of 1,111 constant mutants, 0 of 122 alarms) is the
S27 immediate check `oracle/s27_immcheck.py` (sha256 cfeca52d…), not `body_check_v16.py`. `body_check_v16.py`
compares the bytes left after masking relocation fields; it has no mutant validation of its own. The A3 numbers
stay in the record as a second, stricter byte check and are not reported as the validated check.

Added: the S27 check is run on the same module and reference pairs as A3 (S43 110, S44 232, the 58 kept S26
references, the 164 rebuilt S26 references once the rebuild finishes), on the seven openEuler x86-64 modules and on
the 38 scored OpenAnolis modules. Configuration is the S27 reported operating point, `S27_DISABLE=T1,IMM-FRAME`,
with the binding oracle's `Obj` from `/opt/atlas/lpfid/blind-reloc-oracle.py` (sha256 7d79c9d9…, the file S27 used).
The module and reference compilers are recorded per row. Verdict: multiset mode, as in S27; sequence mode recorded.

Scope rule fixed now: the existing rule RS (`S26-DEVIATION-RS-v16-2026-10-15.md`) is applied to the output, so
`init_module`, `cleanup_module` and their `__pfx_` symbols do not count toward a module's verdict. Reason: here the
reference objects contain the generator's scaffolding, which the S27 references did not, and its immediates are not
fix code. Seen when this was written: 8 rows, which diverge only in scaffolding or not at all. Raw counts without RS
are reported alongside. Every remaining DIVERGENT function is root-caused from the differing immediates.
Scripts: `results/s44/s44_imm.py`, chain `~/s44/imm_chain.sh` on Testbed B.
