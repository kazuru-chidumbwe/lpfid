# S16: LPFid oracle rules frozen before real-fix evaluation

Status: FROZEN 8 Oct 2026, 12:15 UTC (drafted 7 Oct). The fixture good modules were rechecked with this exact oracle and all are CONSISTENT (record below). No S12 module had been passed to the oracle when it was frozen. Once frozen, any rule change needs a dated deviation in this file. Results from both the frozen rules and the changed rules are then reported side by side.

## Frozen artefacts

| File | SHA-256 of the deployed copy (bytes that ran) | SHA-256 of the blob in the harness commit | Harness commit |
|---|---|---|---|
| pilot/scripts/blind-reloc-oracle.py | 7d79c9d941c2bc7c11750fe5dd6e16e5afddefe6e84c16bd275b46d0667b843c | 95c3d92d40a9194a76fe9d9a530844925fb67056d22838f7275181bd3e1aa204 | 48b7de2 |
| pilot/scripts/lpfid-mutate.py | 258d0da5a40144e6aa3a19b565e988fed967a93ed29edc98ef39acb9da986bf4 | 2a46819bc561eb537d2ab8218aba13d3bf6d9efcbc89879bb3aad48552bb12df | 48b7de2 |

The two hashes of each file differ only in line endings: the deployed copies (desk working tree and `/opt/atlas/lpfid/` on the build host) have CRLF line endings, the commit stores LF. `git diff 48b7de2` on the working tree reports no change, and the working tree with CR removed hashes to the blob value (checked 8 Oct). Either hash identifies the frozen oracle; any later run records the hash of the bytes it ran.

Dependency: pyelftools as pinned in the harness requirements.

## What the oracle sees

Inputs:
- The module under test (.ko).
- One or more reference objects compiled from the same patched source. There are two kinds:
  - R-kp: kpatch's own patched objects.
  - R-ind: an S22 independent compile with plain make, outside kpatch.
- Optionally, the pin vmlinux (for P1) and the pin build tree (for klp symbols that live in modules).

The oracle is blind: it never learns whether a fault was injected, or which one.

For every function present in both the module and a reference, it extracts the relocations inside the function body as (type, normalised target) pairs.

## Normalisation rules

Each rule can be switched off for the S15 ablation with `LPFID_DISABLE=<rule>,...`.

| Rule | What it does | Why it is needed |
|---|---|---|
| N0 | `.klp.sym.<obj>.<name>,<pos>` becomes `<name>` | The module and reference name the same target in different ways. The position is checked by P1, not here. |
| N1 | Compiler-numbered local suffix `.<digits>` becomes `.N` | The numbering (`__key.198`) changes between builds. |
| N2 | A section symbol plus an offset is replaced by the symbol at that offset, when one exists | Section-relative and symbol-relative references to the same object have to compare equal. |
| N3 | A pr_fmt module-name prefix in a referenced string becomes `<pfx>:` | The module name differs from the reference object's KBUILD_MODNAME. |
| (always) | A string-section target is replaced by the referenced string bytes | String merging moves addends between builds. |
| (always) | Any other section target is replaced by its family (.rodata, .data, .bss, .text, .init, .exit) | Section suffixes differ between builds. |
| A1 | The effective offset inside the target is part of the target (`sym+0x8`). For PC-relative types the effective offset is the addend plus 4. | `sym+8` is a different binding from `sym+0`. |
| T1 | Toolchain identity: the full GCC/clang banners in `.comment` must overlap, otherwise the result is INCONCLUSIVE_TOOLCHAIN. `LPFID_T1=version` relaxes this to the version number, for S3 only. | Two distribution builds of the same gcc version can emit different code. |

The ignore list stays empty. Every relocation target is compared.

## P1 sympos binding check

P1 runs when `--vmlinux` or `LPFID_VMLINUX` is given.

For each `.klp.sym.<obj>.<name>,<pos>`, it resolves the symbol the way the kernel does:
- vmlinux: the N-th symbol with that name, in address order.
- Modules: symbol-table order.
- Position 0: the name must be unique.

Source files come from STT_FILE grouping. The chosen copy must be defined in the same source file as the reference object of the function that holds the relocation.

Per-symbol status:
- CONSISTENT
- DIVERGENT: a different copy is bound.
- LOAD_FAIL: no such symbol, position past the last copy, or position 0 on an ambiguous name.
- INCONCLUSIVE: the expected file is unknown or not unique among the copies.

Per-module verdict, worst first: DIVERGENT, LOAD_FAIL, INCONCLUSIVE, CONSISTENT. If there are no klp symbols the verdict is NOT_APPLICABLE; without a vmlinux it is NOT_CHECKED.

## Comparison modes and verdicts

| Mode | A function is equal when |
|---|---|
| multiset | Its per-function Counter of (type, target) matches. This mode tolerates reordering. |
| sequence | Its list of (type, target), ordered by offset, matches. This mode catches swaps. |

A per-mode verdict is one of:
- CONSISTENT: every common function is equal.
- DIVERGENT
- NO_COMMON_FUNCTIONS
- INCONCLUSIVE_TOOLCHAIN

The overall verdict is the worse of the sequence verdict and the P1 verdict, using this order: DIVERGENT, LOAD_FAIL, INCONCLUSIVE_TOOLCHAIN, NO_COMMON_FUNCTIONS, INCONCLUSIVE, CONSISTENT. NOT_CHECKED and NOT_APPLICABLE count as CONSISTENT.

The primary reported verdict is `overall`. Multiset and sequence are reported alongside it so the cost of each mode is visible.

## Reporting rules fixed now

1. A module is a false alarm when its overall verdict is DIVERGENT or LOAD_FAIL, it was built from the unmodified fix, and S9 classifies it as a correct patch. Each false alarm gets a root cause in the S9 table. None is dropped.
2. Verdicts against R-kp and R-ind are both reported. Where they disagree, that is a finding in its own right, not a reason to choose one.
3. S12 build failures stay in the denominator of the funnel (pre-registration step 9). They never reach the oracle and are reported as a separate column.
4. Mutant detection is reported per operator. Equivalent mutants are a separate class with the reason they are equivalent (for example, `sympos-equivalent`: the name is unique and a position change cannot alter the binding). They are left out of the detection denominator and their count is reported.
5. Known blind spot, stated in the paper: a change confined to an instruction immediate (the `constant` operator, 0/45 detected in the S2 probe) does not change any relocation. Coverage of that case is claimed only through the runtime check, never through the static oracle.

## Checks done before freezing

- S2 probe on 6.6.47, 9 fixtures, 5 sites per operator:
  - Goods: 9/9 consistent.
  - addend: 45/45 detected. dropcall: 45/45 detected.
  - swap: 45/45 detected, in sequence mode only.
  - constant: 0/45 detected (the blind spot above).
  - sympos: 21 equivalent and 5 LOAD_FAIL.
- P1 unit test on duplicate names in the real vmlinux (1583 names): 36440/36440 bindings resolved correctly.
- Recheck of the fixture good modules on the build host after the clean fixture rebuild (deviation 4 in the S12 pre-registration; the runtime host fixture builds shared the deviation 3 flaw and are discarded). Runner `lab/fixtures/fixtures.py`, phase G; output `/opt/atlas/lpfid-fixtures/goods-recheck.json` on the build host, written 12:15 UTC 8 Oct; oracle copy at `/opt/atlas/lpfid/` hashed equal to the deployed-copy values above. Result: **78 / 78 CONSISTENT**, none divergent, no errors. 78 subjects = 3 pins (5.16.10, 6.1.119, 6.6.47) x (17 in-tree + 9 kpatch fixtures): 51 in-tree, 27 kpatch. P1 against each pin's vmlinux: 22 CONSISTENT, 56 NOT_APPLICABLE (no klp symbols).
- The corpus is 78 modules, not the 76 of the discarded runtime host run: that run lacked `shadow-newpid` on 5.16.10 and 6.1.119, which the clean per-patch rebuild produced. The 51 in-tree modules are the same.

## Freeze record

- Goods recheck result: 78 / 78 CONSISTENT (`goods-recheck.json`, 12:15 UTC 8 Oct 2026; oracle sha256 7d79c9d9...843c).
- Freeze commit (Atlas): the commit that set this file to FROZEN (message "LPFid: S16 oracle frozen"); `12bd9c42` (8 Oct 2026).
- Public timestamp: first push of the `lpfid` repository, which carries this file and the S12 pre-registration. 

## Deviation 1 (8 Oct 2026): oracle v1.1, two canonicalisation rules added

**Why.** On the 123 unmodified S12 modules (reference R-kp) the frozen oracle reported 18 DIVERGENT. The S9 root cause (`internal/S9-ROOTCAUSE-S12-DIVERGENT-2026-10-08.md`) found all 18 to be false alarms: in 838 differing relocation pairs, module and reference reach the same target, and a one-byte perturbation of every pair is detected by the same comparison. Two gaps in `target()` cause them: (1) the offset of a PC-relative target is taken as `addend + 4`, which is wrong when the instruction ends with an immediate (48 pairs, 16 modules); (2) a named label in a string section (`.LCn`, kept by kpatch) is compared by name while the reference's section-relative reference is compared by string (12 pairs, 5 modules).

**Change.** `pilot/scripts/blind-reloc-oracle-v1.1.py` is a separate file; the frozen v1 file is not touched. It adds:

- N4: for a PC-relative relocation, the offset into the target is `addend + (end of instruction - offset of the field)`, with the instruction decoded by capstone 5.0.7. When decoding fails, or the tail is outside 4 to 12 bytes, the v1 value `addend + 4` is used and counted in `n4_fallbacks`.
- N5: a named symbol defined in a string section is replaced by the string at its value plus the offset, the same treatment v1 gives section symbols into string sections.

`LPFID_DISABLE=N4,N5` gives the v1 behaviour. No other rule, mode or verdict changes. The tool runs under `/opt/atlas/venvs/lpfid-oracle-v11` on the build host (capstone 5.0.7, pyelftools 0.33).

| File | SHA-256 (deployed, LF) |
| --- | --- |
| blind-reloc-oracle-v1.1.py | 5139e049aa6fc4a1ca1c6641595a9fdd802e7e11d6de058d702cbc7d898d0add |

**Validation before any held-out use** (`lab/s12/oracle_v11_validate.py`; output `/opt/atlas/lpfid/oracle-v11-validation.json`). It runs on inputs that v1 has already scored:

- the 78 fixture goods, where v1.1 must stay CONSISTENT;
- the 1,266 S1 redirect mutants, where v1.1 must detect every mutant v1 detected;
- the 123 S12 modules, which is the set that exposed the gaps and so is not a held-out test.

On every input v1.1 also runs with N4 and N5 off, and its verdicts must equal v1's. The result is recorded below when the run finishes.

**Reporting.**
- v1 remains the primary result on every set it has already scored, including S12 R-kp (105 CONSISTENT, 18 DIVERGENT), and is reported as it is.
- v1.1 is frozen when the validation passes, before any module of the S21 sweeps (v0.9.10, v0.9.8, v0.9.7, gcc-14 pair) or any S22 independent reference (R-ind) is scored.
- On those sets both versions are run and reported side by side; only there is v1.1 tested on modules it has not seen.
- If the validation fails, v1.1 is not used and this deviation records why.

**Validation result (finished 16:06 UTC, 8 Oct 2026): PASS.** Summary `lab/s12/oracle-v11-validate-2026-10-08.json`, full rows `lab/s12/oracle-v11-validation-2026-10-08.json`; 1,467 inputs, 0 N4 fallbacks.

| Set | n | v1 | v1.1 | v1.1 with N4, N5 off = v1 |
| --- | ---: | --- | --- | ---: |
| Fixture goods | 78 | 78 CONSISTENT | 78 CONSISTENT | 78/78 |
| S1 redirect mutants | 1,266 | 1,266 DIVERGENT | 1,266 DIVERGENT (none missed) | 1,266/1,266 |
| S12 unmodified, R-kp | 123 | 105 CONSISTENT, 18 DIVERGENT | 123 CONSISTENT | 123/123 |

The only verdicts that change are the 18 S12 false alarms of the S9 root cause, each DIVERGENT to CONSISTENT.

**v1.1 frozen (8 Oct 2026):** file `pilot/scripts/blind-reloc-oracle-v1.1.py`, harness commit `6bf5744`, SHA-256 `5139e049aa6fc4a1ca1c6641595a9fdd802e7e11d6de058d702cbc7d898d0add` (equal to the deployed copy on the build host). No S21 sweep module and no S22 reference had been scored by either version at the freeze.

## Deviation 2 (9 Oct 2026): oracle v1.2, N3 narrowed (N3M) and alternatives compared (ALT)

**Why.** The S2 operator mutants (`lab/s2/MISSES-2026-10-09.md`) showed that N3 maps any leading "word: " of a referenced string to "<pfx>: ", so 16 addend mutants that shift a string reference into a colon-terminated word ("focaltech: ..." to "h: ...") compare equal. Separately, the replacement code of alternatives is never compared: no S2 miss came from it (the one redirect mutant there changed unreferenced code and is equivalent), but a fault in replacement code that does run would be invisible.

**Change.** `pilot/scripts/blind-reloc-oracle-v1.2.py`, a separate file; v1.1 is not touched.
- N3M replaces N3: a string prefix is absorbed only when it is the module's own name (`.modinfo` name=) or, in a reference, when its text after the prefix equals a module string that carries the module's own name.
- ALT: for each compared function, the relocations in the replacement code of every `.altinstructions` entry whose instruction lies in the function are compared as well (entry size from the entry spacing; replacement length from the last byte of an entry).
- `LPFID_DISABLE=N3M,ALT` gives v1.1.

| File | SHA-256 (deployed, LF) | Harness commit |
| --- | --- | --- |
| blind-reloc-oracle-v1.2.py | b7731376aac630e0809f643a8d80670ee7d34cdcade323eac8ec5657250e9a3e | dda4f42 |

**Validation before any held-out use** (`lab/s12/oracle_v12_validate.py`): every input v1.1 has scored (fixture goods, S12 R-kp, S1 redirect mutants, all S2 mutants). Pass when v1.2 with N3M,ALT off equals v1.1 everywhere, every unmodified module stays CONSISTENT with them on, and no mutant v1.1 detected is lost. Then v1.2 is frozen before it scores any 5.15, gcc-14, S11 or R-ind module, and all versions are reported side by side.

### Deviation 2: validation result and freeze (recorded 10 Oct 2026)

The validation finished at 15:03:52 UTC on 9 Oct (`lab/s12/oracle-v12-validation-2026-10-09.json`, copy of `/opt/atlas/lpfid/oracle-v12-validation.json`). Over 9,680 inputs (78 fixture and 123 real-fix unmodified modules, 1,266 S1 redirect mutants, all S2 mutants of both corpora):

- with N3M and ALT switched off, v1.2 gave the same verdict as v1.1 on all 9,680;
- with them on, every unmodified module stayed CONSISTENT (0 of 201 alarms);
- no mutant that v1.1 detected was lost;
- 16 mutants were detected by v1.2 only, all addend mutants that shift a string reference into a colon-terminated word (3 real-fix, 13 fixture), the N3 blind spot that motivated the change.

**Pass.** v1.2 (SHA-256 b7731376...e9a3e, the value recorded in Deviation 2, unchanged on the build host) is frozen from that moment. The scoring runner (`s21oracle.py`, `gate_v12()`) includes v1.2 only when this file reports a pass, so every set that v1.2 scored (5.15 arm, gcc-14 pair, R-ind, S3, S11) was scored after the pass, with v1 and v1.1 side by side.

## Deviation 3 (10 Oct 2026): oracle v1.3, rule DUP

**Why.** On the held-out 5.15 arm, v1.1 and v1.2 raised one alarm in every kpatch release and against both references: CVE-2026-80664 (`net/netfilter/xt_nat.c`). Traced: the module replaces only `xt_nat_checkentry`, which compares as consistent; the alarm is in `init_module` and `cleanup_module`. The patched object is a loadable module, so the reference set defines both names twice (`xt_nat.o` and kpatch's `patch-hook.o`), and the oracle paired the livepatch module's own scaffolding functions with the first definition in argument order, `xt_nat.o`'s. A false alarm caused by pairing, not by the module.

**Change.** `pilot/scripts/blind-reloc-oracle-v1.3.py`, a separate file; v1.2 is not touched. DUP: when the references define a function name more than once, the module's function is paired with the definition whose relocation multiset is closest to its own. Names defined once are paired as before. `LPFID_DISABLE=DUP` gives v1.2. Checked on the one module before validation: v1.2 DIVERGENT, v1.3 CONSISTENT (pairs both functions with `patch-hook.o`), v1.3 with DUP off DIVERGENT.

| File | SHA-256 (deployed, LF) | Harness commit |
| --- | --- | --- |
| blind-reloc-oracle-v1.3.py | c6add9ab14d994cf6d7920ff6d6820840c9fa554001727865990957b9e200133 | 0bbab7a |

**Validation before any use** (`lab/s12/oracle_v13_validate.py`): every input v1.2 was validated on (9,680), plus every module v1.2 has since scored (5.15 arm, gcc-14 pair, R-ind, S3, S11). Pass when v1.3 with DUP off equals v1.2 everywhere, every unmodified module of the 9,680 stays CONSISTENT, and no mutant v1.2 detected is lost. All versions are reported side by side; the held-out false-alarm rate is reported for v1.2 (frozen before those modules were scored) and for v1.3 (fixed after seeing them).

### Deviation 3: validation result (10 Oct 2026, 04:27 UTC) and an addendum on the R-ind reference set

**Validation PASS** (`lab/s12/oracle-v13-validation-2026-10-10.json`, 10,456 inputs: the 9,680 of the v1.2 validation and 776 held-out modules v1.2 had scored): with DUP off, v1.3 equals v1.2 on every input; every unmodified module of the 9,680 stays CONSISTENT; no mutant v1.2 detected is lost; no mutant newly detected. On the held-out modules exactly four verdicts change, the `xt_nat` false alarm (5.15/CVE-2026-80664) in all four 5.15 releases against R-kp, DIVERGENT to CONSISTENT. v1.3 is frozen from this point.

**Addendum, recorded before any rescoring.** Against R-ind the same alarm remains, because the R-ind reference of a fix is only the independent compile of the changed objects (here `xt_nat.o`), while the R-kp reference also holds the generator's scaffolding object `patch-hook.o`. The module contains that scaffolding whatever the fix, so the R-ind reference set is extended with the same `patch-hook.o` as R-kp. For a fix whose changed objects are all in `vmlinux` this changes nothing (no `vmlinux` object defines `init_module` or `cleanup_module`, and scaffolding functions otherwise have no counterpart in the reference and are not compared). Every R-ind set is rescored with v1.3 under the extended reference set (`lab/s12/rind_hook_v13.py`), and both are reported.

**Addendum result (10 Oct 2026).** `lab/results-2026-10-10/rind-hook-v13.json`. With `patch-hook.o` in the R-ind reference set, v1.3 clears the `xt_nat` alarm in all four 5.15 releases and changes no other R-ind verdict (the v0.9.10 `pwq_cache` module stays DIVERGENT). The scaffolding object is not added to the R-dev (S3) references: it is compiled by the module's own toolchain, so its compiler record would satisfy the strict toolchain rule for a reference that was built by another toolchain (with it, the 81 strict comparisons stopped being inconclusive). S3 is reported as scored, without it.

## Deviation 4 (11 Oct 2026): oracle v1.4, rules R0, RB, RC; evaluated on a held-out klp-build set

**Why.** On the 34 klp-build modules of S11, every frozen version (v1 to v1.3) flags 31 against R-ind. Root cause of every alarm (`lab/s11/KLP-LOAD-FAILS-2026-10-10.md`): 7 modules carry a real generator fault (62 string pointers off target, objtool `elf_add_data()`, fixed upstream as fa31c5b01 in 6.19.9; confirmed by a rebuild with only that fix and at run time); 23 differ only by representation in klp-build's linked module (`R_X86_64_NONE` rows, one merged `.rodata` without object symbols, `__bug_table` entry naming); 1 carries a byte-identical copy of a const object that lives in vmlinux (`futex_q_init`). v1.3 therefore has a false-alarm rate of 24 of 27 fault-free modules on klp-build output, which this deviation addresses.

**Change.** `pilot/scripts/blind-reloc-oracle-v1.4.py`, generated from v1.3 by `pilot/scripts/make_oracle_v14.py` (exact-match edits, v1.3 hash checked); v1.3 is not touched.
- R0: relocations of type `R_X86_64_NONE` are dropped on both sides (no effect when applied; a missing real relocation still leaves the reference's row unmatched).
- RB: every target in `__bug_table` (named `__bug_table_N` or section plus offset) is one label.
- RC: where a function's two sequences have equal length and differ only at module targets that are anonymous `.rodata` offsets, a pair is accepted when the module bytes there equal the reference target's bytes over the reference target's extent (string up to and including its NUL, or the symbol's size).
- Not covered, by design: const objects the module copies from vmlinux (their bytes are in vmlinux and contain relocated fields). That alarm class stays and is reported.
- `LPFID_DISABLE=R0,RB,RC` gives v1.3.

| File | SHA-256 | Harness commit |
| --- | --- | --- |
| blind-reloc-oracle-v1.4.py | b6496d03866701c15d71366d7322f8d5b7f2ee71e1bb2b5394054099d1d0ed29 | 4c5053f |

The rules were written after seeing the 34 S11 modules and the 7 control rebuilds, so v1.4's verdicts on those are a fit, reported as such and never as evidence. An unrecorded speed-only draft `blind-reloc-oracle-v1.3.1.py` (10 Oct, untracked) exists in the harness folder and on the build host; it was never validated or used for any reported result and is not part of this deviation.

**Validation before any held-out use** (`lab/s12/oracle_v14_validate.py`): every input of the v1.3 validation (10,456) plus the S11 sets (34 klp-build modules against R-ind and R-kp, 7 fixed-objtool rebuilds). Pass when (a) v1.4 with R0,RB,RC off equals v1.3 on every input; (b) with the rules on, every unmodified module of the 9,680 stays CONSISTENT; (c) no mutant v1.3 detected is lost; (d) the 7 S11 modules with the objtool fault stay DIVERGENT. Then v1.4 is frozen.

**Held-out evaluation, registered now, before any held-out fix is drawn or built.**
- Sample H: from the 6.19 eligible pool of the committed `s12select.py` run (175 fixes, `out/6.19/candidates.tsv`, rows with no failed step), minus the 40 of the S11 main sample: `random.Random(seed + 2).sample(sorted(pool), 40)` with the same seed (`vulns.git` e65245d8). Script `lab/s11/s11_heldout_select.py`, output `out/6.19/heldout-h.json`.
- Builds: each fix of H twice with klp-build on the 6.19 pin, as in S11 (`s11klp.py` recipe): stock, and with only fa31c5b01 applied to objtool (`s11_fixobjtool.py` recipe). R-ind for each fix by `s22refs.py`, unchanged.
- Labels, mechanical and oracle-free: a stock module is FAULTY when, in some patched function, a relocation pointing into `.rodata` reaches different bytes (C string to NUL) than the paired relocation of the same fix's fixed-objtool module (pairs in offset order); otherwise CLEAN. Fixed-objtool modules are CLEAN by construction for this fault class.
- Measures, reported for v1.3 and v1.4 side by side with Wilson 95% intervals: detection = DIVERGENT among FAULTY stock modules; false alarms = DIVERGENT among CLEAN stock modules and among fixed-objtool modules, each alarm root-caused. Plus the addend operator of the S1 mutation tool on every fixed-objtool module's `.rodata` string relocations (one mutant per relocation, offset +1), detection reported per oracle version.
- No rule above changes after the first held-out build; a runner fault means the run is archived as invalid and rerun.


**Amendment to the held-out evaluation (11 Oct 2026, before any held-out module was scored; builds in progress).** The label and rule RC both test whether a string reference reaches the intended bytes (against the fixed-objtool build and against the independent compile respectively), so detection of the objtool string fault and of the +1 offset mutants is close to certain by construction. They are kept and reported only as a consistency check (RC does not hide this fault), not as evidence of detection power. The measures are re-ranked and one is added:
- Primary: false alarms of v1.3 and v1.4 on held-out klp-build modules without the fault (stock modules labelled CLEAN, and every fixed-objtool module), with Wilson 95% intervals; every alarm root-caused.
- Added, non-masking check of R0, RB and RC on klp-build output (the validation inputs are kpatch modules): the frozen operators of the mutation tool `lpfid-mutate.py` (redirect, swap, addend, sympos, dropcall; `constant` changes no relocation and is out of the oracle's scope) on every held-out fixed-objtool module, at most 10 sites per operator and module, drawn by the registered S2 rule (`lab/s2/s2run.py` `run_subject`: `random.Random(f"20261008:{id}:{op}")`, no-op and duplicate mutants removed), redirect applied by the S1 rule. Pass when v1.4 detects every mutant v1.3 detects; mutants detected by v1.3 only are listed and root-caused.
- The klp-build fault claim rests on the S11 root cause, the upstream fix, the control rebuild and the run-time demonstration, not on v1.4.

**Correction to the amendment (11 Oct 2026, before any held-out module was scored).** An implementation check of the operator mutants on one S11 fit module (fixed-objtool CVE-2026-31449, K=2) showed the pass rule "v1.4 detects every mutant v1.3 detects" is ill-posed on klp-build output: v1.3 flags the unmutated parent itself (representation), so it "detects" every mutant, including those in klp-build's own scaffolding (`livepatch_mod_init`, `livepatch_mod_exit`), which has no counterpart in the reference and is compared by no version. The non-masking check is restated:
- Visible: v1.3 run on the mutant with its own parent module as the only reference, restricted (`--functions`) to the functions the module shares with R-ind, reports DIVERGENT. Same toolchain and layout, so representation cannot cause it.
- Masked: visible, the parent is CONSISTENT under v1.4 against R-ind, and the mutant is CONSISTENT under v1.4 against R-ind.
- Pass when no mutant is masked. Reported: per operator, visible mutants on v1.4-CONSISTENT parents and v1.4's detection of them (Wilson 95%), and invisible mutants (outside the compared functions or equivalent at the relocation level).
