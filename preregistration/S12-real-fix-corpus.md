# S12 real-fix corpus: pre-registered selection rule (7 Oct 2026)

Agreed on 7 Oct 2026. This file and `lab/s12/s12select.py` are committed together **before** the selection runs. After this commit the rule is not changed; any deviation is reported as a deviation with its reason. Background and rationale: [S12-SELECTION-RULE-DRAFT-2026-10-07.md](S12-SELECTION-RULE-DRAFT-2026-10-07.md).

## Sources

- **CVE records:** kernel CNA repository `git.kernel.org/pub/scm/linux/security/vulns.git`, cloned fresh on the build host at selection time. The commit used is written into every output file. Each record's `.dyad` file gives, per stable branch, the commit that introduced the bug and the stable commit that fixed it.
- **Fix diffs:** the stable commit named in the `.dyad` line, fetched from `linux-stable` (branches `linux-6.1.y`, `linux-6.6.y`, `linux-6.12.y`, history after each pin tag).
- **Pin trees** (built with gcc-13 13.3.0, configs unchanged from the existing pins):

| Branch | Pin | Tree on the build host |
| --- | --- | --- |
| 6.1.y | 6.1.119 (DEBUG_INFO on) | `/opt/atlas/livepatch-corpus/linux-second-pin` |
| 6.6.y | 6.6.47 | `/opt/atlas/livepatch-corpus/pilot-work/linux` |
| 6.12.y | 6.12.112 | `/opt/atlas/livepatch-corpus/linux-6.12.112` |

## Steps (each counted and reported per branch)

1. All published CVE records with a `.dyad` file.
2. The record names a fix in the branch released **after** the pin, and the bug is present in the pin (introduced in an earlier mainline release, or in a stable release of the same branch at or before the pin).
3. The fix only modifies existing `.c` files (no headers, assembly, build files, added or deleted files).
4. Every touched file is compiled in the pin's configuration (its `.o` exists in the built pin tree).
5. x86 relevant: no path under `arch/` other than `arch/x86/`.
6. Applies to the pin with `patch -p1 --dry-run --fuzz=2` (offsets allowed; fuzz use recorded).
7. **Cap:** at most 2 files and at most 3 functions changed. Functions are counted on the stable parent of each touched file: a changed line belongs to the function whose body (kernel style, `{` and `}` at column 0) contains it; changed lines outside any function body are data or declarations and mark the fix as type T3. Fixes that pass steps 1 to 6 but fail step 7 form the **over-cap pool**.
8. **Random sample:** seed = first 8 hex digits of the vulns.git commit, as an integer. Main sample: `random.Random(seed).sample(sorted(eligible CVE ids), 40)`. Over-cap sample: `random.Random(seed + 1).sample(sorted(over-cap CVE ids), 10)`. If a pool is smaller, all of it is taken. A CVE may be drawn on more than one branch; overlaps are reported.
9. **Build:** kpatch-build 0.9.11 on the build host against the pin. Every drawn fix stays in the denominator; build failures are reported with their logs, never replaced by another draw.

Totals intended: 3 branches x (40 main + 10 over-cap) = up to 150 fixes.

## Patch types (assigned by the script before any build)

| Type | Rule |
| --- | --- |
| T1 | one function changed, not inline |
| T2 | two or more functions, or a changed function declared `inline` |
| T3 | any changed line outside a function body (global, static data, struct, declaration) |

## Evaluation rules fixed now

- The **reference compile** for the blind oracle is built on the **same host and toolchain** as the module (the build host). The oracle and runtime checks run on the runtime host; every runtime number for an RQ comes from one host.
- Oracle normalisation rules are frozen at harness commit (recorded at S16) before any S12 module is evaluated; nothing is tuned on S12.
- Results are reported per branch, per type, main and over-cap separately, with Wilson 95% intervals.
- upstream klp-build is not used for S12 (it exists only from 6.19); the generator comparison is S11.

## Deviation 1 (7 Oct 2026, before any 6.12 candidate was seen)

The 6.12.y pin 6.12.112 is the current head of the 6.12.y branch, so no CVE fix exists after it (step 2 gave 0). The 6.1.y and 6.6.y selections ran as registered (vulns.git `e65245d8`).

Replacement rule for 6.12.y, fixed before running it: the pin is the latest 6.12.y release published on or before 2025-10-07 (one year before selection), which is **6.12.51** (released 6 Oct 2025, kernel.org listing). It is built on the build host with the 6.12.112 configuration through `olddefconfig`, gcc-13 13.3.0. Selection for 6.12.y then runs with the same script, the same vulns.git commit (`e65245d8`) and the same seed. 6.12.112 stays the pin for S6b and S11.

## Deviation 2 (7 Oct 2026): 6.1.119 pin on the build host lacked debug info

The registered pin is 6.1.119 with DEBUG_INFO on (as on the runtime host). The the build host copy had been built without it, and kpatch-build refused every 6.1 job at once ("kernel doesn't have 'CONFIG_DEBUG_INFO' enabled", 0 s). These 50 attempts are tool-setup failures, not kpatch outcomes: they are kept under `results/infra-failed-6.1-*` and excluded from the denominator. The the build host pin was rebuilt with the runtime host config (same gcc-13), and all 6.1 jobs rerun. Selection is unaffected: debug info does not change which objects are compiled, so step 4 is identical.

## Deviation 3 (7 Oct 2026, evening): build runner left fixes applied; all builds discarded and rerun

The runner called `kpatch-build --skip-cleanup` (to keep kpatch's patched objects as references). That flag also leaves the fix applied in the source tree, so each worker's source copy accumulated every earlier fix. Every build after a worker's first job was invalid (failures in files the fix did not touch, e.g. `net/ipv6/mcast.c`, `arch/x86/kernel/ftrace.c`). All S12 builds and the started S21 builds were stopped and moved to `/opt/atlas/s12/invalid-20261007-skipcleanup/`; none is used. The contaminated work trees were deleted.

Fix: before every job the worker's source copy is restored from the pristine pin tree with a checksum-based sync that gives changed files a fresh timestamp (so make rebuilds their objects), excluding build products; a dry-run check then confirms every `.c` and `.h` file matches the pin, else the job aborts. A canary (fix A, fix B, fix A again on one worker; A's two modules must have identical relocations and symbols) must pass before the full rerun. The selection, seed and samples are unchanged.

Addendum to deviation 3 (7 Oct 2026, 21:00 UTC). The exclusion-list restore described above dropped `arch/x86/kernel/vmlinux.lds.S` and was replaced before any rerun: each source copy is now restored from the official release tarball of its pin (checked first: every pin tree matches its tarball, 0 files differ), with a full checksum check after every restore. The first canary run built fix A twice with identical symbols, identical relocations in every non-debug section and a byte-identical patched object (`kernel/fork.o`); only `.rela.debug_*` offsets into `.debug_str` differed (string merge order, never read by the oracle). The canary comparison was narrowed to exclude debug relocation sections and adds the patched-object check; it passed on the existing builds without rebuilding. The rerun started at 20:59 UTC.

## Deviation 4 (8 Oct 2026, before any S12 module was evaluated): static evaluation moves to the build host

The runtime host, registered above as the evaluation host, has been unreachable since the evening of 7 Oct. All static evaluation (fixture recheck, oracle freeze, oracle on S12 modules, mutants, the PS3 presence test) moves to the build host, the host that builds the modules and the independent references. Modules, references and oracle therefore share one host and one toolchain, which the strict toolchain rule requires anyway. In the manuscript the hosts are named by role: the build host and the runtime host (the machine that boots test kernels; decided separately). Each research question takes all its numbers from one host.

While moving, the fixture builds were found to share the deviation 3 flaw: the runtime host script (`lab/s1full.py`) built all nine kpatch test patches per pin in one source copy with `--skip-cleanup`, so each later patch was built on a tree that still carried the earlier ones. Those fixture references and modules are discarded. The fixture corpus is rebuilt on the build host by `lab/fixtures/fixtures.py`, which restores the source from the release tarball before every kpatch build and verifies it. The 5.16.10 pin tree differs from its tarball in one host-tool file, `tools/lib/subcmd/subcmd-util.h` (the upstream gcc-12 fix to `xrealloc`, needed to build objtool with gcc-12; never compiled into the kernel or a module). It is kept as a documented build fix: the same file is placed in the restore source, so the verification still holds. Each fixture pin is compiled with the compiler of its vmlinux (5.16.10: gcc-12; 6.1.119 and 6.6.47: gcc-13).

## Deviation 5 (8 Oct 2026): the two oracle controls are redefined for real-fix modules

The controls of manuscript Section 6.7 were written for the fixture corpus. Run on the S12 modules (runner `lab/s12/s12oracle.py`, output `lab/s12/oracle-rkp-2026-10-08.json`), both failed for a reason in the control, not in the module:

- **Wrong-reference control.** Every kpatch reference set contains the same generator object, `patch-hook.o`. A module compared with another fix's references therefore always shares the hook functions and is reported CONSISTENT on them, so the control "must not be CONSISTENT" failed for 106 of 123 modules. Redefined: the other fix's references without the shared generator object. Under this definition the control passed for all 123 modules.
- **No-op control.** A copy written through the mutation path without an edit is byte-identical to the module, so its verdict always equals the module's own verdict; "must be CONSISTENT" therefore excluded every alarm (18 modules). Redefined: the no-op copy must be byte-identical and must reproduce the unmodified module's verdict, which is what the control is for (the mutation path introduces no difference by itself). Under this definition the control passed for all 123 modules.

The oracle, its rules and the references are unchanged (S16 hash `7d79c9d9...843c` checked by the runner before the run). Both the controls as first written and the redefined controls are recorded per module in the output, so results can be reported under both. Fixture-corpus controls keep their original definition, which works there because fixture references contain no shared generator object.

## Deviation 6 (8 Oct 2026, before any result by patch type was analysed): `inline` matched as a word

`s12select.py` set a fix's `inline` flag when a changed function's header contained the substring `inline`. That also matches `noinline` and function names such as `ext4_prepare_inline_data`. The sample and every build are unchanged; only the T1/T2/T3 labels can change. `lab/s12/retype_inline.py` recomputes the labels for all 150 selected fixes with the same function boundaries (output `lab/s12/retype-inline-2026-10-08.json`):

| Rule | All 150 | Main 120 |
| --- | --- | --- |
| As run (substring) | T1 91, T2 44, T3 15 | T1 91, T2 19, T3 10 |
| `inline` as a whole word (used from now on) | T1 97, T2 38, T3 15 | T1 97, T2 13, T3 10 |
| Whole word or `__always_inline` | same as whole word | same as whole word |

The as-run rule reproduces every recorded label (150/150). Six fixes move from T2 to T1: 6.1 CVE-2025-68264, 6.6 CVE-2026-89541, 6.12 CVE-2025-68261, CVE-2026-43068, CVE-2026-68184, CVE-2026-89550. Results by patch type use the word rule; the as-run counts are reported next to them.

## Clarifications of the registered selection rule (8 Oct 2026)

Two behaviours of the committed `s12select.py` were not written in this document. They were part of the rule as run, so they are recorded here as clarifications, with their effect:

- **Unknown introducing version.** When the vulns record gives the introducing version as `0` (unknown), the fix is treated as present in the pin. This affected 11 fixes that passed step 2 (6.1: 3, 6.6: 4, 6.12: 4, of 16,909); none is in the main or over-cap sample.
- **Unfetchable stable commit.** A fix whose stable commit cannot be read from the stable repository is counted as a step 3 failure ("stable commit not available"). This affected no fix.

## Deviation 7 (8 Oct 2026, before any 5.15 fix was selected or built): a 5.15.y arm for the v0.9.7 / v0.9.8 bracket

**Why.** The S21 sweep brackets two generator fixes: `901445a` (`__UNIQUE_ID()` correlation, between v0.9.7 and v0.9.8) and `c608faf` (gcc 14 symbol order, between v0.9.10 and v0.9.11). v0.9.7 and v0.9.8 built none of the 240 main-set jobs on the three pins: each branch stops at one version-age error (6.1 invalid ancestor objects, 6.6 `setlocalversion --save-scmversion`, 6.12 `paravirt_patch_site`; `lab/s12/TRIAGE-FAILURES-2026-10-08.md`). That is reported as a result, but it leaves the `901445a` bracket untested. A kernel those releases support closes it.

**Added arm.**
- Branch 5.15.y. Pin: the 5.15.y release tagged on the same day as v6.1.119 (22 Nov 2024), or the latest 5.15.y release before it if none was tagged that day. Release tarball checked against kernel.org's signed SHA-256 list.
- Pin configuration and build: the recipe of the other pins (`tb-newpins.sh`): the 6.6.47 base configuration, LIVEPATCH and DEBUG_INFO enabled, `olddefconfig`, gcc 13.3.0 on the build host.
- Selection: the committed `s12select.py`, unchanged, with the same `vulns.git` commit and seed rule; only the branch argument is new. Main sample of 40 (the over-cap sample is drawn and recorded but not built, as for the other sweep versions).
- Builds: the main sample with all four versions (v0.9.7, v0.9.8, v0.9.10, v0.9.11), gcc 13, with the per-job tarball restore and the canary of Deviation 3 run on this pin first.
- Scoring: frozen oracle v1 and v1.1 side by side (`lab/s12/s21oracle.py`), as for the rest of S21.
- If v0.9.7 or v0.9.8 still cannot build on 5.15, that is reported with its cause and the bracket is stated as untestable on supported LTS kernels; no older pin is added after that.
