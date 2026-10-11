# S11 pre-registration: kpatch-build and klp-build on the same fixes (Linux 6.19.14)

Written and committed before any 6.19 fix is selected or built (night of 8 to 9 October 2026). Plan item S11 (RQ4); manuscript 6.2 and 7.5. Runner `lab/s11/s11.sh` and `lab/s11/s11klp.py` on the build host, queued after the S21 5.15 chain (`s515.sh`).

## Pin and generators

- Pin: Linux 6.19.14, the tree built on the build host on 7 October from the kernel.org tarball (`tb-newpins.sh`: the 6.6.47 base configuration, LIVEPATCH and DEBUG_INFO, olddefconfig, gcc 13.3.0). klp-build exists from 6.19, so this is the earliest release where both generators can be run. The tree is checked against the tarball before any build.
- klp-build: the in-tree `scripts/livepatch/klp-build` of 6.19.14, run with `-T` (keep the temporary objects) and `--no-replace`, gcc 13.3.0.
- kpatch-build v0.9.11, gcc 13.3.0, as for S12. If v0.9.11 cannot build for 6.19.14 at all (as v0.9.7/v0.9.8 cannot for the newer pins), that is reported with its cause and the comparison is klp-build alone against the references.

## Fixes

The committed `s12select.py`, unchanged, with the same `vulns.git` commit (`e65245d8`) and seed rule, branch 6.19 at pin 6.19.14, stable branch `linux-6.19.y` fetched after the pin. Main sample of 40; the over-cap sample is drawn and recorded but not built.

## Builds and references

- Every job starts from a tree restored to the release tarball and checked, as in S12 (Deviation 3); the S12 canary is run on 6.19 first (fix A, fix B, fix A).
- References per module: the generator's own patched objects (kpatch: its `patched/` objects and `patch-hook.o`; klp-build: `klp-tmp/patched/`), and the independent compile of S22 (`s22refs.py`, plain `make`, one section per function).

## Outcome

- Per fix: built or not by each generator, with the cause of every failure from the build log.
- Frozen oracle v1 and v1.1 on every module against both references (`s21oracle.py`).
- Generator comparison per fix built by both: oracle verdicts against the independent reference, and the set of replaced functions and livepatch symbols in each module. Every difference, and every alarm, is root-caused to a generator behaviour or classed as a false alarm, as in S21.
- Load check of every module on the runtime host with the 6.19.14 pin.
- No rule above changes after the first 6.19 build; a runner fault means the run is archived as invalid and rerun.

## Deviation 1 (9 Oct 2026, 11:25 UTC): pin moved from 6.19.14 to 6.19, before any 6.19 fix was selected or built

**Why.** The first run (started 11:02) selected no fix: `linux-6.19.y` ends at v6.19.14 (branch head b9dbb457 = v6.19.14, checked with `git ls-remote`), so the rule "fixes on the stable branch after the pin" has nothing to draw from at the registered pin. That run built nothing; it was stopped before scoring and is recorded as invalid in `build-progress.txt`.

**Change (decided by the author).** Pin: Linux 6.19, the base release (klp-build exists from 6.19), built by the same recipe as 6.19.14 (`tb-newpins.sh`: kernel.org tarball checked against `sha256sums.asc`, the 6.6.47 base configuration, LIVEPATCH and DEBUG_INFO, olddefconfig, gcc 13.3.0). Fixes: `s12select.py` unchanged, same `vulns.git` commit and seed rule, branch 6.19 at pin 6.19, `linux-6.19.y` fetched after v6.19, so fixes released in 6.19.1 to 6.19.14 are the pool. klp-build is the in-tree script of the 6.19 pin. Everything else in this registration is unchanged.

**Runner.** `lab/s11/s11-v619.sh` (copy of `s11.sh` with V=6.19, a fresh `stable619` fetch, and a stop if the main sample is empty); `s12build.py` and `s21oracle.py` map branch 6.19 to the 6.19 pin. The runtime host's load check of the S11 modules is run against the 6.19 pin (its chain names 6.19.14; that step is run by hand for 6.19).

## Deviation 2 (11 Oct 2026, ~12:20 UTC): oracle scoring of the klp-build modules against R-ind, all versions with both controls; R-kp with v1.3 only

**Why.** klp-build's own reference is the whole patched `vmlinux.o`, and each oracle call against it takes 10 to 15 minutes (the oracle indexes every function of every reference object; `lab/s11/KLP-LOAD-FAILS-2026-10-10.md`, cost). `s21oracle.py` runs v1, v1.1 and v1.2, each with the wrong-reference and no-op controls, so nine calls per module: after 37 hours it had started 12 of the 34 modules, about 70 hours more before the R-ind pass would begin. It also predates v1.3 (S16 Deviation 3), the version the paper reports. It was stopped; its partial output is kept in `oracle/_superseded-s11-v12-rkp/` and not used.

**Change.** (1) Against R-ind (S22, seconds per call), v1, v1.1, v1.2 and v1.3 on every klp-build module, each with the wrong-reference control (another fix's references; must not be CONSISTENT) and the no-op control (byte copy; must reproduce the verdict), by `s21oracle.py` unchanged with v1.3 added to its oracle table under its frozen hash (`lab/s11/s11_rind_allver.py`). (2) Against R-kp, v1.3 only, already scored by `lab/s11/klp_v13.py` (`oracle/s11-klp-v13.json`), without the controls. The generator comparison (Outcome, third item) uses R-ind, as registered. Builds, load check and every other rule are unchanged.
