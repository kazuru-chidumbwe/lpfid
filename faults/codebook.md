# S9 codebook, frozen 10 Oct 2026 before the first coding pass

Items: the 206 candidate commits of `/opt/atlas/s9-kpatch-candidates.txt` (fix-like keywords among the 867 commits touching `kpatch-build/`), messages and diffstats in `lab/s9-commits-2026-10-10.txt`. Coder A codes every item from the commit message and diffstat only; coder B re-codes a random 30% (seed 20261010) independently from the same text. Agreement: Cohen's kappa per variable with a bootstrap 95% interval. No rule below changes after coder A starts.

## Variables

1. **defect**: `yes` if the message describes the generator producing a wrong result or failing on some input (error, wrong output, crash at build, load or enable time, missed change), `no` otherwise (refactor, cleanup, tests, documentation, CI, packaging, new architecture or feature support without a described failure, a fix to the harness scripts only).
2. **symptom** (only if defect = yes), the earliest point where the defect shows, as the message describes it:
   - `build-fail`: kpatch-build, create-diff-object or the link stops with an error;
   - `load-fail`: the module is rejected when loaded;
   - `enable-crash`: oops, panic or hang when the module is enabled or the patched code runs;
   - `silent`: the module builds, loads and enables, and its behaviour or data is wrong (wrong symbol, address, value, missing change), with no error reported;
   - `unclear`: the message does not say which of these.
   A message that says only "wrong", "incorrect" or "broken" without saying where it fails is `unclear` unless it states that the build succeeds.
3. **class** (only if defect = yes): `binding` (wrong symbol, symbol position, callee, local or global binding), `data` (wrong address, addend, string, variable, relocation offset), `scope` (changed code not included in the module, or unchanged code included), `eligibility` (callbacks, shadow variables, hooks, replace or state handling, patchability checks), `other` (anything else: build plumbing, toolchain or kernel-version incompatibility that only stops the build).
4. **arch**: the architecture the message names, or `any` if none.
5. **evidence**: the shortest phrase from the message that supports the symptom code.

## Rules for hard cases

- A commit that adds support for a new kernel or compiler version is a defect only if the message describes the generator failing or producing wrong output on that version; its class is `other` unless the failure is in binding, data or scope.
- A revert is coded like the commit it reverts would have been, from the revert's own message.
- If one commit fixes several defects, code the most severe symptom (silent over enable-crash over load-fail over build-fail).
