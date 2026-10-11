# S2 pre-registration: operator mutants on real-fix and fixture modules (8 Oct 2026)

Written and committed before any S2 mutant is scored. Runner `lab/s2/s2run.py` (the build host `/opt/atlas/s2`). 3. A dry listing on three subjects (site counts only; no mutant written, no oracle run) checked the site and hunk rules before this file was written.

## Subjects

- **S12:** the 123 built S12 modules (kpatch v0.9.11, gcc-13, three pins). Reference R-kp (kpatch's patched objects + `patch-hook.o`), P1 against the pin `vmlinux`. Primary set.
- **Fixtures:** the 78 fixture goods of the S16 recheck, with their own references. Design set; reported separately and never pooled with S12.

## Operators

`swap`, `addend`, `sympos` (`vmlinux`-guided), `dropcall`, `constant` from `lpfid-mutate.py` (SHA-256 `258d0da5...6bf4`), and `redirect` by the S1 rule (callee i to callee i+1, applied with `perturb-plt32-redirect.py`, SHA-256 `8b57d886...eed2`).

## Site rules

1. A site whose enclosing function is defined in the module's kpatch scaffolding (the functions of `patch-hook.o`) is excluded: those functions are generator code, not the fix. A site with no enclosing function is excluded. Redirect sites carry no function and are kept, as in S1. `sympos` sites are symbol-level and kept.
2. Per module and operator, up to **K = 10** eligible sites are drawn with `random.Random("20261008:<subject>:<op>")`.
3. **Inside-hunk:** the site's function, with compiler suffixes (`.cold`, `.part.N`, `.isra.N`, `.constprop.N`) removed, is one of the functions the fix's diff changes (`selection.json` field `functions`). Otherwise outside-hunk. Redirect and `sympos` mutants, and all fixture mutants, are not labelled.

## Mutant quality

- A mutant whose bytes equal its parent is a no-op: discarded and counted.
- `sympos-equivalent` sites (unique names) are counted per module and never mutated.
- A mutant whose bytes equal an earlier mutant of the same parent is a duplicate: scored once. Raw and deduplicated counts are both reported.
- Behaviourally equivalent edits that change bytes are counted as detected when flagged; a hand check of a random sample is reported separately (not part of this run).

## Oracles and outcome

Frozen v1 (`7d79c9d9...843c`) and frozen v1.1 (`5139e049...0add`), both on every scored mutant; the runner checks all four hashes before it starts. A mutant is **detected** when the overall verdict is DIVERGENT or LOAD_FAIL. Reported per operator and set: drawn, build failures, no-ops, duplicates, scored, detected, multiset and sequence divergences, and detection by hunk label; every mutant where v1 and v1.1 disagree is listed. Expected from the S2 probe and the oracle design, stated now: `constant` is a blind spot of the static oracle (no relocation changes); `swap` is visible in sequence mode only.

## After this run

The mutants stay under `/opt/atlas/s2/mut` for the baseline runner (loader, livepatch core) on the runtime host. No rule above changes after the first mutant is scored; a fault in the runner means the run is archived as invalid and rerun from scratch.
