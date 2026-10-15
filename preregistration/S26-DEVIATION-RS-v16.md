# Deviation: oracle v1.6 rule RS (scaffolding scope), 15 Oct 2026

## Why

The S26 Amazon draw under v1.4 reported 58/164 DIVERGENT. A post-hoc classifier showed 57 were only `init_module` / `cleanup_module` scaffolding (Section 7.2 `xt_nat` class). Reporting that as a classifier left the shipped claim outside the frozen oracle.

## Change

`blind-reloc-oracle-v1.6.py` = v1.5 + rule **RS**: after RF, functions named `init_module`, `cleanup_module`, `__pfx_init_module`, `__pfx_cleanup_module` are removed from the fidelity result set (still listed under `scaffolding_divergences`). `body_check_v16.py` does the same. Disable with `LPFID_DISABLE=RS`.

## Non-masking (`lab/s34/non_masking_v16.py`, PASS)

- A: `LPFID_DISABLE=RF,RS` → v1.6 ≡ v1.4 on every S26 keep module and every S34-gcc44 scored package.
- B: `LPFID_DISABLE=RS` → v1.6 ≡ v1.5.
- C: 57 scaffolding-only Amazon modules become CONSISTENT; CVE-2023-5090 stays DIVERGENT on `svm_set_x2apic_msr_interception`.
- D: reloc-index mutant vs parent module is DIVERGENT under v1.6 (visible-mutant protocol).

## S26 under v1.6

`lab/s26/s26-v16-SUMMARY.json`: **163 CONSISTENT / 1 DIVERGENT** (CVE-2023-5090 non-string `.rodata`). Owned as 1 of 164 unresolved under frozen rules; not extended into RC (would be a third fitted rule on n=1).
