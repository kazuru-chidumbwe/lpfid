# S26 divergence root-cause (first 10 packages) — 13 Oct 2026

The whole-module reference-differential over the first 10 shipped Amazon Linux 2023 livepatch packages
flagged 13 modules DIVERGENT (v1.3 and v1.4 agree). Every divergent module's compiler matched its
reference (`module_compilers == reference_compilers`), so none is a compiler artifact. Each divergence
was root-caused from the preserved artifacts in `results/<pkg>/keep/<patch>/` (ko + reference .o + full
v1.4 JSON). Two classes, both already characterised, neither a fidelity fault.

## Class A — generator loader scaffolding (12 of 13)

The reference is the plain-compiled source object. When the patched function lives in the object that
also defines the module's init/exit (nbd.o, ext4 super, netem, nvme-tcp, tls, nf_tables, esp, libata,
authencesn, kvm/svm), the oracle compares the shipped `.ko`'s `init_module` / `cleanup_module` against
that object's original registration code. A kpatch-build livepatch's `init_module` / `cleanup_module`
are the generator's loader (they call `klp_enable_patch`, `patch_find_object_by_name`,
`patch_free_livepatch`, `add_callbacks_to_patch_objects`, `kzalloc.constprop`), not the fix. The set
`functions_in_module_not_in_reference` is byte-identical across all 13: the kpatch scaffolding helpers.

Confirmed by scoping the oracle to the actual patched targets (defined FUNC symbols minus the scaffolding):
e.g. CVE-2024-49855 restricted to `nbd_handle_cmd, nbd_requeue_cmd, nbd_xmit_timeout` scores CONSISTENT
(5 compared, 0 divergent). The real patched functions match in every Class-A module; only the generated
init/cleanup differ. This is the pre-registered Deviation-4 scaffolding exclusion — the only new point is
that kpatch names its scaffolding `init_module`/`cleanup_module`, which the fixture rule (keyed on
`livepatch_mod_init`) did not cover. The §7.6 scoring compares patched targets, i.e. excludes the
generator's init/cleanup, exactly as the fixture modules did.

## Class B — non-string `.rodata` naming (1 of 13)

CVE-2023-5090 (6.1.56-82.125), patched function `svm_set_x2apic_msr_interception`: the sole divergence is
`32S:direct_access_msrs+0x170` (module, named) vs `32S:sec:.rodata+0x170` (reference, anonymous). Same
data, same offset; the reference compiler left the array in anonymous `.rodata` without a symbol while the
module names it. This is the identical representation limitation written up in §7.5 for the klp-build
held-out alarms (RC reconciles strings, not non-string `.rodata` data), and was ruled EQUIVALENT there.

## Outcome

Zero real fidelity faults in the first 10 packages. The prereg ethical-slip gate (report any shipped fault
to Amazon before §7.6 publishes) is NOT triggered by these. This is consistent with §7.5: on real shipped
generator output the oracle's raw alarms are all explainable as scaffolding or the known `.rodata` naming
difference, with no masking. Remaining packages (11–30, 6.12 and 6.18 series) are scored the same way;
every non-CONSISTENT module is preserved under `results/<pkg>/keep/` for the same root-cause pass.

## Final — all 30 packages (14 Oct 2026)

The run completed 09:06 UTC 14 Oct: 30 packages, 0 build failures, 164 modules scored. Verdicts
106 CONSISTENT/CONSISTENT, 58 DIVERGENT/DIVERGENT, 0 NO_REF. Eligibility 162 SOUND, 1 OUT_OF_SCOPE,
1 UNDETERMINED; is_replace 0, uses_shadow 1, has_callbacks 1.

The two combined-CVE objects in `kernel-livepatch-6.1.94-99.176`
(`livepatch-CVE-2024-41091-CVE-2024-41090-0001` and `-0002`) were initially NO_REF: Amazon's patch
basename joins the two CVEs with `&` (`CVE-2024-41091&CVE-2024-41090.0001`) while the shipped module
stem joins them with `-`, so `ref_dir_for` did not pair them. The matcher now maps `&` to `-` as well
as `.` to `-`; both modules paired against their already-built references (`tap.o`, `tun.o`) with no
rebuild. `-0001` scores CONSISTENT, `-0002` DIVERGENT. (Backups: `s26_run.py.bak-premerge`,
`result.json.bak-noref`.)

Root-cause over all 58 divergences (`classify_div.py`): 57 are Class A loader scaffolding
(`init_module`/`cleanup_module` only; patched targets CONSISTENT), 1 is Class B, the same CVE-2023-5090
`svm_set_x2apic_msr_interception` non-string `.rodata` naming difference described above. Every divergent
module's compiler banner matched its reference. No real fidelity fault in any of the 30 packages; the
prereg ethical-slip gate is NOT triggered. The newly-paired `-0002` divergence is Class A scaffolding.

See [[project_s26_shipped_livepatch]], internal/S16-ORACLE-FREEZE (Deviation-4), 07-results.md §7.5.


## Addendum: automated patched-function rate (15 Oct 2026)

Classifier `scoring/classify_div.py` drops `init_module` / `cleanup_module` (and `__pfx_` forms) from each DIVERGENT report. Summary: `results/s26-patched-fn-SUMMARY.json`.

Under that scope, **163 of 164** modules are CONSISTENT (106 overall CONSISTENT + 57 scaffolding-only). The sole residual is CVE-2023-5090 on `kernel-livepatch-6.1.56-82.125` (non-string `.rodata`: `direct_access_msrs+0x170` vs `sec:.rodata+0x170`), already Class B above.
