# S39 pre-registration: real shipped arm64 livepatch modules (Amazon Linux 2023, AArch64)

Frozen 20 Oct 2026, before any Amazon aarch64 module is scored. S37 established the binding oracle on arm64 on
four kpatch-build modules built from synthetic integration-test patches. S39 strengthens the arm64 leg with
real shipped modules: the AArch64 counterpart of the x86-64 Amazon scan (S26), scored the same way.

## Host and toolchain (recorded before the draw)

- A real aarch64 host (AWS Graviton). References are built inside the Amazon Linux 2023 aarch64 container,
  running natively on the host, so the reference compiler is AL2023's own aarch64 gcc, the compiler that built
  the shipped module. The module and its reference share one toolchain family, as Section 5.2.3 requires.
- Record the host, uname -m (expect aarch64), the AL2023 gcc banner, and the oracle hash.

## Subjects (frozen scope, pre-draw)

- The population is the 173 `kernel-livepatch-*.aarch64` packages Amazon Linux 2023 publishes. The draw is ten
  packages from each of the 6.1, 6.12 and 6.18 kernel series, thirty in all, mirroring S26. The draw is seeded
  (seed 39) over the series-sorted package list and recorded before any module is scored. Every shipped
  `livepatch-CVE-*.ko` module in a drawn package is a subject.
- Each package resolves to Amazon's content-delivery network and is signed with the Amazon Linux 2023 key,
  verified on fetch, as in S26.

## Reference

For each module, an independent compile of the module's own CVE patch applied to the exact kernel source the
package names (the kernel source rpm bundled in the livepatch source rpm), compiled one section per function in
the AL2023 aarch64 container, as Section 5.2.3 and S26 treat shipped modules. No generator is in this path.

## Oracle and checks

Oracle v1.7 (the AArch64 extension frozen in S37). Each shipped module is scored against the reference objects
built from its own patch, on the patched functions, in multiset and sequence modes (binding and addend). The
pin's aarch64 `vmlinux` (from the matching kernel package) is supplied so the sympos check runs on the real
position bindings the shipped modules carry, which S37's corpus lacked. Scaffolding (`init_module`,
`cleanup_module`) is excluded from the fidelity verdict, as in S26.

## Metrics and success criterion

False-alarm rate on the unmodified shipped modules (patched functions), with a Wilson 95% interval; the sympos
check's verdicts on the real position bindings; every divergence root-caused and the shipped module and
reference objects retained, as in S26. Success is a false-alarm rate on real shipped arm64 modules comparable
to the x86-64 shipped result (S26: patched functions match in 163 of 164), and a sympos check that resolves the
real position bindings. A divergence that roots to a real generator fault is reported as a finding, not
suppressed.

## Deviations policy

The draw and the rules above are frozen before scoring. Any package that fails to download, whose source rpm or
kernel source is unavailable, or whose reference does not build, stays in the denominator with its reason, as
in S26 and S34.

## Archive

The draw, the modules, the references, the verdicts and this pre-registration are archived to `results/arm64/`
beside the S37 materials, and the result updates the Section 7.4 cross-architecture paragraph and Section 9.3.

## Addendum B1 (20 Oct 18:45, before S39b scores anything)

The drawn packages also ship Amazon's code-named livepatches (DirtyAH6, OVSwrap, fraggap and others, 59 modules).
The x86-64 scan (S26, Section 7.6) scored these with the CVE modules; S39 built references only from CVE-named
patches. S39b brings the arm64 leg to the S26 scope: every patch in each source tar gets a reference, and
modules pair with references by the S26 rule (module `livepatch-<patch>`, `.` and `&` as `-`). Same oracle
(v1.7), container, flags and scaffolding rule. The 62 previously scored CVE modules are rebuilt and rescored
as a reproducibility check; any change in their verdicts is reported. Per-file make logs are kept, so a patch
that yields no object (CVE-2023-3776 in S39) is reported with its cause. CVE-2023-3609, declined in S39 on a
compiler mismatch, is rebuilt with the compiler its module records (gcc 11.3.1-4, from the AL2023
2023.1.20230628 release repository) and scored under the same strict toolchain rule.

### B1 outcome note (20 Oct, after S39b)

CVE-2023-3776's patch includes `kpatch-macros.h`, which kpatch-build puts on the include path and a plain compile
does not have (make log, out39b mklog). Its reference was rebuilt with kpatch's own `kmod/patch` headers (v0.9.10) on
the include path and with the compiler its module records (gcc 11.3.1-4), together with CVE-2023-3609.
