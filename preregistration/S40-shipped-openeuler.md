# S40 pre-registration: openEuler as a third shipped livepatch vendor

Frozen 20 Oct 2026, before any openEuler module is scored. openEuler
(Huawei) is the third distribution that publishes both the shipped livepatch module and buildable source with no
subscription, beside Amazon Linux 2023 and OpenAnolis. It shores up the shipped-vendor generalisation (the
OpenAnolis arm is four distinct hotfixes repeated across builds).

## Population (public openEuler hotpatch_update trees)

Seven kernels, one NVR each, on both x86_64 and aarch64: 4.19.90 (20.03-SP4), 5.10.0 (22.03-SP1 through SP4),
and 6.6.0 (24.03 and 24.03-SP1). The trees hold cumulative ACC revisions per kernel (20.03-SP4: 7; 22.03-SP1..
SP4: 17, 9, 12, 6; 24.03: 8; 24.03-SP1: 4), 63 RPMs per architecture. 24.03-SP2, SP3 and SP4 have no
hotpatch_update directory. Each later ACC on a kernel is a cumulative superset of the earlier one, and one
`.ko` (SysCare `patch-kernel-<nvr>-ACC-*`, carrying one `vmlinux-<uuid>.ko`) holds every patch in that build.

## Primary unit (frozen) and reference

The primary unit is the LATEST ACC per kernel: seven modules per architecture. A random draw would rescore the
same kernel, so no random draw is used. The reference for each module is an independent compile of the whole
`.syscare.tar.gz` (the CVE patches) inside the matching `kernel-<nvr>-ACC-*.src.rpm` applied to that kernel's
source, not one CVE at a time. The binary's own SOURCERPM tag names a `patch-kernel-...src.rpm` that is not the
directory file; the reference is built from `kernel-<nvr>-ACC-*.src.rpm`. Earlier ACC revisions on each kernel
are a clustered sensitivity arm, not the primary count.

## Hosts and toolchain (matching, per kernel)

The reference compiler must match the module's `.comment`. The kernels need different openEuler compilers, so a
single container will not do: 4.19.90 -> GCC 7.3.0, 5.10.0 -> GCC 10.3.1, 6.6.0/24.03 -> openEuler GCC
12.3.1-30, 6.6.0/24.03-SP1 -> openEuler GCC 12.3.1-62. The 4.19 and 5.10 `.comment` strings carry no openEuler
rebuild id, so those two kernels are gated on the exact compiler version the module records. References are
built in the matching openEuler container (native, so x86_64 on Testbed B and aarch64 on the Graviton t4g).

## Two sections (the vendor change and the architecture change move together)

The x86_64 openEuler run is the third shipped vendor beside Amazon x86-64 and OpenAnolis x86-64, and updates
the shipped-vendor section (Section 7.6). The aarch64 openEuler run is a third vendor on AArch64 and extends the
cross-architecture section (Section 7.4) beside S39. The two are kept apart and reported separately.

## Oracle, metrics, success

Oracle v1.7. Each shipped module scored against its reference on the patched functions, binding and addend, in
multiset and sequence modes; the openEuler aarch64 `vmlinux` is supplied so the sympos check runs on the
positioned klp bindings these modules carry. Metrics: false-alarm rate per architecture with a Wilson interval,
sympos verdicts, every divergence root-caused and objects retained. Success is a false-alarm rate comparable to
the Amazon shipped result, establishing openEuler as a faithful third vendor.

## Exclusions and deviations

The four packages opened for format reconnaissance (24.03 ACC-1-8 x86_64; 24.03-SP1 ACC-1-4, 22.03-SP4 ACC-1-6,
20.03-SP4 ACC-1-7 aarch64) are excluded from the scored set, as the OpenAnolis census excluded its probe
package. AlmaLinux is not a candidate: its repos ship only the `kpatch`/`kpatch-dnf` tools, not module packages.
Any module whose reference compiler cannot be matched, or whose source does not build, stays in the denominator
with its reason.

## Addendum A1 (20 Oct 18:25, before any primary unit is scored)

1. Primary unit made exact: the latest ACC per kernel and architecture that was not opened before scoring. The
   recon packages are excluded as frozen above, and the pipeline-validation package (24.03 ACC-1-7 x86_64) is
   excluded on the same ground. Units (14): x86_64 20.03-SP4 ACC-1-7, 22.03-SP1 1-17, SP2 1-9, SP3 1-12, SP4 1-6,
   24.03 1-6, 24.03-SP1 1-4; aarch64 20.03-SP4 ACC-1-6, 22.03-SP1 1-17, SP2 1-9, SP3 1-12, SP4 1-5, 24.03 1-8,
   24.03-SP1 1-3. List: s40_units.txt in results/s40-openeuler.
2. Reference configuration: the vendor's own build config from the exact binary kernel rpm, falling back to the
   in-tree openeuler_defconfig; never a generic defconfig. The config source and hash are recorded per unit.
3. The exact kernel-debuginfo vmlinux is supplied on both architectures (not only aarch64), so the sympos check
   runs wherever the module carries positioned bindings.
4. Approved by the author 20 Oct 2026, before any primary unit returned a verdict (first scoring launch 18:33
   UTC; the 18:22 launch scored nothing and is archived as invalid-notools-20oct). The four latest ACCs opened
   before scoring (24.03 ACC-1-8 and ACC-1-7 x86_64; 20.03-SP4 ACC-1-7, 22.03-SP4 ACC-1-6, 24.03-SP1 ACC-1-4
   aarch64) are reported in the sensitivity arm, labelled as opened before scoring, never in the primary count.

## Addendum A2 (20 Oct 19:55 UTC; written after verdicts on five primary units had been seen)

Two reference-build changes were made after the first primary units were scored. This addendum records what
was seen before each change, so the counted run can be read against it.

**Change 1, target kernel modules for the sympos check (decided about 19:00 UTC).** The pipeline supplied only
`vmlinux`, so symbols bound into loadable modules (`.klp.rela.<obj>`, e.g. `drm`, `drm_kms_helper`) could not be
resolved and came back INCONCLUSIVE. From 19:28 the exact kernel-debuginfo's module objects are supplied
(named `<obj>.ko-<ver>.debug`; the 18:56 launch used a pattern that missed them). Seen before this change:
- 4.19.90 20.03-SP4 ACC-1-7 x86_64: DIVERGENT (`pinctrl_enable`), sympos INCONCLUSIVE.
- 4.19.90 20.03-SP4 ACC-1-6 aarch64: DIVERGENT (`pinctrl_enable`), sympos CONSISTENT.

**Change 2, hot/cold partitioning off in the reference (decided about 19:45 UTC).** When a shipped module carries
no `.cold` symbol, its reference is compiled with `-fno-reorder-blocks-and-partition` as well as one section per
function; otherwise with the default. The choice is recorded per unit (`xflags` in config.txt). The trigger was
the 22.03-SP1 x86_64 verdict below: two of its three divergent functions were `.cold` splits present only in the
reference. The rule reads a property of the shipped module (presence of `.cold`), not a verdict, and was
checked on one unit (x86_64 22.03-SP1) before adoption. Seen before this change, in
addition to the two units above:
- 5.10.0 22.03-SP1 ACC-1-17 x86_64: DIVERGENT (`hugetlbfs_parse_param`, `ima_collect_measurement`,
  `ip6_finish_output2`), sympos INCONCLUSIVE; with the flag (test run): DIVERGENT (`ip6_finish_output2` only),
  sympos CONSISTENT.
- 5.10.0 22.03-SP1 ACC-1-17 aarch64: DIVERGENT (`ip6_finish_output2`, `unix_stream_sendpage`).
- 5.10.0 22.03-SP2 ACC-1-9 aarch64: INCONCLUSIVE (sympos INCONCLUSIVE, before Change 1 took effect).

**Treatment.** These five units stay in the primary set; excluding them after seeing their verdicts would be
the larger bias. Their earlier verdicts are archived (invalid-nomodules-20oct, invalid-modpattern-20oct,
invalid-coldsplit-20oct on both hosts) and are reported beside the counted ones. The counted run started at
19:48 UTC with both changes; no unit of it had been scored before. No comparison rule of the oracle was changed,
and none is added after scoring: every residual divergence in the counted run is root-caused and reported as it
falls. The paper states that both changes were made after these five verdicts were seen.

## Addendum A3 (20 Oct 23:45 local; written after the verdicts below had been seen)

**Change: the reference compiler for the 4.19 and 5.10 kernels is the release's own compiler.** The pre-registration
gates these kernels on the gcc version the module records (7.3.0, 10.3.1) because their `.comment` carries no
rebuild id. The containers installed the latest gcc of that version from the release's update repository
(22.03-SP1: gcc 10.3.1-28). The kernel packages in the OS repository were built with the OS repository's compiler
(22.03-SP1: gcc 10.3.1-20), and a hotpatch is built against that kernel. From now on each 4.19 and 5.10 reference is
built with the compiler the release's OS repository carries (`dnf distro-sync` with the update repositories
disabled), recorded per unit.

**Seen before this change:** every counted 4.19 and 5.10 verdict on both architectures (20.03-SP4, 22.03-SP1 to SP4;
x86_64 and aarch64), in particular 22.03-SP1 ACC-1-17 DIVERGENT on both architectures (`ip6_finish_output2`, and
`unix_stream_sendpage` on aarch64). A diagnostic rebuild of the x86_64 22.03-SP1 reference with gcc 10.3.1-20 matched
all 24 functions. The change was chosen after that result.

**Treatment.** All ten 4.19/5.10 units are rebuilt and rescored with the release compiler; both the update-compiler
verdicts and the release-compiler verdicts are reported, and the paper states that the compiler was changed after
the SP1 verdicts were seen. The 6.6 units already use the exact rebuild their modules record and are unchanged.

### A3 counting rule (20 Oct ~23:55 local, before any A3 reference is scored)

For the ten 4.19 and 5.10 units the **counted verdict is the one against the release (OS-repository) compiler**,
for every unit, whatever it shows. The update-compiler verdicts (the 18:40-19:48 runs) are reported beside them as a
sensitivity result. No unit is counted under whichever compiler happens to match: if a unit that matched with the
update compiler diverges with the release compiler, that divergence is counted and root-caused. At the time of
writing, the A3 runner had rebuilt one reference (20.03-SP4 aarch64) and scored none.
