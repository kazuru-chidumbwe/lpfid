# S37 arm64 binding-oracle corpus result

Date 20 Oct 2026. Pre-registration internal/S37-PREREG-2026-10-19.md (deviations D1 pin 6.19, D2 cross-build on
Testbed B, D3 subject correction). Scored result: the binding oracle on generator-produced arm64 klp.rela
modules. Follows the decode validation (S37-PATHB-RESULT) and the klp-layer validation (S37-KLP-VALIDATION).

## Method

- Pin Linux 6.19 arm64 (first stable with arm64 HAVE_LIVEPATCH; the klp-build pin), cross-built on Testbed B
  with aarch64-linux-gnu-gcc 13.3.0, the version the x86-64 build host runs. A module and its reference share
  the one cross-toolchain (Section 5.2.3 reproducible-build control).
- Generator kpatch-build 0.9.11, cross (TARGET_ARCH=aarch64, CROSS_COMPILE=aarch64-linux-gnu-).
- Fixes: kpatch integration-test patches (the source of the x86-64 fixtures), those that apply to the pin and
  that create-diff-object processes on arm64.
- Reference: kpatch's own patched objects (corpus/<name>/ref), the first reference of Section 5.2.3. Scored
  with oracle v1.7 (AArch64 extension of v1.6).
- Mutation: lpfid-mutate-aa.py (AArch64 dispatch of the Section 6.3 operators), scoped to the functions the
  oracle compares (patched functions; scaffolding excluded), up to ten sites per operator per module in
  deterministic index order.

## Build outcomes (generator coverage)

8 integration patches applied to the pin; kpatch-build built 4, and 4 failed. Three failures are
create-diff-object find_local_syms correlation on heavy multi-static files (module -> net/netlink/af_netlink.c;
shadow-newpid -> kernel/fork.c and kernel/exit.c; syscall -> kernel/sys.c); one is a patch that did not apply
(new-function). Built modules and patched functions:

- data-new: meminfo_proc_show
- gcc-static-local-var-6: __nf_ip6_route
- macro-callbacks: pre/post patch and unpatch callbacks
- new-globals: kpatch_print_message, meminfo_proc_show

## Detection and false alarms

Mutations in the patched functions, scored against the kpatch reference.

| Operator (class) | Detected / applied | Rate | Wilson 95% |
| --- | --- | --- | --- |
| redirect (binding) | 24 / 24 | 1.00 | 0.862 to 1.0 |
| swap (binding, sequence) | 22 / 22 | 1.00 | 0.851 to 1.0 |
| addend (data) | 33 / 33 | 1.00 | 0.896 to 1.0 |
| dropcall (scope) | 32 / 32 | 1.00 | 0.893 to 1.0 |
| constant (body, blind spot) | 0 / 14 | 0.00 | 0.0 to 0.215 |

False alarms: 0 of 4 unmodified modules (Wilson 0.0 to 0.490). No unknown relocation type on any module. Every drawn mutant was scored: errors (un-scoreable) and apply-failures are both zero for every operator, so each denominator is the full drawn set (drawn = applied). The sweep JSON records drawn, applied, detected, errors and apply_fail per operator and module.

The corpus has no klp symbol whose name is duplicated in the pin's vmlinux, so the vmlinux-guided sympos
operator drew no site here. The sympos fault's detection on arm64 is shown on the lpfid-arrtest module
(fs/proc/array.c, proc_pid_status): changing render_cap_t,1 to ,2 scores LOAD_FAIL ("sympos 2 > 1 copies").

Data: results-arm64/s37-corpus-sweep.json; corpus/manifest.txt.

## Reading

Binding, data and scope faults in the patched functions are detected on arm64 at the same rates as on x86-64
(the Wilson intervals overlap the fixture rates), the body class is the declared blind spot on both, and the
unmodified modules raise no alarm. The arm64 corpus is four modules because kpatch-build builds four of the
eight integration patches on this pin; that bounds the generator, not the oracle.
