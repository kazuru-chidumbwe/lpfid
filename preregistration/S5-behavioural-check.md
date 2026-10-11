# S5 pre-registration: behavioural check on three fixes (11 Oct 2026)

Written and committed before any probe runs on a module or mutant. Scope decided by the author on 11 Oct: 3 to 5 fixes. Manuscript 5.5 (behavioural check) and 7.4.

## Fixes and contracts

Chosen from the built real-fix modules (S12 kpatch-build, S11 klp-build) for one property: the fix changes the result of a single system call that a static probe can make inside the minimal VM, deterministically. Fixes whose effect needs network traffic, a disk image, a device the VM lacks, or a race were not eligible. Three fixes qualified, on three pins and both generators:

| Fix | Pin, generator | Probe | Vulnerable | Fixed |
| --- | --- | --- | --- | --- |
| CVE-2024-57903 | 6.1.119, kpatch-build v0.9.11 | setsockopt(SO_REUSEPORT) on an AF_UNIX socket | `PROBE result=0 errno=0` | `PROBE result=-1 errno=95` |
| CVE-2024-50195 | 6.6.47, kpatch-build v0.9.11 | clock_settime on /dev/ptp0 (KVM PTP) with tv_nsec = 2e9 | `PROBE result=-1 errno=95` | `PROBE result=-1 errno=22` |
| CVE-2026-31774 | 6.19, klp-build | IORING_OP_SENDMSG with sqe->len = 0xffffffff | `PROBE result=5` | `PROBE result=-22` |

Contracts: `lab/s5/contracts/*.json`; probes: `lab/s5/probes/*.c` (static binaries). Contract-writing effort is reported as non-blank, non-comment probe lines (15, 17, 60) plus one line each for the two expected outputs.

## Procedure (one VM boot per module)

The pin boots under KVM on the runtime host with a busybox initramfs holding the probe and the module. Phase 1: the probe runs 3 times before the module is loaded and must print the vulnerable line each time, else the run is a contract failure, not a verdict. Phase 2: insmod, wait for enabled = 1 and transition = 0 (60 s), run the probe 3 times; the fixed line is expected. Phase 3 (all three modules are in scope for a revert: no hazard by the eligibility check): write 0 to enabled, wait for the transition, run the probe 3 times; the vulnerable line is expected.

## Subjects and verdicts

- The unmodified module of each fix (must pass every phase; a failure here means the contract or the check is wrong and is reported as such).
- Every operator mutant of that module: the existing S2 mutants for the two kpatch-build fixes (6.1: 45, 6.6: 37), and for the klp-build fix the same S2 generator (`lab/s2/s2run.py` run_subject: K = 10 per operator, seeded, no-op and duplicate mutants removed) run once before any probe.
- Verdict per mutant: DETECTED when phase 2 does not print the fixed line on every repeat, or phase 3 does not print the vulnerable line on every repeat; LOUD when the mutant fails to load, enable or complete the transition, or the VM crashes (reported separately; the loader already sees these); PASSED otherwise. Disagreement between repeats is reported as flakiness.
- Reported per operator with Wilson 95% intervals, next to the binding oracle's verdict on the same mutants (v1.3 against R-ind for the kpatch fixes as in S2; v1.4 against R-ind for the klp-build fix), with attention to the `constant` operator, which changes no relocation.

## Rules

No rule above changes after the first probe runs on a module. A runner fault means the run is archived as invalid and rerun.

## Contract validation on the unmodified modules (11 Oct 2026, before any mutant ran)

- CVE-2024-57903 and CVE-2026-31774: phase 1 vulnerable, phase 2 fixed, phase 3 vulnerable on every repeat; contracts valid.
- CVE-2024-50195: contract failure as defined above. Phase 1 already printed `errno=22`: glibc's `clock_settime()` wrapper rejects `tv_nsec >= 1e9` before the system call, so the probe never reached the kernel. Revision 2 of the probe makes the raw system call; it is validated on the unmodified module (phases 1 to 3) before any mutant runs. Contract-writing effort for this fix is reported as two revisions.
- Runner: probe outputs are extracted as `PROBE result=... [errno=...]` tokens, so a kernel message printed on the same console line cannot corrupt them (one phase-2 line of CVE-2024-57903 was interleaved in the first run); the console log level is unchanged so that oopses stay visible.

## How the fixes were chosen, and what the result covers (recorded 11 Oct 2026, before any mutant result was read)

- The fixes were chosen for being testable, not sampled. The built real-fix modules whose changed files lie outside `drivers/` and on-disk filesystems (77 of the 123 S12 modules, plus two S11 klp-build fixes) were screened by reading the fix diff, in no fixed order, and screening stopped once three qualified. Fourteen diffs were read; 3 admit a deterministic single-system-call contract. The other 11 change a race (CVE-2026-53352, CVE-2026-43439, CVE-2026-89603), a fork or exit path (CVE-2025-38100), a packet path (CVE-2026-53184, CVE-2026-31415), a reachable-only-from-netlink validation (CVE-2026-72400), a kthread or reschedule path (CVE-2024-56709, CVE-2026-45895), a module teardown (CVE-2025-37995) or user-space pointer reading that needs a crafted rseq area (CVE-2025-38067).
- The result therefore measures how well the behavioural check judges a module when a contract exists for its fix. It says nothing about the share of fixes that admit a contract; on the diffs read, that share was 3 of 14, and the paper reports it as such and does not generalise the detection rates to fixes in general.
